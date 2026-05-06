// logique réseau haut niveau

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[path = "netmanager.rs"]
pub mod netmanager;
#[path = "packets.rs"]
pub mod packets;

use crate::crypto::{self, abs, cpabe, DocumentLabel, RevocationEntry, RevocationList};
use crate::{AppState, Clearance, PendingRevocation};

use netmanager::NetworkManager;
use packets::{D3csFrame, D3csRequest};

#[derive(Clone, Serialize)]
pub struct ConnectedNode {
    pub name: String,
    pub classification: Option<String>,
    pub mission: Option<String>,
    pub is_authority: bool,
}

#[derive(Clone, Serialize)]
pub struct NetworkStatus {
    pub enabled: bool,
    pub node_id: String,
    pub tm_id: String,
    pub group: String,
    pub joined: bool,
    pub subscriptions: Vec<String>,
    pub pending_key_delivery: bool,
    pub has_public_params: bool,
    pub has_user_secret_key: bool,
    pub has_tm_delegate_key: bool,
    pub has_abs_key: bool,
    pub authority_reachable: bool,
    pub notifications: Vec<String>,
    pub connected_nodes: Vec<ConnectedNode>,
}

#[derive(Clone)]
struct PendingKey {
    login: String,
    clearance: Clearance,
    user_topic: String,
    tm_topic: String,
    asked_at: Instant,
    delegate_from: Option<String>,
    delegate_at: Option<Instant>,
    asked_delegate: bool,
    authority_done: bool,
    user_done: bool,
    tm_done: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PskaEntry {
    pub name: String,
    pub data: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct CtEntry {
    id: u64,
    ciphertext: String,
    signature: String,
}

pub struct NetworkRuntime {
    manager: NetworkManager,
    node_id: String,
    tm_id: String,
    is_authority: bool,
    pending: Mutex<HashMap<String, PendingKey>>,
    notifications: Mutex<Vec<String>>,
    authority_seen: Mutex<Option<(String, Instant)>>,
    abs_sync_attempts: Mutex<HashMap<String, Instant>>,
}

// implémentation permettant de créer et initialiser le runtime réseau d'un noeud

impl NetworkRuntime {
    // new -> initialisation pour un noeud réseau
    pub fn new(_state: &Arc<AppState>, node_id: &str) -> Result<Self> {
        let runtime_dir = std::env::var("D3CS_NETWORK_DIR")
            .unwrap_or_else(|_| "src/network/logs/runtime".to_string());
        let node_id = normalize_node(node_id);
        let group = std::env::var("D3CS_CONNECTIVITY").unwrap_or_else(|_| {
            if node_id.eq_ignore_ascii_case("U5") {
                "Net2".to_string()
            } else {
                "Net1".to_string()
            }
        });
        let tm_id = std::env::var("D3CS_TM_ID").unwrap_or_else(|_| tm_for_node(&node_id));
        let is_authority = node_id.eq_ignore_ascii_case("Authority");

        let manager = NetworkManager::new(&node_id, &runtime_dir, &group)?;
        manager.join()?;
        manager.subscribe("TM")?;
        manager.subscribe(&tm_id)?;
        manager.subscribe(&node_id)?;
        if is_authority {
            manager.subscribe("Authority")?;
            manager.subscribe("TM0")?;
        }

        Ok(Self {
            manager,
            node_id,
            tm_id,
            is_authority,
            pending: Mutex::new(HashMap::new()),
            notifications: Mutex::new(Vec::new()),
            authority_seen: Mutex::new(None),
            abs_sync_attempts: Mutex::new(HashMap::new()),
        })
    }

    // start -> lance la boucle réseau en arrière plan
    pub fn start(self: &Arc<Self>, state: Arc<AppState>) {
        let this = self.clone();
        thread::spawn(move || loop {
            let _ = this.tick(&state);
            thread::sleep(Duration::from_millis(100));
        });
    }

    // revoie le statut du noeud (local/network, identifiants, clés, authority_reachable, etc.)
    pub fn status_for_login(&self, state: &Arc<AppState>, login: &str) -> NetworkStatus {
        let group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        let pending = self.pending.lock().ok().and_then(|p| p.get(login).cloned());
        let pending_key_delivery = pending
            .map(|x| !(x.user_done && x.tm_done))
            .unwrap_or(false);
        let user_dir = format!("{}/{}", state.users_dir, login);
        let has_public_params = Path::new(&format!("{}/pp.bin", user_dir)).exists();
        let has_user_secret_key = Path::new(&format!("{}/psks{}.bin", user_dir, login)).exists();
        let has_tm_delegate_key =
            Path::new(&format!("{}/pska/pska{}.bin", state.tm_dir, login)).exists();
        let has_abs_key = Path::new(&format!("{}/skw{}.bin", user_dir, login)).exists();

        NetworkStatus {
            enabled: true,
            node_id: self.node_id.clone(),
            tm_id: self.tm_id.clone(),
            group,
            joined: self.manager.is_joined(),
            subscriptions: self.manager.subscriptions(),
            pending_key_delivery,
            has_public_params,
            has_user_secret_key,
            has_tm_delegate_key,
            has_abs_key,
            authority_reachable: self.authority_reachable(),
            notifications: self.latest_notifications(),
            connected_nodes: self.connected_nodes(state),
        }
    }

    // permet de switcher de groupe de connectivité Net1<->Net2
    pub fn set_connectivity_group(&self, state: &Arc<AppState>, group: &str) -> Result<()> {
        self.manager.set_group(group)?;
        self.subscribe_core()?;
        if self.tm_id == "TM0" {
            self.send_synchronize(state)?;
        }
        if self.is_authority {
            self.sync_missing_abs_keys(state)?;
        }
        self.notify(format!("Connectivity switched to {group}"));
        Ok(())
    }

    // appelée lorsqu'un utilisateur sign up en mode réseau, ce qui fait une requête de clés
    pub fn request_key_material(
        &self,
        state: &Arc<AppState>,
        login: &str,
        clearance: &Clearance,
    ) -> Result<()> {
        let login = normalize_login(login);
        let user_topic = login_to_user_topic(&login);
        let tm_topic = tm_for_login(&login).unwrap_or_else(|| self.tm_id.clone());

        self.manager.subscribe(&user_topic)?;
        self.manager.subscribe(&tm_topic)?;

        let req = PendingKey {
            login: login.clone(),
            clearance: clearance.clone(),
            user_topic: user_topic.clone(),
            tm_topic: tm_topic.clone(),
            asked_at: Instant::now(),
            delegate_from: None,
            delegate_at: None,
            asked_delegate: false,
            authority_done: false,
            user_done: false,
            tm_done: false,
        };
        if let Ok(mut p) = self.pending.lock() {
            p.insert(login.clone(), req);
        }

        self.publish(
            &self.tm_id,
            "TM",
            D3csRequest::KeyRequest,
            vec![
                login.clone(),
                serde_json::to_string(clearance)?,
                user_topic,
                tm_topic,
            ],
            true,
        )?;
        self.setup_storage(state)?;
        self.notify(format!("KEY_REQUEST emitted for {login}"));
        Ok(())
    }

    // partage d'un document chiffré sur le réseau
    pub fn share_ciphertext(&self, state: &Arc<AppState>, doc_id: u64) -> Result<()> {
        let ct = fs::read_to_string(format!("{}/{}.ct", self.ct_dir(state), doc_id))?;
        let sig = fs::read_to_string(format!("{}/{}.sign", self.sig_dir(state), doc_id))?;
        self.publish(
            &self.tm_id,
            "TM",
            D3csRequest::CtShare,
            vec![doc_id.to_string(), ct, sig],
            false,
        )
    }

    // publication d'une frame Revoke vers l'autorité
    pub fn request_revocation(&self, mission: &str) -> Result<()> {
        self.publish(
            &self.tm_id,
            "Authority",
            D3csRequest::Revoke,
            vec![mission.to_string()],
            true,
        )
    }

    // regarde si une mission n'est pas déjà révoquée dans l'ARL
    pub fn check_arl(&self, state: &Arc<AppState>, mission: &str) -> Result<bool> {
        let arl = crypto::get_arl(state)?;
        Ok(arl
            .items
            .iter()
            .any(|e| e.attribute_type == "mission" && e.attribute_value == mission))
    }

    // check si le noeud courant peut effectuer une délégation pour la clearance demandée
    pub fn delegation_check(&self, state: &Arc<AppState>, requested: &Clearance) -> Result<bool> {
        if self.check_arl(state, &requested.mission)? {
            return Ok(false);
        }
        if !is_delegable_classification(&requested.classification) {
            return Ok(false);
        }
        let Some(login) = tm_to_login(&self.tm_id) else {
            return Ok(false);
        };
        let db = state
            .user_db
            .lock()
            .map_err(|_| anyhow!("DB lock poisoned"))?;
        let Some(record) = db.users.get(&login) else {
            return Ok(false);
        };
        if !is_delegable_classification(&record.clearance.classification) {
            return Ok(false);
        }
        if requested.mission != record.clearance.mission {
            return Ok(false);
        }
        Ok(level(&requested.classification) <= level(&record.clearance.classification))
    }

    pub fn write_message(&self, m: &str) -> String {
        m.to_string()
    }

    // permet de créer un DocumentLabel à partir d'une classification et d'une mission
    pub fn choose_label(&self, classification: &str, mission: &str) -> DocumentLabel {
        DocumentLabel {
            classification: classification.to_string(),
            mission: mission.to_string(),
        }
    }

    // assemblage d'un message avec un label de sécurité sous la forme d'une chaîne texte
    pub fn bind(&self, message: &str, label: &DocumentLabel) -> String {
        format!("{}|{}|{}", message, label.classification, label.mission)
    }

    // permet d'ajouter une mission dans l'ARL si elle n'est pas déjà révoquée
    pub fn append_arl(&self, state: &Arc<AppState>, mission: &str) -> Result<RevocationList> {
        let mut arl = crypto::get_arl(state)?;
        if !arl
            .items
            .iter()
            .any(|x| x.attribute_type == "mission" && x.attribute_value == mission)
        {
            arl.items.push(RevocationEntry {
                attribute_type: "mission".to_string(),
                attribute_value: mission.to_string(),
            });
        }
        self.update_arl(state, &arl)?;
        Ok(arl)
    }

    // permet de remplacer l'ARL locale par une nouvelle ARL (e.g. lorsqu'un TM d'un utilisateur se
    // voit modififer son ARL via une update de la part de l'autorité)
    pub fn update_arl(&self, state: &Arc<AppState>, new_arl: &RevocationList) -> Result<()> {
        write_atomic_text(
            &format!("{}/arl.json", state.tm_dir),
            &serde_json::to_string(new_arl)?,
        )?;
        Ok(())
    }

    // crée le fichier ARL s'il n'existe pas encore
    pub fn setup_arl(&self, state: &Arc<AppState>) -> Result<()> {
        let p = format!("{}/arl.json", state.tm_dir);
        if !Path::new(&p).exists() {
            write_atomic_text(
                &p,
                &serde_json::to_string(&RevocationList {
                    version: 1,
                    items: Vec::new(),
                })?,
            )?;
        }
        Ok(())
    }

    // crée les répertoires de stockage (chiffrés, chiffrés intermédiaires, signatures, PSKA)
    pub fn setup_storage(&self, state: &Arc<AppState>) -> Result<()> {
        fs::create_dir_all(self.ct_dir(state))?;
        fs::create_dir_all(self.sig_dir(state))?;
        fs::create_dir_all(self.cti_dir(state))?;
        fs::create_dir_all(format!("{}/pska", state.tm_dir))?;
        Ok(())
    }

    // initialisation des presets BLP/Biba
    pub fn setup_presets(&self, state: &Arc<AppState>) -> Result<()> {
        let _ = crypto::get_presets(state)?;
        Ok(())
    }

    // mise à jour des PSKA, requête initiée par l'autorité
    pub fn update_pska(&self, state: &Arc<AppState>, diff: &[PskaEntry]) -> Result<()> {
        fs::create_dir_all(format!("{}/pska", state.tm_dir))?;
        for e in diff {
            if e.data.trim().is_empty() {
                continue;
            }
            write_atomic_text(&format!("{}/pska/{}", state.tm_dir, e.name), &e.data)?;
        }
        Ok(())
    }

    // récupère la classification d'un utilisateur depuis la base d'utilisateurs
    pub fn get_classification_attribute(
        &self,
        state: &Arc<AppState>,
        login: &str,
    ) -> Option<String> {
        #[derive(Deserialize)]
        struct UserToken {
            classification: String,
        }

        let login = normalize_login(login);

        if let Ok(db) = state.user_db.lock() {
            if let Some(user) = db.users.get(&login) {
                return Some(user.clearance.classification.clone());
            }
        }

        let token_path = format!("{}/{}/token.json", state.users_dir, login);
        let raw = fs::read_to_string(token_path).ok()?;
        let token: UserToken = serde_json::from_str(&raw).ok()?;
        Some(token.classification)
    }

    pub fn ask_for_decryption(&self, _ct_id: u64) {}
    pub fn transfer(&self, _cti_id: u64) {}
    pub fn new_user(&self, state: &Arc<AppState>, login: &str, c: &Clearance) -> Result<()> {
        self.request_key_material(state, login, c)
    }
    pub fn ask_user_delegate(&self) {}
    pub fn send(&self, _tk: &str) {}
    pub fn ask_for_sharing(&self, state: &Arc<AppState>, doc_id: u64) -> Result<()> {
        self.share_ciphertext(state, doc_id)
    }

    // permet d'envoyer à l'autorité une demande de révocation
    pub fn ask_revocation_request(&self, requester: &str, missions: &[String]) -> Result<()> {
        self.publish(
            &self.tm_id,
            "Authority",
            D3csRequest::AskRevocation,
            vec![requester.to_string(), serde_json::to_string(missions)?],
            true,
        )
    }
    pub fn ask_revocation(&self, mission: &str) -> Result<()> {
        self.request_revocation(mission)
    }
    pub fn new_user_alert(&self, login: &str) {
        self.notify(format!("newUserAlert for {login}"));
    }

    // horloge réseau, qui va lire les trames et les acheminer tout les X ms
    fn tick(&self, state: &Arc<AppState>) -> Result<()> {
        for frame in self.manager.poll()? {
            let _ = self.handle_frame(state, frame);
        }
        self.process_pending(state)?;
        self.sync_missing_abs_keys(state)?;
        Ok(())
    }

    // traite une trame réseau en l'envoyant au bon handler
    fn handle_frame(&self, state: &Arc<AppState>, frame: D3csFrame) -> Result<()> {
        if !self.is_relevant(&frame) {
            return Ok(());
        }
        if frame.src == self.tm_id || frame.src == self.node_id {
            return Ok(());
        }
        if frame.src.eq_ignore_ascii_case("Authority") {
            if let Ok(mut s) = self.authority_seen.lock() {
                let current_group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
                *s = Some((current_group, Instant::now()));
            }
        }

        match frame.request {
            D3csRequest::KeyRequest => self.on_key_request(state, &frame),
            D3csRequest::DelegateAccept => self.on_delegate_accept(&frame),
            D3csRequest::AskDelegation => self.on_ask_delegation(state, &frame),
            D3csRequest::AskRevocation => self.on_ask_revocation(state, &frame),
            D3csRequest::KeyResponse => self.on_key_response(state, &frame),
            D3csRequest::CtShare => self.on_ct_share(state, &frame),
            D3csRequest::Revoke => self.on_revoke(state, &frame),
            D3csRequest::ArlUpdate => self.on_arl_update(state, &frame),
            D3csRequest::Synchronize => self.on_synchronize(state, &frame),
            D3csRequest::PskaSync => self.on_pska_sync(state, &frame),
            D3csRequest::Unknown(_) => Ok(()),
        }
    }

    // permet de traiter la trame KEY_REQUEST
    fn on_key_request(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let login = normalize_login(&frame.args[0]);
        let clearance: Clearance = serde_json::from_str(&frame.args[1])?;
        let user_topic = frame
            .args
            .get(2)
            .cloned()
            .unwrap_or_else(|| login_to_user_topic(&login));
        let tm_topic = frame
            .args
            .get(3)
            .cloned()
            .unwrap_or_else(|| tm_for_login(&login).unwrap_or_else(|| self.tm_id.clone()));

        if self.is_authority {
            let k = self.authority_keygen(state, &login, &clearance)?;
            self.publish(
                "Authority",
                &user_topic,
                D3csRequest::KeyResponse,
                vec![
                    "USER_KEYGEN".to_string(),
                    login.clone(),
                    k.pp,
                    k.psks,
                    k.skw,
                ],
                true,
            )?;
            self.publish(
                "Authority",
                &tm_topic,
                D3csRequest::KeyResponse,
                vec!["TM_KEY".to_string(), login.clone(), k.params, k.pska],
                true,
            )?;
            return Ok(());
        }

        if self.delegation_check(state, &clearance)? {
            self.publish(
                &self.tm_id,
                &frame.src,
                D3csRequest::DelegateAccept,
                vec![
                    login,
                    serde_json::to_string(&clearance)?,
                    user_topic,
                    tm_topic,
                ],
                true,
            )?;
        }

        Ok(())
    }

    // permet de traiter la trame DELEGATE_ACCEPT
    fn on_delegate_accept(&self, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let login = normalize_login(&frame.args[0]);
        let clearance: Clearance = serde_json::from_str(&frame.args[1])?;
        if let Ok(mut p) = self.pending.lock() {
            let e = p.entry(login.clone()).or_insert(PendingKey {
                login,
                clearance,
                user_topic: frame.args.get(2).cloned().unwrap_or_default(),
                tm_topic: frame.args.get(3).cloned().unwrap_or_default(),
                asked_at: Instant::now(),
                delegate_from: None,
                delegate_at: None,
                asked_delegate: false,
                authority_done: false,
                user_done: false,
                tm_done: false,
            });
            e.delegate_from = Some(frame.src.clone());
            e.delegate_at = Some(Instant::now());
        }
        Ok(())
    }

    // permet de traiter la trame ASK_DELEGATION
    fn on_ask_delegation(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let login = normalize_login(&frame.args[0]);
        let clearance: Clearance = serde_json::from_str(&frame.args[1])?;
        if !self.delegation_check(state, &clearance)? {
            return Ok(());
        }

        let delegator =
            tm_to_login(&self.tm_id).ok_or_else(|| anyhow!("Cannot map TM to delegator"))?;
        let pp: cpabe::PublicParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/pp.bin", state.tm_dir))?)?;
        let params: abs::AbsParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/params.bin", state.tm_dir))?)?;
        let psks_in: cpabe::PsksV1 = serde_json::from_str(&fs::read_to_string(format!(
            "{}/{}/psks{}.bin",
            state.users_dir, delegator, delegator
        ))?)?;
        let pska_in: cpabe::PskaV1 = serde_json::from_str(&fs::read_to_string(format!(
            "{}/pska/pska{}.bin",
            state.tm_dir, delegator
        ))?)?;

        let attrs = attrs_from_clearance(&clearance);
        let (psks_out, tk) = cpabe::delegate(&pp, &psks_in, &attrs)?;
        let pska_out = cpabe::tm_delegate(&pska_in, &tk)?;
        write_atomic_text(
            &format!("{}/{}/tk{}.bin", state.users_dir, delegator, login),
            &serde_json::to_string(&tk)?,
        )?;

        let user_topic = frame
            .args
            .get(2)
            .cloned()
            .unwrap_or_else(|| login_to_user_topic(&login));
        let tm_topic = frame
            .args
            .get(3)
            .cloned()
            .unwrap_or_else(|| tm_for_login(&login).unwrap_or_else(|| self.tm_id.clone()));

        self.publish(
            &delegator.to_ascii_uppercase(),
            &user_topic,
            D3csRequest::KeyResponse,
            vec![
                "USER_DELEGATION".to_string(),
                login.clone(),
                serde_json::to_string(&pp)?,
                serde_json::to_string(&psks_out)?,
            ],
            true,
        )?;
        self.publish(
            &self.tm_id,
            &tm_topic,
            D3csRequest::KeyResponse,
            vec![
                "TM_KEY".to_string(),
                login,
                serde_json::to_string(&params)?,
                serde_json::to_string(&pska_out)?,
            ],
            true,
        )?;
        Ok(())
    }

    // permet de traiter la trame KEY_RESPONSE
    fn on_key_response(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let kind = frame.args[0].as_str();
        let login = normalize_login(&frame.args[1]);
        match kind {
            "USER_KEYGEN" => {
                if frame.args.len() >= 5 {
                    self.store_user_payload(
                        state,
                        &login,
                        &frame.args[2],
                        &frame.args[3],
                        Some(&frame.args[4]),
                    )?;
                    self.mark_pending(&login, &frame.src, true, false);
                }
            }
            "USER_DELEGATION" => {
                if frame.args.len() >= 4 {
                    self.store_user_payload(state, &login, &frame.args[2], &frame.args[3], None)?;
                    self.mark_pending(&login, &frame.src, true, false);
                }
            }
            "USER_ABS_SYNC" => {
                if frame.args.len() >= 3 {
                    self.store_abs_only(state, &login, &frame.args[2])?;
                    self.mark_pending(&login, &frame.src, true, false);
                }
            }
            "TM_KEY" => {
                if frame.args.len() >= 4 {
                    self.store_tm_payload(state, &login, &frame.args[2], &frame.args[3])?;
                    self.mark_pending(&login, &frame.src, false, true);
                }
            }
            _ => {}
        }
        Ok(())
    }

    // permet de traiter la trame CT_SHARE
    fn on_ct_share(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 3 {
            return Ok(());
        }
        let id = frame.args[0].parse::<u64>().unwrap_or(0);
        if id == 0 {
            return Ok(());
        }
        let ct: cpabe::CiphertextV1 = serde_json::from_str(&frame.args[1])?;
        let sig: abs::AbsSignatureV1 = serde_json::from_str(&frame.args[2])?;
        let params: abs::AbsParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/params.bin", state.tm_dir))?)?;
        let ct_ser = serde_json::to_string(&ct)?;
        if !abs::verify_any(&params, &sig, ct_ser.as_bytes())? {
            return Ok(());
        }
        let ct_path = format!("{}/{}.ct", self.ct_dir(state), id);
        let sig_path = format!("{}/{}.sign", self.sig_dir(state), id);
        if !Path::new(&ct_path).exists() {
            write_atomic_text(&ct_path, &frame.args[1])?;
        }
        if !Path::new(&sig_path).exists() {
            write_atomic_text(&sig_path, &frame.args[2])?;
        }
        Ok(())
    }

    // permet de traiter la trame REVOKE
    fn on_revoke(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.is_empty() || !(self.is_authority || self.tm_id == "TM0") {
            return Ok(());
        }
        let mission = frame.args[0].clone();
        let arl = self.append_arl(state, &mission)?;
        self.publish(
            "TM0",
            "TM",
            D3csRequest::ArlUpdate,
            vec![serde_json::to_string(&arl)?],
            true,
        )
    }

    // permet de traiter la trame ASK_REVOCATION
    fn on_ask_revocation(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if !self.is_authority || frame.args.len() < 2 {
            return Ok(());
        }
        let requester = frame.args[0].clone();
        let missions: Vec<String> = serde_json::from_str(&frame.args[1]).unwrap_or_default();
        if missions.is_empty() {
            return Ok(());
        }
        let mut queue = state
            .pending_revocations
            .lock()
            .map_err(|_| anyhow!("Revocation queue error"))?;
        let next_id = queue.iter().map(|x| x.id).max().unwrap_or(0) + 1;
        queue.push(PendingRevocation {
            id: next_id,
            requester: requester.clone(),
            missions: missions.clone(),
        });
        self.notify(format!("ASK_REVOCATION from {requester}"));
        Ok(())
    }

    // permet de traiter la trame ARL_UPDATE
    fn on_arl_update(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.is_empty() {
            return Ok(());
        }
        let arl: RevocationList = serde_json::from_str(&frame.args[0])?;
        self.update_arl(state, &arl)
    }

    // permet de traiter la trame SYNCHRONIZE
    fn on_synchronize(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let incoming_pska: Vec<PskaEntry> =
            serde_json::from_str(&frame.args[0]).unwrap_or_default();
        let incoming_ct: Vec<CtEntry> = serde_json::from_str(&frame.args[1]).unwrap_or_default();

        self.update_pska(state, &incoming_pska)?;
        self.store_ct_entries(state, &incoming_ct)?;

        let incoming_names = incoming_pska
            .iter()
            .map(|x| x.name.clone())
            .collect::<HashSet<_>>();
        let local = self.read_pska_entries(state)?;
        let diff = local
            .into_iter()
            .filter(|x| !incoming_names.contains(&x.name))
            .collect::<Vec<_>>();
        if !diff.is_empty() {
            self.publish(
                &self.tm_id,
                &frame.src,
                D3csRequest::PskaSync,
                vec![serde_json::to_string(&diff)?],
                false,
            )?;
        }
        Ok(())
    }

    // permet de traiter la trame PSKA_SYNC
    fn on_pska_sync(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.is_empty() {
            return Ok(());
        }
        let diff: Vec<PskaEntry> = serde_json::from_str(&frame.args[0]).unwrap_or_default();
        self.update_pska(state, &diff)?;
        if self.is_authority {
            for p in diff {
                if let Some(login) = login_from_pska_file(&p.name) {
                    self.extract_abs_after_sync(state, &login)?;
                    self.new_user_alert(&login);
                }
            }
        }
        Ok(())
    }

    // permet de gérer les demandes de clé en attente
    fn process_pending(&self, state: &Arc<AppState>) -> Result<()> {
        let authority_present = self.manager.is_node_present("Authority").unwrap_or(false)
            || self.authority_reachable();
        let delay = if authority_present {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(300)
        };
        let mut ask = Vec::new();

        if let Ok(mut p) = self.pending.lock() {
            for it in p.values_mut() {
                if it.authority_done || it.asked_delegate {
                    continue;
                }
                if let (Some(tm), Some(ts)) = (it.delegate_from.clone(), it.delegate_at) {
                    if ts.elapsed() >= delay {
                        ask.push((
                            tm,
                            it.login.clone(),
                            it.clearance.clone(),
                            it.user_topic.clone(),
                            it.tm_topic.clone(),
                        ));
                        it.asked_delegate = true;
                    }
                }
            }
            p.retain(|_, v| {
                !(v.user_done && v.tm_done) && v.asked_at.elapsed() < Duration::from_secs(120)
            });
        }

        for (tm, login, clr, ut, tt) in ask {
            self.publish(
                &self.tm_id,
                &tm,
                D3csRequest::AskDelegation,
                vec![login, serde_json::to_string(&clr)?, ut, tt],
                true,
            )?;
        }

        if self.tm_id == "TM0" {
            let _ = self.send_synchronize(state);
        }

        Ok(())
    }

    // lorsque l'autorité rejoint un groupe, elle doit livrer les clés ABS manquantes
    // aux utilisateurs déjà sign up présents dans ce même groupe
    fn sync_missing_abs_keys(&self, state: &Arc<AppState>) -> Result<()> {
        if !self.is_authority {
            return Ok(());
        }

        let current_group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        let now = Instant::now();
        let retry_delay = Duration::from_secs(2);
        let mut to_sync = Vec::new();

        {
            let mut attempts = self
                .abs_sync_attempts
                .lock()
                .map_err(|_| anyhow!("ABS sync attempts lock poisoned"))?;

            for (login, _) in signed_up_users(state) {
                let user_topic = login_to_user_topic(&login);
                let user_group = self.manager.current_group_of(&user_topic).ok().flatten();
                if user_group.as_deref() != Some(current_group.as_str()) {
                    continue;
                }

                let abs_key_path = format!("{}/{}/skw{}.bin", state.users_dir, login, login);
                if Path::new(&abs_key_path).exists() {
                    attempts.remove(&login);
                    continue;
                }

                let should_send = attempts
                    .get(&login)
                    .map(|last| last.elapsed() >= retry_delay)
                    .unwrap_or(true);
                if should_send {
                    attempts.insert(login.clone(), now);
                    to_sync.push(login);
                }
            }
        }

        for login in to_sync {
            self.extract_abs_after_sync(state, &login)?;
        }

        Ok(())
    }

    // permet d'envoyer un message SYNCHRONIZE à tous les autres TMs
    fn send_synchronize(&self, state: &Arc<AppState>) -> Result<()> {
        let pskas = self.read_pska_entries(state)?;
        let cts = self.read_ct_entries(state)?;
        self.publish(
            &self.tm_id,
            "TM",
            D3csRequest::Synchronize,
            vec![serde_json::to_string(&pskas)?, serde_json::to_string(&cts)?],
            false,
        )
    }

    // permet de lancer ABE.Keygen et ABS.extract
    fn authority_keygen(
        &self,
        state: &Arc<AppState>,
        login: &str,
        clearance: &Clearance,
    ) -> Result<AuthorityKeys> {
        let pp: cpabe::PublicParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/pp.bin", state.tm_dir))?)?;
        let msk: cpabe::MasterKeyV1 = serde_json::from_str(&fs::read_to_string(format!(
            "{}/msk.bin",
            state.authority_dir
        ))?)?;
        let params: abs::AbsParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/params.bin", state.tm_dir))?)?;
        let abs_sk: abs::AbsMasterKeyV1 = serde_json::from_str(&fs::read_to_string(format!(
            "{}/sk.bin",
            state.authority_dir
        ))?)?;

        let attrs = attrs_from_clearance(clearance);
        let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs)?;
        let skw = abs::extract(&params, &abs_sk, &clearance.classification)?;

        let pp_s = serde_json::to_string(&pp)?;
        let params_s = serde_json::to_string(&params)?;
        let pska_s = serde_json::to_string(&pska)?;
        let psks_s = serde_json::to_string(&psks)?;
        let skw_s = serde_json::to_string(&skw)?;

        self.store_user_payload(state, login, &pp_s, &psks_s, Some(&skw_s))?;
        self.store_tm_payload(state, login, &params_s, &pska_s)?;

        Ok(AuthorityKeys {
            pp: pp_s,
            params: params_s,
            pska: pska_s,
            psks: psks_s,
            skw: skw_s,
        })
    }

    // envoi de la clé ABS après synchronisation (lorsque l'autorité était inaccessible)
    fn extract_abs_after_sync(&self, state: &Arc<AppState>, login: &str) -> Result<()> {
        let Some(classif) = self.get_classification_attribute(state, login) else {
            return Ok(());
        };
        let params: abs::AbsParamsV1 =
            serde_json::from_str(&fs::read_to_string(format!("{}/params.bin", state.tm_dir))?)?;
        let abs_sk: abs::AbsMasterKeyV1 = serde_json::from_str(&fs::read_to_string(format!(
            "{}/sk.bin",
            state.authority_dir
        ))?)?;
        let skw = abs::extract(&params, &abs_sk, &classif)?;
        self.publish(
            "Authority",
            &login_to_user_topic(login),
            D3csRequest::KeyResponse,
            vec![
                "USER_ABS_SYNC".to_string(),
                login.to_string(),
                serde_json::to_string(&skw)?,
            ],
            true,
        )
    }

    // lecture de toutes les PSKA stockées côté TM avant de faire une synchronisation
    fn read_pska_entries(&self, state: &Arc<AppState>) -> Result<Vec<PskaEntry>> {
        let mut out = Vec::new();
        let dir = format!("{}/pska", state.tm_dir);
        if !Path::new(&dir).exists() {
            return Ok(out);
        }
        for e in fs::read_dir(dir)? {
            let e = e?;
            if !e.file_type()?.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".bin") {
                continue;
            }
            let data = fs::read_to_string(e.path())?;
            if data.trim().is_empty() {
                continue;
            }
            out.push(PskaEntry { name, data });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    // lecture de tous les chiffrés avant de faire une synchronisation
    fn read_ct_entries(&self, state: &Arc<AppState>) -> Result<Vec<CtEntry>> {
        let mut out = Vec::new();
        let ct_dir = self.ct_dir(state);
        if !Path::new(&ct_dir).exists() {
            return Ok(out);
        }
        for e in fs::read_dir(&ct_dir)? {
            let e = e?;
            if !e.file_type()?.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".ct") {
                continue;
            }
            let Ok(id) = name.trim_end_matches(".ct").parse::<u64>() else {
                continue;
            };
            let sig_path = format!("{}/{}.sign", self.sig_dir(state), id);
            if !Path::new(&sig_path).exists() {
                continue;
            }
            let ciphertext = fs::read_to_string(e.path())?;
            let signature = fs::read_to_string(sig_path)?;
            if ciphertext.trim().is_empty() || signature.trim().is_empty() {
                continue;
            }
            out.push(CtEntry {
                id,
                ciphertext,
                signature,
            });
        }
        out.sort_by_key(|x| x.id);
        Ok(out)
    }

    // stockage local des chiffrés lors d'une synchronisation réseau
    fn store_ct_entries(&self, state: &Arc<AppState>, items: &[CtEntry]) -> Result<()> {
        fs::create_dir_all(self.ct_dir(state))?;
        fs::create_dir_all(self.sig_dir(state))?;
        for i in items {
            let ct_path = format!("{}/{}.ct", self.ct_dir(state), i.id);
            let sig_path = format!("{}/{}.sign", self.sig_dir(state), i.id);
            if !Path::new(&ct_path).exists() {
                if !i.ciphertext.trim().is_empty() {
                    write_atomic_text(&ct_path, &i.ciphertext)?;
                }
            }
            if !Path::new(&sig_path).exists() {
                if !i.signature.trim().is_empty() {
                    write_atomic_text(&sig_path, &i.signature)?;
                }
            }
        }
        Ok(())
    }

    // écrit localement les clés reçues par un utilisateur suite à un keygen
    fn store_user_payload(
        &self,
        state: &Arc<AppState>,
        login: &str,
        pp: &str,
        psks: &str,
        skw: Option<&str>,
    ) -> Result<()> {
        if pp.trim().is_empty() || psks.trim().is_empty() {
            return Err(anyhow!("Invalid empty user key payload"));
        }
        let user_dir = format!("{}/{}", state.users_dir, login);
        fs::create_dir_all(&user_dir)?;
        write_atomic_text(&format!("{}/pp.bin", user_dir), pp)?;
        write_atomic_text(&format!("{}/psks{}.bin", user_dir, login), psks)?;
        if let Some(v) = skw {
            if v.trim().is_empty() {
                return Err(anyhow!("Invalid empty ABS key payload"));
            }
            write_atomic_text(&format!("{}/skw{}.bin", user_dir, login), v)?;
        }
        Ok(())
    }

    // stockage de la clé secrète ABS suite à un transfert de l'autorité (suite à la reconnexion)
    fn store_abs_only(&self, state: &Arc<AppState>, login: &str, skw: &str) -> Result<()> {
        if skw.trim().is_empty() {
            return Err(anyhow!("Invalid empty ABS key payload"));
        }
        let user_dir = format!("{}/{}", state.users_dir, login);
        fs::create_dir_all(&user_dir)?;
        write_atomic_text(&format!("{}/skw{}.bin", user_dir, login), skw)?;
        Ok(())
    }

    // enregistement des clés ABS.params et PSKA dans le dossier TM
    fn store_tm_payload(
        &self,
        state: &Arc<AppState>,
        login: &str,
        params: &str,
        pska: &str,
    ) -> Result<()> {
        if params.trim().is_empty() || pska.trim().is_empty() {
            return Err(anyhow!("Invalid empty TM key payload"));
        }
        write_atomic_text(&format!("{}/params.bin", state.tm_dir), params)?;
        write_atomic_text(&format!("{}/pska/pska{}.bin", state.tm_dir, login), pska)?;
        Ok(())
    }

    // permet de marquer l'avancement d'une demande de clés en attente
    fn mark_pending(&self, login: &str, source: &str, user_done: bool, tm_done: bool) {
        if let Ok(mut p) = self.pending.lock() {
            if let Some(e) = p.get_mut(login) {
                if source.eq_ignore_ascii_case("Authority") {
                    e.authority_done = true;
                }
                if user_done {
                    e.user_done = true;
                }
                if tm_done {
                    e.tm_done = true;
                }
            }
        }
    }

    // retourne si la trame est pertinente ou non à traiter par le runtime actuel
    fn is_relevant(&self, frame: &D3csFrame) -> bool {
        if frame.dst == "TM" {
            return true;
        }
        if frame.dst == self.tm_id || frame.dst == self.node_id {
            return true;
        }
        if frame.dst.eq_ignore_ascii_case("Authority") {
            return self.is_authority;
        }
        self.manager.subscriptions().iter().any(|x| x == &frame.dst)
    }

    // permet de publier une trame sur le réseau (secured ou non)
    fn publish(
        &self,
        src: &str,
        dst: &str,
        req: D3csRequest,
        args: Vec<String>,
        secured: bool,
    ) -> Result<()> {
        let frame = D3csFrame::new(src, dst, req, args).with_secured(secured);
        if secured {
            self.manager.publish_secured(&frame)
        } else {
            self.manager.publish(&frame)
        }
    }

    // permet au runtime de s'abonner aux topics essentiels (e.g., TM associé)
    fn subscribe_core(&self) -> Result<()> {
        self.manager.subscribe("TM")?;
        self.manager.subscribe(&self.tm_id)?;
        self.manager.subscribe(&self.node_id)?;
        if self.is_authority {
            self.manager.subscribe("Authority")?;
            self.manager.subscribe("TM0")?;
        }
        Ok(())
    }

    // log de la liste des messages en mémoire
    fn notify(&self, msg: String) {
        if let Ok(mut n) = self.notifications.lock() {
            n.push(msg);
            if n.len() > 100 {
                let start = n.len() - 100;
                *n = n[start..].to_vec();
            }
        }
    }

    // prend les dernières notifications en mémoire
    fn latest_notifications(&self) -> Vec<String> {
        self.notifications
            .lock()
            .map(|n| {
                if n.len() <= 20 {
                    n.clone()
                } else {
                    n[n.len() - 20..].to_vec()
                }
            })
            .unwrap_or_default()
    }

    // retourne si l'autorité est accessible ou non
    fn authority_reachable(&self) -> bool {
        if self.is_authority {
            return true;
        }
        let current_group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        self.authority_seen
            .lock()
            .ok()
            .and_then(|x| x.clone())
            .map(|(seen_group, t)| {
                seen_group == current_group && t.elapsed() < Duration::from_secs(20)
            })
            .unwrap_or(false)
    }

    // liste les autres noeuds visibles dans le même groupe réseau que le noeud courant
    fn connected_nodes(&self, state: &Arc<AppState>) -> Vec<ConnectedNode> {
        let current_group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        let mut out = Vec::new();

        if !self.node_id.eq_ignore_ascii_case("Authority") {
            let authority_group = self.manager.current_group_of("Authority").ok().flatten();
            if authority_group.as_deref() == Some(current_group.as_str()) {
                out.push(ConnectedNode {
                    name: "Authority".to_string(),
                    classification: None,
                    mission: None,
                    is_authority: true,
                });
            }
        }

        for (login, clearance) in signed_up_users(state) {
            let node_id = login_to_user_topic(&login);
            if node_id.eq_ignore_ascii_case(&self.node_id) {
                continue;
            }
            let node_group = self.manager.current_group_of(&node_id).ok().flatten();
            if node_group.as_deref() != Some(current_group.as_str()) {
                continue;
            }
            out.push(ConnectedNode {
                name: login,
                classification: Some(clearance.classification),
                mission: Some(clearance.mission),
                is_authority: false,
            });
        }

        out.sort_by(|a, b| connected_node_sort_key(a).cmp(&connected_node_sort_key(b)));
        out
    }

    // retourne le répertoire des chiffrés
    fn ct_dir(&self, state: &Arc<AppState>) -> String {
        let group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        format!("{}/groups/{}/ct", state.tm_dir, group)
    }

    // retourne le répertoire des signatures
    fn sig_dir(&self, state: &Arc<AppState>) -> String {
        let group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        format!("{}/groups/{}/s", state.tm_dir, group)
    }

    // retourne le répertoire des chiffrés intermédiaires
    fn cti_dir(&self, state: &Arc<AppState>) -> String {
        let group = self.manager.group().unwrap_or_else(|_| "Net1".to_string());
        format!("{}/groups/{}/ct_intermediate", state.tm_dir, group)
    }
}

#[derive(Clone)]
struct AuthorityKeys {
    pp: String,
    params: String,
    pska: String,
    psks: String,
    skw: String,
}

// met l'identifiant du noeud courant dans un format standard
fn normalize_node(node: &str) -> String {
    if node.eq_ignore_ascii_case("authority") {
        "Authority".to_string()
    } else {
        node.to_ascii_uppercase()
    }
}

// met les login en format standard (minuscules)
fn normalize_login(login: &str) -> String {
    if let Some(r) = login.strip_prefix('U') {
        format!("u{r}")
    } else {
        login.to_ascii_lowercase()
    }
}

// indique le niveau de classification
fn level(c: &str) -> i32 {
    if c == "FR-S" {
        1
    } else {
        0
    }
}

// renvoie si la classification est délégable ou non
fn is_delegable_classification(c: &str) -> bool {
    matches!(c, "FR-S" | "FR-DR")
}

// renvoie le TM associé au noeud courant
fn tm_for_node(node: &str) -> String {
    if node.eq_ignore_ascii_case("Authority") {
        "TM0".to_string()
    } else if let Some(r) = node.strip_prefix('U') {
        format!("TM{r}")
    } else {
        "TM0".to_string()
    }
}

// permet de renvoyer le TM d'un login utilisateur
fn tm_for_login(login: &str) -> Option<String> {
    let r = login.to_ascii_lowercase().strip_prefix('u')?.to_string();
    if r.chars().all(|c| c.is_ascii_digit()) {
        Some(format!("TM{r}"))
    } else {
        None
    }
}

// récupère le login associé à un TM
fn tm_to_login(tm: &str) -> Option<String> {
    let r = tm.to_ascii_uppercase().strip_prefix("TM")?.to_string();
    if r == "0" || !r.chars().all(|c| c.is_ascii_digit()) {
        None
    } else {
        Some(format!("u{r}"))
    }
}

// permet de transformer un login utilisateur en topic réseau
fn login_to_user_topic(login: &str) -> String {
    if login.eq_ignore_ascii_case("admin") {
        "Authority".to_string()
    } else if let Some(r) = login.to_ascii_lowercase().strip_prefix('u') {
        if r.chars().all(|c| c.is_ascii_digit()) {
            return format!("U{r}");
        }
        login.to_string()
    } else {
        login.to_string()
    }
}

// renvoie les attributs correspondant à une clearance
fn attrs_from_clearance(c: &Clearance) -> Vec<String> {
    let mut v = if c.classification == "FR-S" {
        vec!["FR-S".to_string(), "FR-DR".to_string()]
    } else {
        vec!["FR-DR".to_string()]
    };
    v.push(c.mission.clone());
    v.sort();
    v.dedup();
    v
}

// permet de retourner un login en fonction de la pska associée
fn login_from_pska_file(name: &str) -> Option<String> {
    if !name.starts_with("pska") || !name.ends_with(".bin") {
        return None;
    }
    let base = name.trim_start_matches("pska").trim_end_matches(".bin");
    if base.is_empty() {
        None
    } else {
        Some(normalize_login(base))
    }
}

fn signed_up_users(state: &Arc<AppState>) -> Vec<(String, Clearance)> {
    #[derive(Deserialize)]
    struct SignupToken {
        classification: String,
        mission: String,
    }

    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&state.users_dir) else {
        return out;
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let login = normalize_login(&entry.file_name().to_string_lossy());
        if login == "admin" {
            continue;
        }

        let token_path = entry.path().join("token.json");
        let Ok(raw) = fs::read_to_string(token_path) else {
            continue;
        };
        let Ok(token) = serde_json::from_str::<SignupToken>(&raw) else {
            continue;
        };

        out.push((
            login,
            Clearance {
                classification: token.classification,
                mission: token.mission,
            },
        ));
    }

    out.sort_by(|a, b| user_sort_key(&a.0).cmp(&user_sort_key(&b.0)));
    out
}

fn connected_node_sort_key(node: &ConnectedNode) -> (u8, u16, String) {
    if node.is_authority {
        return (0, 0, String::new());
    }
    (
        1,
        user_numeric_suffix(&node.name).unwrap_or(u16::MAX),
        node.name.clone(),
    )
}

fn user_sort_key(login: &str) -> (u16, String) {
    (
        user_numeric_suffix(login).unwrap_or(u16::MAX),
        login.to_string(),
    )
}

fn user_numeric_suffix(login: &str) -> Option<u16> {
    let suffix = login.to_ascii_lowercase().strip_prefix('u')?.to_string();
    if suffix.chars().all(|c| c.is_ascii_digit()) {
        suffix.parse::<u16>().ok()
    } else {
        None
    }
}

// permet d'écrire d'une manière sûre dans un fichier pour éviter que le programme plante pendant l'écriture
fn write_atomic_text(path: &str, data: &str) -> Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = format!("{path}.tmp.{}.{}", std::process::id(), nonce);
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    let _ = fs::remove_file(&tmp_path);
    Ok(())
}
