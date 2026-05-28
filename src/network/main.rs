// logique réseau haut niveau -> notamment une fonction traitant chaque requête

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[path = "dodwan.rs"]
pub mod dodwan;
#[path = "netmanager.rs"]
pub mod netmanager;
#[path = "packets.rs"]
pub mod packets;

use crate::crypto::{self, abs, cpabe, DocumentLabel, RevocationList};
use crate::{AppState, Clearance, PendingRevocation, AUTHORITY_LOGIN};

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
    authority_seen: Mutex<Option<Instant>>,
}

// implémentation permettant de créer et initialiser le runtime réseau d'un noeud

impl NetworkRuntime {
    // new -> initialisation pour un noeud réseau
    pub fn new(_state: &Arc<AppState>, node_id: &str) -> Result<Self> {
        let runtime_dir = std::env::var("D3CS_NETWORK_DIR")
            .unwrap_or_else(|_| "src/network/logs/runtime".to_string());
        let node_id = normalize_node(node_id);
        let tm_id = std::env::var("D3CS_TM_ID").unwrap_or_else(|_| tm_for_node(&node_id));
        let is_authority = node_id.eq_ignore_ascii_case("Authority");

        let manager = NetworkManager::new(&node_id, &runtime_dir)?;
        manager.join()?;
        manager.subscribe("TM")?;
        manager.subscribe("User")?;
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
        let pending = self.pending.lock().ok().and_then(|p| p.get(login).cloned());
        let pending_key_delivery = pending
            .map(|x| !(x.user_done && x.tm_done))
            .unwrap_or(false);
        let user_dir = format!("{}/{}", state.users_dir, login);
        let has_public_params = Path::new(&format!("{}/pp.bin", user_dir)).exists();
        let has_user_secret_key = Path::new(&format!("{}/psks{}.bin", user_dir, login)).exists();
        let has_tm_delegate_key = crypto::pska_path_for_login(state, login).exists();
        let has_abs_key = Path::new(&format!("{}/skw{}.bin", user_dir, login)).exists();

        NetworkStatus {
            enabled: true,
            node_id: self.node_id.clone(),
            tm_id: self.tm_id.clone(),
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
        let document = crypto::get_document_payload(state, doc_id)?
            .ok_or_else(|| anyhow!("Document not found"))?;
        self.publish(
            &self.tm_id,
            "TM",
            D3csRequest::CtShare,
            vec![doc_id.to_string(), document.ciphertext, document.signature],
            false,
        )
    }

    pub fn broadcast_arl_update(&self, arl: &RevocationList) -> Result<()> {
        self.publish(
            "Authority",
            "TM",
            D3csRequest::ArlUpdate,
            vec![serde_json::to_string(arl)?],
            true,
        )
    }

    pub fn send_arl_update_to_login(&self, login: &str, arl: &RevocationList) -> Result<()> {
        let login = normalize_login(login);
        let dst = tm_for_login(&login).unwrap_or_else(|| login_to_user_topic(&login));
        self.publish(
            "Authority",
            &dst,
            D3csRequest::ArlUpdate,
            vec![serde_json::to_string(arl)?],
            true,
        )
    }

    // regarde si une mission n'est pas déjà révoquée dans l'ARL
    pub fn check_arl(&self, state: &Arc<AppState>, mission: &str) -> Result<bool> {
        crypto::mission_revoked(state, mission)
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
        crypto::revoke_missions(state, &[mission.to_string()])
    }

    // permet de remplacer l'ARL locale par une nouvelle ARL (e.g. lorsqu'un TM d'un utilisateur se
    // voit modififer son ARL via une update de la part de l'autorité)
    pub fn update_arl(&self, state: &Arc<AppState>, new_arl: &RevocationList) -> Result<()> {
        crypto::update_arl(state, new_arl)
    }

    // crée le fichier ARL s'il n'existe pas encore
    pub fn setup_arl(&self, state: &Arc<AppState>) -> Result<()> {
        let _ = crypto::get_arl(state)?;
        Ok(())
    }

    // crée le répertoire des clés TM
    pub fn setup_storage(&self, state: &Arc<AppState>) -> Result<()> {
        crypto::ensure_document_storage_dirs(state)?;
        Ok(())
    }

    // initialisation des presets BLP/Biba
    pub fn setup_presets(&self, state: &Arc<AppState>) -> Result<()> {
        let _ = crypto::get_presets(state)?;
        Ok(())
    }

    // mise à jour des PSKA, requête initiée par l'autorité
    pub fn update_pska(&self, state: &Arc<AppState>, diff: &[PskaEntry]) -> Result<()> {
        for e in diff {
            if e.data.trim().is_empty() {
                continue;
            }
            let Some(login) = login_from_pska_file(&e.name) else {
                continue;
            };
            if let Some(clearance) = self.get_user_clearance(state, &login) {
                if self.check_arl(state, &clearance.mission)? {
                    continue;
                }
            }
            crypto::write_pska_for_login(state, &login, &e.data)?;
        }
        Ok(())
    }

    // récupère la classification d'un utilisateur depuis la base d'utilisateurs
    pub fn get_user_clearance(&self, state: &Arc<AppState>, login: &str) -> Option<Clearance> {
        #[derive(Deserialize)]
        struct UserToken {
            classification: String,
            mission: String,
        }

        let login = normalize_login(login);

        if let Ok(db) = state.user_db.lock() {
            if let Some(user) = db.users.get(&login) {
                return Some(user.clearance.clone());
            }
        }

        let token_path = format!("{}/{}/token.json", state.users_dir, login);
        let raw = fs::read_to_string(token_path).ok()?;
        let token: UserToken = serde_json::from_str(&raw).ok()?;
        Some(Clearance {
            classification: token.classification,
            mission: token.mission,
        })
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
    pub fn ask_revocation_request(
        &self,
        request_id: u64,
        requester: &str,
        missions: &[String],
    ) -> Result<()> {
        let missions = normalize_revocation_missions(missions);
        let request_key =
            revocation_request_key(requester, &missions, Some(&request_id.to_string()));
        self.publish(
            &self.tm_id,
            "TM",
            D3csRequest::AskRevocation,
            vec![
                requester.to_string(),
                serde_json::to_string(&missions)?,
                request_key,
            ],
            true,
        )
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
                *s = Some(Instant::now());
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
            if self.check_arl(state, &clearance.mission)? {
                let arl = crypto::get_arl(state)?;
                self.send_arl_update_to_login(&login, &arl)?;
                self.notify(format!(
                    "KEY_REQUEST denied for {login}: mission {} revoked",
                    clearance.mission
                ));
                return Ok(());
            }
            self.send_authority_keygen_response(state, &login, &clearance, &user_topic, &tm_topic)?;
            return Ok(());
        }

        if self.delegation_check(state, &clearance)? {
            self.publish_on_topic(
                "TM",
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
        let pska_in: cpabe::PskaV1 =
            serde_json::from_str(&crypto::read_pska_for_login(state, &delegator)?)?;

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

        self.publish_on_topic(
            "User",
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
        self.publish_on_topic(
            "TM",
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
        if crypto::get_document_payload(state, id)?.is_some() {
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
        crypto::store_document_payload(state, id, frame.args[1].clone(), frame.args[2].clone())?;
        Ok(())
    }

    // permet de traiter la trame REVOKE
    fn on_revoke(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.is_empty() || !(self.is_authority || self.tm_id == "TM0") {
            return Ok(());
        }
        let mission = frame.args[0].clone();
        let arl = self.append_arl(state, &mission)?;
        self.broadcast_arl_update(&arl)
    }

    // permet de traiter la trame ASK_REVOCATION
    fn on_ask_revocation(&self, state: &Arc<AppState>, frame: &D3csFrame) -> Result<()> {
        if frame.args.len() < 2 {
            return Ok(());
        }
        let requester = frame.args[0].clone();
        let missions_raw: Vec<String> = serde_json::from_str(&frame.args[1]).unwrap_or_default();
        let missions = normalize_revocation_missions(&missions_raw);
        if missions.is_empty() {
            return Ok(());
        }
        if !self.is_authority {
            return Ok(());
        }
        let mut queue = state
            .pending_revocations
            .lock()
            .map_err(|_| anyhow!("Revocation queue error"))?;
        if queue
            .iter()
            .any(|r| same_pending_revocation(r, &requester, &missions))
        {
            return Ok(());
        }
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
        if frame.src.eq_ignore_ascii_case("Authority") || frame.src == "TM0" {
            if let Some(raw_arl) = frame.args.get(2) {
                if let Ok(arl) = serde_json::from_str::<RevocationList>(raw_arl) {
                    self.update_arl(state, &arl)?;
                }
            }
        }

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
        Ok(())
    }

    // permet de gérer les demandes de clé en attente
    fn process_pending(&self, _state: &Arc<AppState>) -> Result<()> {
        let authority_present = self.authority_reachable();
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
            self.publish_on_topic(
                "TM",
                &self.tm_id,
                &tm,
                D3csRequest::AskDelegation,
                vec![login, serde_json::to_string(&clr)?, ut, tt],
                true,
            )?;
        }

        Ok(())
    }

    // permet d'envoyer un message SYNCHRONIZE à tous les autres TMs
    // permet de lancer ABE.Keygen et ABS.extract
    fn send_authority_keygen_response(
        &self,
        state: &Arc<AppState>,
        login: &str,
        clearance: &Clearance,
        user_topic: &str,
        tm_topic: &str,
    ) -> Result<()> {
        let k = self.authority_keygen(state, clearance)?;
        self.publish_on_topic(
            "User",
            "Authority",
            user_topic,
            D3csRequest::KeyResponse,
            vec![
                "USER_KEYGEN".to_string(),
                login.to_string(),
                k.pp,
                k.psks,
                k.skw,
            ],
            true,
        )?;
        self.publish_on_topic(
            "TM",
            "Authority",
            tm_topic,
            D3csRequest::KeyResponse,
            vec!["TM_KEY".to_string(), login.to_string(), k.params, k.pska],
            true,
        )
    }

    fn authority_keygen(
        &self,
        state: &Arc<AppState>,
        clearance: &Clearance,
    ) -> Result<AuthorityKeys> {
        if self.check_arl(state, &clearance.mission)? {
            return Err(anyhow!(
                "Mission {} revoked in authority ARL",
                clearance.mission
            ));
        }

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

        Ok(AuthorityKeys {
            pp: pp_s,
            params: params_s,
            pska: pska_s,
            psks: psks_s,
            skw: skw_s,
        })
    }

    // lecture de toutes les PSKA stockées côté TM avant de faire une synchronisation
    fn read_pska_entries(&self, state: &Arc<AppState>) -> Result<Vec<PskaEntry>> {
        let mut out = Vec::new();
        let nodes_root = Path::new(&state.tm_dir).join("nodes");
        if !nodes_root.exists() {
            return Ok(out);
        }

        for node_entry in fs::read_dir(nodes_root)? {
            let node_entry = node_entry?;
            if !node_entry.file_type()?.is_dir() {
                continue;
            }
            for e in fs::read_dir(node_entry.path())? {
                let e = e?;
                if !e.file_type()?.is_file() {
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with("pska") || !name.ends_with(".bin") {
                    continue;
                }
                if let Some(login) = login_from_pska_file(&name) {
                    if let Some(clearance) = self.get_user_clearance(state, &login) {
                        if self.check_arl(state, &clearance.mission)? {
                            continue;
                        }
                    }
                }
                let data = fs::read_to_string(e.path())?;
                if data.trim().is_empty() {
                    continue;
                }
                out.push(PskaEntry { name, data });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    // lecture de tous les chiffrés avant de faire une synchronisation
    // stockage local des chiffrés lors d'une synchronisation réseau
    fn store_ct_entries(&self, state: &Arc<AppState>, items: &[CtEntry]) -> Result<()> {
        for i in items {
            if !i.ciphertext.trim().is_empty() && !i.signature.trim().is_empty() {
                let ct: cpabe::CiphertextV1 = match serde_json::from_str(&i.ciphertext) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if !self.ct_matches_local_access(state, &ct)? {
                    continue;
                }
                crypto::store_document_payload(
                    state,
                    i.id,
                    i.ciphertext.clone(),
                    i.signature.clone(),
                )?;
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
        crypto::write_pska_for_login(state, login, pska)?;
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

    fn publish_on_topic(
        &self,
        topic: &str,
        src: &str,
        dst: &str,
        req: D3csRequest,
        args: Vec<String>,
        secured: bool,
    ) -> Result<()> {
        let frame = D3csFrame::new(src, dst, req, args).with_secured(secured);
        if secured {
            self.manager.publish_secured_on_topic(topic, &frame)
        } else {
            self.manager.publish_on_topic(topic, &frame)
        }
    }

    // permet au runtime de s'abonner aux topics essentiels (e.g., TM associé)
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

    // retourne si l'autorite est accessible via les pairs directs DoDWAN.
    fn authority_reachable(&self) -> bool {
        if self.is_authority {
            return true;
        }
        if self
            .direct_neighbor_nodes()
            .iter()
            .any(|node| node.eq_ignore_ascii_case("Authority"))
        {
            return true;
        }
        self.authority_seen
            .lock()
            .ok()
            .and_then(|x| x.clone())
            .map(|t| t.elapsed() < Duration::from_secs(20))
            .unwrap_or(false)
    }

    fn ct_matches_local_access(
        &self,
        state: &Arc<AppState>,
        ct: &cpabe::CiphertextV1,
    ) -> Result<bool> {
        if self.is_authority {
            let Some((clearance, is_authority_user)) = user_record_snapshot(state, AUTHORITY_LOGIN)
            else {
                return Ok(false);
            };
            return crypto::document_label_accessible(
                state,
                &clearance,
                is_authority_user,
                &ct.label,
            );
        }

        let Some(login) = tm_to_login(&self.tm_id) else {
            return Ok(false);
        };
        let Some((clearance, is_authority_user)) = user_record_snapshot(state, &login) else {
            return Ok(false);
        };
        crypto::document_label_accessible(state, &clearance, is_authority_user, &ct.label)
    }

    // liste les autres noeuds visibles comme pairs directs par DoDWAN.
    fn connected_nodes(&self, _state: &Arc<AppState>) -> Vec<ConnectedNode> {
        self.connected_nodes_from_network_nodes(self.direct_neighbor_nodes())
    }

    fn direct_neighbor_nodes(&self) -> Vec<String> {
        let mut out = self
            .manager
            .peers()
            .into_iter()
            .filter_map(|peer| dodwan_peer_to_node(&peer))
            .filter(|node| !node.eq_ignore_ascii_case(&self.node_id))
            .collect::<Vec<_>>();

        out.sort_by(|a, b| node_sort_key(a).cmp(&node_sort_key(b)));
        out.dedup();
        out
    }

    // transforme les identifiants reseau en liste de noeuds sans exposer leurs attributs.
    fn connected_nodes_from_network_nodes(&self, network_nodes: Vec<String>) -> Vec<ConnectedNode> {
        let mut out = Vec::new();

        for node_id in network_nodes {
            if node_id.eq_ignore_ascii_case("Authority") {
                out.push(ConnectedNode {
                    name: "Authority".to_string(),
                    classification: None,
                    mission: None,
                    is_authority: true,
                });
                continue;
            }

            out.push(ConnectedNode {
                name: node_id,
                classification: None,
                mission: None,
                is_authority: false,
            });
        }

        out.sort_by(|a, b| connected_node_sort_key(a).cmp(&connected_node_sort_key(b)));
        out
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

fn dodwan_peer_to_node(peer_id: &str) -> Option<String> {
    let peer = peer_id.trim();
    if peer.eq_ignore_ascii_case("Authority")
        || peer.eq_ignore_ascii_case("N00")
        || peer.eq_ignore_ascii_case("TM0")
    {
        return Some("Authority".to_string());
    }

    let upper = peer.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix('U') {
        return app_user_node_from_suffix(rest);
    }
    if let Some(rest) = upper.strip_prefix("TM") {
        return app_user_node_from_suffix(rest);
    }
    if let Some(rest) = upper.strip_prefix('N') {
        return app_user_node_from_suffix(rest);
    }

    None
}

fn app_user_node_from_suffix(raw: &str) -> Option<String> {
    let idx = raw.parse::<u16>().ok()?;
    if (1..=9).contains(&idx) {
        Some(format!("U{idx}"))
    } else {
        None
    }
}

fn user_record_snapshot(state: &Arc<AppState>, login: &str) -> Option<(Clearance, bool)> {
    let login = normalize_login(login);
    state.user_db.lock().ok().and_then(|db| {
        db.users
            .get(&login)
            .map(|u| (u.clearance.clone(), u.is_authority_user))
    })
}

// permet de transformer un login utilisateur en topic réseau
fn login_to_user_topic(login: &str) -> String {
    if login.eq_ignore_ascii_case(AUTHORITY_LOGIN) {
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

fn normalize_revocation_missions(missions: &[String]) -> Vec<String> {
    let mut out = missions
        .iter()
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn same_pending_revocation(item: &PendingRevocation, requester: &str, missions: &[String]) -> bool {
    item.requester == requester
        && normalize_revocation_missions(&item.missions) == normalize_revocation_missions(missions)
}

fn revocation_request_key(
    requester: &str,
    missions: &[String],
    request_id: Option<&String>,
) -> String {
    if let Some(id) = request_id {
        if id.contains('|') {
            return id.clone();
        }
    }
    let id = request_id.map(String::as_str).unwrap_or("legacy");
    format!(
        "{}|{}|{}",
        id,
        requester,
        normalize_revocation_missions(missions).join(",")
    )
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

fn connected_node_sort_key(node: &ConnectedNode) -> (u8, u16, String) {
    if node.is_authority {
        return (0, 0, String::new());
    }
    node_sort_key(&node.name)
}

fn node_sort_key(node: &str) -> (u8, u16, String) {
    if node.eq_ignore_ascii_case("Authority") {
        return (0, 0, String::new());
    }
    (
        1,
        user_numeric_suffix(node).unwrap_or(u16::MAX),
        node.to_string(),
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
