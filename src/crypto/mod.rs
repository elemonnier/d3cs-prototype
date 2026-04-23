// ce fichier utilise la crypto de cpabe.rs et abs.rs afin d'exécuter des fonctions plus haut niveau,
// comme encrypt_document, utilisant Encrypt de CP-ABE et Sign/Verify de ABS

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::{AppState, Clearance};

pub mod abs;
pub mod cpabe;

#[derive(Clone, Serialize, Deserialize)]
pub struct BlpBibaConfig {
    pub version: u8,
    pub nowriteup: bool,
    pub noreadup: bool,
    pub nowritedown: bool,
    pub noreaddown: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub attribute_type: String,
    pub attribute_value: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationList {
    pub version: u8,
    pub items: Vec<RevocationEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentLabel {
    pub classification: String,
    pub mission: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DocumentDescriptor {
    pub id: u64,
    pub label: DocumentLabel,
}

// récupération des presets Bell-La Padula et Biba dans le fichier de config

fn read_blpbiba(state: &Arc<AppState>) -> Result<BlpBibaConfig> {
    let p = format!("{}/blpbiba.toml", state.config_dir);
    let content = fs::read_to_string(&p)?;
    let cfg: BlpBibaConfig = toml::from_str(&content)?;
    Ok(cfg)
}

// modification des presets BLP/Biba

fn write_blpbiba(state: &Arc<AppState>, cfg: &BlpBibaConfig) -> Result<()> {
    let p = format!("{}/blpbiba.toml", state.config_dir);
    let s = toml::to_string(cfg)?;
    write_atomic(&p, s.as_bytes())
}

// lecture de la liste de révocation de missions

fn read_arl(state: &Arc<AppState>) -> Result<RevocationList> {
    let p = format!("{}/arl.json", state.tm_dir);
    let content = fs::read_to_string(&p)?;
    let arl: RevocationList = serde_json::from_str(&content)?;
    Ok(arl)
}

// écriture sur la liste de révocation de missions

fn write_arl(state: &Arc<AppState>, arl: &RevocationList) -> Result<()> {
    let p = format!("{}/arl.json", state.tm_dir);
    let s = serde_json::to_string(arl)?;
    write_atomic(&p, s.as_bytes())
}

// lecture d'une mission particulière sur l'ARL

fn is_mission_revoked(arl: &RevocationList, mission: &str) -> bool {
    arl.items
        .iter()
        .any(|e| e.attribute_type == "mission" && e.attribute_value.as_str() == mission)
}

// initialisation des presets BLP/Biba par défaut si elle n'existe pas encore

fn ensure_default_blpbiba(state: &Arc<AppState>) -> Result<()> {
    let p = format!("{}/blpbiba.toml", state.config_dir);
    if Path::new(&p).exists() {
        return Ok(());
    }
    let cfg = BlpBibaConfig {
        version: 1,
        nowriteup: true,
        noreadup: true,
        nowritedown: false,
        noreaddown: false,
    };
    write_blpbiba(state, &cfg)
}

// initialisation des attributs s'ils n'existent pas

fn ensure_default_attributes(state: &Arc<AppState>) -> Result<()> {
    let p = format!("{}/attributes.json", state.config_dir);
    if Path::new(&p).exists() {
        return Ok(());
    }
    let content = fs::read_to_string(format!("{}/attributes.json", state.config_dir));
    if content.is_ok() {
        return Ok(());
    }
    let json = serde_json::json!({
        "version": 1,
        "classification": [
            { "name": "FR-DR", "closure": ["FR-DR"], "level": 0 },
            { "name": "FR-S", "closure": ["FR-S", "FR-DR"], "level": 1 }
        ],
        "missions": ["M1", "M2"]
    });
    let s = serde_json::to_string_pretty(&json)?;
    write_atomic(&p, s.as_bytes())
}

// initialisation de l'ARL si elle n'existe pas

fn ensure_default_arl(state: &Arc<AppState>) -> Result<()> {
    let p = format!("{}/arl.json", state.tm_dir);
    if Path::new(&p).exists() {
        return Ok(());
    }
    let arl = RevocationList {
        version: 1,
        items: Vec::new(),
    };
    write_arl(state, &arl)
}

// règle de comparaison des classifications : FR-DR < FR-S

fn classification_level(classification: &str) -> Result<i32> {
    match classification {
        "FR-DR" => Ok(0),
        "FR-S" => Ok(1),
        _ => Err(anyhow!("Unknown classification")),
    }
}

// comparaison des droits en fonction des presets

fn is_read_allowed(cfg: &BlpBibaConfig, user_level: i32, doc_level: i32) -> bool {
    if cfg.noreadup && doc_level > user_level {
        return false;
    }
    if cfg.noreaddown && doc_level < user_level {
        return false;
    }
    true
}

fn is_write_allowed(cfg: &BlpBibaConfig, user_level: i32, doc_level: i32) -> bool {
    if cfg.nowriteup && doc_level > user_level {
        return false;
    }
    if cfg.nowritedown && doc_level < user_level {
        return false;
    }
    true
}

// gestion de l'écriture des fichiers via fichier temporaire pour gérer des erreurs

fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    let tmp_path = format!("{}.tmp", path);
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    fs::remove_file(&tmp_path).ok();
    Ok(())
}

fn file_has_non_empty_content(path: &str) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

fn key_material_matches(
    pp: &cpabe::PublicParamsV1,
    pska: &cpabe::PskaV1,
    psks: &cpabe::PsksV1,
    clearance: &Clearance,
) -> bool {
    let label = DocumentLabel {
        classification: clearance.classification.clone(),
        mission: clearance.mission.clone(),
    };
    let probe = "__d3cs_key_probe__";

    let result = cpabe::encrypt(pp, &label, probe)
        .and_then(|ct| cpabe::tm_decrypt(pp, &ct, pska))
        .and_then(|cti| cpabe::decrypt(pp, &cti, psks));

    matches!(result, Ok(msg) if msg == probe)
}

// représente le treillis d'attributs (e.g. FR-DR inclus dans FR-S)

fn user_attribute_set(clearance: &Clearance) -> Vec<String> {
    let mut out = Vec::new();
    match clearance.classification.as_str() {
        "FR-S" => {
            out.push("FR-S".to_string());
            out.push("FR-DR".to_string());
        }
        "FR-DR" => {
            out.push("FR-DR".to_string());
        }
        _ => {}
    }
    out.push(clearance.mission.clone());
    out.sort();
    out.dedup();
    out
}

// indique le groupe réseau courant en mode réseau

fn network_group(state: &Arc<AppState>) -> Option<String> {
    if state.mode != crate::RunMode::Network {
        return None;
    }
    let rt = state.network_runtime.lock().ok()?.clone()?;
    Some(rt.status_for_login(state, "__guest__").group)
}

#[derive(Clone)]
struct DocumentStorage {
    ct_dir: String,
    sig_dir: String,
    cti_dir: String,
}

fn group_scoped_dir(state: &Arc<AppState>, group: &str, subdir: &str) -> String {
    format!("{}/groups/{}/{}", state.tm_dir, group, subdir)
}

// renvoie le chemin d'écriture du groupe du TM (entre Net1 et Net2)

fn tm_scoped_dir(state: &Arc<AppState>, subdir: &str) -> String {
    if let Some(group) = network_group(state) {
        group_scoped_dir(state, &group, subdir)
    } else {
        format!("{}/{}", state.tm_dir, subdir)
    }
}

fn current_document_storage(state: &Arc<AppState>) -> DocumentStorage {
    DocumentStorage {
        ct_dir: tm_scoped_dir(state, "ct"),
        sig_dir: tm_scoped_dir(state, "s"),
        cti_dir: tm_scoped_dir(state, "ct_intermediate"),
    }
}

fn all_document_storages(state: &Arc<AppState>) -> Vec<DocumentStorage> {
    if state.mode != crate::RunMode::Network {
        return vec![current_document_storage(state)];
    }

    let mut storages = Vec::new();
    let groups_root = format!("{}/groups", state.tm_dir);
    if let Ok(entries) = fs::read_dir(&groups_root) {
        let mut groups = entries
            .flatten()
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                if !file_type.is_dir() {
                    return None;
                }
                Some(entry.file_name().to_string_lossy().to_string())
            })
            .collect::<Vec<_>>();
        groups.sort();
        groups.dedup();

        for group in groups {
            storages.push(DocumentStorage {
                ct_dir: group_scoped_dir(state, &group, "ct"),
                sig_dir: group_scoped_dir(state, &group, "s"),
                cti_dir: group_scoped_dir(state, &group, "ct_intermediate"),
            });
        }
    }

    let current = current_document_storage(state);
    if !storages
        .iter()
        .any(|storage| storage.ct_dir == current.ct_dir)
    {
        storages.push(current);
    }

    storages
}

fn next_document_id(state: &Arc<AppState>) -> Result<u64> {
    let mut max_id = 0u64;

    for storage in all_document_storages(state) {
        if !Path::new(&storage.ct_dir).exists() {
            continue;
        }
        for entry in fs::read_dir(&storage.ct_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".ct") {
                continue;
            }
            if let Ok(id) = name.split('.').next().unwrap_or("").parse::<u64>() {
                if id > max_id {
                    max_id = id;
                }
            }
        }
    }

    Ok(max_id + 1)
}

fn find_document_storage(state: &Arc<AppState>, id: u64) -> Option<DocumentStorage> {
    for storage in all_document_storages(state) {
        let ct_path = format!("{}/{}.ct", storage.ct_dir, id);
        let sig_path = format!("{}/{}.sign", storage.sig_dir, id);
        if Path::new(&ct_path).exists() && Path::new(&sig_path).exists() {
            return Some(storage);
        }
    }
    None
}

// initialisation de la crypto (presets, attributs, ARL, ABE.Setup, ABS.Setup)

pub fn setup_if_needed(state: &Arc<AppState>) -> Result<()> {
    ensure_default_blpbiba(state)?;
    ensure_default_attributes(state)?;
    ensure_default_arl(state)?;

    let pp_path = format!("{}/pp.bin", state.tm_dir);
    let msk_path = format!("{}/msk.bin", state.authority_dir);
    let params_path = format!("{}/params.bin", state.tm_dir);
    let abs_sk_path = format!("{}/sk.bin", state.authority_dir);

    if !Path::new(&pp_path).exists() || !Path::new(&msk_path).exists() {
        let (pp, msk) = cpabe::setup()?;
        let pp_s = serde_json::to_string(&pp)?;
        let msk_s = serde_json::to_string(&msk)?;
        write_atomic(&pp_path, pp_s.as_bytes())?;
        write_atomic(&msk_path, msk_s.as_bytes())?;
    }

    if !Path::new(&params_path).exists() || !Path::new(&abs_sk_path).exists() {
        let (params, sk) = abs::setup()?;
        let params_s = serde_json::to_string(&params)?;
        let sk_s = serde_json::to_string(&sk)?;
        write_atomic(&params_path, params_s.as_bytes())?;
        write_atomic(&abs_sk_path, sk_s.as_bytes())?;
    }

    Ok(())
}

// génération de clés utilisateur en cas de besoin (si elles ne sont pas créées) :
// main.rs lors du boot, création d'utilisateur hors réseau (api.rs), avant déchiffrement

pub fn ensure_user_keys(
    state: &Arc<AppState>,
    login: &str,
    clearance: &Clearance,
    user_is_admin: bool,
) -> Result<()> {
    let user_dir = format!("{}/{}", state.users_dir, login);
    fs::create_dir_all(&user_dir)?;

    let psks_path = format!("{}/psks{}.bin", user_dir, login);
    let skw_path = format!("{}/skw{}.bin", user_dir, login);
    let pska_path = format!("{}/pska{}.bin", format!("{}/pska", state.tm_dir), login);

    let pp_path = format!("{}/pp.bin", state.tm_dir);

    let mut need = !file_has_non_empty_content(&psks_path)
        || !file_has_non_empty_content(&skw_path)
        || !file_has_non_empty_content(&pska_path);
    if !need {
        let keys_match = (|| -> Result<bool> {
            let pp: cpabe::PublicParamsV1 = serde_json::from_str(&fs::read_to_string(&pp_path)?)?;
            let pska: cpabe::PskaV1 = serde_json::from_str(&fs::read_to_string(&pska_path)?)?;
            let psks: cpabe::PsksV1 = serde_json::from_str(&fs::read_to_string(&psks_path)?)?;
            Ok(key_material_matches(&pp, &pska, &psks, clearance))
        })()
        .unwrap_or(false);

        need = !keys_match;
        if !need {
            return Ok(());
        }
    }

    let msk_path = format!("{}/msk.bin", state.authority_dir);
    let params_path = format!("{}/params.bin", state.tm_dir);
    let abs_sk_path = format!("{}/sk.bin", state.authority_dir);

    let pp: cpabe::PublicParamsV1 = serde_json::from_str(&fs::read_to_string(&pp_path)?)?;
    let msk: cpabe::MasterKeyV1 = serde_json::from_str(&fs::read_to_string(&msk_path)?)?;
    let abs_params: abs::AbsParamsV1 = serde_json::from_str(&fs::read_to_string(&params_path)?)?;
    let abs_msk: abs::AbsMasterKeyV1 = serde_json::from_str(&fs::read_to_string(&abs_sk_path)?)?;

    let mut attrs = user_attribute_set(clearance);
    if user_is_admin {
        attrs.push("M1".to_string());
        attrs.push("M2".to_string());
    } else {
        attrs.push(clearance.mission.clone());
    }
    attrs.sort();
    attrs.dedup();

    let (pska, psks) = cpabe::keygen(&pp, &msk, &attrs)?;
    let pska_s = serde_json::to_string(&pska)?;
    let psks_s = serde_json::to_string(&psks)?;
    write_atomic(&pska_path, pska_s.as_bytes())?;
    write_atomic(&psks_path, psks_s.as_bytes())?;

    let skw = abs::extract(&abs_params, &abs_msk, &clearance.classification)?;
    let skw_s = serde_json::to_string(&skw)?;
    write_atomic(&skw_path, skw_s.as_bytes())?;

    let token = serde_json::json!({
        "version": 1,
        "classification": clearance.classification,
        "mission": clearance.mission
    });
    let token_s = serde_json::to_string(&token)?;
    let token_path = format!("{}/token.json", user_dir);
    write_atomic(&token_path, token_s.as_bytes())?;

    Ok(())
}

pub fn get_presets(state: &Arc<AppState>) -> Result<BlpBibaConfig> {
    read_blpbiba(state)
}

pub fn update_presets(state: &Arc<AppState>, cfg: &BlpBibaConfig) -> Result<()> {
    write_blpbiba(state, cfg)
}

pub fn get_arl(state: &Arc<AppState>) -> Result<RevocationList> {
    read_arl(state)
}

pub fn clear_arl(state: &Arc<AppState>) -> Result<()> {
    let arl = RevocationList {
        version: 1,
        items: Vec::new(),
    };
    write_arl(state, &arl)
}

pub fn revoke_missions(state: &Arc<AppState>, missions: &[String]) -> Result<RevocationList> {
    let mut arl = read_arl(state)?;
    for m in missions {
        if !arl
            .items
            .iter()
            .any(|e| e.attribute_type == "mission" && e.attribute_value == *m)
        {
            arl.items.push(RevocationEntry {
                attribute_type: "mission".to_string(),
                attribute_value: m.clone(),
            });
        }
    }
    write_arl(state, &arl)?;
    Ok(arl)
}

// fonction permettant d'afficher les documents sur le panel "Documents" de l'IHM

pub fn list_documents(
    state: &Arc<AppState>,
    user_clearance: &Clearance,
    user_is_admin: bool,
) -> Result<Vec<DocumentDescriptor>> {
    let cfg = read_blpbiba(state)?;
    let arl = read_arl(state)?;

    let user_level = classification_level(&user_clearance.classification)?;
    let mut out = BTreeMap::new();

    for storage in all_document_storages(state) {
        if !Path::new(&storage.ct_dir).exists() {
            continue;
        }

        for entry in fs::read_dir(&storage.ct_dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".ct") {
                continue;
            }
            let id: u64 = match name.split('.').next().unwrap_or("").parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ct_s = match fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let ct: cpabe::CiphertextV1 = match serde_json::from_str(&ct_s) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sig_path = format!("{}/{}.sign", storage.sig_dir, id);
            let sig_s = match fs::read_to_string(&sig_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if serde_json::from_str::<abs::AbsSignatureV1>(&sig_s).is_err() {
                continue;
            }

            if is_mission_revoked(&arl, &ct.label.mission) {
                continue;
            }

            let doc_level = match classification_level(&ct.label.classification) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let accessible = if user_is_admin {
                is_read_allowed(&cfg, user_level, doc_level)
            } else {
                is_read_allowed(&cfg, user_level, doc_level)
                    && ct.label.mission == user_clearance.mission
            };

            if !accessible {
                continue;
            }

            out.entry(id).or_insert_with(|| DocumentDescriptor {
                id,
                label: DocumentLabel {
                    classification: ct.label.classification,
                    mission: ct.label.mission,
                },
            });
        }
    }

    Ok(out.into_values().collect())
}

// fonction permettant de chiffrer un document depuis le panel Labelling

pub fn encrypt_document(
    state: &Arc<AppState>,
    login: &str,
    user_clearance: &Clearance,
    user_is_admin: bool,
    label: &DocumentLabel,
    message: &str,
) -> Result<u64> {
    let cfg = read_blpbiba(state)?;
    let arl = read_arl(state)?;

    if is_mission_revoked(&arl, &label.mission) {
        return Err(anyhow!("Mission revoked in ARL"));
    }

    if !user_is_admin && label.mission != user_clearance.mission {
        return Err(anyhow!("Mission not allowed for this user"));
    }

    let user_level = classification_level(&user_clearance.classification)?;
    let doc_level = classification_level(&label.classification)?;
    if !is_write_allowed(&cfg, user_level, doc_level) {
        return Err(anyhow!("Write not allowed by presets (BLP/Biba)"));
    }

    let pp_path = format!("{}/pp.bin", state.tm_dir);
    let params_path = format!("{}/params.bin", state.tm_dir);
    let user_dir = format!("{}/{}", state.users_dir, login);
    let skw_path = format!("{}/skw{}.bin", user_dir, login);

    let pp: cpabe::PublicParamsV1 = serde_json::from_str(&fs::read_to_string(&pp_path)?)?;
    let abs_params: abs::AbsParamsV1 = serde_json::from_str(&fs::read_to_string(&params_path)?)?;
    let skw_s = fs::read_to_string(&skw_path).map_err(|_| anyhow!("Missing ABS signing key"))?;
    let skw: abs::AbsUserKeyV1 = serde_json::from_str(&skw_s)?;

    let ct = cpabe::encrypt(&pp, label, message)?;
    let ct_s = serde_json::to_string(&ct)?;
    let sig = abs::sign(&abs_params, &skw, ct_s.as_bytes())?;
    let sig_ok = abs::verify_any(&abs_params, &sig, ct_s.as_bytes())?;
    if !sig_ok {
        return Err(anyhow!("ABS.Verify failed after signing"));
    }

    let storage = current_document_storage(state);
    let ct_dir = storage.ct_dir;
    let sig_dir = storage.sig_dir;
    fs::create_dir_all(&ct_dir)?;
    fs::create_dir_all(&sig_dir)?;
    let next_id = next_document_id(state)?;

    let ct_path = format!("{}/{}.ct", ct_dir, next_id);
    let sig_path = format!("{}/{}.sign", sig_dir, next_id);

    let sig_s = serde_json::to_string(&sig)?;

    let tmp_ct_path = format!("{}.tmp", ct_path);
    let tmp_sig_path = format!("{}.tmp", sig_path);

    write_atomic(&tmp_ct_path, ct_s.as_bytes())?;
    write_atomic(&tmp_sig_path, sig_s.as_bytes())?;

    fs::rename(&tmp_ct_path, &ct_path)?;
    fs::rename(&tmp_sig_path, &sig_path)?;
    fs::remove_file(&tmp_ct_path).ok();
    fs::remove_file(&tmp_sig_path).ok();

    Ok(next_id)
}

// fonction qui déchiffre un document depuis le panel Documents

pub fn decrypt_document(state: &Arc<AppState>, login: &str, id: u64) -> Result<String> {
    let (clearance, user_is_admin) = {
        let db = state.user_db.lock().map_err(|_| anyhow!("DB error"))?;
        let record = db
            .users
            .get(login)
            .ok_or_else(|| anyhow!("User not found"))?;
        (record.clearance.clone(), record.is_admin)
    };
    ensure_user_keys(state, login, &clearance, user_is_admin)?;

    let storage = find_document_storage(state, id).ok_or_else(|| anyhow!("Document not found"))?;
    let ct_path = format!("{}/{}.ct", storage.ct_dir, id);
    let sig_path = format!("{}/{}.sign", storage.sig_dir, id);
    let ct_s = fs::read_to_string(&ct_path)?;
    let sig_s = fs::read_to_string(&sig_path)?;

    let ct: cpabe::CiphertextV1 = serde_json::from_str(&ct_s)?;
    let sig: abs::AbsSignatureV1 = serde_json::from_str(&sig_s)?;

    let params_path = format!("{}/params.bin", state.tm_dir);
    let abs_params: abs::AbsParamsV1 = serde_json::from_str(&fs::read_to_string(&params_path)?)?;

    let msg_bytes = serde_json::to_string(&ct)?.into_bytes();
    let sig_ok = abs::verify_any(&abs_params, &sig, &msg_bytes)?;
    if !sig_ok {
        return Err(anyhow!("ABS signature invalid for this ciphertext"));
    }

    let pp_path = format!("{}/pp.bin", state.tm_dir);
    let pp: cpabe::PublicParamsV1 = serde_json::from_str(&fs::read_to_string(&pp_path)?)?;

    let user_dir = format!("{}/{}", state.users_dir, login);
    let psks_path = format!("{}/psks{}.bin", user_dir, login);
    let pska_path = format!("{}/pska/pska{}.bin", state.tm_dir, login);

    let pska_s = fs::read_to_string(&pska_path)
        .map_err(|_| anyhow!("Missing PSKA file (runtime/tm/pska)"))?;
    let psks_s =
        fs::read_to_string(&psks_path).map_err(|_| anyhow!("Missing PSKS file (users)"))?;
    let pska: cpabe::PskaV1 = serde_json::from_str(&pska_s)?;
    let psks: cpabe::PsksV1 = serde_json::from_str(&psks_s)?;

    let cti = cpabe::tm_decrypt(&pp, &ct, &pska)?;
    let cti_dir = storage.cti_dir;
    fs::create_dir_all(&cti_dir).ok();
    let cti_path = format!("{}/{}.cti", cti_dir, id);
    let cti_s = serde_json::to_string(&cti)?;
    write_atomic(&cti_path, cti_s.as_bytes()).ok();

    cpabe::decrypt(&pp, &cti, &psks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_check_rejects_mismatched_pska_psks() -> Result<()> {
        let (pp, msk) = cpabe::setup()?;
        let attrs = vec!["FR-S".to_string(), "FR-DR".to_string(), "M1".to_string()];
        let clearance = Clearance {
            classification: "FR-S".to_string(),
            mission: "M1".to_string(),
        };
        let (pska_a, psks_a) = cpabe::keygen(&pp, &msk, &attrs)?;
        let (pska_b, _) = cpabe::keygen(&pp, &msk, &attrs)?;

        assert!(key_material_matches(&pp, &pska_a, &psks_a, &clearance));
        assert!(!key_material_matches(&pp, &pska_b, &psks_a, &clearance));

        Ok(())
    }
}
