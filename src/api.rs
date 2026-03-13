use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Response, StatusCode};

use crate::{AppState, Clearance, PendingRevocation, RunMode};
use crate::crypto::{BlpBibaConfig, DocumentLabel, RevocationList};
use crate::network::NetworkStatus;

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    message: Option<String>,
    data: Option<T>,
}

fn json_response<T: Serialize>(code: u16, ok: bool, message: Option<String>, data: Option<T>) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&ApiResponse { ok, message, data }).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    let ct = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..]).unwrap();
    let status = if code == 200 { StatusCode(200) } else { StatusCode(code) };
    Response::from_data(body).with_header(ct).with_status_code(status)
}

fn serve_static(state: &Arc<AppState>, path: &str) -> Result<Response<fs::File>> {
    let clean = if path == "/" { "/index.html" } else { path };
    let rel = clean.trim_start_matches('/');
    let file_path = format!("{}/{}", state.ihm_dir, rel);
    let file = fs::File::open(&file_path)?;
    let content_type = if file_path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if file_path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if file_path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else {
        "application/octet-stream"
    };
    let ct = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap();
    let cache = Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap();
    Ok(Response::from_file(file).with_header(ct).with_header(cache))
}

fn read_body(req: &mut tiny_http::Request) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    req.as_reader().read_to_end(&mut buf)?;
    Ok(buf)
}

fn get_cookie(req: &tiny_http::Request, name: &str) -> Option<String> {
    for h in req.headers().iter() {
        if h.field.equiv("Cookie") {
            if let Ok(s) = std::str::from_utf8(h.value.as_bytes()) {
                for part in s.split(';') {
                    let p = part.trim();
                    if let Some((k, v)) = p.split_once('=') {
                        if k.trim() == name {
                            return Some(v.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn session_cookie_name(state: &Arc<AppState>) -> String {
    format!("session_{}", state.port)
}

fn set_cookie_header(state: &Arc<AppState>, token: &str) -> Header {
    let v = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/",
        session_cookie_name(state),
        token
    );
    Header::from_bytes(&b"Set-Cookie"[..], v.as_bytes()).unwrap()
}

fn clear_cookie_header(state: &Arc<AppState>) -> Header {
    let v = format!(
        "{}=; Max-Age=0; Path=/; SameSite=Lax",
        session_cookie_name(state)
    );
    Header::from_bytes(&b"Set-Cookie"[..], v.as_bytes()).unwrap()
}

fn get_session_user(state: &Arc<AppState>, req: &tiny_http::Request) -> Option<String> {
    if let Some(tok) = get_cookie(req, &session_cookie_name(state)) {
        if let Ok(sessions) = state.sessions.lock() {
            if let Some(login) = sessions.get(&tok) {
                return Some(login.clone());
            }
        }
    }
    if is_authority_panel(state) {
        return Some("admin".to_string());
    }
    None
}

fn require_auth(state: &Arc<AppState>, req: &tiny_http::Request) -> Result<String> {
    get_session_user(state, req).ok_or_else(|| anyhow!("Not authenticated"))
}

fn is_admin(state: &Arc<AppState>, login: &str) -> bool {
    let db = match state.user_db.lock() {
        Ok(v) => v,
        Err(_) => return false,
    };
    db.users.get(login).map(|u| u.is_admin).unwrap_or(false)
}

fn get_user_record(state: &Arc<AppState>, login: &str) -> Option<(Clearance, bool)> {
    let db = state.user_db.lock().ok()?;
    let u = db.users.get(login)?;
    Some((u.clearance.clone(), u.is_admin))
}

fn user_has_abs_key(state: &Arc<AppState>, login: &str) -> bool {
    let p = format!("{}/{}/skw{}.bin", state.users_dir, login, login);
    std::path::Path::new(&p).exists()
}

fn is_delegable_classification(classification: &str) -> bool {
    matches!(classification, "FR-S" | "FR-DR")
}

fn get_runtime(state: &Arc<AppState>) -> Option<Arc<crate::network::NetworkRuntime>> {
    let guard = state.network_runtime.lock().ok()?;
    guard.clone()
}

fn is_authority_panel(state: &Arc<AppState>) -> bool {
    state.mode == RunMode::Network && state.port == 18080
}

fn me_data_for(state: &Arc<AppState>, login: String, clearance: Clearance, is_admin: bool) -> MeData {
    let mut network_group = None;
    let mut pending_key_delivery = false;
    let mut has_abs_key = user_has_abs_key(state, &login);

    if state.mode == RunMode::Network {
        if let Some(rt) = get_runtime(state) {
            let status = rt.status_for_login(state, &login);
            network_group = Some(status.group);
            pending_key_delivery = status.pending_key_delivery;
            has_abs_key = status.has_abs_key;
        }
    }

    MeData {
        login,
        clearance,
        is_admin,
        is_authority: is_authority_panel(state),
        mode: if state.mode == RunMode::Network { "network".to_string() } else { "local".to_string() },
        has_abs_key,
        network_group,
        pending_key_delivery,
    }
}

fn ensure_signup_user_files(state: &Arc<AppState>, login: &str, clearance: &Clearance) -> Result<()> {
    let dir = format!("{}/{}", state.users_dir, login);
    fs::create_dir_all(&dir)?;
    let token = serde_json::json!({
        "version": 1,
        "classification": clearance.classification,
        "mission": clearance.mission
    });
    fs::write(format!("{}/token.json", dir), serde_json::to_string(&token)?)?;
    Ok(())
}

fn pending_revocations_path(state: &Arc<AppState>) -> String {
    format!("{}/pending_revocations.json", state.tm_dir)
}

fn load_pending_revocations_shared(state: &Arc<AppState>) -> Vec<PendingRevocation> {
    let path = pending_revocations_path(state);
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<PendingRevocation>>(&raw).unwrap_or_default()
}

fn save_pending_revocations_shared(state: &Arc<AppState>, queue: &[PendingRevocation]) -> Result<()> {
    let path = pending_revocations_path(state);
    let raw = serde_json::to_string(queue)?;
    fs::write(path, raw)?;
    Ok(())
}

fn merge_pending_revocations(a: Vec<PendingRevocation>, b: Vec<PendingRevocation>) -> Vec<PendingRevocation> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut all = a;
    all.extend(b);
    for item in all {
        let key = format!("{}|{}|{}", item.id, item.requester, item.missions.join(","));
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        out.push(item);
    }
    out.sort_by_key(|x| x.id);
    out
}

fn next_revocation_id(queue: &[PendingRevocation]) -> u64 {
    let from_queue = queue.iter().map(|x| x.id).max().unwrap_or(0).saturating_add(1);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    from_queue.max(now_ms)
}

#[derive(Deserialize)]
struct SigninRequest {
    login: String,
    password: String,
}

#[derive(Deserialize)]
struct SignupRequest {
    login: String,
    password: String,
    clearance: serde_json::Value,
}

#[derive(Serialize)]
struct MeData {
    login: String,
    clearance: Clearance,
    is_admin: bool,
    is_authority: bool,
    mode: String,
    has_abs_key: bool,
    network_group: Option<String>,
    pending_key_delivery: bool,
}

#[derive(Deserialize)]
struct EncryptRequest {
    message: String,
    classification: String,
    mission: String,
}

#[derive(Serialize)]
struct EncryptData {
    id: u64,
}

#[derive(Serialize)]
struct DocumentsData {
    documents: Vec<crate::crypto::DocumentDescriptor>,
}

#[derive(Deserialize)]
struct DecryptRequest {
    id: u64,
}

#[derive(Serialize)]
struct DecryptData {
    message: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    missions: Vec<String>,
}

#[derive(Deserialize)]
struct PresetsUpdateRequest {
    nowriteup: bool,
    noreadup: bool,
    nowritedown: bool,
    noreaddown: bool,
}

#[derive(Deserialize)]
struct NetworkGroupRequest {
    group: String,
}

#[derive(Deserialize)]
struct RevocationAskRequest {
    missions: Vec<String>,
}

#[derive(Deserialize)]
struct RevocationApproveRequest {
    id: u64,
    approve: bool,
}

#[derive(Serialize)]
struct RevocationQueueData {
    requests: Vec<PendingRevocation>,
}

pub fn handle_request(mut req: tiny_http::Request, state: Arc<AppState>, token_gen: fn() -> String) -> Result<()> {
    let url = req.url().to_string();

    if !url.starts_with("/api/") {
        if let Ok(r) = serve_static(&state, &url) {
            let _ = req.respond(r);
        } else {
            let _ = req.respond(
                Response::from_string("Not found")
                    .with_status_code(StatusCode(404))
                    .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/plain; charset=utf-8"[..]).unwrap()),
            );
        }
        return Ok(());
    }

    let method = req.method().clone();

    match (method, url.as_str()) {
        (Method::Get, "/api/me") => {
            if let Some(login) = get_session_user(&state, &req) {
                if let Some((clearance, is_admin)) = get_user_record(&state, &login) {
                    let resp = json_response(200, true, None, Some(me_data_for(&state, login, clearance, is_admin)));
                    let _ = req.respond(resp);
                    return Ok(());
                }
            }
            let resp = json_response(200, true, None, None::<MeData>);
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Get, "/api/network/status") => {
            let login = get_session_user(&state, &req);
            if state.mode != RunMode::Network {
                let data = NetworkStatus {
                    enabled: false,
                    node_id: "local".to_string(),
                    tm_id: "local".to_string(),
                    group: "local".to_string(),
                    joined: false,
                    subscriptions: Vec::new(),
                    pending_key_delivery: false,
                    has_abs_key: login
                        .as_ref()
                        .map(|l| user_has_abs_key(&state, l))
                        .unwrap_or(false),
                    authority_reachable: false,
                    notifications: Vec::new(),
                };
                let _ = req.respond(json_response(200, true, None, Some(data)));
                return Ok(());
            }
            if let Some(rt) = get_runtime(&state) {
                let data = rt.status_for_login(&state, login.as_deref().unwrap_or("__guest__"));
                let _ = req.respond(json_response(200, true, None, Some(data)));
            } else {
                let _ = req.respond(json_response::<NetworkStatus>(500, false, Some("Network runtime unavailable".to_string()), None));
            }
            Ok(())
        }

        (Method::Post, "/api/network/group") => {
            let login = get_session_user(&state, &req);
            let body = read_body(&mut req)?;
            let parsed: NetworkGroupRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;
            if state.mode != RunMode::Network {
                let _ = req.respond(json_response::<NetworkStatus>(400, false, Some("Only available in network mode".to_string()), None));
                return Ok(());
            }
            if let Some(rt) = get_runtime(&state) {
                match rt.set_connectivity_group(&state, &parsed.group) {
                    Ok(_) => {
                        if let Some(login_ref) = login.as_ref() {
                            if let Some((clearance, is_admin)) = get_user_record(&state, login_ref) {
                                if !is_admin && !user_has_abs_key(&state, login_ref) {
                                    let _ = rt.new_user(&state, login_ref, &clearance);
                                }
                            }
                        }
                        let data = rt.status_for_login(&state, login.as_deref().unwrap_or("__guest__"));
                        let _ = req.respond(json_response(200, true, None, Some(data)));
                    }
                    Err(e) => {
                        let _ = req.respond(json_response::<NetworkStatus>(400, false, Some(e.to_string()), None));
                    }
                }
            } else {
                let _ = req.respond(json_response::<NetworkStatus>(500, false, Some("Network runtime unavailable".to_string()), None));
            }
            Ok(())
        }

        (Method::Post, "/api/signin") => {
            let body = read_body(&mut req)?;
            let parsed: SigninRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            let db = state.user_db.lock().map_err(|_| anyhow!("DB error"))?;
            let record = db.users.get(&parsed.login).cloned();
            drop(db);

            match record {
                Some(u) if u.password == parsed.password => {
                    let token = token_gen();
                    {
                        let mut sessions = state.sessions.lock().map_err(|_| anyhow!("Session store error"))?;
                        sessions.insert(token.clone(), parsed.login.clone());
                    }
                    let data = me_data_for(&state, parsed.login.clone(), u.clearance.clone(), u.is_admin);
                    let resp = json_response(200, true, None, Some(data))
                        .with_header(set_cookie_header(&state, &token));
                    let _ = req.respond(resp);
                    Ok(())
                }
                _ => {
                    let resp = json_response::<MeData>(401, false, Some("Invalid login/password".to_string()), None);
                    let _ = req.respond(resp);
                    Ok(())
                }
            }
        }

        (Method::Post, "/api/signup") => {
            let body = read_body(&mut req)?;
            let parsed: SignupRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            let clearance = match parsed.clearance {
                serde_json::Value::String(s) => serde_json::from_str::<Clearance>(&s).map_err(|_| anyhow!("Invalid clearance JSON"))?,
                serde_json::Value::Object(_) => serde_json::from_value::<Clearance>(parsed.clearance).map_err(|_| anyhow!("Invalid clearance object"))?,
                _ => return Err(anyhow!("Invalid clearance format")),
            };

            let arl = crate::crypto::get_arl(&state).map_err(|e| anyhow!(e.to_string()))?;
            if arl.items.iter().any(|e| e.attribute_type == "mission" && e.attribute_value == clearance.mission) {
                let resp = json_response::<MeData>(
                    400,
                    false,
                    Some(format!("Attribute {} revoked", clearance.mission)),
                    None,
                );
                let _ = req.respond(resp);
                return Ok(());
            }

            if state.mode == RunMode::Network && !is_delegable_classification(&clearance.classification) {
                let authority_reachable = get_runtime(&state)
                    .map(|rt| rt.status_for_login(&state, "__guest__").authority_reachable)
                    .unwrap_or(false);
                if !authority_reachable {
                    let resp = json_response::<MeData>(
                        400,
                        false,
                        Some(format!("Attribute {} cannot be delegated", clearance.classification)),
                        None,
                    );
                    let _ = req.respond(resp);
                    return Ok(());
                }
            }

            let mut db = state.user_db.lock().map_err(|_| anyhow!("DB error"))?;
            if db.users.contains_key(&parsed.login) {
                let resp = json_response::<MeData>(400, false, Some("User already exists".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }

            db.users.insert(
                parsed.login.clone(),
                crate::UserRecord {
                    password: parsed.password.clone(),
                    clearance: clearance.clone(),
                    is_admin: false,
                },
            );
            drop(db);

            let mut signup_message = None;
            if state.mode == RunMode::Network {
                ensure_signup_user_files(&state, &parsed.login, &clearance)?;
                if let Some(rt) = get_runtime(&state) {
                    rt.new_user(&state, &parsed.login, &clearance).map_err(|e| anyhow!(e.to_string()))?;
                }
                signup_message = Some("waiting for key generation or delegation process".to_string());
            } else {
                crate::crypto::ensure_user_keys(&state, &parsed.login, &clearance, false).map_err(|e| anyhow!(e.to_string()))?;
            }

            let token = token_gen();
            {
                let mut sessions = state.sessions.lock().map_err(|_| anyhow!("Session store error"))?;
                sessions.insert(token.clone(), parsed.login.clone());
            }

            let data = me_data_for(&state, parsed.login.clone(), clearance, false);
            let resp = json_response(200, true, signup_message, Some(data))
                .with_header(set_cookie_header(&state, &token));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Post, "/api/logout") => {
            if let Some(tok) = get_cookie(&req, &session_cookie_name(&state)) {
                let mut sessions = state.sessions.lock().map_err(|_| anyhow!("Session store error"))?;
                sessions.remove(&tok);
            }
            let resp = json_response::<serde_json::Value>(200, true, None, None)
                .with_header(clear_cookie_header(&state));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Get, "/api/presets") => {
            let _ = require_auth(&state, &req)?;
            let cfg = crate::crypto::get_presets(&state)?;
            let resp = json_response(200, true, None, Some(cfg));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Post, "/api/presets") => {
            let login = require_auth(&state, &req)?;
            if !is_admin(&state, &login) {
                let resp = json_response::<BlpBibaConfig>(403, false, Some("Authority only".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let body = read_body(&mut req)?;
            let parsed: PresetsUpdateRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            let cfg = BlpBibaConfig {
                version: 1,
                nowriteup: parsed.nowriteup,
                noreadup: parsed.noreadup,
                nowritedown: parsed.nowritedown,
                noreaddown: parsed.noreaddown,
            };

            crate::crypto::update_presets(&state, &cfg)?;
            let resp = json_response(200, true, None, Some(cfg));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Get, "/api/revocations") => {
            let login = require_auth(&state, &req)?;
            if !is_admin(&state, &login) {
                let resp = json_response::<RevocationList>(403, false, Some("Authority only".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let arl = crate::crypto::get_arl(&state)?;
            let resp = json_response(200, true, None, Some(arl));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Get, "/api/revocation/requests") => {
            let login = require_auth(&state, &req)?;
            if !is_admin(&state, &login) {
                let resp = json_response::<RevocationQueueData>(403, false, Some("Authority only".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let requests = if state.mode == RunMode::Network {
                let shared = load_pending_revocations_shared(&state);
                let local = state
                    .pending_revocations
                    .lock()
                    .map_err(|_| anyhow!("Revocation queue error"))?
                    .clone();
                merge_pending_revocations(shared, local)
            } else {
                state
                    .pending_revocations
                    .lock()
                    .map_err(|_| anyhow!("Revocation queue error"))?
                    .clone()
            };
            let _ = req.respond(json_response(200, true, None, Some(RevocationQueueData { requests })));
            Ok(())
        }

        (Method::Post, "/api/revocation/request") => {
            let login = require_auth(&state, &req)?;
            if is_admin(&state, &login) {
                let resp = json_response::<serde_json::Value>(400, false, Some("Authority cannot request revocation".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let body = read_body(&mut req)?;
            let parsed: RevocationAskRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;
            if parsed.missions.is_empty() {
                let resp = json_response::<serde_json::Value>(400, false, Some("Select at least one mission".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let mut queue = if state.mode == RunMode::Network {
                load_pending_revocations_shared(&state)
            } else {
                state
                    .pending_revocations
                    .lock()
                    .map_err(|_| anyhow!("Revocation queue error"))?
                    .clone()
            };
            let next_id = next_revocation_id(&queue);
            queue.push(PendingRevocation {
                id: next_id,
                requester: login.clone(),
                missions: parsed.missions,
            });
            if state.mode == RunMode::Network {
                save_pending_revocations_shared(&state, &queue)?;
                if let Some(rt) = get_runtime(&state) {
                    if let Some(last) = queue.last() {
                        let _ = rt.ask_revocation_request(&last.requester, &last.missions);
                    }
                }
            }
            if let Ok(mut local_q) = state.pending_revocations.lock() {
                *local_q = queue.clone();
            }
            let _ = req.respond(json_response::<serde_json::Value>(200, true, Some("Revocation request sent to authority".to_string()), None));
            Ok(())
        }

        (Method::Post, "/api/revocation/approve") => {
            let login = require_auth(&state, &req)?;
            if !is_admin(&state, &login) {
                let resp = json_response::<serde_json::Value>(403, false, Some("Authority only".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let body = read_body(&mut req)?;
            let parsed: RevocationApproveRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;
            let mut queue = if state.mode == RunMode::Network {
                let shared = load_pending_revocations_shared(&state);
                let local = state
                    .pending_revocations
                    .lock()
                    .map_err(|_| anyhow!("Revocation queue error"))?
                    .clone();
                merge_pending_revocations(shared, local)
            } else {
                state
                    .pending_revocations
                    .lock()
                    .map_err(|_| anyhow!("Revocation queue error"))?
                    .clone()
            };
            let idx = queue.iter().position(|r| r.id == parsed.id);
            let Some(idx) = idx else {
                let resp = json_response::<serde_json::Value>(404, false, Some("Request not found".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            };
            let req_item = queue.remove(idx);
            if state.mode == RunMode::Network {
                save_pending_revocations_shared(&state, &queue)?;
            }
            if let Ok(mut local_q) = state.pending_revocations.lock() {
                *local_q = queue.clone();
            }

            if parsed.approve {
                if state.mode == RunMode::Network {
                    if let Some(rt) = get_runtime(&state) {
                        for m in &req_item.missions {
                            let _ = rt.ask_revocation(m);
                        }
                    }
                }
                let _ = crate::crypto::revoke_missions(&state, &req_item.missions)?;
                let _ = req.respond(json_response::<serde_json::Value>(200, true, Some("Revocation approved".to_string()), None));
            } else {
                let _ = req.respond(json_response::<serde_json::Value>(200, true, Some("Revocation rejected".to_string()), None));
            }
            Ok(())
        }

        (Method::Post, "/api/revoke") => {
            let login = require_auth(&state, &req)?;
            if !is_admin(&state, &login) || is_authority_panel(&state) {
                let resp = json_response::<RevocationList>(403, false, Some("Authority only".to_string()), None);
                let _ = req.respond(resp);
                return Ok(());
            }
            let body = read_body(&mut req)?;
            let parsed: RevokeRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            if state.mode == RunMode::Network {
                if let Some(rt) = get_runtime(&state) {
                    for m in &parsed.missions {
                        let _ = rt.ask_revocation(m);
                    }
                }
            }

            let arl = crate::crypto::revoke_missions(&state, &parsed.missions)?;
            let resp = json_response(200, true, None, Some(arl));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Get, "/api/documents") => {
            let login = require_auth(&state, &req)?;
            let (clearance, is_admin) = get_user_record(&state, &login).ok_or_else(|| anyhow!("User not found"))?;
            let docs = crate::crypto::list_documents(&state, &clearance, is_admin)?;
            let resp = json_response(200, true, None, Some(DocumentsData { documents: docs }));
            let _ = req.respond(resp);
            Ok(())
        }

        (Method::Post, "/api/encrypt") => {
            let login = require_auth(&state, &req)?;
            let (clearance, is_admin_flag) = get_user_record(&state, &login).ok_or_else(|| anyhow!("User not found"))?;
            let body = read_body(&mut req)?;
            let parsed: EncryptRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            let label = DocumentLabel {
                classification: parsed.classification,
                mission: parsed.mission,
            };

            match crate::crypto::encrypt_document(&state, &login, &clearance, is_admin_flag, &label, &parsed.message) {
                Ok(id) => {
                    if state.mode == RunMode::Network {
                        if let Some(rt) = get_runtime(&state) {
                            let _ = rt.ask_for_sharing(&state, id);
                        }
                    }
                    let resp = json_response(200, true, None, Some(EncryptData { id }));
                    let _ = req.respond(resp);
                    Ok(())
                }
                Err(e) => {
                    let resp = json_response::<EncryptData>(400, false, Some(e.to_string()), None);
                    let _ = req.respond(resp);
                    Ok(())
                }
            }
        }

        (Method::Post, "/api/decrypt") => {
            let login = require_auth(&state, &req)?;
            let body = read_body(&mut req)?;
            let parsed: DecryptRequest = serde_json::from_slice(&body).map_err(|_| anyhow!("Invalid JSON"))?;

            match crate::crypto::decrypt_document(&state, &login, parsed.id) {
                Ok(msg) => {
                    let resp = json_response(200, true, None, Some(DecryptData { message: msg }));
                    let _ = req.respond(resp);
                    Ok(())
                }
                Err(e) => {
                    let resp = json_response::<DecryptData>(400, false, Some(e.to_string()), None);
                    let _ = req.respond(resp);
                    Ok(())
                }
            }
        }

        _ => {
            let resp = json_response::<serde_json::Value>(404, false, Some("Not found".to_string()), None);
            let _ = req.respond(resp);
            Ok(())
        }
    }
}


