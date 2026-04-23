// point d'entrée principal de l'application Rust, qui démarre le serveur

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine;
use rand_core::RngCore;

mod api;
mod authority;
mod crypto;
#[path = "network/main.rs"]
mod network;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Clearance {
    pub classification: String,
    pub mission: String,
}

#[derive(Clone)]
pub struct UserRecord {
    pub password: String,
    pub clearance: Clearance,
    pub is_admin: bool,
}

pub struct UserDb {
    pub users: HashMap<String, UserRecord>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRevocation {
    pub id: u64,
    pub requester: String,
    pub missions: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Local,
    Network,
}

pub struct AppState {
    pub host: String,
    pub port: u16,
    pub config_dir: String,
    pub users_dir: String,
    pub tm_dir: String,
    pub authority_dir: String,
    pub ihm_dir: String,
    pub mode: RunMode,
    pub user_db: Mutex<UserDb>,
    pub sessions: Mutex<HashMap<String, String>>,
    pub pending_revocations: Mutex<Vec<PendingRevocation>>,
    pub network_runtime: Mutex<Option<Arc<network::NetworkRuntime>>>,
}

// génère un token de session aléatoire

fn random_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

// permet de créer l'utilisateur admin

fn build_default_users() -> HashMap<String, UserRecord> {
    let mut users = HashMap::new();

    users.insert(
        "admin".to_string(),
        UserRecord {
            password: "minad".to_string(),
            clearance: Clearance {
                classification: "FR-S".to_string(),
                mission: "M1".to_string(),
            },
            is_admin: true,
        },
    );

    users
}

// permet de charger les variables d'environnement

fn load_env_var(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn effective_bind_host(host: &str) -> String {
    host.to_string()
}

fn quiet_startup() -> bool {
    matches!(
        std::env::var("D3CS_QUIET_STARTUP").ok().as_deref(),
        Some("1" | "true" | "TRUE")
    )
}

fn print_access_urls(bind_host: &str, port: u16, mode: RunMode, node_id: &str) {
    if mode == RunMode::Network {
        if !quiet_startup() {
            println!("started {node_id} on {bind_host}:{port}");
        }
    } else {
        println!("listening on http://{bind_host}:{port}");
    }
}

fn clear_terminal() -> Result<()> {
    print!("\x1B[2J\x1B[H");
    io::stdout().flush()?;
    Ok(())
}

// décide si l'application se lance en mode network ou en local

fn parse_mode(arg: Option<&String>) -> RunMode {
    match arg.map(|s| s.to_ascii_lowercase()) {
        Some(v) if v == "network" => RunMode::Network,
        _ => RunMode::Local,
    }
}

// détermine l'utilisateur connecté en fonction du port

fn derive_node_from_port(port: u16) -> String {
    if port == 18080 {
        "Authority".to_string()
    } else if (18081..=18089).contains(&port) {
        format!("U{}", port - 18080)
    } else {
        "Authority".to_string()
    }
}

// retourne la valeur du port en fonction de l'admin/utilisateur

fn default_port_for_node(node_id: &str) -> u16 {
    let upper = node_id.to_ascii_uppercase();
    if upper == "AUTHORITY" {
        18080
    } else if let Some(rest) = upper.strip_prefix('U') {
        if let Ok(i) = rest.parse::<u16>() {
            18080 + i
        } else {
            18080
        }
    } else {
        18080
    }
}

fn ensure_network_ports_available(host: &str, nodes: &[&str]) -> Result<()> {
    let mut busy = Vec::new();
    let mut reservations = Vec::new();

    for node in nodes {
        let port = default_port_for_node(node);
        match TcpListener::bind((host, port)) {
            Ok(listener) => reservations.push(listener),
            Err(_) => busy.push(port),
        }
    }

    drop(reservations);

    if !busy.is_empty() {
        let ports = busy
            .into_iter()
            .map(|port| format!("{host}:{port}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow::anyhow!(
            "Some network demo ports are already in use: {ports}. Another cluster may already be running; stop it before launching `cargo run -- network-all` again."
        ));
    }

    Ok(())
}

// permet de trouver le dossier racine du projet, ce qui va permettre de reconstruire les chemins du projet

fn detect_base_dir() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("D3CS_BASE_DIR") {
        let p = PathBuf::from(raw);
        if p.exists() {
            return Ok(p);
        }
    }

    let cwd = std::env::current_dir()?;
    if cwd.join("Cargo.toml").exists() {
        return Ok(cwd);
    }

    let exe = std::env::current_exe()?;
    for ancestor in exe.ancestors() {
        if ancestor.join("Cargo.toml").exists() {
            return Ok(ancestor.to_path_buf());
        }
    }

    Ok(std::env::current_dir()?)
}

// permet de transformer un chemin relatif en chemin absolu

fn absolutize_path(base_dir: &Path, p: String) -> String {
    let candidate = PathBuf::from(&p);
    if candidate.is_absolute() {
        p
    } else {
        base_dir.join(candidate).to_string_lossy().to_string()
    }
}

// fonction dépréciée qui utilisait soit src/gui/ soit src/ihm/ pour le dossier IHM

fn default_gui_dir(base_dir: &Path) -> String {
    if base_dir.join("src/gui").exists() {
        "src/gui".to_string()
    } else {
        "src/ihm".to_string()
    }
}

// permet de lancer l'ensemble des ports réseau en fonction des variables d'environnement

fn spawn_network_cluster(base_dir: &Path) -> Result<()> {
    let exe = std::env::current_exe()?;
    let host = effective_bind_host(&load_env_var("D3CS_HOST", "127.0.0.1"));
    let config_dir = absolutize_path(base_dir, load_env_var("D3CS_CONFIG_DIR", "src/config"));
    let users_dir = absolutize_path(base_dir, load_env_var("D3CS_USERS_DIR", "runtime/users"));
    let tm_dir = absolutize_path(base_dir, load_env_var("D3CS_TM_DIR", "runtime/tm"));
    let authority_dir = absolutize_path(
        base_dir,
        load_env_var("D3CS_AUTHORITY_DIR", "runtime/authority"),
    );
    let ihm_dir = absolutize_path(
        base_dir,
        load_env_var("D3CS_IHM_DIR", &default_gui_dir(base_dir)),
    );
    let network_dir = absolutize_path(
        base_dir,
        load_env_var("D3CS_NETWORK_DIR", "src/network/dodwan/runtime"),
    );
    let nodes = [
        "Authority",
        "U1",
        "U2",
        "U3",
        "U4",
        "U5",
        "U6",
        "U7",
        "U8",
        "U9",
    ];
    let mut children = Vec::new();

    ensure_network_ports_available(&host, &nodes)?;
    clear_terminal()?;

    for node in nodes {
        let port = default_port_for_node(node);
        let child = Command::new(&exe)
            .arg("network")
            .arg(node)
            .current_dir(base_dir)
            .env("D3CS_HOST", host.clone())
            .env("D3CS_NODE_ID", node)
            .env("D3CS_PORT", port.to_string())
            .env("D3CS_BASE_DIR", base_dir.to_string_lossy().to_string())
            .env("D3CS_CONFIG_DIR", config_dir.clone())
            .env("D3CS_USERS_DIR", users_dir.clone())
            .env("D3CS_TM_DIR", tm_dir.clone())
            .env("D3CS_AUTHORITY_DIR", authority_dir.clone())
            .env("D3CS_IHM_DIR", ihm_dir.clone())
            .env("D3CS_NETWORK_DIR", network_dir.clone())
            .env("D3CS_QUIET_STARTUP", "1")
            .spawn()?;
        println!("started {node} on {host}:{port}");
        children.push((node.to_string(), child));
    }

    for (node, mut child) in children {
        let status = child.wait()?;
        eprintln!("{node} exited with status: {status}");
    }

    Ok(())
}

// clear de l'ARL, dossiers utilisateur, PSKA dès lancement de l'application

fn reset_startup_state(state: &Arc<AppState>) -> Result<()> {
    crate::crypto::clear_arl(state)?;

    if Path::new(&state.users_dir).exists() {
        for entry in fs::read_dir(&state.users_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let login = entry.file_name().to_string_lossy().to_string();
            if login != "admin" {
                if let Err(e) = fs::remove_dir_all(entry.path()) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    let pska_dir = format!("{}/pska", state.tm_dir);
    if Path::new(&pska_dir).exists() {
        for entry in fs::read_dir(&pska_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "pskaadmin.bin" {
                if let Err(e) = fs::remove_file(entry.path()) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    for dir in ["ct", "s", "ct_intermediate"] {
        let full_dir = format!("{}/{}", state.tm_dir, dir);
        if Path::new(&full_dir).exists() {
            for entry in fs::read_dir(&full_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                if let Err(e) = fs::remove_file(entry.path()) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    Ok(())
}

// démarrage de l'application : chargement de la config, choix local/network, initialisation des
// dossiers/crypto/users, lance le serveur HTTP

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let base_dir = detect_base_dir()?;
    std::env::set_var("D3CS_BASE_DIR", base_dir.to_string_lossy().to_string());

    let args: Vec<String> = std::env::args().collect();
    if matches!(
        args.get(1).map(|s| s.to_ascii_lowercase()),
        Some(ref v) if v == "network-all"
    ) {
        return spawn_network_cluster(&base_dir);
    }
    let mode = parse_mode(args.get(1));
    let cli_node_id = args.get(2).cloned();

    let host = effective_bind_host(&load_env_var("D3CS_HOST", "127.0.0.1"));
    let env_port = std::env::var("D3CS_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok());
    let node_id = std::env::var("D3CS_NODE_ID")
        .ok()
        .or(cli_node_id)
        .unwrap_or_else(|| derive_node_from_port(env_port.unwrap_or(18080)));
    let default_port = if mode == RunMode::Network {
        default_port_for_node(&node_id)
    } else {
        8080
    };
    let port = env_port.unwrap_or(default_port);
    let config_dir = absolutize_path(&base_dir, load_env_var("D3CS_CONFIG_DIR", "src/config"));
    let users_dir = absolutize_path(&base_dir, load_env_var("D3CS_USERS_DIR", "runtime/users"));
    let tm_dir = absolutize_path(&base_dir, load_env_var("D3CS_TM_DIR", "runtime/tm"));
    let authority_dir = absolutize_path(
        &base_dir,
        load_env_var("D3CS_AUTHORITY_DIR", "runtime/authority"),
    );
    let ihm_dir = absolutize_path(
        &base_dir,
        load_env_var("D3CS_IHM_DIR", &default_gui_dir(&base_dir)),
    );
    let network_dir = absolutize_path(
        &base_dir,
        load_env_var("D3CS_NETWORK_DIR", "src/network/dodwan/runtime"),
    );
    std::env::set_var("D3CS_CONFIG_DIR", config_dir.clone());
    std::env::set_var("D3CS_USERS_DIR", users_dir.clone());
    std::env::set_var("D3CS_TM_DIR", tm_dir.clone());
    std::env::set_var("D3CS_AUTHORITY_DIR", authority_dir.clone());
    std::env::set_var("D3CS_IHM_DIR", ihm_dir.clone());
    std::env::set_var("D3CS_NETWORK_DIR", network_dir);

    let state = Arc::new(AppState {
        host: host.clone(),
        port,
        config_dir,
        users_dir,
        tm_dir,
        authority_dir,
        ihm_dir,
        mode,
        user_db: Mutex::new(UserDb {
            users: build_default_users(),
        }),
        sessions: Mutex::new(HashMap::new()),
        pending_revocations: Mutex::new(Vec::new()),
        network_runtime: Mutex::new(None),
    });

    authority::ensure_directories(&state).with_context(|| {
        format!(
            "cannot create required directories under base {}",
            base_dir.to_string_lossy()
        )
    })?;
    crypto::setup_if_needed(&state).context("crypto setup failed")?;
    if mode == RunMode::Local || node_id.eq_ignore_ascii_case("Authority") {
        reset_startup_state(&state).context("startup reset failed")?;
    }

    {
        let db = state.user_db.lock().unwrap();
        for (login, record) in db.users.iter() {
            crypto::ensure_user_keys(&state, login, &record.clearance, record.is_admin)
                .with_context(|| format!("key provisioning failed for user {login}"))?;
        }
    }

    if mode == RunMode::Network {
        let runtime = Arc::new(
            network::NetworkRuntime::new(&state, &node_id)
                .with_context(|| format!("network runtime init failed for node {node_id}"))?,
        );
        runtime.start(state.clone());
        if let Ok(mut slot) = state.network_runtime.lock() {
            *slot = Some(runtime);
        }
    }

    let addr = format!("{}:{}", host, port);
    let server = tiny_http::Server::http(&addr).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    print_access_urls(&host, port, mode, &node_id);
    for request in server.incoming_requests() {
        let state_cloned = state.clone();
        let _ = api::handle_request(request, state_cloned, random_session_token);
    }

    Ok(())
}
