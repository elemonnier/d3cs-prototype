// fichier permettant de mesurer les temps d'exécution des primitives crypto

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::Local;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Clearance {
    pub classification: String,
    pub mission: String,
}

#[derive(Clone)]
pub struct UserRecord {
    pub password: String,
    pub clearance: Clearance,
    pub is_authority_user: bool,
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

pub const AUTHORITY_LOGIN: &str = "authority";
pub const AUTHORITY_PASSWORD: &str = "authority";

pub mod network {
    #[derive(Clone)]
    pub struct NetworkRuntime;
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

#[allow(dead_code)]
#[path = "../crypto/mod.rs"]
mod crypto;

fn load_env_var(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn detect_base_dir() -> Result<PathBuf> {
    if let Ok(raw) = std::env::var("D3CS_BASE_DIR") {
        let path = PathBuf::from(raw);
        if path.exists() {
            return Ok(path);
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

    Ok(cwd)
}

fn absolutize_path(base_dir: &Path, path: String) -> String {
    let candidate = PathBuf::from(&path);
    if candidate.is_absolute() {
        path
    } else {
        base_dir.join(candidate).to_string_lossy().to_string()
    }
}

fn default_gui_dir(base_dir: &Path) -> String {
    if base_dir.join("src/gui").exists() {
        "src/gui".to_string()
    } else {
        "src/ihm".to_string()
    }
}

fn build_default_users() -> HashMap<String, UserRecord> {
    let mut users = HashMap::new();
    users.insert(
        AUTHORITY_LOGIN.to_string(),
        UserRecord {
            password: AUTHORITY_PASSWORD.to_string(),
            clearance: Clearance {
                classification: "FR-S".to_string(),
                mission: "M1".to_string(),
            },
            is_authority_user: true,
        },
    );
    users
}

fn build_default_state() -> Result<Arc<AppState>> {
    let base_dir = detect_base_dir()?;
    let host = load_env_var("D3CS_HOST", "127.0.0.1");
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

    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&users_dir)?;
    fs::create_dir_all(&tm_dir)?;
    fs::create_dir_all(&authority_dir)?;
    fs::create_dir_all(&ihm_dir)?;

    Ok(Arc::new(AppState {
        host,
        port: 8080,
        config_dir,
        users_dir,
        tm_dir,
        authority_dir,
        ihm_dir,
        mode: RunMode::Local,
        user_db: Mutex::new(UserDb {
            users: build_default_users(),
        }),
        sessions: Mutex::new(HashMap::new()),
        pending_revocations: Mutex::new(Vec::new()),
        network_runtime: Mutex::new(None),
    }))
}

fn measure<T, F>(name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let started_at = Instant::now();
    let out = f()?;
    let elapsed_us = started_at.elapsed().as_micros();
    console_log(format!("{name} : executed in {elapsed_us} us"));
    Ok(out)
}

fn console_log(message: impl AsRef<str>) {
    println!(
        "{} {}",
        Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
        message.as_ref()
    );
}

fn seed_empty_arl(state: &Arc<AppState>) -> Result<Option<String>> {
    let arl_path = PathBuf::from(&state.tm_dir)
        .join("nodes")
        .join("authority")
        .join("arl.json");
    let previous = fs::read_to_string(&arl_path).ok();

    let arl = crypto::RevocationList {
        version: 0,
        items: Vec::new(),
    };
    let content = serde_json::to_string(&arl)?;
    if let Some(parent) = arl_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&arl_path, content)?;

    Ok(previous)
}

fn restore_arl(state: &Arc<AppState>, previous: Option<String>) -> Result<()> {
    let arl_path = PathBuf::from(&state.tm_dir)
        .join("nodes")
        .join("authority")
        .join("arl.json");
    if let Some(content) = previous {
        if let Some(parent) = arl_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&arl_path, content)?;
    } else if arl_path.exists() {
        fs::remove_file(&arl_path)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let attr = "FR-DR";
    let message = b"test";
    let cpabe_attrs = vec!["FR-DR".to_string(), "M1".to_string()];
    let label = crypto::DocumentLabel {
        classification: "FR-DR".to_string(),
        mission: "M1".to_string(),
    };

    let (abs_params, abs_msk) = measure("abs::setup()", || {
        crypto::abs::setup().context("abs::setup failed")
    })?;
    let abs_user_key = measure("abs::extract()", || {
        crypto::abs::extract(&abs_params, &abs_msk, attr).context("abs::extract failed")
    })?;
    let abs_sig = measure("abs::sign()", || {
        crypto::abs::sign(&abs_params, &abs_user_key, message).context("abs::sign failed")
    })?;
    let abs_verified = measure("abs::verify_with_attr()", || {
        crypto::abs::verify_with_attr(&abs_params, &abs_sig, message, attr)
            .context("abs::verify_with_attr failed")
    })?;
    anyhow::ensure!(abs_verified, "abs::verify_with_attr returned false");

    let (pp, msk) = measure("cpabe::setup()", || {
        crypto::cpabe::setup().context("cpabe::setup failed")
    })?;
    let (pska, psks) = measure("cpabe::keygen()", || {
        crypto::cpabe::keygen(&pp, &msk, &cpabe_attrs).context("cpabe::keygen failed")
    })?;
    let (delegated_psks, tk) = measure("cpabe::delegate()", || {
        crypto::cpabe::delegate(&pp, &psks, &cpabe_attrs).context("cpabe::delegate failed")
    })?;
    let delegated_pska = measure("cpabe::tm_delegate()", || {
        crypto::cpabe::tm_delegate(&pska, &tk).context("cpabe::tm_delegate failed")
    })?;
    let ct = measure("cpabe::encrypt()", || {
        crypto::cpabe::encrypt(&pp, &label, "test").context("cpabe::encrypt failed")
    })?;
    let cti = measure("cpabe::tm_decrypt()", || {
        crypto::cpabe::tm_decrypt(&pp, &ct, &pska).context("cpabe::tm_decrypt failed")
    })?;
    let decrypted = measure("cpabe::decrypt()", || {
        crypto::cpabe::decrypt(&pp, &cti, &psks).context("cpabe::decrypt failed")
    })?;
    anyhow::ensure!(
        decrypted == "test",
        "cpabe::decrypt returned an unexpected plaintext"
    );

    let delegated_cti = crypto::cpabe::tm_decrypt(&pp, &ct, &delegated_pska)
        .context("delegated cpabe::tm_decrypt failed")?;
    let delegated_decrypted = crypto::cpabe::decrypt(&pp, &delegated_cti, &delegated_psks)
        .context("delegated cpabe::decrypt failed")?;
    anyhow::ensure!(
        delegated_decrypted == "test",
        "delegated cpabe decrypt returned an unexpected plaintext"
    );

    let state = build_default_state().context("failed to build benchmark AppState")?;
    let previous_arl = seed_empty_arl(&state).context("failed to seed ARL for revoke_missions")?;
    let missions = vec!["M1".to_string()];
    let revoke_result = measure("mod::revoke_missions()", || {
        crypto::revoke_missions(&state, &missions).context("revoke_missions failed")
    });
    let restore_result = restore_arl(&state, previous_arl);

    let arl = revoke_result?;
    restore_result.context("failed to restore ARL after revoke_missions benchmark")?;
    anyhow::ensure!(
        arl.items
            .iter()
            .any(|item| { item.attribute_type == "mission" && item.attribute_value == "M1" }),
        "revoke_missions did not add mission M1 to the ARL"
    );

    Ok(())
}
