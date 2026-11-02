use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingRevocation {
    pub id: u64,
    pub requester: String,
    pub missions: Vec<String>,
}
pub struct UserDb {
    pub users: HashMap<String, UserRecord>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Local,
    Network,
}
pub const AUTHORITY_LOGIN: &str = "authority";
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

#[path = "../crypto/mod.rs"]
mod crypto;

const OUTPUT_DIR: &str = "results/cpabe/tm_storage";

fn serialized_size<T: Serialize>(value: &T) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn decoded_size(value: &str) -> usize {
    STANDARD_NO_PAD
        .decode(value)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

fn public_params_size(value: &crypto::cpabe::PublicParamsV1) -> usize {
    [&value.g, &value.g2, &value.h, &value.f, &value.f2, &value.y]
        .into_iter()
        .map(|item| decoded_size(item))
        .sum()
}

fn master_key_size(value: &crypto::cpabe::MasterKeyV1) -> usize {
    decoded_size(&value.alpha) + decoded_size(&value.beta)
}

fn pska_size(value: &crypto::cpabe::PskaV1) -> usize {
    decoded_size(&value.d)
}

fn psks_size(value: &crypto::cpabe::PsksV1) -> usize {
    value
        .attrs
        .iter()
        .map(|item| decoded_size(&item.d) + decoded_size(&item.d_prime))
        .sum()
}

fn tk_size(value: &crypto::cpabe::TkV1) -> usize {
    decoded_size(&value.t)
}

fn ciphertext_size(value: &crypto::cpabe::CiphertextV1) -> usize {
    decoded_size(&value.abe.c_tilde)
        + decoded_size(&value.abe.c)
        + value
            .abe
            .leafs
            .iter()
            .map(|item| decoded_size(&item.c_i) + decoded_size(&item.c_i_prime))
            .sum::<usize>()
        + decoded_size(&value.sym.nonce)
        + decoded_size(&value.sym.ciphertext)
}

fn intermediate_ciphertext_size(value: &crypto::cpabe::IntermediateCiphertextV1) -> usize {
    decoded_size(&value.abe.c_tilde)
        + decoded_size(&value.abe.f)
        + value
            .abe
            .leafs
            .iter()
            .map(|item| decoded_size(&item.c_i) + decoded_size(&item.c_i_prime))
            .sum::<usize>()
        + decoded_size(&value.sym.nonce)
        + decoded_size(&value.sym.ciphertext)
}

fn command_output(command: &str, args: &[&str]) -> String {
    std::process::Command::new(command)
        .args(args)
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn arl(entries: usize) -> crypto::RevocationList {
    crypto::RevocationList {
        version: 1,
        items: (0..entries)
            .map(|i| crypto::RevocationEntry {
                attribute_type: "mission".to_string(),
                attribute_value: format!("M{i}"),
            })
            .collect(),
    }
}

fn main() -> Result<()> {
    let output = Path::new(OUTPUT_DIR);
    fs::create_dir_all(output)?;

    let (pp, msk) = crypto::cpabe::setup()?;
    let attrs = vec!["FR-DR".to_string(), "M1".to_string()];
    let (pska, psks) = crypto::cpabe::keygen(&pp, &msk, &attrs)?;
    let (delegated_psks, tk) = crypto::cpabe::delegate(&pp, &psks, &attrs)?;
    let delegated_pska = crypto::cpabe::tm_delegate(&pska, &tk)?;
    let label = crypto::DocumentLabel {
        classification: "FR-DR".to_string(),
        mission: "M1".to_string(),
    };
    let ciphertext = crypto::cpabe::encrypt(&pp, &label, "storage-size")?;
    let intermediate = crypto::cpabe::tm_decrypt(&pp, &ciphertext, &delegated_pska)?;
    anyhow::ensure!(
        crypto::cpabe::decrypt(&pp, &intermediate, &delegated_psks)? == "storage-size",
        "CP-ABE storage reference round-trip failed"
    );

    let rows = [
        (
            "public_parameters",
            serialized_size(&pp)?,
            public_params_size(&pp),
            "TM PP",
        ),
        (
            "master_secret_key",
            serialized_size(&msk)?,
            master_key_size(&msk),
            "Authority MSK",
        ),
        ("pska", serialized_size(&pska)?, pska_size(&pska), "TM PSKA"),
        (
            "psks",
            serialized_size(&psks)?,
            psks_size(&psks),
            "User PSKS",
        ),
        ("tk", serialized_size(&tk)?, tk_size(&tk), "Delegation TK"),
        (
            "delegated_pska",
            serialized_size(&delegated_pska)?,
            pska_size(&delegated_pska),
            "Delegated TM PSKA",
        ),
        (
            "delegated_psks",
            serialized_size(&delegated_psks)?,
            psks_size(&delegated_psks),
            "Delegated user PSKS",
        ),
        (
            "ciphertext",
            serialized_size(&ciphertext)?,
            ciphertext_size(&ciphertext),
            "Stored CT",
        ),
        (
            "intermediate_ciphertext",
            serialized_size(&intermediate)?,
            intermediate_ciphertext_size(&intermediate),
            "Stored CTI",
        ),
    ];
    let mut csv = String::from(
        "object,serialized_json_bytes,decoded_crypto_payload_bytes,representation,storage_role\n",
    );
    for (object, serialized, decoded, role) in rows {
        csv.push_str(&format!(
            "{object},{serialized},{decoded},serde_json UTF-8 with Base64 fields,{role}\n"
        ));
    }
    fs::write(output.join("cpabe_object_sizes.csv"), csv)?;

    let abs_params = crypto::abs::setup()?.0;
    let fixed_state = serialized_size(&pp)?
        + serialized_size(&abs_params)?
        + serialized_size(&pska)?
        + serialized_size(&tk)?;
    let mut scalability = String::from(
        "arl_entries,fixed_tm_state_serialized_bytes,arl_serialized_size_bytes,total_tm_state_serialized_bytes\n",
    );
    let mut summary =
        String::from("configuration,total_tm_state_serialized_bytes,arl_share_percent\n");
    for entries in [0usize, 1, 10, 50, 100, 500, 1000] {
        let arl_size = serialized_size(&arl(entries))?;
        let total = fixed_state + arl_size;
        scalability.push_str(&format!("{entries},{fixed_state},{arl_size},{total}\n"));
        let share = 100.0 * arl_size as f64 / total as f64;
        summary.push_str(&format!("ARL_{entries},{total},{share:.6}\n"));
    }
    fs::write(output.join("tm_storage_scalability.csv"), scalability)?;
    fs::write(output.join("tm_storage_summary.csv"), summary)?;

    let status = command_output("git", &["status", "--porcelain"]);
    let metadata = serde_json::json!({
        "benchmark": "CP-ABE TM storage and serialized object sizes",
        "cryptographic_version": "2",
        "curve": "BLS12-381",
        "hash_to_curve": "G2, deterministic hash-to-curve",
        "build_mode": "release",
        "git_commit": command_output("git", &["rev-parse", "HEAD"]),
        "git_worktree": if status == "unavailable" { status } else if status.is_empty() { "clean".to_string() } else { "modified".to_string() },
        "rustc": command_output("rustc", &["--version"]),
        "dependencies": command_output("cargo", &["tree", "--depth", "1"]),
        "operating_system": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "processor": command_output(
            "bash",
            &[
                "-lc",
                "lscpu | sed -n '/Model name/ { s/^[^:]*:[[:space:]]*//; p; q; }'",
            ],
        ),
        "system_id": pp.system_id,
        "arl_cardinalities": [0, 1, 10, 50, 100, 500, 1000],
        "size_note": "decoded_crypto_payload_bytes counts decoded Base64 cryptographic fields; JSON metadata and labels are excluded",
    });
    fs::write(
        output.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    Ok(())
}
