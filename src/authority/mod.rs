use anyhow::Result;
use std::fs;
use std::sync::Arc;

use crate::AppState;

pub fn ensure_directories(state: &Arc<AppState>) -> Result<()> {
    fs::create_dir_all(&state.config_dir)?;
    fs::create_dir_all(&state.users_dir)?;
    fs::create_dir_all(&state.tm_dir)?;
    fs::create_dir_all(&state.authority_dir)?;
    fs::create_dir_all(&state.ihm_dir)?;

    fs::create_dir_all(format!("{}/ct", state.tm_dir))?;
    fs::create_dir_all(format!("{}/s", state.tm_dir))?;
    fs::create_dir_all(format!("{}/ct_intermediate", state.tm_dir))?;
    fs::create_dir_all(format!("{}/pska", state.tm_dir))?;

    Ok(())
}