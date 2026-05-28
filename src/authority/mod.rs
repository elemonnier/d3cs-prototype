use anyhow::Result;
use std::fs;
use std::sync::Arc;

use crate::AppState;

// s'assure que les répertoires sont bien créés

pub fn ensure_directories(state: &Arc<AppState>) -> Result<()> {
    fs::create_dir_all(&state.config_dir)?;
    fs::create_dir_all(&state.users_dir)?;
    fs::create_dir_all(&state.tm_dir)?;
    fs::create_dir_all(&state.authority_dir)?;
    fs::create_dir_all(&state.ihm_dir)?;
    fs::create_dir_all(format!("{}/nodes", state.tm_dir))?;

    Ok(())
}
