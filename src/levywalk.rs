//! Launcher for LEPTON's native Levy Walk mobility model.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Launch the embedded LEPTON distribution with its native mobility model.
pub fn run(base_dir: &Path) -> Result<()> {
    let lepton_home = base_dir.join("src/network/tools/lepton");
    let config = lepton_home.join("conf/levywalk.conf");
    let script = lepton_home.join("bin/lepton.sh");

    if !script.is_file() {
        anyhow::bail!("LEPTON launcher not found: {}", script.display());
    }
    if !config.is_file() {
        anyhow::bail!(
            "LEPTON Levy Walk configuration not found: {}",
            config.display()
        );
    }

    println!("Launching native LEPTON with its Levy Walk configuration...");
    let status = Command::new("./bin/lepton.sh")
        .current_dir(&lepton_home)
        .arg("start")
        .arg(format!("conf={}", config.display()))
        .status()
        .context("failed to launch LEPTON")?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("LEPTON exited with status {status}")
    }
}
