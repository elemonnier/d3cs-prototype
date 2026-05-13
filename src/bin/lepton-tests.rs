// programme lançant 10 démons dodwan grâce à la simulation Lepton

use std::process::Command;

const LEPTON_HOME: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/network/tools/lepton");
const DODWAN_HOME: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/network/tools/dodwan");
const DODWAN_ADAPTER_HOME: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/network/tools/dodwan-adapter"
);
const D3CS_USERS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/runtime/users");
const OPPNET_ADAPTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/network/tools/dodwan-adapter/bin/adapter.sh"
);

fn main() {
    Command::new("./bin/lepton.sh")
        .current_dir(LEPTON_HOME)
        .env("DODWAN_HOME", DODWAN_HOME)
        .env("DODWAN_ADAPTER_HOME", DODWAN_ADAPTER_HOME)
        .env("D3CS_USERS_DIR", D3CS_USERS_DIR)
        .arg("start")
        .arg(format!("oppnet_adapter={OPPNET_ADAPTER}"))
        .arg("nodes=10")
        .status()
        .unwrap();
}
