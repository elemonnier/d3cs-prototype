# d3cs-prototype

Rust prototype of a dynamic and decentralized data-centric security (D3CS) demonstrator combining CP-ABE and ABS, with a local web UI and a simulated network mode (with DoDWAN = document dissemination in wireless ad-hoc networks).

## Docs

- Ciphertext-policy attribute-based encryption (CP-ABE) cryptography from: Porwal, S., Mittal, S. A fully flexible key delegation mechanism with efficient fine-grained access control in CP-ABE. J Ambient Intell Human Comput 14, 12837–12856 (2023). https://doi.org/10.1007/s12652-022-04196-y
- Attribute-based signatures (ABS) cryptography from: Li, J., Kim, K. Hidden attribute-based signatures without anonymity revocation. Information Sciences 180(9), 1681–1689 (2010). https://doi.org/10.1016/j.ins.2010.01.008
- DoDWAN: https://casa-irisa.univ-ubs.fr/dodwan/
- Find workflow functionnalities in diagrams/.

## Prerequisites

- Rust toolchain installed (`cargo`, `rustc`)
- Linux/WSL environment recommended

Quick check:

```bash
cargo --version
rustc --version
```

## Quick Start (Local Mode)

From the project root:

```bash
cargo build
cargo run
```

Then open:
- `http://127.0.0.1:18080` (port currently set in `.env`)

Default admin credentials at startup:
- login: `admin` / password: `minad`

Or as user:
- login: `u1` / password: `u1`
- login: `u2` / password: `u2`
- etc. until `u9`

## Execution Modes

### 1) Local (default)

```bash
cargo run
```

- single process
- web UI + API on the configured port (default 127.0.0.1:18080)

### 2) Network (multiple processes/ports)

```bash
cargo run -- network-all
```

Starts `Authority` + `U1..U9` and waits for child processes to exit.
Ports: 127.0.0.1:18080 for Authority, :18081 for u1, :18082 for u2, until :18089 for u9

Clearance mapping is:
U1 -> FR-DR:M1
U2 -> FR-S:M1
U3 -> FR-DR:M2
U4 -> FR-S:M2
U5 -> FR-DR:M1
U6 -> FR-S:M1
U7 -> FR-DR:M2
U8 -> FR-S:M2
U9 -> FR-DR:M1

Network is managed via GET/POST requests (defined in src/api.rs) from GUI to local server. Cookies are used to let the users be connected through HTTP pages. Polling is performed every 500ms to receive server state (instead of Websocket that uses interrupt). A simulation publish/subscribe (to simulate DoDWAN) is performed between nodes.

## Timings

```bash
cargo run --bin timings --release
```

Allows you to measure the execution time of CP-ABE and ABS methods.

## Lepton simulation

```bash
src/network/tools/lepton/bin/lepton.sh start
```

Allows you to start lepton simulation.

## Environment Variables

Loaded via `.env` if present:

- `D3CS_HOST` (default `127.0.0.1`)
- `D3CS_PORT` (local default `8080`, overridden by `.env` in this repo)
- `D3CS_CONFIG_DIR` (default `src/config`)
- `D3CS_USERS_DIR` (default `runtime/users`)
- `D3CS_TM_DIR` (default `runtime/tm`)
- `D3CS_AUTHORITY_DIR` (default `runtime/authority`)
- `D3CS_IHM_DIR` (default `src/gui` if present, otherwise `src/ihm`)
- `D3CS_NETWORK_DIR` (default `src/network/dodwan/runtime`)

## Demo Example

1. Run local execution (cargo run)
2. Sign in as admin (`admin` / `minad`)
3. Encrypt a document (`classification` + `mission`)
4. Browse/decrypt documents from the list
5. Test revocation/presets as admin

## Structure

- `src/`: main server + API routes + orchestration
- `src/crypto/`: CP-ABE / ABS
- `src/network/`: network runtime and local DoDWAN adapter
- `src/gui/`: main web interface
- `src/config/`: attributes + BLP/Biba presets
- `runtime/tm/`: technical artifacts (CT, signatures, ARL, params)
- `runtime/users/`: user data and derived keys
- `runtime/authority/`: authority secrets
- `specs/`: demonstrator specifications (in French)
- `diagrams/`: operation flow diagrams

## Important Notes

- Demonstration project: do not use in production. Hybrid encryption is missing for demonstration purpose.
- Avoid versioning real secrets in `.env`, `runtime/authority/`, `runtime/users/`.
- GPT-5.3-Codex was used in this project to generate code according to the specs.

## Paper

Work in progress!
