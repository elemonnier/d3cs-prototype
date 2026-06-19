# d3cs-prototype

Rust prototype of a dynamic and decentralized data-centric security (D3CS) demonstrator combining CP-ABE and ABS, with a local web UI and a emulated network mode (with DoDWAN = Document Dissemination in Wireless Ad-hoc Networks and LEPTON = Lightweight Emulation PlaTform for Opportunistic Networking).

## Demo

A demonstration is available in this folder: d3cs.mp4

## Docs

- Ciphertext-policy attribute-based encryption (CP-ABE) cryptography from: Porwal, S., Mittal, S. A fully flexible key delegation mechanism with efficient fine-grained access control in CP-ABE. J Ambient Intell Human Comput 14, 12837–12856 (2023). https://doi.org/10.1007/s12652-022-04196-y
- Attribute-based signatures (ABS) cryptography from: Li, J., Kim, K. Hidden attribute-based signatures without anonymity revocation. Information Sciences 180(9), 1681–1689 (2010). https://doi.org/10.1016/j.ins.2010.01.008
- DoDWAN: https://casa-irisa.univ-ubs.fr/dodwan/
- DoDWAN-NAPI: https://casa-irisa.univ-ubs.fr/dodwan/doc/napi/dodwan_network_api_protocol.html
- LEPTON: https://casa-irisa.univ-ubs.fr/lepton/

## Prerequisites

- Rust toolchain installed (`cargo`, `rustc`)
- Linux/WSL environment recommended

Quick check:

```bash
cargo --version
rustc --version
```

## Execution Modes

### 1) Local (default)

```bash
cargo run
```

Then open:
- `http://127.0.0.1:18080` (port currently set in `.env`)

Login: authority / password: authority
You can create accounts on the "Sign up" menu.

### 2) Network single-process

```bash
cargo run -- network Authority
```

```bash
cargo run -- network U1
```

etc. until U9

### 2) Network (multiple processes/ports)

```bash
cargo run -- network-all
```

Starts `Authority` + `U1..U9` and waits for child processes to exit.
Ports: 127.0.0.1:18080 for Authority, :18081 for u1, :18082 for u2, until :18089 for u9.

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

## Timings

Allows you to measure the execution time of CP-ABE and ABS methods.

```bash
cargo run --bin timings --release
```

## Structure

- `src/main.rs`: application entry point, mode selection, startup orchestration, HTTP server
- `src/api.rs`: HTTP API routes used by the web UI
- `src/authority/`: authority setup helpers and authority-side storage initialization
- `src/crypto/`: CP-ABE and ABS primitives (setup, keygen, encrypt, decrypt, delegate, extract, sign, verify, etc.)
- `src/network/`: network mode runtime, DoDWAN/LEPTON integration, packet handling
- `src/bin/`: standalone binaries such as timings and network tool tests
- `src/gui/`: local web UI served by the Rust HTTP server
- `src/config/`: attribute definitions and BLP/Biba presets
- `docs/specs/`: local and network demonstrator specifications
- `docs/sequencediagrams/`: workflow sequence diagrams
- `docs/statediagrams/`: state diagrams
- `docs/cmds/`: DoDWAN command/frame notes
- `docs/papers/`: reference papers used by the prototype

## Important Notes

- Demonstration project: do not use in production. Hybrid encryption is missing for demonstration purpose.
- Avoid versioning real secrets in `.env`, `runtime/authority/`, `runtime/users/`.
- GPT-5.x-Codex was used in this project to generate code according to the specs.

## Paper

Work in progress!
