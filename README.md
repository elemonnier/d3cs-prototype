# d3cs-prototype

Rust prototype of a dynamic and decentralized data-centric security (D3CS) demonstrator combining CP-ABE and ABS, with a local web UI and a simulated network mode (with DoDWAN = document dissemination in wireless ad-hoc networks).

## Docs

- Ciphertext-policy attribute-based encryption (CP-ABE) cryptography from: Porwal, S., Mittal, S. A fully flexible key delegation mechanism with efficient fine-grained access control in CP-ABE. J Ambient Intell Human Comput 14, 12837–12856 (2023). https://doi.org/10.1007/s12652-022-04196-y
- Attribute-based signatures (ABS) cryptography from: Li, J., Kim, K. Hidden attribute-based signatures without anonymity revocation. Information Sciences 180(9), 1681–1689 (2010). https://doi.org/10.1016/j.ins.2010.01.008
- DoDWAN: https://casa-irisa.univ-ubs.fr/dodwan/
- Find workflow functionnalities in diagrams/.

## Goal

This project provides a sandbox to:
- manage clearances (`classification`, `mission`)
- handle delegation of accesses
- encrypt/decrypt labeled documents
- handle attribute revocation
- test local and multi-node execution

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
cargo run
```

Then open:
- `http://127.0.0.1:18080` (port currently set in `.env`)

Default admin credentials at startup:
- login: `admin`
- password: `minad`

## Execution Modes

### 1) Local (default)

```bash
cargo run
```

- single process
- web UI + API on the configured port

### 2) Network on a Specific Node

```bash
cargo run -- network U1
```

Common port mapping examples:
- `Authority` -> `18080`
- `U1` -> `18081`
- ...
- `U9` -> `18089`

To force a port:

```bash
D3CS_PORT=18081 cargo run -- network U1
```

### 3) Local Network Cluster (multiple processes)

```bash
cargo run -- network-all
```

Starts `Authority` + `U1..U9` and waits for child processes to exit.

## Environment Variables

Loaded via `.env` if present:

- `D3CS_HOST` (default `127.0.0.1`)
- `D3CS_PORT` (local default `8080`, overridden by `.env` in this repo)
- `D3CS_CONFIG_DIR` (default `config`)
- `D3CS_USERS_DIR` (default `users`)
- `D3CS_TM_DIR` (default `tm`)
- `D3CS_AUTHORITY_DIR` (default `authority`)
- `D3CS_IHM_DIR` (default `gui` if present, otherwise `ihm`)
- `D3CS_NETWORK_DIR` (default `network/dodwan/runtime`)

## Recommended Demo Flow

1. Sign in as admin (`admin` / `minad`)
2. Create a user via `Sign up` (clearance JSON)
3. Encrypt a document (`classification` + `mission`)
4. Browse/decrypt documents from the list
5. Test revocation/presets as admin

Example clearance JSON:

```json
{
  "classification": "FR-S",
  "mission": "M1"
}
```

## Useful Structure

- `src/`: main server + API routes + orchestration
- `src/crypto/`: CP-ABE / ABS / policy logic
- `network/`: network runtime and local DoDWAN adapter
- `gui/`: main web interface
- `config/`: attributes + BLP/Biba presets
- `tm/`: technical artifacts (CT, signatures, ARL, params)
- `users/`: user data and derived keys
- `authority/`: authority secrets
- `specs/`: functional demonstrator specifications (in French)
- `diagrams/`: operation flow diagrams

## Verification

Check that the code compiles:

```bash
cargo check
```

## Important Notes

- Demonstration project: do not use in production. Hybrid encryption is missing for demonstration purpose.
- Avoid versioning real secrets in `.env`, `authority/`, `users/`.

## Demo and paper

Work in progress!