DoDWAN integration shim

This prototype uses `src/network/netmanager.rs` as a local DoDWAN-compatible pub/sub adapter.
The runtime bus is stored under `src/network/dodwan/runtime/` and exposes join, subscribe,
send, sendSecured, publish, publishSecured, and onRcv behavior.

A full upstream DoDWAN daemon can be wired by replacing the storage adapter in
`src/network/netmanager.rs` while preserving the same API used by `src/network/main.rs`.
