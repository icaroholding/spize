# AEX Protocol v1

The protocol specification is under active maintenance. Until this
document is fully written, the authoritative references are:

- **Wire format byte-exact reference** — `crates/aex-core/src/wire.rs`:
  `registration_challenge_bytes`, `transfer_intent_bytes`,
  `transfer_receipt_bytes`, `data_ticket_bytes`.
- **State machine + architectural reasoning** —
  [docs/architecture.md](./architecture.md).
- **Reference identities format** — see the `AgentId::new()` validator
  in `crates/aex-core/src/types.rs`.

A full spec that allows re-implementation without reading the Rust
code is tracked as an alpha.3 deliverable.
