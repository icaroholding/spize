//! AEX conformance test suite — Rust side.
//!
//! Each submodule pins a Rust-side implementation of a normative protocol rule
//! to the values documented in `docs/protocol-v1.md`. Sibling SDKs
//! (`packages/sdk-python`, `packages/sdk-typescript`) maintain their own
//! conforming tests against the same spec.

mod retry;
