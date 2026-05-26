// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// Licensed under either of MIT OR Apache-2.0 at your option. The schema
// is dual-licensed (data-only) so non-AGPL clients can depend on it.

//! Cap'n Proto schema and generated Rust bindings for the p2poolv2 IPC
//! interface.
//!
//! This crate is the canonical schema for talking to a p2poolv2 daemon
//! over Cap'n Proto RPC. It mirrors the layout of
//! [`bitcoin-capnp-types`](https://github.com/2140-dev/bitcoin-capnp-types):
//! the schema lives in `proto/p2poolv2.capnp` and `build.rs` invokes
//! `capnpc` at build time to emit the Rust bindings into `OUT_DIR`.
//!
//! The schema is dual-licensed `MIT OR Apache-2.0` so that non-AGPL
//! clients (e.g., the sv2-p2pool integration crate) can depend on it
//! without inheriting the daemon's AGPL license. See the sv2-p2pool
//! ADR `docs/adr/0010-capnp-schema-hosting.md` for the rationale.
//!
//! # Stability
//!
//! Phase 2 stub. The interface is the one proposed in the integration
//! plan (`plan-sv2-p2pool-repo-2026-05-22.md` §2.2) but is **not yet
//! finalized**: the file ID in `proto/p2poolv2.capnp` is a placeholder
//! that should be regenerated with `capnp id` before this crate is
//! published to crates.io.

#![allow(clippy::all, missing_docs)]

pub mod p2poolv2_capnp {
    include!(concat!(env!("OUT_DIR"), "/p2poolv2_capnp.rs"));
}
