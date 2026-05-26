# p2poolv2-capnp-types

Cap'n Proto schema and generated Rust bindings for the [p2poolv2](https://github.com/p2poolv2/p2poolv2)
IPC interface. Mirrors the [`bitcoin-capnp-types`](https://github.com/2140-dev/bitcoin-capnp-types)
shape: schema in `proto/`, bindings emitted at build time by `capnpc`.

## License

Dual-licensed `MIT OR Apache-2.0`. The schema is data-only; the AGPL
boundary stays at the p2poolv2 daemon binary, not at this crate. See
the sv2-p2pool ADR `docs/adr/0010-capnp-schema-hosting.md` for the
rationale.

## Status

Phase 2 stub. The interface is the one proposed in the sv2-p2pool
integration plan; the file ID in `proto/p2poolv2.capnp` is a
placeholder that should be regenerated with `capnp id` before this
crate is published to crates.io.
