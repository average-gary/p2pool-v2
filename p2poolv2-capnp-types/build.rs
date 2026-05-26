// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// Licensed under either of MIT OR Apache-2.0 at your option. The schema
// is dual-licensed (data-only) so non-AGPL clients can depend on it.

fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("proto")
        .file("proto/p2poolv2.capnp")
        .run()
        .expect("compiling p2poolv2.capnp schema");
    println!("cargo:rerun-if-changed=proto/p2poolv2.capnp");
}
