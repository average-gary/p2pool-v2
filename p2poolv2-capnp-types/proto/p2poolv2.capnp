# Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
#
# This Cap'n Proto schema is dual-licensed MIT OR Apache-2.0 to match the
# `bitcoin-capnp-types` precedent: the schema is plain data and must be
# consumable from non-AGPL clients. The AGPL boundary stays at the
# p2poolv2 daemon binary, not at the schema.
#
# NOTE on file ID: this file ID was generated as a placeholder and SHOULD
# be regenerated with `capnp id` before this crate is published to
# crates.io. Schema/wire format is not finalized; this is the IPC
# contract proposed in plan-sv2-p2pool-repo-2026-05-22.md §2.2.

@0xb1c0a7c0ffeec0a7;

# Share-chain IPC interface. Phase-2 stub: methods on the p2poolv2 side
# return placeholder responses; real validation, submission, and tip
# subscription wiring is a follow-up PR (see issue #7 and ADR 0010 in
# the sv2-p2pool repo).
interface ShareChain {
    # Validate a candidate Sv2 template against the share-chain tip.
    #
    # The caller (sv2-p2pool client) provides the coinbase split plus
    # the wtxid list and any missing-tx blobs the server requests. The
    # server returns a structured ValidationResult.
    validateTemplate @0 (
        coinbasePrefix :Data,
        coinbaseSuffix :Data,
        wtxidList      :List(Data),
        missingTxs     :List(Data),
    ) -> (result :ValidationResult);

    # Submit a solved block (raw serialized block + share hash) to the
    # share-chain. Returns whether it was accepted as a valid share.
    submitSolution @1 (
        rawBlock :Data,
        shareHash :Data,
    ) -> (accepted :Bool);

    # Subscribe to share-chain tip changes. The supplied callback's
    # `onNewTip` method is invoked whenever the share-chain tip
    # advances.
    subscribeChainTip @2 (callback :ChainTipCallback);
}

struct ValidationResult {
    union {
        ok                  @0 :Void;
        staleChainTip       @1 :Void;
        invalidCoinbase     @2 :Text;
        missingTransactions @3 :List(Data);
    }
}

interface ChainTipCallback {
    onNewTip @0 (newTipHash :Data) -> ();
}
