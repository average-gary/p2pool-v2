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

    # Read the current share-chain tip blockhash. Returns
    # `uninitialised` when the daemon has not yet completed
    # genesis setup (mirrors `ChainStoreHandle::get_chain_tip()`
    # returning a NotFound on the inner store).
    getChainTip @3 () -> (result :ChainTipResult);

    # Look up a single share header by its share blockhash.
    # Returns `genesis` for the all-zeros sentinel that marks the
    # genesis block's predecessor (preserves the engine's existing
    # genesis-reached check); `notFound` for a missing header;
    # `found` carrying just the prev_share_blockhash field the
    # engine consumes today. Other ShareHeader fields are
    # deliberately not serialised — see the comment on
    # `ShareHeaderRead`.
    getShareHeader @4 (shareHash :Data) -> (result :ShareHeaderResult);

    # Read the current confirmed-chain tip height. Returns
    # `uninitialised` when no confirmed tip exists yet.
    getTipHeight @5 () -> (result :TipHeightResult);

    # Read the bitcoin network the daemon was configured with. The
    # client is expected to call this exactly once at startup and
    # cache the value (the daemon does not support hot-swapping
    # networks).
    getNetwork @6 () -> (result :NetworkResult);
}

struct ValidationResult {
    union {
        ok                  @0 :Void;
        staleChainTip       @1 :Void;
        invalidCoinbase     @2 :Text;
        missingTransactions @3 :List(Data);
    }
}

# Result of `getChainTip`. Discriminated to distinguish "no genesis
# yet" (`uninitialised`) from a real transport error (capnp::Error).
struct ChainTipResult {
    union {
        tip           @0 :Data;   # 32-byte BlockHash
        uninitialised @1 :Void;
    }
}

# Result of `getTipHeight`. Same discrimination as ChainTipResult.
struct TipHeightResult {
    union {
        height        @0 :UInt32;
        uninitialised @1 :Void;
    }
}

# Result of `getShareHeader`. Three-way discrimination:
#
# * `found`     — header exists; carries the minimal subset the
#                 engine actually reads.
# * `notFound`  — no header for the requested share hash. The
#                 engine treats this as a truncated walk and
#                 falls back to invalidate-all.
# * `genesis`   — the all-zeros sentinel was passed; preserves
#                 the engine's "stop at genesis" check without
#                 requiring it to know the all-zeros encoding.
struct ShareHeaderResult {
    union {
        found    @0 :ShareHeaderRead;
        notFound @1 :Void;
        genesis  @2 :Void;
    }
}

# Minimal subset of `p2poolv2_lib::ShareHeader` exposed to the
# engine. The engine reads only `prev_share_blockhash` today;
# every other field on `ShareHeader` (uncles, miner_bitcoin_address,
# merkle_root, bitcoin_header, bits, time, donation, donation_address,
# fee, fee_address, coinbase_value, coinbaseaux_flags,
# witness_commitment, bitcoin_height, coinbase_nsecs, extranonce)
# is intentionally NOT serialised. If a future contributor needs
# one of those fields they should add it deliberately and bump the
# schema rather than reach into the daemon some other way.
struct ShareHeaderRead {
    prevShareBlockhash @0 :Data;   # 32-byte BlockHash
}

# Result of `getNetwork`. Discriminated rather than a bare enum so
# that "unknown" is representable for forward-compat with future
# bitcoin networks the schema crate doesn't yet enumerate.
struct NetworkResult {
    union {
        mainnet  @0 :Void;
        testnet  @1 :Void;
        testnet4 @2 :Void;
        regtest  @3 :Void;
        signet   @4 :Void;
        unknown  @5 :Void;
    }
}

interface ChainTipCallback {
    onNewTip @0 (newTipHash :Data) -> ();
}
