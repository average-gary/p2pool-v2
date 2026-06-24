// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::consensus::encode::serialize_hex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(any(test, feature = "test-utils"))]
pub mod mock;

/// JSON-RPC 1.0 request structure (Bitcoin Core format)
#[derive(Serialize)]
struct JsonRpcRequest {
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

/// JSON-RPC 1.0 response structure (Bitcoin Core format)
/// In JSON-RPC 1.0, both result and error are always present
/// One will be the actual value, the other will be null
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
    result: T,
    error: Option<JsonRpcError>,
}

/// JSON-RPC 1.0 error structure
#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize, Clone)]
#[allow(dead_code)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub username: String,
    pub password: String,
}

/// Custom Debug to redact passwords
impl std::fmt::Debug for BitcoinRpcConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BitcoinRpcConfig")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Error type for the BitcoindRpcClient
#[derive(Debug)]
pub enum BitcoindRpcError {
    HttpError { status_code: u16, message: String },
    ParseError { message: String },
    RpcError { code: i32, message: String },
    Other(String),
}

impl Error for BitcoindRpcError {
    fn description(&self) -> &str {
        match self {
            BitcoindRpcError::HttpError { message, .. } => message,
            BitcoindRpcError::ParseError { message } => message,
            BitcoindRpcError::RpcError { message, .. } => message,
            BitcoindRpcError::Other(msg) => msg,
        }
    }
}
impl fmt::Display for BitcoindRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoindRpcError::HttpError {
                status_code,
                message,
            } => {
                write!(f, "HTTP error {status_code}: {message}")
            }
            BitcoindRpcError::ParseError { message } => {
                write!(f, "Parse error: {message}")
            }
            BitcoindRpcError::RpcError { code, message } => {
                write!(f, "RPC error {code}: {message}")
            }
            BitcoindRpcError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct GetBlockchainInfo {
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
}

/// Outcome of `getblocktemplate` in `proposal` mode.
///
/// Bitcoin Core's `getblocktemplate` (BIP 23) replies in proposal mode with:
/// - `null` (no rejection) → the candidate is a valid block extending the
///   current tip,
/// - A string (or, in some forks, an object with a `reject-reason` field)
///   describing why the proposal was rejected. The special reason
///   `"duplicate"` means bitcoind already has the block in its chain — for
///   p2pool's purposes that is still "the block looks valid", just not novel.
///
/// The Track B redesign surfaces this richer outcome so that callers
/// (e.g. SCMJ pre-validation, `submit_solution` book-keeping) can distinguish
/// the three cases instead of being forced into a `bool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// bitcoind considers the proposed block valid relative to its tip
    /// (response was `null` / contained no reject reason).
    Accepted,
    /// bitcoind has already seen this block — `reject-reason == "duplicate"`.
    /// The block is structurally fine; it just isn't new.
    Duplicate,
    /// bitcoind rejected the proposal. The string carries the reject reason
    /// (e.g. `"bad-prevblk"`, `"high-hash"`, `"inconclusive"`).
    Rejected(String),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoindRpcClient {
    client: reqwest::Client,
    url: String,
    request_id: Arc<AtomicU64>,
}

impl BitcoindRpcClient {
    pub fn new(url: &str, username: &str, password: &str) -> Result<Self, BitcoindRpcError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            )
            .parse()
            .map_err(|e| BitcoindRpcError::Other(format!("Invalid header: {e}")))?,
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| BitcoindRpcError::Other(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            client,
            url: url.to_string(),
            request_id: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, BitcoindRpcError> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            method: method.to_string(),
            params,
            id,
        };

        let response = match self.client.post(&self.url).json(&request).send().await {
            Ok(resp) => resp,
            Err(e) => {
                let status_code = e.status().map(|s| s.as_u16());
                error!(
                    "HTTP request failed to bitcoin node: status={:?}, error={}",
                    status_code, e
                );
                return Err(BitcoindRpcError::Other(format!("HTTP request failed: {e}")));
            }
        };

        let status = response.status();

        // Check for non-success HTTP status codes
        if !status.is_success() {
            let status_code = status.as_u16();
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            error!(
                "Error reaching bitcoin node with status={:?}. Message={:?}",
                status_code, error_body
            );
            return Err(BitcoindRpcError::HttpError {
                status_code,
                message: error_body,
            });
        }

        let rpc_response: JsonRpcResponse<T> =
            response
                .json()
                .await
                .map_err(|e| BitcoindRpcError::ParseError {
                    message: format!("Failed to parse response: {e}"),
                })?;

        // JSON-RPC 1.0: check error first, then return result
        if let Some(error) = rpc_response.error {
            return Err(BitcoindRpcError::RpcError {
                code: error.code,
                message: error.message,
            });
        }

        // In JSON-RPC 1.0, result is always present (can be null for void methods like submitblock)
        Ok(rpc_response.result)
    }

    /// Get current bitcoin difficulty from bitcoind rpc
    pub async fn get_difficulty(&self) -> Result<f64, BitcoindRpcError> {
        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = self.request("getdifficulty", params).await?;
        Ok(result.as_f64().unwrap())
    }

    pub async fn getblockchaininfo(&self) -> Result<GetBlockchainInfo, BitcoindRpcError> {
        self.request("getblockchaininfo", vec![]).await
    }

    /// Get current bitcoin block count from bitcoind rpc
    /// We use special rules for signet
    pub async fn getblocktemplate(
        &self,
        network: bitcoin::Network,
    ) -> Result<String, BitcoindRpcError> {
        let params = match network {
            bitcoin::Network::Signet => {
                vec![serde_json::json!({
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit", "signet"],
                })]
            }
            _ => {
                vec![serde_json::json!({
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit"],
                })]
            }
        };
        debug!("Requesting getblocktemplate with params: {:?}", params);

        // Configure retry parameters
        const MAX_RETRIES: u32 = 5;
        const INITIAL_BACKOFF_MS: u64 = 10;
        const MAX_BACKOFF_MS: u64 = 160;

        let mut attempt = 0;
        let mut backoff_ms = INITIAL_BACKOFF_MS;
        let mut last_error = None;

        while attempt <= MAX_RETRIES {
            match self
                .request::<serde_json::Value>("getblocktemplate", params.clone())
                .await
            {
                Ok(result) => {
                    return Ok(result.to_string());
                }
                Err(e) => {
                    attempt += 1;
                    last_error = Some(e);

                    if attempt > MAX_RETRIES {
                        break;
                    }

                    debug!(
                        "getblocktemplate attempt {} failed, retrying in {}ms",
                        attempt, backoff_ms
                    );

                    // Sleep with exponential backoff
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;

                    // Double the backoff for next attempt (capped at max)
                    backoff_ms = std::cmp::min(backoff_ms * 2, MAX_BACKOFF_MS);
                }
            }
        }

        Err(last_error.unwrap_or(BitcoindRpcError::Other(
            "Failed to get block template after all retries".to_string(),
        )))
    }

    /// Decode a raw transaction using bitcoind RPC
    ///
    /// Sends the transaction serialized as hex to the Bitcoin Core RPC,
    /// then receives and parses the decoded transaction information.
    pub async fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, BitcoindRpcError> {
        // Serialize the transaction to hex string
        let tx_hex = serialize_hex(tx);

        // Prepare params for the RPC call
        let params = vec![serde_json::Value::String(tx_hex)];

        // Make the RPC request
        match self
            .request::<serde_json::Value>("decoderawtransaction", params)
            .await
        {
            Ok(result) => {
                // Parse the response into a bitcoin::Transaction
                let tx: bitcoin::Transaction = match serde_json::from_value(result) {
                    Ok(tx) => tx,
                    Err(e) => {
                        return Err(BitcoindRpcError::Other(format!(
                            "Failed to decode raw transaction: {e}"
                        )));
                    }
                };
                Ok(tx)
            }
            Err(e) => Err(BitcoindRpcError::Other(format!(
                "Failed to decode raw transaction: {e}",
            ))),
        }
    }

    pub async fn submit_block(&self, block: &bitcoin::Block) -> Result<String, BitcoindRpcError> {
        // Serialize the block to hex string
        let block_hex = serialize_hex(block);

        // Prepare params for the RPC call
        let params = vec![serde_json::Value::String(block_hex)];

        // Make the RPC request - submitblock returns null on success, or error string on failure
        let result: serde_json::Value = self.request("submitblock", params).await?;
        Ok(result.to_string())
    }

    /// Validate a proposed bitcoin block by calling `getblocktemplate` in
    /// proposal mode (BIP 23).
    ///
    /// Returns a [`ProposalOutcome`]:
    /// - `Accepted` when bitcoind returns `null` (or an object with no
    ///   `reject-reason` field) — the candidate is a valid block.
    /// - `Duplicate` when the reject reason is `"duplicate"` — the block is
    ///   already in bitcoind's chain. p2pool treats this as "structurally
    ///   fine, just not novel".
    /// - `Rejected(reason)` for any other reject reason.
    pub async fn validate_block_proposal(
        &self,
        block: &bitcoin::Block,
    ) -> Result<ProposalOutcome, BitcoindRpcError> {
        let block_hex = hex::encode(bitcoin::consensus::encode::serialize(block));
        let params = vec![serde_json::json!({
            "mode": "proposal",
            "data": block_hex,
        })];
        let response: serde_json::Value = self.request("getblocktemplate", params).await?;
        Ok(parse_proposal_outcome(&response))
    }
}

/// Pure parser for the `getblocktemplate` proposal-mode response.
///
/// Bitcoin Core has historically returned the reject-reason in a couple of
/// shapes depending on version / fork:
/// - JSON `null` for an accepted proposal.
/// - A bare string (e.g. `"duplicate"`, `"bad-prevblk"`).
/// - An object with a `reject-reason` field (BIP 23 long form), in which case
///   the absence of that field also indicates acceptance.
///
/// We accept all three shapes here so callers don't have to. The function is
/// `pub(crate)` so it can be unit-tested without an HTTP round-trip.
pub(crate) fn parse_proposal_outcome(response: &serde_json::Value) -> ProposalOutcome {
    // 1. Explicit `null` → accepted.
    if response.is_null() {
        return ProposalOutcome::Accepted;
    }

    // 2. Bare string reject-reason (legacy / common in tests).
    if let Some(reason) = response.as_str() {
        if reason.is_empty() {
            return ProposalOutcome::Accepted;
        }
        if reason == "duplicate" {
            return ProposalOutcome::Duplicate;
        }
        return ProposalOutcome::Rejected(reason.to_string());
    }

    // 3. Object shape: look for `reject-reason`.
    if let Some(obj) = response.as_object() {
        match obj.get("reject-reason") {
            None => ProposalOutcome::Accepted,
            Some(serde_json::Value::Null) => ProposalOutcome::Accepted,
            Some(serde_json::Value::String(s)) if s == "duplicate" => ProposalOutcome::Duplicate,
            Some(serde_json::Value::String(s)) => ProposalOutcome::Rejected(s.clone()),
            Some(other) => ProposalOutcome::Rejected(other.to_string()),
        }
    } else {
        // Anything else (number, array, bool) is treated as a rejection so we
        // surface the unexpected payload rather than silently accept.
        ProposalOutcome::Rejected(response.to_string())
    }
}

/// Trait abstraction over the parts of bitcoind's JSON-RPC API that p2poolv2 uses.
///
/// This allows callers (and downstream crates such as `sv2-p2pool-engine`) to
/// substitute a mock implementation for unit tests without spinning up a real
/// HTTP server.
///
/// All methods are object-safe: there are no generic methods, so callers may use
/// `Arc<dyn BitcoindLike>` as well as `impl BitcoindLike` / generic `B: BitcoindLike`.
#[async_trait]
pub trait BitcoindLike: Send + Sync {
    /// Current network difficulty (`getdifficulty`).
    async fn get_difficulty(&self) -> Result<f64, BitcoindRpcError>;

    /// Blockchain info (`getblockchaininfo`). Used for IBD checks.
    async fn getblockchaininfo(&self) -> Result<GetBlockchainInfo, BitcoindRpcError>;

    /// Fetch a block template for the given network (`getblocktemplate`).
    /// Returns the raw JSON template as a string.
    async fn getblocktemplate(&self, network: bitcoin::Network)
    -> Result<String, BitcoindRpcError>;

    /// Decode a raw bitcoin transaction via `decoderawtransaction`.
    async fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, BitcoindRpcError>;

    /// Submit a mined block to bitcoind (`submitblock`).
    async fn submit_block(&self, block: &bitcoin::Block) -> Result<String, BitcoindRpcError>;

    /// Validate a candidate block via `getblocktemplate` proposal mode.
    ///
    /// Returns a [`ProposalOutcome`] so callers can distinguish accepted,
    /// duplicate, and rejected (with reason) outcomes. See
    /// [`BitcoindRpcClient::validate_block_proposal`] for the wire details.
    async fn validate_block_proposal(
        &self,
        block: &bitcoin::Block,
    ) -> Result<ProposalOutcome, BitcoindRpcError>;
}

#[async_trait]
impl BitcoindLike for BitcoindRpcClient {
    async fn get_difficulty(&self) -> Result<f64, BitcoindRpcError> {
        BitcoindRpcClient::get_difficulty(self).await
    }

    async fn getblockchaininfo(&self) -> Result<GetBlockchainInfo, BitcoindRpcError> {
        BitcoindRpcClient::getblockchaininfo(self).await
    }

    async fn getblocktemplate(
        &self,
        network: bitcoin::Network,
    ) -> Result<String, BitcoindRpcError> {
        BitcoindRpcClient::getblocktemplate(self, network).await
    }

    async fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, BitcoindRpcError> {
        BitcoindRpcClient::decoderawtransaction(self, tx).await
    }

    async fn submit_block(&self, block: &bitcoin::Block) -> Result<String, BitcoindRpcError> {
        BitcoindRpcClient::submit_block(self, block).await
    }

    async fn validate_block_proposal(
        &self,
        block: &bitcoin::Block,
    ) -> Result<ProposalOutcome, BitcoindRpcError> {
        BitcoindRpcClient::validate_block_proposal(self, block).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::CompactTarget;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    #[tokio::test]
    async fn test_bitcoin_client() {
        // Start mock server
        let mock_server = MockServer::start().await;

        let auth_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Define expected request and response (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "method": "test",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "test response",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "testuser", "testpass").unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }

    #[tokio::test]
    async fn test_bitcoin_client_with_invalid_credentials() {
        let mock_server = MockServer::start().await;

        let client =
            BitcoindRpcClient::new(&mock_server.uri(), "invaliduser", "invalidpass").unwrap();
        let params: Vec<serde_json::Value> = vec![];
        let result: Result<String, BitcoindRpcError> = client.request("test", params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since we only use it to test the connection to a locally running bitcoind
    async fn test_bitcoin_client_real_connection() {
        let client = BitcoindRpcClient::new("http://localhost:38332", "p2pool", "p2pool").unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = client.request("getblockchaininfo", params).await.unwrap();

        assert!(result.is_object());
        assert!(result.get("chain").is_some());
    }

    #[tokio::test]
    async fn test_get_difficulty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "getdifficulty",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": 1234.56,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let difficulty = client.get_difficulty().await.unwrap();

        assert_eq!(difficulty, 1234.56);
    }

    #[tokio::test]
    async fn test_getblockchaininfo() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "getblockchaininfo",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "initialblockdownload": true,
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let info = client.getblockchaininfo().await.unwrap();

        assert_eq!(
            info,
            GetBlockchainInfo {
                initial_block_download: true,
            }
        );
    }

    #[tokio::test]
    async fn test_getblocktemplate_mainnet() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "getblocktemplate",
                "params": [{
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit"],
                }],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "version": 536870912,
                    "previousblockhash": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "transactions": [],
                    "coinbaseaux": {},
                    "coinbasevalue": 625000000,
                    "longpollid": "mockid",
                    "target": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "mintime": 1610000000,
                    "mutable": ["time", "transactions", "prevblock"],
                    "noncerange": "00000000ffffffff",
                    "sigoplimit": 80000,
                    "sizelimit": 4000000,
                    "curtime": 1610000000,
                    "bits": "170d6d54",
                    "height": 1000000,
                    "default_witness_commitment": "6a24aa21a9ed"
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let result = client.getblocktemplate(bitcoin::Network::Bitcoin).await;
        let result = result.unwrap();

        let result = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert!(result.get("version").is_some());
        assert_eq!(result.get("height").unwrap(), 1000000);
    }

    #[tokio::test]
    async fn test_getblocktemplate_signet() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "getblocktemplate",
                "params": [{
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit", "signet"],
                }],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "version": 536870912,
                    "previousblockhash": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "transactions": [],
                    "coinbaseaux": {},
                    "coinbasevalue": 625000000,
                    "longpollid": "mockid",
                    "target": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "mintime": 1610000000,
                    "mutable": ["time", "transactions", "prevblock"],
                    "noncerange": "00000000ffffffff",
                    "sigoplimit": 80000,
                    "sizelimit": 4000000,
                    "curtime": 1610000000,
                    "bits": "170d6d54",
                    "height": 2000000,
                    "default_witness_commitment": "6a24aa21a9ed"
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let result = client
            .getblocktemplate(bitcoin::Network::Signet)
            .await
            .unwrap();

        let result = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert!(result.get("version").is_some());
        assert_eq!(result.get("height").unwrap(), 2000000);
    }

    #[tokio::test]
    async fn test_decoderawtransaction() {
        let mock_server = MockServer::start().await;
        let tx_hex = "0100000001000000000000000000000000000000000000000000000000000000\
                  0000000000ffffffff1c02fa01010004bdaf326804554ce1370c0101010101\
                  01010101010101ffffffff0300e1f50500000000160014fd8b1a0b2a4c387d\
                  0a418969c62f2812c76ee45d0011102401000000160014ca81d03f2707c355\
                  502622c7db77fdf79546926e0000000000000000266a24aa21a9eddd9e37e4\
                  20b1b58781dada016dfa5812f62133a381e1a58e83389735b2330ef700000000";
        let tx = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(
            hex::decode(tx_hex).unwrap().as_slice(),
        )
        .unwrap();

        // Setup mock for decoderawtransaction (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "decoderawtransaction",
                "params": [tx_hex],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": serde_json::to_value(tx.clone()).unwrap(),
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();

        let decoded_tx = client.decoderawtransaction(&tx).await.unwrap();

        assert_eq!(decoded_tx, tx);
    }

    #[tokio::test]
    async fn test_submit_block() {
        let mock_server = MockServer::start().await;

        // Create a simple block
        let block = bitcoin::Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: "5e9a183768460fbf56eab199a66057375b424bdca195e7ecc808374365a7ea67"
                    .parse()
                    .unwrap(),
                merkle_root: "277c298e9f1254a59411cfc29f1a88ec6ee12cf4c955044d8bb8a7242cfed919"
                    .parse()
                    .unwrap(),
                time: 1610000000,
                bits: CompactTarget::from_consensus(503543726),
                nonce: 12345,
            },
            txdata: vec![],
        };

        let block_hex = serialize_hex(&block);

        // Setup mock for submitblock (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "submitblock",
                "params": [block_hex],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,  // null indicates success in Bitcoin Core
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();

        let result = client.submit_block(&block).await.unwrap();
        assert_eq!(result, "null"); // Successful submission returns null
    }

    #[tokio::test]
    async fn test_getblocktemplate_retry_logic() {
        let mock_server = MockServer::start().await;
        let auth_header = "Basic cDJwb29sOnAycG9vbA==";

        // Mock 3 failed responses followed by a successful one (JSON-RPC 1.0)
        // First 3 calls fail
        for i in 0..3 {
            Mock::given(method("POST"))
                .and(path("/"))
                .and(header("Authorization", auth_header))
                .and(body_json(serde_json::json!({
                    "method": "getblocktemplate",
                    "params": [{
                        "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                        "rules": ["segwit"],
                    }],
                    "id": i
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "result": null,
                    "error": {
                        "code": -1,
                        "message": format!("Failed attempt {}", i)
                    },
                    "id": i
                })))
                .expect(1) // Each mock should be called exactly once
                .mount(&mock_server)
                .await;
        }

        // Fourth call succeeds
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "method": "getblocktemplate",
                "params": [{
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit"],
                }],
                "id": 3
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "version": 536870912,
                    "height": 1000000,
                    "previousblockhash": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "bits": "1a01f56e"
                },
                "error": null,
                "id": 3
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let result = client.getblocktemplate(bitcoin::Network::Bitcoin).await;

        assert!(result.is_ok());
        let result_value = serde_json::from_str::<serde_json::Value>(&result.unwrap()).unwrap();
        assert_eq!(result_value.get("height").unwrap(), 1000000);
    }

    #[tokio::test]
    async fn test_request_with_4xx_http_error() {
        let mock_server = MockServer::start().await;

        // Mock a 401 Unauthorized response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "method": "getdifficulty",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let result: Result<f64, BitcoindRpcError> = client.get_difficulty().await;

        assert!(result.is_err());
        if let Err(BitcoindRpcError::HttpError {
            status_code,
            message,
        }) = result
        {
            assert_eq!(status_code, 401);
            assert_eq!(message, "Unauthorized");
        } else {
            panic!("Expected BitcoindRpcError::HttpError, got {result:?}");
        }
    }

    // ---- parse_proposal_outcome unit tests ----------------------------------

    #[test]
    fn proposal_outcome_null_is_accepted() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::Value::Null),
            ProposalOutcome::Accepted,
        );
    }

    #[test]
    fn proposal_outcome_empty_string_is_accepted() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!("")),
            ProposalOutcome::Accepted,
        );
    }

    #[test]
    fn proposal_outcome_duplicate_string() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!("duplicate")),
            ProposalOutcome::Duplicate,
        );
    }

    #[test]
    fn proposal_outcome_rejected_string() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!("bad-prevblk")),
            ProposalOutcome::Rejected("bad-prevblk".to_string()),
        );
    }

    #[test]
    fn proposal_outcome_object_without_reject_reason_is_accepted() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!({})),
            ProposalOutcome::Accepted,
        );
    }

    #[test]
    fn proposal_outcome_object_with_null_reject_reason_is_accepted() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!({ "reject-reason": null })),
            ProposalOutcome::Accepted,
        );
    }

    #[test]
    fn proposal_outcome_object_with_duplicate_reject_reason() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!({ "reject-reason": "duplicate" })),
            ProposalOutcome::Duplicate,
        );
    }

    #[test]
    fn proposal_outcome_object_with_other_reject_reason() {
        assert_eq!(
            parse_proposal_outcome(&serde_json::json!({ "reject-reason": "high-hash" })),
            ProposalOutcome::Rejected("high-hash".to_string()),
        );
    }
}
