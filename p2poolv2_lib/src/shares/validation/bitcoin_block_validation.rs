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

use super::ValidationError;
use bitcoindrpc::{BitcoindLike, ProposalOutcome};

/// Validate the bitcoin block.
///
/// Returns:
/// - `Ok(true)` when bitcoind already has the block (`ProposalOutcome::Duplicate`).
///   This preserves the legacy semantics of "block exists in chain" for the
///   one historical caller while the surrounding code is migrated to consume
///   [`ProposalOutcome`] directly.
/// - `Ok(false)` when bitcoind accepts the proposal as a valid candidate
///   (`ProposalOutcome::Accepted`).
/// - `Err(_)` when bitcoind rejects the proposal or the RPC call fails — the
///   reject reason is folded into the [`ValidationError`] message.
#[allow(dead_code)]
pub async fn validate_bitcoin_block(
    block: &bitcoin::Block,
    bitcoindrpc_client: &dyn BitcoindLike,
) -> Result<bool, ValidationError> {
    match bitcoindrpc_client
        .validate_block_proposal(block)
        .await
        .map_err(|e| ValidationError::new(format!("Bitcoin block validation failed: {e}")))?
    {
        ProposalOutcome::Duplicate => Ok(true),
        ProposalOutcome::Accepted => Ok(false),
        ProposalOutcome::Rejected(reason) => Err(ValidationError::new(format!(
            "Bitcoin block validation rejected: {reason}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use bitcoin::consensus::Decodable;
    use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    #[tokio::test]
    async fn test_validate_bitcoin_block_success() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string =
            include_str!("../../../../p2poolv2_tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "duplicate",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let client =
            BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap();
        let result = validate_bitcoin_block(&block, &client).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_accepted() {
        // bitcoind accepts the proposal -> null result -> Ok(false) (not duplicate).
        let mock_server = MockServer::start().await;
        let block_hex_string =
            include_str!("../../../../p2poolv2_tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let client =
            BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap();
        let result = validate_bitcoin_block(&block, &client).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_rejected_surfaces_error() {
        // bitcoind rejects with a non-duplicate reason -> ValidationError.
        let mock_server = MockServer::start().await;
        let block_hex_string =
            include_str!("../../../../p2poolv2_tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "bad-prevblk",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let client =
            BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap();
        let result = validate_bitcoin_block(&block, &client).await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("bad-prevblk"),
            "expected reject reason in error, got {msg}"
        );
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_http_error() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string =
            include_str!("../../../../p2poolv2_tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response with HTTP 500 error
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let client =
            BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap();
        let result = validate_bitcoin_block(&block, &client).await;
        assert!(result.is_err());
    }
}
