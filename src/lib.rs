pub mod e9571_btc_coinjoin_analyse_lib {
    use super::*;
    use serde_json::{json, Value};
    use reqwest::Client;
    use std::error::Error;

    // Struct to hold suspicious transaction details
    #[derive(Debug)]
    pub struct SuspiciousTransaction {
        pub txid: String,
        pub block_height: u64,
        pub block_hash: String,
        pub input_count: usize,
        pub output_count: usize,
    }

    // BitcoinClient struct
    pub struct BitcoinClient {
        url: String,
        client: Client,
        auth: (String, String),
    }

    impl BitcoinClient {
        pub fn new(url: &str, username: &str, password: &str) -> Self {
            BitcoinClient {
                url: url.to_string(),
                client: Client::new(),
                auth: (username.to_string(), password.to_string()),
            }
        }

        pub async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, Box<dyn Error>> {
            let body = json!({
                "jsonrpc": "1.0",
                "id": "1",
                "method": method,
                "params": params
            });
            let response = self
                .client
                .post(&self.url)
                .basic_auth(&self.auth.0, Some(&self.auth.1))
                .json(&body)
                .send()
                .await?;
            let json: Value = response.json().await?;
            if let Some(err) = json.get("error").and_then(|e| e.as_object()) {
                return Err(format!("RPC error: {}", err["message"].as_str().unwrap_or("unknown")).into());
            }
            Ok(json["result"].clone())
        }

        pub async fn get_latest_height(&self) -> Result<u64, Box<dyn Error>> {
            let result = self.call("getblockchaininfo", vec![]).await?;
            Ok(result["blocks"].as_u64().ok_or("Failed to parse block height")?)
        }

        pub async fn get_block(&self, block_hash: &str) -> Result<Value, Box<dyn Error>> {
            self.call("getblock", vec![json!(block_hash), json!(2)]).await
        }

        pub async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error>> {
            let result = self.call("getblockhash", vec![json!(height)]).await?;
            Ok(result.as_str().ok_or("Failed to parse block hash")?.to_string())
        }
    }

    // Function to check if a transaction is a Coinbase transaction
    fn is_coinbase_transaction(tx: &Value) -> bool {
        if let Some(vin) = tx["vin"].as_array() {
            if vin.len() == 1 {
                if let Some(first_input) = vin.get(0) {
                    return first_input.get("coinbase").is_some() ||
                        (first_input.get("txid").is_none() && first_input.get("vout").is_none());
                }
            }
        }
        false
    }

    // Function to analyze blocks and return suspicious transactions
    pub async fn analyze_blocks(
        client: &BitcoinClient,
        start_height: u64,
        range: u64,
        min_inputs: usize,
        min_outputs: usize,
    ) -> Result<Vec<SuspiciousTransaction>, Box<dyn Error>> {
        let mut suspicious_txs: Vec<SuspiciousTransaction> = Vec::new();
        let mut stats = (0, 0, 0, 0); // (total_txs, coinbase_txs, _, _)

        for height in (start_height.saturating_sub(range - 1)..=start_height).rev() {
            let block_hash = client.get_block_hash(height).await?;
            println!("Scanning block {} (hash: {})", height, block_hash);

            let block = client.get_block(&block_hash).await?;
            let txs = block["tx"].as_array().ok_or("Failed to parse transactions")?;
            stats.0 += txs.len();

            for tx in txs {
                let txid = tx["txid"].as_str().ok_or("Failed to parse txid")?.to_string();
                let vin = tx["vin"].as_array().ok_or("Failed to parse vin")?;
                let vout = tx["vout"].as_array().ok_or("Failed to parse vout")?;

                if is_coinbase_transaction(tx) {
                    stats.1 += 1;
                    continue;
                }

                if vin.len() >= min_inputs && vout.len() >= min_outputs {
                    suspicious_txs.push(SuspiciousTransaction {
                        txid: txid.clone(),
                        block_height: height,
                        block_hash: block_hash.clone(),
                        input_count: vin.len(),
                        output_count: vout.len(),
                    });
                }
            }
        }

        Ok(suspicious_txs)
    }
}