# e9571_btc_coinjoin_analyse_lib

A BTC coinjoin analysis library that identifies suspicious transactions through input/output anomaly thresholds, capable of recognizing ZeroLink, WabiSabi, JoinMarket, and Chaumian protocol coinjoin behaviors.

## Description

This library provides tools to connect to a Bitcoin node via RPC and analyze blockchain transactions for suspicious activity based on input and output thresholds. It is designed for developers and researchers interested in detecting CoinJoin transactions.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
e9571_btc_coinjoin_analyse_lib = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

## Usage

Below is an example of how to use the `e9571_btc_coinjoin_analyse_lib` to connect to a Bitcoin node, retrieve the latest block height, and analyze a range of blocks for suspicious transactions.

```rust
use e9571_btc_coinjoin_analyse_lib::e9571_btc_coinjoin_analyse_lib::{BitcoinClient, analyze_blocks};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize Bitcoin client
    let client = BitcoinClient::new(
        "http://192.168.1.3:8336",
        "btc_user",
        "btc_user",
    );

    // Get the latest blockchain height
    let latest_height = client.get_latest_height().await?;
    println!("Latest blockchain height: {}", latest_height);

    // Define analysis parameters using the latest height
    let start_height = latest_height - 100; // Start from 100 blocks before the latest
    let range = 10; // Number of blocks to analyze
    let min_inputs = 3; // Minimum number of inputs for suspicious transaction
    let min_outputs = 3; // Minimum number of outputs for suspicious transaction

    // Analyze blocks for suspicious transactions
    let suspicious_txs = analyze_blocks(&client, start_height, range, min_inputs, min_outputs).await?;

    // Print results
    if suspicious_txs.is_empty() {
        println!("No suspicious transactions found in the specified block range.");
    } else {
        println!("Found {} suspicious transactions:", suspicious_txs.len());
        for tx in suspicious_txs {
            println!(
                "TXID: {}, Block Height: {}, Block Hash: {}, Inputs: {}, Outputs: {}",
                tx.txid, tx.block_height, tx.block_hash, tx.input_count, tx.output_count
            );
        }
    }

    Ok(())
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Repository

[https://github.com/e9571/e9571_btc_coinjoin_analyse_lib](https://github.com/e9571/e9571_btc_coinjoin_analyse_lib)

## Documentation

[https://docs.rs/e9571_btc_coinjoin_analyse_lib](https://docs.rs/e9571_btc_coinjoin_analyse_lib)
