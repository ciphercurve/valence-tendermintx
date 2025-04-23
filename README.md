# Valence TendermintX - A Modern Tendermint ZK Light Client

> [!WARNING]
> This repository contains critical infrastructure 
> and has not been audited (yet)!
>
> Use at your own Risk!
>
> Currently missing the message hash verification

## Overview

Valence TendermintX is a modern implementation of a Tendermint ZK Light Client, inspired by Succinct's `Tendermintx`. While the original implementation was built on Plonky2 circuits, this version leverages the SP1 ZKVM crate directly, providing a more streamlined and maintainable codebase.

The project aims to provide a secure and efficient way to verify Tendermint block headers and validator sets in a zero-knowledge context, enabling trustless verification of blockchain state transitions.

## Architecture

The project is structured into several key components:

### Core Components

- **Input Data Fetcher**: Handles fetching and processing block headers and validator sets from Tendermint RPC endpoints
- **Verification Module**: Implements the core verification logic for both skip and step proofs
- **Type System**: Defines the data structures used throughout the verification process
- **Constants**: Contains configuration parameters and constants used in the verification process

### Key Features

- **Merkle Proof Verification**: Implements efficient verification of Merkle proofs for block headers
- **Validator Signature Verification**: Verifies validator signatures using Ed25519
- **Voting Power Verification**: Ensures proper voting power thresholds are met
- **Chain ID Consistency**: Maintains chain ID consistency across block transitions
- **Skip and Step Proofs**: Supports both skip proofs (for non-consecutive blocks) and step proofs (for consecutive blocks)

## Usage

### Prerequisites

- Rust (2024 edition)
- Access to a Tendermint RPC endpoint

### Configuration

Create a `.env` file with your Tendermint RPC URL:

```env
TENDERMINT_RPC_URL=http://your-tendermint-rpc:26657
```

### Running the Light Client

```rust
use base64::Engine;
use verification::verification::{verify_skip, verify_step};

#[tokio::main]
async fn main() {
    const MAX_VALIDATOR_SET_SIZE: usize = 100;
    let trusted_header: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode("YOUR_TRUSTED_HEADER_BASE64")
        .unwrap()
        .try_into()
        .unwrap();
    let trusted_height = YOUR_TRUSTED_HEIGHT;
    let target_height = YOUR_TARGET_HEIGHT;
    
    let mut input_data_fetcher = input::InputDataFetcher::default();
    
    // Verify skip proof
    let skip_inputs = input_data_fetcher
        .get_skip_inputs::<MAX_VALIDATOR_SET_SIZE>(
            trusted_height,
            trusted_header.to_vec(),
            target_height,
        )
        .await;
    verify_skip(&skip_inputs).unwrap();

    // Verify step proof
    let step_inputs = input_data_fetcher
        .get_step_inputs::<MAX_VALIDATOR_SET_SIZE>(trusted_height, trusted_header.to_vec())
        .await;
    verify_step(&step_inputs).unwrap();
}
```

## Security Considerations

- The implementation has not been audited yet
- Proper validation of RPC endpoints is crucial
- Ensure secure handling of validator signatures
- Monitor voting power thresholds carefully

## Differences from Succinct's Implementation

While inspired by Succinct's `Tendermintx`, this implementation differs in several key ways:

1. **ZKVM Compatibility**: Built for direct use with RISC-V ZKVMs rather than Plonky2 circuits
2. **Modern Dependencies**: Uses the latest versions of Tendermint and related crates
3. **Simplified Architecture**: Removes Field element dependencies and other Plonky2-specific types
4. **Enhanced Type Safety**: Leverages Rust's type system for better safety guarantees

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. Code is well-documented
3. Security considerations are addressed
4. Changes are backward compatible

## Acknowledgments

- Inspired by Succinct's `Tendermintx`
- Built on the Tendermint ecosystem
- Leverages the SP1 ZKVM crate