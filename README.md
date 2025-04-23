# Tendermint Light Client Security Analysis

>[!WARNING]
> This cryptographic protocol for tendermint consensus verification
> has not been audited.
> This is not the official TendermintX implementation and 
> all use is at own risk!

>[!NOTE]
> Currently the skip range is set to be unlimited.
> Limiting it probably makes sense but this is not currently a priority.


This document provides a comprehensive security comparison between two implementations of Tendermint light client verification:

1. The reference implementation [TendermintX](https://github.com/succinctlabs/tendermintx)
2. This implementation [see verification logic](src/verification/verification.rs)

## Core Security Guarantees with Code Examples

### 0. What is being verified

*Skip Circuit*:
- the trusted validator set against the trusted validator hash
- validator hash proof against trusted header
- target block signatures
- target block chain id against header
- target block height against header
- the voting power

>[!NOTE]
> The Skip Circuit is special in a sense that it will assume that our
> trusted validator set from the previous block will behave honestly
> The assumption is that if and only if 1/3rd + of the verifier set has not changed,
> then we continue to trust it.

*Step Circuit*
- the next valifdator set against the next validator hash
- the previous header hash proof
- the previous validator hash proof
- the previous validator set against the previous validator hash
- target block signatures
- target block chain id against header
- target block height against header
- the voting power

### 1. Block Header Verification

Both implementations verify block headers through Merkle proofs and ensure proper chain continuity. Here's how they compare:

**Reference Implementation (Circuit)**:
```rust
fn verify_prev_header_in_header(
    &mut self,
    header: &TendermintHashVariable,
    prev_header: TendermintHashVariable,
    last_block_id_proof: &BlockIDInclusionProofVariable,
) {
    // Verify the last block ID proof matches the current header
    let last_block_id_path = self.get_path_to_leaf(LAST_BLOCK_ID_INDEX);
    let header_from_last_block_id_proof =
        self.get_root_from_merkle_proof(last_block_id_proof, &last_block_id_path);
    self.assert_is_equal(header_from_last_block_id_proof, *header);

    // Extract and verify the previous header hash
    let extracted_prev_header_hash: Bytes32Variable =
        last_block_id_proof.leaf[2..2 + HASH_SIZE].into();
    self.assert_is_equal(prev_header, extracted_prev_header_hash);
}
```

**This Implementation (Runtime)**:
```rust
pub fn verify_step(step_inputs: &StepInputs, prev_header_hash: Vec<u8>) -> Result<(), String> {
    // Verify the last block ID proof matches the current header
    if !verify_merkle_proof(
        step_inputs.next_header.hash().as_bytes().try_into().unwrap(),
        &step_inputs.next_block_last_block_id_proof.leaf,
        &step_inputs.next_block_last_block_id_proof.proof,
        &step_inputs.next_block_last_block_id_proof.path_indices,
    ) {
        return Err("Invalid next block last block ID proof".to_string());
    }

    // Verify the previous header hash matches
    let prev_hash_header =
        step_inputs.next_block_last_block_id_proof.leaf[2..2 + HASH_SIZE].to_vec();
    assert_eq!(prev_header_hash, prev_hash_header);

    // Verify the next validators hash matches the previous header's next validators hash
    let mut tree_builder = TreeBuilder {};
    let computed_prev_header_root = tree_builder.get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
        &MerkleInclusionProofVariable {
            proof: step_inputs.prev_block_next_validators_hash_proof.proof.clone(),
            leaf: step_inputs.prev_block_next_validators_hash_proof.leaf.clone(),
        },
        &get_path_indices(NEXT_VALIDATORS_HASH_INDEX as u64, 14),
    );
    assert_eq!(computed_prev_header_root, prev_header_hash);

    // Verify the new validators hash matches
    let extracted_prev_header_next_validators_hash =
        step_inputs.prev_block_next_validators_hash_proof.leaf[2..2 + HASH_SIZE].to_vec();
    let new_validators_hash = step_inputs.next_header.validators_hash.as_bytes().to_vec();
    assert_eq!(new_validators_hash, extracted_prev_header_next_validators_hash);

    Ok(())
}
```

Both implementations:
- Verify the last block ID proof matches the current header
- Extract and verify the previous header hash
- Verify the next validators hash matches the previous header's next validators hash
- Use the same path indices and hash sizes
- Maintain the same security guarantees for header verification
- Ensure proper chain continuity through header hash verification

### 2. Validator Set Verification

Both implementations verify that 2/3 of the validator set's voting power has signed the block:

**Reference Implementation (Circuit)**:
```rust
fn verify_voting_threshold<const VALIDATOR_SET_SIZE_MAX: usize>(
    &mut self,
    validator_voting_power: &[U64Variable],
    nb_enabled_validators: Variable,
    threshold_numerator: &U64Variable,
    threshold_denominator: &U64Variable,
    include_in_check: &[BoolVariable],
) {
    let total_voting_power = self.get_total_voting_power::<VALIDATOR_SET_SIZE_MAX>(
        validator_voting_power,
        nb_enabled_validators,
    );
    let gt_threshold = self.is_voting_power_greater_than_threshold::<VALIDATOR_SET_SIZE_MAX>(
        validator_voting_power,
        include_in_check,
        &total_voting_power,
        threshold_numerator,
        threshold_denominator,
    );
    let true_v = self._true();
    self.assert_is_equal(gt_threshold, true_v);
}
```

**This Implementation (Runtime)**:
```rust
pub fn verify_skip(skip_inputs: &SkipInputs, trusted_header_hash: Vec<u8>) -> Result<(), String> {
    // Verify validator signatures and voting power
    let mut total_voting_power: u64 = 0;
    let mut signed_voting_power: u64 = 0;
    let mut signed_validators_from_trusted: u64 = 0;
    let trusted_validator_addresses: std::collections::HashSet<_> = skip_inputs
        .trusted_block_validators_hash_fields
        .iter()
        .map(|v| v.pubkey.clone())
        .collect();
        
    for validator in &skip_inputs.target_block_validators {
        if validator.signed {
            let message = &validator.message[..validator.message_byte_length as usize];
            let mut signature_bytes = Vec::new();
            signature_bytes.extend_from_slice(&validator.signature.r);
            signature_bytes.extend_from_slice(&validator.signature.s);

            let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
                .map_err(|_| "Invalid signature format")?;
            let public_key = ed25519_dalek::PublicKey::from_bytes(&validator.pubkey)
                .map_err(|_| "Invalid public key format")?;

            public_key
                .verify_strict(message, &signature)
                .map_err(|_| "Invalid signature for validator")?;

            signed_voting_power += validator.voting_power;

            if trusted_validator_addresses.contains(&validator.pubkey) {
                signed_validators_from_trusted += validator.voting_power;
            }
        }
        total_voting_power += validator.voting_power;
    }
    
    // more than 2/3 total votes
    if signed_voting_power * 3 <= total_voting_power * 2 {
        return Err(format!(
            "Insufficient voting power signed the target block. Got {}/{} voting power",
            signed_voting_power, total_voting_power
        ));
    }
    
    // more than 1/3 trusted votes
    if signed_validators_from_trusted * 3 < signed_voting_power {
        return Err(format!(
            "Insufficient validators from trusted block signed the target block. Got {}/{} voting power from trusted validators",
            signed_validators_from_trusted, signed_voting_power
        ));
    }
    
    Ok(())
}
```

Both implementations:
- Calculate total voting power
- Track signed voting power
- Enforce the 2/3 threshold requirement
- Handle validator set changes correctly
- Verify validator signatures using ed25519
- Track voting power from trusted validators

### 3. Input Handling and Data Fetching

The implementation includes a robust input handling system:

**This Implementation (Runtime)**:
```rust
pub struct InputDataFetcher {
    pub urls: Vec<String>,
}

impl InputDataFetcher {
    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: Vec<u8>,
        target_block_number: u64,
    ) -> SkipInputs {
        // Fetch validator sets and headers
        let trusted_block_validator_set = self
            .get_validator_set_from_number(trusted_block_number)
            .await;
        let target_block_validator_set = self
            .get_validator_set_from_number(target_block_number)
            .await;

        let target_signed_header = self
            .get_signed_header_from_number(target_block_number)
            .await;
        let trusted_signed_header = self
            .get_signed_header_from_number(trusted_block_number)
            .await;

        // Generate proofs and prepare inputs
        let target_block_chain_id_proof = get_merkle_proof(
            &target_signed_header.header(),
            CHAIN_ID_INDEX as u64,
            target_signed_header.header().chain_id.clone().encode_vec(),
        );

        // ... additional proof generation and input preparation ...
    }
}
```

Key features:
- Asynchronous data fetching from multiple RPC endpoints
- Robust error handling and retries
- Efficient proof generation
- Support for both step and skip verification
- Proper handling of validator set changes

## Implementation Differences

### 1. Circuit vs Runtime Verification

The reference implementation (`verification-comparison.rs`) is implemented as a zero-knowledge circuit using Plonky2, while the This Implementation (`verification.rs`) is a runtime verification system.

### 2. Merkle Proof Handling

- **Reference Implementation**: Uses a more formalized approach with explicit path indices and depth parameters
- **This Implementation**: Uses a more practical approach with helper functions for proof generation and verification
- Added caching for proof generation to improve performance

### 3. Validator Set Verification

- **Reference Implementation**: More strictly typed with explicit size constraints and array bounds
- **This Implementation**: More flexible with dynamic sizing and runtime checks
- Added ed25519 signature verification
- Enhanced tracking of trusted validator voting power

### 4. Error Handling

- **Reference Implementation**: Uses circuit assertions and boolean constraints
- **This Implementation**: Uses Rust's Result type with detailed error messages
- Added comprehensive error handling for network requests and data validation

## Security Considerations

1. **Signature Verification**: The implementation uses ed25519_dalek for strict signature verification
2. **Voting Power Thresholds**: Enforces both 2/3 total voting power and 1/3 trusted validator voting power requirements
3. **Chain Continuity**: Ensures proper chain continuity through header hash verification
4. **Validator Set Changes**: Properly handles validator set changes during skips
5. **Network Security**: Supports multiple RPC endpoints for redundancy and security

## Running Tests
To verify a light client proof for a `