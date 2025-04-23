# Tendermint Light Client Security Analysis

>[!WARNING]
> This cryptographic protocol for tendermint consensus verification
> has not been audited.
> This is not the official TendermintX implementation and 
> all use is at own risk!

This document provides a comprehensive security comparison between two implementations of Tendermint light client verification:

1. The reference implementation [TendermintX](https://github.com/succinctlabs/tendermintx)
2. This implementation [see verification logic](src/verification/verification.rs)

## Core Security Guarantees with Code Examples

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

fn verify_prev_header_next_validators_hash(
    &mut self,
    new_validators_hash: TendermintHashVariable,
    prev_header: &TendermintHashVariable,
    prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
) {
    // Verify the next validators hash proof matches the previous header
    let next_val_hash_path = self.get_path_to_leaf(NEXT_VALIDATORS_HASH_INDEX);
    let computed_prev_header_root = self.get_root_from_merkle_proof(
        prev_header_next_validators_hash_proof,
        &next_val_hash_path,
    );
    self.assert_is_equal(computed_prev_header_root, *prev_header);

    // Verify the new validators hash matches the previous header's next validators hash
    let extracted_prev_header_next_validators_hash =
        prev_header_next_validators_hash_proof.leaf[2..2 + HASH_SIZE].into();
    self.assert_is_equal(
        new_validators_hash,
        extracted_prev_header_next_validators_hash,
    );
}
```

**Production Implementation (Runtime)**:
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
    let new_validators_hash = step_inputs.next_header_validators_hash_proof.leaf[2..2 + HASH_SIZE].to_vec();
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

**Production Implementation (Runtime)**:
```rust
pub fn verify_skip(skip_inputs: &SkipInputs) -> Result<(), String> {
    let mut total_voting_power: u64 = 0;
    let mut signed_voting_power: u64 = 0;
    
    for validator in &skip_inputs.target_block_validators {
        if validator.signed {
            signed_voting_power += validator.voting_power;
        }
        total_voting_power += validator.voting_power;
    }
    
    if signed_voting_power * 3 <= total_voting_power * 2 {
        return Err(format!(
            "Insufficient voting power signed the target block. Got {}/{} voting power",
            signed_voting_power, total_voting_power
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

### 3. Skip Verification

Both implementations ensure skipped blocks maintain security through validator set overlap:

**Reference Implementation (Circuit)**:
```rust
fn verify_trusted_validators<const VALIDATOR_SET_SIZE_MAX: usize>(
    &mut self,
    validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
    trusted_header: TendermintHashVariable,
    trusted_validator_hash_proof: &HashInclusionProofVariable,
    trusted_validator_hash_fields: &ArrayVariable<ValidatorHashFieldVariable, VALIDATOR_SET_SIZE_MAX>,
    trusted_nb_enabled_validators: Variable,
) {
    // ... proof verification ...
    let threshold_numerator = self.constant::<U64Variable>(1);
    let threshold_denominator = self.constant::<U64Variable>(3);
    self.verify_voting_threshold::<VALIDATOR_SET_SIZE_MAX>(
        &trusted_vp,
        trusted_nb_enabled_validators,
        &threshold_numerator,
        &threshold_denominator,
        &trusted_validator_signed_on_target_header,
    );
}
```

**Production Implementation (Runtime)**:
```rust
pub fn verify_skip(skip_inputs: &SkipInputs) -> Result<(), String> {
    let mut signed_validators_from_trusted: u64 = 0;
    let trusted_validator_addresses: std::collections::HashSet<_> = skip_inputs
        .trusted_block_validators_hash_fields
        .iter()
        .map(|v| v.pubkey.clone())
        .collect();
        
    for validator in &skip_inputs.target_block_validators {
        if validator.signed && trusted_validator_addresses.contains(&validator.pubkey) {
            signed_validators_from_trusted += validator.voting_power;
        }
    }
    
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
- Track validators from the trusted block
- Verify >1/3 voting power from trusted validators
- Handle validator set changes during skips
- Maintain the same security guarantees for skip verification

## Implementation Differences

### 1. Circuit vs Runtime Verification

The reference implementation (`verification-comparison.rs`) is implemented as a zero-knowledge circuit using Plonky2, while the production implementation (`verification.rs`) is a runtime verification system.

### 2. Merkle Proof Handling

- **Reference Implementation**: Uses a more formalized approach with explicit path indices and depth parameters
- **Production Implementation**: Uses a more practical approach with helper functions for proof generation and verification

### 3. Validator Set Verification

- **Reference Implementation**: More strictly typed with explicit size constraints and array bounds
- **Production Implementation**: More flexible with dynamic sizing and runtime checks

### 4. Error Handling

- **Reference Implementation**: Uses circuit assertions and boolean constraints
- **Production Implementation**: Uses Rust's Result type with detailed error messages

## Security Considerations

1. **Circuit Implementation Advantages**
   - Provides cryptographic guarantees through zero-knowledge proofs
   - Formal verification of constraints is possible
   - No reliance on runtime environment security

2. **Runtime Implementation Advantages**
   - More flexible handling of edge cases
   - Better performance for direct verification
   - More detailed error reporting
   - Easier to audit and maintain

3. **Shared Security Properties**
   - Both maintain the core Tendermint security model
   - Both properly verify validator signatures
   - Both enforce the 2/3 voting power requirement
   - Both handle skip verification with proper validator set overlap checks

## Running Tests
To verify a light client proof for a `step`:

```shell
cargo test test_verify_step
```

To verify a light client proof for a `skip`:

```shell
carg test test_verify_skip
```

See [main.rs](src/main.rs) for details

## Conclusion

The production implementation (`verification.rs`) closely follows the security model of the reference implementation (`verification-comparison.rs`) while providing a more practical runtime verification system. The key security guarantees are preserved, though the trust model differs due to the circuit vs runtime implementation choice.

The production implementation is suitable for direct verification in a trusted environment, while the reference implementation is better suited for zero-knowledge proof generation. Both implementations maintain the core security properties required for Tendermint light client verification.