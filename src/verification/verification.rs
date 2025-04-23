use sha2::Sha256;
use tendermint::merkle::HASH_SIZE;
use tendermint_proto::Protobuf;

use crate::consts::{
    BLOCK_HEIGHT_INDEX, CHAIN_ID_INDEX, HEADER_PROOF_DEPTH, PROTOBUF_CHAIN_ID_SIZE_BYTES,
    VALIDATOR_BYTE_LENGTH_MAX, VALIDATOR_SET_SIZE_MAX,
};
use crate::input::get_path_indices;
use crate::types::conversion::ValidatorVariable;
use crate::types::types::{SkipInputs, StepInputs};
use crate::utils::{inner_hash, leaf_hash};
use crate::verification::tree::{TendermintMerkleTree, TreeBuilder};
use crate::verification::{compute_validators_hash, get_merkle_proof};

use ed25519_dalek;

use super::{hash_validator_set, marshal_tendermint_validator};

pub fn verify_merkle_proof(
    root_hash: &[u8; 32],
    leaf: &[u8],
    proof: &[Vec<u8>],
    path_indices: &[bool],
) -> bool {
    let computed_root = get_root_from_merkle_proof_hashed_leaf(leaf, proof, path_indices);
    computed_root.as_slice() == root_hash
}

pub fn get_root_from_merkle_proof_hashed_leaf(
    leaf: &[u8],
    proof: &[Vec<u8>],
    path_indices: &[bool],
) -> [u8; 32] {
    let mut hash_so_far = leaf_hash::<Sha256>(leaf);
    for (i, aunt) in proof.iter().enumerate() {
        hash_so_far = if path_indices[i] {
            inner_hash::<Sha256>(aunt.as_slice().try_into().unwrap(), hash_so_far)
        } else {
            inner_hash::<Sha256>(hash_so_far, aunt.as_slice().try_into().unwrap())
        };
    }
    hash_so_far
}

pub fn verify_skip(skip_inputs: &SkipInputs, trusted_header_hash: Vec<u8>) -> Result<(), String> {
    // verify the trusted validator set
    let mut tree_builder = TreeBuilder {};
    let header_from_validator_root_proof = tree_builder
        .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
            &MerkleInclusionProofVariable {
                proof: skip_inputs
                    .trusted_block_validators_hash_proof
                    .proof
                    .clone(),
                leaf: skip_inputs.trusted_block_validators_hash_proof.leaf.clone(),
            },
            skip_inputs
                .trusted_block_validators_hash_proof
                .path_indices
                .clone(),
        );

    // Ensure the trusted validator hash proof aligns with the trusted header.
    assert_eq!(header_from_validator_root_proof, trusted_header_hash);

    // Calculate the validators hash of the trusted block using the provided fields.
    let computed_val_hash = compute_validators_hash::<VALIDATOR_SET_SIZE_MAX>(
        &skip_inputs.trusted_block_validators_hash_fields,
        skip_inputs.nb_trusted_validators as u64,
    );

    // Extract the expected trusted validators hash from the valid validators hash proof.
    let expected_val_hash =
        skip_inputs.trusted_block_validators_hash_proof.leaf[2..2 + HASH_SIZE].to_vec();

    // Confirm the computed validators hash matches the expected hash.
    assert_eq!(computed_val_hash, expected_val_hash);
    // verify the target validator set
    assert!(verify_validator_set(
        skip_inputs.target_block_validators.clone(),
        skip_inputs.nb_target_validators as u64,
        skip_inputs
            .target_header
            .validators_hash
            .as_bytes()
            .try_into()
            .unwrap()
    ));

    // verify the validators hash
    if !verify_merkle_proof(
        skip_inputs
            .target_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &skip_inputs.target_block_validators_hash_proof.leaf,
        &skip_inputs.target_block_validators_hash_proof.proof,
        &skip_inputs.target_block_validators_hash_proof.path_indices,
    ) {
        return Err("Invalid target block validators hash proof".to_string());
    }

    // verify the target chain id
    if skip_inputs.target_header.chain_id != skip_inputs.trusted_header.chain_id {
        return Err(format!(
            "Chain ID mismatch between trusted block and target block"
        ));
    }
    let encoded_chain_id = skip_inputs.target_header.chain_id.clone().encode_vec();
    let mut extended_chain_id = encoded_chain_id.clone();
    extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
    let target_block_chain_id_proof = get_merkle_proof(
        &skip_inputs.target_header,
        CHAIN_ID_INDEX as u64,
        encoded_chain_id.clone(),
    );
    let target_path_indices = get_path_indices(CHAIN_ID_INDEX as u64, 14);
    if !verify_merkle_proof(
        skip_inputs
            .target_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &target_block_chain_id_proof.0,
        &target_block_chain_id_proof.1,
        &target_path_indices,
    ) {
        return Err("Invalid target block chain ID proof".to_string());
    }

    // verify the target block height
    let height_path_indices = get_path_indices(BLOCK_HEIGHT_INDEX as u64, 14);
    if !verify_merkle_proof(
        skip_inputs
            .target_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &skip_inputs.target_block_height_proof.0,
        &skip_inputs.target_block_height_proof.1,
        &height_path_indices,
    ) {
        return Err("Invalid target block height proof".to_string());
    }

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

pub fn verify_step(step_inputs: &StepInputs, prev_header_hash: Vec<u8>) -> Result<(), String> {
    // verify the target validator set
    assert!(verify_validator_set(
        step_inputs.next_block_validators.clone(),
        step_inputs.nb_validators as u64,
        step_inputs
            .next_header
            .validators_hash
            .as_bytes()
            .try_into()
            .unwrap()
    ));
    let next_header_hash = step_inputs.next_header.hash();
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_validators_hash_proof.leaf,
        &step_inputs.next_block_validators_hash_proof.proof,
        &step_inputs.next_block_validators_hash_proof.path_indices,
    ) {
        return Err("Invalid next block validators hash proof".to_string());
    }

    // verify target chain id
    let encoded_chain_id = step_inputs.next_header.chain_id.clone().encode_vec();
    let mut extended_chain_id = encoded_chain_id.clone();
    extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
    let target_block_chain_id_proof = get_merkle_proof(
        &step_inputs.next_header,
        CHAIN_ID_INDEX as u64,
        encoded_chain_id.clone(),
    );
    let target_path_indices = get_path_indices(CHAIN_ID_INDEX as u64, 14);
    if !verify_merkle_proof(
        step_inputs
            .next_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &target_block_chain_id_proof.0,
        &target_block_chain_id_proof.1,
        &target_path_indices,
    ) {
        return Err("Invalid target block chain ID proof".to_string());
    }

    // verify next block height
    let height_path_indices = get_path_indices(BLOCK_HEIGHT_INDEX as u64, 14);
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_height_proof.0,
        &step_inputs.next_block_height_proof.1,
        &height_path_indices,
    ) {
        return Err("Invalid next block height proof".to_string());
    }

    // verify the last block id in the next block
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_last_block_id_proof.leaf,
        &step_inputs.next_block_last_block_id_proof.proof,
        &step_inputs.next_block_last_block_id_proof.path_indices,
    ) {
        return Err("Invalid next block last block ID proof".to_string());
    }

    // verify the previous header
    let prev_hash_header =
        step_inputs.next_block_last_block_id_proof.leaf[2..2 + HASH_SIZE].to_vec();
    assert_eq!(prev_header_hash, prev_hash_header);

    // root of validator hash proof must match previous header hash
    let mut tree_builder = TreeBuilder {};
    let computed_prev_header_root = tree_builder.get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
        &MerkleInclusionProofVariable {
            proof: step_inputs
                .prev_block_next_validators_hash_proof
                .proof
                .clone(),
            leaf: step_inputs
                .prev_block_next_validators_hash_proof
                .leaf
                .clone(),
        },
        step_inputs
            .prev_block_next_validators_hash_proof
            .path_indices
            .clone(),
    );
    assert_eq!(computed_prev_header_root, prev_hash_header);

    // assert the validator hash was actually under the previous header
    let extracted_prev_header_next_validators_hash =
        step_inputs.prev_block_next_validators_hash_proof.leaf[2..2 + HASH_SIZE].to_vec();
    assert_eq!(
        extracted_prev_header_next_validators_hash,
        step_inputs.next_header.validators_hash.as_bytes()
    );

    // verify validator signatures and voting power
    let mut total_voting_power: u64 = 0;
    let mut signed_voting_power: u64 = 0;
    for validator in &step_inputs.next_block_validators {
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
        }
        total_voting_power += validator.voting_power;
    }
    // more than 2/3 total votes
    if signed_voting_power * 3 <= total_voting_power * 2 {
        return Err(format!(
            "Insufficient voting power signed the next block. Got {}/{} voting power",
            signed_voting_power, total_voting_power
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::verification::{marshal_int64_varint, marshal_tendermint_validator};

    #[test]
    fn test_marshal_int64_varint() {
        // Test case 1: Small number (1 byte)
        assert_eq!(marshal_int64_varint(1), vec![0x01]);
        // Test case 2: Number requiring 2 bytes
        assert_eq!(marshal_int64_varint(300), vec![0xAC, 0x02]);
        // Test case 3: Maximum 1-byte value
        assert_eq!(marshal_int64_varint(127), vec![0x7F]);
        // Test case 4: Minimum 2-byte value
        assert_eq!(marshal_int64_varint(128), vec![0x80, 0x01]);
        // Test case 5: Large number
        assert_eq!(
            marshal_int64_varint(123456789),
            vec![0x95, 0x9A, 0xEF, 0x3A]
        );
        // Test case 6: Maximum u64 value
        assert_eq!(
            marshal_int64_varint(u64::MAX),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        );
    }

    #[test]
    fn test_marshal_tendermint_validator() {
        // This is a test case generated from a validator in block 11000 of the mocha-3 testnet.
        let voting_power = 100010_u64;
        let pubkey =
            hex::decode("de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba")
                .unwrap();
        let expected_marshal = hex::decode(
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
        )
        .unwrap();
        // Marshal the validator
        let result = marshal_tendermint_validator(&pubkey, &voting_power);
        // Verify the marshaled output matches the expected bytes
        assert_eq!(result, expected_marshal);
    }
}

pub struct MerkleInclusionProofVariable {
    pub proof: Vec<Vec<u8>>,
    pub leaf: Vec<u8>,
}

pub fn log2_ceil_usize(x: usize) -> usize {
    if x <= 1 {
        // log2(0) and log2(1) are both 0.
        return 0;
    }

    let mut result = 0;
    // Subtract 1 to ensure rounding up for powers of 2.
    let mut value = x - 1;

    while value > 0 {
        value >>= 1;
        result += 1;
    }

    result as usize
}

pub fn verify_validator_set(
    validators: Vec<ValidatorVariable>,
    nb_validators: u64,
    root: Vec<u8>,
) -> bool {
    // Marshal validators and compute validator set hash
    let mut marshaled_validators = Vec::new();
    let mut validator_byte_lengths = Vec::new();

    for validator in validators.clone() {
        let marshaled = marshal_tendermint_validator(&validator.pubkey, &validator.voting_power);
        validator_byte_lengths.push(marshaled.len() as u64);
        marshaled_validators.push(marshaled);
    }

    // Pad to VALIDATOR_SET_SIZE_MAX
    while marshaled_validators.len() < VALIDATOR_SET_SIZE_MAX {
        marshaled_validators.push(vec![0u8; VALIDATOR_BYTE_LENGTH_MAX]);
        validator_byte_lengths.push(VALIDATOR_BYTE_LENGTH_MAX as u64);
    }

    // Compute validator set hash
    let computed_validators_hash = hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
        &marshaled_validators,
        &validator_byte_lengths,
        nb_validators,
    );

    computed_validators_hash == root
}
