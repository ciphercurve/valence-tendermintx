use sha2::Sha256;
use std::collections::HashMap;
use tendermint::block::Header;
use tendermint_proto::Protobuf;

use crate::consts::{BLOCK_HEIGHT_INDEX, CHAIN_ID_INDEX, PROTOBUF_CHAIN_ID_SIZE_BYTES};
use crate::input::get_path_indices;
use crate::types::types::{SkipInputs, StepInputs};
use crate::utils::{Proof, generate_proofs_from_header, inner_hash, leaf_hash};

use ed25519_dalek;

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

pub fn verify_skip(skip_inputs: &SkipInputs) -> Result<(), String> {
    // Verify chain ID consistency
    if skip_inputs.target_header.chain_id != skip_inputs.trusted_header.chain_id {
        return Err(format!(
            "Chain ID mismatch between trusted block and target block"
        ));
    }

    // Verify chain ID merkle proofs
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

    /*let trusted_path_indices = get_path_indices(CHAIN_ID_INDEX as u64, 14);
    let trusted_block_chain_id_proof = get_merkle_proof(
        &skip_inputs.trusted_header,
        CHAIN_ID_INDEX as u64,
        encoded_chain_id.clone(),
    );
    if !verify_merkle_proof(
        skip_inputs
            .trusted_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &trusted_block_chain_id_proof.0,
        &trusted_block_chain_id_proof.1,
        &trusted_path_indices,
    ) {
        return Err("Invalid trusted block chain ID proof".to_string());
    }*/

    // Verify height proof
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

    // Verify validators hash proofs
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

    if !verify_merkle_proof(
        skip_inputs
            .trusted_header
            .hash()
            .as_bytes()
            .try_into()
            .unwrap(),
        &skip_inputs.trusted_block_validators_hash_proof.leaf,
        &skip_inputs.trusted_block_validators_hash_proof.proof,
        &skip_inputs.trusted_block_validators_hash_proof.path_indices,
    ) {
        return Err("Invalid trusted block validators hash proof".to_string());
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

    // Verify more than 2/3 of voting power signed
    if signed_voting_power * 3 <= total_voting_power * 2 {
        return Err(format!(
            "Insufficient voting power signed the target block. Got {}/{} voting power",
            signed_voting_power, total_voting_power
        ));
    }

    // Verify that 1/3rd or more of the validators that signed the target block were the same validators as in the trusted block
    if signed_validators_from_trusted * 3 < signed_voting_power {
        return Err(format!(
            "Insufficient validators from trusted block signed the target block. Got {}/{} voting power from trusted validators",
            signed_validators_from_trusted, signed_voting_power
        ));
    }

    Ok(())
}

pub fn verify_step(step_inputs: &StepInputs) -> Result<(), String> {
    // Verify chain ID merkle proofs
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

    let next_header_hash = step_inputs.next_header.hash();

    // Verify height proof
    let height_path_indices = get_path_indices(BLOCK_HEIGHT_INDEX as u64, 14);
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_height_proof.0,
        &step_inputs.next_block_height_proof.1,
        &height_path_indices,
    ) {
        return Err("Invalid next block height proof".to_string());
    }

    // Verify validators hash proof
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_validators_hash_proof.leaf,
        &step_inputs.next_block_validators_hash_proof.proof,
        &step_inputs.next_block_validators_hash_proof.path_indices,
    ) {
        return Err("Invalid next block validators hash proof".to_string());
    }

    // Verify last block ID proof
    if !verify_merkle_proof(
        next_header_hash.as_bytes().try_into().unwrap(),
        &step_inputs.next_block_last_block_id_proof.leaf,
        &step_inputs.next_block_last_block_id_proof.proof,
        &step_inputs.next_block_last_block_id_proof.path_indices,
    ) {
        return Err("Invalid next block last block ID proof".to_string());
    }

    // Verify prev block's next validators hash proof
    if !verify_merkle_proof(
        step_inputs.prev_header.as_slice().try_into().unwrap(),
        &step_inputs.prev_block_next_validators_hash_proof.leaf,
        &step_inputs.prev_block_next_validators_hash_proof.proof,
        &step_inputs
            .prev_block_next_validators_hash_proof
            .path_indices,
    ) {
        return Err("Invalid prev block next validators hash proof".to_string());
    }

    // Verify validator signatures and voting power
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

    // Verify more than 2/3 of voting power signed
    if signed_voting_power * 3 <= total_voting_power * 2 {
        return Err(format!(
            "Insufficient voting power signed the next block. Got {}/{} voting power",
            signed_voting_power, total_voting_power
        ));
    }

    Ok(())
}

pub fn get_merkle_proof(
    block_header: &Header,
    index: u64,
    encoded_leaf: Vec<u8>,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut proof_cache: HashMap<Vec<u8>, Vec<Proof>> = HashMap::new();
    let hash: Vec<u8> = block_header.hash().as_bytes().try_into().unwrap();
    let proofs = match proof_cache.get(&hash) {
        Some(proofs) => proofs.clone(),
        None => {
            let (hash, proofs) = generate_proofs_from_header(block_header);
            proof_cache.insert(hash.to_vec(), proofs.clone());
            proofs
        }
    };
    let proof = proofs[index as usize].clone();
    (
        encoded_leaf,
        proof.aunts.iter().map(|a| a.to_vec()).collect(),
    )
}
