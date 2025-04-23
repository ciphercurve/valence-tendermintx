use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tendermint::block::Header;
use tree::{TendermintMerkleTree, TreeBuilder};

use crate::{
    types::conversion::ValidatorHashFieldVariable,
    utils::{Proof, generate_proofs_from_header},
};

pub mod tree;
pub mod verification;

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

fn marshal_int64_varint(value: u64) -> Vec<u8> {
    let mut res = Vec::new();
    let mut remaining = value;
    loop {
        let mut byte = (remaining & 0x7F) as u8;
        remaining >>= 7;
        if remaining > 0 {
            byte |= 0x80;
        }
        res.push(byte);
        if remaining == 0 {
            break;
        }
    }
    res
}

pub fn marshal_tendermint_validator(pubkey: &[u8], voting_power: &u64) -> Vec<u8> {
    // The encoding is as follows in bytes: 10 34 10 32 <pubkey> 16 <varint>
    let mut res = vec![10u8, 34u8, 10u8, 32u8];
    res.extend_from_slice(&pubkey);
    res.push(16u8);
    // The remaining bytes of the serialized validator are the voting power as a "varint".
    let voting_power_serialized = marshal_int64_varint(*voting_power);
    res.extend_from_slice(&voting_power_serialized);
    res
}

fn hash_validator_leaf(validator: &[u8]) -> [u8; 32] {
    // The encoding is as follows in bytes: 0x00 || validatorBytes
    let mut validator_bytes = vec![0u8]; // Leaf node prefix
    validator_bytes.extend_from_slice(validator);
    let mut hasher = Sha256::new();
    hasher.update(&validator_bytes);
    hasher.finalize().into()
}

fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
    validators: &[Vec<u8>],
    validator_byte_lengths: &[u64],
    enabled_validators: u64,
) -> Vec<u8> {
    let mut validator_leaf_hashes = Vec::new();
    for i in 0..VALIDATOR_SET_SIZE_MAX {
        validator_leaf_hashes.push(hash_validator_leaf(&validators[i]))
    }
    assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
    assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
    let mut circuit_builder = TreeBuilder {};
    circuit_builder.get_root_from_hashed_leaves::<VALIDATOR_SET_SIZE_MAX>(
        validator_leaf_hashes.iter().map(|x| x.to_vec()).collect(),
        enabled_validators,
    )
}

fn compute_validators_hash<const VALIDATOR_SET_SIZE_MAX: usize>(
    validators: &Vec<ValidatorHashFieldVariable>,
    nb_enabled_validators: u64,
) -> Vec<u8> {
    // Extract the necessary fields.
    let byte_lengths: Vec<u64> = validators.iter().map(|v| v.validator_byte_length).collect();
    let marshalled_validators: Vec<Vec<u8>> = validators
        .iter()
        .map(|v| marshal_tendermint_validator(&v.pubkey, &v.voting_power))
        .collect();

    // Compute the validators hash of the validator set.
    hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
        &marshalled_validators,
        &byte_lengths,
        nb_enabled_validators,
    )
}
