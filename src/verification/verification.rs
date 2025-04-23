use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tendermint::block::Header;
use tendermint_proto::Protobuf;

use crate::consts::{
    BLOCK_HEIGHT_INDEX, CHAIN_ID_INDEX, PROTOBUF_CHAIN_ID_SIZE_BYTES, VALIDATOR_BYTE_LENGTH_MAX,
    VALIDATOR_SET_SIZE_MAX,
};
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

    // Marshal validators and compute validator set hash
    let mut marshaled_validators = Vec::new();
    let mut validator_byte_lengths = Vec::new();

    for validator in &step_inputs.next_block_validators {
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
        step_inputs.nb_validators as u64,
    );
    println!("computed_validators_hash: {:?}", computed_validators_hash);
    println!(
        "step_inputs.next_header.validators_hash: {:?}",
        step_inputs.next_header.validators_hash.as_bytes()
    );
    // Verify computed hash matches the header's validators hash
    if computed_validators_hash != step_inputs.next_header.validators_hash.as_bytes() {
        return Err("Computed validators hash does not match header's validators hash".to_string());
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

fn hash_validator_leaf(validator: &[u8], validator_byte_length: u64) -> [u8; 32] {
    // The encoding is as follows in bytes: 0x00 || validatorBytes
    let mut validator_bytes = vec![0u8]; // Leaf node prefix
    validator_bytes.extend_from_slice(validator);
    validator_bytes.resize(64, 0u8);
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
        validator_leaf_hashes.push(hash_validator_leaf(
            &validators[i],
            validator_byte_lengths[i],
        ))
    }
    println!("validator_leaf_hashes: {:?}", validator_leaf_hashes);
    assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
    assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
    let mut circuit_builder = CircuitBuilder {};
    circuit_builder.get_root_from_hashed_leaves::<100>(
        validator_leaf_hashes.iter().map(|x| x.to_vec()).collect(),
        enabled_validators,
    )
}

struct CircuitBuilder {}

pub trait TendermintMerkleTree {
    fn get_root_from_merkle_proof_hashed_leaf<const PROOF_DEPTH: usize>(
        &mut self,
        proof: &Vec<Vec<u8>>,
        path_indices: &Vec<bool>,
        leaf: Vec<u8>,
    ) -> Vec<u8>;

    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize, const LEAF_SIZE_BYTES: usize>(
        &mut self,
        inclusion_proof: &MerkleInclusionProofVariable,
        path_indices: Vec<bool>,
    ) -> Vec<u8>;

    fn leaf_hash(&mut self, leaf: &[u8]) -> Vec<u8>;

    fn inner_hash(&mut self, left: &[u8], right: &[u8]) -> Vec<u8>;

    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: Vec<Vec<u8>>,
        merkle_hash_enabled: Vec<bool>,
    ) -> (Vec<Vec<u8>>, Vec<bool>);

    fn hash_leaves<const LEAF_SIZE_BYTES: usize>(&mut self, leaves: Vec<Vec<u8>>) -> Vec<Vec<u8>>;

    fn get_root_from_hashed_leaves<const MAX_NB_LEAVES: usize>(
        &mut self,
        leaf_hashes: Vec<Vec<u8>>,
        nb_enabled_leaves: u64,
    ) -> Vec<u8>;

    fn compute_root_from_leaves<const MAX_NB_LEAVES: usize, const LEAF_SIZE_BYTES: usize>(
        &mut self,
        leaves: Vec<Vec<u8>>,
        nb_enabled_leaves: u64,
    ) -> Vec<u8>;
}

/// Merkle Tree implementation for the Tendermint spec (follows Comet BFT Simple Merkle Tree spec: https://docs.cometbft.com/main/spec/core/encoding#merkle-trees).
/// Adds pre-image prefix of 0x01 to inner nodes and 0x00 to leaf nodes for second pre-image resistance.
/// Computed root hash is independent of the number of empty leaves, unlike the simple Merkle Tree.
impl TendermintMerkleTree for CircuitBuilder {
    /// Leaf should already be hashed.
    fn get_root_from_merkle_proof_hashed_leaf<const PROOF_DEPTH: usize>(
        &mut self,
        proof: &Vec<Vec<u8>>,
        path_indices: &Vec<bool>,
        leaf: Vec<u8>,
    ) -> Vec<u8> {
        let mut hash_so_far = leaf;

        for i in 0..PROOF_DEPTH {
            let aunt = proof[i].clone();
            let path_index = path_indices[i];
            let left_hash_pair = self.inner_hash(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash(&aunt, &hash_so_far);

            if path_index {
                hash_so_far = right_hash_pair;
            } else {
                hash_so_far = left_hash_pair;
            }
        }
        hash_so_far
    }

    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize, const LEAF_SIZE_BYTES: usize>(
        &mut self,
        inclusion_proof: &MerkleInclusionProofVariable,
        path_indices: Vec<bool>,
    ) -> Vec<u8> {
        let hashed_leaf = self.leaf_hash(&inclusion_proof.leaf);

        self.get_root_from_merkle_proof_hashed_leaf::<PROOF_DEPTH>(
            &inclusion_proof.proof,
            &path_indices,
            hashed_leaf,
        )
    }

    fn leaf_hash(&mut self, leaf: &[u8]) -> Vec<u8> {
        // Leaf node pre-image is 0x00 || leaf.
        let zero_byte = 0u8;

        let mut encoded_leaf = vec![zero_byte];

        // Append the leaf bytes to the zero byte.
        encoded_leaf.extend(leaf.to_vec());

        // Load the output of the hash.
        let mut hasher = Sha256::new();
        hasher.update(&encoded_leaf);
        hasher.finalize().to_vec()
    }

    fn inner_hash(&mut self, left: &[u8], right: &[u8]) -> Vec<u8> {
        // Inner node pre-image is 0x01 || left || right.
        let one_byte = 1u8;

        let mut encoded_leaf = vec![one_byte];

        // Append the left bytes to the one byte.
        encoded_leaf.extend(left);

        // Append the right bytes to the bytes so far.
        encoded_leaf.extend(right);
        let mut hasher = Sha256::new();
        hasher.update(&encoded_leaf);
        hasher.finalize().to_vec()
    }

    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: Vec<Vec<u8>>,
        merkle_hash_enabled: Vec<bool>,
    ) -> (Vec<Vec<u8>>, Vec<bool>) {
        let zero = false;
        let one = true;

        let mut new_merkle_hashes = Vec::new();
        let mut new_merkle_hash_enabled = Vec::new();

        for i in (0..merkle_hashes.len()).step_by(2) {
            let both_nodes_enabled = merkle_hash_enabled[i] && merkle_hash_enabled[i + 1];

            let first_node_disabled = !merkle_hash_enabled[i];
            let second_node_disabled = !merkle_hash_enabled[i + 1];
            let both_nodes_disabled = first_node_disabled && second_node_disabled;

            // Calculuate the inner hash.
            let inner_hash = self.inner_hash(&merkle_hashes[i], &merkle_hashes[i + 1]);

            if both_nodes_enabled {
                new_merkle_hashes.push(inner_hash);
            } else {
                new_merkle_hashes.push(merkle_hashes[i].clone());
            }

            // Set the inner node one level up to disabled if both nodes are disabled.
            if both_nodes_disabled {
                new_merkle_hash_enabled.push(zero);
            } else {
                new_merkle_hash_enabled.push(one);
            }
        }

        // Return the hashes and enabled nodes for the next layer up.
        (new_merkle_hashes, new_merkle_hash_enabled)
    }

    fn hash_leaves<const LEAF_SIZE_BYTES: usize>(&mut self, leaves: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        leaves.iter().map(|leaf| self.leaf_hash(&leaf)).collect()
    }

    fn get_root_from_hashed_leaves<const MAX_NB_LEAVES: usize>(
        &mut self,
        leaf_hashes: Vec<Vec<u8>>,
        nb_enabled_leaves: u64,
    ) -> Vec<u8> {
        let empty_bytes = &[0u8; 32];

        // Extend leaf_hashes to be a power of 2.
        let padded_nb_leaves = 2_u32.pow(log2_ceil_usize(MAX_NB_LEAVES) as u32);
        assert!(padded_nb_leaves >= MAX_NB_LEAVES as u32 && padded_nb_leaves.is_power_of_two());

        // Hash each of the validators to get their corresponding leaf hash.
        // Pad the leaves to be a power of 2.
        let mut current_nodes = leaf_hashes;
        current_nodes.resize(padded_nb_leaves as usize, empty_bytes.to_vec());

        // Whether to treat the validator as empty.
        // Pad the enabled array to be a power of 2.
        let mut current_node_enabled = Vec::new();
        let mut is_enabled = true;
        for i in 0..padded_nb_leaves {
            // If at_end, then the rest of the leaves (including this one) are disabled.
            let at_end = i as u64 == nb_enabled_leaves;
            let not_at_end = !at_end;
            is_enabled = not_at_end && is_enabled;

            current_node_enabled.push(is_enabled);
        }

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while current_nodes.len() > 1 {
            (current_nodes, current_node_enabled) =
                self.hash_merkle_layer(current_nodes, current_node_enabled);
        }

        // Return the root hash.
        current_nodes[0].clone()
    }

    fn compute_root_from_leaves<const MAX_NB_LEAVES: usize, const LEAF_SIZE_BYTES: usize>(
        &mut self,
        leaves: Vec<Vec<u8>>,
        nb_enabled_leaves: u64,
    ) -> Vec<u8> {
        let hashed_leaves = self.hash_leaves::<LEAF_SIZE_BYTES>(leaves);
        self.get_root_from_hashed_leaves::<MAX_NB_LEAVES>(hashed_leaves, nb_enabled_leaves)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        types::types::InclusionProof,
        verification::verification::{
            CircuitBuilder, MerkleInclusionProofVariable, marshal_int64_varint,
            marshal_tendermint_validator,
        },
    };

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
