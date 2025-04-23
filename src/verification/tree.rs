use sha2::{Digest, Sha256};

use crate::verification::verification::log2_ceil_usize;

use super::verification::MerkleInclusionProofVariable;

pub struct TreeBuilder;

pub trait TendermintMerkleTree {
    fn get_root_from_merkle_proof_hashed_leaf<const PROOF_DEPTH: usize>(
        &mut self,
        proof: &Vec<Vec<u8>>,
        path_indices: &Vec<bool>,
        leaf: Vec<u8>,
    ) -> Vec<u8>;

    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize>(
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
impl TendermintMerkleTree for TreeBuilder {
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

    fn get_root_from_merkle_proof<const PROOF_DEPTH: usize>(
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
