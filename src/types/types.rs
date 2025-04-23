use crate::types::conversion::{ValidatorHashFieldVariable, ValidatorVariable};
use tendermint::block::Header;

#[derive(Debug)]
pub struct InclusionProof {
    pub leaf: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub path_indices: Vec<bool>,
}

#[derive(Debug)]
pub struct ChainIdProofValueType {
    pub chain_id: Vec<u8>,
    pub enc_chain_id_byte_length: u32,
    pub proof: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct HeightProofValueType {
    pub height: u64,
    pub enc_height_byte_length: u32,
    pub proof: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct StepInputs {
    pub next_header: Header,
    pub round: usize,
    pub next_block_validators: Vec<ValidatorVariable>,
    pub nb_validators: usize,
    pub next_block_chain_id_proof: ChainIdProofValueType,
    pub next_block_height_proof: (Vec<u8>, Vec<Vec<u8>>),
    pub next_block_validators_hash_proof: InclusionProof,
    pub next_block_last_block_id_proof: InclusionProof,
    pub prev_block_next_validators_hash_proof: InclusionProof,
}

#[derive(Debug)]
pub struct SkipInputs {
    pub target_block_validators: Vec<ValidatorVariable>, // validators
    pub nb_target_validators: usize,                     // nb_validators
    pub target_header: Header,                           // target_header
    pub round: usize,                                    // round
    pub target_block_chain_id_proof: ChainIdProofValueType, // target_chain_id_proof,
    pub target_block_height_proof: (Vec<u8>, Vec<Vec<u8>>), // target_block_height_proof,
    pub target_block_validators_hash_proof: InclusionProof, // target_header_validators_hash_proof,
    pub trusted_header: Header,                          // trusted_header
    pub trusted_block_validators_hash_proof: InclusionProof, // trusted_validators_hash_proof
    pub trusted_block_validators_hash_fields: Vec<ValidatorHashFieldVariable>, // trusted_validators_hash_fields
    pub nb_trusted_validators: usize, // nb_trusted_validators
}
