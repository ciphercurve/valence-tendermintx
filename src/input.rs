use std::env;

use tendermint::block::Header;
use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::Info;
use tendermint_proto::Protobuf;

use crate::consts::{
    BLOCK_HEIGHT_INDEX, CHAIN_ID_INDEX, LAST_BLOCK_ID_INDEX, MAX_NUM_RETRIES,
    NEXT_VALIDATORS_HASH_INDEX, PROTOBUF_CHAIN_ID_SIZE_BYTES, VALIDATORS_HASH_INDEX,
};
use crate::types::conversion::{get_validator_data_from_block, validator_hash_field_from_block};
use crate::types::types::{ChainIdProofValueType, InclusionProof, SkipInputs, StepInputs};
use crate::utils::{CommitResponse, ValidatorSetResponse};
use crate::verification::get_merkle_proof;

#[derive(Debug)]
pub struct InputDataFetcher {
    pub urls: Vec<String>,
}

/// Computes the path indices for a Merkle proof based on the index and total number of leaves.
pub fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total - 1;
    let mut current_index = index;
    while current_total >= 1 {
        path_indices.push(current_index % 2 == 1);
        current_total /= 2;
        current_index /= 2;
    }
    path_indices
}

impl Default for InputDataFetcher {
    fn default() -> Self {
        dotenv::dotenv().ok();

        // TENDERMINT_RPC_URL is a list of comma separated tendermint rpc urls.
        let urls = env::var("TENDERMINT_RPC_URL").expect("TENDERMINT_RPC_URL is not set in .env");

        // Split the url's by commas.
        let urls = urls
            .split(',')
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        Self::new(urls)
    }
}

impl InputDataFetcher {
    pub fn new(urls: Vec<String>) -> Self {
        Self { urls }
    }

    // Request data from the Tendermint RPC with quadratic backoff & multiple RPC's.
    pub async fn request_from_rpc(&self, route: &str, retries: usize) -> String {
        for _ in 0..self.urls.len() {
            let url = format!("{}/{}", self.urls[0], route);
            let mut res = reqwest::get(url.clone()).await;
            let mut num_retries = 0;
            while res.is_err() && num_retries < retries {
                res = reqwest::get(url.clone()).await;
                // Quadratic backoff for requests.
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(num_retries as u32)))
                    .await;
                num_retries += 1;
            }

            if res.is_ok() {
                return res.unwrap().text().await.unwrap();
            }
        }
        panic!("Failed to fetch data from Tendermint RPC endpoint");
    }

    pub async fn get_signed_header_from_number(&self, block_number: u64) -> SignedHeader {
        let query_route = format!("commit?height={}", block_number.to_string().as_str());
        let fetched_result = self.request_from_rpc(&query_route, MAX_NUM_RETRIES).await;
        let v: CommitResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        v.result.signed_header
    }

    pub async fn get_validator_set_from_number(&mut self, block_number: u64) -> Vec<Info> {
        let mut validators = Vec::new();

        let mut page_number = 1;
        let mut num_so_far = 0;
        loop {
            let fetched_result = self.fetch_validator_result(block_number, page_number).await;

            validators.extend(fetched_result.result.validators);
            // Parse count to u32.
            let parsed_count: u32 = fetched_result.result.count.parse().unwrap();
            // Parse total to u32.
            let parsed_total: u32 = fetched_result.result.total.parse().unwrap();

            num_so_far += parsed_count;
            if num_so_far >= parsed_total {
                break;
            }
            page_number += 1;
        }

        validators
    }

    async fn fetch_validator_result(
        &mut self,
        block_number: u64,
        page_number: u64,
    ) -> ValidatorSetResponse {
        let query_route = format!(
            "validators?height={}&per_page=100&page={}",
            block_number.to_string().as_str(),
            page_number.to_string().as_str()
        );

        let fetched_result = self.request_from_rpc(&query_route, MAX_NUM_RETRIES).await;
        let v: ValidatorSetResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");
        v
    }

    pub fn get_inclusion_proof(
        &mut self,
        block_header: &Header,
        index: u64,
        encoded_leaf: Vec<u8>,
    ) -> InclusionProof {
        let (leaf, proof) = get_merkle_proof(block_header, index, encoded_leaf);
        let path_indices = get_path_indices(index, 14); // Header has 14 fields
        InclusionProof {
            leaf: leaf.try_into().unwrap(),
            proof,
            path_indices,
        }
    }

    pub async fn get_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        trusted_block_number: u64,
        trusted_block_hash: Vec<u8>,
        target_block_number: u64,
    ) -> SkipInputs {
        let trusted_block_validator_set = self
            .get_validator_set_from_number(trusted_block_number)
            .await;
        let nb_trusted_validators = trusted_block_validator_set.len();
        let target_block_validator_set = self
            .get_validator_set_from_number(target_block_number)
            .await;
        let nb_target_validators = target_block_validator_set.len();

        let target_signed_header = self
            .get_signed_header_from_number(target_block_number)
            .await;

        let trusted_signed_header = self
            .get_signed_header_from_number(trusted_block_number)
            .await;

        let target_block_header = target_signed_header.header.clone();
        let trusted_block_header = trusted_signed_header.header.clone();
        let round = target_signed_header.commit.round.value() as usize;

        let encoded_chain_id = target_signed_header.header().chain_id.clone().encode_vec();
        let target_block_chain_id_proof = get_merkle_proof(
            &target_signed_header.header(),
            CHAIN_ID_INDEX as u64,
            encoded_chain_id.clone(),
        );
        // Extend the chain id to the maximum encoded length.
        let mut extended_chain_id = encoded_chain_id.clone();
        extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
        let target_block_chain_id_proof = ChainIdProofValueType {
            chain_id: extended_chain_id,
            enc_chain_id_byte_length: encoded_chain_id.len() as u32,
            proof: target_block_chain_id_proof.1,
        };

        let target_block_height_proof = get_merkle_proof(
            &target_signed_header.header(),
            BLOCK_HEIGHT_INDEX as u64,
            target_signed_header.header().height.encode_vec(),
        );
        let target_block_validators_hash_proof = self.get_inclusion_proof(
            &target_signed_header.header(),
            VALIDATORS_HASH_INDEX as u64,
            target_signed_header.header().validators_hash.encode_vec(),
        );

        let trusted_block_validators_hash_fields = validator_hash_field_from_block(
            &trusted_block_validator_set,
            &trusted_signed_header.commit,
        );
        let trusted_block_validators_hash_proof = self.get_inclusion_proof(
            &trusted_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            trusted_signed_header.header.validators_hash.encode_vec(),
        );

        let target_block_validators =
            get_validator_data_from_block(&target_block_validator_set, &target_signed_header);

        assert_eq!(trusted_block_hash, trusted_block_header.hash().as_bytes());

        SkipInputs {
            target_block_validators,
            nb_target_validators,
            target_header: target_block_header,
            round,
            target_block_chain_id_proof,
            target_block_height_proof,
            target_block_validators_hash_proof,
            trusted_header: trusted_block_header,
            trusted_block_validators_hash_proof,
            trusted_block_validators_hash_fields,
            nb_trusted_validators,
        }
    }
    // step starts here
    pub async fn get_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        prev_block_number: u64,
    ) -> StepInputs {
        let prev_block_signed_header = self.get_signed_header_from_number(prev_block_number).await;
        let prev_header = prev_block_signed_header.header.clone();
        let next_block_signed_header = self
            .get_signed_header_from_number(prev_block_number + 1)
            .await;
        let next_block_validators = self
            .get_validator_set_from_number(prev_block_number + 1)
            .await;
        let nb_validators = next_block_validators.len();
        assert!(
            nb_validators <= VALIDATOR_SET_SIZE_MAX,
            "The validator set size of the next block is larger than the
            VALIDATOR_SET_SIZE_MAX."
        );
        let next_block_validators =
            get_validator_data_from_block(&next_block_validators, &next_block_signed_header);
        let next_chain_id = next_block_signed_header.header.chain_id.clone();
        let next_block_chain_id_proof = get_merkle_proof(
            &next_block_signed_header.header,
            CHAIN_ID_INDEX as u64,
            next_chain_id.clone().encode_vec(),
        );
        // Extend the chain id to the maximum encoded length
        let mut extended_chain_id = next_chain_id.clone().encode_vec();
        extended_chain_id.resize(PROTOBUF_CHAIN_ID_SIZE_BYTES, 0u8);
        let next_block_chain_id_proof = ChainIdProofValueType {
            chain_id: extended_chain_id,
            enc_chain_id_byte_length: next_chain_id.encode_vec().len() as u32,
            proof: next_block_chain_id_proof.1,
        };

        let next_block_height_proof = get_merkle_proof(
            &next_block_signed_header.header,
            BLOCK_HEIGHT_INDEX as u64,
            next_block_signed_header.header.height.encode_vec(),
        );
        let next_block_validators_hash_proof = self.get_inclusion_proof(
            &next_block_signed_header.header,
            VALIDATORS_HASH_INDEX as u64,
            next_block_signed_header.header.validators_hash.encode_vec(),
        );
        let next_block_last_block_id_proof = self.get_inclusion_proof(
            &next_block_signed_header.header,
            LAST_BLOCK_ID_INDEX as u64,
            <tendermint::block::Id as tendermint_proto::Protobuf<
                tendermint_proto::types::BlockId,
            >>::encode_vec(
                next_block_signed_header
                    .header
                    .last_block_id
                    .unwrap_or_default(),
            ),
        );
        let prev_block_next_validators_hash_proof = self.get_inclusion_proof(
            &prev_header,
            NEXT_VALIDATORS_HASH_INDEX as u64,
            prev_header.next_validators_hash.encode_vec(),
        );
        let round = next_block_signed_header.commit.round.value() as usize;
        let next_block_header = next_block_signed_header.header;

        StepInputs {
            next_header: next_block_header,
            round,
            next_block_validators,
            nb_validators,
            next_block_chain_id_proof,
            next_block_height_proof,
            next_block_validators_hash_proof,
            next_block_last_block_id_proof,
            prev_block_next_validators_hash_proof,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::verification::{get_merkle_proof, verification::verify_merkle_proof};
    use tendermint_proto::Protobuf;

    #[tokio::test]
    async fn test_verify_merkle_proof() {
        let data_fetcher = super::InputDataFetcher::default();
        let block_number = 28122519;
        let signed_header = data_fetcher
            .get_signed_header_from_number(block_number)
            .await;
        // Get the chain ID proof
        let encoded_chain_id = signed_header.header.chain_id.clone().encode_vec();
        let (leaf, proof) = get_merkle_proof(
            &signed_header.header,
            super::CHAIN_ID_INDEX as u64,
            encoded_chain_id.clone(),
        );
        let path_indices = super::get_path_indices(super::CHAIN_ID_INDEX as u64, 14);
        // Verify the proof
        let root_hash = signed_header.header.hash();
        assert!(verify_merkle_proof(
            root_hash.as_bytes().try_into().unwrap(),
            &leaf,
            &proof,
            &path_indices
        ));
    }
}
