use tendermint::PublicKey;
use tendermint::block::signed_header::SignedHeader;
use tendermint::block::{Commit, CommitSig};
use tendermint::chain::Id;
use tendermint::crypto::default::signature::Verifier;
use tendermint::crypto::signature::Verifier as _;
use tendermint::validator::{Info, Set as TendermintValidatorSet};
use tendermint::vote::{SignedVote, ValidatorIndex};

use crate::consts::{
    DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE, VALIDATOR_BYTE_LENGTH_MAX,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, VALIDATOR_SET_SIZE_MAX,
};
use crate::utils::get_vote_from_commit_sig;

#[derive(Debug, Clone)]
pub struct ValidatorVariable {
    pub pubkey: Vec<u8>,
    pub signature: EDDSASignatureVariableValue,
    pub message: Vec<u8>,
    pub message_byte_length: u64,
    pub voting_power: u64,
    pub validator_byte_length: u64,
    pub signed: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatorHashFieldVariable {
    pub pubkey: Vec<u8>,
    pub voting_power: u64,
    pub validator_byte_length: u64,
}
#[derive(Debug, Clone)]
pub struct EDDSASignatureVariableValue {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Get the padded_message, message_length, and signature for the validator from a specific
/// commit signature.
fn get_signed_message_data(
    chain_id: &Id,
    pubkey: &PublicKey,
    commit_sig: &CommitSig,
    val_idx: &ValidatorIndex,
    commit: &Commit,
) -> (
    [u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
    usize,
    EDDSASignatureVariableValue,
) {
    let vote = get_vote_from_commit_sig(commit_sig, *val_idx, commit).unwrap();
    let signed_vote =
        SignedVote::from_vote(vote.clone(), chain_id.clone()).expect("missing signature");
    let mut padded_signed_message = signed_vote.sign_bytes();
    let msg_length = padded_signed_message.len();

    padded_signed_message.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

    let sig = signed_vote.signature();

    let signature_value = EDDSASignatureVariableValue {
        r: sig.as_bytes()[0..32].try_into().unwrap(),
        s: sig.as_bytes()[32..64].try_into().unwrap(),
    };

    Verifier::verify(*pubkey, &signed_vote.sign_bytes(), sig)
        .expect("Signature should be valid for validator");

    (
        padded_signed_message.try_into().unwrap(),
        msg_length,
        signature_value,
    )
}

/// Get the validator data for a specific block.
pub fn get_validator_data_from_block(
    block_validators: &[Info],
    signed_header: &SignedHeader,
) -> Vec<ValidatorVariable> {
    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let validator_set = TendermintValidatorSet::new(block_validators.to_vec(), None);

    // Exclude invalid validators (i.e. those that are malformed & are not included in the validator set).
    for i in 0..signed_header.commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let pubkey = &validator.pub_key.to_bytes();

        if signed_header.commit.signatures[i].is_commit() {
            // Get the padded_message, message_length, and signature for the validator.
            let (padded_msg, msg_length, signature) = get_signed_message_data(
                &signed_header.header.chain_id,
                &validator.pub_key,
                &signed_header.commit.signatures[i],
                &val_idx,
                &signed_header.commit,
            );

            validators.push(ValidatorVariable {
                pubkey: pubkey.to_vec(),
                signature,
                message: padded_msg.to_vec(),
                message_byte_length: msg_length as u64,
                voting_power: validator.power(),
                validator_byte_length: val_bytes.len() as u64,
                signed: true,
            });
        } else {
            let signature_value = EDDSASignatureVariableValue {
                r: DUMMY_SIGNATURE[0..32].try_into().unwrap(),
                s: DUMMY_SIGNATURE[32..64].try_into().unwrap(),
            };

            // These are dummy signatures (included in val hash, did not vote)
            validators.push(ValidatorVariable {
                pubkey: pubkey.to_vec(),
                signature: signature_value,
                message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX].to_vec(),
                message_byte_length: 32,
                voting_power: validator.power(),
                validator_byte_length: val_bytes.len() as u64,
                signed: false,
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for _ in signed_header.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let pubkey = &DUMMY_PUBLIC_KEY;
        let signature_value = EDDSASignatureVariableValue {
            r: DUMMY_SIGNATURE[0..32].try_into().unwrap(),
            s: DUMMY_SIGNATURE[32..64].try_into().unwrap(),
        };

        validators.push(ValidatorVariable {
            pubkey: pubkey.to_vec(),
            signature: signature_value,
            message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX].to_vec(),
            message_byte_length: 32,
            voting_power: 0u64,
            validator_byte_length: VALIDATOR_BYTE_LENGTH_MAX as u64,
            signed: false,
        });
    }

    validators
}

pub fn validator_hash_field_from_block(
    trusted_validator_set: &[Info],
    trusted_commit: &Commit,
) -> Vec<ValidatorHashFieldVariable> {
    let mut trusted_validator_fields = Vec::new();

    let validator_set = TendermintValidatorSet::new(trusted_validator_set.to_vec(), None);

    let block_validators = validator_set.validators();

    for i in 0..trusted_commit.signatures.len() {
        let validator = Box::new(match validator_set.validator(block_validators[i].address) {
            Some(validator) => validator,
            None => continue, // Cannot find matching validator, so we skip the vote
        });
        let val_bytes = validator.hash_bytes();
        let pubkey = &validator.pub_key.to_bytes();

        trusted_validator_fields.push(ValidatorHashFieldVariable {
            pubkey: pubkey.to_vec(),
            voting_power: validator.power(),
            validator_byte_length: val_bytes.len() as u64,
        });
    }

    let val_so_far = trusted_validator_fields.len();

    // These are empty signatures (not included in val hash)
    for _ in val_so_far..VALIDATOR_SET_SIZE_MAX {
        let pubkey = &DUMMY_PUBLIC_KEY;

        trusted_validator_fields.push(ValidatorHashFieldVariable {
            pubkey: pubkey.to_vec(),
            voting_power: 0u64,
            validator_byte_length: VALIDATOR_BYTE_LENGTH_MAX as u64,
        });
    }

    trusted_validator_fields
}
