/// The number of validators on the Tendermint chain.
pub const VALIDATOR_SET_SIZE_MAX: usize = 100;

/// The maximum number of bytes in a protobuf-encoded chain ID. The maximum chain ID length is
/// 50 characters + 2 bytes for the encoding prefix. Source:
/// https://docs.tendermint.com/v0.34/tendermint-core/using-tendermint.html#fields
pub const PROTOBUF_CHAIN_ID_SIZE_BYTES: usize = 52;

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
pub const VALIDATOR_BYTE_LENGTH_MAX: usize = 46;

/// The maximum number of bytes in a validator message (CanonicalVote toSignBytes).
pub const VALIDATOR_MESSAGE_BYTES_LENGTH_MAX: usize = 124;

// Header indices for the Merkle tree.
pub const CHAIN_ID_INDEX: usize = 1;
pub const BLOCK_HEIGHT_INDEX: usize = 2;
pub const LAST_BLOCK_ID_INDEX: usize = 4;
pub const VALIDATORS_HASH_INDEX: usize = 7;
pub const NEXT_VALIDATORS_HASH_INDEX: usize = 8;

/// The chain ID for the Neutron chain
/// pub const NEUTRON_CHAIN_ID_BYTES: &[u8] = b"pion-1";

pub const DUMMY_SIGNATURE: [u8; 64] = [
    55, 20, 104, 158, 84, 120, 194, 17, 6, 237, 157, 164, 85, 88, 158, 137, 187, 119, 187, 240,
    159, 73, 80, 63, 133, 162, 74, 91, 48, 53, 6, 138, 1, 41, 22, 121, 249, 46, 198, 145, 155, 102,
    3, 210, 168, 135, 173, 55, 252, 72, 45, 126, 169, 178, 191, 7, 153, 67, 112, 90, 150, 33, 140,
    7,
];

// DUMMY_PRIVATE_KEY is [1u8; 32].
pub const DUMMY_PUBLIC_KEY: [u8; 32] = [
    138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29,
    148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
];

pub const MAX_NUM_RETRIES: usize = 3;
