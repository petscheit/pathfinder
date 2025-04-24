//! Contains the [FeltHash] trait and implementations thereof for the
//! [Pedersen](PedersenHash) and [Poseidon](PoseidonHash) hashes.
use pathfinder_crypto::hash::{pedersen_hash, poseidon_hash};
use pathfinder_crypto::Felt;
use tiny_keccak::{Hasher, Keccak};

/// Allows for implementations to be generic over Felt hash functions.
///
/// Implemented by [PedersenHash] and [PoseidonHash].
pub trait FeltHash {
    fn hash(a: Felt, b: Felt) -> Felt;
}

/// Implements [Hash] for the [Starknet Pedersen hash](pedersen_hash).
#[derive(Debug, Clone, Copy)]
pub struct PedersenHash {}

impl FeltHash for PedersenHash {
    fn hash(a: Felt, b: Felt) -> Felt {
        pedersen_hash(a, b)
    }
}

/// Implements [Hash] for the [Starknet Poseidon hash](poseidon_hash).
#[derive(Debug, Clone, Copy)]
pub struct PoseidonHash;
impl FeltHash for PoseidonHash {
    fn hash(a: Felt, b: Felt) -> Felt {
        poseidon_hash(a.into(), b.into()).into()
    }
}

/// A 160 MSB truncated version of Keccak, where each value is shifted left by 96 bits
/// before hashing, and the result is shifted right by 96 bits.
/// Implements keccak(x << 96, y << 96) >> 96
#[derive(Debug, Clone, Copy)]
pub struct TruncatedKeccakHash;

impl FeltHash for TruncatedKeccakHash {
    fn hash(a: Felt, b: Felt) -> Felt {
        keccak_hash(a, b)
    }
}

/// Implements the truncated Keccak hash function: `keccak(BE(a) || BE(b)) >> 96`.
/// Takes the full big-endian representations of `a` and `b`, concatenates them,
/// computes the Keccak-256 hash, and returns the top 160 bits (right-shifted by 96 bits).
pub fn keccak_hash(a: Felt, b: Felt) -> Felt {
    // Get the full big-endian byte representations of the inputs
    let a_bytes = a.to_be_bytes();
    let b_bytes = b.to_be_bytes();

    // Compute the Keccak-256 hash of the concatenated bytes
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(&a_bytes);
    keccak.update(&b_bytes);
    keccak.finalize(&mut output);

    // Take the top 160 bits (first 20 bytes) of the hash result
    // and place them into the lower 20 bytes of the result Felt.
    // This effectively performs a right shift by 96 bits.
    let mut result_bytes = [0u8; 32];
    result_bytes[12..32].copy_from_slice(&output[0..20]);

    // Convert the result bytes (big-endian) back to Felt
    Felt::from_be_bytes(result_bytes).expect("Conversion from BE bytes should always succeed")
}
