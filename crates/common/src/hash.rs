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

/// Implements the truncated Keccak hash function using a mask approach
fn keccak_hash(a: Felt, b: Felt) -> Felt {
    // The mask keeps only the top 160 bits (zeros out the bottom 96 bits)
    
    // Convert inputs to bytes and apply mask (keep only first 20 bytes)
    let mut masked_a = [0u8; 32];
    let mut masked_b = [0u8; 32];
    masked_a[0..20].copy_from_slice(&a.to_be_bytes()[0..20]);
    masked_b[0..20].copy_from_slice(&b.to_be_bytes()[0..20]);
    
    // Hash the masked inputs
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(&masked_a);
    keccak.update(&masked_b);
    keccak.finalize(&mut output);
    
    // Apply mask to output and convert to Felt
    let mut masked_output = [0u8; 32];
    masked_output[0..20].copy_from_slice(&output[0..20]);
    Felt::from_be_bytes(masked_output).unwrap()
}
