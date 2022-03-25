pub use secp256k1_zkp::*;

use anyhow::Result;
use std::num::NonZeroU8;

/// Compute an attestation public key for the given oracle public key,
/// announcement nonce public key and outcome index.
pub fn attestation_pk(
    oracle_pk: &secp256k1_zkp::PublicKey,
    nonce_pk: &secp256k1_zkp::PublicKey,
    index: NonZeroU8,
) -> Result<secp256k1_zkp::PublicKey> {
    let mut nonce_pk_sum = *nonce_pk;
    nonce_pk_sum.mul_assign(SECP256K1, &index_to_bytes(index))?;

    let attestation_pk = oracle_pk.combine(&nonce_pk_sum)?;

    Ok(attestation_pk)
}

fn index_to_bytes(index: NonZeroU8) -> [u8; 32] {
    let mut bytes = [0u8; 32];

    bytes[31] = index.get();

    bytes
}
