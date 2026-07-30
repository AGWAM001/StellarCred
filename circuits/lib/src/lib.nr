// Shared credential helper used by all credential circuits.
//
// Asserts that:
//   1) Poseidon2([value, salt], 2) == commitment
//   2) The issuer's secp256k1 ECDSA signature over the commitment is valid.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

pub fn assert_committed_and_signed(
    value: Field,
    salt: Field,
    sig: [u8; 64],
    commitment: Field,
    issuer_x: [u8; 32],
    issuer_y: [u8; 32],
) {
    assert(Poseidon2::hash([value, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
}
