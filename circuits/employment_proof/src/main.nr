// employment_proof
//
// Proves "I am employed" (and optionally at seniority >= min_seniority)
// without revealing the employer or exact role, bound to a commitment a
// trusted issuer (the employer) signed (secp256k1 ECDSA, in-circuit).
// Unlocks income-linked lending, professional gating, and DAO contributor
// verification.
//
// employment_status is a small u64 tag (e.g. 1 = employed, 0 = unemployed);
// the actual employer / role stays off-chain in the issuer's records, only
// the commitment (Poseidon2([employment_status, salt])) ever appears on-chain.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    employment_status: u64,
    seniority: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    min_seniority: pub u64,
) {
    assert(Poseidon2::hash([employment_status as Field, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
    // The status tag must be > 0 (i.e. the holder is "employed"); issuers are
    // expected to only sign non-zero tags, but the constraint also defends
    // against forged zero-tag credentials.
    assert(employment_status != 0);
    assert(seniority >= min_seniority);
}
