// income_proof
//
// Proves "my income is at least `threshold`" without revealing the figure,
// bound to a commitment a trusted issuer signed (secp256k1 ECDSA, in-circuit).

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    income: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    threshold: pub u64,
) {
    assert(Poseidon2::hash([income as Field, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
    assert(income >= threshold);
}

// ─── Tests ────────────────────────────────────────────────────────────────────
// Run: nargo test --package income_proof

global INC_ZERO_SIG: [u8; 64] = [0; 64];
global INC_ZERO_X: [u8; 32]   = [0; 32];
global INC_ZERO_Y: [u8; 32]   = [0; 32];

#[test(should_fail)]
fn test_wrong_commitment_rejected() {
    main(250000, 0xabcd, INC_ZERO_SIG, 0x1, INC_ZERO_X, INC_ZERO_Y, 100000);
}

// income < threshold: person does not meet the minimum.
#[test(should_fail)]
fn test_income_below_threshold_rejected() {
    let income: u64    = 49999;
    let threshold: u64 = 50000;
    let bad_commitment = 0x2;
    main(income, 0x1, INC_ZERO_SIG, bad_commitment, INC_ZERO_X, INC_ZERO_Y, threshold);
}

// income == threshold - 1: off-by-one boundary.
#[test(should_fail)]
fn test_income_one_below_threshold_rejected() {
    let income: u64    = 99999;
    let threshold: u64 = 100000;
    let bad_commitment = 0x3;
    main(income, 0x1, INC_ZERO_SIG, bad_commitment, INC_ZERO_X, INC_ZERO_Y, threshold);
}

// salt mismatch.
#[test(should_fail)]
fn test_salt_mismatch_rejected() {
    let income: u64 = 250000;
    let real_salt: Field = 0xfeed;
    let wrong_salt: Field = 0xface;
    let commitment = Poseidon2::hash([income as Field, real_salt], 2);
    main(income, wrong_salt, INC_ZERO_SIG, commitment, INC_ZERO_X, INC_ZERO_Y, 100000);
}
