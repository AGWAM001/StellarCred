// funds_proof
//
// Proves "my account balance is at least `threshold`" without revealing the
// figure, bound to a commitment a trusted issuer signed (secp256k1 ECDSA,
// in-circuit). The balance is an integer (e.g. USD cents or whole dollars).

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    balance: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    threshold: pub u64,
) {
    assert(Poseidon2::hash([balance as Field, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
    assert(balance >= threshold);
}

// ─── Tests ────────────────────────────────────────────────────────────────────
// Run: nargo test --package funds_proof

global FND_ZERO_SIG: [u8; 64] = [0; 64];
global FND_ZERO_X: [u8; 32]   = [0; 32];
global FND_ZERO_Y: [u8; 32]   = [0; 32];

#[test(should_fail)]
fn test_wrong_commitment_rejected() {
    main(100000, 0x1234, FND_ZERO_SIG, 0x1, FND_ZERO_X, FND_ZERO_Y, 50000);
}

// balance < threshold.
#[test(should_fail)]
fn test_balance_below_threshold_rejected() {
    let balance: u64   = 9999;
    let threshold: u64 = 10000;
    let bad_commitment = 0x2;
    main(balance, 0x1, FND_ZERO_SIG, bad_commitment, FND_ZERO_X, FND_ZERO_Y, threshold);
}

// Exact off-by-one: balance is 1 unit below threshold.
#[test(should_fail)]
fn test_balance_one_below_threshold_rejected() {
    let balance: u64   = 49999;
    let threshold: u64 = 50000;
    let bad_commitment = 0x3;
    main(balance, 0x1, FND_ZERO_SIG, bad_commitment, FND_ZERO_X, FND_ZERO_Y, threshold);
}

// salt mismatch: commitment uses a different salt.
#[test(should_fail)]
fn test_salt_mismatch_rejected() {
    let balance: u64 = 100000;
    let real_salt: Field = 0xcafe;
    let wrong_salt: Field = 0xbabe;
    let commitment = Poseidon2::hash([balance as Field, real_salt], 2);
    main(balance, wrong_salt, FND_ZERO_SIG, commitment, FND_ZERO_X, FND_ZERO_Y, 50000);
}
