// kyc_proof
//
// Proves the holder knows the secret behind a KYC credential AND that a trusted
// issuer signed the commitment to it (secp256k1 ECDSA, verified in-circuit).
// Public inputs, in order: commitment, issuer_x, issuer_y, so the contract can
// bind the public key to the registered issuer. The signature and secret stay
// private.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    secret: Field,
    salt: Field,
    sig: [u8; 64],
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
) {
    assert(Poseidon2::hash([secret, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
}

// ─── Tests ────────────────────────────────────────────────────────────────────
// Run: nargo test --package kyc_proof

// Dummy issuer keys used for should_fail tests only (signature never checked
// because the commitment assertion fails first).
global ZERO_SIG: [u8; 64] = [0; 64];
global ZERO_X: [u8; 32] = [0; 32];
global ZERO_Y: [u8; 32] = [0; 32];

// ── Reject paths ─────────────────────────────────────────────────────────────

// A tampered commitment that does not match Poseidon2([secret, salt], 2).
#[test(should_fail)]
fn test_wrong_commitment_rejected() {
    let secret = 0x1234;
    let salt   = 0xabcd;
    let bad_commitment = 0x0000000000000000000000000000000000000000000000000000000000000001;
    main(secret, salt, ZERO_SIG, bad_commitment, ZERO_X, ZERO_Y);
}

// A zero commitment never equals a real Poseidon2 hash (Poseidon2 output is
// non-zero for any non-trivial input in the BN254 scalar field).
#[test(should_fail)]
fn test_zero_commitment_rejected() {
    main(42, 99, ZERO_SIG, 0, ZERO_X, ZERO_Y);
}

// A different secret produces a different commitment — wrong secret must fail.
#[test(should_fail)]
fn test_secret_mismatch_rejected() {
    let correct_secret = 0xdeadbeef;
    let wrong_secret   = 0xdeadc0de;
    let salt           = 0x1111;
    // commitment computed for correct_secret, but main called with wrong_secret
    let fake_commitment = Poseidon2::hash([correct_secret as Field, salt as Field], 2);
    main(wrong_secret, salt, ZERO_SIG, fake_commitment, ZERO_X, ZERO_Y);
}
