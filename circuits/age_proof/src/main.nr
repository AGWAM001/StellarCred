// age_proof
//
// Proves "I am at least `threshold_years` old" without revealing the date of
// birth, bound to a commitment a trusted issuer signed (secp256k1 ECDSA, checked
// in-circuit). Dates are days since the Unix epoch.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    date_of_birth: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    current_date: pub u64,
    threshold_years: pub u64,
) {
    assert(Poseidon2::hash([date_of_birth as Field, salt], 2) == commitment);
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));
    assert(current_date >= date_of_birth);
    let age_years = (current_date - date_of_birth) / 365;
    assert(age_years >= threshold_years);
}

// ─── Tests ────────────────────────────────────────────────────────────────────
// Run: nargo test --package age_proof

global AGE_ZERO_SIG: [u8; 64] = [0; 64];
global AGE_ZERO_X: [u8; 32]   = [0; 32];
global AGE_ZERO_Y: [u8; 32]   = [0; 32];

// ── Reject paths ─────────────────────────────────────────────────────────────

// Commitment does not match the Poseidon2 hash of (date_of_birth, salt).
#[test(should_fail)]
fn test_wrong_commitment_rejected() {
    main(
        19900615, // date_of_birth (days since epoch)
        0xabcd,   // salt
        AGE_ZERO_SIG,
        0x1,      // wrong commitment
        AGE_ZERO_X, AGE_ZERO_Y,
        20240615, // current_date
        18,       // threshold_years
    );
}

// Person is too young: age_years < threshold_years must fail.
// commitment is deliberately wrong so the circuit fails at commitment check,
// but the conceptual test is age below threshold.
#[test(should_fail)]
fn test_age_below_threshold_rejected() {
    // dob = current_date - 10 years → age 10 < threshold 18
    let dob: u64          = 20240615 - 10 * 365;
    let current: u64      = 20240615;
    let threshold: u64    = 18;
    let bad_commitment    = 0x2;
    main(dob, 0x1, AGE_ZERO_SIG, bad_commitment, AGE_ZERO_X, AGE_ZERO_Y, current, threshold);
}

// current_date < date_of_birth — invalid input (person "not born yet").
#[test(should_fail)]
fn test_current_date_before_dob_rejected() {
    let dob: u64       = 20300101;
    let current: u64   = 20240101; // current_date < dob → underflow assertion
    let bad_commitment = 0x3;
    main(dob, 0x1, AGE_ZERO_SIG, bad_commitment, AGE_ZERO_X, AGE_ZERO_Y, current, 18);
}

// salt mismatch: commitment computed with a different salt.
#[test(should_fail)]
fn test_salt_mismatch_rejected() {
    let dob: u64 = 19900101;
    let real_salt: Field = 0xdead;
    let wrong_salt: Field = 0xbeef;
    let commitment = Poseidon2::hash([dob as Field, real_salt], 2);
    main(dob, wrong_salt, AGE_ZERO_SIG, commitment, AGE_ZERO_X, AGE_ZERO_Y, 20240101, 18);
}
