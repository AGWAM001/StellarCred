// age_proof
//
// Proves "I am at least `threshold_years` old" without revealing the date of
// birth, bound to a commitment a trusted issuer signed (secp256k1 ECDSA, checked
// in-circuit). Dates are days since the Unix epoch.

use dep::credential_lib;

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
    credential_lib::assert_committed_and_signed(date_of_birth as Field, salt, sig, commitment, issuer_x, issuer_y);
    assert(current_date >= date_of_birth);
    let age_years = (current_date - date_of_birth) / 365;
    assert(age_years >= threshold_years);
}
