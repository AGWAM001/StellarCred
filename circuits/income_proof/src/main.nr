// income_proof
//
// Proves "my income is at least `threshold`" without revealing the figure,
// bound to a commitment a trusted issuer signed (secp256k1 ECDSA, in-circuit).

use dep::credential_lib;

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
    credential_lib::assert_committed_and_signed(income as Field, salt, sig, commitment, issuer_x, issuer_y);
    assert(income >= threshold);
}
