// funds_proof
//
// Proves "my account balance is at least `threshold`" without revealing the
// figure, bound to a commitment a trusted issuer signed (secp256k1 ECDSA,
// in-circuit). The balance is an integer (e.g. USD cents or whole dollars).

use dep::credential_lib;

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
    credential_lib::assert_committed_and_signed(balance as Field, salt, sig, commitment, issuer_x, issuer_y);
    assert(balance >= threshold);
}
