// kyc_proof
//
// Proves the holder knows the secret behind a KYC credential AND that a trusted
// issuer signed the commitment to it (secp256k1 ECDSA, verified in-circuit).
// Public inputs, in order: commitment, issuer_x, issuer_y, so the contract can
// bind the public key to the registered issuer. The signature and secret stay
// private.

use dep::credential_lib;

fn main(
    secret: Field,
    salt: Field,
    sig: [u8; 64],
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
) {
    credential_lib::assert_committed_and_signed(secret, salt, sig, commitment, issuer_x, issuer_y);
}
