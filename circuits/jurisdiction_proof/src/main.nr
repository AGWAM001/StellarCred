// jurisdiction_proof
//
// Proves "my country of residence is NOT in the restricted list" without
// revealing which country it is, bound to a commitment a trusted issuer signed
// (secp256k1 ECDSA, in-circuit). Country codes are ISO 3166-1 numeric
// (US=840, IR=364, KP=408); unused slots in the restricted list are 0.

use dep::credential_lib;

global RESTRICTED_LEN: u32 = 8;

fn main(
    // private
    country_code: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    restricted: pub [u64; RESTRICTED_LEN],
) {
    credential_lib::assert_committed_and_signed(country_code as Field, salt, sig, commitment, issuer_x, issuer_y);
    for i in 0..RESTRICTED_LEN {
        assert(country_code != restricted[i]);
    }
}
