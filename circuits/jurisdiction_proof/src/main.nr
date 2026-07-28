// jurisdiction_proof
//
// Proves jurisdiction eligibility bound to a commitment a trusted issuer signed
// (secp256k1 ECDSA, in-circuit). Country codes are ISO 3166-1 numeric
// (US=840, IR=364, KP=408); unused slots in the list are 0.
//
// mode = 0 (denylist): proves "my country is NOT in the restricted list"
// mode = 1 (allowlist): proves "my country IS in the allowed list"

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

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
    mode: pub u64,
) {
    // Verify the commitment matches the private country_code + salt.
    assert(Poseidon2::hash([country_code as Field, salt], 2) == commitment);

    // Verify the issuer's ECDSA signature over the commitment.
    let z: [u8; 32] = commitment.to_be_bytes();
    assert(verify_signature(issuer_x, issuer_y, sig, z));

    // Mode must be 0 (denylist) or 1 (allowlist).
    assert((mode == 0) | (mode == 1));

    if mode == 0 {
        // Denylist: country must NOT match any entry.
        for i in 0..RESTRICTED_LEN {
            assert(country_code != restricted[i]);
        }
    } else {
        // Allowlist: country must match at least one entry.
        let mut found: bool = false;
        for i in 0..RESTRICTED_LEN {
            if country_code == restricted[i] {
                found = true;
            }
        }
        assert(found);
    }
}

#[test]
fn test_denylist_pass() {
    // Country 566 (Nigeria) is NOT in the restricted list.
    // We can't call main() directly without valid sig/commitment,
    // so test the denylist logic inline.
    let country_code: u64 = 566;
    let restricted: [u64; 8] = [840, 364, 408, 0, 0, 0, 0, 0];
    let mode: u64 = 0;
    assert((mode == 0) | (mode == 1));
    if mode == 0 {
        for i in 0..8 {
            assert(country_code != restricted[i]);
        }
    }
}

#[test]
fn test_allowlist_pass() {
    // Country 566 (Nigeria) IS in the allowed list.
    let country_code: u64 = 566;
    let restricted: [u64; 8] = [566, 276, 356, 0, 0, 0, 0, 0];
    let mode: u64 = 1;
    assert((mode == 0) | (mode == 1));
    if mode == 1 {
        let mut found: bool = false;
        for i in 0..8 {
            if country_code == restricted[i] {
                found = true;
            }
        }
        assert(found);
    }
}

#[test(should_fail)]
fn test_denylist_fail() {
    // Country 840 (US) IS in the restricted list — should fail in denylist mode.
    let country_code: u64 = 840;
    let restricted: [u64; 8] = [840, 364, 408, 0, 0, 0, 0, 0];
    let mode: u64 = 0;
    assert((mode == 0) | (mode == 1));
    if mode == 0 {
        for i in 0..8 {
            assert(country_code != restricted[i]);
        }
    }
}

#[test(should_fail)]
fn test_allowlist_fail() {
    // Country 840 (US) is NOT in the allowed list — should fail in allowlist mode.
    let country_code: u64 = 840;
    let restricted: [u64; 8] = [566, 276, 356, 0, 0, 0, 0, 0];
    let mode: u64 = 1;
    assert((mode == 0) | (mode == 1));
    if mode == 1 {
        let mut found: bool = false;
        for i in 0..8 {
            if country_code == restricted[i] {
                found = true;
            }
        }
        assert(found);
    }
}

#[test(should_fail)]
fn test_invalid_mode() {
    let mode: u64 = 2;
    assert((mode == 0) | (mode == 1));
}

