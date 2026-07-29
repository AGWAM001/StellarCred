// jurisdiction_proof
//
// Proves "my country of residence is NOT in the restricted list" without
// revealing which country it is, bound to a commitment a trusted issuer signed
// (secp256k1 ECDSA, in-circuit). Country codes are ISO 3166-1 numeric
// (US=840, IR=364, KP=408); unused slots in the restricted list are 0.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

// Fixed at compile time, not passed in. A ZK circuit is a fixed set of
// constraints, so the loop below unrolls into exactly RESTRICTED_LEN
// comparisons that every proof must satisfy. If the list length were a runtime
// value the prover controlled, they could shorten it and skip the entries that
// would have caught them.
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
    // Commitment binding. `commitment` is public, `country_code` and `salt` are
    // not. This is the only constraint forcing the private country code to be
    // the one inside the credential the issuer signed below - without it a
    // holder could present a genuine signed commitment and separately claim any
    // country they wanted, which is exactly the sanctions bypass this circuit
    // exists to prevent.
    // `salt` is essential here, more so than in the threshold circuits: there
    // are only ~250 ISO 3166-1 numeric codes, so an unsalted commitment could
    // be reversed in a few hundred hashes and the holder's country read
    // straight off the public inputs.
    assert(Poseidon2::hash([country_code as Field, salt], 2) == commitment);

    // `verify_signature` takes a 32-byte message *digest*, and we pass the
    // commitment bytes, so the digest IS the commitment. Hence `prehash: false`
    // on the issuer's signing path - a pre-hashing signer would sign
    // sha256(commitment), and this check would reject its credentials.
    let z: [u8; 32] = commitment.to_be_bytes();

    // Issuer authentication, in-circuit. The verifier sees only public inputs,
    // so if this were left to the chain a holder could commit to a permitted
    // country, sign it with their own key, and clear the exclusion check below
    // with a credential no issuer ever attested. Checking here makes the proof
    // itself evidence that (issuer_x, issuer_y) signed this exact commitment;
    // the contract's IssuerRegistry lookup on that key is what makes the signer
    // *trusted*. Neither check stands alone.
    // `sig` stays private because a signature uniquely identifies a credential
    // and would make a holder's proofs linkable across protocols.
    assert(verify_signature(issuer_x, issuer_y, sig, z));

    // Non-membership, proved rather than asserted. `restricted` is public and
    // `country_code` is not, so the contract has no way to run this check
    // itself - it cannot see the country. Every slot must be compared: a single
    // skipped entry is a jurisdiction that passes sanctions screening.
    // Two consequences of `restricted` being a prover-supplied public input:
    //   - The contract MUST check the list against its own policy. A prover who
    //     submits an all-zero list produces a perfectly valid proof of nothing.
    //   - Zero padding does double duty. Padding slots are 0, so the loop also
    //     enforces `country_code != 0`, rejecting a credential with an empty or
    //     unset country. This guard is incidental rather than designed: it
    //     holds only while at least one slot is still padding, and it vanishes
    //     the moment all RESTRICTED_LEN slots carry real codes.
    //     Whoever fills the last slot must add an explicit
    //     `assert(country_code != 0)` here in the same change. It has to go
    //     here and nowhere else - `country_code` is a private input that never
    //     reaches the verifier, so the contract cannot make up for its loss.
    for i in 0..RESTRICTED_LEN {
        assert(country_code != restricted[i]);
    }
}
