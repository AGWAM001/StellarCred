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
    // Commitment binding. `commitment` is public, `date_of_birth` and `salt`
    // are not. This is the only constraint tying the private date of birth to
    // the credential the issuer signed below. Remove it and the prover can feed
    // in any date of birth they like while presenting a genuine issuer-signed
    // commitment - the age check further down would then be about a number the
    // issuer never saw.
    // `salt` is what makes the commitment hiding. A date of birth has only a
    // few tens of thousands of plausible values, so an unsalted commitment
    // could be reversed by exhaustive search over the public input alone.
    assert(Poseidon2::hash([date_of_birth as Field, salt], 2) == commitment);

    // `verify_signature` expects a 32-byte message *digest*, so we hand it the
    // commitment's bytes directly: the digest IS the commitment. This is why
    // the issuer signs with `prehash: false` - a pre-hashing signer would
    // produce a signature over sha256(commitment) and every credential it
    // issued would fail this check.
    let z: [u8; 32] = commitment.to_be_bytes();

    // Issuer authentication, in-circuit. If this check lived outside the
    // circuit, the proof would attest only "I know a preimage of some
    // commitment" - the holder could invent a commitment over a date of birth
    // of their choosing and sign it themselves. Verifying here makes the proof
    // itself evidence that (issuer_x, issuer_y) signed this exact commitment;
    // the contract then checks that key against IssuerRegistry to establish
    // that the signer is trusted. Both halves are needed: this assert alone
    // proves only that *someone* signed.
    // Keeping `sig` private also matters: a signature uniquely identifies one
    // credential, so revealing it would let observers link every age proof a
    // holder ever makes back to a single credential.
    assert(verify_signature(issuer_x, issuer_y, sig, z));

    // Underflow guard. To be precise about what this does and does not buy:
    // Noir does NOT wrap on unsigned underflow. It range-constrains the result,
    // so with a date of birth after `current_date` the subtraction below fails
    // during witness generation and no proof is produced at all (verified on
    // the pinned nargo 1.0.0-beta.9: `a - b` on u64 with a < b aborts with
    // "Failed assertion"). There is no enormous `age_years` for an attacker to
    // reach, and removing this line does not open a soundness hole.
    // It stays for two reasons: it puts the precondition in the source instead
    // of leaving it implicit in backend arithmetic semantics, and it fails
    // naming the actual problem - a future-dated credential - rather than as an
    // opaque arithmetic failure inside the expression below.
    assert(current_date >= date_of_birth);

    // Age derivation. Integer division truncates, and 365 ignores leap days, so
    // `age_years` runs slightly ahead of true age (~1 day per 4 years elapsed).
    // The bias is in the holder's favour and bounded by a few weeks at adult
    // ages; anything needing exact birthday semantics must not use this circuit.
    let age_years = (current_date - date_of_birth) / 365;

    // The claim itself, proved rather than asserted. `threshold_years` is a
    // public input, i.e. a number the prover supplies alongside the proof - it
    // carries no weight on its own. This constraint is the only thing that ties
    // that public claim to the signed private date of birth. Move it on-chain
    // and there is nothing left to check against: the contract cannot see
    // `date_of_birth`, so a holder could submit any `threshold_years` they
    // wanted and the proof would still verify.
    // Note both `current_date` and `threshold_years` are public inputs under
    // the prover's control. The circuit proves the relation between them; the
    // contract is responsible for rejecting a stale `current_date` or a
    // `threshold_years` that does not match the policy being enforced.
    assert(age_years >= threshold_years);
}
