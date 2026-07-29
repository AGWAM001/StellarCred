// income_proof
//
// Proves "my income is at least `threshold`" without revealing the figure,
// bound to a commitment a trusted issuer signed (secp256k1 ECDSA, in-circuit).

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    // `income` is u64, not Field, and that is a security choice: `>=` on Field
    // has no well-defined ordering over BN254: a prover could pick a value that
    // wraps the modulus and compares however they need it to. u64 gives a
    // genuine bounded integer comparison, and the width is range-checked by the
    // proving system when the witness is assigned.
    income: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    threshold: pub u64,
) {
    // Commitment binding. `commitment` is public, `income` and `salt` are not.
    // This is the sole link between the private income and the credential the
    // issuer signed below. Remove it and the prover supplies any income they
    // like alongside a genuine signed commitment, and the threshold check
    // becomes a statement about a number no issuer ever attested.
    // `salt` keeps the commitment hiding: incomes cluster on round numbers, so
    // an unsalted commitment would be recoverable by hashing candidate values
    // until one matched the public input.
    // The `as Field` widening cast is lossless - u64 fits in BN254 with room to
    // spare - so it cannot alias two different incomes onto one commitment.
    assert(Poseidon2::hash([income as Field, salt], 2) == commitment);

    // `verify_signature` consumes a 32-byte message *digest*, so the commitment
    // bytes are the digest. Hence `prehash: false` on the issuer side: a signer
    // that pre-hashes would sign sha256(commitment), and this check would
    // reject every credential it issued.
    let z: [u8; 32] = commitment.to_be_bytes();

    // Issuer authentication, in-circuit. Checked here rather than on-chain
    // because the verifier only sees public inputs - a holder could otherwise
    // commit to an income of their choosing and sign it with their own key.
    // Verifying here makes the proof itself evidence that (issuer_x, issuer_y)
    // signed this exact commitment; the contract's IssuerRegistry lookup on
    // that public key is what upgrades "someone signed" to "a trusted issuer
    // signed". Neither check is sufficient alone.
    // `sig` stays private because a signature uniquely identifies a credential;
    // publishing it would make every proof from that credential linkable.
    assert(verify_signature(issuer_x, issuer_y, sig, z));

    // The claim itself, proved rather than asserted. `threshold` is a public
    // input the prover chooses; on its own it is an unbacked assertion. This
    // constraint is what binds it to the signed private income. It cannot be
    // enforced on-chain because the contract never sees `income` - without it
    // a holder submits any threshold they want and the proof still verifies.
    // The contract remains responsible for checking that the `threshold` in the
    // public inputs is the one its policy actually requires.
    assert(income >= threshold);
}
