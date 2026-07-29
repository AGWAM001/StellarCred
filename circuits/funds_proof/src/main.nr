// funds_proof
//
// Proves "my account balance is at least `threshold`" without revealing the
// figure, bound to a commitment a trusted issuer signed (secp256k1 ECDSA,
// in-circuit). The balance is an integer (e.g. USD cents or whole dollars).

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private
    // `balance` is u64 rather than Field on purpose: `>=` on Field has no
    // meaningful ordering over BN254 and a prover could choose a value that
    // wraps the modulus to compare however they needed. u64 is a bounded
    // integer whose width the proving system range-checks, so the comparison
    // below means what it reads as. It also caps the balance at ~1.8e19, which
    // is comfortably above any real figure in cents.
    balance: u64,
    salt: Field,
    sig: [u8; 64],
    // public
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
    threshold: pub u64,
) {
    // Commitment binding. `commitment` is public, `balance` and `salt` are not.
    // This constraint is the only thing forcing the private balance to be the
    // one inside the credential the issuer signed below. Remove it and the two
    // halves of the proof decouple: a holder presents a genuine signed
    // commitment while proving a threshold about an unrelated balance.
    // `salt` makes the commitment hiding - balances are guessable enough that
    // an unsalted commitment could be reversed by search over the public input.
    // The `as Field` cast is a lossless widening, so it cannot map two distinct
    // balances to the same commitment.
    assert(Poseidon2::hash([balance as Field, salt], 2) == commitment);

    // `verify_signature` takes a 32-byte message *digest*, and we pass the
    // commitment bytes, so the digest IS the commitment. That is the reason the
    // issuer signs with `prehash: false`: a pre-hashing signer would sign
    // sha256(commitment) and this assert would reject its credentials outright.
    let z: [u8; 32] = commitment.to_be_bytes();

    // Issuer authentication, in-circuit. On-chain is too late - the verifier
    // sees only public inputs, so without this a holder could commit to any
    // balance and sign it with their own key. Checking here makes the proof
    // itself evidence that (issuer_x, issuer_y) signed this exact commitment,
    // and the contract's IssuerRegistry lookup on that public key turns
    // "someone signed" into "a trusted issuer signed". Both are required.
    // `sig` is private because a signature is a unique per-credential
    // identifier; revealing it would let observers link a holder's proofs.
    assert(verify_signature(issuer_x, issuer_y, sig, z));

    // The claim itself, proved rather than asserted. `threshold` is a public
    // input chosen by the prover and carries no weight by itself; this
    // constraint is what ties it to the signed private balance. It cannot move
    // on-chain because the contract never sees `balance` - drop it and a holder
    // submits whatever threshold they want and still verifies.
    // The contract must still confirm the `threshold` in the public inputs is
    // the figure its policy demands.
    assert(balance >= threshold);
}
