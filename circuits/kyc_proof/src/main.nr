// kyc_proof
//
// Proves the holder knows the secret behind a KYC credential AND that a trusted
// issuer signed the commitment to it (secp256k1 ECDSA, verified in-circuit).
// Public inputs, in order: commitment, issuer_x, issuer_y, so the contract can
// bind the public key to the registered issuer. The signature and secret stay
// private.

use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // private: never leaves the holder's device, never appears in public inputs
    secret: Field,
    salt: Field,
    sig: [u8; 64],
    // public: the contract sees these and binds them to on-chain state
    commitment: pub Field,
    issuer_x: pub [u8; 32],
    issuer_y: pub [u8; 32],
) {
    // Commitment binding. `commitment` is public, `secret` and `salt` are not.
    // This constraint is what forces the private witness to be the *same*
    // credential the issuer signed below: the only way to satisfy it is to know
    // a (secret, salt) pair that Poseidon2-hashes to the public commitment.
    // Remove it and the two halves of the proof come apart - a holder could
    // present a commitment a real issuer signed while knowing nothing about the
    // credential behind it, i.e. prove possession of someone else's credential.
    // `salt` also makes the commitment hiding: without it the commitment is a
    // deterministic hash of a low-entropy value and anyone could recover the
    // credential from the public input by brute force.
    assert(Poseidon2::hash([secret, salt], 2) == commitment);

    // `verify_signature` takes a 32-byte message *digest*, not a message. We
    // pass the commitment's big-endian bytes directly, so the digest IS the
    // commitment. That is why the issuer must sign with `prehash: false`
    // (see frontend/packages/issuer): signing with a pre-hash would make the
    // issuer's digest sha256(commitment) instead of commitment, and this
    // assert would reject every credential it ever issued. The commitment is
    // already a Poseidon2 output, so using it as the digest is sound - it is a
    // collision-resistant hash of the credential, not raw attacker input.
    let z: [u8; 32] = commitment.to_be_bytes();

    // Issuer authentication, in-circuit. Two reasons this cannot move on-chain:
    //   1. Soundness - the verifier only ever sees the public inputs. If the
    //      signature were merely asserted rather than checked here, a holder
    //      could pick any commitment, sign it with their own key, and mint a
    //      credential the issuer never approved. Checking it here means a valid
    //      proof *is* evidence that the holder of (issuer_x, issuer_y) signed
    //      this exact commitment.
    //   2. Privacy - `sig` is private. A signature is a stable, unique
    //      identifier for a credential; publishing it on-chain would let anyone
    //      link every proof made from the same credential back to one holder,
    //      which defeats the point of the ZK proof.
    // The issuer key is public precisely so the contract can check it against
    // IssuerRegistry. Without that on-chain check, this assert proves only
    // "*someone* signed it" - the registry lookup is what makes it "a *trusted*
    // issuer signed it". Both halves are required.
    assert(verify_signature(issuer_x, issuer_y, sig, z));
}
