use soroban_sdk::{Bytes, Env};
use test_support::{
    fixture, setup_verifier_under, AGE, AGGREGATE, EMPLOYMENT, FUNDS, INCOME, JURISDICTION, KYC,
    RANGE, SET_MEMBERSHIP,
};

// Every fixture below is a real UltraHonk artifact from `fixtures/negative/`
// (see `fixtures/negative/README.md` and `circuits/scripts/gen_negative_fixtures.js`):
// a valid proof paired with public inputs mutated away from it. The proof no
// longer binds to those inputs, so `verify_proof` must return `false`.
//
// The cases are declared one per credential type instead of in a loop because
// `fixture!` wraps `include_bytes!`, which needs a path literal. Reading the
// files at loop time would need `std::fs`, which this crate does not link
// (`#![no_std]`).

// Registers a negative fixture's VK under `$circuit`'s credential type and
// asserts its proof/public-input pair is rejected.
macro_rules! rejects_negative_fixture {
    ($test_name:ident, $circuit:ident, $case:literal) => {
        #[test]
        fn $test_name() {
            let env = Env::default();
            env.mock_all_auths();
            let credential_type = $circuit.ct(&env);
            let verifier = setup_verifier_under(&env, &credential_type, 1, fixture!($case, "vk"));

            assert!(
                !verifier.verify_proof(
                    &credential_type,
                    &Bytes::from_slice(&env, fixture!($case, "proof")),
                    &Bytes::from_slice(&env, fixture!($case, "public_inputs")),
                    &None,
                ),
                "negative fixture {} must be rejected",
                $case
            );
        }
    };
}

// ── KYC ─────────────────────────────────────────────────────────────────────

// Issuer key fields zeroed in the public inputs: the proof was made by a
// different issuer, so it does not verify against them.
rejects_negative_fixture!(
    rejects_proof_with_wrong_issuer_pubkey,
    KYC,
    "negative/kyc_wrong_issuer"
);

// Public inputs truncated by one field, so the count no longer matches the VK.
rejects_negative_fixture!(
    rejects_proof_with_truncated_public_inputs,
    KYC,
    "negative/kyc_truncated_inputs"
);

// An age proof and age public inputs checked against the KYC VK.
rejects_negative_fixture!(
    rejects_proof_from_wrong_circuit_type,
    KYC,
    "negative/kyc_wrong_circuit"
);

// ── Threshold circuits ──────────────────────────────────────────────────────

rejects_negative_fixture!(
    rejects_age_below_threshold,
    AGE,
    "negative/age_unmet_threshold"
);
rejects_negative_fixture!(
    rejects_income_below_threshold,
    INCOME,
    "negative/income_unmet_threshold"
);
rejects_negative_fixture!(
    rejects_funds_below_threshold,
    FUNDS,
    "negative/funds_unmet_threshold"
);
rejects_negative_fixture!(
    rejects_range_below_threshold,
    RANGE,
    "negative/range_unmet_threshold"
);

// ── Set and list circuits ───────────────────────────────────────────────────

rejects_negative_fixture!(
    rejects_denylisted_jurisdiction,
    JURISDICTION,
    "negative/jurisdiction_denylisted"
);
rejects_negative_fixture!(
    rejects_wrong_merkle_root,
    SET_MEMBERSHIP,
    "negative/set_membership_wrong_root"
);

// ── Aggregate and single-claim circuits ─────────────────────────────────────

rejects_negative_fixture!(
    rejects_malformed_aggregate_layout,
    AGGREGATE,
    "negative/aggregate_malformed_layout"
);
rejects_negative_fixture!(
    rejects_tampered_employment_proof,
    EMPLOYMENT,
    "negative/employment_invalid_proof"
);
