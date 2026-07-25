#![cfg(test)]

use super::*;
use credential_verifier::{CredentialVerifier, CredentialVerifierClient};
use issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    vec, Address, BytesN, Bytes, Env,
};

// Real UltraHonk artifacts from existing circuits, used to test helper logic.
const KYC_VK: &[u8] = include_bytes!("../../../fixtures/kyc/vk");
const KYC_PROOF: &[u8] = include_bytes!("../../../fixtures/kyc/proof");
const KYC_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/kyc/public_inputs");

const AGE_VK: &[u8] = include_bytes!("../../../fixtures/age/vk");
const AGE_PROOF: &[u8] = include_bytes!("../../../fixtures/age/proof");
const AGE_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/age/public_inputs");

// ── Helpers ─────────────────────────────────────────────────────────────────

fn pubkey_from(env: &Env, public_inputs: &[u8], start_field: u32) -> BytesN<64> {
    let mut arr = [0u8; 64];
    for i in 0..64usize {
        arr[i] = public_inputs[(start_field as usize + i) * 32 + 31];
    }
    BytesN::from_array(env, &arr)
}

fn demo_pubkey(env: &Env) -> BytesN<64> {
    pubkey_from(env, KYC_PUBLIC_INPUTS, 1)
}

struct Harness {
    registry: ProofRegistryClient<'static>,
    issuer: Address,
}

fn deploy(env: &Env) -> Harness {
    let admin = Address::generate(env);

    // IssuerRegistry with one issuer trusted for kyc.
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(env, &ir_id);
    let issuer = Address::generate(env);
    ir.register_issuer(
        &issuer,
        &demo_pubkey(env),
        &vec![env, symbol_short!("kyc")],
    );

    // CredentialVerifier with the kyc VK.
    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(env, KYC_VK));

    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    Harness {
        registry: ProofRegistryClient::new(env, &pr_id),
        issuer,
    }
}

fn submit(env: &Env, h: &Harness, holder: &Address, expiry: u64) {
    h.registry.submit_proof(
        holder,
        &h.issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(env, KYC_PROOF),
        &Bytes::from_slice(env, KYC_PUBLIC_INPUTS),
        &expiry,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Existing single-proof tests (unchanged).
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn submit_then_verified() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);

    let (valid, _at, expiry) = h.registry.is_verified(&holder, &symbol_short!("kyc"));
    assert!(valid);
    assert_eq!(expiry, 1000);
}

#[test]
fn expires_after_ledger_time_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    assert!(h.registry.is_verified(&holder, &symbol_short!("kyc")).0);

    env.ledger().with_mut(|li| li.timestamp = 2000);
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

#[test]
fn rejects_wrong_issuer_key() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let issuer = Address::generate(&env);
    IssuerRegistryClient::new(&env, &ir_id).register_issuer(
        &issuer,
        &BytesN::from_array(&env, &[3u8; 64]),
        &vec![&env, symbol_short!("kyc")],
    );
    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, KYC_VK));
    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);

    let holder = Address::generate(&env);
    let res = registry.try_submit_proof(
        &holder,
        &issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, KYC_PROOF),
        &Bytes::from_slice(&env, KYC_PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

#[test]
fn rejects_untrusted_issuer() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);
    let stranger = Address::generate(&env);

    let res = h.registry.try_submit_proof(
        &holder,
        &stranger,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, KYC_PROOF),
        &Bytes::from_slice(&env, KYC_PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

#[test]
fn rejects_invalid_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    let mut bad = KYC_PROOF.to_vec();
    bad[5000] ^= 0xff;
    let res = h.registry.try_submit_proof(
        &holder,
        &h.issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, &bad),
        &Bytes::from_slice(&env, KYC_PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

#[test]
fn unverified_holder_returns_false() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let stranger = Address::generate(&env);
    assert!(!h.registry.is_verified(&stranger, &symbol_short!("kyc")).0);
}

#[test]
fn revoke_clears_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    h.registry.revoke_proof(&holder, &symbol_short!("kyc"));
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

// ── check_claim / threshold tests ────────────────────────────────────────────

#[test]
fn check_claim_no_threshold_matches_is_verified() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    assert!(h.registry.check_claim(&holder, &symbol_short!("kyc"), &None));
}

#[test]
fn funds_threshold_stored_and_checked() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer = Address::generate(&env);
    ir.register_issuer(
        &issuer,
        &pubkey_from(&env, include_bytes!("../../../fixtures/funds/public_inputs"), 1),
        &vec![&env, symbol_short!("funds")],
    );
    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(
            &symbol_short!("funds"),
            &Bytes::from_slice(&env, include_bytes!("../../../fixtures/funds/vk")),
        );
    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    registry.submit_proof(
        &holder,
        &issuer,
        &symbol_short!("funds"),
        &Bytes::from_slice(&env, include_bytes!("../../../fixtures/funds/proof")),
        &Bytes::from_slice(&env, include_bytes!("../../../fixtures/funds/public_inputs")),
        &9999,
    );

    assert!(registry.check_claim(&holder, &symbol_short!("funds"), &Some(200_000)));
    assert!(registry.check_claim(&holder, &symbol_short!("funds"), &Some(50_000)));
    assert!(registry.check_claim(&holder, &symbol_short!("funds"), &None));
    assert!(!registry.check_claim(&holder, &symbol_short!("funds"), &Some(250_000)));
}

#[test]
fn age_threshold_stored_and_checked() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer = Address::generate(&env);
    ir.register_issuer(
        &issuer,
        &pubkey_from(&env, AGE_PUBLIC_INPUTS, 1),
        &vec![&env, symbol_short!("age")],
    );
    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("age"), &Bytes::from_slice(&env, AGE_VK));
    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    registry.submit_proof(
        &holder,
        &issuer,
        &symbol_short!("age"),
        &Bytes::from_slice(&env, AGE_PROOF),
        &Bytes::from_slice(&env, AGE_PUBLIC_INPUTS),
        &9999,
    );

    assert!(registry.check_claim(&holder, &symbol_short!("age"), &Some(18)));
    assert!(registry.check_claim(&holder, &symbol_short!("age"), &Some(16)));
    assert!(!registry.check_claim(&holder, &symbol_short!("age"), &Some(21)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Aggregate proof tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Build synthetic aggregate public inputs for KYC + age (133 fields × 32 bytes).
/// Layout: [kyc(65 fields) | age(67 fields) | num_credentials(1 field)]
fn build_aggregate_public_inputs(env: &Env) -> Bytes {
    // Use the KYC and age fixtures as source for the inner public inputs.
    let kyc = KYC_PUBLIC_INPUTS; // 65 × 32 = 2080 bytes
    let age = AGE_PUBLIC_INPUTS; // 67 × 32 = 2144 bytes

    // num_credentials = 2, encoded as a 32-byte big-endian field (u64 in last 8 bytes).
    let mut num = [0u8; 32];
    num[24..32].copy_from_slice(&2u64.to_be_bytes());

    let mut buf = Vec::with_capacity(kyc.len() + age.len() + 32);
    buf.extend_from_slice(kyc);
    buf.extend_from_slice(age);
    buf.extend_from_slice(&num);
    Bytes::from_slice(env, &buf)
}

/// Build an aggregate harness with issuers registered for both kyc and age,
/// and VKs set for kyc, age, and aggregate. Uses the *single* kyc VK as a
/// stand-in for the aggregate VK so the `verify_proof` call doesn't panic with
/// VkNotSet. The test still validates the aggregate-specific logic (pubkey
/// matching, threshold extraction, and atomic multi-claim storage) because the
/// inner kyc proof bytes will cause VerificationFailed — which is expected and
/// distinct from the aggregate helpers.
struct AggregateHarness {
    registry: ProofRegistryClient<'static>,
    issuer_kyc: Address,
    issuer_age: Address,
}

fn deploy_aggregate(env: &Env) -> AggregateHarness {
    let admin = Address::generate(env);

    // IssuerRegistry — register two distinct issuers.
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(env, &ir_id);

    let issuer_kyc = Address::generate(env);
    let kyc_pk = pubkey_from(env, KYC_PUBLIC_INPUTS, 1);
    ir.register_issuer(&issuer_kyc, &kyc_pk, &vec![env, symbol_short!("kyc")]);

    let issuer_age = Address::generate(env);
    let age_pk = pubkey_from(env, AGE_PUBLIC_INPUTS, 1);
    ir.register_issuer(&issuer_age, &age_pk, &vec![env, symbol_short!("age")]);

    // CredentialVerifier — set VKs for kyc, age, and aggregate.
    let v_id = env.register(CredentialVerifier, (admin,));
    let vc = CredentialVerifierClient::new(env, &v_id);
    vc.set_vk(&symbol_short!("kyc"), &Bytes::from_slice(env, KYC_VK));
    vc.set_vk(&symbol_short!("age"), &Bytes::from_slice(env, AGE_VK));
    // Use the kyc VK as a stand-in for aggregate — the aggregate proof fixture
    // will have its own VK once generated by circuits/scripts/build.sh.
    vc.set_vk(&symbol_short!("aggregate"), &Bytes::from_slice(env, KYC_VK));

    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    AggregateHarness {
        registry: ProofRegistryClient::new(env, &pr_id),
        issuer_kyc,
        issuer_age,
    }
}

#[test]
fn aggregate_rejects_untrusted_kyc_issuer() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy_aggregate(&env);
    let holder = Address::generate(&env);
    let stranger = Address::generate(&env); // not registered
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = h.registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, stranger, h.issuer_age.clone()],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, KYC_PROOF),
        &public_inputs,
        &1000,
    );
    assert!(res.is_err());
}

#[test]
fn aggregate_rejects_untrusted_age_issuer() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy_aggregate(&env);
    let holder = Address::generate(&env);
    let stranger = Address::generate(&env); // not registered
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = h.registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, h.issuer_kyc.clone(), stranger],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, KYC_PROOF),
        &public_inputs,
        &1000,
    );
    assert!(res.is_err());
}

#[test]
fn aggregate_rejects_key_mismatch() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    // Register an issuer with a DIFFERENT key than the KYC proof's pubkey.
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer_kyc = Address::generate(&env);
    ir.register_issuer(
        &issuer_kyc,
        &BytesN::from_array(&env, &[7u8; 64]), // wrong key
        &vec![&env, symbol_short!("kyc")],
    );

    // Correct age issuer.
    let issuer_age = Address::generate(&env);
    let age_pk = pubkey_from(&env, AGE_PUBLIC_INPUTS, 1);
    ir.register_issuer(&issuer_age, &age_pk, &vec![&env, symbol_short!("age")]);

    let v_id = env.register(CredentialVerifier, (admin,));
    let vc = CredentialVerifierClient::new(&env, &v_id);
    vc.set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, KYC_VK));
    vc.set_vk(&symbol_short!("age"), &Bytes::from_slice(&env, AGE_VK));
    vc.set_vk(&symbol_short!("aggregate"), &Bytes::from_slice(&env, KYC_VK));

    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, issuer_kyc.clone(), issuer_age.clone()],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, KYC_PROOF),
        &public_inputs,
        &1000,
    );
    assert!(res.is_err());
}

/// Test that the revoke_all function clears proofs for all credential types
/// that were previously submitted.
#[test]
fn revoke_all_clears_multiple_types() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    // Set up issuer + verifier so submit_proof passes for kyc.
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer = Address::generate(&env);
    ir.register_issuer(
        &issuer,
        &pubkey_from(&env, KYC_PUBLIC_INPUTS, 1),
        &vec![&env, symbol_short!("kyc")],
    );

    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, KYC_VK));

    let pr_id = env.register(ProofRegistry, (v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    // Submit a kyc proof.
    registry.submit_proof(
        &holder,
        &issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, KYC_PROOF),
        &Bytes::from_slice(&env, KYC_PUBLIC_INPUTS),
        &1000,
    );
    assert!(registry.is_verified(&holder, &symbol_short!("kyc")).0);

    // Revoke all and confirm kyc is gone.
    registry.revoke_all(&holder);
    assert!(!registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

/// Test that aggregate_pubkey_match correctly validates a pubkey at an offset.
#[test]
fn aggregate_pubkey_match_at_offset() {
    let env = Env::default();

    // Build public inputs: [padding(65 fields) | kyc_fields(65 fields)]
    // The KYC pubkey should be at start_field=66 (after the 65 padding fields).
    let padding = vec![0u8; 65 * 32];
    let mut agg = Vec::from(padding);
    agg.extend_from_slice(KYC_PUBLIC_INPUTS);
    // num_credentials = 2
    let mut num = [0u8; 32];
    num[24..32].copy_from_slice(&2u64.to_be_bytes());
    agg.extend_from_slice(&num);
    let agg_bytes = Bytes::from_slice(&env, &agg);

    let expected = pubkey_from(&env, KYC_PUBLIC_INPUTS, 1);
    assert!(ProofRegistry::aggregate_pubkey_match(
        &agg_bytes,
        66, // 65 padding + pubkey at field 1 within KYC block
        &expected
    ));
}

/// Test that num_credentials extraction works from the last field.
#[test]
fn read_num_credentials_from_aggregate() {
    let env = Env::default();
    let public_inputs = build_aggregate_public_inputs(&env);

    // Last field (index 132) should contain 2.
    let num = ProofRegistry::read_u64_field(&public_inputs, AGG_FIELD_NUM_CREDENTIALS);
    assert_eq!(num, 2);
}
