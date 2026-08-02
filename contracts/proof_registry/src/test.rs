#![cfg(test)]

extern crate std;

use super::*;
use credential_verifier::{CredentialVerifier, CredentialVerifierClient};
use issuer_registry::{IssuerRegistry, IssuerRegistryClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, Address, BytesN, Bytes, Env, IntoVal,
};

// Real UltraHonk artifacts (kyc_proof circuit, Noir beta.9 + bb 0.87.0), so
// submit_proof exercises genuine on-chain verification through the verifier.
const VK: &[u8] = include_bytes!("../../../fixtures/kyc/vk");
const PROOF: &[u8] = include_bytes!("../../../fixtures/kyc/proof");
const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/kyc/public_inputs");

// funds_proof fixture: proves balance >= 200_000 (threshold stored in public inputs).
const FUNDS_VK: &[u8] = include_bytes!("../../../fixtures/funds/vk");
const FUNDS_PROOF: &[u8] = include_bytes!("../../../fixtures/funds/proof");
const FUNDS_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/funds/public_inputs");

// age_proof fixture: proves age >= 18 years (threshold_years in public inputs).
const AGE_VK: &[u8] = include_bytes!("../../../fixtures/age/vk");
const AGE_PROOF: &[u8] = include_bytes!("../../../fixtures/age/proof");
const AGE_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/age/public_inputs");

fn pubkey_from(env: &Env, public_inputs: &[u8]) -> BytesN<64> {
    let mut arr = [0u8; 64];
    for i in 0..64usize {
        arr[i] = public_inputs[(1 + i) * 32 + 31];
    }
    BytesN::from_array(env, &arr)
}

fn demo_pubkey(env: &Env) -> BytesN<64> {
    pubkey_from(env, PUBLIC_INPUTS)
}

fn u8_slice_to_vec_u32(env: &Env, slice: &[u8]) -> Vec<u32> {
    let mut vec = Vec::new(env);
    for i in (0..slice.len()).step_by(4) {
        if i + 4 <= slice.len() {
            let mut chunk = [0u8; 4];
            chunk.copy_from_slice(&slice[i..i+4]);
            vec.push_back(u32::from_be_bytes(chunk));
        }
    }
    vec
}

fn get_test_wasm(env: &Env) -> Bytes {
    let paths = [
        "target/wasm32v1-none/release/proof_registry.wasm",
        "../../target/wasm32v1-none/release/proof_registry.wasm",
        "../target/wasm32v1-none/release/proof_registry.wasm",
    ];
    for path in paths.iter() {
        if let Ok(wasm) = std::fs::read(path) {
            return Bytes::from_slice(env, &wasm);
        }
    }
    panic!("Could not find target/wasm32v1-none/release/proof_registry.wasm. Please run 'cargo build --target wasm32v1-none --release' first.");
}

struct Harness {
    registry: ProofRegistryClient<'static>,
    registry_id: Address,
    issuer: Address,
    admin: Address,
}

fn deploy(env: &Env) -> Harness {
    let admin = Address::generate(env);

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(env, &ir_id);
    let issuer = Address::generate(env);
    ir.register_issuer(
        &issuer,
        &demo_pubkey(env),
        &vec![env, symbol_short!("kyc")],
    );

    let v_id = env.register(CredentialVerifier, (admin,));
    CredentialVerifierClient::new(env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(env, VK));

    let pr_id = env.register(ProofRegistry, (admin.clone(), v_id, ir_id));
    Harness {
        registry: ProofRegistryClient::new(env, &pr_id),
        registry_id: pr_id,
        issuer,
        admin,
    }
}

fn submit(env: &Env, h: &Harness, holder: &Address, expiry: u64) {
    h.registry.submit_proof(
        holder,
        &h.issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(env, PROOF),
        &Bytes::from_slice(env, PUBLIC_INPUTS),
        &expiry,
    );
}

#[test]
fn submit_then_verified() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);

    let (valid, _at, expiry) = h.registry.is_verified(&holder, &symbol_short!("kyc"), &None);
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
    assert!(h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);

    env.ledger().with_mut(|li| li.timestamp = 2000);
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
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
    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, VK));
    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);

    let holder = Address::generate(&env);
    let res = registry.try_submit_proof(
        &holder,
        &issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, PROOF),
        &Bytes::from_slice(&env, PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
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
        &Bytes::from_slice(&env, PROOF),
        &Bytes::from_slice(&env, PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
}

#[test]
fn rejects_invalid_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    let mut bad = PROOF.to_vec();
    bad[5000] ^= 0xff;
    let res = h.registry.try_submit_proof(
        &holder,
        &h.issuer,
        &symbol_short!("kyc"),
        &Bytes::from_slice(&env, &bad),
        &Bytes::from_slice(&env, PUBLIC_INPUTS),
        &1000,
    );
    assert!(res.is_err());
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
}

#[test]
fn unverified_holder_returns_false() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let stranger = Address::generate(&env);
    assert!(!h.registry.is_verified(&stranger, &symbol_short!("kyc"), &None).0);
}

#[test]
fn revoke_clears_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    h.registry.revoke_proof(&holder, &symbol_short!("kyc"));
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
}

#[test]
fn issuer_revoke_invalidates_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    assert!(h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
    assert!(h.registry.check_claim(&holder, &symbol_short!("kyc"), &None));

    h.registry.revoke(&h.issuer, &holder, &symbol_short!("kyc"));

    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
    assert!(!h.registry.check_claim(&holder, &symbol_short!("kyc"), &None));
    // Expiry data preserved for audit even though proof is no longer valid.
    let (_valid, _at, expiry) = h.registry.is_verified(&holder, &symbol_short!("kyc"));
    assert_eq!(expiry, 1000);
}

#[test]
fn issuer_revoke_rejects_wrong_issuer() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);
    let stranger = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    let res = h.registry.try_revoke(&stranger, &holder, &symbol_short!("kyc"));
    assert!(res.is_err());
    assert!(h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
}

#[test]
fn issuer_revoke_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    h.registry.revoke(&h.issuer, &holder, &symbol_short!("kyc"));

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                h.registry_id.clone(),
                (symbol_short!("revoked"),).into_val(&env),
                (
                    holder.clone(),
                    symbol_short!("kyc"),
                    h.issuer.clone(),
                    env.ledger().timestamp()
                )
                    .into_val(&env),
            ),
        ],
    );
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
        &pubkey_from(&env, FUNDS_PUBLIC_INPUTS),
        &vec![&env, symbol_short!("funds")],
    );
    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("funds"), &Bytes::from_slice(&env, FUNDS_VK));
    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    registry.submit_proof(
        &holder,
        &issuer,
        &symbol_short!("funds"),
        &Bytes::from_slice(&env, FUNDS_PROOF),
        &Bytes::from_slice(&env, FUNDS_PUBLIC_INPUTS),
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
        &pubkey_from(&env, AGE_PUBLIC_INPUTS),
        &vec![&env, symbol_short!("age")],
    );
    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("age"), &Bytes::from_slice(&env, AGE_VK));
    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
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

// -- claim_expiry tests -----------------------------------------------------

#[test]
fn claim_expiry_returns_expiry_for_valid_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 5000);
    assert_eq!(h.registry.claim_expiry(&holder, &symbol_short!("kyc")), 5000);
}

#[test]
fn claim_expiry_returns_zero_for_nonexistent_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let stranger = Address::generate(&env);

    assert_eq!(h.registry.claim_expiry(&stranger, &symbol_short!("kyc")), 0);
}

#[test]
fn claim_expiry_returns_expiry_even_after_expired() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    submit(&env, &h, &holder, 1000);
    assert_eq!(h.registry.claim_expiry(&holder, &symbol_short!("kyc")), 1000);

    env.ledger().with_mut(|li| li.timestamp = 2000);
    assert_eq!(h.registry.claim_expiry(&holder, &symbol_short!("kyc")), 1000);
    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc"), &None).0);
}