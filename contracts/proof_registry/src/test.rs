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

// Real UltraHonk artifacts from existing circuits.
const VK: &[u8] = include_bytes!("../../../fixtures/kyc/vk");
const PROOF: &[u8] = include_bytes!("../../../fixtures/kyc/proof");
const PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/kyc/public_inputs");

const FUNDS_VK: &[u8] = include_bytes!("../../../fixtures/funds/vk");
const FUNDS_PROOF: &[u8] = include_bytes!("../../../fixtures/funds/proof");
const FUNDS_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/funds/public_inputs");

const AGE_VK: &[u8] = include_bytes!("../../../fixtures/age/vk");
const AGE_PROOF: &[u8] = include_bytes!("../../../fixtures/age/proof");
const AGE_PUBLIC_INPUTS: &[u8] = include_bytes!("../../../fixtures/age/public_inputs");

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the issuer secp256k1 key from public inputs at a given field offset.
fn pubkey_from_offset(env: &Env, public_inputs: &[u8], start_field: u32) -> BytesN<64> {
    let mut arr = [0u8; 64];
    for i in 0..64usize {
        arr[i] = public_inputs[(start_field as usize + i) * 32 + 31];
    }
    BytesN::from_array(env, &arr)
}

/// Extract the issuer key from the standard single-proof layout (fields 1..65).
fn pubkey_from(env: &Env, public_inputs: &[u8]) -> BytesN<64> {
    pubkey_from_offset(env, public_inputs, 1)
}

fn demo_pubkey(env: &Env) -> BytesN<64> {
    pubkey_from(env, PUBLIC_INPUTS)
}

fn u8_slice_to_vec_u32(env: &Env, slice: &[u8]) -> Vec<u32> {
    let mut vec = Vec::new(env);
    for i in (0..slice.len()).step_by(4) {
        if i + 4 <= slice.len() {
            let mut chunk = [0u8; 4];
            chunk.copy_from_slice(&slice[i..i + 4]);
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

    let v_id = env.register(CredentialVerifier, (admin.clone(),));
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

// ═══════════════════════════════════════════════════════════════════════════════
// Single-proof tests
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
        &Bytes::from_slice(&env, PROOF),
        &Bytes::from_slice(&env, PUBLIC_INPUTS),
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

// ── submit_proofs_batch tests ─────────────────────────────────────────────────

fn kyc_submission(env: &Env, issuer: &Address, expiry: u64) -> ProofSubmission {
    ProofSubmission {
        credential_type: symbol_short!("kyc"),
        proof: Bytes::from_slice(env, PROOF),
        public_inputs: u8_slice_to_vec_u32(env, PUBLIC_INPUTS),
        issuer_id: issuer.clone(),
        expiry,
    }
}

struct MultiHarness {
    registry: ProofRegistryClient<'static>,
    kyc_issuer: Address,
    funds_issuer: Address,
    age_issuer: Address,
    admin: Address,
}

fn deploy_multi(env: &Env) -> MultiHarness {
    let admin = Address::generate(env);
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(env, &ir_id);

    let kyc_issuer = Address::generate(env);
    ir.register_issuer(
        &kyc_issuer,
        &pubkey_from(env, PUBLIC_INPUTS),
        &vec![env, symbol_short!("kyc")],
    );

    let funds_issuer = Address::generate(env);
    ir.register_issuer(
        &funds_issuer,
        &pubkey_from(env, FUNDS_PUBLIC_INPUTS),
        &vec![env, symbol_short!("funds")],
    );

    let age_issuer = Address::generate(env);
    ir.register_issuer(
        &age_issuer,
        &pubkey_from(env, AGE_PUBLIC_INPUTS),
        &vec![env, symbol_short!("age")],
    );

    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    let vc = CredentialVerifierClient::new(env, &v_id);
    vc.set_vk(&symbol_short!("kyc"), &Bytes::from_slice(env, VK));
    vc.set_vk(&symbol_short!("funds"), &Bytes::from_slice(env, FUNDS_VK));
    vc.set_vk(&symbol_short!("age"), &Bytes::from_slice(env, AGE_VK));

    let pr_id = env.register(ProofRegistry, (admin.clone(), v_id, ir_id));
    MultiHarness {
        registry: ProofRegistryClient::new(env, &pr_id),
        kyc_issuer,
        funds_issuer,
        age_issuer,
        admin,
    }
}

#[test]
fn batch_all_pass() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let h = deploy_multi(&env);
    let holder = Address::generate(&env);

    let submissions = vec![
        &env,
        ProofSubmission {
            credential_type: symbol_short!("kyc"),
            proof: Bytes::from_slice(&env, PROOF),
            public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS),
            issuer_id: h.kyc_issuer.clone(),
            expiry: 9999,
        },
        ProofSubmission {
            credential_type: symbol_short!("funds"),
            proof: Bytes::from_slice(&env, FUNDS_PROOF),
            public_inputs: u8_slice_to_vec_u32(&env, FUNDS_PUBLIC_INPUTS),
            issuer_id: h.funds_issuer.clone(),
            expiry: 9999,
        },
        ProofSubmission {
            credential_type: symbol_short!("age"),
            proof: Bytes::from_slice(&env, AGE_PROOF),
            public_inputs: u8_slice_to_vec_u32(&env, AGE_PUBLIC_INPUTS),
            issuer_id: h.age_issuer.clone(),
            expiry: 9999,
        },
    ];

    h.registry.submit_proofs_batch(&holder, &submissions);

    assert!(h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
    assert!(h.registry.is_verified(&holder, &symbol_short!("funds")).0);
    assert!(h.registry.is_verified(&holder, &symbol_short!("age")).0);
}

#[test]
fn batch_one_fail_reverts_all() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let h = deploy_multi(&env);
    let holder = Address::generate(&env);

    let mut bad_funds = FUNDS_PROOF.to_vec();
    bad_funds[5000] ^= 0xff;

    let submissions = vec![
        &env,
        ProofSubmission {
            credential_type: symbol_short!("kyc"),
            proof: Bytes::from_slice(&env, PROOF),
            public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS),
            issuer_id: h.kyc_issuer.clone(),
            expiry: 9999,
        },
        ProofSubmission {
            credential_type: symbol_short!("funds"),
            proof: Bytes::from_slice(&env, &bad_funds),
            public_inputs: u8_slice_to_vec_u32(&env, FUNDS_PUBLIC_INPUTS),
            issuer_id: h.funds_issuer.clone(),
            expiry: 9999,
        },
    ];

    let res = h.registry.try_submit_proofs_batch(&holder, &submissions);
    assert!(res.is_err());

    assert!(!h.registry.is_verified(&holder, &symbol_short!("kyc")).0);
    assert!(!h.registry.is_verified(&holder, &symbol_short!("funds")).0);
}

#[test]
fn batch_max_size_boundary_accepts_five() {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let types = [
        symbol_short!("kyc"),
        symbol_short!("funds"),
        symbol_short!("age"),
        symbol_short!("income"),
        symbol_short!("juris"),
    ];

    let admin = Address::generate(&env);
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer = Address::generate(&env);
    ir.register_issuer(
        &issuer,
        &pubkey_from(&env, PUBLIC_INPUTS),
        &vec![&env, types[0].clone(), types[1].clone(), types[2].clone(), types[3].clone(), types[4].clone()],
    );

    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    let vc = CredentialVerifierClient::new(&env, &v_id);
    for t in types.iter() {
        vc.set_vk(t, &Bytes::from_slice(&env, VK));
    }

    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    let submissions = vec![
        &env,
        ProofSubmission { credential_type: types[0].clone(), proof: Bytes::from_slice(&env, PROOF), public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS), issuer_id: issuer.clone(), expiry: 9999 },
        ProofSubmission { credential_type: types[1].clone(), proof: Bytes::from_slice(&env, PROOF), public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS), issuer_id: issuer.clone(), expiry: 9999 },
        ProofSubmission { credential_type: types[2].clone(), proof: Bytes::from_slice(&env, PROOF), public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS), issuer_id: issuer.clone(), expiry: 9999 },
        ProofSubmission { credential_type: types[3].clone(), proof: Bytes::from_slice(&env, PROOF), public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS), issuer_id: issuer.clone(), expiry: 9999 },
        ProofSubmission { credential_type: types[4].clone(), proof: Bytes::from_slice(&env, PROOF), public_inputs: u8_slice_to_vec_u32(&env, PUBLIC_INPUTS), issuer_id: issuer.clone(), expiry: 9999 },
    ];

    registry.submit_proofs_batch(&holder, &submissions);
    assert!(registry.is_verified(&holder, &types[0]).0);
    assert!(registry.is_verified(&holder, &types[4]).0);
}

#[test]
fn batch_exceeds_max_size_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer = Address::generate(&env);
    ir.register_issuer(
        &issuer,
        &pubkey_from(&env, PUBLIC_INPUTS),
        &vec![&env, symbol_short!("kyc")],
    );
    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    CredentialVerifierClient::new(&env, &v_id)
        .set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, VK));
    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    let sub = kyc_submission(&env, &issuer, 9999);
    let submissions = vec![
        &env, sub.clone(), sub.clone(), sub.clone(), sub.clone(), sub.clone(), sub,
    ];

    let res = registry.try_submit_proofs_batch(&holder, &submissions);
    assert!(res.is_err());
}

#[test]
fn batch_empty_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);

    let submissions: Vec<ProofSubmission> = Vec::new(&env);
    let res = registry.try_submit_proofs_batch(&holder, &submissions);
    assert!(res.is_err());
}

#[test]
fn batch_duplicate_credential_type_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let holder = Address::generate(&env);

    let sub = kyc_submission(&env, &h.issuer, 9999);
    let submissions = vec![&env, sub.clone(), sub];

    let res = h.registry.try_submit_proofs_batch(&holder, &submissions);
    assert!(res.is_err());
}

// ── Admin / upgrade tests ────────────────────────────────────────────────────

#[test]
fn upgrade_by_admin_succeeds() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);

    let real_wasm = get_test_wasm(&env);
    let new_wasm_hash = env.deployer().upload_contract_wasm(real_wasm);

    h.registry.upgrade(&new_wasm_hash);
}

#[test]
fn upgrade_by_non_admin_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);

    let real_wasm = get_test_wasm(&env);
    let new_wasm_hash = env.deployer().upload_contract_wasm(real_wasm);

    let res = h.registry
        .mock_auths(&[])
        .try_upgrade(&new_wasm_hash);
    assert!(res.is_err());
}

#[test]
fn admin_transfer_works() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);

    let new_admin = Address::generate(&env);

    h.registry.set_admin(&new_admin);
    assert_eq!(h.registry.admin(), new_admin);

    let real_wasm = get_test_wasm(&env);
    let new_wasm_hash = env.deployer().upload_contract_wasm(real_wasm);

    let res = h.registry
        .mock_auths(&[MockAuth {
            address: &h.admin,
            invoke: &MockAuthInvoke {
                contract: &h.registry.address,
                fn_name: "upgrade",
                args: (&new_wasm_hash,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_upgrade(&new_wasm_hash);
    assert!(res.is_err());

    h.registry
        .mock_auths(&[MockAuth {
            address: &new_admin,
            invoke: &MockAuthInvoke {
                contract: &h.registry.address,
                fn_name: "upgrade",
                args: (&new_wasm_hash,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .upgrade(&new_wasm_hash);
}

#[test]
fn set_admin_by_non_admin_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let h = deploy(&env);
    let new_admin = Address::generate(&env);
    let res = h.registry
        .mock_auths(&[])
        .try_set_admin(&new_admin);
    assert!(res.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Aggregate proof tests
// ═══════════════════════════════════════════════════════════════════════════════

fn build_aggregate_public_inputs(env: &Env) -> Bytes {
    let kyc = PUBLIC_INPUTS;
    let age = AGE_PUBLIC_INPUTS;

    let mut num = [0u8; 32];
    num[24..32].copy_from_slice(&2u64.to_be_bytes());

    let total = kyc.len() + age.len() + 32;
    let mut buf = [0u8; 4256];
    buf[..kyc.len()].copy_from_slice(kyc);
    buf[kyc.len()..kyc.len() + age.len()].copy_from_slice(age);
    buf[kyc.len() + age.len()..kyc.len() + age.len() + 32].copy_from_slice(&num);
    Bytes::from_slice(env, &buf[..total])
}

struct AggregateHarness {
    registry: ProofRegistryClient<'static>,
    issuer_kyc: Address,
    issuer_age: Address,
}

fn deploy_aggregate(env: &Env) -> AggregateHarness {
    let admin = Address::generate(env);

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(env, &ir_id);

    let issuer_kyc = Address::generate(env);
    let kyc_pk = pubkey_from(env, PUBLIC_INPUTS);
    ir.register_issuer(&issuer_kyc, &kyc_pk, &vec![env, symbol_short!("kyc")]);

    let issuer_age = Address::generate(env);
    let age_pk = pubkey_from(env, AGE_PUBLIC_INPUTS);
    ir.register_issuer(&issuer_age, &age_pk, &vec![env, symbol_short!("age")]);

    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    let vc = CredentialVerifierClient::new(env, &v_id);
    vc.set_vk(&symbol_short!("kyc"), &Bytes::from_slice(env, VK));
    vc.set_vk(&symbol_short!("age"), &Bytes::from_slice(env, AGE_VK));
    // Stand-in aggregate VK: real one generated by circuits/scripts/build.sh
    vc.set_vk(&symbol_short!("aggregate"), &Bytes::from_slice(env, VK));

    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
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
    let stranger = Address::generate(&env);
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = h.registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, stranger, h.issuer_age.clone()],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, PROOF),
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
    let stranger = Address::generate(&env);
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = h.registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, h.issuer_kyc.clone(), stranger],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, PROOF),
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

    let ir_id = env.register(IssuerRegistry, (admin.clone(),));
    let ir = IssuerRegistryClient::new(&env, &ir_id);
    let issuer_kyc = Address::generate(&env);
    ir.register_issuer(
        &issuer_kyc,
        &BytesN::from_array(&env, &[7u8; 64]),
        &vec![&env, symbol_short!("kyc")],
    );

    let issuer_age = Address::generate(&env);
    let age_pk = pubkey_from(&env, AGE_PUBLIC_INPUTS);
    ir.register_issuer(&issuer_age, &age_pk, &vec![&env, symbol_short!("age")]);

    let v_id = env.register(CredentialVerifier, (admin.clone(),));
    let vc = CredentialVerifierClient::new(&env, &v_id);
    vc.set_vk(&symbol_short!("kyc"), &Bytes::from_slice(&env, VK));
    vc.set_vk(&symbol_short!("age"), &Bytes::from_slice(&env, AGE_VK));
    vc.set_vk(&symbol_short!("aggregate"), &Bytes::from_slice(&env, VK));

    let pr_id = env.register(ProofRegistry, (admin, v_id, ir_id));
    let registry = ProofRegistryClient::new(&env, &pr_id);
    let holder = Address::generate(&env);
    let public_inputs = build_aggregate_public_inputs(&env);

    let res = registry.try_submit_aggregate_proof(
        &holder,
        &vec![&env, issuer_kyc.clone(), issuer_age.clone()],
        &vec![&env, symbol_short!("kyc"), symbol_short!("age")],
        &Bytes::from_slice(&env, PROOF),
        &public_inputs,
        &1000,
    );
    assert!(res.is_err());
}

#[test]
fn aggregate_pubkey_match_at_offset() {
    let env = Env::default();

    let padding = [0u8; 65 * 32];
    let mut num = [0u8; 32];
    num[24..32].copy_from_slice(&2u64.to_be_bytes());

    let total = padding.len() + PUBLIC_INPUTS.len() + 32;
    let mut agg = [0u8; 4256];
    agg[..padding.len()].copy_from_slice(&padding);
    agg[padding.len()..padding.len() + PUBLIC_INPUTS.len()]
        .copy_from_slice(PUBLIC_INPUTS);
    agg[padding.len() + PUBLIC_INPUTS.len()..padding.len() + PUBLIC_INPUTS.len() + 32]
        .copy_from_slice(&num);
    let agg_bytes = Bytes::from_slice(&env, &agg[..total]);

    let expected = pubkey_from_offset(&env, PUBLIC_INPUTS, 1);
    assert!(ProofRegistry::aggregate_pubkey_match(
        &agg_bytes,
        66,
        &expected
    ));
}

#[test]
fn read_num_credentials_from_aggregate() {
    let env = Env::default();
    let public_inputs = build_aggregate_public_inputs(&env);

    let num = ProofRegistry::read_u64_field(&public_inputs, AGG_FIELD_NUM_CREDENTIALS);
    assert_eq!(num, 2);
}
