#![cfg(test)]

use super::*;
use soroban_sdk::{symbol_short, testutils::{Address as _, Events as _}, vec, Address, BytesN, Env, IntoVal};

fn setup(env: &Env) -> (Address, IssuerRegistryClient<'_>) {
    let admin = Address::generate(env);
    let contract_id = env.register(IssuerRegistry, (admin.clone(),));
    (admin, IssuerRegistryClient::new(env, &contract_id))
}

#[test]
fn register_and_query() {
    let env = Env::default();
    env.mock_all_auths();
    let (_admin, client) = setup(&env);

    let issuer = Address::generate(&env);
    let pubkey = BytesN::from_array(&env, &[7u8; 64]);
    let types = vec![&env, symbol_short!("kyc"), symbol_short!("age")];

    client.register_issuer(&issuer, &pubkey, &types);

    assert_eq!(client.get_issuer_pubkey(&issuer), pubkey);
    assert!(client.is_valid_issuer(&issuer, &symbol_short!("kyc")));
    assert!(client.is_valid_issuer(&issuer, &symbol_short!("age")));
    assert!(!client.is_valid_issuer(&issuer, &symbol_short!("income")));
}

#[test]
fn get_issuers_lists_registered() {
    let env = Env::default();
    env.mock_all_auths();
    let (_admin, client) = setup(&env);

    let issuer_a = Address::generate(&env);
    let issuer_b = Address::generate(&env);
    let pubkey = BytesN::from_array(&env, &[7u8; 64]);
    let types = vec![&env, symbol_short!("kyc")];

    client.register_issuer(&issuer_a, &pubkey, &types);
    client.register_issuer(&issuer_b, &pubkey, &types);

    let listed = client.get_issuers();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&issuer_a));
    assert!(listed.contains(&issuer_b));
    assert_eq!(client.get_issuer(&issuer_a).pubkey, pubkey);
}

#[test]
fn revoked_issuer_is_invalid() {
    let env = Env::default();
    env.mock_all_auths();
    let (_admin, client) = setup(&env);

    let issuer = Address::generate(&env);
    let pubkey = BytesN::from_array(&env, &[1u8; 64]);
    client.register_issuer(&issuer, &pubkey, &vec![&env, symbol_short!("kyc")]);
    assert!(client.is_valid_issuer(&issuer, &symbol_short!("kyc")));

    client.revoke_issuer(&issuer);
    assert!(!client.is_valid_issuer(&issuer, &symbol_short!("kyc")));
}

#[test]
fn unknown_issuer_is_invalid() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    let stranger = Address::generate(&env);
    assert!(!client.is_valid_issuer(&stranger, &symbol_short!("kyc")));
}

#[test]
fn register_issuer_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(IssuerRegistry, (admin.clone(),));
    let client = IssuerRegistryClient::new(&env, &contract_id);

    let issuer = Address::generate(&env);
    let pubkey = BytesN::from_array(&env, &[7u8; 64]);
    let types = vec![&env, symbol_short!("kyc")];

    client.register_issuer(&issuer, &pubkey, &types);

    // Filter to this contract's events to avoid picking up noise from other
    // contracts that may have been registered in the same Env.
    assert_eq!(
        env.events().all().filter_by_contract(&contract_id),
        vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("iss_reg"), symbol_short!("register")).into_val(&env),
                EventIssuerRegistered {
                    issuer: issuer.clone(),
                    pubkey: pubkey.clone(),
                }
                .into_val(&env),
            ),
        ],
    );
}

#[test]
fn revoke_issuer_emits_event() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(IssuerRegistry, (admin.clone(),));
    let client = IssuerRegistryClient::new(&env, &contract_id);

    let issuer = Address::generate(&env);
    let pubkey = BytesN::from_array(&env, &[1u8; 64]);
    client.register_issuer(&issuer, &pubkey, &vec![&env, symbol_short!("kyc")]);
    client.revoke_issuer(&issuer);

    // Filter to this contract's events so the assertion is stable regardless
    // of what other contracts were registered in the same Env.
    assert_eq!(
        env.events().all().filter_by_contract(&contract_id),
        vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("iss_reg"), symbol_short!("register")).into_val(&env),
                EventIssuerRegistered {
                    issuer: issuer.clone(),
                    pubkey: pubkey.clone(),
                }
                .into_val(&env),
            ),
            (
                contract_id.clone(),
                (symbol_short!("iss_reg"), symbol_short!("revoked")).into_val(&env),
                EventIssuerRevoked { issuer: issuer.clone() }.into_val(&env),
            ),
        ],
    );
}
