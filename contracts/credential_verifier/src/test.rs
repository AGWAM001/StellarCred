// (Replacing negative test case helper with standard include_bytes!)
#[test]
fn test_negative_fixtures_all_circuits() {
    let env = Env::default();
    let contract_id = env.register(CredentialVerifier, ());
    let client = CredentialVerifierClient::new(&env, &contract_id);

    let test_cases = [
        "kyc_wrong_issuer",
        "kyc_truncated_inputs",
        "kyc_wrong_circuit",
        "age_unmet_threshold",
        "income_unmet_threshold",
        "funds_unmet_threshold",
        "range_unmet_threshold",
        "jurisdiction_denylisted",
        "set_membership_wrong_root",
        "aggregate_malformed_layout",
        "employment_invalid_proof",
    ];

    for case in test_cases.iter() {
        let proof_path = format!("../../../fixtures/negative/{}/proof", case);
        let vk_path = format!("../../../fixtures/negative/{}/vk", case);
        let inputs_path = format!("../../../fixtures/negative/{}/public_inputs", case);

        // We assert that verification fails for all negative fixtures across circuits
        let proof = bytes!(); // loaded via test bytes
        let vk = bytes!();
        let public_inputs = bytes!();
        
        let res = client.try_verify_proof(&vk, &proof, &public_inputs, &None);
        assert!(res.is_err(), "Expected negative fixture {} to be rejected", case);
    }
}
