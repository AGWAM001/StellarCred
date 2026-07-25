#![no_std]
//! ProofRegistry
//!
//! Caches successful verifications so protocols don't re-run the (expensive)
//! UltraHonk verifier on every interaction. A holder proves once; the registry
//! records "this address satisfies credential X until ledger time T". Any gated
//! protocol then makes a single cheap `is_verified` call.
//!
//! On `submit_proof` the registry (1) checks the named issuer is registered and
//! trusted for the credential type via IssuerRegistry, (2) forwards the proof to
//! CredentialVerifier, and only caches the result if both pass.

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, vec, Address, Bytes, BytesN, Env, Symbol, Vec,
};

// Persistent-entry lifetime management (~5s ledgers).
const DAY_IN_LEDGERS: u32 = 17280;
const PROOF_BUMP_THRESHOLD: u32 = DAY_IN_LEDGERS;
const PROOF_TTL: u32 = 90 * DAY_IN_LEDGERS;

// ── Aggregate proof public-input layout (N=2: KYC + age) ────────────────────
// The aggregate_proof circuit packs N credential public inputs sequentially,
// followed by num_credentials as the last field.
//
// KYC (65 fields): commitment(1) + issuer_x(32) + issuer_y(32)
// Age  (67 fields): commitment(1) + issuer_x(32) + issuer_y(32) +
//                    current_date(1) + threshold_years(1)
//
// Field indices (0-based) within public_inputs:
const AGG_FIELD_KYC_START: u32 = 0;      // KYC commitment
const AGG_FIELD_KYC_PUBKEY: u32 = 1;     // KYC issuer_x[0] at byte offset 32
const AGG_FIELD_AGE_START: u32 = 65;     // age commitment
const AGG_FIELD_AGE_PUBKEY: u32 = 66;    // age issuer_x[0]
const AGG_FIELD_AGE_THRESHOLD: u32 = 131; // age threshold_years = AGG_FIELD_AGE_START(65) + 1(commitment) + 32(issuer_x) + 32(issuer_y) + 1(current_date) = 131
const AGG_FIELD_NUM_CREDENTIALS: u32 = 132; // num_credentials (last field)

/// Typed client for the deployed CredentialVerifier contract. Declared as an
/// interface (not a crate dependency) so this contract links only the client,
/// never the verifier's exported wasm symbols.
#[contractclient(name = "VerifierClient")]
pub trait VerifierInterface {
    fn verify_proof(env: Env, credential_type: Symbol, proof: Bytes, public_inputs: Bytes) -> bool;
}

/// Typed client for the deployed IssuerRegistry contract.
#[contractclient(name = "IssuerClient")]
pub trait IssuerRegistryInterface {
    fn is_valid_issuer(env: Env, issuer_id: Address, credential_type: Symbol) -> bool;
    fn get_issuer_pubkey(env: Env, issuer_id: Address) -> BytesN<64>;
}

// Public-input layout (each field is 32 bytes, big-endian): field 0 is the
// commitment, fields 1..33 are issuer_x bytes (one byte per field, in the low
// byte), fields 33..65 are issuer_y bytes. The signed public key therefore
// occupies bytes 32..2080 of `public_inputs`.
const PUBKEY_START_FIELD: u32 = 1;
const FIELD_BYTES: u32 = 32;

#[contracttype]
#[derive(Clone)]
pub struct ProofRecord {
    pub verified_at: u64,
    pub expiry: u64,
    /// For parameterised credential types (age, income, funds), the threshold
    /// value that was committed to in the proof's public inputs. None for types
    /// with no numeric threshold (kyc, jurisdiction).
    pub threshold: Option<u64>,
}

#[contracttype]
pub enum DataKey {
    Verifier,
    IssuerRegistry,
    /// Cached verification, keyed by (holder, credential_type).
    Proof(Address, Symbol),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    VerificationFailed = 2,
    NotAuthorized = 3,
    IssuerNotTrusted = 4,
    /// The public key the proof was made against does not match the registered
    /// issuer's key.
    IssuerKeyMismatch = 5,
    /// The aggregate proof's num_credentials field doesn't match the expected
    /// count or the inner public inputs are too short.
    AggregateLayoutInvalid = 6,
}

#[contract]
pub struct ProofRegistry;

#[contractimpl]
impl ProofRegistry {
    /// `verifier` and `issuer_registry` are the deployed contract addresses.
    pub fn __constructor(env: Env, verifier: Address, issuer_registry: Address) {
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage()
            .instance()
            .set(&DataKey::IssuerRegistry, &issuer_registry);
    }

    /// Verify a proof and, if valid, cache it for `holder` until `expiry`
    /// (ledger timestamp, seconds). The holder authorizes their own submission.
    /// `issuer_id` must be registered and trusted for `credential_type`.
    pub fn submit_proof(
        env: Env,
        holder: Address,
        issuer_id: Address,
        credential_type: Symbol,
        proof: Bytes,
        public_inputs: Bytes,
        expiry: u64,
    ) {
        holder.require_auth();

        // 1. The named issuer must be trusted for this credential type.
        let registry = IssuerClient::new(&env, &Self::issuer_registry(&env));
        if !registry.is_valid_issuer(&issuer_id, &credential_type) {
            panic_with_error!(&env, Error::IssuerNotTrusted);
        }

        // 2. The public key the proof attests to (in its public inputs) must be
        //    the registered issuer's key. Without this, a proof could be made
        //    against an attacker-controlled key.
        let expected = registry.get_issuer_pubkey(&issuer_id);
        if !Self::public_inputs_match_pubkey(&public_inputs, &expected) {
            panic_with_error!(&env, Error::IssuerKeyMismatch);
        }

        // 3. The proof must verify against the registered VK for this type.
        //    VerifierClient panics with VkNotSet if no VK is registered for the type.
        let verifier = VerifierClient::new(&env, &Self::verifier(&env));
        if !verifier.verify_proof(&credential_type, &proof, &public_inputs) {
            panic_with_error!(&env, Error::VerificationFailed);
        }

        Self::store_claim(
            &env,
            &holder,
            &credential_type,
            env.ledger().timestamp(),
            expiry,
            Self::extract_threshold(&credential_type, &public_inputs),
        );
    }

    /// Returns `(is_currently_valid, verified_at, expiry)`. `is_currently_valid`
    /// accounts for expiry against the current ledger time.
    pub fn is_verified(env: Env, holder: Address, credential_type: Symbol) -> (bool, u64, u64) {
        match env
            .storage()
            .persistent()
            .get::<_, ProofRecord>(&DataKey::Proof(holder, credential_type))
        {
            Some(r) => {
                let valid = r.expiry > env.ledger().timestamp();
                (valid, r.verified_at, r.expiry)
            }
            None => (false, 0, 0),
        }
    }

    /// Like `is_verified` but also enforces a minimum threshold for parameterised
    /// credential types (age, income, funds). A proof submitted with a threshold
    /// of 200_000 satisfies `min_threshold = 50_000` because it proves strictly
    /// more. For `kyc` and `jurisdiction`, pass `min_threshold = None`.
    pub fn check_claim(
        env: Env,
        holder: Address,
        credential_type: Symbol,
        min_threshold: Option<u64>,
    ) -> bool {
        match env
            .storage()
            .persistent()
            .get::<_, ProofRecord>(&DataKey::Proof(holder, credential_type))
        {
            Some(r) => {
                if r.expiry <= env.ledger().timestamp() {
                    return false;
                }
                match min_threshold {
                    None => true,
                    Some(min) => r.threshold.unwrap_or(0) >= min,
                }
            }
            None => false,
        }
    }

    /// Verify an aggregate proof that bundles N credential proofs into a single
    /// UltraHonk proof, and atomically store all N claims. This reduces on-chain
    /// verification from N separate `submit_proof` calls to 1.
    ///
    /// The aggregate circuit (N=2 PoC: KYC + age) packs the public inputs as:
    ///   [kyc_fields(65) | age_fields(67) | num_credentials(1)] = 133 fields.
    /// Each inner credential's issuer must be independently registered and trusted.
    pub fn submit_aggregate_proof(
        env: Env,
        holder: Address,
        issuer_ids: Vec<Address>,
        credential_types: Vec<Symbol>,
        proof: Bytes,
        public_inputs: Bytes,
        expiry: u64,
    ) {
        holder.require_auth();

        // 1. Verify the outer aggregate proof against the aggregate VK.
        let verifier = VerifierClient::new(&env, &Self::verifier(&env));
        if !verifier.verify_proof(
            &symbol_short!("aggregate"),
            &proof,
            &public_inputs,
        ) {
            panic_with_error!(&env, Error::VerificationFailed);
        }

        // 2. Validate num_credentials (last field) matches supplied types.
        let num = Self::read_u64_field(&public_inputs, AGG_FIELD_NUM_CREDENTIALS);
        if num != credential_types.len() as u64 || num < 2 {
            panic_with_error!(&env, Error::AggregateLayoutInvalid);
        }

        let registry = IssuerClient::new(&env, &Self::issuer_registry(&env));
        let now = env.ledger().timestamp();

        // 3. For each credential in the aggregate, validate the issuer and
        //    pubkey, then atomically store the claim.
        //
        //    Public-input layout per credential type:
        //      kyc:          65 fields (field offsets tracked below)
        //      age:          67 fields
        //      income:       66 fields
        //      funds:        66 fields
        //      jurisdiction: 73 fields
        //
        //    The aggregate_proof circuit (PoC) packs them in a fixed order
        //    [kyc(65) | age(67) | num_credentials(1)] = 133 fields.
        //    Future circuits for N>2 extend this prefix.
        let mut field_offset: u32 = 0;

        for i in 0..credential_types.len() {
            let ct = credential_types.get(i).unwrap();
            let issuer = issuer_ids.get(i).unwrap();

            if !registry.is_valid_issuer(&issuer, &ct) {
                panic_with_error!(&env, Error::IssuerNotTrusted);
            }

            // Pubkey is always at (commitment field + 1) relative to the
            // credential block's start. Commitment is at field_offset.
            let expected = registry.get_issuer_pubkey(&issuer);
            if !Self::aggregate_pubkey_match(&public_inputs, field_offset + 1, &expected) {
                panic_with_error!(&env, Error::IssuerKeyMismatch);
            }

            let threshold = Self::extract_threshold_from_aggregate(
                &ct, &public_inputs, field_offset,
            );

            Self::store_claim(&env, &holder, &ct, now, expiry, threshold);

            // Advance the field offset by the credential's public-input width.
            field_offset += Self::aggregate_field_count(&ct);
        }
    }

    /// Revoke a cached proof. The holder authorizes their own revocation.
    pub fn revoke_proof(env: Env, holder: Address, credential_type: Symbol) {
        holder.require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::Proof(holder, credential_type));
    }

    /// Revoke ALL cached proofs for a holder — useful after an aggregate proof
    /// is submitted and the holder wants a clean slate.
    pub fn revoke_all(env: Env, holder: Address) {
        holder.require_auth();
        // Remove each known credential type. This is a best-effort removal;
        // types without a stored proof are a no-op thanks to the SDK.
        // "jurisdiction" is >9 chars so must use Symbol::new instead of symbol_short!.
        let types = [
            symbol_short!("kyc"),
            symbol_short!("age"),
            symbol_short!("income"),
            Symbol::new(&env, "jurisdiction"),
            symbol_short!("funds"),
        ];
        for t in types {
            env.storage()
                .persistent()
                .remove(&DataKey::Proof(holder.clone(), t));
        }
    }

    pub fn verifier_address(env: Env) -> Address {
        Self::verifier(&env)
    }

    pub fn issuer_registry_address(env: Env) -> Address {
        Self::issuer_registry(&env)
    }

    /// Extract the numeric threshold from the proof's public inputs for
    /// credential types that carry one. Public-input layout after the common
    /// header (commitment field 0, issuer_x fields 1-32, issuer_y fields 33-64):
    ///   age:        field 65 = current_date, field 66 = threshold_years
    ///   income:     field 65 = threshold
    ///   funds:      field 65 = threshold
    ///   kyc:        (no extra fields)
    fn extract_threshold(credential_type: &Symbol, public_inputs: &Bytes) -> Option<u64> {
        if *credential_type == symbol_short!("age") {
            // field 66, bytes 2112-2143, u64 in last 8 bytes
            Some(Self::read_u64_field(public_inputs, 66))
        } else if *credential_type == symbol_short!("income")
            || *credential_type == symbol_short!("funds")
        {
            // field 65, bytes 2080-2111, u64 in last 8 bytes
            Some(Self::read_u64_field(public_inputs, 65))
        } else {
            None
        }
    }

    /// Read a big-endian u64 from the last 8 bytes of a 32-byte field element.
    fn read_u64_field(public_inputs: &Bytes, field_index: u32) -> u64 {
        let base = field_index * FIELD_BYTES;
        let mut b = [0u8; 8];
        for i in 0..8u32 {
            b[i as usize] = public_inputs.get(base + 24 + i).unwrap_or(0);
        }
        u64::from_be_bytes(b)
    }

    /// True iff the secp256k1 public key embedded in `public_inputs` (fields
    /// 1..65, one byte per field in the low byte) equals `expected` (x || y).
    fn public_inputs_match_pubkey(public_inputs: &Bytes, expected: &BytesN<64>) -> bool {
        Self::aggregate_pubkey_match(public_inputs, PUBKEY_START_FIELD, expected)
    }

    /// Like `public_inputs_match_pubkey` but with a configurable starting field
    /// so it can validate the pubkey in any slice of an aggregate proof.
    fn aggregate_pubkey_match(
        public_inputs: &Bytes,
        start_field: u32,
        expected: &BytesN<64>,
    ) -> bool {
        let exp = expected.to_array();
        for i in 0..64u32 {
            let offset = (start_field + i) * FIELD_BYTES + (FIELD_BYTES - 1);
            match public_inputs.get(offset) {
                Some(b) if b == exp[i as usize] => {}
                _ => return false,
            }
        }
        true
    }

    /// Atomically write a ProofRecord and bump its TTL.
    fn store_claim(
        env: &Env,
        holder: &Address,
        credential_type: &Symbol,
        verified_at: u64,
        expiry: u64,
        threshold: Option<u64>,
    ) {
        let key = DataKey::Proof(holder.clone(), credential_type.clone());
        let record = ProofRecord {
            verified_at,
            expiry,
            threshold,
        };
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, PROOF_BUMP_THRESHOLD, PROOF_TTL);
    }

    /// Returns the number of 32-byte field elements a credential type occupies
    /// in the aggregate proof's public inputs. Used to compute field offsets
    /// when iterating over multiple credentials.
    fn aggregate_field_count(credential_type: &Symbol) -> u32 {
        // Common header: commitment(1) + issuer_x(32) + issuer_y(32) = 65
        let base: u32 = 65;
        if *credential_type == symbol_short!("kyc") {
            base // no extra fields
        } else if *credential_type == symbol_short!("age") {
            base + 2 // current_date + threshold_years
        } else if *credential_type == symbol_short!("income")
            || *credential_type == symbol_short!("funds")
        {
            base + 1 // threshold
        } else {
            // TODO: add jurisdiction handling (73 fields = base + 8) when
            // extending the aggregate_proof circuit to N>2 credential types.
            base
        }
    }

    /// Extract the threshold from within an aggregate proof's credential block.
    /// `field_offset` is the 0-based field index where this credential block
    /// starts (i.e., the commitment field).
    fn extract_threshold_from_aggregate(
        credential_type: &Symbol,
        public_inputs: &Bytes,
        field_offset: u32,
    ) -> Option<u64> {
        if *credential_type == symbol_short!("age") {
            // Base(65) + current_date(1) = offset 66 from block start
            Some(Self::read_u64_field(public_inputs, field_offset + 65 + 1))
        } else if *credential_type == symbol_short!("income")
            || *credential_type == symbol_short!("funds")
        {
            // Base(65) = offset 65 from block start
            Some(Self::read_u64_field(public_inputs, field_offset + 65))
        } else {
            None
        }
    }

    fn issuer_registry(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::IssuerRegistry)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
    }

    fn verifier(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Verifier)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
    }
}

mod test;
