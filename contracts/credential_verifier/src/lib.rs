#![no_std]
//! CredentialVerifier
//!
//! Stateless cryptographic gateway. A single `verify_proof` entry point accepts
//! any credential type — it looks up the VK by Symbol from persistent storage
//! and runs the UltraHonk verifier. Adding a new credential type requires only
//! calling `set_vk` with the new circuit's VK; no contract changes or redeploy.
//!
//! Verification keys are set by an admin (one VK per credential circuit). Each VK
//! is tied to a specific Noir circuit and must be produced with the same `bb`
//! version used to generate proofs (Barretenberg v0.87.0 / Noir 1.0.0-beta.9).
//! `proof` and `public_inputs` are the opaque byte blobs emitted by `bb`.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Bytes, Env, Symbol,
};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, PROOF_BYTES};

// Persistent-entry lifetime management (~5s ledgers). VKs are long-lived.
const DAY_IN_LEDGERS: u32 = 17280;
const VK_BUMP_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const VK_TTL: u32 = 180 * DAY_IN_LEDGERS;

#[contracttype]
pub enum DataKey {
    Admin,
    /// Verification key bytes, keyed by (credential-type symbol, version).
    Vk(Symbol, u32),
    /// Tracks the latest VK version registered for a credential type.
    LatestVersion(Symbol),
    /// Marks a specific (credential_type, version) as deprecated — no longer
    /// accepted for new submissions. Old proofs using this version remain
    /// readable (the VK is not deleted).
    DeprecatedVersion(Symbol, u32),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    VkNotSet = 2,
    VkInvalid = 3,
    /// The requested VK version has been deprecated by the admin; new
    /// submissions against it are rejected.
    VersionDeprecated = 4,
}

#[contract]
pub struct CredentialVerifier;

#[contractimpl]
impl CredentialVerifier {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Register a verification key for a credential circuit at the given version.
    /// Admin-only. The VK is validated by parsing it before storage, rejecting
    /// malformed keys at set time.
    ///
    /// If `version` is greater than the currently-tracked latest version for
    /// `credential_type`, the latest-version pointer is updated automatically.
    pub fn set_vk(env: Env, credential_type: Symbol, version: u32, vk: Bytes) {
        Self::require_admin(&env);
        if UltraHonkVerifier::new(&env, &vk).is_err() {
            panic_with_error!(&env, Error::VkInvalid);
        }
        let key = DataKey::Vk(credential_type.clone(), version);
        env.storage().persistent().set(&key, &vk);
        env.storage()
            .persistent()
            .extend_ttl(&key, VK_BUMP_THRESHOLD, VK_TTL);

        // Update the latest-version pointer when registering a newer version.
        let latest_key = DataKey::LatestVersion(credential_type);
        let current: u32 = env.storage().persistent().get(&latest_key).unwrap_or(0);
        if version > current {
            env.storage().persistent().set(&latest_key, &version);
            env.storage()
                .persistent()
                .extend_ttl(&latest_key, VK_BUMP_THRESHOLD, VK_TTL);
        }
    }

    /// Verify an UltraHonk proof for any registered credential type. Looks up
    /// the VK by `(credential_type, vk_version)`. Pass `vk_version = None` to
    /// use the latest registered version automatically.
    ///
    /// Returns `true` iff the proof is valid. Returns `false` for malformed
    /// inputs or invalid proofs; panics with `VkNotSet` if no VK has been
    /// registered for this type/version, or with `VersionDeprecated` if the
    /// requested version has been deprecated.
    pub fn verify_proof(
        env: Env,
        credential_type: Symbol,
        proof: Bytes,
        public_inputs: Bytes,
        vk_version: Option<u32>,
    ) -> bool {
        // Proofs are fixed-length; reject early before touching the verifier.
        if proof.len() as usize != PROOF_BYTES {
            return false;
        }

        let version = match vk_version {
            Some(v) if v > 0 => v,
            _ => env
                .storage()
                .persistent()
                .get(&DataKey::LatestVersion(credential_type.clone()))
                .unwrap_or_else(|| panic_with_error!(&env, Error::VkNotSet)),
        };

        // Reject submissions against a deprecated VK version.
        let dep_key = DataKey::DeprecatedVersion(credential_type.clone(), version);
        if env.storage().persistent().get::<_, bool>(&dep_key).unwrap_or(false) {
            panic_with_error!(&env, Error::VersionDeprecated);
        }

        let vk: Bytes = env
            .storage()
            .persistent()
            .get(&DataKey::Vk(credential_type, version))
            .unwrap_or_else(|| panic_with_error!(&env, Error::VkNotSet));

        match UltraHonkVerifier::new(&env, &vk) {
            Ok(verifier) => verifier.verify(&env, &proof, &public_inputs).is_ok(),
            Err(_) => false,
        }
    }

    /// Mark a VK version as deprecated. Admin-only. New proof submissions against
    /// this version will be rejected (`VersionDeprecated`), but the VK is not
    /// deleted so old proofs already stored by ProofRegistry remain readable.
    pub fn deprecate_version(env: Env, credential_type: Symbol, version: u32) {
        Self::require_admin(&env);
        let key = DataKey::DeprecatedVersion(credential_type, version);
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, VK_BUMP_THRESHOLD, VK_TTL);
    }

    /// Returns the highest registered VK version for `credential_type`, or 0 if
    /// no VK has been registered yet.
    pub fn get_latest_version(env: Env, credential_type: Symbol) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::LatestVersion(credential_type))
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized));
        admin.require_auth();
    }
}

mod test;
