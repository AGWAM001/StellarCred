// @stellarcred/sdk
//
// A tiny, zero-dependency* read-only client for protocols integrating
// StellarCred. The only thing a protocol trusts is the on-chain
// ProofRegistry — there is no API key, no backend, and no personal data
// handling. `hasClaim` is the primary integration call.
//
// *Requires @stellar/stellar-sdk as a peer dependency.
//
// Quick start (Next.js / Vite / Node.js):
//
//   import StellarCred from "@stellarcred/sdk";
//
//   // Option A: configure explicitly at startup (recommended for servers)
//   StellarCred.configure({
//     registryId: process.env.PROOF_REGISTRY_ID,
//     rpcUrl: "https://soroban-testnet.stellar.org",
//   });
//
//   // Option B: set env vars instead (STELLARCRED_REGISTRY_ID, etc.)
//   //           — works in both Node.js and Next.js (NEXT_PUBLIC_* prefix)
//
//   const ok = await StellarCred.hasClaim(walletAddress, "kyc");

// The claim-checking implementation lives in `./claims` (config, low-level
// reads, hasClaim / hasClaims / getClaims / watchClaim / buildVerifyUrl /
// parseReturnParams). `index.ts` only re-exports it and assembles the
// `StellarCred` namespace, so `core.ts` and `react.ts` can import from
// `./claims` directly without creating a circular dependency on this file.
export {
  configure,
  healthCheck,
  isConfigured,
  TimeoutError,
  CLAIM_TYPES,
  hasClaim,
  hasClaims,
  getClaims,
  buildVerifyUrl,
  parseReturnParams,
  watchClaim,
} from "./claims";

export type {
  ClaimType,
  ClaimOptions,
  Claim,
  BatchClaimOptions,
  UntrustedReturnParams,
  WatchClaimOptions,
  WatchClaimCallbackOptions,
} from "./claims";

import {
  configure,
  healthCheck,
  isConfigured,
  TimeoutError,
  CLAIM_TYPES,
  hasClaim,
  hasClaims,
  getClaims,
  buildVerifyUrl,
  parseReturnParams,
  watchClaim,
} from "./claims";

// ---------------------------------------------------------------------------
// Namespace export (StellarCred.hasClaim / StellarCred.getClaims / etc.)
// ---------------------------------------------------------------------------

export const StellarCred = {
  configure,
  healthCheck,
  isConfigured,
  hasClaim,
  hasClaims,
  getClaims,
  buildVerifyUrl,
  parseReturnParams,
  watchClaim,
  CLAIM_TYPES,
  TimeoutError,
};
export default StellarCred;

// Framework-agnostic core — for use outside React (Vue, Svelte, vanilla).
export { createClaimGate } from "./core";
export type { ClaimGateConfig, ClaimGateState, ClaimGateListener, ClaimGate } from "./core";

// React hook — re-implemented on top of createClaimGate.
export { useStellarCred } from "./react";
