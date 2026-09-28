# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Explicit degraded mode (Issue #634)**: `lib/rpc-health.ts` classifies Soroban RPC failures (`rpc-unreachable`, `not-configured`, `read-failed`), keeps app-wide health state, probes the endpoint on mount/interval/`online`, and exposes `useRpcHealth()`. A global `RpcStatusBanner` states that credential status is *unknown*, not unverified, whenever the endpoint is unreachable.
- **Pre-proving network check**: proof generation (single and batch) now checks the RPC endpoint first and defers to a `blocked` stage with a "Check the network again" / "Generate anyway" choice, instead of spending the proving step into a guaranteed submission failure.
- **Badge unknown state**: the embedded badge renders "Unknown — network unavailable" in amber with `data-status="unknown"` and retries the read, rather than showing "Not verified" during an outage.
- Tests for the classifier, health store, probe, and the tri-state read path (`lib/rpc-health.test.ts`, `lib/contract-simulation.test.ts`).

### Changed
- **Reads are tri-state**: `checkClaim` and `isVerified` return `verified` / `unverified` / `unknown`. A failed read, a simulation error, or a missing contract id returns `unknown` with an `RpcIssue` instead of a false negative; only a real negative or a holder with no account on the ledger returns `unverified`. Consumers (`/apps`, `/apps/[id]`, `/verifier`, `/verify-preset`, `/badge`) render the unknown state explicitly.
- `useProtocolAccessCheck` gained an `unknown` state (with `issue`) and an `unresolved` flag; a throw remains `error`. `next` no longer reports `degraded` from a single unreadable requirement.

## [0.1.1] - 2026-09-26

### Added
- **SDK Release & Packaging**: Configured dual CommonJS (`dist/index.js`) and ECMAScript Modules (`dist/index.mjs`) builds with full TypeScript declarations (`dist/index.d.ts`).
- **Claim Verification**: `hasClaim`, `getClaims`, and `verifyProof` client methods supporting zero-knowledge credential verification directly against deployed ProofRegistry contracts.
- **Typed Errors**: Introduced structured error taxonomy (`StellarCredError`, `RpcError`, `ContractError`, `NetworkError`) for predictable failure handling.
- **Bounded Request Timeouts**: Configurable timeout (`requestTimeoutMs`) preventing stalled Soroban RPC nodes from hanging integrations.
- **Environment & Presets**: Out-of-the-box configuration presets for Soroban testnet and mainnet, with automatic environment variable resolution.
- **Contract GatedPool Integration**: Real token client integration supporting live token transfers on deposit and open withdrawal semantics.

### Changed
- Refactored SDK export bundle to only ship compiled artifacts (`dist/`), excluding tests, fixtures, and internal source code.
- Hardened release automation workflow in `.github/workflows/release.yml` with version parity validation.

## [0.1.0] - 2026-08-15

### Added
- Initial release of the StellarCred TypeScript SDK client.
- Soroban RPC simulation client for reading on-chain credential registry states.
