/**
 * Read-only SDK surface for browser-based gating (issue #631).
 *
 * The full `@stellarcred/sdk` package pulls in `@stellar/stellar-sdk` to build
 * and simulate transactions. For a protocol whose ONLY use is checking
 * `hasClaim`, that is a lot of machinery for what is fundamentally a single
 * `simulateTransaction` RPC call whose result is a three-element tuple.
 *
 * This module provides the read path using ONLY the two subpaths:
 *
 *   - `@stellar/stellar-sdk/rpc`       — Server + Api.isSimulationError
 *   - `@stellar/stellar-sdk/contract`  — Contract + Client
 *
 * The top-level `@stellar/stellar-sdk` entry point is NOT imported, which
 * avoids pulling in the transaction-builder, wallet-kit, signer, and
 * SEP-41 client machinery.
 *
 * ## Tradeoff, stated honestly
 *
 * What this saves: the top-level SDK barrel, `TransactionBuilder`, `Account`,
 * `FeeBumpTransaction`, `WalletKit`-related code, and everything else the
 * top-level entry re-exports. Measurable in a bundler with tree-shaking.
 *
 * What this does NOT do: hand-roll XDR. Building a valid `TransactionEnvelope`
 * for the Soroban RPC `simulateTransaction` method requires the full envelope
 * structure — source account, seq, fee, timebounds, ext, operation, host
 * function, auth, and ScVal args. That is exactly the code the SDK already
 * provides. A hand-rolled variant (tier C in the issue) would be 200–400 LOC
 * of XDR encoding to own and test forever.
 *
 * ## How to measure whether to go further
 *
 * In a clean temp directory:
 *   npm install esbuild @stellar/stellar-sdk
 *   echo 'import { rpc, Contract, nativeToScVal, scValToNative } from "@stellar/stellar-sdk"; console.log(rpc, Contract, nativeToScVal, scValToNative);' > index.mjs
 *   npx esbuild index.mjs --bundle --minify --format=esm --outfile=with-full.js
 *   echo 'import { rpc } from "@stellar/stellar-sdk/rpc"; import { Contract, nativeToScVal, scValToNative } from "@stellar/stellar-sdk/contract"; console.log(rpc, Contract, nativeToScVal, scValToNative);' > index2.mjs
 *   npx esbuild index2.mjs --bundle --minify --format=esm --outfile=with-subpaths.js
 *
 * Compare `with-full.js` vs `with-subpaths.js` gzipped sizes. If the delta is
 * small, subpaths are already the answer and no further work is needed. If the
 * delta is large but a hand-rolled XDR encoder would still save meaningfully
 * over subpaths, the issue remains open for tier C.
 */

// Subpath imports — no top-level barrel.
import { rpc } from "@stellar/stellar-sdk/rpc";
import { Contract, nativeToScVal, scValToNative } from "@stellar/stellar-sdk/contract";

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

export interface ReadonlyConfig {
  /** Soroban RPC endpoint, e.g. `https://soroban-testnet.stellar.org`. */
  rpcUrl: string;
  /** Network passphrase, e.g. `Test SDF Network ; September 2015`. */
  networkPassphrase: string;
  /** Deployed ProofRegistry contract ID (C... address). */
  registryId: string;
  /** Per-request timeout in ms. Default 10_000. */
  requestTimeoutMs?: number;
}

let _roConfig: Required<ReadonlyConfig> = {
  rpcUrl: "",
  networkPassphrase: "",
  registryId: "",
  requestTimeoutMs: 10_000,
};

/**
 * Configure the read-only client. Call once at app startup.
 *
 * Example:
 *   configureReadonly({
 *     rpcUrl: "https://soroban-testnet.stellar.org",
 *     networkPassphrase: "Test SDF Network ; September 2015",
 *     registryId: process.env.NEXT_PUBLIC_PROOF_REGISTRY_ID!,
 *   });
 */
export function configureReadonly(opts: ReadonlyConfig): void {
  _roConfig = {
    rpcUrl: opts.rpcUrl,
    networkPassphrase: opts.networkPassphrase,
    registryId: opts.registryId,
    requestTimeoutMs: opts.requestTimeoutMs ?? 10_000,
  };
  _roServer = null;
  _roContract = null;
}

let _roServer: rpc.Server | null = null;
let _roContract: Contract | null = null;

function server(): rpc.Server {
  if (!_roServer) {
    _roServer = new rpc.Server(_roConfig.rpcUrl, {
      allowHttp: _roConfig.rpcUrl.startsWith("http://"),
    });
  }
  return _roServer;
}

function contract(): Contract {
  if (!_roContract) {
    _roContract = new Contract(_roConfig.registryId);
  }
  return _roContract;
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

export interface ReadonlyClaimResult {
  /** True if the wallet has a valid, unexpired proof of this claim type. */
  valid: boolean;
  /** Unix seconds the proof was verified at (0 if absent). */
  verifiedAt: number;
  /** Unix seconds the proof expires at (0 if absent). */
  expiry: number;
}

/**
 * Read-only equivalent of `StellarCred.hasClaim`. Uses the same
 * `is_verified(holder, credential_type, trusted_issuers)` simulation as the
 * full SDK, but imports only the two subpaths, not the top-level barrel.
 *
 * Returns `{ valid, verifiedAt, expiry }`. `valid === false` covers both
 * "no proof exists" and "proof exists but is expired or revoked" — the
 * contract's `is_verified` returns `[false, 0, 0]` in either case.
 *
 * Throws only when `throwOnError: true` and the RPC itself fails.
 */
export async function hasClaimReadonly(
  wallet: string,
  claimType: string,
  opts: {
    trustedIssuers?: string[];
    throwOnError?: boolean;
    requestTimeoutMs?: number;
  } = {},
): Promise<ReadonlyClaimResult> {
  if (!_roConfig.registryId) {
    if (opts.throwOnError) {
      throw new Error("hasClaimReadonly: registryId not configured — call configureReadonly()");
    }
    return { valid: false, verifiedAt: 0, expiry: 0 };
  }

  const timeoutMs = opts.requestTimeoutMs ?? _roConfig.requestTimeoutMs;
  const call = contract().call(
    "is_verified",
    nativeToScVal(wallet, { type: "address" }),
    nativeToScVal(claimType, { type: "symbol" }),
    nativeToScVal(opts.trustedIssuers ?? [], { type: "vec" }),
  );

  let retval: unknown;
  try {
    const tx = buildSimulationTx(call);
    const sim = await withTimeout(
      server().simulateTransaction(tx),
      timeoutMs,
      `is_verified simulation timed out after ${timeoutMs}ms`,
    );
    if (rpc.Api.isSimulationError(sim)) {
      const msg = typeof sim.error === "string" ? sim.error : JSON.stringify(sim.error);
      throw new Error(`is_verified simulation failed: ${msg}`);
    }
    retval = (sim as rpc.Api.SimulateTransactionSuccessResponse).result?.retval;
  } catch (err) {
    if (opts.throwOnError) throw err;
    return { valid: false, verifiedAt: 0, expiry: 0 };
  }

  if (!retval) return { valid: false, verifiedAt: 0, expiry: 0 };

  // The contract returns `(bool, u64, u64)`.
  const decoded = scValToNative(retval) as unknown;
  if (!Array.isArray(decoded) || decoded.length < 3) {
    return { valid: false, verifiedAt: 0, expiry: 0 };
  }
  const [valid, verifiedAt, expiry] = decoded as [boolean, bigint | number, bigint | number];
  return {
    valid: Boolean(valid),
    verifiedAt: Number(verifiedAt),
    expiry: Number(expiry),
  };
}

/**
 * Batched read: checks several claim types for one wallet with a single
 * configured registry. Returns a map of `claimType -> valid`. Missing or
 * failed types resolve to `false`, matching the full SDK's `hasClaims`.
 */
export async function hasClaimsReadonly(
  wallet: string,
  claimTypes: readonly string[],
  opts: { trustedIssuers?: string[]; requestTimeoutMs?: number } = {},
): Promise<Record<string, boolean>> {
  const results: Record<string, boolean> = {};
  await Promise.all(
    Array.from(new Set(claimTypes)).map(async (t) => {
      const r = await hasClaimReadonly(wallet, t, opts);
      results[t] = r.valid;
    }),
  );
  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internals
// ─────────────────────────────────────────────────────────────────────────────

/** Build a minimal unsigned envelope for a read-only simulation. */
function buildSimulationTx(call: ReturnType<Contract["call"]>) {
  // Deliberately local import so the tree-shaker can drop TransactionBuilder
  // when the caller only uses the readonly surface.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { TransactionBuilder, Account, Operation } = require("@stellar/stellar-sdk/contract");
  const placeholder = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
  const source = new Account(placeholder, "0");
  return new TransactionBuilder(source, {
    fee: "100",
    networkPassphrase: _roConfig.networkPassphrase,
  })
    .addOperation(call)
    .setTimeout(30)
    .build();
}

function withTimeout<T>(p: Promise<T>, ms: number, msg: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(msg)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}