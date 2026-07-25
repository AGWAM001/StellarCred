"use client";

// Real Soroban contract calls against the deployed StellarCred contracts.
//  - submitProof: builds, signs (via wallet), and submits a ProofRegistry
//    submit_proof transaction carrying a real UltraHonk proof.
//  - submitAggregateProof: same for the aggregate_proof circuit (N=2 PoC).
//  - isVerified: read-only simulation of ProofRegistry.is_verified.
//
// @stellar/stellar-sdk is imported dynamically so it never runs during SSR.

import { Buffer } from "buffer";
import { RPC_URL, NETWORK_PASSPHRASE, CONTRACTS } from "./stellar";
import { signTx } from "./wallet";

type SDK = typeof import("@stellar/stellar-sdk");

let sdkPromise: Promise<SDK> | null = null;
let sdkModule: SDK | null = null;
function sdk(): Promise<SDK> {
  if (!sdkPromise) {
    sdkPromise = import("@stellar/stellar-sdk").then((m) => {
      sdkModule = m;
      return m;
    });
  }
  return sdkPromise;
}

/** Synchronously access the already-loaded SDK. Only valid after sdk() has resolved. */
function sdkSync(): SDK {
  if (!sdkModule) throw new Error("SDK not loaded — call await sdk() first");
  return sdkModule;
}

let server: InstanceType<SDK["rpc"]["Server"]> | null = null;
async function getServer() {
  if (!server) {
    const { rpc } = await sdk();
    server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith("http://") });
  }
  return server;
}

const PROOF_REGISTRY_ERRORS: Record<number, string> = {
  1: "Contracts not initialised — check that all contract IDs are set in the environment.",
  2: "Proof verification failed — the ZK proof is invalid or was generated against the wrong circuit VK.",
  3: "Not authorised — wallet signature missing or wrong account.",
  4: "Issuer not trusted — the issuer address isn't registered for this credential type.",
  5: "Issuer key mismatch — this credential was signed with a key that doesn't match what's registered on-chain. Re-issue the credential and try again.",
  6: "Aggregate layout invalid — the proof's public inputs don't match the expected format or credential count.",
};

export interface ContractError {
  friendly: string;
  code: number | null;
  raw: string;
}

export function parseContractError(raw: string): ContractError {
  const match = raw.match(/Error\(Contract,\s*#(\d+)\)/);
  if (match) {
    const code = parseInt(match[1]);
    return {
      code,
      friendly: PROOF_REGISTRY_ERRORS[code] ?? `Contract error #${code}.`,
      raw,
    };
  }
  if (raw.includes("Error(Auth")) {
    return { code: null, friendly: "Wallet authorisation failed — approve the transaction in Freighter.", raw };
  }
  if (raw.includes("Error(WasmVm")) {
    return { code: null, friendly: "Contract execution failed — the proof or inputs were malformed.", raw };
  }
  return { code: null, friendly: raw, raw };
}

export interface VerificationStatus {
  valid: boolean;
  verifiedAt: number;
  expiry: number;
}

// ── Shared tx building, signing, submission, and polling ─────────────────────

function isBadUnionSwitch(e: unknown): boolean {
  return e instanceof Error && e.message.startsWith("Bad union switch");
}

/** Build, sign, submit, and poll a transaction. */
async function sendAndConfirm(
  holder: string,
  buildOp: (contract: InstanceType<SDK["Contract"]>) => InstanceType<SDK["xdr"]["Operation"]>,
  label: string,
): Promise<string> {
  if (!CONTRACTS.proofRegistry) {
    throw new Error(
      "ProofRegistry contract id not set. Deploy the contracts and fill NEXT_PUBLIC_PROOF_REGISTRY_ID.",
    );
  }

  const { Contract, TransactionBuilder, BASE_FEE } = await sdk();
  const srv = await getServer();

  const account = await srv.getAccount(holder);
  const contract = new Contract(CONTRACTS.proofRegistry);
  const op = buildOp(contract);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(op)
    .setTimeout(60)
    .build();

  const prepared = await srv.prepareTransaction(tx);
  const signedXdr = await signTx(prepared.toXDR(), holder);
  const sent = await srv.sendTransaction(
    TransactionBuilder.fromXDR(signedXdr, NETWORK_PASSPHRASE),
  );

  if (sent.status === "ERROR") {
    const errHex =
      sent.errorResult &&
      typeof (sent.errorResult as { toXDR?: (f: string) => string }).toXDR === "function"
        ? (sent.errorResult as { toXDR: (f: string) => string }).toXDR("hex")
        : String(sent.errorResult);
    throw new Error(`${label} rejected: ${errHex}`);
  }

  const start = Date.now();
  let result;
  try {
    result = await srv.getTransaction(sent.hash);
  } catch (e) {
    if (isBadUnionSwitch(e)) return sent.hash;
    throw e;
  }
  while (result.status === "NOT_FOUND" && Date.now() - start < 30_000) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      result = await srv.getTransaction(sent.hash);
    } catch (e) {
      if (isBadUnionSwitch(e)) return sent.hash;
      throw e;
    }
  }
  if (result.status !== "SUCCESS") {
    throw new Error(`Transaction ${sent.hash} did not succeed (${result.status}).`);
  }
  return sent.hash;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Submit a proof to the ProofRegistry. Returns the confirmed transaction hash.
 */
export async function submitProof(params: {
  holder: string;
  issuerId: string;
  credentialType: string;
  proof: Uint8Array;
  publicInputs: Uint8Array;
  ttlSecs: number;
}): Promise<string> {
  const { holder, issuerId, credentialType, proof, publicInputs, ttlSecs } = params;
  const expiry = Math.floor(Date.now() / 1000) + ttlSecs;

  return sendAndConfirm(holder, (contract) => {
    const { Address, nativeToScVal, xdr } = sdkSync();
    return contract.call(
      "submit_proof",
      Address.fromString(holder).toScVal(),
      Address.fromString(issuerId).toScVal(),
      nativeToScVal(credentialType, { type: "symbol" }),
      xdr.ScVal.scvBytes(Buffer.from(proof)),
      xdr.ScVal.scvBytes(Buffer.from(publicInputs)),
      nativeToScVal(BigInt(expiry), { type: "u64" }),
    );
  }, "Submission");
}

/**
 * Submit an aggregate proof that bundles N credential proofs into a single
 * on-chain transaction. Accepts arrays of issuer IDs and credential types for
 * extensibility to N≤5.
 */
export async function submitAggregateProof(params: {
  holder: string;
  issuerIds: string[];
  credentialTypes: string[];
  proof: Uint8Array;
  publicInputs: Uint8Array;
  ttlSecs: number;
}): Promise<string> {
  const { holder, issuerIds, credentialTypes, proof, publicInputs, ttlSecs } = params;
  const expiry = Math.floor(Date.now() / 1000) + ttlSecs;

  return sendAndConfirm(holder, (contract) => {
    const { Address, nativeToScVal, xdr } = sdkSync();
    // Build ScVec for issuer_ids and credential_types.
    const issuerScVec = xdr.ScVal.scvVec(
      issuerIds.map((id) => Address.fromString(id).toScVal()),
    );
    const typeScVec = xdr.ScVal.scvVec(
      credentialTypes.map((t) => nativeToScVal(t, { type: "symbol" })),
    );
    return contract.call(
      "submit_aggregate_proof",
      Address.fromString(holder).toScVal(),
      issuerScVec,
      typeScVec,
      xdr.ScVal.scvBytes(Buffer.from(proof)),
      xdr.ScVal.scvBytes(Buffer.from(publicInputs)),
      nativeToScVal(BigInt(expiry), { type: "u64" }),
    );
  }, "Aggregate submission");
}

/**
 * Like isVerified but also enforces a minimum threshold for parameterised
 * credential types (age, income, funds). Calls ProofRegistry.check_claim which
 * stores the proved threshold and checks stored >= minThreshold server-side.
 * For kyc / jurisdiction pass minThreshold = undefined.
 */
export async function checkClaim(
  holder: string,
  credentialType: string,
  minThreshold?: number,
): Promise<boolean> {
  if (!CONTRACTS.proofRegistry) return false;

  const { rpc, Contract, TransactionBuilder, Address, nativeToScVal, scValToNative, BASE_FEE } =
    await sdk();
  const srv = await getServer();

  const account = await srv.getAccount(holder);
  const contract = new Contract(CONTRACTS.proofRegistry);
  const op = contract.call(
    "check_claim",
    Address.fromString(holder).toScVal(),
    nativeToScVal(credentialType, { type: "symbol" }),
    minThreshold !== undefined
      ? nativeToScVal(BigInt(minThreshold), { type: "u64" })
      : nativeToScVal(null, { type: "void" }),
  );
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(op)
    .setTimeout(30)
    .build();

  const sim = await srv.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim) || !sim.result) return false;
  return scValToNative(sim.result.retval) as boolean;
}

/** Read-only check of whether `holder` has a currently-valid proof of `type`. */
export async function isVerified(
  holder: string,
  credentialType: string,
): Promise<VerificationStatus> {
  const empty: VerificationStatus = { valid: false, verifiedAt: 0, expiry: 0 };
  if (!CONTRACTS.proofRegistry) return empty;

  const { rpc, Contract, TransactionBuilder, Address, nativeToScVal, scValToNative, BASE_FEE } =
    await sdk();
  const srv = await getServer();

  const account = await srv.getAccount(holder);
  const contract = new Contract(CONTRACTS.proofRegistry);
  const op = contract.call(
    "is_verified",
    Address.fromString(holder).toScVal(),
    nativeToScVal(credentialType, { type: "symbol" }),
  );
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(op)
    .setTimeout(30)
    .build();

  const sim = await srv.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim) || !sim.result) return empty;

  const [valid, verifiedAt, expiry] = scValToNative(sim.result.retval) as [
    boolean,
    bigint | number,
    bigint | number,
  ];
  return { valid, verifiedAt: Number(verifiedAt), expiry: Number(expiry) };
}
