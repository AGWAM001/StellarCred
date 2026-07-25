# @stellarcred/sdk

Read-only client for [StellarCred](https://github.com/Psalmuel01/StellarCred) — check zero-knowledge credential proofs on Stellar from any protocol, frontend, or backend.

Protocols call one function. No API key, no backend, no personal data handling — the only thing you trust is the on-chain ProofRegistry.

## Install

```bash
npm install @stellarcred/sdk
```

## Quick start

```ts
import StellarCred from "@stellarcred/sdk";

// Configure once at startup
StellarCred.configure({
  registryId: process.env.PROOF_REGISTRY_ID,
});

// Check a claim — returns true/false
const eligible = await StellarCred.hasClaim(walletAddress, "kyc");
```

## Configuration

Call `configure()` once before any other call, or set environment variables — both approaches work in Node.js, Next.js, and edge runtimes.

```ts
StellarCred.configure({
  registryId: "C...",                              // ProofRegistry contract ID
  rpcUrl: "https://soroban-testnet.stellar.org",   // defaults to testnet
  networkPassphrase: "Test SDF Network ; September 2015",
  baseUrl: "https://stellarcred.xyz",              // used by buildVerifyUrl
});
```

**Environment variables** (auto-read at import time, no `configure()` needed):

| Variable | Next.js alias |
|---|---|
| `STELLARCRED_REGISTRY_ID` | `NEXT_PUBLIC_PROOF_REGISTRY_ID` |
| `STELLARCRED_RPC_URL` | `NEXT_PUBLIC_RPC_URL` |
| `STELLARCRED_NETWORK_PASSPHRASE` | `NEXT_PUBLIC_NETWORK_PASSPHRASE` |
| `STELLARCRED_BASE_URL` | `NEXT_PUBLIC_STELLARCRED_BASE_URL` |

## API

### `hasClaim(wallet, claimType, opts?)`

Returns `true` if `wallet` has a currently valid, unexpired proof of `claimType`.

For parameterised claims (age, income, funds), pass `minThreshold` to enforce the threshold on-chain. A proof generated with threshold=200,000 satisfies `minThreshold: 50000` — the check is `stored >= required`.

```ts
// Binary claims — no threshold needed
const kycOk   = await StellarCred.hasClaim(wallet, "kyc");
const jurisOk = await StellarCred.hasClaim(wallet, "jurisdiction");

// Threshold claims — enforced on-chain, fully trustless
const ageOk   = await StellarCred.hasClaim(wallet, "age",    { minThreshold: 21 });
const incOk   = await StellarCred.hasClaim(wallet, "income", { minThreshold: 200000 });
const fundsOk = await StellarCred.hasClaim(wallet, "funds",  { minThreshold: 50000 });
```

### `getClaims(wallet)`

Returns all active claims a wallet has proved, across all known credential types.

```ts
const claims = await StellarCred.getClaims(wallet);
// [{ type: "kyc", verifiedAt: 1719000000, expiry: 1726776000 }, ...]
```

### `buildVerifyUrl(options)`

Builds a StellarCred verification URL to redirect users to. After verifying, StellarCred returns the user to `returnUrl` with `?sc_verified=true&sc_wallet=<address>` appended.

```ts
// Basic — redirect to verify KYC
const url = StellarCred.buildVerifyUrl({
  returnUrl: "https://yourapp.xyz/deposit",
  claim: "kyc",
});

// With threshold — user proves balance >= $50,000
const url = StellarCred.buildVerifyUrl({
  returnUrl: "https://yourapp.xyz/vault",
  claim: "funds",
  claimParams: { threshold: "50000" },
});

// Age gate — require 21+
const url = StellarCred.buildVerifyUrl({
  returnUrl: "https://yourapp.xyz/markets",
  claim: "age",
  claimParams: { threshold_years: "21" },
});

// Jurisdiction — block specific countries (ISO 3166-1 numeric codes)
const url = StellarCred.buildVerifyUrl({
  returnUrl: "https://yourapp.xyz/app",
  claim: "jurisdiction",
  claimParams: { restricted: ["840", "364"] },
});
```

## Claim types

| Type | Proves | Threshold parameter |
|---|---|---|
| `kyc` | Identity verified by a KYC provider | — |
| `age` | Holder is at least N years old | `threshold_years` (years) |
| `income` | Annual income exceeds threshold | `threshold` (USD) |
| `jurisdiction` | Country is not in a restricted list | `restricted` (country codes) |
| `funds` | Liquid balance exceeds threshold | `threshold` (USD) |

## Full integration example

```ts
import StellarCred from "@stellarcred/sdk";

StellarCred.configure({ registryId: process.env.PROOF_REGISTRY_ID });

async function handleDeposit(wallet: string) {
  // Check all required claims
  const [kycOk, fundsOk] = await Promise.all([
    StellarCred.hasClaim(wallet, "kyc"),
    StellarCred.hasClaim(wallet, "funds", { minThreshold: 50000 }),
  ]);

  if (!kycOk || !fundsOk) {
    // Redirect to verify the missing claim
    const missing = !kycOk ? "kyc" : "funds";
    const opts = missing === "funds" ? { claimParams: { threshold: "50000" } } : {};
    return redirect(StellarCred.buildVerifyUrl({
      returnUrl: "https://yourapp.xyz/deposit",
      claim: missing,
      ...opts,
    }));
  }

  // All claims verified — proceed
  processDeposit(wallet);
}
```

## Peer dependency

Requires `@stellar/stellar-sdk >= 13.0.0` as a peer dependency.

```bash
npm install @stellar/stellar-sdk
```

## How it works

StellarCred stores ZK proofs on Stellar. A holder proves a claim once (in their browser, using UltraHonk / Barretenberg); the result is cached in the `ProofRegistry` contract. Your protocol reads it with a single free simulation — no wallet connection, no fee, no personal data.

The `minThreshold` check calls `ProofRegistry.check_claim` on-chain, which compares the threshold stored in the proof's public inputs against your required minimum. It is not a frontend check — the contract enforces it.

## License

MIT

## Using StellarCred outside React

The SDK exports a framework-agnostic `createClaimGate` core that exposes a subscribe/unsubscribe API. Use it anywhere — Vue, Svelte, vanilla JS, or any other framework.

```ts
import { createClaimGate } from "@stellarcred/sdk";

const gate = createClaimGate({ wallet: "G…" });
gate.subscribe((state) => {
  console.log(state.claims);  // { kyc: true, age: true, ... }
  console.log(state.loading); // false
});

// Re-check claims later
gate.refetch();

// Clean up when done
gate.destroy();
```

### API

```ts
createClaimGate(config: ClaimGateConfig): ClaimGate
```

| Field | Type | Description |
|---|---|---|
| `subscribe(fn)` | `(ClaimGateState) => void` | Subscribe to state changes; returns unsubscribe |
| `unsubscribe(fn)` | `void` | Remove a listener |
| `getSnapshot()` | `ClaimGateState` | Get current state synchronously |
| `refetch()` | `void` | Re-run all claim checks |
| `destroy()` | `void` | Stop polling, clear listeners |

### TypeScript

```ts
import type { ClaimGate, ClaimGateState, ClaimGateConfig } from "@stellarcred/sdk";
```

### React

The existing `useStellarCred` React hook is built on top of `createClaimGate`. It has the same behavior as before — just implemented on the shared core.

```ts
import { useStellarCred } from "@stellarcred/sdk";
// Works exactly as before
const { claims, loading, error, refetch } = useStellarCred(walletAddress);
```

### Vue example

See [`examples/vue-gate/ClaimGate.vue`](./examples/vue-gate/ClaimGate.vue) for a complete Vue 3 component using `createClaimGate`.

```vue
<script setup lang="ts">
import { createClaimGate } from "@stellarcred/sdk";
import { ref, onMounted, onUnmounted } from "vue";

const props = defineProps<{ wallet: string }>();
const state = ref({ claims: null, loading: true, error: null });
let gate;

onMounted(() => {
  gate = createClaimGate({ wallet: props.wallet });
  gate.subscribe((s) => { state.value = s; });
});
onUnmounted(() => gate?.destroy());
</script>
```

### Svelte example

See [`examples/svelte-gate/ClaimGate.svelte`](./examples/svelte-gate/ClaimGate.svelte) for a complete Svelte component.

```svelte
<script lang="ts">
  import { createClaimGate } from "@stellarcred/sdk";
  import { onMount, onDestroy } from "svelte";

  export let wallet: string;
  let state = { claims: null, loading: true, error: null };
  let gate;

  onMount(() => {
    gate = createClaimGate({ wallet });
    gate.subscribe((s) => { state = s; });
  });
  onDestroy(() => gate?.destroy());
</script>

{#if state.loading}<p>Checking claims…</p>
{:else}{#each Object.entries(state.claims || {}) as [type, ok]}
  <p>{type}: {ok ? '✅' : '❌'}</p>
{/each}{/if}
```
