# StellarCred Circuits — Constraint Audit

> Noir **1.0.0-beta.9** · Barretenberg (UltraHonk) **v0.87.0** · `nargo info` run 2026-07-25

## Overview

In-browser proving time is dominated by circuit constraint count (backend gate count,
not just ACIR opcodes). This audit establishes a **baseline measurement** of every
circuit's ACIR opcode count and provides a constraint-breakdown analysis so future
PRs can measure regression or improvement.

All circuits share a common skeleton: **Poseidon2 commitment hash** → **secp256k1 ECDSA
signature verification** → **type-specific threshold or membership check**.

## Audit Table

| Circuit                | Total ACIR Opcodes | ECDSA         | Poseidon2     | Field→Bytes + Commitment | Threshold / Logic | Notes |
|------------------------|--------------------|----------------|----------------|--------------------------|-------------------|-------|
| `commit`               | 4                  | —              | 4 (100%)       | —                        | —                 | Witness-only helper; never proven. |
| `kyc_proof`            | 582                | 1 blackbox¹    | 4              | ~577                      | —                 | Baseline proof circuit — no threshold. |
| `income_proof`         | 588                | 1 blackbox¹    | 4              | ~577                      | ~6 (≥ comparison) | +6 opcodes vs kyc for `income ≥ threshold`. |
| `funds_proof`          | 588                | 1 blackbox¹    | 4              | ~577                      | ~6 (≥ comparison) | Identical profile to income_proof. |
| `accreditation_proof`  | 588                | 1 blackbox¹    | 4              | ~577                      | ~6 (≥ comparison) | Identical profile to income_proof. |
| `age_proof`            | 601                | 1 blackbox¹    | 4              | ~577                      | ~20 (sub, div, ≥) | +19 vs kyc; division by 365 is the delta. |
| `jurisdiction_proof`   | 607                | 1 blackbox¹    | 4              | ~577                      | ~26 (8 × ≠ loop) | +25 vs kyc; unrolled loop over 8 entries. |

> ¹ ECDSA secp256k1 verification uses a single ACIR blackbox opcode (`EcdsaSecp256k1`),
> but expands to an estimated ~30,000 backend gates in Barretenberg (rough
> order-of-magnitude; not yet profiled with `bb`). This is why proving time is
> dominated by ECDSA across all circuits despite it appearing as "1 opcode" in the
> ACIR count.

### What drives the ~577 non-ECDSA, non-Poseidon2 opcodes?

The constrained `to_be_bytes()` decomposition of the field element into 32 bytes
generates the bulk of the remaining opcodes. Each of the 32 output bytes requires
a range check (`0 ≤ byte ≤ 255`), and each range check decomposes into bit-level
constraints in ACIR.

> **Note:** The `nargo info --json` output also lists "Unconstrained functions"
> (`directive_to_radix`: 17, `directive_invert`: 9, `directive_integer_quotient`: 8).
> These are **witness-only hints** that do NOT contribute to the constraint count —
> they are listed separately because they run outside the constraint system. The
> constraint count comes entirely from the constrained range checks and field
> arithmetic emitted by `to_be_bytes()` and related operations.

## Constraint Contributor Analysis

### 1. ECDSA secp256k1 Verification (dominant cost)

**ACIR:** 1 blackbox opcode  
**Backend:** ~30,000 UltraHonk gates (est.)

Every credential circuit uses `std::ecdsa_secp256k1::verify_signature` to prove
the issuer signed the commitment. This is **expected** — the ECDSA check is the
root of trust that binds a credential to a registered issuer. It is the single
largest contributor to proving time and **cannot be removed without replacing
the entire trust model**.

**ACIR visibility:** Because ECDSA is a blackbox function, it contributes only
1 opcode to the ACIR count, making the ACIR numbers look deceptively low. All
constraint-count differences between circuits come from the **non-ECDSA** logic.

### 2. Poseidon2 Commitment Hash (negligible)

**ACIR:** 4 opcodes  
**Backend:** ~200 gates (estimate)

The commitment hash `Poseidon2::hash([value, salt], 2)` is consistent across all
circuits and contributes negligible cost. This is the most efficient zk-friendly
hash available in Noir 1.0.0-beta.9. **No optimization needed.**

### 3. Field → Bytes Conversion (~577 ACIR opcodes)

**ACIR:** ~570–580 opcodes  
**Backend:** ~3,000 gates (estimate, range checks for 32 bytes)

`commitment.to_be_bytes()` is required to pass the 32-byte message to ECDSA
verification. Each byte needs a range check. This is the **second-largest ACIR
contributor** but still small relative to ECDSA backend cost.

**Potential optimization:** If the ECDSA blackbox could accept a field element
directly (instead of bytes), these ~577 opcodes would be eliminated. This
requires a Noir stdlib or Barretenberg change — track upstream.

### 4. Type-Specific Logic (0–26 ACIR opcodes)

These are negligible in the overall constraint budget:

| Circuit | Extra Opcodes | Operations | Cost per op |
|---------|---------------|------------|-------------|
| `kyc_proof` | 0 (baseline) | None | — |
| `income_proof` | +6 | `income ≥ threshold` (u64) | ~6 |
| `funds_proof` | +6 | `balance ≥ threshold` (u64) | ~6 |
| `accreditation_proof` | +6 | `net_worth ≥ threshold` (u64) | ~6 |
| `age_proof` | +19 | subtract, divide by 365, compare | ~7/7/5 |
| `jurisdiction_proof` | +25 | 8 × `country_code ≠ restricted[i]` | ~3 |

## Per-Circuit Analysis & Optimization Suggestions

### `commit` — 4 opcodes

**Purpose:** Witness-only helper for deriving credential commitments. Never proven.

**Finding:** Trivial — 4 Poseidon2 opcodes. No optimization needed.

### `kyc_proof` — 582 opcodes

**Purpose:** Proves knowledge of a KYC secret bound to an issuer-signed commitment.

**Structure:** Poseidon2 → to_be_bytes → ECDSA. No threshold logic.

**Finding:** Minimal, well-structured baseline. The 582 is essentially the fixed
cost of any credential proof.

**Optimization suggestion:** None needed at the circuit level. This is the lower
bound for any circuit that requires ECDSA + commitment.

### `income_proof` — 588 opcodes

**Purpose:** Proves income ≥ threshold.

**Structure:** kyc_proof + `income ≥ threshold` (u64 comparison).

**Finding:** The +6 opcode delta is the u64 comparison. Efficient.

**Optimization suggestion:** Merge `income_proof`, `funds_proof`, and
`accreditation_proof` into a single **generic `threshold_proof`** circuit
parameterized by the credential type. All three have identical structure and
constraint counts — only the input name differs. This reduces code duplication
(3 Nargo.toml packages → 1) and simplifies the build matrix without changing
constraints.

### `funds_proof` — 588 opcodes

**Purpose:** Proves account balance ≥ threshold.

**Structure:** Identical to `income_proof`.

**Finding:** Same as income_proof.

**Optimization suggestion:** See `income_proof` — merge into generic threshold circuit.

### `accreditation_proof` — 588 opcodes

**Purpose:** Proves net worth ≥ threshold for accredited investor verification.

**Structure:** Identical to `income_proof`.

**Finding:** Same as income_proof.

**Optimization suggestion:** See `income_proof` — merge into generic threshold circuit.

### `age_proof` — 601 opcodes

**Purpose:** Proves `age_years ≥ threshold_years` from a concealed date of birth.

**Structure:** kyc_proof + date comparison + subtraction + division by 365 +
threshold comparison.

**Finding:** The division by 365 is the sole differentiator from other threshold
circuits (+13 opcodes for the division over a plain comparison). In Noir, integer
division uses the `directive_integer_quotient` directive (8 opcodes) and generates
additional constraints.

**Optimization suggestion:** Replace `(current_date - date_of_birth) / 365` with
a **multiplication-based check**:

```noir
// Instead of:
//   let age_years = (current_date - date_of_birth) / 365;
//   assert(age_years >= threshold_years);
//
// Use:
assert(current_date >= date_of_birth + threshold_years * 365);
```

This eliminates the division entirely. The multiplication `threshold_years * 365`
is a constant-time operation when `threshold_years` is a circuit input (the Noir
compiler can precompute or use efficient multiplication). Expected ACIR savings:
~10–15 opcodes (eliminates the constrained range checks, bit decompositions,
and comparison operations that verify the division result; the unconstrained
`directive_integer_quotient` itself is a witness-only hint that does not
contribute to ACIR counts — see the note in "What drives the ~577 opcodes?").
Backend gate savings are an estimated ~2,000 (not yet profiled with `bb`).

### `jurisdiction_proof` — 607 opcodes

**Purpose:** Proves residence country is NOT in a restricted list of 8 entries.

**Structure:** kyc_proof + 8 unrolled loop iterations of `assert(code ≠ restricted[i])`.

**Finding:** Each loop iteration costs ~3 opcodes (u64 inequality check). The
loop unrolling is necessary because Noir does not support dynamic loops. If the
restricted list grows beyond 8, constraint count will grow linearly.

**Optimization suggestions (two-tiered):**

1. **Short-term (list stays small):** Keep the unrolled loop. At ~3 opcodes per entry
   and lists of <20 entries, the cost is negligible relative to ECDSA.

2. **Long-term (list grows large):** Replace linear scan with a **sorted Merkle
   inclusion check**. The holder proves their country code is NOT in a
   publicly-known restricted Merkle tree by proving non-membership (e.g., via
   sorted leaf ordering: prove two adjacent leaves `a < code < b` with no gap).
   This makes the jurisdiction check **O(log n)** instead of **O(n)**.

## Key Findings

1. **ECDSA dominates backend cost** (~30,000 gates) across all circuits, but
   appears as only 1 ACIR opcode due to blackbox treatment. Future constraint
   optimization should focus on backend gate profiling, not just ACIR counts.

2. **Field→bytes conversion is the largest ACIR contributor** (~570 opcodes)
   and is the most promising target for ACIR-level optimization if the Noir
   stdlib ever supports ECDSA verification directly on field elements.

3. **Type-specific logic is negligible** (0–26 opcodes, <5% of ACIR, <0.1% of
   backend gates). Optimization effort here yields diminishing returns.

4. **Three circuits are structurally identical** (`income_proof`, `funds_proof`,
   `accreditation_proof`) — all have 588 opcodes. Merging them into a single
   parameterized circuit would reduce code duplication without changing constraints.

5. **age_proof division is unnecessary.** The division by 365 can be replaced
   with multiplication, saving ~10–15 ACIR opcodes and ~2,000 backend gates.

6. **jurisdiction_proof scales linearly** with the restricted list size. At 8
   entries (25 extra opcodes) this is fine, but a Merkle-based approach should
   be evaluated if lists grow.

## Baseline Commitment

These numbers are committed as the **baseline for Noir 1.0.0-beta.9 + bb v0.87.0**.
Any circuit change PR should re-run `nargo info` and update this document,
noting the delta and whether it represents a regression or improvement.

```bash
# Reproduce:
noirup -v 1.0.0-beta.9
cd circuits/
for d in commit kyc_proof income_proof funds_proof accreditation_proof age_proof jurisdiction_proof; do
  echo "=== $d ===" && cd "$d" && nargo info && cd -
done
```
- `value`: The numerical representation of the credential attribute (see `attributeToValue` below).
- `salt`: A cryptographically secure random `Field` element to prevent rainbow-table attacks.
- The output `commitment` is a single `Field` element.

### ECDSA Signing Convention
Issuers sign the `commitment` to attest to its validity using **secp256k1 ECDSA**.
- **Prehash**: `false`. The circuit expects the signature over the raw 32-byte big-endian representation of the `commitment`, *not* a sha256 hash of it. 
- The circuit verifies the signature against the issuer's public key (`issuer_x` and `issuer_y` coordinates).

### Verifier Key (VK) Determinism
The VK for each circuit is strictly deterministic based on the Noir circuit logic and the exact compiler toolchain version. 
- Current toolchain version pinned for verification: `noirup -v 1.0.0-beta.9`
- Any change to the Noir source code or the compiler version will produce a different VK. The VK deployed to the on-chain `CredentialVerifier` via `set_vk` must perfectly match the VK generated by the issuers/provers using this pinned toolchain, otherwise proofs will fail to verify.

### Test Vectors

`circuits/testvectors/<circuit>.json` pins, per circuit, the exact witness in its committed `Prover.toml`, the public inputs it derives, and a `sha256` hash of the resulting Barretenberg VK — captured with the pinned toolchain above. `circuits/scripts/testvectors.js check` (run in CI on every push/PR) recompiles and re-proves each circuit from its committed `Prover.toml` and fails the build if any of those three drift from what's committed, so a circuit-logic change, a witness edit, or a toolchain bump that silently changes proof output gets caught instead of surfacing later as an on-chain verification failure.

To regenerate the vectors intentionally (after a deliberate circuit change or a pinned toolchain bump — update `NOIR_VERSION`/`BB_VERSION` in `circuits/scripts/testvectors.js` first if it's the latter):

```bash
export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"
node circuits/scripts/testvectors.js update
```

Review the diff before committing — every field changing except `witness` usually means something other than the intended change moved.

---

## `attributeToValue` Mapping

To securely commit to human-readable attributes, issuers must map them to `Field` or `u64` values:

- **KYC (`kyc_proof`)**: The value is a random `Field` element acting as a secret, representing a successful KYC verification.
- **Age (`age_proof`)**: The value is the holder's Date of Birth (DOB) represented as **days since the Unix epoch** (e.g., `Jan 1 1990` = `7305`).
- **Income (`income_proof`)**: The value is the holder's annual income represented as a `u64` in whole currency units (e.g., whole USD).
- **Funds (`funds_proof`)**: The value is the holder's account balance represented as a `u64` in whole currency units.
- **Accreditation (`accreditation_proof`)**: The value is the holder's net worth represented as a `u64` in whole currency units.
- **Jurisdiction (`jurisdiction_proof`)**: The value is the country of residence represented as its **ISO 3166-1 numeric** code (e.g., US = `840`, IR = `364`, KP = `408`). Unused slots in a restricted list are padded with `0`.

---

## Circuit Public Inputs

The following tables define the ABI order of public inputs for each credential circuit.

### `kyc_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([secret, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |

### `age_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([date_of_birth, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |
| 3 | `current_date` | `u64` | Current date as days since Unix epoch |
| 4 | `threshold_years` | `u64` | Minimum required age in years |

### `income_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([income, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |
| 3 | `threshold` | `u64` | Minimum required annual income |

### `funds_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([balance, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |
| 3 | `threshold` | `u64` | Minimum required account balance |

### `accreditation_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([net_worth, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |
| 3 | `threshold` | `u64` | Minimum required net worth |

### `jurisdiction_proof`
| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `commitment` | `Field` | `Poseidon2([country_code, salt], 2)` |
| 1 | `issuer_x` | `[u8; 32]` | Issuer secp256k1 public key X coordinate |
| 2 | `issuer_y` | `[u8; 32]` | Issuer secp256k1 public key Y coordinate |
| 3 | `restricted` | `[u64; 8]` | List of up to 8 restricted ISO 3166-1 numeric codes (padded with `0`s) |
