# Issuer Key Rotation and Emergency Revocation

Operational procedure for rotating an issuer's secp256k1 signing key without
invalidating the credentials it has already issued, and for killing a key
immediately when it is compromised.

Applies to `IssuerRegistry` (version 1.1.0 and later). ProofRegistry
(`submit_proof`, `submit_proofs`, `submit_aggregate_proof`) is the consumer that
benefits; it verifies proofs against the issuer's **key set** rather than a
single registered key.

---

## 1. Why this exists

A credential is bound to the secp256k1 key that signed it: the circuit verifies
the issuer signature over the commitment, and the key travels with the proof as
a public input. While `IssuerRegistry` held exactly one key per issuer, any key
change silently invalidated every credential already in a holder's wallet —
submissions failed with `IssuerKeyMismatch` and there was no migration path.

An issuer now holds a **key set**:

| | Current key | Retired key |
|---|---|---|
| Backs new issuance | yes | no |
| Backs already-issued credentials | yes | yes, until its validity window closes |
| Can be revoked | yes (issuance stops) | yes (verification stops) |
| Validity window | none (open-ended) | `(retired_at, valid_until]` |

---

## 2. Choosing a path

| Situation | Path | Effect on outstanding credentials |
|---|---|---|
| Scheduled rotation, HSM/HSM migration, routine key hygiene | **Rotate** (§3) | keep verifying until their natural expiry |
| Suspected or confirmed key compromise | **Revoke** (§4), then **Rotate** (§3) | stop verifying immediately |

Rotation is the default. Revocation is the emergency path and is deliberately
unforgiving: it ignores the validity window.

---

## 3. Procedure A — rotation (the normal path)

**Preconditions**

- The new key pair is generated in the issuer's signing environment (KMS/HSM or
  equivalent). The private key must never touch a build artefact or a browser.
- You hold the `admin` role on `IssuerRegistry`. Key management is admin-only,
  like issuer registration itself; an issuer cannot rewrite the registry's view
  of its own key.
- You know the latest expiry among the issuer's outstanding credentials. That is
  the value the window must cover.

**Step 1 — pick the window**

```
old_key_valid_until = max(expiry of every outstanding credential of this issuer)
```

Constraints enforced on-chain:

- `old_key_valid_until` must be **strictly greater** than the current ledger
  timestamp, and at most **366 days** ahead (`MAX_KEY_RETENTION_SECS`). This
  matches `ProofRegistry`'s one-year maximum credential TTL, so any credential
  the protocol is willing to accept can always be covered by one window.
- Too short and holders' credentials break before they expire
  (`IssuerKeyMismatch`). Too long and a leaked retired key keeps working for
  longer than necessary.

**Step 2 — rotate**

```bash
stellar contract invoke \
  --id "$ISSUER_REGISTRY_ID" \
  --source "$ADMIN_KEY" \
  --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  --send yes \
  -- rotate_issuer_key \
  --issuer_id "$ISSUER_ADDRESS" \
  --new_pubkey "$NEW_PUBKEY_HEX" \
  --old_key_valid_until "$OLD_KEY_VALID_UNTIL"
```

The previous key is retired with the window above and `new_pubkey` becomes the
key used for all new issuance. The issuer's credential-type trust is unchanged.

**Step 3 — verify**

```bash
# Current signing key is the new one.
stellar contract invoke --id "$ISSUER_REGISTRY_ID" --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  -- get_issuer_pubkey --issuer_id "$ISSUER_ADDRESS"

# Both the new key and the retired one still verify.
stellar contract invoke --id "$ISSUER_REGISTRY_ID" --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  -- is_valid_issuer_key --issuer_id "$ISSUER_ADDRESS" --pubkey "$NEW_PUBKEY_HEX"

# Full key set, current key first.
stellar contract invoke --id "$ISSUER_REGISTRY_ID" --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  -- get_issuer_keys --issuer_id "$ISSUER_ADDRESS"
```

Then confirm end to end that a credential **signed before** the rotation still
submits and reads back as verified (`is_verified(holder, credential_type)`).

**Step 4 — switch the signing environment**

Point issuance at the new key only after Step 3 passes. Credentials signed with
the old key after the window closes will be rejected, so the cutover must land
before `old_key_valid_until`.

**Step 5 — keep the key history alive (keeper job)**

The retired-key history lives in a persistent entry with the contract's normal
entry lifetime (~120 days, refreshed by every rotation and revocation). When
that entry lapses, a retired key stops verifying even if its validity window is
still open — so a window longer than the entry lifetime needs periodic
maintenance:

```bash
stellar contract invoke --id "$ISSUER_REGISTRY_ID" --source "$ADMIN_KEY" \
  --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" --send yes \
  -- refresh_issuer_keys_ttl --issuer_id "$ISSUER_ADDRESS"
```

It is admin-only, emits no event, and only extends the entry lifetime — it
cannot change which keys are valid. Schedule it for every issuer that has
rotated, well inside the entry lifetime (a monthly cron is ample).

### Notes and limits

- Up to **8 retired keys** are retained per issuer. Entries whose window has
  closed are pruned automatically on the next rotation, so a long-lived issuer
  can rotate repeatedly; you only hit the cap if you perform more than eight
  rotations whose windows overlap.
- A retired key cannot be re-installed as the current key
  (`KeyAlreadyRetired`) — that would revive credentials signed with it.
- Re-registering an existing issuer with a *different* pubkey is rejected
  (`KeyChangeRequiresRotation`). Re-registration still updates credential types.
  This is deliberate: it is the path that used to invalidate credentials
  silently.
- Rotation does not un-revoke a revoked issuer; a fully revoked issuer stays
  revoked regardless of its key set.

---

## 4. Procedure B — emergency revocation (compromise)

Use this when a signing key may be in someone else's hands. Revocation is
immediate and idempotency is explicit (a second attempt fails rather than
silently succeeding).

**Step 1 — kill the key**

```bash
stellar contract invoke \
  --id "$ISSUER_REGISTRY_ID" \
  --source "$ADMIN_KEY" \
  --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  --send yes \
  -- revoke_issuer_key \
  --issuer_id "$ISSUER_ADDRESS" \
  --pubkey "$COMPROMISED_PUBKEY_HEX"
```

The key can be either:

- **a retired key** still inside its window — proofs signed with it stop
  verifying on the next ledger, even though the window has not closed. The
  issuer keeps issuing normally.
- **the current key** — the issuer can no longer issue: `is_valid_issuer`
  returns false, so no new submission for that issuer is accepted. The issuer is
  blocked until Step 2, and the admin performs Step 2 on its behalf.

**Step 2 — install a replacement key**

Run §3 with a freshly generated key. Because the current key was revoked, the
rotation records it in history as revoked (never valid) and clears the issuer's
blocked state. Outstanding credentials signed with *other*, non-revoked retired
keys keep verifying until their own windows close.

**Step 3 — investigate the blast radius**

Credentials signed with the revoked key no longer verify anywhere in the
protocol, including ones already submitted and cached: read them again with
`is_verified` after revoking rather than trusting a pre-incident cache. Ask
holders to re-derive their proofs with a credential signed by a live key.

---

## 5. Events to alert on

| Event | Topics | Meaning |
|---|---|---|
| `iss_reg.key_rot` | `("iss_reg", "key_rot")` | `EventIssuerKeyRotated { issuer, old_pubkey, new_pubkey, old_key_valid_until }` |
| `iss_reg.key_revk` | `("iss_reg", "key_revk")` | `EventIssuerKeyRevoked { issuer, pubkey, was_current, revoked_at }` |

Recommended alerts:

- **`key_revk`** — page immediately. This is either a compromise or a broken
  rotation; both need a human within minutes.
- **`key_rot`** — ticket for review. Confirm `old_key_valid_until` matches the
  issuer's outstanding credential expiries and that the cutover to the new
  signing key happened before the window closes.
- **`key_rot` for an issuer you did not schedule** — treat as `key_revk`.

Full event schemas: [EVENTS.md](../EVENTS.md).

---

## 6. Error codes

`IssuerRegistry` errors (see
[contract-error-codes.md](contract-error-codes.md) for the full table):

| Code | Variant | What to do |
|---|---|---|
| 6 | `KeyNotFound` | Key unknown to this issuer, or its window already closed — nothing to revoke. |
| 7 | `KeyAlreadyRevoked` | Already revoked; no action needed. |
| 8 | `KeyAlreadyRetired` | Refusing to re-install a live key from the history. |
| 9 | `KeyHistoryFull` | Eight retired keys are still inside their windows. Wait for one to expire, or revoke keys you no longer need. |
| 10 | `InvalidKeyWindow` | Window is empty or longer than 366 days. |
| 11 | `KeyAlreadyCurrent` | The new key is already current — nothing to rotate. |
| 12 | `KeyChangeRequiresRotation` | `register_issuer` cannot change a pubkey. Use `rotate_issuer_key`. |

`ProofRegistry` reports `IssuerKeyMismatch` (code 5) when the key in a proof's
public inputs is not in the issuer's live key set — either the window closed or
the key was revoked. It reports `IssuerNotTrusted` (code 4) when the issuer
itself is revoked or its current key was revoked.

---

## 7. Dry run on testnet

The contract tests in `contracts/issuer_registry/src/test.rs` and
`contracts/proof_registry/src/test.rs` cover both paths end to end, including
"a credential signed before the rotation still submits":

```bash
cargo test -p issuer_registry
cargo test -p proof_registry
```

For a manual testnet rehearsal, deploy to testnet, register an issuer, submit a
proof, then rotate and re-submit the same proof: it must still verify. Repeat
with `revoke_issuer_key` on the signing key: the submission must fail.
