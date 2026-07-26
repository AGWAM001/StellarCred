/**
 * In-memory idempotency store for the /api/issue endpoint.
 *
 * Design:
 * - Stores opaque key → serialized response (status, body, headers) with a TTL.
 * - The key is an opaque ID from the `Idempotency-Key` header; the store itself
 *   tracks no identity fields (no userId, no walletAddress, no PII).
 * - Expired entries are lazily purged on access and periodically during sets.
 * - All data is in-memory only — server restart clears everything.
 */

export interface CachedResponse {
  status: number;
  body: string; // JSON-stringified response body
  headers: Record<string, string>;
  createdAt: number; // Date.now() timestamp
}

/** Default TTL: 60 seconds (configurable via IDEMPOTENCY_TTL_SECONDS env var). */
const DEFAULT_TTL_SECONDS = 60;

function ttlMs(): number {
  const env = process.env.IDEMPOTENCY_TTL_SECONDS;
  if (env) {
    const parsed = parseInt(env, 10);
    if (Number.isFinite(parsed) && parsed > 0) return parsed * 1000;
  }
  return DEFAULT_TTL_SECONDS * 1000;
}

const store = new Map<string, CachedResponse>();

/**
 * Retrieve a cached response by idempotency key.
 * Returns `null` if the key is not found or the entry has expired.
 */
export function idempotencyGet(key: string): CachedResponse | null {
  const entry = store.get(key);
  if (!entry) return null;

  if (Date.now() - entry.createdAt > ttlMs()) {
    store.delete(key);
    return null;
  }

  return entry;
}

/**
 * Store a response under an idempotency key with the current timestamp.
 */
export function idempotencySet(key: string, response: CachedResponse): void {
  store.set(key, response);

  // Lazy cleanup: purge all expired entries every 100 new keys to avoid
  // unbounded growth. Skip on the very first set (size 0 would also match).
  if (store.size >= 100 && store.size % 100 === 0) {
    idempotencyCleanup();
  }
}

/**
 * Remove all expired entries from the store.
 * Useful for testing and periodic maintenance.
 */
export function idempotencyCleanup(): void {
  const now = Date.now();
  const ttl = ttlMs();
  for (const [key, entry] of store) {
    if (now - entry.createdAt > ttl) {
      store.delete(key);
    }
  }
}

/**
 * Clear the entire store. Only exposed for testing.
 */
export function idempotencyClear(): void {
  store.clear();
}

/**
 * Return the number of entries in the store. Only exposed for testing.
 */
export function idempotencySize(): number {
  return store.size;
}
