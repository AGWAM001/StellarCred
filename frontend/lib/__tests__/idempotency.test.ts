import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  idempotencyGet,
  idempotencySet,
  idempotencyCleanup,
  idempotencyClear,
  idempotencySize,
  CachedResponse,
} from "../idempotency";

function makeEntry(overrides: Partial<CachedResponse> = {}): CachedResponse {
  return {
    status: 200,
    body: JSON.stringify({ credentials: [{ type: "kyc", value: "0xabc" }] }),
    headers: { "content-type": "application/json" },
    createdAt: Date.now(),
    ...overrides,
  };
}

describe("idempotency store", () => {
  beforeEach(() => {
    idempotencyClear();
  });

  afterEach(() => {
    idempotencyClear();
  });

  describe("idempotencyGet", () => {
    it("returns null on cache miss (key not set)", () => {
      expect(idempotencyGet("key-1")).toBeNull();
    });

    it("returns the cached response on cache hit", () => {
      const entry = makeEntry();
      idempotencySet("key-1", entry);
      const cached = idempotencyGet("key-1");
      expect(cached).not.toBeNull();
      expect(cached!.status).toBe(200);
      expect(cached!.body).toBe(entry.body);
      expect(cached!.headers).toEqual(entry.headers);
    });

    it("returns null for a different key (independent keys)", () => {
      idempotencySet("key-a", makeEntry());
      expect(idempotencyGet("key-b")).toBeNull();
    });

    it("returns the correct response for each independent key", () => {
      const entryA = makeEntry({ status: 200 });
      const entryB = makeEntry({ status: 400, body: JSON.stringify({ error: "bad" }) });
      idempotencySet("key-a", entryA);
      idempotencySet("key-b", entryB);
      expect(idempotencyGet("key-a")!.status).toBe(200);
      expect(idempotencyGet("key-b")!.status).toBe(400);
    });

    it("returns null after TTL expiry", () => {
      // Use Date.now mocking to simulate passage of time.
      const now = Date.now();
      const nowSpy = vi.spyOn(Date, "now").mockReturnValue(now);
      idempotencySet("key-1", makeEntry({ createdAt: now }));

      // Advance time past the default 60-second TTL + 1 ms.
      nowSpy.mockReturnValue(now + 61_000);

      expect(idempotencyGet("key-1")).toBeNull();

      vi.restoreAllMocks();
    });

    it("still hits just before TTL expires", () => {
      const now = Date.now();
      const nowSpy = vi.spyOn(Date, "now").mockReturnValue(now);
      idempotencySet("key-1", makeEntry({ createdAt: now }));

      // 59 seconds later — still valid.
      nowSpy.mockReturnValue(now + 59_000);

      expect(idempotencyGet("key-1")).not.toBeNull();

      vi.restoreAllMocks();
    });

    it("returns null for empty string key (treated as missing)", () => {
      // Empty keys are not stored; the store handles them gracefully.
      expect(idempotencyGet("")).toBeNull();
    });
  });

  describe("idempotencySet", () => {
    it("stores an entry and increments size", () => {
      expect(idempotencySize()).toBe(0);
      idempotencySet("key-1", makeEntry());
      expect(idempotencySize()).toBe(1);
    });

    it("overwrites an existing entry with the same key", () => {
      idempotencySet("key-1", makeEntry({ status: 200 }));
      idempotencySet("key-1", makeEntry({ status: 202 }));
      expect(idempotencySize()).toBe(1);
      expect(idempotencyGet("key-1")!.status).toBe(202);
    });
  });

  describe("idempotencyCleanup", () => {
    it("removes expired entries but keeps fresh ones", () => {
      const now = Date.now();
      vi.spyOn(Date, "now").mockReturnValue(now);

      // Fresh entry.
      idempotencySet("fresh", makeEntry({ createdAt: now }));
      // Expired entry — manually set with old timestamp.
      idempotencySet("stale", makeEntry({ createdAt: now - 61_000 }));

      idempotencyCleanup();

      expect(idempotencyGet("fresh")).not.toBeNull();
      // Expired entry should have been cleaned up and also return null on get.
      expect(idempotencyGet("stale")).toBeNull();
      expect(idempotencySize()).toBe(1);

      vi.restoreAllMocks();
    });

    it("is a no-op when there are no expired entries", () => {
      idempotencySet("key-1", makeEntry());
      idempotencySet("key-2", makeEntry());
      const before = idempotencySize();
      idempotencyCleanup();
      expect(idempotencySize()).toBe(before);
    });
  });

  describe("idempotencyClear", () => {
    it("removes all entries", () => {
      idempotencySet("key-1", makeEntry());
      idempotencySet("key-2", makeEntry());
      expect(idempotencySize()).toBe(2);
      idempotencyClear();
      expect(idempotencySize()).toBe(0);
    });
  });

  describe("idempotencySize", () => {
    it("returns 0 for an empty store", () => {
      expect(idempotencySize()).toBe(0);
    });

    it("returns the correct count after multiple sets", () => {
      idempotencySet("a", makeEntry());
      idempotencySet("b", makeEntry());
      idempotencySet("c", makeEntry());
      expect(idempotencySize()).toBe(3);
    });
  });
});
