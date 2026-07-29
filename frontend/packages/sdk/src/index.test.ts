import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  configure,
  hasClaim,
  getClaims,
  buildVerifyUrl,
  watchClaim,
  TimeoutError,
  CLAIM_TYPES,
} from "./index.js";

// Mock the ProofRegistryClient
vi.mock("../../proof-registry/src/index.js", () => ({
  Client: vi.fn().mockImplementation(() => ({
    is_verified: vi.fn(),
    check_claim: vi.fn(),
  })),
}));

import { Client as ProofRegistryClient } from "../../proof-registry/src/index.js";

describe("StellarCred SDK", () => {
  let mockClient: any;

  beforeEach(() => {
    // Reset configuration before each test
    configure({
      registryId: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      rpcUrl: "https://soroban-testnet.stellar.org",
      networkPassphrase: "Test SDF Network ; September 2015",
      baseUrl: "https://stellarcred.xyz",
    });

    // Create fresh mock for each test
    mockClient = {
      is_verified: vi.fn(),
      check_claim: vi.fn(),
    };
    
    (ProofRegistryClient as any).mockImplementation(() => mockClient);
    
    // Setup fake timers for watchClaim tests
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.restoreCurrentDate();
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  describe("hasClaim", () => {
    it("returns false when no registryId configured", async () => {
      configure({ registryId: "" });
      
      const result = await hasClaim("GTEST", "kyc");
      
      expect(result).toBe(false);
      expect(mockClient.is_verified).not.toHaveBeenCalled();
      expect(mockClient.check_claim).not.toHaveBeenCalled();
    });

    it("calls readIsVerified when no minThreshold", async () => {
      mockClient.is_verified.mockResolvedValue({
        result: [true, BigInt(1000), BigInt(2000)],
      });
      
      const result = await hasClaim("GTEST", "kyc");
      
      expect(result).toBe(true);
      expect(mockClient.is_verified).toHaveBeenCalledWith({
        holder: "GTEST",
        credential_type: "kyc",
        trusted_issuers: undefined,
      });
      expect(mockClient.check_claim).not.toHaveBeenCalled();
    });

    it("calls readCheckClaim when minThreshold is set", async () => {
      mockClient.check_claim.mockResolvedValue({
        result: true,
      });
      
      const result = await hasClaim("GTEST", "age", { minThreshold: 21 });
      
      expect(result).toBe(true);
      expect(mockClient.check_claim).toHaveBeenCalledWith({
        holder: "GTEST",
        credential_type: "age",
        min_threshold: BigInt(21),
        trusted_issuers: undefined,
      });
      expect(mockClient.is_verified).not.toHaveBeenCalled();
    });

    it("returns false when readIsVerified returns false", async () => {
      mockClient.is_verified.mockResolvedValue({
        result: [false, BigInt(1000), BigInt(2000)],
      });
      
      const result = await hasClaim("GTEST", "kyc");
      
      expect(result).toBe(false);
    });

    it("returns false when readCheckClaim returns below threshold", async () => {
      mockClient.check_claim.mockResolvedValue({
        result: false,
      });
      
      const result = await hasClaim("GTEST", "funds", { minThreshold: 50000 });
      
      expect(result).toBe(false);
    });
  });

  describe("getClaims", () => {
    it("filters out null claims", async () => {
      // Mock is_verified to return valid claim for 'kyc', null for 'age'
      mockClient.is_verified
        .mockResolvedValueOnce({ result: [true, BigInt(1000), BigInt(2000)] }) // kyc
        .mockResolvedValueOnce({ result: null }) // age
        .mockResolvedValueOnce({ result: [true, BigInt(1500), BigInt(2500)] }) // income
        .mockResolvedValueOnce({ result: null }) // jurisdiction
        .mockResolvedValueOnce({ result: null }) // funds
        .mockResolvedValueOnce({ result: null }); // accreditation
      
      const result = await getClaims("GTEST");
      
      expect(result).toHaveLength(2);
      expect(result.some(c => c.type === "kyc")).toBe(true);
      expect(result.some(c => c.type === "income")).toBe(true);
      expect(result.some(c => c.type === "age")).toBe(false);
    });

    it("maps verifiedAt to a number", async () => {
      mockClient.is_verified.mockResolvedValue({
        result: [true, BigInt(1609459200), BigInt(2000000000)], // Unix timestamp as BigInt
      });
      
      const result = await getClaims("GTEST");
      
      expect(result).toHaveLength(1);
      expect(result[0].verifiedAt).toBe(1609459200);
      expect(typeof result[0].verifiedAt).toBe("number");
    });

    it("maps expiry to a number", async () => {
      mockClient.is_verified.mockResolvedValue({
        result: [true, BigInt(1000), BigInt(1609459200)], // Unix timestamp as BigInt
      });
      
      const result = await getClaims("GTEST");
      
      expect(result).toHaveLength(1);
      expect(result[0].expiry).toBe(1609459200);
      expect(typeof result[0].expiry).toBe("number");
    });

    it("filters out claims with invalid/missing required fields", async () => {
      // Mock first call to return invalid (false) claim, second to return valid
      mockClient.is_verified
        .mockResolvedValueOnce({ result: [false, BigInt(1000), BigInt(2000)] }) // kyc - invalid
        .mockResolvedValueOnce({ result: [true, BigInt(1500), BigInt(2500)] }) // age - valid
        .mockResolvedValueOnce({ result: null }) // income - null
        .mockResolvedValueOnce({ result: null }) // jurisdiction - null
        .mockResolvedValueOnce({ result: null }) // funds - null
        .mockResolvedValueOnce({ result: null }); // accreditation - null
      
      const result = await getClaims("GTEST");
      
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe("age");
    });
  });

  describe("buildVerifyUrl", () => {
    it("sets age param correctly", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "age",
        claimParams: { threshold_years: "21" },
      });
      
      expect(url).toContain("threshold_years=21");
      expect(url).toContain("claim=age");
    });

    it("sets income param correctly", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "income",
        claimParams: { threshold: "50000" },
      });
      
      expect(url).toContain("threshold=50000");
      expect(url).toContain("claim=income");
    });

    it("sets funds param correctly", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "funds",
        claimParams: { threshold: "100000" },
      });
      
      expect(url).toContain("threshold=100000");
      expect(url).toContain("claim=funds");
    });

    it("sets jurisdiction param correctly", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "jurisdiction",
      });
      
      expect(url).toContain("claim=jurisdiction");
    });

    it("handles restricted as array", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "jurisdiction",
        claimParams: { restricted: ["US", "CN"] },
      });
      
      expect(url).toContain("restricted=US%2CCN");
    });

    it("handles restricted as string", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "jurisdiction",
        claimParams: { restricted: "US" },
      });
      
      expect(url).toContain("restricted=US");
    });

    it("uses base URL override when provided", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "kyc",
        baseUrl: "https://custom.stellarcred.xyz",
      });
      
      expect(url).toStartWith("https://custom.stellarcred.xyz");
    });

    it("uses default base URL when no override", () => {
      const url = buildVerifyUrl({
        returnUrl: "/test",
        claim: "kyc",
      });
      
      expect(url).toStartWith("https://stellarcred.xyz");
    });
  });

  describe("watchClaim", () => {
    beforeEach(() => {
      vi.clearAllTimers();
    });

    it("Promise form resolves when claim is verified", async () => {
      let callCount = 0;
      mockClient.is_verified.mockImplementation(async () => {
        callCount++;
        return {
          result: callCount >= 2 ? [true, BigInt(1000), BigInt(2000)] : [false, BigInt(0), BigInt(0)],
        };
      });
      
      const promise = watchClaim("GTEST", "kyc", { pollMs: 1000, timeoutMs: 10000 });
      
      // Fast-forward time to trigger the second poll
      vi.advanceTimersByTime(1000);
      await vi.runAllTimersAsync();
      
      const result = await promise;
      expect(result).toBe(true);
    });

    it("Promise form rejects with TimeoutError on timeout", async () => {
      mockClient.is_verified.mockResolvedValue({
        result: [false, BigInt(0), BigInt(0)],
      });
      
      const promise = watchClaim("GTEST", "kyc", { pollMs: 1000, timeoutMs: 2000 });
      
      // Fast-forward past timeout
      vi.advanceTimersByTime(2000);
      await vi.runAllTimersAsync();
      
      await expect(promise).rejects.toThrow(TimeoutError);
    });

    it("Callback form fires onChange when state changes", async () => {
      const onChange = vi.fn();
      let callCount = 0;
      
      mockClient.is_verified.mockImplementation(async () => {
        callCount++;
        return {
          result: callCount >= 2 ? [true, BigInt(1000), BigInt(2000)] : [false, BigInt(0), BigInt(0)],
        };
      });
      
      const stop = watchClaim("GTEST", "kyc", { 
        pollMs: 1000, 
        timeoutMs: 10000, 
        onChange 
      });
      
      // Initial call should happen immediately, then advance for second call
      await vi.runOnlyPendingTimersAsync();
      vi.advanceTimersByTime(1000);
      await vi.runOnlyPendingTimersAsync();
      
      expect(onChange).toHaveBeenCalledWith(true);
      stop();
    });

    it("Callback form does not fire onChange when state is unchanged", async () => {
      const onChange = vi.fn();
      
      mockClient.is_verified.mockResolvedValue({
        result: [false, BigInt(0), BigInt(0)],
      });
      
      const stop = watchClaim("GTEST", "kyc", { 
        pollMs: 1000, 
        timeoutMs: 5000, 
        onChange 
      });
      
      // Initial call + two more polls
      await vi.runOnlyPendingTimersAsync();
      vi.advanceTimersByTime(2000);
      await vi.runOnlyPendingTimersAsync();
      
      // onChange should not be called since state remained false
      expect(onChange).not.toHaveBeenCalled();
      stop();
    });

    it("stop() cancels polling", async () => {
      const onChange = vi.fn();
      
      mockClient.is_verified.mockResolvedValue({
        result: [false, BigInt(0), BigInt(0)],
      });
      
      const stop = watchClaim("GTEST", "kyc", { 
        pollMs: 1000, 
        timeoutMs: 10000, 
        onChange 
      });
      
      // Stop immediately
      stop();
      
      // Advance time - no calls should happen
      vi.advanceTimersByTime(2000);
      await vi.runOnlyPendingTimersAsync();
      
      expect(mockClient.is_verified).toHaveBeenCalledTimes(1); // Only initial call
    });
  });
});