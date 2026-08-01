import { useState, useEffect, useCallback, useRef } from "react";
import {
  createClaimGate,
  type ClaimGate,
  type ClaimGateState,
} from "./core";
import type { ClaimType } from "./index";

/**
 * Configuration options for the `useStellarCred` React hook.
 *
 * @example
 * ```tsx
 * const { claims } = useStellarCred(wallet, {
 *   claims: ["kyc", "age"],
 *   minThresholds: { age: 21 },
 * });
 * ```
 */
export interface UseStellarCredOptions {
  claims?: ClaimType[];
    /**
   * Minimum thresholds for parameterized claims.
   *
   * Example:
   * {
   *   age: 21,
   *   funds: 50000,
   * }
   */
  minThresholds?: Partial<Record<ClaimType, number>>;
}

/**
 * Result returned by the `useStellarCred` React hook.
 *
 * @example
 * ```tsx
 * const { claims, loading, error, refetch } = useStellarCred(wallet);
 * ```
 */
export interface UseStellarCredResult {
  claims: Partial<Record<ClaimType, boolean>> | null;
  loading: boolean;
  error: Error | null;
  refetch: () => void;
}

/**
 * React hook for checking StellarCred claims for a wallet.
 *
 * The hook automatically fetches claim verification status when the wallet
 * changes and exposes loading, error, and refetch state.
 *
 * @param wallet Stellar wallet address, or `null` when disconnected.
 * @param options Optional configuration for which claims to check.
 *
 * @returns Current claim status, loading state, any error, and a refetch function.
 *
 * @example
 * ```tsx
 * const { claims, loading } = useStellarCred(wallet, {
 *   claims: ["kyc", "age"],
 * });
 * ```
 */
export function useStellarCred(
  wallet: string | null,
  options?: UseStellarCredOptions
): UseStellarCredResult {
  const [state, setState] = useState<ClaimGateState>(EMPTY_STATE);
  const gateRef = useRef<ClaimGate | null>(null);

    try {
      const typesToCheck: ClaimType[] =
        options?.claims || ["kyc", "age", "jurisdiction", "income", "funds", "accreditation"];

      // One batched read shares a single client across all types; per-type
      // failures resolve to `false` inside `hasClaims`.
      const results = await StellarCred.hasClaims(wallet, typesToCheck, {
        minThresholds: options?.minThresholds,
      });

    const unsub = gate.subscribe(setState);

    return () => {
      unsub();
      gate.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet, JSON.stringify(options?.claims), JSON.stringify(options?.minThresholds)]);

  return {
    claims: state.claims,
    loading: state.loading,
    error: state.error,
    refetch,
  };
}
