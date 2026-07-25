import { useState, useEffect, useCallback, useRef } from "react";
import { StellarCred, type ClaimType } from "./index";

interface UseStellarCredOptions {
  claims?: ClaimType[];
  minThresholds?: Partial<Record<ClaimType, number>>;
}

interface UseStellarCredResult {
  claims: Partial<Record<ClaimType, boolean>> | null;
  loading: boolean;
  error: Error | null;
  refetch: () => void;
}

const EMPTY_STATE: ClaimGateState = {
  claims: null,
  loading: true,
  error: null,
};

/**
 * React hook for checking StellarCred claims.
 *
 * Re-implemented on top of the framework-agnostic `createClaimGate` core to
 * prove the core is sufficient for any framework. No behavior change versus
 * the previous implementation.
 */
export function useStellarCred(
  wallet: string | null,
  options?: UseStellarCredOptions
): UseStellarCredResult {
  const [state, setState] = useState<ClaimGateState>(EMPTY_STATE);
  const gateRef = useRef<ClaimGate | null>(null);

    try {
      const typesToCheck = options?.claims || ["kyc", "age", "jurisdiction", "income", "funds", "accreditation"];
      const results: Partial<Record<ClaimType, boolean>> = {};

  useEffect(() => {
    const gate = createClaimGate({
      wallet,
      claims: options?.claims,
      minThresholds: options?.minThresholds,
    });
    gateRef.current = gate;

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
