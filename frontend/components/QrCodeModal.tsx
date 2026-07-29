"use client";

import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import CopyButton from "./CopyButton";
import { toQrDataUrl } from "@/lib/qr";

export function QrCodeModal({
  title,
  value,
  hint,
  onClose,
}: {
  title: string;
  value: string;
  /** Explanatory copy shown under the QR code. */
  hint?: string;
  onClose: () => void;
}) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setDataUrl(null);
    setError("");
    toQrDataUrl(value)
      .then((url) => { if (!cancelled) setDataUrl(url); })
      .catch(() => { if (!cancelled) setError("Couldn't generate QR code."); });
    return () => { cancelled = true; };
  }, [value]);

  return (
    <Modal title={title} onClose={onClose}>
      <div style={{ textAlign: "center" }}>
        {error ? (
          <p style={{ color: "var(--danger)", fontSize: "0.875rem" }}>{error}</p>
        ) : (
          <div
            style={{
              width: 240,
              height: 240,
              margin: "0 auto",
              display: "grid",
              placeItems: "center",
              borderRadius: "var(--radius)",
              background: "#fff",
            }}
          >
            {dataUrl && (
              // eslint-disable-next-line @next/next/no-img-element -- data: URL, not an optimizable remote image
              <img src={dataUrl} alt="QR code" width={224} height={224} />
            )}
          </div>
        )}

        {hint && (
          <p className="faint" style={{ fontSize: "0.8125rem", marginTop: "1rem", lineHeight: 1.6 }}>
            {hint}
          </p>
        )}

        <div className="row" style={{ marginTop: "1rem", justifyContent: "center", gap: "0.4rem" }}>
          <code
            className="mono faint"
            style={{
              fontSize: "0.72rem",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: 220,
            }}
          >
            {value}
          </code>
          <CopyButton value={value} />
        </div>
      </div>
    </Modal>
  );
}
