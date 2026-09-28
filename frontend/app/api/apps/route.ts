import { NextResponse } from "next/server";
import rawDemoProtocols from "@/data/demo-protocols.json";

export const dynamic = "force-dynamic";

const INDEXER_URL = process.env.INDEXER_URL ?? "http://localhost:3001";

export async function GET() {
  // Fetch community / third-party apps from the indexer.
  let communityApps: unknown[] = [];
  try {
    const res = await fetch(`${INDEXER_URL}/apps`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });

    if (res.ok) {
      const data = await res.json();
      communityApps = data.apps ?? [];
    }
  } catch {
    // Indexer unavailable — fall through with an empty list.
  }

  return NextResponse.json({
    // Demo protocols are served first so the UI can render them immediately
    // even when the indexer is unreachable.  The `isDemo: true` field lets
    // consumers visually distinguish them from real integrations.
    demos: rawDemoProtocols,
    apps: communityApps,
  });
}
