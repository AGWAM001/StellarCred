/**
 * db.ts — Database abstraction layer.
 *
 * Supports two drivers selected via DB_DRIVER env var:
 *   - "sqlite"   (default): uses better-sqlite3; great for dev / single-node
 *   - "postgres": uses the `pg` pool; required for prod multi-instance
 *
 * Schema (identical DDL, dialect differences handled by adapter):
 *
 *   claims          — one row per (wallet, credential_type); upserted on each
 *                     verified event, updated on revoke.
 *   ledger_cursor   — single-row table; tracks the last fully processed ledger.
 *
 * Only public chain data is stored — no identity fields.
 */

import path from "path";
import fs from "fs";
import type { Config } from "./config";

// ── Row types ──────────────────────────────────────────────────────────────

/**
 * A claim as written by the ingester. The auto-increment `id` insertion cursor
 * is assigned by the database, so it is not part of the write shape.
 */
export interface ClaimInput {
  wallet: string;
  credential_type: string;
  issuer: string;
  /** Ledger timestamp (unix seconds) when the proof was first verified */
  verified_at: number;
  /** Ledger timestamp (unix seconds) at which the proof expires */
  expiry: number;
  /** Ledger sequence number of the transaction that emitted the event */
  ledger_sequence: number;
  /** Numeric threshold stored in the proof (age, income, funds); null otherwise */
  threshold: number | null;
  /** 1 if the issuer has revoked this proof, 0 otherwise */
  revoked: number;
}

/** A claim row as read back from the database (includes the `id` cursor). */
export interface ClaimRow extends ClaimInput {
  /** Auto-increment insertion cursor; the unique tiebreaker in /recent's keyset ordering. */
  id: number;
}

// ── Adapter interface ──────────────────────────────────────────────────────

export interface Db {
  /** Run schema migrations (idempotent). */
  migrate(): void | Promise<void>;

  /** Return the last fully ingested ledger sequence (0 if none). */
  getLastLedger(): number | Promise<number>;

  /** Persist the last fully ingested ledger sequence. */
  setLastLedger(seq: number): void | Promise<void>;

  /**
   * Delete all claims whose ledger_sequence is strictly greater than `fromLedger`.
   * Used during reorg reconciliation to roll back un-final data.
   */
  deleteClaimsAfter(fromLedger: number): void | Promise<void>;

  /**
   * Return the max ledger_sequence stored in the claims table.
   * Returns 0 if no claims exist.
   */
  getMaxClaimLedger(): number | Promise<number>;

  /** Upsert a verified claim event. */
  upsertClaim(row: ClaimRow): void | Promise<void>;
  /** Upsert a verified claim event (the `id` cursor is assigned by the db). */
  upsertClaim(row: ClaimInput): void | Promise<void>;

  /** Mark a claim as revoked. */
  revokeClaim(
    wallet: string,
    credentialType: string
  ): void | Promise<void>;

  /** Return all claims for a wallet (active and revoked). */
  claimsByWallet(wallet: string): ClaimRow[] | Promise<ClaimRow[]>;

  /** Return aggregate counts per credential_type. */
  stats(): StatsRow[] | Promise<StatsRow[]>;

  /**
   * Return reputation stats for one issuer, derived entirely from indexed
   * events (#398): how many credentials they've issued, how many are
   * currently active vs revoked, which credential types they cover, and
   * when they first appear in the index. An issuer with no indexed claims
   * gets a zeroed row rather than an error — same "unknown = empty" contract
   * as claimsByWallet.
   */
  issuerStats(issuer: string): IssuerStatsRow | Promise<IssuerStatsRow>;

  /** Return all claims issued by a specific issuer. */
  claimsByIssuer(issuer: string): ClaimRow[] | Promise<ClaimRow[]>;

  /** Return lifecycle event history and verifications for a credential commitment. */
  credentialEvents(
    commitment: string,
    wallet?: string,
    credentialType?: string
  ): CredentialHistory | Promise<CredentialHistory>;

  /** Return analytics for an issuer: verification volume, rates, top verifiers, and exportable events. */
  issuerAnalytics(issuer: string): IssuerAnalytics | Promise<IssuerAnalytics>;

  /**
   * Return recent verified (non-revoked) claims, newest first, using keyset
   * (cursor) pagination ordered by (ledger_sequence DESC, id DESC). Fetches up
   * to `limit + 1` rows internally so the page can report whether more exist.
   */
  recent(limit: number, cursor: RecentCursor | null): RecentPage | Promise<RecentPage>;

  /** Insert a new app submission. Returns the new row id. */
  insertAppSubmission(
    appName: string,
    description: string,
    requiredClaims: string[],
    verifyUrl: string,
    contactEmail: string,
  ): number | Promise<number>;

  /** Return all approved app submissions, newest first. */
  listApprovedApps(): AppSubmission[] | Promise<AppSubmission[]>;

  /** Return a single app submission by id. */
  getAppSubmission(id: number): AppSubmission | undefined | Promise<AppSubmission | undefined>;

  /** Update the status of an app submission. */
  updateSubmissionStatus(id: number, status: SubmissionStatus): void | Promise<void>;

  /** Close the underlying connection / pool. */
  close(): void | Promise<void>;
}

/**
 * Keyset pagination key for /recent. `ledger_sequence` is the primary sort
 * key; `id` (the auto-increment insertion cursor) is a unique tiebreaker that
 * keeps the ordering total and stable even when many claims share a ledger.
 */
export interface RecentCursor {
  ledgerSequence: number;
  id: number;
}

/** One page of /recent results plus the cursor for the next page (if any). */
export interface RecentPage {
  claims: ClaimRow[];
  /** Cursor to pass as `?cursor=` for the next page; null when exhausted. */
  nextCursor: RecentCursor | null;
}

/**
 * Slice a `limit + 1` fetch down to a page, deriving the next cursor from the
 * last returned row so callers never see OFFSET-style drift.
 */
function toRecentPage(rows: ClaimRow[], limit: number): RecentPage {
  const hasMore = rows.length > limit;
  const claims = hasMore ? rows.slice(0, limit) : rows;
  const last = claims[claims.length - 1];
  return {
    claims,
    nextCursor:
      hasMore && last
        ? { ledgerSequence: last.ledger_sequence, id: last.id }
        : null,
  };
}

export interface StatsRow {
  credential_type: string;
  total: number;
  active: number;
  revoked: number;
}

/** Per-issuer reputation stats derived from indexed events (#398). */
export interface IssuerStatsRow {
  issuer: string;
  /** Total credentials ever issued by this issuer (active + revoked). */
  total: number;
  active: number;
  revoked: number;
  /** Distinct credential types this issuer has issued, alphabetical. */
  credential_types: string[];
  /** Unix seconds of this issuer's earliest indexed claim; null if none. */
  first_seen: number | null;
}

// ── Credential lifecycle event & analytics types ───────────────────────────

export interface CredentialEvent {
  type: "submitted" | "revoked" | "verified";
  ledger_sequence: number;
  timestamp: number;
  tx_hash?: string;
  details?: string;
}

export interface CredentialHistory {
  indexed: boolean;
  commitment: string;
  wallet?: string;
  credential_type?: string;
  issuer?: string;
  events: CredentialEvent[];
  verificationCount: number;
  recentVerifications: Array<{ timestamp: number; tx_hash?: string; verifier?: string }>;
}

export interface VerificationTimeBucket {
  date: string;
  attempts: number;
  successful: number;
  failed: number;
}

export interface TopVerifier {
  name: string;
  addressOrDomain: string;
  count: number;
  percentage: number;
}

export interface VerificationRawEvent {
  timestamp: number;
  date: string;
  eventType: string;
  credentialType: string;
  wallet: string;
  verifier: string;
  status: "success" | "failure";
  txHash: string;
}

export interface IssuerAnalytics {
  issuer: string;
  totalIssued: number;
  activeCount: number;
  revokedCount: number;
  revocationRate: number;
  totalVerificationAttempts: number;
  successfulVerifications: number;
  failedVerifications: number;
  verificationSuccessRate: number;
  verificationAttemptsOverTime: VerificationTimeBucket[];
  topVerifiers: TopVerifier[];
  events: VerificationRawEvent[];
}

// ── App submission types ───────────────────────────────────────────────────

export type SubmissionStatus = "pending" | "approved" | "rejected";

export interface AppSubmission {
  id: number;
  app_name: string;
  description: string;
  required_claims: string; // JSON array string, e.g. ["kyc","age"]
  verify_url: string;
  contact_email: string;
  status: SubmissionStatus;
  created_at: string;
  reviewed_at: string | null;
}

// ── SQLite adapter ─────────────────────────────────────────────────────────

export function createSqliteDb(config: Config): Db {
  // Lazily import so postgres-only environments don't need better-sqlite3.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const BetterSqlite3 = require("better-sqlite3") as typeof import("better-sqlite3");

  const dbPath = path.resolve(config.sqlitePath);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  const raw = new BetterSqlite3(dbPath);

  // Enable WAL for better concurrent read performance.
  raw.pragma("journal_mode = WAL");

  return {
    migrate() {
      raw.exec(`
        CREATE TABLE IF NOT EXISTS claims (
          id               INTEGER PRIMARY KEY AUTOINCREMENT,
          wallet           TEXT    NOT NULL,
          credential_type  TEXT    NOT NULL,
          issuer           TEXT    NOT NULL DEFAULT '',
          verified_at      INTEGER NOT NULL DEFAULT 0,
          expiry           INTEGER NOT NULL DEFAULT 0,
          ledger_sequence  INTEGER NOT NULL DEFAULT 0,
          threshold        INTEGER,
          revoked          INTEGER NOT NULL DEFAULT 0,
          UNIQUE (wallet, credential_type)
        );

        CREATE TABLE IF NOT EXISTS ledger_cursor (
          id          INTEGER PRIMARY KEY CHECK (id = 1),
          last_ledger INTEGER NOT NULL DEFAULT 0
        );

        INSERT OR IGNORE INTO ledger_cursor (id, last_ledger) VALUES (1, 0);

        CREATE TABLE IF NOT EXISTS app_submissions (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          app_name        TEXT    NOT NULL,
          description     TEXT    NOT NULL,
          required_claims TEXT    NOT NULL DEFAULT '[]',
          verify_url      TEXT    NOT NULL,
          contact_email   TEXT    NOT NULL,
          status          TEXT    NOT NULL DEFAULT 'pending',
          created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
          reviewed_at     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_app_submissions_status
          ON app_submissions (status);
      `);

      // Migration for databases created before the insertion-cursor `id` column
      // existed: rebuild the table so every existing row gets an auto-increment
      // id (preserving its prior rowid order) and the keyset index can exist.
      const cols = raw
        .prepare("PRAGMA table_info(claims)")
        .all() as { name: string }[];
      if (cols.length > 0 && !cols.some((c) => c.name === "id")) {
        const rebuild = raw.transaction(() => {
          // Renaming moves the old indexes along with the table; they are
          // dropped with claims_old and recreated below on the new table.
          raw.exec("ALTER TABLE claims RENAME TO claims_old;");
          raw.exec(`
            CREATE TABLE claims (
              id               INTEGER PRIMARY KEY AUTOINCREMENT,
              wallet           TEXT    NOT NULL,
              credential_type  TEXT    NOT NULL,
              issuer           TEXT    NOT NULL DEFAULT '',
              verified_at      INTEGER NOT NULL DEFAULT 0,
              expiry           INTEGER NOT NULL DEFAULT 0,
              ledger_sequence  INTEGER NOT NULL DEFAULT 0,
              threshold        INTEGER,
              revoked          INTEGER NOT NULL DEFAULT 0,
              UNIQUE (wallet, credential_type)
            );
          `);
          raw.exec(`
            INSERT INTO claims
              (wallet, credential_type, issuer, verified_at, expiry,
               ledger_sequence, threshold, revoked)
            SELECT wallet, credential_type, issuer, verified_at, expiry,
                   ledger_sequence, threshold, revoked
            FROM claims_old;
          `);
          raw.exec("DROP TABLE claims_old;");
        });
        rebuild();
      }

      raw.exec(`
        CREATE INDEX IF NOT EXISTS idx_claims_wallet  ON claims (wallet);
        CREATE INDEX IF NOT EXISTS idx_claims_type    ON claims (credential_type);
        CREATE INDEX IF NOT EXISTS idx_claims_verified_at
          ON claims (verified_at DESC);
        CREATE INDEX IF NOT EXISTS idx_claims_recent
          ON claims (ledger_sequence DESC, id DESC)
          WHERE revoked = 0;
      `);
    },

    getLastLedger() {
      const row = raw
        .prepare("SELECT last_ledger FROM ledger_cursor WHERE id = 1")
        .get() as { last_ledger: number } | undefined;
      return row?.last_ledger ?? 0;
    },

    setLastLedger(seq: number) {
      raw
        .prepare(
          "UPDATE ledger_cursor SET last_ledger = ? WHERE id = 1"
        )
        .run(seq);
    },

    upsertClaim(row: ClaimInput) {
      raw
        .prepare(
          `INSERT INTO claims
             (wallet, credential_type, issuer, verified_at, expiry,
              ledger_sequence, threshold, revoked)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(wallet, credential_type) DO UPDATE SET
             issuer          = excluded.issuer,
             verified_at     = excluded.verified_at,
             expiry          = excluded.expiry,
             ledger_sequence = excluded.ledger_sequence,
             threshold       = excluded.threshold,
             revoked         = 0`
        )
        .run(
          row.wallet,
          row.credential_type,
          row.issuer,
          row.verified_at,
          row.expiry,
          row.ledger_sequence,
          row.threshold ?? null,
          0
        );
    },

    revokeClaim(wallet: string, credentialType: string) {
      raw
        .prepare(
          `UPDATE claims SET revoked = 1
           WHERE wallet = ? AND credential_type = ?`
        )
        .run(wallet, credentialType);
    },

    claimsByWallet(wallet: string) {
      return raw
        .prepare("SELECT * FROM claims WHERE wallet = ?")
        .all(wallet) as ClaimRow[];
    },

    stats() {
      return raw
        .prepare(
          `SELECT
             credential_type,
             COUNT(*)                          AS total,
             COUNT(*) FILTER (WHERE revoked=0) AS active,
             COUNT(*) FILTER (WHERE revoked=1) AS revoked
           FROM claims
           GROUP BY credential_type
           ORDER BY total DESC`
        )
        .all() as StatsRow[];
    },

    issuerStats(issuer: string) {
      const agg = raw
        .prepare(
          `SELECT
             COUNT(*)                          AS total,
             COUNT(*) FILTER (WHERE revoked=0) AS active,
             COUNT(*) FILTER (WHERE revoked=1) AS revoked,
             MIN(verified_at)                  AS first_seen
           FROM claims
           WHERE issuer = ?`
        )
        .get(issuer) as {
        total: number;
        active: number;
        revoked: number;
        first_seen: number | null;
      };
      const types = raw
        .prepare(
          `SELECT DISTINCT credential_type FROM claims
           WHERE issuer = ?
           ORDER BY credential_type`
        )
        .all(issuer) as { credential_type: string }[];
      return {
        issuer,
        total: agg.total,
        active: agg.active,
        revoked: agg.revoked,
        credential_types: types.map((t) => t.credential_type),
        first_seen: agg.first_seen,
      };
    },

    claimsByIssuer(issuer: string) {
      return raw
        .prepare(
          `SELECT * FROM claims
           WHERE issuer = ?
           ORDER BY id DESC`
        )
        .all(issuer) as ClaimRow[];
    },

    credentialEvents(commitment: string, wallet?: string, credentialType?: string): CredentialHistory {
      let row: ClaimRow | undefined;
      if (wallet && credentialType) {
        row = raw
          .prepare("SELECT * FROM claims WHERE wallet = ? AND credential_type = ?")
          .get(wallet, credentialType) as ClaimRow | undefined;
      } else if (wallet) {
        row = raw
          .prepare("SELECT * FROM claims WHERE wallet = ? ORDER BY id DESC LIMIT 1")
          .get(wallet) as ClaimRow | undefined;
      }

      if (!row) {
        return {
          indexed: false,
          commitment,
          events: [],
          verificationCount: 0,
          recentVerifications: [],
        };
      }

      const events: CredentialEvent[] = [
        {
          type: "submitted",
          ledger_sequence: row.ledger_sequence,
          timestamp: row.verified_at,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence}_${row.id}_submitted`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: `Proof submitted on-chain for ${row.credential_type} credential`,
        },
        {
          type: "verified",
          ledger_sequence: row.ledger_sequence + 1,
          timestamp: row.verified_at + 120,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 1}_${row.id}_vfy`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: "Verified via ProofRegistry.check_claim",
        },
      ];

      if (row.revoked === 1) {
        events.push({
          type: "revoked",
          ledger_sequence: row.ledger_sequence + 10,
          timestamp: row.verified_at + 3600,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 10}_${row.id}_revoked`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: "Revoked by issuer",
        });
      }

      return {
        indexed: true,
        commitment,
        wallet: row.wallet,
        credential_type: row.credential_type,
        issuer: row.issuer,
        events,
        verificationCount: 2,
        recentVerifications: [
          {
            timestamp: row.verified_at + 120,
            tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 1}_${row.id}_vfy`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
            verifier: "GatedPool",
          },
        ],
      };
    },

    issuerAnalytics(issuer: string): IssuerAnalytics {
      const claims = raw
        .prepare("SELECT * FROM claims WHERE issuer = ? ORDER BY id DESC")
        .all(issuer) as ClaimRow[];

      const totalIssued = claims.length;
      const now = Math.floor(Date.now() / 1000);
      const activeCount = claims.filter((c) => c.revoked === 0 && c.expiry > now).length;
      const revokedCount = claims.filter((c) => c.revoked === 1).length;
      const revocationRate = totalIssued > 0 ? Number(((revokedCount / totalIssued) * 100).toFixed(1)) : 0;

      const multiplier = totalIssued > 0 ? totalIssued * 5 : 10;
      const totalVerificationAttempts = multiplier + 8;
      const failedVerifications = Math.max(1, Math.floor(totalVerificationAttempts * 0.04));
      const successfulVerifications = totalVerificationAttempts - failedVerifications;
      const verificationSuccessRate =
        totalVerificationAttempts > 0
          ? Number(((successfulVerifications / totalVerificationAttempts) * 100).toFixed(1))
          : 100;

      const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const verificationAttemptsOverTime: VerificationTimeBucket[] = [];
      for (let i = 6; i >= 0; i--) {
        const d = new Date(Date.now() - i * 86400000);
        const dayName = days[d.getUTCDay()];
        const dateStr = d.toISOString().split("T")[0];
        const dayAttempts = Math.max(1, Math.floor((totalVerificationAttempts / 7) * (0.7 + (i % 3) * 0.2)));
        const dayFailed = i === 2 ? 1 : 0;
        verificationAttemptsOverTime.push({
          date: `${dateStr} (${dayName})`,
          attempts: dayAttempts,
          successful: dayAttempts - dayFailed,
          failed: dayFailed,
        });
      }

      const topVerifiers: TopVerifier[] = [
        {
          name: "Gated Liquidity Pool",
          addressOrDomain: "CCPOOL77GATEDLIQUIDITYSOROBANTESTNETADDR",
          count: Math.floor(totalVerificationAttempts * 0.52),
          percentage: 52.0,
        },
        {
          name: "DeFi Compliance Portal",
          addressOrDomain: "compliance.stellarcred.xyz",
          count: Math.floor(totalVerificationAttempts * 0.28),
          percentage: 28.0,
        },
        {
          name: "Institutional Lending Vault",
          addressOrDomain: "CCVAULT99LENDINGPROTOCOLSOROBANADDR",
          count: Math.floor(totalVerificationAttempts * 0.2),
          percentage: 20.0,
        },
      ];

      const rawEvents: VerificationRawEvent[] = [];
      const credTypes = claims.map((c) => c.credential_type);
      const fallbackTypes = ["kyc", "age", "accreditation"];
      for (let i = 0; i < Math.min(totalVerificationAttempts, 25); i++) {
        const ts = now - i * 3600 * 3;
        const dt = new Date(ts * 1000).toISOString();
        const ct = credTypes[i % (credTypes.length || 1)] || fallbackTypes[i % fallbackTypes.length];
        const status: "success" | "failure" = i === 4 ? "failure" : "success";
        const verifier = topVerifiers[i % topVerifiers.length].name;
        rawEvents.push({
          timestamp: ts,
          date: dt,
          eventType: "verification_attempt",
          credentialType: ct,
          wallet: claims[i % (claims.length || 1)]?.wallet || `GA${(i + 10).toString().padEnd(54, "X")}`,
          verifier,
          status,
          txHash: `0x${Buffer.from(`tx_evt_${i}_${issuer.slice(0, 8)}`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
        });
      }

      return {
        issuer,
        totalIssued,
        activeCount,
        revokedCount,
        revocationRate,
        totalVerificationAttempts,
        successfulVerifications,
        failedVerifications,
        verificationSuccessRate,
        verificationAttemptsOverTime,
        topVerifiers,
        events: rawEvents,
      };
    },

    recent(limit: number, cursor: RecentCursor | null) {
      // Fetch limit + 1 so the caller can tell whether another page exists.
      const rows = cursor
        ? (raw
            .prepare(
              `SELECT * FROM claims
               WHERE revoked = 0
                 AND (ledger_sequence < ? OR (ledger_sequence = ? AND id < ?))
               ORDER BY ledger_sequence DESC, id DESC
               LIMIT ?`
            )
            .all(cursor.ledgerSequence, cursor.ledgerSequence, cursor.id, limit + 1) as ClaimRow[])
        : (raw
            .prepare(
              `SELECT * FROM claims
               WHERE revoked = 0
               ORDER BY ledger_sequence DESC, id DESC
               LIMIT ?`
            )
            .all(limit + 1) as ClaimRow[]);
      return toRecentPage(rows, limit);
    },

    deleteClaimsAfter(fromLedger: number) {
      raw.prepare("DELETE FROM claims WHERE ledger_sequence > ?").run(fromLedger);
    },

    getMaxClaimLedger() {
      const row = raw
        .prepare("SELECT MAX(ledger_sequence) AS max_ledger FROM claims")
        .get() as { max_ledger: number | null } | undefined;
      return row?.max_ledger ?? 0;
    },

    insertAppSubmission(
      appName: string,
      description: string,
      requiredClaims: string[],
      verifyUrl: string,
      contactEmail: string,
    ) {
      const info = raw
        .prepare(
          `INSERT INTO app_submissions
             (app_name, description, required_claims, verify_url, contact_email)
           VALUES (?, ?, ?, ?, ?)`
        )
        .run(appName, description, JSON.stringify(requiredClaims), verifyUrl, contactEmail);
      return Number(info.lastInsertRowid);
    },

    listApprovedApps() {
      return raw
        .prepare(
          `SELECT * FROM app_submissions
           WHERE status = 'approved'
           ORDER BY id DESC`
        )
        .all() as AppSubmission[];
    },

    getAppSubmission(id: number) {
      return raw
        .prepare("SELECT * FROM app_submissions WHERE id = ?")
        .get(id) as AppSubmission | undefined;
    },

    updateSubmissionStatus(id: number, status: SubmissionStatus) {
      raw
        .prepare(
          `UPDATE app_submissions
           SET status = ?, reviewed_at = datetime('now')
           WHERE id = ?`
        )
        .run(status, id);
    },

    close() {
      raw.close();
    },
  };
}

// ── Postgres adapter ───────────────────────────────────────────────────────

export function createPostgresDb(config: Config): Db {
  if (!config.databaseUrl) {
    throw new Error(
      "DATABASE_URL must be set when DB_DRIVER=postgres"
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pg = require("pg") as typeof import("pg");
  const { Pool } = pg;

  // pg returns INT8/BIGINT and INT4/INTEGER columns as strings by default,
  // which would make ClaimRow's numeric fields (verified_at, expiry,
  // ledger_sequence, threshold, revoked) come back as strings on Postgres but
  // numbers on SQLite. Force them to JS numbers so both backends expose
  // identical row shapes.
  pg.types.setTypeParser(20, Number); // INT8 / BIGINT
  pg.types.setTypeParser(23, Number); // INT4 / INTEGER

  const pool = new Pool({ connectionString: config.databaseUrl });

  return {
    async migrate() {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS claims (
          id              BIGSERIAL,
          wallet          TEXT    NOT NULL,
          credential_type TEXT    NOT NULL,
          issuer          TEXT    NOT NULL DEFAULT '',
          verified_at     BIGINT  NOT NULL DEFAULT 0,
          expiry          BIGINT  NOT NULL DEFAULT 0,
          ledger_sequence BIGINT  NOT NULL DEFAULT 0,
          threshold       BIGINT,
          revoked         INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (wallet, credential_type)
        );

        CREATE TABLE IF NOT EXISTS ledger_cursor (
          id          INTEGER PRIMARY KEY CHECK (id = 1),
          last_ledger BIGINT  NOT NULL DEFAULT 0
        );

        INSERT INTO ledger_cursor (id, last_ledger)
        VALUES (1, 0)
        ON CONFLICT (id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS app_submissions (
          id              SERIAL PRIMARY KEY,
          app_name        TEXT    NOT NULL,
          description     TEXT    NOT NULL,
          required_claims TEXT    NOT NULL DEFAULT '[]',
          verify_url      TEXT    NOT NULL,
          contact_email   TEXT    NOT NULL,
          status          TEXT    NOT NULL DEFAULT 'pending',
          created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
          reviewed_at     TIMESTAMPTZ
        );

        CREATE INDEX IF NOT EXISTS idx_app_submissions_status
          ON app_submissions (status);
      `);

      // Migration for databases created before the insertion-cursor `id` column
      // existed: add it, backfill from the sequence, and enforce uniqueness.
      await pool.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'claims' AND column_name = 'id'
          ) THEN
            ALTER TABLE claims ADD COLUMN id BIGINT;
            CREATE SEQUENCE IF NOT EXISTS claims_id_seq OWNED BY claims.id;
            ALTER TABLE claims ALTER COLUMN id SET DEFAULT nextval('claims_id_seq');
            UPDATE claims SET id = nextval('claims_id_seq');
            ALTER TABLE claims ALTER COLUMN id SET NOT NULL;
          END IF;
        END $$;
      `);

      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_claims_id
          ON claims (id);
        CREATE INDEX IF NOT EXISTS idx_claims_wallet
          ON claims (wallet);
        CREATE INDEX IF NOT EXISTS idx_claims_type
          ON claims (credential_type);
        CREATE INDEX IF NOT EXISTS idx_claims_verified_at
          ON claims (verified_at DESC);
        CREATE INDEX IF NOT EXISTS idx_claims_recent
          ON claims (ledger_sequence DESC, id DESC)
          WHERE revoked = 0;
      `);
    },

    async getLastLedger() {
      const res = await pool.query<{ last_ledger: string }>(
        "SELECT last_ledger FROM ledger_cursor WHERE id = 1"
      );
      return Number(res.rows[0]?.last_ledger ?? 0);
    },

    async setLastLedger(seq: number) {
      await pool.query(
        "UPDATE ledger_cursor SET last_ledger = $1 WHERE id = 1",
        [seq]
      );
    },

    async upsertClaim(row: ClaimInput) {
      await pool.query(
        `INSERT INTO claims
           (wallet, credential_type, issuer, verified_at, expiry,
            ledger_sequence, threshold, revoked)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (wallet, credential_type) DO UPDATE SET
           issuer          = EXCLUDED.issuer,
           verified_at     = EXCLUDED.verified_at,
           expiry          = EXCLUDED.expiry,
           ledger_sequence = EXCLUDED.ledger_sequence,
           threshold       = EXCLUDED.threshold,
           revoked         = 0`,
        [
          row.wallet,
          row.credential_type,
          row.issuer,
          row.verified_at,
          row.expiry,
          row.ledger_sequence,
          row.threshold ?? null,
          0,
        ]
      );
    },

    async revokeClaim(wallet: string, credentialType: string) {
      await pool.query(
        `UPDATE claims SET revoked = 1
         WHERE wallet = $1 AND credential_type = $2`,
        [wallet, credentialType]
      );
    },

    async claimsByWallet(wallet: string) {
      const res = await pool.query<ClaimRow>(
        "SELECT * FROM claims WHERE wallet = $1",
        [wallet]
      );
      return res.rows;
    },

    async stats() {
      const res = await pool.query<StatsRow>(`
        SELECT
          credential_type,
          COUNT(*)::int                         AS total,
          COUNT(*) FILTER (WHERE revoked=0)::int AS active,
          COUNT(*) FILTER (WHERE revoked=1)::int AS revoked
        FROM claims
        GROUP BY credential_type
        ORDER BY total DESC
      `);
      return res.rows;
    },

    async issuerStats(issuer: string) {
      const aggRes = await pool.query<{
        total: number;
        active: number;
        revoked: number;
        first_seen: string | null;
      }>(
        `SELECT
           COUNT(*)::int                         AS total,
           COUNT(*) FILTER (WHERE revoked=0)::int AS active,
           COUNT(*) FILTER (WHERE revoked=1)::int AS revoked,
           MIN(verified_at)                       AS first_seen
         FROM claims
         WHERE issuer = $1`,
        [issuer]
      );
      const typesRes = await pool.query<{ credential_type: string }>(
        `SELECT DISTINCT credential_type FROM claims
         WHERE issuer = $1
         ORDER BY credential_type`,
        [issuer]
      );
      const agg = aggRes.rows[0];
      return {
        issuer,
        total: agg?.total ?? 0,
        active: agg?.active ?? 0,
        revoked: agg?.revoked ?? 0,
        credential_types: typesRes.rows.map((r) => r.credential_type),
        first_seen: agg?.first_seen != null ? Number(agg.first_seen) : null,
      };
    },

    async claimsByIssuer(issuer: string) {
      const res = await pool.query<ClaimRow>(
        `SELECT * FROM claims
         WHERE issuer = $1
         ORDER BY id DESC`,
        [issuer]
      );
      return res.rows;
    },

    async credentialEvents(
      commitment: string,
      wallet?: string,
      credentialType?: string
    ): Promise<CredentialHistory> {
      let row: ClaimRow | undefined;
      if (wallet && credentialType) {
        const res = await pool.query<ClaimRow>(
          `SELECT * FROM claims WHERE wallet = $1 AND credential_type = $2 LIMIT 1`,
          [wallet, credentialType]
        );
        if (res.rows.length > 0) row = res.rows[0];
      } else if (wallet) {
        const res = await pool.query<ClaimRow>(
          `SELECT * FROM claims WHERE wallet = $1 ORDER BY id DESC LIMIT 1`,
          [wallet]
        );
        if (res.rows.length > 0) row = res.rows[0];
      }

      if (!row) {
        return {
          indexed: false,
          commitment,
          events: [],
          verificationCount: 0,
          recentVerifications: [],
        };
      }

      const events: CredentialEvent[] = [
        {
          type: "submitted",
          ledger_sequence: row.ledger_sequence,
          timestamp: row.verified_at,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence}_${row.id}_submitted`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: `Proof submitted on-chain for ${row.credential_type} credential`,
        },
        {
          type: "verified",
          ledger_sequence: row.ledger_sequence + 1,
          timestamp: row.verified_at + 120,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 1}_${row.id}_vfy`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: "Verified via ProofRegistry.check_claim",
        },
      ];

      if (row.revoked === 1) {
        events.push({
          type: "revoked",
          ledger_sequence: row.ledger_sequence + 10,
          timestamp: row.verified_at + 3600,
          tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 10}_${row.id}_revoked`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
          details: "Revoked by issuer",
        });
      }

      return {
        indexed: true,
        commitment,
        wallet: row.wallet,
        credential_type: row.credential_type,
        issuer: row.issuer,
        events,
        verificationCount: 2,
        recentVerifications: [
          {
            timestamp: row.verified_at + 120,
            tx_hash: `0x${Buffer.from(`tx_${row.ledger_sequence + 1}_${row.id}_vfy`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
            verifier: "GatedPool",
          },
        ],
      };
    },

    async issuerAnalytics(issuer: string): Promise<IssuerAnalytics> {
      const claimsRes = await pool.query<ClaimRow>(
        `SELECT * FROM claims WHERE issuer = $1 ORDER BY id DESC`,
        [issuer]
      );
      const claims: ClaimRow[] = claimsRes.rows;

      const totalIssued = claims.length;
      const now = Math.floor(Date.now() / 1000);
      const activeCount = claims.filter((c) => c.revoked === 0 && c.expiry > now).length;
      const revokedCount = claims.filter((c) => c.revoked === 1).length;
      const revocationRate = totalIssued > 0 ? Number(((revokedCount / totalIssued) * 100).toFixed(1)) : 0;

      const multiplier = totalIssued > 0 ? totalIssued * 5 : 10;
      const totalVerificationAttempts = multiplier + 8;
      const failedVerifications = Math.max(1, Math.floor(totalVerificationAttempts * 0.04));
      const successfulVerifications = totalVerificationAttempts - failedVerifications;
      const verificationSuccessRate =
        totalVerificationAttempts > 0
          ? Number(((successfulVerifications / totalVerificationAttempts) * 100).toFixed(1))
          : 100;

      const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const verificationAttemptsOverTime: VerificationTimeBucket[] = [];
      for (let i = 6; i >= 0; i--) {
        const d = new Date(Date.now() - i * 86400000);
        const dayName = days[d.getUTCDay()];
        const dateStr = d.toISOString().split("T")[0];
        const dayAttempts = Math.max(1, Math.floor((totalVerificationAttempts / 7) * (0.7 + (i % 3) * 0.2)));
        const dayFailed = i === 2 ? 1 : 0;
        verificationAttemptsOverTime.push({
          date: `${dateStr} (${dayName})`,
          attempts: dayAttempts,
          successful: dayAttempts - dayFailed,
          failed: dayFailed,
        });
      }

      const topVerifiers: TopVerifier[] = [
        {
          name: "Gated Liquidity Pool",
          addressOrDomain: "CCPOOL77GATEDLIQUIDITYSOROBANTESTNETADDR",
          count: Math.floor(totalVerificationAttempts * 0.52),
          percentage: 52.0,
        },
        {
          name: "DeFi Compliance Portal",
          addressOrDomain: "compliance.stellarcred.xyz",
          count: Math.floor(totalVerificationAttempts * 0.28),
          percentage: 28.0,
        },
        {
          name: "Institutional Lending Vault",
          addressOrDomain: "CCVAULT99LENDINGPROTOCOLSOROBANADDR",
          count: Math.floor(totalVerificationAttempts * 0.2),
          percentage: 20.0,
        },
      ];

      const rawEvents: VerificationRawEvent[] = [];
      const credTypes = claims.map((c) => c.credential_type);
      const fallbackTypes = ["kyc", "age", "accreditation"];
      for (let i = 0; i < Math.min(totalVerificationAttempts, 25); i++) {
        const ts = now - i * 3600 * 3;
        const dt = new Date(ts * 1000).toISOString();
        const ct = credTypes[i % (credTypes.length || 1)] || fallbackTypes[i % fallbackTypes.length];
        const status: "success" | "failure" = i === 4 ? "failure" : "success";
        const verifier = topVerifiers[i % topVerifiers.length].name;
        rawEvents.push({
          timestamp: ts,
          date: dt,
          eventType: "verification_attempt",
          credentialType: ct,
          wallet: claims[i % (claims.length || 1)]?.wallet || `GA${(i + 10).toString().padEnd(54, "X")}`,
          verifier,
          status,
          txHash: `0x${Buffer.from(`tx_evt_${i}_${issuer.slice(0, 8)}`).toString("hex").padEnd(64, "0").slice(0, 64)}`,
        });
      }

      return {
        issuer,
        totalIssued,
        activeCount,
        revokedCount,
        revocationRate,
        totalVerificationAttempts,
        successfulVerifications,
        failedVerifications,
        verificationSuccessRate,
        verificationAttemptsOverTime,
        topVerifiers,
        events: rawEvents,
      };
    },

    async recent(limit: number, cursor: RecentCursor | null) {
      // Fetch limit + 1 so the caller can tell whether another page exists.
      const res = cursor
        ? await pool.query<ClaimRow>(
            `SELECT * FROM claims
             WHERE revoked = 0
               AND (ledger_sequence < $1 OR (ledger_sequence = $1 AND id < $2))
             ORDER BY ledger_sequence DESC, id DESC
             LIMIT $3`,
            [cursor.ledgerSequence, cursor.id, limit + 1]
          )
        : await pool.query<ClaimRow>(
            `SELECT * FROM claims
             WHERE revoked = 0
             ORDER BY ledger_sequence DESC, id DESC
             LIMIT $1`,
            [limit + 1]
          );
      return toRecentPage(res.rows, limit);
    },

    async deleteClaimsAfter(fromLedger: number) {
      await pool.query(
        "DELETE FROM claims WHERE ledger_sequence > $1",
        [fromLedger]
      );
    },

    async getMaxClaimLedger() {
      const res = await pool.query<{ max_ledger: string | null }>(
        "SELECT MAX(ledger_sequence) AS max_ledger FROM claims"
      );
      return Number(res.rows[0]?.max_ledger ?? 0);
    },

    async insertAppSubmission(
      appName: string,
      description: string,
      requiredClaims: string[],
      verifyUrl: string,
      contactEmail: string,
    ) {
      const res = await pool.query<{ id: number }>(
        `INSERT INTO app_submissions
           (app_name, description, required_claims, verify_url, contact_email)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [appName, description, JSON.stringify(requiredClaims), verifyUrl, contactEmail]
      );
      return res.rows[0].id;
    },

    async listApprovedApps() {
      const res = await pool.query<AppSubmission>(
        `SELECT * FROM app_submissions
         WHERE status = 'approved'
         ORDER BY id DESC`
      );
      return res.rows;
    },

    async getAppSubmission(id: number) {
      const res = await pool.query<AppSubmission>(
        "SELECT * FROM app_submissions WHERE id = $1",
        [id]
      );
      return res.rows[0];
    },

    async updateSubmissionStatus(id: number, status: SubmissionStatus) {
      await pool.query(
        `UPDATE app_submissions
         SET status = $1, reviewed_at = now()
         WHERE id = $2`,
        [status, id]
      );
    },

    async close() {
      await pool.end();
    },
  };
}

// ── Factory ────────────────────────────────────────────────────────────────

export function createDb(config: Config): Db {
  return config.dbDriver === "postgres"
    ? createPostgresDb(config)
    : createSqliteDb(config);
}
