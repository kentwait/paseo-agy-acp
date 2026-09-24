import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  AdmissionController,
  AdmissionMigrationError,
  AdmissionRuntimeError,
  type AdmissionPolicy
} from "../Admission Controller/controller.js";
import {
  parseProcessIdentity,
  serializeProcessIdentity,
  type ProcessEvidence,
  type ProcessEvidencePlatform,
  type ProcessIdentity
} from "../Admission Controller/process-evidence.js";
import {
  assertAdmissionSchemaIntegrity,
  SchemaIntegrityError
} from "../Admission Controller/schema.js";

const BOOT_ID = "f4bca3da-9bd5-4f2e-89b8-5e12e5ee8f31";
const NAMESPACE_INODE = 4_026_531_836;
const OWNER_ID = "11111111-1111-4111-8111-111111111111";
const REQUEST_ID = "v3-request";
const LEASE_ID = "v3-lease";
const stateDirs: string[] = [];

const POLICY: AdmissionPolicy = {
  maxActiveTurns: 3,
  maxConcurrentStarts: 1,
  minStartIntervalMs: 2_000,
  queueTimeoutMs: 30 * 60_000,
  capacityCooldownMs: 30_000
};

function databasePath(): string {
  const stateDir = mkdtempSync(path.join(os.tmpdir(), "paseo-agy-schema-v4-"));
  stateDirs.push(stateDir);
  return path.join(stateDir, "runtime.sqlite");
}

function identity(pid: number): ProcessIdentity {
  return {
    bootId: BOOT_ID,
    pid,
    startTimeTicks: String(100 + pid),
    pidNamespaceInode: NAMESPACE_INODE,
    ppid: 1,
    pgrp: pid,
    session: pid
  };
}

function processEvidence(platform: ProcessEvidencePlatform = "linux"): ProcessEvidence {
  const current = identity(process.pid);
  return {
    platform,
    capture: () => current,
    observe: () => "same",
    inspectProcessGroup: () => "empty"
  };
}

function openController(file: string, platform: ProcessEvidencePlatform = "linux"): AdmissionController {
  return new AdmissionController({
    databasePath: file,
    policy: POLICY,
    encryptionKey: Buffer.alloc(32, 131),
    contentFingerprintKey: Buffer.alloc(32, 132),
    processEvidence: processEvidence(platform)
  });
}

function createV3Database(file: string): void {
  const db = new Database(file);
  try {
    db.pragma("foreign_keys = ON");
    db.exec(`
      CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at INTEGER NOT NULL
      );
      CREATE TABLE turn_requests (
        request_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        state TEXT NOT NULL,
        enqueued_at INTEGER NOT NULL,
        deadline_at INTEGER NOT NULL,
        lease_generation INTEGER NOT NULL DEFAULT 0,
        terminal_at INTEGER,
        queued_owner_instance_id TEXT,
        queued_owner_recorded_at INTEGER
      );
      CREATE TABLE leases (
        lease_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE REFERENCES turn_requests(request_id),
        generation INTEGER NOT NULL,
        owner_instance_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        acquired_at INTEGER NOT NULL,
        heartbeat_at INTEGER NOT NULL,
        suspect_since INTEGER,
        suspect_reason TEXT CHECK (suspect_reason IS NULL OR suspect_reason IN ('heartbeat_expired', 'identity_unverifiable'))
      );
      CREATE TABLE cooldowns (
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        not_before INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (provider, model)
      );
      CREATE TABLE turn_payloads (
        request_id TEXT PRIMARY KEY REFERENCES turn_requests(request_id) ON DELETE CASCADE,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        key_version INTEGER NOT NULL,
        content_fingerprint TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE lease_process_identities (
        lease_id TEXT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
        request_id TEXT NOT NULL REFERENCES turn_requests(request_id),
        lease_generation INTEGER NOT NULL,
        owner_instance_id TEXT NOT NULL,
        prompt_channel TEXT NOT NULL,
        connector_owner_instance_id TEXT NOT NULL,
        connector_created_at TEXT NOT NULL,
        connector_boot_id TEXT NOT NULL,
        connector_pid INTEGER NOT NULL,
        connector_start_time_ticks TEXT NOT NULL,
        connector_pid_namespace_inode INTEGER NOT NULL,
        connector_ppid INTEGER NOT NULL,
        connector_pgrp INTEGER NOT NULL,
        connector_session INTEGER NOT NULL,
        child_boot_id TEXT NOT NULL,
        child_pid INTEGER NOT NULL,
        child_start_time_ticks TEXT NOT NULL,
        child_pid_namespace_inode INTEGER NOT NULL,
        child_ppid INTEGER NOT NULL,
        child_pgrp INTEGER NOT NULL,
        child_session INTEGER NOT NULL,
        recorded_at INTEGER NOT NULL
      );
      CREATE TABLE start_history (
        lease_id TEXT PRIMARY KEY,
        started_at INTEGER NOT NULL
      );
      CREATE TABLE policy_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        max_active_turns INTEGER NOT NULL CHECK (max_active_turns >= 1),
        max_concurrent_starts INTEGER NOT NULL CHECK (max_concurrent_starts >= 1),
        min_start_interval_ms INTEGER NOT NULL CHECK (min_start_interval_ms >= 2000),
        queue_timeout_ms INTEGER NOT NULL CHECK (queue_timeout_ms > 0 AND queue_timeout_ms <= 1800000),
        capacity_cooldown_ms INTEGER NOT NULL CHECK (capacity_cooldown_ms >= 30000),
        drain_state TEXT NOT NULL CHECK (drain_state IN ('steady', 'soft_draining_to_1')),
        policy_fingerprint TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by_owner_instance_id TEXT NOT NULL
      );
      CREATE TABLE queued_owner_instances (
        owner_instance_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        boot_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        start_time_ticks TEXT NOT NULL,
        pid_namespace_inode INTEGER NOT NULL,
        ppid INTEGER NOT NULL,
        pgrp INTEGER NOT NULL,
        session INTEGER NOT NULL,
        recorded_at INTEGER NOT NULL
      );
      CREATE TABLE sessions (
        session_id TEXT NOT NULL PRIMARY KEY,
        conversation_id TEXT,
        conversation_cursor INTEGER NOT NULL,
        model TEXT NOT NULL,
        effort TEXT NOT NULL,
        mode TEXT NOT NULL,
        cwd TEXT NOT NULL,
        roots_json TEXT NOT NULL,
        v2_user_message_ids_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE events (
        event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        from_state TEXT NOT NULL,
        to_state TEXT NOT NULL,
        occurred_at INTEGER NOT NULL,
        correlation_hmac TEXT NOT NULL
      );
      CREATE INDEX turn_requests_queue ON turn_requests(state, enqueued_at);
      CREATE INDEX turn_requests_queued_owner ON turn_requests(queued_owner_instance_id)
        WHERE queued_owner_instance_id IS NOT NULL;
      CREATE INDEX leases_phase ON leases(phase);
      CREATE UNIQUE INDEX lease_process_identities_request ON lease_process_identities(request_id);
      CREATE INDEX start_history_started ON start_history(started_at);
      CREATE INDEX sessions_updated_at_session_id ON sessions(updated_at DESC, session_id ASC);
      CREATE INDEX sessions_cwd_updated_at_session_id ON sessions(cwd, updated_at DESC, session_id ASC);
      CREATE INDEX events_occurred ON events(occurred_at, event_seq);
    `);
    db.prepare("INSERT INTO schema_migrations VALUES (1, 'shared-admission-queue', 1)").run();
    db.prepare("INSERT INTO schema_migrations VALUES (2, 'shared-admission-queue-v2', 2)").run();
    db.prepare("INSERT INTO schema_migrations VALUES (3, 'shared-admission-queue-v3', 3)").run();
    db.prepare(
      `INSERT INTO turn_requests (
         request_id, session_id, agent_id, fingerprint, provider, model, state,
         enqueued_at, deadline_at, lease_generation, terminal_at,
         queued_owner_instance_id, queued_owner_recorded_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(REQUEST_ID, "v3-session", "v3-agent", "v3-fingerprint", "antigravity", "model-test", "dispatch_intent", 100, 1_000, 1, null, OWNER_ID, 101);
    db.prepare(
      `INSERT INTO leases (
         lease_id, request_id, generation, owner_instance_id, phase, acquired_at, heartbeat_at,
         suspect_since, suspect_reason
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(LEASE_ID, REQUEST_ID, 1, OWNER_ID, "dispatch_intent", 101, 102, null, null);
    db.prepare("INSERT INTO cooldowns VALUES (?, ?, ?, ?)").run("antigravity", "model-test", 900, 101);
    db.prepare(
      `INSERT INTO turn_payloads (
         request_id, nonce, ciphertext, auth_tag, key_version, content_fingerprint, expires_at, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(REQUEST_ID, Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6]), Buffer.from([7, 8, 9]), 1, "content-fingerprint", 900, 101);
    db.prepare(
      `INSERT INTO lease_process_identities (
         lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
         connector_owner_instance_id, connector_created_at, connector_boot_id, connector_pid,
         connector_start_time_ticks, connector_pid_namespace_inode, connector_ppid, connector_pgrp,
         connector_session, child_boot_id, child_pid, child_start_time_ticks, child_pid_namespace_inode,
         child_ppid, child_pgrp, child_session, recorded_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      LEASE_ID,
      REQUEST_ID,
      1,
      OWNER_ID,
      "stdin",
      OWNER_ID,
      "2026-08-14T00:00:00.000Z",
      BOOT_ID,
      3711,
      "100",
      NAMESPACE_INODE,
      1,
      3711,
      3711,
      BOOT_ID,
      4182,
      "200",
      NAMESPACE_INODE,
      3711,
      4182,
      4182,
      103
    );
    db.prepare("INSERT INTO start_history VALUES (?, ?)").run(LEASE_ID, 101);
    db.prepare(
      `INSERT INTO policy_state VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(1, 3, 1, 2_000, 30 * 60_000, 30_000, "steady", "legacy-policy-fingerprint", 101, OWNER_ID);
    db.prepare(
      `INSERT INTO queued_owner_instances VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(OWNER_ID, "2026-08-14T00:00:00.000Z", BOOT_ID, 3711, "100", NAMESPACE_INODE, 1, 3711, 3711, 101);
    db.prepare(
      `INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run("v3-session", "conversation-v3", 12, "model-test", "high", "default", "/tmp", "[]", "[]", 101);
    db.prepare("INSERT INTO events (kind, from_state, to_state, occurred_at, correlation_hmac) VALUES (?, ?, ?, ?, ?)").run(
      "request_dispatch_intent",
      "starting",
      "dispatch_intent",
      103,
      "a".repeat(64)
    );
  } finally {
    db.close();
  }
}

function snapshot(file: string): Record<string, unknown[]> {
  const db = new Database(file, { readonly: true });
  try {
    const snapshot: Record<string, unknown[]> = {};
    for (const table of ["turn_requests", "leases", "cooldowns", "turn_payloads", "start_history", "sessions", "events"]) {
      snapshot[table] = db.prepare(`SELECT * FROM ${table}`).all();
    }
    return snapshot;
  } finally {
    db.close();
  }
}

function columns(file: string, table: string): string[] {
  const db = new Database(file, { readonly: true });
  try {
    return (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((row) => row.name);
  } finally {
    db.close();
  }
}

function ledger(file: string): Array<{ version: number; name: string }> {
  const db = new Database(file, { readonly: true });
  try {
    return db.prepare("SELECT version, name FROM schema_migrations ORDER BY version").all() as Array<{ version: number; name: string }>;
  } finally {
    db.close();
  }
}

afterEach(() => {
  for (const stateDir of stateDirs.splice(0)) rmSync(stateDir, { recursive: true, force: true });
});

describe("canonical platform-tagged process evidence and schema v4", () => {
  it("serializes and parses only canonical evidence for the selected platform", () => {
    const linux = identity(4182);
    const encoded = serializeProcessIdentity(linux, "linux");
    expect(parseProcessIdentity(encoded, "linux")).toEqual(linux);
    expect(parseProcessIdentity(encoded, "darwin")).toBeNull();
    expect(parseProcessIdentity(JSON.stringify({ ...JSON.parse(encoded), extra: true }), "linux")).toBeNull();
    expect(parseProcessIdentity(serializeProcessIdentity(linux, "darwin"), "linux")).toBeNull();
    expect(parseProcessIdentity('{"platform":"linux"}', "linux")).toBeNull();
  });

  it("creates fresh v4 state directly and records the selected evidence platform", () => {
    const file = databasePath();
    const admission = openController(file, "darwin");
    try {
      admission.claimDurablePolicy(POLICY, OWNER_ID, 1_000);
      admission.enqueue({
        requestId: "fresh-v4-request",
        sessionId: "fresh-v4-session",
        agentId: "fresh-v4-agent",
        fingerprint: "fresh-v4-fingerprint",
        provider: "antigravity",
        model: "model-test",
        now: 1_001
      });
    } finally {
      admission.close();
    }

    const db = new Database(file, { readonly: true });
    try {
      expect(ledger(file)).toEqual([{ version: 4, name: "shared-admission-queue-v4" }]);
      expect(db.prepare("SELECT process_evidence_platform FROM policy_state").get()).toEqual({ process_evidence_platform: "darwin" });
      const row = db.prepare("SELECT queued_owner_evidence_json AS evidence FROM queued_owner_instances").get() as { evidence: string };
      expect(parseProcessIdentity(row.evidence, "darwin")).toEqual(identity(process.pid));
    } finally {
      db.close();
    }
  });

  it("migrates a real v3 fixture transactionally and preserves durable state", () => {
    const file = databasePath();
    createV3Database(file);
    const before = snapshot(file);
    const admission = openController(file);
    try {
      expect(admission.schemaVersion).toBe(4);
      expect(ledger(file)).toEqual([
        { version: 1, name: "shared-admission-queue" },
        { version: 2, name: "shared-admission-queue-v2" },
        { version: 3, name: "shared-admission-queue-v3" },
        { version: 4, name: "shared-admission-queue-v4" }
      ]);
      expect(snapshot(file)).toEqual(before);
      expect(columns(file, "lease_process_identities")).toContain("connector_evidence_json");
      expect(columns(file, "queued_owner_instances")).toContain("queued_owner_evidence_json");
      const db = new Database(file, { readonly: true });
      try {
        db.pragma("foreign_keys = ON");
        const row = db.prepare("SELECT connector_evidence_json AS connector, child_evidence_json AS child FROM lease_process_identities").get() as {
          connector: string;
          child: string;
        };
        expect(parseProcessIdentity(row.connector, "linux")).toEqual({ ...identity(3711), startTimeTicks: "100" });
        expect(parseProcessIdentity(row.child, "linux")).toEqual({ ...identity(4182), startTimeTicks: "200", ppid: 3711 });
        expect(db.prepare(
          `SELECT lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
                  connector_owner_instance_id, connector_created_at, recorded_at
           FROM lease_process_identities`
        ).get()).toEqual({
          lease_id: LEASE_ID,
          request_id: REQUEST_ID,
          lease_generation: 1,
          owner_instance_id: OWNER_ID,
          prompt_channel: "stdin",
          connector_owner_instance_id: OWNER_ID,
          connector_created_at: "2026-08-14T00:00:00.000Z",
          recorded_at: 103
        });
        expect(db.prepare(
          "SELECT owner_instance_id, created_at, recorded_at FROM queued_owner_instances"
        ).get()).toEqual({
          owner_instance_id: OWNER_ID,
          created_at: "2026-08-14T00:00:00.000Z",
          recorded_at: 101
        });
        expect(db.prepare("SELECT * FROM policy_state").get()).toEqual({
          id: 1,
          max_active_turns: 3,
          max_concurrent_starts: 1,
          min_start_interval_ms: 2_000,
          queue_timeout_ms: 30 * 60_000,
          capacity_cooldown_ms: 30_000,
          drain_state: "steady",
          policy_fingerprint: "legacy-policy-fingerprint",
          updated_at: 101,
          updated_by_owner_instance_id: OWNER_ID,
          process_evidence_platform: "linux"
        });
        expect(() => assertAdmissionSchemaIntegrity(db)).not.toThrow();
      } finally {
        db.close();
      }
    } finally {
      admission.close();
    }
  });

  it("rejects noncanonical v4 evidence through the exact schema guard", () => {
    const file = databasePath();
    createV3Database(file);
    const admission = openController(file);
    admission.close();
    const db = new Database(file);
    try {
      db.pragma("foreign_keys = ON");
      const row = db.prepare("SELECT child_evidence_json AS evidence FROM lease_process_identities").get() as { evidence: string };
      const parsed = JSON.parse(row.evidence) as Record<string, unknown>;
      db.prepare("UPDATE lease_process_identities SET child_evidence_json = ? WHERE lease_id = ?").run(
        JSON.stringify({ ...parsed, extra: true }),
        LEASE_ID
      );
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(SchemaIntegrityError);
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(/canonical JSON/i);
    } finally {
      db.close();
    }
  });

  it("rejects evidence whose platform differs from the policy binding", () => {
    const file = databasePath();
    createV3Database(file);
    const admission = openController(file);
    admission.close();
    const db = new Database(file);
    try {
      db.pragma("foreign_keys = ON");
      const row = db.prepare("SELECT child_evidence_json AS evidence FROM lease_process_identities").get() as { evidence: string };
      db.prepare(
        `UPDATE lease_process_identities
         SET connector_evidence_json = ?, child_evidence_json = ?
         WHERE lease_id = ?`
      ).run(
        serializeProcessIdentity(identity(3711), "darwin"),
        serializeProcessIdentity(identity(4182), "darwin"),
        LEASE_ID
      );
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(SchemaIntegrityError);
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(/platform does not match/i);
      expect(row.evidence).not.toBe(serializeProcessIdentity(identity(4182), "darwin"));
    } finally {
      db.close();
    }
  });

  it("rejects a partial queued-owner index with the wrong predicate", () => {
    const file = databasePath();
    const admission = openController(file);
    admission.close();
    const db = new Database(file);
    try {
      db.pragma("foreign_keys = ON");
      db.exec(`
        DROP INDEX turn_requests_queued_owner;
        CREATE INDEX turn_requests_queued_owner
          ON turn_requests(queued_owner_instance_id)
          WHERE queued_owner_instance_id IS NULL;
      `);
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(SchemaIntegrityError);
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(/index .*definition|index .*schema contract/i);
    } finally {
      db.close();
    }
  });

  it("rejects partial, unknown, and newer migration ledgers", () => {
    for (const mutation of [
      "DELETE FROM schema_migrations WHERE version = 4",
      "INSERT INTO schema_migrations (version, name, applied_at) VALUES (5, 'unknown', 5)",
      "UPDATE schema_migrations SET version = 3, name = 'shared-admission-queue-v3' WHERE version = 4"
    ]) {
      const file = databasePath();
      const admission = openController(file);
      admission.close();
      const db = new Database(file);
      db.pragma("foreign_keys = ON");
      db.exec(mutation);
      db.close();
      expect(() => openController(file)).toThrow(AdmissionMigrationError);
    }
  });

  it("rolls back a v3 schema with unexpected affected metadata", () => {
    const file = databasePath();
    createV3Database(file);
    const db = new Database(file);
    db.exec("ALTER TABLE queued_owner_instances ADD COLUMN unexpected TEXT");
    db.close();
    expect(() => openController(file)).toThrow(AdmissionMigrationError);
    expect(columns(file, "queued_owner_instances")).toContain("unexpected");
    expect(columns(file, "queued_owner_instances")).not.toContain("queued_owner_evidence_json");
  });

  it("rejects a v3 identity index with the wrong key column", () => {
    const file = databasePath();
    createV3Database(file);
    const db = new Database(file);
    db.exec(`
      DROP INDEX lease_process_identities_request;
      CREATE UNIQUE INDEX lease_process_identities_request ON lease_process_identities(lease_id);
    `);
    db.close();
    expect(() => openController(file)).toThrow(AdmissionMigrationError);
  });

  it("rolls back malformed v3 evidence and leaves the original database usable", () => {
    const file = databasePath();
    createV3Database(file);
    const db = new Database(file);
    db.prepare("UPDATE lease_process_identities SET connector_boot_id = ? WHERE lease_id = ?").run("malformed", LEASE_ID);
    db.close();

    expect(() => openController(file)).toThrow(AdmissionMigrationError);
    expect(ledger(file)).toEqual([
      { version: 1, name: "shared-admission-queue" },
      { version: 2, name: "shared-admission-queue-v2" },
      { version: 3, name: "shared-admission-queue-v3" }
    ]);
    expect(columns(file, "lease_process_identities")).toContain("connector_boot_id");
    expect(columns(file, "lease_process_identities")).not.toContain("connector_evidence_json");
  });

  it("rolls back a failed v4 DDL operation without partial tables", () => {
    const file = databasePath();
    createV3Database(file);
    const db = new Database(file);
    db.exec("CREATE TABLE policy_state_v4 (id INTEGER PRIMARY KEY)");
    db.close();

    expect(() => openController(file)).toThrow(AdmissionMigrationError);
    expect(ledger(file)).toHaveLength(3);
    expect(columns(file, "lease_process_identities")).toContain("connector_boot_id");
    expect(columns(file, "policy_state")).not.toContain("process_evidence_platform");
  });

  it("rejects an opener whose evidence platform differs from durable state", () => {
    const file = databasePath();
    const admission = openController(file);
    try {
      admission.claimDurablePolicy(POLICY, OWNER_ID, 1_000);
      admission.enqueue({
        requestId: "platform-request",
        sessionId: "platform-session",
        agentId: "platform-agent",
        fingerprint: "platform-fingerprint",
        provider: "antigravity",
        model: "model-test",
        now: 1_001
      });
    } finally {
      admission.close();
    }

    expect(() => openController(file, "darwin")).toThrow(AdmissionRuntimeError);
    expect(() => openController(file, "darwin")).toThrow(/process evidence platform does not match/i);
  });
});
