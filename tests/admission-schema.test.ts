import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  createLinuxProcessEvidence,
  type ProcessEvidence
} from "../Admission Controller/process-evidence.js";
import { AdmissionController, type AdmissionPolicy } from "../Admission Controller/controller.js";
import {
  ADMISSION_SCHEMA_VERSION,
  SchemaIntegrityError,
  assertAdmissionSchemaIntegrity
} from "../Admission Controller/schema.js";

const stateDirs: string[] = [];
const controllers: AdmissionController[] = [];

const POLICY: AdmissionPolicy = {
  maxActiveTurns: 3,
  maxConcurrentStarts: 1,
  minStartIntervalMs: 2_000,
  queueTimeoutMs: 30 * 60_000,
  capacityCooldownMs: 30_000
};

function processEvidence(): ProcessEvidence {
  return createLinuxProcessEvidence({
    listProcessIds: () => [],
    readers: {
      readFile(path) {
        if (path === "/proc/sys/kernel/random/boot_id") return "f4bca3da-9bd5-4f2e-89b8-5e12e5ee8f31\n";
        if (path === `/proc/${process.pid}/stat`) {
          const fields = [
            "S", "1", String(process.pid), String(process.pid), "0", "-1", "4194560", "1", "0", "0", "0", "4", "2", "0", "0", "20", "0", "1", "0", "100", "0", "0"
          ];
          return `${process.pid} (test) ${fields.join(" ")}\n`;
        }
        throw Object.assign(new Error("gone"), { code: "ENOENT" });
      },
      readLink(path) {
        if (path === `/proc/${process.pid}/ns/pid`) return "pid:[4026531836]";
        throw Object.assign(new Error("gone"), { code: "ENOENT" });
      }
    }
  });
}

function createController(): AdmissionController {
  const stateDir = mkdtempSync(path.join(os.tmpdir(), "paseo-agy-schema-"));
  stateDirs.push(stateDir);
  const admission = new AdmissionController({
    databasePath: path.join(stateDir, "runtime.sqlite"),
    policy: POLICY,
    encryptionKey: Buffer.alloc(32, 41),
    contentFingerprintKey: Buffer.alloc(32, 42),
    processEvidence: processEvidence()
  });
  controllers.push(admission);
  return admission;
}

function columnNames(db: Database.Database, table: string): string[] {
  return (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((column) => column.name);
}

afterEach(() => {
  for (const admission of controllers.splice(0)) admission.close();
  for (const stateDir of stateDirs.splice(0)) rmSync(stateDir, { recursive: true, force: true });
});

describe("AdmissionController schema v4", () => {
  it("contains the exact v4 shared queue tables and migration ledger", () => {
    const admission = createController();
    const db = new Database(admission.databasePath, { readonly: true });
    try {
      const tables = (db
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .all() as Array<{ name: string }>).map((row) => row.name);
      expect(tables).toEqual([
        "cooldowns",
        "events",
        "lease_process_identities",
        "leases",
        "policy_state",
        "queued_owner_instances",
        "schema_migrations",
        "sessions",
        "start_history",
        "turn_payloads",
        "turn_requests"
      ]);
      expect(columnNames(db, "turn_requests")).toEqual([
        "request_id",
        "session_id",
        "agent_id",
        "fingerprint",
        "provider",
        "model",
        "state",
        "enqueued_at",
        "deadline_at",
        "lease_generation",
        "terminal_at",
        "queued_owner_instance_id",
        "queued_owner_recorded_at"
      ]);
      expect(columnNames(db, "turn_requests")).not.toContain("parent_id");
      expect(columnNames(db, "leases")).toContain("suspect_since");
      expect(columnNames(db, "leases")).toContain("suspect_reason");
      expect(columnNames(db, "lease_process_identities")).toEqual([
        "lease_id",
        "request_id",
        "lease_generation",
        "owner_instance_id",
        "prompt_channel",
        "connector_owner_instance_id",
        "connector_created_at",
        "connector_evidence_json",
        "child_evidence_json",
        "recorded_at"
      ]);
      expect(columnNames(db, "policy_state")).toEqual([
        "id",
        "max_active_turns",
        "max_concurrent_starts",
        "min_start_interval_ms",
        "queue_timeout_ms",
        "capacity_cooldown_ms",
        "drain_state",
        "policy_fingerprint",
        "updated_at",
        "updated_by_owner_instance_id",
        "process_evidence_platform"
      ]);
      expect(columnNames(db, "queued_owner_instances")).toEqual([
        "owner_instance_id",
        "created_at",
        "queued_owner_evidence_json",
        "recorded_at"
      ]);
      expect(db.prepare("SELECT version, name FROM schema_migrations ORDER BY version").all()).toEqual([
        { version: 4, name: "shared-admission-queue-v4" }
      ]);
      expect(tables).not.toContain("delivery_outbox");
      expect(tables).not.toContain("delivery_claim_leases");
      expect(tables).not.toContain("recovery_claims");
      expect(admission.schemaVersion).toBe(ADMISSION_SCHEMA_VERSION);
    } finally {
      db.close();
    }
  });

  it("rejects an old-scheme table instead of silently accepting mixed ownership", () => {
    const admission = createController();
    admission.close();
    controllers.splice(controllers.indexOf(admission), 1);

    const db = new Database(admission.databasePath);
    db.pragma("foreign_keys = ON");
    try {
      db.exec("CREATE TABLE delivery_outbox (event_id TEXT PRIMARY KEY)");
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(SchemaIntegrityError);
      expect(() => assertAdmissionSchemaIntegrity(db)).toThrow(/unexpected table delivery_outbox/i);
    } finally {
      db.close();
    }
  });
});
