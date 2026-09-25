import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import {
  ADMISSION_SCHEMA_VERSION,
  assertAdmissionSchemaIntegrity
} from "./schema.js";
import {
  createLinuxProcessEvidence,
  requireProcessEvidence,
  serializeProcessIdentity,
  type ProcessEvidence,
  type ProcessEvidencePlatform,
  type ProcessIdentity,
  type ProcessIdentityState
} from "./process-evidence.js";
import {
  normalizePlatformProcessIdentity,
  parsePlatformProcessIdentity,
  PLATFORM_PROCESS_IDENTITY_KEYS,
  serializePlatformProcessIdentity,
  type PlatformProcessIdentity
} from "./canonical-process-identity.js";
import {
  isAllowedAdmissionActiveTurns,
  isAllowedAdmissionConcurrentStarts
} from "./policy-limits.js";

export {
  isAllowedAdmissionActiveTurns,
  isAllowedAdmissionConcurrentStarts
} from "./policy-limits.js";

const MAX_DISPATCH_CONTENTION_RECHECKS = 500;
const DISPATCH_CONTENTION_RECHECK_DELAY_MS = 2;
const LEASE_HEARTBEAT_STALE_MS = 4_000;
const ADMISSION_MIGRATION_NAMES = [
  "shared-admission-queue",
  "shared-admission-queue-v2",
  "shared-admission-queue-v3",
  "shared-admission-queue-v4"
] as const;

const dispatchContentionRetrySignal = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

export interface AdmissionPolicy {
  maxActiveTurns: number;
  maxConcurrentStarts: number;
  minStartIntervalMs: number;
  queueTimeoutMs: number;
  capacityCooldownMs: number;
}

export interface AdmissionControllerOptions {
  databasePath: string;
  policy: AdmissionPolicy;
  encryptionKey?: Buffer;
  contentFingerprintKey?: Buffer;
  processEvidence?: ProcessEvidence<PlatformProcessIdentity>;
  /** Test-only synchronous hook for proving rollback at the atomic dispatch boundary. */
  faultInjection?: AdmissionControllerFaultInjection;
}

/** Test-only synchronous hooks for proving rollback at durable transaction midpoints. */
export interface AdmissionControllerFaultInjection {
  afterProcessIdentityPersisted?(): void;
}

interface EnqueueRequestBase {
  requestId: string;
  sessionId: string;
  fingerprint: string;
  provider: string;
  model: string;
  now: number;
  ownerIdentity?: VerifiedConnectorIdentity;
}

export type EnqueueRequest = EnqueueRequestBase & {
  agentId?: string;
  parentId?: string;
};

export type ConfirmedProviderOutcome = "completed" | "failed" | "cancelled";

export type RequestState =
  | "queued"
  | "admitted"
  | "starting"
  | "dispatch_intent"
  | "dispatch_ambiguous"
  | "active"
  | "provider_terminal"
  | "completed"
  | "failed"
  | "cancelled"
  | "queue_timeout"
  | "recovery_required";

export type PolicyEventState = "policy_steady" | "policy_soft_draining_to_1";

export type SanitizedEventState = RequestState | PolicyEventState | "absent";

export type SanitizedEventKind =
  | "request_enqueued"
  | "request_cancelled"
  | "request_abandoned"
  | "request_queue_timed_out"
  | "request_admitted"
  | "request_starting"
  | "request_dispatch_intent"
  | "request_active"
  | "request_dispatch_ambiguous"
  | "request_provider_terminal"
  | "request_released"
  | "request_recovery_required"
  | "request_recovery_seat_released"
  | "queued_owner_dead"
  | "policy_drain_completed";

/** Exact, identifier-free pagination input for the sanitized audit journal. */
export interface SanitizedEventPageRequest {
  afterEventSeq: number;
  limit: number;
}

/** Audit-only state transition. It cannot be used to recover request payloads or identities. */
export interface SanitizedAdmissionEvent {
  readonly eventSeq: number;
  readonly kind: SanitizedEventKind;
  readonly fromState: SanitizedEventState;
  readonly toState: SanitizedEventState;
  readonly occurredAt: number;
  readonly correlationHmac: string;
}

export interface StoredRequest {
  requestId: string;
  sessionId: string;
  agentId: string;
  fingerprint: string;
  provider: string;
  model: string;
  state: RequestState;
  enqueuedAt: number;
}

/** Terminal fact for the existing online ACP output path. */
export interface LiveTurnCompletion {
  readonly outcome: ConfirmedProviderOutcome;
  readonly failure?: Readonly<{
    readonly category: "provider_capacity" | "quota" | "auth" | "permission" | "timeout" | "transport" | "unknown";
    readonly httpStatus?: number;
    readonly code?: string;
    readonly reason?: string;
  }>;
}

/** Durable queue observation. It grants no admission or recovery authority. */
export interface AdmissionQueueSnapshot {
  readonly requestId: string;
  readonly position: number;
  readonly eligiblePosition: number | null;
  readonly enqueuedAt: number;
  readonly waitedMs: number;
  readonly cooldownUntil: number | null;
}

export interface AdmissionLease {
  leaseId: string;
  requestId: string;
  generation: number;
  ownerInstanceId: string;
}

export type LeaseFence = Pick<AdmissionLease, "leaseId" | "generation" | "ownerInstanceId">;

/** Nonterminal controller phases which need a startup recovery decision. */
export type RecoverableDispatchPhase =
  | "admitted"
  | "starting"
  | "dispatch_intent"
  | "dispatch_ambiguous"
  | "active"
  | "recovery_required";

/** Immutable evidence for one process instance. */
export type VerifiedProcessIdentity = PlatformProcessIdentity;

export type VerifiedLinuxProcessIdentity = ProcessIdentity;

/** Connector owner evidence paired with the connector's stable instance ID. */
export type VerifiedConnectorIdentity = PlatformProcessIdentity & {
  ownerInstanceId: string;
  createdAt: string;
};

export type VerifiedLinuxConnectorIdentity = ProcessIdentity & {
  ownerInstanceId: string;
  createdAt: string;
};

/** The only process record accepted at the irreversible dispatch boundary. */
export interface VerifiedProcessRecord {
  requestId: string;
  leaseId: string;
  generation: number;
  ownerInstanceId: string;
  processIdentity: {
    connector: VerifiedConnectorIdentity;
    child: VerifiedProcessIdentity;
  };
  promptChannel: "stdin" | "pty";
}

export type VerifiedLinuxProcessRecord = Omit<VerifiedProcessRecord, "processIdentity"> & {
  processIdentity: {
    connector: VerifiedLinuxConnectorIdentity;
    child: VerifiedLinuxProcessIdentity;
  };
};

/** Durable process evidence available to startup recovery, never request content. */
export interface RecoverableDispatchProcessIdentity {
  readonly promptChannel: "stdin" | "pty";
  readonly connector: VerifiedConnectorIdentity;
  readonly child: VerifiedProcessIdentity;
}

/**
 * One nonterminal dispatch candidate after connector startup. A null process
 * identity is intentionally explicit: the caller must fail closed into
 * recovery and must not resume or replay the dispatch from this inventory.
 */
export interface RecoverableDispatch {
  readonly requestId: string;
  readonly sessionId: string;
  readonly provider: string;
  readonly model: string;
  readonly fence: LeaseFence;
  readonly phase: RecoverableDispatchPhase;
  readonly heartbeatAt: number;
  readonly processIdentity: RecoverableDispatchProcessIdentity | null;
}

/** Durable queued-owner evidence for a request that has not dispatched. */
export interface RecoverableQueuedOwner {
  readonly requestId: string;
  readonly owner: VerifiedConnectorIdentity;
}

export type LeaseSuspectReason = "heartbeat_expired" | "identity_unverifiable";

export interface AdmissionRuntimeReaperSummary {
  readonly inspected: number;
  readonly released: number;
  readonly retained: number;
  readonly markedRecoveryRequired: number;
  readonly suspected: number;
  readonly queuedSettled: number;
}

export type DispatchIntentFailureReason =
  | "invalid_process_identity"
  | "stale_lease"
  | "conflicting_intent"
  | "transaction_fault";

/** Result for the dispatcher identity callback. Success means dispatch_intent is already durable too. */
export type ProcessIdentityRecordResult =
  | { status: "recorded"; idempotent: boolean }
  | { status: "not_recorded"; reason: DispatchIntentFailureReason };

/** Result for the dispatch boundary's following commit callback; only an exact durable replay succeeds. */
export type DispatchIntentCommitResult =
  | { status: "committed"; idempotent: boolean }
  | { status: "not_committed"; reason: DispatchIntentFailureReason };

interface RequestRow {
  request_id: string;
  session_id: string;
  agent_id: string;
  fingerprint: string;
  provider: string;
  model: string;
  state: RequestState;
  enqueued_at: number;
  lease_generation: number;
}

interface LeaseRow {
  lease_id: string;
  request_id: string;
  generation: number;
  owner_instance_id: string;
  phase: RequestState;
}

interface DispatchContentionRecheckRow extends LeaseRow {
  request_state: RequestState;
  request_lease_generation: number;
}

interface PayloadRow {
  nonce: Buffer;
  ciphertext: Buffer;
  auth_tag: Buffer;
  key_version: number;
  content_fingerprint: string | null;
  expires_at: number;
}

interface EncryptedPayload {
  nonce: Buffer;
  ciphertext: Buffer;
  authTag: Buffer;
}

interface SanitizedEventRow {
  event_seq: unknown;
  kind: unknown;
  from_state: unknown;
  to_state: unknown;
  occurred_at: unknown;
  correlation_hmac: unknown;
}

interface LeaseProcessIdentityRow {
  lease_id: string;
  request_id: string;
  lease_generation: number;
  owner_instance_id: string;
  prompt_channel: "stdin" | "pty";
  connector_owner_instance_id: string;
  connector_created_at: string;
  connector_evidence_json: unknown;
  child_evidence_json: unknown;
  recorded_at: number;
}

interface PolicyStateRow {
  max_active_turns: unknown;
  max_concurrent_starts: unknown;
  min_start_interval_ms: unknown;
  queue_timeout_ms: unknown;
  capacity_cooldown_ms: unknown;
  drain_state: unknown;
  policy_fingerprint: unknown;
  updated_at: unknown;
  updated_by_owner_instance_id: unknown;
  process_evidence_platform: unknown;
}

interface QueuedOwnerRequestRow {
  state: RequestState;
  queued_owner_instance_id: string | null;
}

interface QueuedOwnerIdentityRow {
  owner_instance_id: string;
  created_at: string;
  queued_owner_evidence_json: unknown;
  recorded_at: number;
}

interface RecoverableQueuedOwnerRow extends QueuedOwnerIdentityRow {
  request_id: unknown;
}

/** Raw values from SQLite must be normalized before startup recovery uses them. */
interface RecoverableDispatchRow {
  lease_id: unknown;
  lease_request_id: unknown;
  lease_generation: unknown;
  lease_owner_instance_id: unknown;
  lease_phase: unknown;
  lease_heartbeat_at: unknown;
  request_id: unknown;
  request_session_id: unknown;
  request_provider: unknown;
  request_model: unknown;
  request_state: unknown;
  request_lease_generation: unknown;
  request_enqueued_at: unknown;
  identity_lease_id: unknown;
  identity_request_id: unknown;
  identity_lease_generation: unknown;
  identity_owner_instance_id: unknown;
  identity_prompt_channel: unknown;
  identity_connector_owner_instance_id: unknown;
  identity_connector_created_at: unknown;
  identity_connector_evidence_json: unknown;
  identity_child_evidence_json: unknown;
}

type AtomicDispatchIntentOutcome =
  | { status: "committed"; idempotent: boolean }
  | { status: "not_committed"; reason: DispatchIntentFailureReason };

interface V3LeaseProcessIdentityRow {
  lease_id: unknown;
  request_id: unknown;
  lease_generation: unknown;
  owner_instance_id: unknown;
  prompt_channel: unknown;
  connector_owner_instance_id: unknown;
  connector_created_at: unknown;
  connector_boot_id: unknown;
  connector_pid: unknown;
  connector_start_time_ticks: unknown;
  connector_pid_namespace_inode: unknown;
  connector_ppid: unknown;
  connector_pgrp: unknown;
  connector_session: unknown;
  child_boot_id: unknown;
  child_pid: unknown;
  child_start_time_ticks: unknown;
  child_pid_namespace_inode: unknown;
  child_ppid: unknown;
  child_pgrp: unknown;
  child_session: unknown;
  recorded_at: unknown;
}

interface V3QueuedOwnerIdentityRow {
  owner_instance_id: unknown;
  created_at: unknown;
  boot_id: unknown;
  pid: unknown;
  start_time_ticks: unknown;
  pid_namespace_inode: unknown;
  ppid: unknown;
  pgrp: unknown;
  session: unknown;
  recorded_at: unknown;
}

interface V3ColumnInfoRow {
  name: unknown;
  type: unknown;
  notnull: unknown;
  pk: unknown;
}

const V3_MIGRATION_COLUMNS: Readonly<Record<string, readonly (readonly [string, string, number, number])[]>> = {
  lease_process_identities: [
    ["lease_id", "TEXT", 0, 1],
    ["request_id", "TEXT", 1, 0],
    ["lease_generation", "INTEGER", 1, 0],
    ["owner_instance_id", "TEXT", 1, 0],
    ["prompt_channel", "TEXT", 1, 0],
    ["connector_owner_instance_id", "TEXT", 1, 0],
    ["connector_created_at", "TEXT", 1, 0],
    ["connector_boot_id", "TEXT", 1, 0],
    ["connector_pid", "INTEGER", 1, 0],
    ["connector_start_time_ticks", "TEXT", 1, 0],
    ["connector_pid_namespace_inode", "INTEGER", 1, 0],
    ["connector_ppid", "INTEGER", 1, 0],
    ["connector_pgrp", "INTEGER", 1, 0],
    ["connector_session", "INTEGER", 1, 0],
    ["child_boot_id", "TEXT", 1, 0],
    ["child_pid", "INTEGER", 1, 0],
    ["child_start_time_ticks", "TEXT", 1, 0],
    ["child_pid_namespace_inode", "INTEGER", 1, 0],
    ["child_ppid", "INTEGER", 1, 0],
    ["child_pgrp", "INTEGER", 1, 0],
    ["child_session", "INTEGER", 1, 0],
    ["recorded_at", "INTEGER", 1, 0]
  ],
  policy_state: [
    ["id", "INTEGER", 0, 1],
    ["max_active_turns", "INTEGER", 1, 0],
    ["max_concurrent_starts", "INTEGER", 1, 0],
    ["min_start_interval_ms", "INTEGER", 1, 0],
    ["queue_timeout_ms", "INTEGER", 1, 0],
    ["capacity_cooldown_ms", "INTEGER", 1, 0],
    ["drain_state", "TEXT", 1, 0],
    ["policy_fingerprint", "TEXT", 1, 0],
    ["updated_at", "INTEGER", 1, 0],
    ["updated_by_owner_instance_id", "TEXT", 1, 0]
  ],
  queued_owner_instances: [
    ["owner_instance_id", "TEXT", 0, 1],
    ["created_at", "TEXT", 1, 0],
    ["boot_id", "TEXT", 1, 0],
    ["pid", "INTEGER", 1, 0],
    ["start_time_ticks", "TEXT", 1, 0],
    ["pid_namespace_inode", "INTEGER", 1, 0],
    ["ppid", "INTEGER", 1, 0],
    ["pgrp", "INTEGER", 1, 0],
    ["session", "INTEGER", 1, 0],
    ["recorded_at", "INTEGER", 1, 0]
  ]
};

export class AdmissionConflictError extends Error {
  constructor(_requestId: string) {
    super("request identity was reused with different immutable metadata");
    this.name = "AdmissionConflictError";
  }
}

export class PayloadExpiredError extends Error {
  constructor(_requestId: string) {
    super("request payload has expired");
    this.name = "PayloadExpiredError";
  }
}

export class PayloadConflictError extends Error {
  constructor(_requestId: string) {
    super("request already has a different durable payload");
    this.name = "PayloadConflictError";
  }
}

export class LeaseFenceError extends Error {
  constructor(_leaseId: string) {
    super("lease is not owned by the supplied generation fence");
    this.name = "LeaseFenceError";
  }
}

/** Raised when durable recovery inventory data cannot be trusted. */
export class RecoverableDispatchInventoryError extends Error {
  constructor() {
    super("recoverable dispatch inventory contains an invalid durable row");
    this.name = "RecoverableDispatchInventoryError";
  }
}

class AdmissionControllerInjectedFaultError extends Error {
  constructor() {
    super("admission transaction fault injection");
    this.name = "AdmissionControllerInjectedFaultError";
  }
}

export class AdmissionMigrationError extends Error {
  constructor(detail: string) {
    super(`admission schema migration failed: ${detail}`);
    this.name = "AdmissionMigrationError";
  }
}

export class AdmissionRuntimeError extends Error {
  constructor(message: string) {
    super(`admission runtime error: ${message}`);
    this.name = "AdmissionRuntimeError";
  }
}

/**
 * A local, cross-process admission plane. It deliberately refuses to infer
 * that a dispatched turn is safe to replay after a crash.
 */
export class AdmissionController {
  readonly databasePath: string;
  readonly policy: AdmissionPolicy;
  readonly #db: Database.Database;
  readonly #encryptionKey?: Buffer;
  readonly #contentFingerprintKey?: Buffer;
  readonly #faultInjection?: AdmissionControllerFaultInjection;
  readonly #processEvidence: ProcessEvidence<PlatformProcessIdentity>;
  readonly #queuedOwnerIdentity: VerifiedConnectorIdentity;

  constructor(options: AdmissionControllerOptions) {
    this.databasePath = options.databasePath;
    this.policy = validatePolicy(options.policy);
    this.#encryptionKey = validatePurposeKey(options.encryptionKey, "encryption");
    this.#contentFingerprintKey = validatePurposeKey(options.contentFingerprintKey, "content fingerprint");
    this.#faultInjection = validateFaultInjection(options.faultInjection);
    this.#processEvidence = requireProcessEvidence<PlatformProcessIdentity>(
      options.processEvidence ?? createLinuxProcessEvidence()
    );
    this.#queuedOwnerIdentity = captureControllerQueuedOwnerIdentity(this.#processEvidence);
    this.#db = new Database(options.databasePath);
    try {
      this.#db.pragma("foreign_keys = ON");
      this.#db.pragma("journal_mode = WAL");
      this.#db.pragma("synchronous = FULL");
      this.#db.pragma("busy_timeout = 5000");
      this.migrate();
      this.assertDurableStatePlatform();
    } catch (error) {
      try {
        this.#db.close();
      } catch {
        this.#encryptionKey?.fill(0);
        this.#contentFingerprintKey?.fill(0);
        throw error;
      }
      this.#encryptionKey?.fill(0);
      this.#contentFingerprintKey?.fill(0);
      throw error;
    }
  }

  close(): void {
    this.#db.close();
    this.#encryptionKey?.fill(0);
    this.#contentFingerprintKey?.fill(0);
  }

  get schemaVersion(): number {
    const ledger = this.#db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'")
      .get();
    if (ledger === undefined) return 0;
    const row = this.#db
      .prepare("SELECT MAX(version) AS version FROM schema_migrations")
      .get() as { version: number | null };
    return row.version ?? 0;
  }

  get processEvidence(): ProcessEvidence {
    return requireLinuxProcessEvidence(this.#processEvidence);
  }

  private assertDurableStatePlatform(): void {
    const platform = this.#processEvidence.platform;
    const policy = this.readPolicyStateInTransaction();
    if (policy !== undefined && policy.process_evidence_platform !== platform) {
      throw new AdmissionRuntimeError("process evidence platform does not match durable admission platform");
    }

    const dispatchRows = this.#db
      .prepare("SELECT connector_evidence_json, child_evidence_json FROM lease_process_identities")
      .all() as Array<{ connector_evidence_json: unknown; child_evidence_json: unknown }>;
    for (const row of dispatchRows) {
      if (
        parsePlatformProcessIdentity(row.connector_evidence_json, platform) === null ||
        parsePlatformProcessIdentity(row.child_evidence_json, platform) === null
      ) {
        throw new AdmissionRuntimeError("durable process evidence is invalid for the selected platform");
      }
    }

    const ownerRows = this.#db
      .prepare("SELECT queued_owner_evidence_json FROM queued_owner_instances")
      .all() as Array<{ queued_owner_evidence_json: unknown }>;
    for (const row of ownerRows) {
      if (parsePlatformProcessIdentity(row.queued_owner_evidence_json, platform) === null) {
        throw new AdmissionRuntimeError("durable queued-owner evidence is invalid for the selected platform");
      }
    }
  }

  enqueue(input: EnqueueRequest): { requestId: string; existed: boolean } {
    return this.transaction(() => {
      const result = this.enqueueRequest(input);
      this.persistQueuedOwnerReference(input, input.now, result.existed);
      return result;
    });
  }

  enqueueWithPayload(
    input: EnqueueRequest,
    plaintext: string,
    expiresAt: number
  ): { requestId: string; existed: boolean } {
    this.validatePayloadExpiry(input.now, expiresAt);
    const keyVersion = 1;
    const contentFingerprint = this.contentFingerprint("turn", input.requestId, plaintext);
    const encrypted = this.encrypt(plaintext, this.payloadAad(input.requestId, keyVersion));

    return this.transaction(() => {
      const result = this.enqueueRequest(input);
      const request = this.requireRequestState(input.requestId);
      if (request.state !== "queued") throw new Error("request is no longer queued");
      this.persistQueuedOwnerReference(input, input.now, result.existed);

      const existing = this.#db
        .prepare("SELECT content_fingerprint FROM turn_payloads WHERE request_id = ?")
        .get(input.requestId) as { content_fingerprint: string | null } | undefined;
      if (existing) {
        if (existing.content_fingerprint !== contentFingerprint) throw new PayloadConflictError(input.requestId);
        return { requestId: input.requestId, existed: true };
      }

      this.insertPayload(input.requestId, encrypted, keyVersion, contentFingerprint, expiresAt, input.now);
      return result;
    });
  }

  persistPayload(requestId: string, plaintext: string, now: number, expiresAt: number): void {
    this.validatePayloadExpiry(now, expiresAt);
    const keyVersion = 1;
    const contentFingerprint = this.contentFingerprint("turn", requestId, plaintext);
    const encrypted = this.encrypt(plaintext, this.payloadAad(requestId, keyVersion));

    this.transaction(() => {
      const request = this.requireRequestState(requestId);
      if (request.state !== "queued") throw new Error("request is no longer queued");
      const existing = this.#db
        .prepare("SELECT content_fingerprint FROM turn_payloads WHERE request_id = ?")
        .get(requestId) as { content_fingerprint: string | null } | undefined;
      if (existing) {
        if (existing.content_fingerprint !== contentFingerprint) throw new PayloadConflictError(requestId);
        return;
      }
      this.insertPayload(requestId, encrypted, keyVersion, contentFingerprint, expiresAt, now);
    });
  }

  readPayload(requestId: string, now: number): string {
    const row = this.transaction(() => {
      const row = this.#db
        .prepare(
          "SELECT nonce, ciphertext, auth_tag, key_version, content_fingerprint, expires_at FROM turn_payloads WHERE request_id = ?"
        )
        .get(requestId) as PayloadRow | undefined;
      if (!row) throw new Error("no payload is available");
      if (row.expires_at <= now) {
        this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(requestId);
        return null;
      }
      return row;
    });
    if (!row) throw new PayloadExpiredError(requestId);
    if (row.content_fingerprint === null) {
      throw new Error("request payload predates authenticated row binding");
    }

    return this.decrypt(
      { nonce: row.nonce, ciphertext: row.ciphertext, authTag: row.auth_tag },
      this.payloadAad(requestId, row.key_version)
    );
  }

  /** Cancelling after admission needs process and provider-terminal evidence. */
  cancelQueued(requestId: string, now: number): void {
    this.transaction(() => {
      const request = this.#db
        .prepare("SELECT state FROM turn_requests WHERE request_id = ?")
        .get(requestId) as { state: RequestState } | undefined;
      if (!request) throw new Error("unknown request");
      if (request.state !== "queued") throw new Error("request is no longer queued");

      this.#db
        .prepare("UPDATE turn_requests SET state = 'cancelled', terminal_at = ? WHERE request_id = ?")
        .run(now, requestId);
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(requestId);
      this.journalTransition("request_cancelled", requestId, "queued", "cancelled", now);
    });
  }

  admitNext(now: number, ownerInstanceId: string): AdmissionLease | null {
    validateIdentifier(ownerInstanceId, "admission owner instance ID");
    validateTimestamp(now, "admission timestamp");
    return this.transaction(() => {
      this.expireQueued(now);
      if (!this.hasDispatchCapacity(now)) return null;
      const candidate = this.selectEligibleRequest(now);
      if (!candidate) return null;
      return this.reserveAdmission(candidate, now, ownerInstanceId);
    });
  }

  /**
   * Atomically admit this request only when the global selector chose it.
   * Callers may wait on their own request, but cannot bypass the controller's
   * oldest-eligible and agent-fair ordering.
   */
  admitRequest(requestId: string, now: number, ownerInstanceId: string): AdmissionLease | null {
    validateIdentifier(requestId, "admission request ID");
    validateIdentifier(ownerInstanceId, "admission owner instance ID");
    validateTimestamp(now, "admission timestamp");
    return this.transaction(() => {
      this.expireQueued(now);
      if (!this.hasDispatchCapacity(now)) return null;
      const candidate = this.selectEligibleRequest(now);
      if (candidate?.request_id !== requestId) return null;
      return this.reserveAdmission(candidate, now, ownerInstanceId);
    });
  }

  getQueueSnapshot(requestId: string, now: number): AdmissionQueueSnapshot | null {
    validateIdentifier(requestId, "queue snapshot request ID");
    validateTimestamp(now, "queue snapshot timestamp");
    return this.transaction(() => {
      this.expireQueued(now);
      const rows = this.orderedQueuedRequests();
      const index = rows.findIndex((row) => row.request_id === requestId);
      if (index < 0) return null;
      const row = rows[index]!;
      const eligible = rows.filter((candidate) => !this.isCooldownActive(candidate.provider, candidate.model, now));
      const eligibleIndex = eligible.findIndex((candidate) => candidate.request_id === requestId);
      return Object.freeze({
        requestId,
        position: index + 1,
        eligiblePosition: eligibleIndex < 0 ? null : eligibleIndex + 1,
        enqueuedAt: row.enqueued_at,
        waitedMs: Math.max(0, now - row.enqueued_at),
        cooldownUntil: this.cooldownUntil(row.provider, row.model, now)
      });
    });
  }

  markStarting(fence: LeaseFence, now: number): void {
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase !== "admitted") throw new Error("lease is not admitted");
      const starts = this.#db
        .prepare("SELECT COUNT(*) AS count FROM leases WHERE phase IN ('starting', 'dispatch_intent')")
        .get() as { count: number };
      if (starts.count >= this.policy.maxConcurrentStarts) throw new Error("concurrent start limit reached");
      this.#db
        .prepare("DELETE FROM start_history WHERE started_at < ?")
        .run(now - this.policy.minStartIntervalMs);
      const latestStart = this.#db
        .prepare("SELECT started_at FROM start_history ORDER BY started_at DESC LIMIT 1")
        .get() as { started_at: number } | undefined;
      if (latestStart && now < latestStart.started_at + this.policy.minStartIntervalMs) {
        throw new Error("start interval has not elapsed");
      }
      this.#db.prepare("INSERT INTO start_history (lease_id, started_at) VALUES (?, ?)").run(fence.leaseId, now);
      this.setLeasePhase(lease, "starting", now);
    });
  }

  /**
   * Persist a verified process record and dispatch_intent in one SQLite
   * transaction. The following dispatch-boundary commit callback is an exact replay
   * check, so no crash window exists between those two callbacks.
   */
  recordProcessIdentity(input: unknown): ProcessIdentityRecordResult {
    const outcome = this.persistProcessIdentityAndDispatchIntent(input);
    return outcome.status === "committed"
      ? { status: "recorded", idempotent: outcome.idempotent }
      : { status: "not_recorded", reason: outcome.reason };
  }

  /**
   * Confirm the atomic identity-and-intent persistence. A fresh call performs
   * the same transaction; a matching dispatch_intent record is idempotent.
   */
  commitDispatchIntent(input: unknown): DispatchIntentCommitResult {
    const outcome = this.persistProcessIdentityAndDispatchIntent(input);
    return outcome.status === "committed"
      ? { status: "committed", idempotent: outcome.idempotent }
      : { status: "not_committed", reason: outcome.reason };
  }

  markDispatchIntent(fence: LeaseFence, now: number): void {
    this.transition(fence, "starting", "dispatch_intent", now);
  }

  markActive(fence: LeaseFence, now: number): void {
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase !== "dispatch_intent") throw new Error("lease is not dispatch_intent");
      this.setLeasePhase(lease, "active", now);
      // Once the irreversible write has been issued, the payload must never be
      // available to a recovery path that could repeat the business prompt.
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(lease.request_id);
    });
  }

  markDispatchAmbiguous(fence: LeaseFence, now: number): void {
    this.transition(fence, "dispatch_intent", "dispatch_ambiguous", now);
  }

  /**
   * End a reserved turn only when the Connector still has direct proof that no
   * business prompt write occurred. This is terminal, never a requeue.
   */
  abandonBeforePrompt(
    fence: LeaseFence,
    now: number,
    outcome: Extract<ConfirmedProviderOutcome, "failed" | "cancelled">
  ): void {
    validateTimestamp(now, "pre-prompt abandonment timestamp");
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase !== "admitted" && lease.phase !== "starting" && lease.phase !== "dispatch_intent") {
        throw new Error("lease is not safely abandonable before prompt write");
      }
      this.#db
        .prepare("UPDATE turn_requests SET state = ?, terminal_at = ? WHERE request_id = ?")
        .run(outcome, now, lease.request_id);
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(lease.request_id);
      const released = this.#db
        .prepare("DELETE FROM leases WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?")
        .run(fence.leaseId, fence.ownerInstanceId, fence.generation);
      if (released.changes !== 1) throw new LeaseFenceError(fence.leaseId);
      this.journalTransition("request_abandoned", lease.request_id, lease.phase, outcome, now);
      this.completeSoftDrainTo1IfSettled(fence.ownerInstanceId, now);
    });
  }

  /** Retain an uncertain dispatch as visible capacity debt; never requeue it. */
  markExecutionRecoveryRequired(fence: LeaseFence, now: number): void {
    validateTimestamp(now, "execution recovery timestamp");
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase === "recovery_required") return;
      if (
        lease.phase !== "starting" &&
        lease.phase !== "dispatch_intent" &&
        lease.phase !== "dispatch_ambiguous" &&
        lease.phase !== "active"
      ) {
        throw new Error("lease cannot enter execution recovery");
      }
      const updated = this.#db
        .prepare(
          `UPDATE leases SET phase = 'recovery_required', heartbeat_at = ?
           WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?`
        )
        .run(now, fence.leaseId, fence.ownerInstanceId, fence.generation);
      if (updated.changes !== 1) throw new LeaseFenceError(fence.leaseId);
      this.#db
        .prepare("UPDATE turn_requests SET state = 'recovery_required', terminal_at = ? WHERE request_id = ?")
        .run(now, lease.request_id);
      this.journalTransition("request_recovery_required", lease.request_id, lease.phase, "recovery_required", now);
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(lease.request_id);
    });
  }

  /**
   * Release only the local seat after the Connector has independently proved
   * that the persisted connector, child, and process group are all gone. The
   * request deliberately remains recovery_required and cannot be replayed.
   */
  releaseExitedRecoverySeat(fence: LeaseFence, now: number): void {
    validateTimestamp(now, "exited recovery seat timestamp");
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (
        lease.phase === "provider_terminal" ||
        lease.phase === "completed" ||
        lease.phase === "failed" ||
        lease.phase === "cancelled" ||
        lease.phase === "queue_timeout"
      ) {
        throw new Error("lease is not an unresolved local execution");
      }
      this.#db
        .prepare("UPDATE turn_requests SET state = 'recovery_required', terminal_at = ? WHERE request_id = ?")
        .run(now, lease.request_id);
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(lease.request_id);
      const released = this.#db
        .prepare("DELETE FROM leases WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?")
        .run(fence.leaseId, fence.ownerInstanceId, fence.generation);
      if (released.changes !== 1) throw new LeaseFenceError(fence.leaseId);
      this.journalTransition(
        "request_recovery_seat_released",
        lease.request_id,
        lease.phase,
        "recovery_required",
        now
      );
      this.completeSoftDrainTo1IfSettled(fence.ownerInstanceId, now);
    });
  }

  /**
   * Persist the terminal state and release the seat used by the existing live
   * ACP update path. No delivery replay record is created.
   */
  completeLiveTurn(fence: LeaseFence, now: number, completion: LiveTurnCompletion): void {
    validateTimestamp(now, "live turn completion timestamp");
    validateLiveTurnCompletion(completion);
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase !== "active") throw new Error("lease is not active");
      const request = this.getRequest(lease.request_id);
      if (request === null) throw new Error("unknown request");

      this.#db
        .prepare("UPDATE turn_requests SET state = 'provider_terminal', terminal_at = ? WHERE request_id = ?")
        .run(now, lease.request_id);
      this.journalTransition("request_provider_terminal", lease.request_id, "active", "provider_terminal", now);

      if (completion.failure?.category === "provider_capacity") {
        const notBefore = now + this.policy.capacityCooldownMs;
        this.#db
          .prepare(
            `INSERT INTO cooldowns (provider, model, not_before, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(provider, model) DO UPDATE SET
               not_before = MAX(cooldowns.not_before, excluded.not_before),
               updated_at = MAX(cooldowns.updated_at, excluded.updated_at)`
          )
          .run(request.provider, request.model, notBefore, now);
      }

      this.#db
        .prepare("UPDATE turn_requests SET state = ?, terminal_at = ? WHERE request_id = ?")
        .run(completion.outcome, now, lease.request_id);
      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(lease.request_id);
      const released = this.#db
        .prepare("DELETE FROM leases WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?")
        .run(fence.leaseId, fence.ownerInstanceId, fence.generation);
      if (released.changes !== 1) throw new LeaseFenceError(fence.leaseId);
      this.journalTransition("request_released", lease.request_id, "provider_terminal", completion.outcome, now);
      this.completeSoftDrainTo1IfSettled(fence.ownerInstanceId, now);
    });
  }

  heartbeat(fence: LeaseFence, now: number): void {
    const result = this.#db
      .prepare(
        `UPDATE leases
         SET heartbeat_at = ?, suspect_since = NULL, suspect_reason = NULL
         WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?`
      )
      .run(now, fence.leaseId, fence.ownerInstanceId, fence.generation);
    if (result.changes !== 1) throw new LeaseFenceError(fence.leaseId);
  }

  /**
   * Runtime recovery is evidence-only: a stale heartbeat can mark suspicion,
   * but only connector/child/process-group proof can release local capacity.
   */
  reapSuspects(now: number, processEvidence: ProcessEvidence): AdmissionRuntimeReaperSummary {
    validateTimestamp(now, "runtime reaper timestamp");
    const evidence = requireProcessEvidence(processEvidence);
    if (evidence.platform !== this.#processEvidence.platform) {
      throw new AdmissionRuntimeError("process evidence platform does not match durable admission platform");
    }
    let released = 0;
    let retained = 0;
    let markedRecoveryRequired = 0;
    let suspected = 0;
    let queuedSettled = 0;

    for (const queuedOwner of this.listRecoverableQueuedOwners()) {
      const owner = evidence.observe(queuedOwner.owner);
      if (isGoneIdentity(owner)) {
        if (this.settleQueuedOwnerDeath(queuedOwner.requestId, queuedOwner.owner.ownerInstanceId, now)) {
          queuedSettled += 1;
        }
      }
    }

    const dispatches = this.listRecoverableDispatches();
    for (const dispatch of dispatches) {
      if (dispatch.processIdentity === null) {
        if (this.markSuspect(dispatch.fence, now, "identity_unverifiable")) suspected += 1;
        retained += 1;
        continue;
      }

      const connector = evidence.observe(dispatch.processIdentity.connector);
      const child = evidence.observe(dispatch.processIdentity.child);
      const residue = evidence.inspectProcessGroup(dispatch.processIdentity.child);
      const unverifiable =
        connector === "unverifiable" || child === "unverifiable" || residue === "unverifiable";

      if (unverifiable || isHeartbeatStale(dispatch.heartbeatAt, now)) {
        const reason = unverifiable ? "identity_unverifiable" : "heartbeat_expired";
        if (this.markSuspect(dispatch.fence, now, reason)) suspected += 1;
      }

      if (isGoneIdentity(connector) && isGoneIdentity(child) && residue === "empty") {
        try {
          this.releaseExitedRecoverySeat(dispatch.fence, now);
          released += 1;
          continue;
        } catch {
          retained += 1;
          continue;
        }
      }

      if (unverifiable) {
        retained += 1;
        continue;
      }

      if (connector !== "same") {
        try {
          this.markExecutionRecoveryRequired(dispatch.fence, now);
          markedRecoveryRequired += 1;
        } catch {
          // A concurrent owner may have advanced or settled the exact fence.
        }
      }
      retained += 1;
    }

    return Object.freeze({
      inspected: dispatches.length,
      released,
      retained,
      markedRecoveryRequired,
      suspected,
      queuedSettled
    });
  }

  setCapacityCooldown(provider: string, model: string, notBefore: number, now: number): void {
    if (!Number.isSafeInteger(notBefore) || !Number.isSafeInteger(now) || notBefore < now) {
      throw new Error("capacity cooldown must use integer timestamps and cannot end before it is recorded");
    }
    this.#db
      .prepare(
        `INSERT INTO cooldowns (provider, model, not_before, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(provider, model) DO UPDATE SET
           not_before = MAX(cooldowns.not_before, excluded.not_before),
           updated_at = MAX(cooldowns.updated_at, excluded.updated_at)`
      )
      .run(provider, model, notBefore, now);
  }

  /**
   * Read an identifier-free page of the append-only audit journal. The exact
   * input shape deliberately provides no request/session/provider lookup seam.
   */
  readSanitizedEvents(input: unknown): readonly SanitizedAdmissionEvent[] {
    const page = normalizeSanitizedEventPageRequest(input);
    const rows = this.#db
      .prepare(
        `SELECT event_seq, kind, from_state, to_state, occurred_at, correlation_hmac
         FROM events WHERE event_seq > ? ORDER BY event_seq ASC LIMIT ?`
      )
      .all(page.afterEventSeq, page.limit) as SanitizedEventRow[];
    return Object.freeze(rows.map((row) => normalizeSanitizedEventRow(row)));
  }

  getRequest(requestId: string): StoredRequest | null {
    const row = this.#db
      .prepare(
        `SELECT request_id, session_id, agent_id, fingerprint, provider, model, state, enqueued_at
         , lease_generation
         FROM turn_requests WHERE request_id = ?`
      )
      .get(requestId) as RequestRow | undefined;
    return row ? toStoredRequest(row) : null;
  }

  /**
   * Enumerate durable, nonterminal dispatches for connector startup recovery.
   * This deliberately reads no prompt or outbox table, never decrypts data,
   * and returns a null identity instead of implying that a dispatch is safe to
   * resume when immutable process evidence is absent.
   */
  listRecoverableDispatches(): readonly RecoverableDispatch[] {
    const rows = this.#db
      .prepare(
        `SELECT lease.lease_id AS lease_id,
                lease.request_id AS lease_request_id,
                lease.generation AS lease_generation,
                lease.owner_instance_id AS lease_owner_instance_id,
                lease.phase AS lease_phase,
                lease.heartbeat_at AS lease_heartbeat_at,
                request.request_id AS request_id,
                request.session_id AS request_session_id,
                request.provider AS request_provider,
                request.model AS request_model,
                request.state AS request_state,
                request.lease_generation AS request_lease_generation,
                request.enqueued_at AS request_enqueued_at,
                identity.lease_id AS identity_lease_id,
                identity.request_id AS identity_request_id,
                identity.lease_generation AS identity_lease_generation,
                identity.owner_instance_id AS identity_owner_instance_id,
                identity.prompt_channel AS identity_prompt_channel,
                identity.connector_owner_instance_id AS identity_connector_owner_instance_id,
                identity.connector_created_at AS identity_connector_created_at,
                identity.connector_evidence_json AS identity_connector_evidence_json,
                identity.child_evidence_json AS identity_child_evidence_json
         FROM leases AS lease
         LEFT JOIN turn_requests AS request ON request.request_id = lease.request_id
         LEFT JOIN lease_process_identities AS identity ON identity.lease_id = lease.lease_id
         ORDER BY request.enqueued_at ASC, request.request_id ASC, lease.lease_id ASC`
      )
      .all() as RecoverableDispatchRow[];
    const inventory: RecoverableDispatch[] = [];
    for (const row of rows) {
      const dispatch = toRecoverableDispatch(row, this.#processEvidence.platform);
      if (dispatch !== null) inventory.push(dispatch);
    }
    return Object.freeze(inventory);
  }

  /**
   * Enumerate queued requests whose owning connector was durably recorded at
   * enqueue time. This returns no payload and grants no replay authority.
   */
  listRecoverableQueuedOwners(): readonly RecoverableQueuedOwner[] {
    const rows = this.#db
      .prepare(
        `SELECT request.request_id AS request_id,
                owner.owner_instance_id AS owner_instance_id,
                owner.created_at AS created_at,
                owner.queued_owner_evidence_json AS queued_owner_evidence_json,
                owner.recorded_at AS recorded_at
         FROM turn_requests AS request
         JOIN queued_owner_instances AS owner
           ON owner.owner_instance_id = request.queued_owner_instance_id
         WHERE request.state = 'queued'
           AND request.queued_owner_instance_id IS NOT NULL
         ORDER BY request.enqueued_at ASC, request.request_id ASC`
      )
      .all() as RecoverableQueuedOwnerRow[];
    const owners: RecoverableQueuedOwner[] = [];
    for (const row of rows) owners.push(toRecoverableQueuedOwner(row, this.#processEvidence.platform));
    return Object.freeze(owners);
  }

  settleQueuedOwnerDeath(requestId: string, ownerInstanceId: string, now: number): boolean {
    validateIdentifier(requestId, "queued owner request ID");
    validateIdentifier(ownerInstanceId, "queued owner instance ID");
    validateTimestamp(now, "queued owner death timestamp");

    return this.transaction(() => {
      const request = this.#db
        .prepare(
          `SELECT state, queued_owner_instance_id
           FROM turn_requests
           WHERE request_id = ?`
        )
        .get(requestId) as QueuedOwnerRequestRow | undefined;
      if (request === undefined || request.state !== "queued") return false;
      if (request.queued_owner_instance_id !== ownerInstanceId) return false;

      const lease = this.#db
        .prepare("SELECT 1 FROM leases WHERE request_id = ? LIMIT 1")
        .get(requestId);
      if (lease !== undefined) return false;

      const result = this.#db
        .prepare(
          `UPDATE turn_requests
           SET state = 'cancelled', terminal_at = ?
           WHERE request_id = ?
             AND state = 'queued'
             AND queued_owner_instance_id = ?
             AND NOT EXISTS (SELECT 1 FROM leases WHERE request_id = ?)`
        )
        .run(now, requestId, ownerInstanceId, requestId);
      if (result.changes !== 1) return false;

      this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(requestId);
      this.journalTransition("queued_owner_dead", requestId, "queued", "cancelled", now);
      return true;
    });
  }

  claimDurablePolicy(policy: AdmissionPolicy, ownerInstanceId: string, now: number): void {
    const normalizedPolicy = validatePolicy(policy);
    validateIdentifier(ownerInstanceId, "durable policy owner instance ID");
    validateTimestamp(now, "durable policy claim timestamp");
    const policyFingerprint = this.policyFingerprint(normalizedPolicy);
    const platform = this.#processEvidence.platform;

    this.transaction(() => {
      const result = this.#db
        .prepare(
          `INSERT INTO policy_state (
             id, max_active_turns, max_concurrent_starts, min_start_interval_ms,
             queue_timeout_ms, capacity_cooldown_ms, drain_state, policy_fingerprint,
             updated_at, updated_by_owner_instance_id, process_evidence_platform
           )
           SELECT 1, ?, ?, ?, ?, ?, 'steady', ?, ?, ?, ?
           WHERE NOT EXISTS (SELECT 1 FROM policy_state WHERE id = 1)`
        )
        .run(
          normalizedPolicy.maxActiveTurns,
          normalizedPolicy.maxConcurrentStarts,
          normalizedPolicy.minStartIntervalMs,
          normalizedPolicy.queueTimeoutMs,
          normalizedPolicy.capacityCooldownMs,
          policyFingerprint,
          now,
          ownerInstanceId,
          platform
        );
      if (result.changes === 1) return;
      this.assertDurablePolicyMatchInTransaction(normalizedPolicy, policyFingerprint, platform);
    });
  }

  assertDurablePolicyMatch(policy: AdmissionPolicy, ownerInstanceId: string, now: number): void {
    const normalizedPolicy = validatePolicy(policy);
    validateIdentifier(ownerInstanceId, "durable policy owner instance ID");
    validateTimestamp(now, "durable policy assertion timestamp");
    const policyFingerprint = this.policyFingerprint(normalizedPolicy);
    this.transaction(() => this.assertDurablePolicyMatchInTransaction(
      normalizedPolicy,
      policyFingerprint,
      this.#processEvidence.platform
    ));
  }

  beginSoftDrainTo1(ownerInstanceId: string, now: number): void {
    validateIdentifier(ownerInstanceId, "soft drain owner instance ID");
    validateTimestamp(now, "soft drain timestamp");
    this.transaction(() => {
      const row = this.requirePolicyStateInTransaction();
      const drainState = policyDrainState(row);
      const maxActiveTurns = policyStateInteger(row.max_active_turns, "durable policy max_active_turns");

      if (drainState === "steady" && maxActiveTurns === 1) return;
      if (drainState !== "steady" && drainState !== "soft_draining_to_1") {
        throw new AdmissionRuntimeError("durable policy drain state is not recognized");
      }
      if (maxActiveTurns !== 3 && drainState !== "soft_draining_to_1") {
        throw new AdmissionRuntimeError("soft drain can only start from a steady three-seat policy");
      }

      if (drainState === "steady") {
        const result = this.#db
          .prepare(
            `UPDATE policy_state
             SET drain_state = 'soft_draining_to_1',
                 updated_at = ?,
                 updated_by_owner_instance_id = ?
             WHERE id = 1 AND drain_state = 'steady' AND max_active_turns = 3`
          )
          .run(now, ownerInstanceId);
        if (result.changes !== 1) throw new AdmissionRuntimeError("soft drain could not be started atomically");
      }

      this.completeSoftDrainTo1IfSettled(ownerInstanceId, now);
    });
  }

  private migrate(): void {
    this.assertRenameColumnAvailable();
    try {
      this.transaction(() => {
        this.#db.pragma("foreign_keys = ON");
        let applied = this.schemaVersion;
        if (applied > ADMISSION_SCHEMA_VERSION) {
          throw new AdmissionMigrationError(`schema version ${applied} is newer than this connector supports`);
        }
        const ledgerExists = this.#db
          .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'")
          .get() !== undefined;
        if (applied === 0) {
          if (ledgerExists) {
            throw new AdmissionMigrationError("admission migration ledger is empty or partial");
          }
          this.createInitialV4Schema(Date.now());
          applied = 4;
        } else {
          assertMigrationSequence(this.#db, applied);
        }
        if (applied === 1) {
          this.migrateV1ToV2(Date.now());
          applied = 2;
        }
        if (applied === 2) {
          this.migrateV2ToV3(Date.now());
          applied = 3;
        }
        if (applied === 3) {
          this.migrateV3ToV4(Date.now());
          applied = 4;
        }
        if (applied !== ADMISSION_SCHEMA_VERSION) {
          throw new AdmissionMigrationError(`schema version ${applied} is not supported`);
        }
        assertAdmissionSchemaIntegrity(this.#db);
      });
    } catch (error) {
      if (error instanceof AdmissionMigrationError) throw error;
      throw new AdmissionMigrationError("v4 DDL transaction rolled back");
    }
  }

  private assertRenameColumnAvailable(): void {
    const row = this.#db.prepare("SELECT sqlite_version() AS version").get() as { version: string };
    if (compareSqliteVersions(row.version, "3.25.0") < 0) {
      throw new AdmissionMigrationError(`SQLite ${row.version} does not support ALTER TABLE RENAME COLUMN`);
    }
  }

  private createInitialV4Schema(appliedAt: number): void {
    const existing = this.#db
      .prepare(
        `SELECT COUNT(*) AS count FROM sqlite_master
         WHERE type = 'table' AND name IN (
           'schema_migrations', 'turn_requests', 'leases', 'cooldowns', 'turn_payloads',
           'lease_process_identities', 'start_history', 'sessions', 'events',
           'policy_state', 'queued_owner_instances'
         )`
      )
      .get() as { count: number };
    if (existing.count > 0) {
      throw new AdmissionMigrationError("unversioned admission tables require an explicit migration before use");
    }
    this.#db.exec(`
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
        connector_evidence_json TEXT NOT NULL CHECK (json_valid(connector_evidence_json)),
        child_evidence_json TEXT NOT NULL CHECK (json_valid(child_evidence_json)),
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
        updated_by_owner_instance_id TEXT NOT NULL,
        process_evidence_platform TEXT NOT NULL CHECK (process_evidence_platform IN ('linux', 'darwin'))
      );
      CREATE TABLE queued_owner_instances (
        owner_instance_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        queued_owner_evidence_json TEXT NOT NULL CHECK (json_valid(queued_owner_evidence_json)),
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
    this.#db
      .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (4, 'shared-admission-queue-v4', ?)")
      .run(appliedAt);
  }

  private createInitialV1Schema(appliedAt: number): void {
    const existing = this.#db
      .prepare(
        `SELECT COUNT(*) AS count FROM sqlite_master
         WHERE type = 'table' AND name IN (
           'turn_requests', 'leases', 'cooldowns', 'turn_payloads',
           'lease_process_identities', 'start_history', 'sessions', 'events',
           'policy_state', 'queued_owner_instances'
         )`
      )
      .get() as { count: number };
    if (existing.count > 0) {
      throw new AdmissionMigrationError("unversioned admission tables require an explicit migration before use");
    }
    this.#db.exec(`
      CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at INTEGER NOT NULL
      );
      CREATE TABLE turn_requests (
        request_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        parent_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        state TEXT NOT NULL,
        enqueued_at INTEGER NOT NULL,
        deadline_at INTEGER NOT NULL,
        lease_generation INTEGER NOT NULL DEFAULT 0,
        terminal_at INTEGER
      );
      CREATE TABLE leases (
        lease_id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE REFERENCES turn_requests(request_id),
        generation INTEGER NOT NULL,
        owner_instance_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        acquired_at INTEGER NOT NULL,
        heartbeat_at INTEGER NOT NULL
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
      CREATE INDEX leases_phase ON leases(phase);
      CREATE UNIQUE INDEX lease_process_identities_request ON lease_process_identities(request_id);
      CREATE INDEX start_history_started ON start_history(started_at);
      CREATE INDEX sessions_updated_at_session_id ON sessions(updated_at DESC, session_id ASC);
      CREATE INDEX sessions_cwd_updated_at_session_id ON sessions(cwd, updated_at DESC, session_id ASC);
      CREATE INDEX events_occurred ON events(occurred_at, event_seq);
    `);
    this.#db
      .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, 'shared-admission-queue', ?)")
      .run(appliedAt);
  }

  private migrateV1ToV2(appliedAt: number): void {
    this.#db.exec(`
      ALTER TABLE turn_requests RENAME COLUMN parent_id TO agent_id;
      ALTER TABLE turn_requests ADD COLUMN queued_owner_instance_id TEXT NULL;
      ALTER TABLE turn_requests ADD COLUMN queued_owner_recorded_at INTEGER NULL;
      CREATE INDEX IF NOT EXISTS turn_requests_queued_owner
        ON turn_requests(queued_owner_instance_id)
        WHERE queued_owner_instance_id IS NOT NULL;
      ALTER TABLE leases ADD COLUMN suspect_since INTEGER NULL;
      ALTER TABLE leases ADD COLUMN suspect_reason TEXT CHECK (suspect_reason IS NULL OR suspect_reason IN ('heartbeat_expired', 'identity_unverifiable'));
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
    `);
    this.#db
      .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (2, 'shared-admission-queue-v2', ?)")
      .run(appliedAt);
  }

  private migrateV2ToV3(appliedAt: number): void {
    this.#db.exec(`
      CREATE TABLE policy_state_v3 (
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
      INSERT INTO policy_state_v3 SELECT * FROM policy_state;
      DROP TABLE policy_state;
      ALTER TABLE policy_state_v3 RENAME TO policy_state;
    `);
    this.#db
      .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (3, 'shared-admission-queue-v3', ?)")
      .run(appliedAt);
  }

  private migrateV3ToV4(appliedAt: number): void {
    assertV3MigrationShape(this.#db);
    if (this.#processEvidence.platform !== "linux") {
      throw new AdmissionMigrationError("schema v3 evidence can only be migrated with a linux process evidence adapter");
    }

    const leaseRows = this.#db
      .prepare(
        `SELECT lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
                connector_owner_instance_id, connector_created_at, connector_boot_id, connector_pid,
                connector_start_time_ticks, connector_pid_namespace_inode, connector_ppid,
                connector_pgrp, connector_session, child_boot_id, child_pid, child_start_time_ticks,
                child_pid_namespace_inode, child_ppid, child_pgrp, child_session, recorded_at
         FROM lease_process_identities`
      )
      .all() as V3LeaseProcessIdentityRow[];
    const ownerRows = this.#db
      .prepare(
        `SELECT owner_instance_id, created_at, boot_id, pid, start_time_ticks, pid_namespace_inode,
                ppid, pgrp, session, recorded_at
         FROM queued_owner_instances`
      )
      .all() as V3QueuedOwnerIdentityRow[];

    const migratedLeaseRows = leaseRows.map((row) => {
      const leaseId = normalizeIdentifier(row.lease_id, "v3 lease process identity lease ID");
      const requestId = normalizeIdentifier(row.request_id, "v3 lease process identity request ID");
      const ownerInstanceId = normalizeOwnerInstanceId(row.owner_instance_id);
      const connector = normalizeVerifiedConnectorIdentity({
        ownerInstanceId: row.connector_owner_instance_id,
        createdAt: row.connector_created_at,
        bootId: row.connector_boot_id,
        pid: row.connector_pid,
        startTimeTicks: row.connector_start_time_ticks,
        pidNamespaceInode: row.connector_pid_namespace_inode,
        ppid: row.connector_ppid,
        pgrp: row.connector_pgrp,
        session: row.connector_session
      });
      if (connector.ownerInstanceId !== ownerInstanceId) {
        throw new Error("v3 lease process identity owner mismatch");
      }
      if (row.prompt_channel !== "stdin" && row.prompt_channel !== "pty") {
        throw new Error("v3 lease process identity prompt channel is invalid");
      }
      const child = normalizeVerifiedProcessIdentity({
        bootId: row.child_boot_id,
        pid: row.child_pid,
        startTimeTicks: row.child_start_time_ticks,
        pidNamespaceInode: row.child_pid_namespace_inode,
        ppid: row.child_ppid,
        pgrp: row.child_pgrp,
        session: row.child_session
      });
      validateTimestamp(row.recorded_at, "v3 lease process identity recorded timestamp");
      return {
        leaseId,
        requestId,
        generation: normalizePositiveSafeInteger(row.lease_generation, "v3 lease process identity generation", Number.MAX_SAFE_INTEGER),
        ownerInstanceId,
        promptChannel: row.prompt_channel,
        connector,
        child,
        recordedAt: row.recorded_at
      };
    });

    const migratedOwnerRows = ownerRows.map((row) => {
      const owner = normalizeVerifiedConnectorIdentity({
        ownerInstanceId: row.owner_instance_id,
        createdAt: row.created_at,
        bootId: row.boot_id,
        pid: row.pid,
        startTimeTicks: row.start_time_ticks,
        pidNamespaceInode: row.pid_namespace_inode,
        ppid: row.ppid,
        pgrp: row.pgrp,
        session: row.session
      });
      validateTimestamp(row.recorded_at, "v3 queued owner recorded timestamp");
      return { owner, recordedAt: row.recorded_at };
    });

    this.#db.exec(`
      CREATE TABLE lease_process_identities_v4 (
        lease_id TEXT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE,
        request_id TEXT NOT NULL REFERENCES turn_requests(request_id),
        lease_generation INTEGER NOT NULL,
        owner_instance_id TEXT NOT NULL,
        prompt_channel TEXT NOT NULL,
        connector_owner_instance_id TEXT NOT NULL,
        connector_created_at TEXT NOT NULL,
        connector_evidence_json TEXT NOT NULL CHECK (json_valid(connector_evidence_json)),
        child_evidence_json TEXT NOT NULL CHECK (json_valid(child_evidence_json)),
        recorded_at INTEGER NOT NULL
      );
      CREATE TABLE queued_owner_instances_v4 (
        owner_instance_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        queued_owner_evidence_json TEXT NOT NULL CHECK (json_valid(queued_owner_evidence_json)),
        recorded_at INTEGER NOT NULL
      );
      CREATE TABLE policy_state_v4 (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        max_active_turns INTEGER NOT NULL CHECK (max_active_turns >= 1),
        max_concurrent_starts INTEGER NOT NULL CHECK (max_concurrent_starts >= 1),
        min_start_interval_ms INTEGER NOT NULL CHECK (min_start_interval_ms >= 2000),
        queue_timeout_ms INTEGER NOT NULL CHECK (queue_timeout_ms > 0 AND queue_timeout_ms <= 1800000),
        capacity_cooldown_ms INTEGER NOT NULL CHECK (capacity_cooldown_ms >= 30000),
        drain_state TEXT NOT NULL CHECK (drain_state IN ('steady', 'soft_draining_to_1')),
        policy_fingerprint TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        updated_by_owner_instance_id TEXT NOT NULL,
        process_evidence_platform TEXT NOT NULL CHECK (process_evidence_platform IN ('linux', 'darwin'))
      );
    `);

    const insertLease = this.#db.prepare(
      `INSERT INTO lease_process_identities_v4 (
         lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
         connector_owner_instance_id, connector_created_at, connector_evidence_json,
         child_evidence_json, recorded_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const row of migratedLeaseRows) {
      insertLease.run(
        row.leaseId,
        row.requestId,
        row.generation,
        row.ownerInstanceId,
        row.promptChannel,
        row.connector.ownerInstanceId,
        row.connector.createdAt,
        serializeProcessIdentity(row.connector, "linux"),
        serializeProcessIdentity(row.child, "linux"),
        row.recordedAt
      );
    }

    const insertOwner = this.#db.prepare(
      `INSERT INTO queued_owner_instances_v4 (
         owner_instance_id, created_at, queued_owner_evidence_json, recorded_at
       ) VALUES (?, ?, ?, ?)`
    );
    for (const row of migratedOwnerRows) {
      insertOwner.run(
        row.owner.ownerInstanceId,
        row.owner.createdAt,
        serializeProcessIdentity(row.owner, "linux"),
        row.recordedAt
      );
    }

    this.#db
      .prepare(
        `INSERT INTO policy_state_v4 (
           id, max_active_turns, max_concurrent_starts, min_start_interval_ms,
           queue_timeout_ms, capacity_cooldown_ms, drain_state, policy_fingerprint,
           updated_at, updated_by_owner_instance_id, process_evidence_platform
         )
         SELECT id, max_active_turns, max_concurrent_starts, min_start_interval_ms,
                queue_timeout_ms, capacity_cooldown_ms, drain_state, policy_fingerprint,
                updated_at, updated_by_owner_instance_id, 'linux'
         FROM policy_state`
      )
      .run();
    this.#db.exec(`
      DROP TABLE lease_process_identities;
      DROP TABLE queued_owner_instances;
      DROP TABLE policy_state;
      ALTER TABLE lease_process_identities_v4 RENAME TO lease_process_identities;
      ALTER TABLE queued_owner_instances_v4 RENAME TO queued_owner_instances;
      ALTER TABLE policy_state_v4 RENAME TO policy_state;
      CREATE UNIQUE INDEX lease_process_identities_request ON lease_process_identities(request_id);
    `);
    this.#db
      .prepare("INSERT INTO schema_migrations (version, name, applied_at) VALUES (4, 'shared-admission-queue-v4', ?)")
      .run(appliedAt);
  }

  private transaction<T>(fn: () => T): T {
    return this.#db.transaction(fn)();
  }

  private runInjectedTransactionFault(callback: (() => void) | undefined): void {
    if (callback === undefined) return;
    try {
      callback();
    } catch {
      throw new AdmissionControllerInjectedFaultError();
    }
  }

  private persistProcessIdentityAndDispatchIntent(input: unknown): AtomicDispatchIntentOutcome {
    const record = normalizeVerifiedProcessRecord(input, this.#processEvidence.platform);
    if (record === null) return { status: "not_committed", reason: "invalid_process_identity" };

    try {
      return this.transaction(() => this.persistProcessIdentityAndDispatchIntentInTransaction(record));
    } catch (error) {
      // Do not expose driver errors or partially durable state to a prompt writer.
      return (
        (isSqliteTransactionContention(error) ? this.recheckDispatchIdentityAfterContention(record) : null) ?? {
          status: "not_committed",
          reason: "transaction_fault"
        }
      );
    }
  }

  /** A failed writer may inspect only a committed, exact winner; it never retries a write. */
  private recheckDispatchIdentityAfterContention(
    record: VerifiedProcessRecord
  ): AtomicDispatchIntentOutcome | null {
    for (let attempt = 0; attempt < MAX_DISPATCH_CONTENTION_RECHECKS; attempt += 1) {
      try {
        const outcome = this.transaction(() => this.inspectDispatchIdentityContentionWinner(record));
        if (outcome !== "pending") return outcome;
      } catch (error) {
        if (!isSqliteTransactionContention(error)) return null;
      }
      if (attempt < MAX_DISPATCH_CONTENTION_RECHECKS - 1) {
        Atomics.wait(dispatchContentionRetrySignal, 0, 0, DISPATCH_CONTENTION_RECHECK_DELAY_MS);
      }
    }
    return null;
  }

  /** Reads the lease and identity under one snapshot so no partial winner can be inferred. */
  private inspectDispatchIdentityContentionWinner(
    record: VerifiedProcessRecord
  ): AtomicDispatchIntentOutcome | "pending" | null {
    const lease = this.#db
      .prepare(
        `SELECT lease.lease_id, lease.request_id, lease.generation, lease.owner_instance_id,
                lease.phase, request.state AS request_state,
                request.lease_generation AS request_lease_generation
         FROM leases AS lease
         JOIN turn_requests AS request ON request.request_id = lease.request_id
         WHERE lease.lease_id = ?`
      )
      .get(record.leaseId) as DispatchContentionRecheckRow | undefined;
    if (
      lease === undefined ||
      lease.request_id !== record.requestId ||
      lease.generation !== record.generation ||
      lease.owner_instance_id !== record.ownerInstanceId ||
      lease.request_lease_generation !== record.generation
    ) {
      return null;
    }
    const identity = this.findLeaseProcessIdentity(record.leaseId);
    if (lease.phase === "dispatch_intent" && lease.request_state === "dispatch_intent") {
      if (
        identity === undefined ||
        identity.request_id !== record.requestId ||
        identity.lease_generation !== record.generation ||
        identity.owner_instance_id !== record.ownerInstanceId
      ) {
        return null;
      }
      return sameLeaseProcessIdentity(identity, record, this.#processEvidence.platform)
        ? { status: "committed", idempotent: true }
        : { status: "not_committed", reason: "conflicting_intent" };
    }
    return lease.phase === "starting" && lease.request_state === "starting" && identity === undefined
      ? "pending"
      : null;
  }

  private persistProcessIdentityAndDispatchIntentInTransaction(
    record: VerifiedProcessRecord
  ): AtomicDispatchIntentOutcome {
    const lease = this.#db
      .prepare(
        "SELECT lease_id, request_id, generation, owner_instance_id, phase FROM leases WHERE lease_id = ?"
      )
      .get(record.leaseId) as LeaseRow | undefined;
    if (
      lease === undefined ||
      lease.request_id !== record.requestId ||
      lease.generation !== record.generation ||
      lease.owner_instance_id !== record.ownerInstanceId
    ) {
      return { status: "not_committed", reason: "stale_lease" };
    }

    const existing = this.findLeaseProcessIdentity(record.leaseId);
    if (lease.phase === "dispatch_intent") {
      return existing !== undefined && sameLeaseProcessIdentity(existing, record, this.#processEvidence.platform)
        ? { status: "committed", idempotent: true }
        : { status: "not_committed", reason: "conflicting_intent" };
    }
    if (lease.phase !== "starting") return { status: "not_committed", reason: "stale_lease" };
    if (existing !== undefined) return { status: "not_committed", reason: "conflicting_intent" };

    const committedAt = Date.now();
    const phase = this.#db
      .prepare(
        `UPDATE leases
         SET phase = 'dispatch_intent', heartbeat_at = ?
         WHERE lease_id = ? AND owner_instance_id = ? AND generation = ? AND phase = 'starting'`
      )
      .run(committedAt, record.leaseId, record.ownerInstanceId, record.generation);
    if (phase.changes !== 1) return { status: "not_committed", reason: "stale_lease" };

    this.insertLeaseProcessIdentity(record, committedAt);
    this.#faultInjection?.afterProcessIdentityPersisted?.();

    const request = this.#db
      .prepare(
        `UPDATE turn_requests
         SET state = 'dispatch_intent'
         WHERE request_id = ? AND lease_generation = ? AND state = 'starting'`
      )
      .run(record.requestId, record.generation);
    if (request.changes !== 1) {
      throw new Error("lease and request state diverged at dispatch intent persistence");
    }
    this.journalTransition(
      "request_dispatch_intent",
      record.requestId,
      "starting",
      "dispatch_intent",
      committedAt
    );
    return { status: "committed", idempotent: false };
  }

  private findLeaseProcessIdentity(leaseId: string): LeaseProcessIdentityRow | undefined {
    return this.#db
      .prepare(
        `SELECT lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
                connector_owner_instance_id, connector_created_at, connector_evidence_json,
                child_evidence_json, recorded_at
         FROM lease_process_identities
         WHERE lease_id = ?`
      )
      .get(leaseId) as LeaseProcessIdentityRow | undefined;
  }

  private insertLeaseProcessIdentity(record: VerifiedProcessRecord, recordedAt: number): void {
    const { connector, child } = record.processIdentity;
    this.#db
      .prepare(
        `INSERT INTO lease_process_identities (
           lease_id, request_id, lease_generation, owner_instance_id, prompt_channel,
           connector_owner_instance_id, connector_created_at, connector_evidence_json,
           child_evidence_json, recorded_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.leaseId,
        record.requestId,
        record.generation,
        record.ownerInstanceId,
        record.promptChannel,
        connector.ownerInstanceId,
        connector.createdAt,
        serializeVerifiedConnectorProcessIdentity(connector, this.#processEvidence.platform),
        serializePlatformProcessIdentity(child, this.#processEvidence.platform),
        recordedAt
      );
  }

  private persistQueuedOwnerReference(input: EnqueueRequest, recordedAt: number, requestExisted: boolean): void {
    const owner = normalizeVerifiedConnectorIdentity(
      input.ownerIdentity ?? this.#queuedOwnerIdentity,
      this.#processEvidence.platform
    );
    const existingOwner = this.findQueuedOwnerIdentity(owner.ownerInstanceId);
    if (existingOwner === undefined) {
      this.insertQueuedOwnerIdentity(owner, recordedAt);
    } else if (!sameQueuedOwnerIdentity(existingOwner, owner, this.#processEvidence.platform)) {
      throw new AdmissionConflictError(input.requestId);
    }

    const request = this.#db
      .prepare(
        `SELECT state, queued_owner_instance_id
         FROM turn_requests
         WHERE request_id = ?`
      )
      .get(input.requestId) as QueuedOwnerRequestRow | undefined;
    if (request === undefined) throw new Error("unknown request");
    if (request.state !== "queued") throw new Error("request is no longer queued");
    if (request.queued_owner_instance_id === owner.ownerInstanceId) return;
    if (request.queued_owner_instance_id !== null) {
      if (requestExisted) return;
      throw new AdmissionConflictError(input.requestId);
    }

    const result = this.#db
      .prepare(
        `UPDATE turn_requests
         SET queued_owner_instance_id = ?, queued_owner_recorded_at = ?
         WHERE request_id = ?
           AND state = 'queued'
           AND queued_owner_instance_id IS NULL`
      )
      .run(owner.ownerInstanceId, recordedAt, input.requestId);
    if (result.changes !== 1) throw new AdmissionConflictError(input.requestId);
  }

  private findQueuedOwnerIdentity(ownerInstanceId: string): QueuedOwnerIdentityRow | undefined {
    return this.#db
      .prepare(
        `SELECT owner_instance_id, created_at, queued_owner_evidence_json, recorded_at
         FROM queued_owner_instances
         WHERE owner_instance_id = ?`
      )
      .get(ownerInstanceId) as QueuedOwnerIdentityRow | undefined;
  }

  private insertQueuedOwnerIdentity(owner: VerifiedConnectorIdentity, recordedAt: number): void {
    this.#db
      .prepare(
        `INSERT INTO queued_owner_instances (
           owner_instance_id, created_at, queued_owner_evidence_json, recorded_at
         ) VALUES (?, ?, ?, ?)`
      )
      .run(
        owner.ownerInstanceId,
        owner.createdAt,
        serializeVerifiedConnectorProcessIdentity(owner, this.#processEvidence.platform),
        recordedAt
      );
  }

  private expireQueued(now: number): void {
    const expired = this.#db
      .prepare(
        "SELECT request_id FROM turn_requests WHERE state = 'queued' AND deadline_at <= ? ORDER BY request_id ASC"
      )
      .all(now) as Array<{ request_id: string }>;
    for (const row of expired) {
      const result = this.#db
        .prepare(
          "UPDATE turn_requests SET state = 'queue_timeout', terminal_at = ? WHERE request_id = ? AND state = 'queued'"
        )
        .run(now, row.request_id);
      if (result.changes === 1) {
        this.#db.prepare("DELETE FROM turn_payloads WHERE request_id = ?").run(row.request_id);
        this.journalTransition("request_queue_timed_out", row.request_id, "queued", "queue_timeout", now);
      }
    }
  }

  private activeLeaseCount(): number {
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS count FROM leases
         WHERE phase IN ('admitted', 'starting', 'dispatch_intent', 'dispatch_ambiguous', 'active', 'recovery_required')`
      )
      .get() as { count: number };
    return row.count;
  }

  private hasSeatCapacity(): boolean {
    const policyState = this.readPolicyStateInTransaction();
    if (policyState !== undefined) {
      const drainState = policyDrainState(policyState);
      if (drainState === "soft_draining_to_1") return false;
      return this.activeLeaseCount() < policyStateInteger(policyState.max_active_turns, "durable policy max_active_turns");
    }
    return this.activeLeaseCount() < this.policy.maxActiveTurns;
  }

  private markSuspect(fence: LeaseFence, now: number, reason: LeaseSuspectReason): boolean {
    validateTimestamp(now, "lease suspect timestamp");
    validateSuspectReason(reason);
    const result = this.#db
      .prepare(
        `UPDATE leases
         SET suspect_since = COALESCE(suspect_since, ?),
             suspect_reason = ?
         WHERE lease_id = ?
           AND owner_instance_id = ?
           AND generation = ?`
      )
      .run(now, reason, fence.leaseId, fence.ownerInstanceId, fence.generation);
    return result.changes === 1;
  }

  private completeSoftDrainTo1IfSettled(ownerInstanceId: string, now: number): void {
    const row = this.readPolicyStateInTransaction();
    if (row === undefined || policyDrainState(row) !== "soft_draining_to_1") return;
    if (this.activeLeaseCount() !== 0) return;

    const terminalPolicy = policyFromState(row, 1);
    const policyFingerprint = this.policyFingerprint(terminalPolicy);
    const result = this.#db
      .prepare(
        `UPDATE policy_state
         SET max_active_turns = 1,
             max_concurrent_starts = ?,
             min_start_interval_ms = ?,
             queue_timeout_ms = ?,
             capacity_cooldown_ms = ?,
             drain_state = 'steady',
             policy_fingerprint = ?,
             updated_at = ?,
             updated_by_owner_instance_id = ?
         WHERE id = 1 AND drain_state = 'soft_draining_to_1'`
      )
      .run(
        terminalPolicy.maxConcurrentStarts,
        terminalPolicy.minStartIntervalMs,
        terminalPolicy.queueTimeoutMs,
        terminalPolicy.capacityCooldownMs,
        policyFingerprint,
        now,
        ownerInstanceId
      );
    if (result.changes !== 1) throw new AdmissionRuntimeError("soft drain could not be completed atomically");
    this.journalTransition(
      "policy_drain_completed",
      "policy-state",
      "policy_soft_draining_to_1",
      "policy_steady",
      now
    );
  }

  private hasDispatchCapacity(now: number): boolean {
    if (!this.hasSeatCapacity()) return false;
    const starts = this.#db
      .prepare("SELECT COUNT(*) AS count FROM leases WHERE phase IN ('admitted', 'starting', 'dispatch_intent')")
      .get() as { count: number };
    if (starts.count >= this.policy.maxConcurrentStarts) return false;
    const cutoff = now - this.policy.minStartIntervalMs;
    const recentStart = this.#db
      .prepare("SELECT 1 FROM start_history WHERE started_at > ? LIMIT 1")
      .get(cutoff);
    if (recentStart !== undefined) return false;
    const recentReservation = this.#db
      .prepare(
        "SELECT 1 FROM leases WHERE phase IN ('admitted', 'starting', 'dispatch_intent') AND acquired_at > ? LIMIT 1"
      )
      .get(cutoff);
    return recentReservation === undefined;
  }

  private reserveAdmission(candidate: RequestRow, now: number, ownerInstanceId: string): AdmissionLease {
    const leaseId = randomUUID();
    const generation = candidate.lease_generation + 1;
    const reserved = this.#db
      .prepare(
        "UPDATE turn_requests SET state = 'admitted', lease_generation = ? WHERE request_id = ? AND state = 'queued'"
      )
      .run(generation, candidate.request_id);
    if (reserved.changes !== 1) throw new Error("selected admission request is no longer queued");
    this.#db
      .prepare(
        `INSERT INTO leases (lease_id, request_id, generation, owner_instance_id, phase, acquired_at, heartbeat_at)
         VALUES (?, ?, ?, ?, 'admitted', ?, ?)`
      )
      .run(leaseId, candidate.request_id, generation, ownerInstanceId, now, now);
    this.journalTransition("request_admitted", candidate.request_id, "queued", "admitted", now);
    return Object.freeze({ leaseId, requestId: candidate.request_id, generation, ownerInstanceId });
  }

  private orderedQueuedRequests(): RequestRow[] {
    return this.#db
      .prepare(
        `SELECT turn_requests.request_id, session_id, agent_id, fingerprint, provider, model,
                turn_requests.state, enqueued_at, lease_generation
         FROM turn_requests
         INNER JOIN turn_payloads payload ON payload.request_id = turn_requests.request_id
         WHERE turn_requests.state = 'queued' AND payload.content_fingerprint IS NOT NULL
         ORDER BY enqueued_at ASC, turn_requests.request_id ASC`
      )
      .all() as RequestRow[];
  }

  private selectEligibleRequest(now: number): RequestRow | null {
    const rows = this.orderedQueuedRequests();
    const activeAgents = new Set(
      (this.#db
        .prepare(
          `SELECT DISTINCT request.agent_id AS agent_id
           FROM leases lease JOIN turn_requests request ON request.request_id = lease.request_id
           WHERE lease.phase IN ('admitted', 'starting', 'dispatch_intent', 'dispatch_ambiguous', 'active', 'recovery_required')`
        )
        .all() as Array<{ agent_id: string }>).map((row) => row.agent_id)
    );
    const eligible = rows.filter((row) => !this.isCooldownActive(row.provider, row.model, now));
    if (eligible.length === 0) return null;
    return eligible.find((row) => !activeAgents.has(row.agent_id)) ?? eligible[0]!;
  }

  private isCooldownActive(provider: string, model: string, now: number): boolean {
    return this.cooldownUntil(provider, model, now) !== null;
  }

  private cooldownUntil(provider: string, model: string, now: number): number | null {
    const row = this.#db
      .prepare("SELECT not_before FROM cooldowns WHERE provider = ? AND model = ?")
      .get(provider, model) as { not_before: number } | undefined;
    return row !== undefined && row.not_before > now ? row.not_before : null;
  }

  private requireLease(fence: LeaseFence): LeaseRow {
    const lease = this.requireLeaseById(fence.leaseId);
    if (lease.generation !== fence.generation || lease.owner_instance_id !== fence.ownerInstanceId) {
      throw new LeaseFenceError(fence.leaseId);
    }
    return lease;
  }

  private requireLeaseById(leaseId: string): LeaseRow {
    const lease = this.#db
      .prepare(
        "SELECT lease_id, request_id, generation, owner_instance_id, phase FROM leases WHERE lease_id = ?"
      )
      .get(leaseId) as LeaseRow | undefined;
    if (!lease) throw new Error("unknown lease");
    return lease;
  }

  private requireRequest(requestId: string): void {
    const row = this.#db.prepare("SELECT 1 FROM turn_requests WHERE request_id = ?").get(requestId);
    if (!row) throw new Error("unknown request");
  }

  private requireRequestState(requestId: string): { state: RequestState } {
    const row = this.#db
      .prepare("SELECT state FROM turn_requests WHERE request_id = ?")
      .get(requestId) as { state: RequestState } | undefined;
    if (!row) throw new Error("unknown request");
    return row;
  }

  private requireEncryptionKey(): Buffer {
    if (!this.#encryptionKey) throw new Error("payload persistence requires an encryption key");
    return this.#encryptionKey;
  }

  private requireContentFingerprintKey(): Buffer {
    if (!this.#contentFingerprintKey) {
      throw new Error("admission event correlation requires a content fingerprint key");
    }
    return this.#contentFingerprintKey;
  }

  private journalTransition(
    kind: SanitizedEventKind,
    requestId: string,
    fromState: SanitizedEventState,
    toState: SanitizedEventState,
    occurredAt: number
  ): void {
    validateIdentifier(requestId, "event correlation input");
    validateTimestamp(occurredAt, "event timestamp");
    if (!isAllowedSanitizedEventTransition(kind, fromState, toState)) {
      throw new Error("admission event transition is not allowlisted");
    }
    const correlationHmac = createHmac("sha256", this.requireContentFingerprintKey())
      .update(JSON.stringify(["paseo-agy-acp", "admission-event-correlation", 1]), "utf8")
      .update(Buffer.from([0]))
      .update(requestId, "utf8")
      .digest("hex");
    this.#db
      .prepare(
        `INSERT INTO events (kind, from_state, to_state, occurred_at, correlation_hmac)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(kind, fromState, toState, occurredAt, correlationHmac);
  }

  private encrypt(plaintext: string, aad: string): EncryptedPayload {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.requireEncryptionKey(), nonce);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    return {
      nonce,
      ciphertext: Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]),
      authTag: cipher.getAuthTag()
    };
  }

  private decrypt(payload: EncryptedPayload, aad: string): string {
    const decipher = createDecipheriv("aes-256-gcm", this.requireEncryptionKey(), payload.nonce);
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(payload.authTag);
    return Buffer.concat([decipher.update(payload.ciphertext), decipher.final()]).toString("utf8");
  }

  private enqueueRequest(input: EnqueueRequest): { requestId: string; existed: boolean } {
    validateEnqueueRequest(input);
    const agentId = requestAgentId(input);
    const existing = this.#db
      .prepare(
        `SELECT session_id, agent_id, fingerprint, provider, model
         FROM turn_requests WHERE request_id = ?`
      )
      .get(input.requestId) as
      | { session_id: string; agent_id: string; fingerprint: string; provider: string; model: string }
      | undefined;
    if (existing) {
      if (
        existing.session_id !== input.sessionId ||
        existing.agent_id !== agentId ||
        existing.fingerprint !== input.fingerprint ||
        existing.provider !== input.provider ||
        existing.model !== input.model
      ) {
        throw new AdmissionConflictError(input.requestId);
      }
      return { requestId: input.requestId, existed: true };
    }

    this.#db
      .prepare(
        `INSERT INTO turn_requests
          (request_id, session_id, agent_id, fingerprint, provider, model, state, enqueued_at, deadline_at)
         VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)`
      )
      .run(
        input.requestId,
        input.sessionId,
        agentId,
        input.fingerprint,
        input.provider,
        input.model,
        input.now,
        input.now + this.policy.queueTimeoutMs
      );
    this.journalTransition("request_enqueued", input.requestId, "absent", "queued", input.now);
    return { requestId: input.requestId, existed: false };
  }

  private insertPayload(
    requestId: string,
    encrypted: EncryptedPayload,
    keyVersion: number,
    contentFingerprint: string,
    expiresAt: number,
    now: number
  ): void {
    this.#db
      .prepare(
        `INSERT INTO turn_payloads
          (request_id, nonce, ciphertext, auth_tag, key_version, content_fingerprint, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        requestId,
        encrypted.nonce,
        encrypted.ciphertext,
        encrypted.authTag,
        keyVersion,
        contentFingerprint,
        expiresAt,
        now
      );
  }

  private contentFingerprint(domain: string, id: string, plaintext: string): string {
    return createHmac("sha256", this.requireContentFingerprintKey())
      .update(JSON.stringify(["paseo-agy-acp", domain, "content", 1, id]), "utf8")
      .update(Buffer.from([0]))
      .update(plaintext, "utf8")
      .digest("hex");
  }

  private payloadAad(requestId: string, keyVersion: number): string {
    return JSON.stringify(["paseo-agy-acp", "turn", 1, requestId, keyVersion]);
  }

  private policyFingerprint(policy: AdmissionPolicy): string {
    return createHmac("sha256", this.requireContentFingerprintKey())
      .update(JSON.stringify(["paseo-agy-acp", "admission-policy", 1]), "utf8")
      .update(Buffer.from([0]))
      .update(JSON.stringify(normalizedPolicyTuple(policy)), "utf8")
      .digest("hex");
  }

  private assertDurablePolicyMatchInTransaction(
    policy: AdmissionPolicy,
    policyFingerprint: string,
    platform: ProcessEvidencePlatform
  ): void {
    const row = this.readPolicyStateInTransaction();
    if (row === undefined) {
      throw new AdmissionRuntimeError("durable policy has not been claimed");
    }
    if (row.process_evidence_platform !== platform) {
      throw new AdmissionRuntimeError("process evidence platform does not match durable admission platform");
    }
    if (!policyStateMatches(row, policy, policyFingerprint, platform)) {
      throw new AdmissionRuntimeError("durable policy does not match shared runtime policy");
    }
  }

  private readPolicyStateInTransaction(): PolicyStateRow | undefined {
    return this.#db
      .prepare(
        `SELECT max_active_turns, max_concurrent_starts, min_start_interval_ms,
                queue_timeout_ms, capacity_cooldown_ms, drain_state, policy_fingerprint,
                updated_at, updated_by_owner_instance_id, process_evidence_platform
         FROM policy_state WHERE id = 1`
      )
      .get() as PolicyStateRow | undefined;
  }

  private requirePolicyStateInTransaction(): PolicyStateRow {
    const row = this.readPolicyStateInTransaction();
    if (row === undefined) throw new AdmissionRuntimeError("durable policy has not been claimed");
    return row;
  }

  private validatePayloadExpiry(now: number, expiresAt: number): void {
    if (!Number.isFinite(now) || !Number.isFinite(expiresAt) || expiresAt <= now) {
      throw new Error("payload expiry must be after persistence time");
    }
  }

  private transition(fence: LeaseFence, expected: RequestState, next: RequestState, now: number): void {
    this.transaction(() => {
      const lease = this.requireLease(fence);
      if (lease.phase !== expected) throw new Error(`lease is not ${expected}`);
      this.setLeasePhase(lease, next, now);
    });
  }

  private setLeasePhase(lease: LeaseRow, phase: RequestState, now: number): void {
    const result = this.#db
      .prepare(
        "UPDATE leases SET phase = ?, heartbeat_at = ? WHERE lease_id = ? AND owner_instance_id = ? AND generation = ?"
      )
      .run(phase, now, lease.lease_id, lease.owner_instance_id, lease.generation);
    if (result.changes !== 1) throw new LeaseFenceError(lease.lease_id);
    this.#db.prepare("UPDATE turn_requests SET state = ? WHERE request_id = ?").run(phase, lease.request_id);
    this.journalTransition(requestTransitionKind(lease.phase, phase), lease.request_id, lease.phase, phase, now);
  }
}

const SANITIZED_EVENT_TRANSITIONS = new Set<string>([
  transitionSignature("request_enqueued", "absent", "queued"),
  transitionSignature("request_cancelled", "queued", "cancelled"),
  transitionSignature("queued_owner_dead", "queued", "cancelled"),
  ...(["admitted", "starting", "dispatch_intent"] as const).flatMap((fromState) => [
    transitionSignature("request_abandoned", fromState, "failed"),
    transitionSignature("request_abandoned", fromState, "cancelled")
  ]),
  transitionSignature("request_queue_timed_out", "queued", "queue_timeout"),
  transitionSignature("request_admitted", "queued", "admitted"),
  transitionSignature("request_starting", "admitted", "starting"),
  transitionSignature("request_dispatch_intent", "starting", "dispatch_intent"),
  transitionSignature("request_active", "dispatch_intent", "active"),
  transitionSignature("request_dispatch_ambiguous", "dispatch_intent", "dispatch_ambiguous"),
  transitionSignature("request_provider_terminal", "active", "provider_terminal"),
  transitionSignature("request_released", "provider_terminal", "completed"),
  transitionSignature("request_released", "provider_terminal", "failed"),
  transitionSignature("request_released", "provider_terminal", "cancelled"),
  ...(["admitted", "starting", "dispatch_intent", "dispatch_ambiguous", "active", "recovery_required"] as const).map(
    (fromState) => transitionSignature("request_recovery_required", fromState, "recovery_required")
  ),
  ...(["admitted", "starting", "dispatch_intent", "dispatch_ambiguous", "active", "recovery_required"] as const).map(
    (fromState) => transitionSignature("request_recovery_seat_released", fromState, "recovery_required")
  ),
  transitionSignature("policy_drain_completed", "policy_soft_draining_to_1", "policy_steady")
]);

function transitionSignature(
  kind: SanitizedEventKind,
  fromState: SanitizedEventState,
  toState: SanitizedEventState
): string {
  return `${kind}\0${fromState}\0${toState}`;
}

function isAllowedSanitizedEventTransition(
  kind: SanitizedEventKind,
  fromState: SanitizedEventState,
  toState: SanitizedEventState
): boolean {
  return SANITIZED_EVENT_TRANSITIONS.has(transitionSignature(kind, fromState, toState));
}

function requestTransitionKind(fromState: RequestState, toState: RequestState): SanitizedEventKind {
  if (fromState === "admitted" && toState === "starting") return "request_starting";
  if (fromState === "starting" && toState === "dispatch_intent") return "request_dispatch_intent";
  if (fromState === "dispatch_intent" && toState === "active") return "request_active";
  if (fromState === "dispatch_intent" && toState === "dispatch_ambiguous") {
    return "request_dispatch_ambiguous";
  }
  throw new Error("request transition is not journalled by the generic lease transition path");
}

function normalizeSanitizedEventPageRequest(input: unknown): SanitizedEventPageRequest {
  const record = dataRecord(input, ["afterEventSeq", "limit"]);
  if (record === null) throw new Error("sanitized event page request must have the exact supported shape");
  if (typeof record.afterEventSeq !== "number" || !Number.isSafeInteger(record.afterEventSeq) || record.afterEventSeq < 0) {
    throw new Error("sanitized event cursor must be a non-negative safe integer");
  }
  if (typeof record.limit !== "number" || !Number.isSafeInteger(record.limit) || record.limit < 1 || record.limit > 1_000) {
    throw new Error("sanitized event page limit must be between 1 and 1000");
  }
  return Object.freeze({ afterEventSeq: record.afterEventSeq, limit: record.limit });
}

function normalizeSanitizedEventRow(row: SanitizedEventRow): SanitizedAdmissionEvent {
  if (typeof row.event_seq !== "number" || !Number.isSafeInteger(row.event_seq) || row.event_seq < 1) {
    throw new Error("sanitized event journal contains an invalid sequence");
  }
  if (!isSanitizedEventKind(row.kind) || !isSanitizedEventState(row.from_state) || !isSanitizedEventState(row.to_state)) {
    throw new Error("sanitized event journal contains a non-allowlisted transition");
  }
  validateTimestamp(row.occurred_at, "sanitized event timestamp");
  if (typeof row.correlation_hmac !== "string" || !/^[0-9a-f]{64}$/.test(row.correlation_hmac)) {
    throw new Error("sanitized event journal contains an invalid correlation HMAC");
  }
  if (!isAllowedSanitizedEventTransition(row.kind, row.from_state, row.to_state)) {
    throw new Error("sanitized event journal contains a non-allowlisted transition");
  }
  return Object.freeze({
    eventSeq: row.event_seq,
    kind: row.kind,
    fromState: row.from_state,
    toState: row.to_state,
    occurredAt: row.occurred_at,
    correlationHmac: row.correlation_hmac
  });
}

function isSanitizedEventKind(value: unknown): value is SanitizedEventKind {
  return (
    value === "request_enqueued" ||
    value === "request_cancelled" ||
    value === "request_abandoned" ||
    value === "request_queue_timed_out" ||
    value === "request_admitted" ||
    value === "request_starting" ||
    value === "request_dispatch_intent" ||
    value === "request_active" ||
    value === "request_dispatch_ambiguous" ||
    value === "request_provider_terminal" ||
    value === "request_released" ||
    value === "request_recovery_required" ||
    value === "request_recovery_seat_released" ||
    value === "queued_owner_dead" ||
    value === "policy_drain_completed"
  );
}

function isSanitizedEventState(value: unknown): value is SanitizedEventState {
  if (value === "absent") return true;
  if (value === "policy_steady" || value === "policy_soft_draining_to_1") return true;
  try {
    normalizeRequestState(value);
    return true;
  } catch {
    return false;
  }
}

function validatePolicy(policy: AdmissionPolicy): AdmissionPolicy {
  for (const [name, value] of Object.entries(policy)) {
    if (!Number.isSafeInteger(value) || value < 0 || (name.startsWith("max") && value < 1)) {
      throw new Error(`invalid admission policy ${name}`);
    }
  }
  if (!isAllowedAdmissionActiveTurns(policy.maxActiveTurns)) {
    throw new Error("invalid admission policy maxActiveTurns");
  }
  if (!isAllowedAdmissionConcurrentStarts(policy.maxConcurrentStarts)) {
    throw new Error("invalid admission policy maxConcurrentStarts");
  }
  return Object.freeze({ ...policy });
}

function normalizedPolicyTuple(policy: AdmissionPolicy): readonly [number, number, number, number, number] {
  return Object.freeze([
    policy.maxActiveTurns,
    policy.maxConcurrentStarts,
    policy.minStartIntervalMs,
    policy.queueTimeoutMs,
    policy.capacityCooldownMs
  ]);
}

function policyStateMatches(
  row: PolicyStateRow,
  policy: AdmissionPolicy,
  policyFingerprint: string,
  platform: ProcessEvidencePlatform
): boolean {
  return (
    row.max_active_turns === policy.maxActiveTurns &&
    row.max_concurrent_starts === policy.maxConcurrentStarts &&
    row.min_start_interval_ms === policy.minStartIntervalMs &&
    row.queue_timeout_ms === policy.queueTimeoutMs &&
    row.capacity_cooldown_ms === policy.capacityCooldownMs &&
    row.policy_fingerprint === policyFingerprint &&
    row.process_evidence_platform === platform
  );
}

function policyFromState(row: PolicyStateRow, maxActiveTurns: number): AdmissionPolicy {
  return validatePolicy({
    maxActiveTurns,
    maxConcurrentStarts: policyStateInteger(row.max_concurrent_starts, "durable policy max_concurrent_starts"),
    minStartIntervalMs: policyStateInteger(row.min_start_interval_ms, "durable policy min_start_interval_ms"),
    queueTimeoutMs: policyStateInteger(row.queue_timeout_ms, "durable policy queue_timeout_ms"),
    capacityCooldownMs: policyStateInteger(row.capacity_cooldown_ms, "durable policy capacity_cooldown_ms")
  });
}

function policyStateInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new AdmissionRuntimeError(`${label} is invalid`);
  }
  return value;
}

function policyDrainState(row: PolicyStateRow): "steady" | "soft_draining_to_1" {
  if (row.drain_state !== "steady" && row.drain_state !== "soft_draining_to_1") {
    throw new AdmissionRuntimeError("durable policy drain state is invalid");
  }
  return row.drain_state;
}

function validateEnqueueRequest(input: EnqueueRequest): void {
  for (const field of ["requestId", "sessionId", "fingerprint", "provider", "model"] as const) {
    const value = input[field];
    if (typeof value !== "string" || value.trim().length === 0 || value.includes("\0")) {
      throw new Error(`invalid request metadata ${field}`);
    }
  }
  validateIdentifier(requestAgentId(input), "request metadata agentId");
  if (!Number.isSafeInteger(input.now) || input.now < 0) {
    throw new Error("invalid request timestamp");
  }
}

function requestAgentId(input: EnqueueRequest): string {
  const record = input as { agentId?: unknown; parentId?: unknown };
  if (record.parentId !== undefined) {
    throw new Error("request metadata parentId is not accepted");
  }
  if (typeof record.agentId === "string") {
    return record.agentId;
  }
  throw new Error("invalid request metadata agentId");
}

function validateIdentifier(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} must be a non-empty single-line identifier`);
  }
}

function validateTimestamp(value: unknown, label: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
}

function validateFaultInjection(value: unknown): AdmissionControllerFaultInjection | undefined {
  if (value === undefined) return undefined;
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("fault injection must be an object");
    }
    const callbacks = value as { afterProcessIdentityPersisted?: unknown };
    const callback = (value: unknown): (() => void) | undefined => {
      if (value === undefined) return undefined;
      if (typeof value !== "function") {
        throw new Error("fault injection callback must be a function");
      }
      return value as () => void;
    };
    const afterProcessIdentityPersisted = callback(callbacks.afterProcessIdentityPersisted);
    return Object.freeze({
      afterProcessIdentityPersisted:
        afterProcessIdentityPersisted === undefined ? undefined : () => afterProcessIdentityPersisted()
    });
  } catch (error) {
    if (error instanceof Error) throw error;
    throw new Error("fault injection is invalid");
  }
}

function assertV3MigrationShape(db: Database.Database): void {
  for (const [table, expectedColumns] of Object.entries(V3_MIGRATION_COLUMNS)) {
    const actual = db.pragma(`table_info('${table}')`) as V3ColumnInfoRow[];
    if (
      !Array.isArray(actual) ||
      actual.length !== expectedColumns.length ||
      actual.some((column, index) => {
        const expected = expectedColumns[index];
        return (
          expected === undefined ||
          column.name !== expected[0] ||
          column.type !== expected[1] ||
          column.notnull !== expected[2] ||
          column.pk !== expected[3]
        );
      })
    ) {
      throw new AdmissionMigrationError(`schema v3 table ${table} does not match the migration contract`);
    }
  }

  const requiredSql = new Map<string, readonly string[]>([
    ["lease_process_identities", [
      "lease_id TEXT PRIMARY KEY REFERENCES leases(lease_id) ON DELETE CASCADE",
      "request_id TEXT NOT NULL REFERENCES turn_requests(request_id)"
    ]],
    ["policy_state", [
      "id INTEGER PRIMARY KEY CHECK (id = 1)",
      "max_active_turns INTEGER NOT NULL CHECK (max_active_turns >= 1)",
      "max_concurrent_starts INTEGER NOT NULL CHECK (max_concurrent_starts >= 1)",
      "min_start_interval_ms INTEGER NOT NULL CHECK (min_start_interval_ms >= 2000)",
      "queue_timeout_ms INTEGER NOT NULL CHECK (queue_timeout_ms > 0 AND queue_timeout_ms <= 1800000)",
      "capacity_cooldown_ms INTEGER NOT NULL CHECK (capacity_cooldown_ms >= 30000)",
      "drain_state TEXT NOT NULL CHECK (drain_state IN ('steady', 'soft_draining_to_1'))"
    ]],
    ["queued_owner_instances", []]
  ]);
  for (const [table, fragments] of requiredSql) {
    const row = db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(table) as { sql?: unknown } | undefined;
    if (typeof row?.sql !== "string") {
      throw new AdmissionMigrationError(`schema v3 table ${table} definition is unavailable`);
    }
    const normalized = row.sql.replace(/\s+/g, " ").trim().toUpperCase();
    for (const fragment of fragments) {
      if (!normalized.includes(fragment.replace(/\s+/g, " ").trim().toUpperCase())) {
        throw new AdmissionMigrationError(`schema v3 table ${table} definition does not match the migration contract`);
      }
    }
  }

  const namedIndexes = (db.pragma("index_list('lease_process_identities')") as Array<{
    name: unknown;
    origin: unknown;
    unique: unknown;
    partial: unknown;
  }>).filter((index) => index.origin === "c");
  if (
    namedIndexes.length !== 1 ||
    namedIndexes[0]?.name !== "lease_process_identities_request" ||
    namedIndexes[0]?.unique !== 1 ||
    namedIndexes[0]?.partial !== 0
  ) {
    throw new AdmissionMigrationError("schema v3 lease process identity indexes do not match the migration contract");
  }
  const indexColumns = (db.pragma("index_xinfo('lease_process_identities_request')") as Array<{
    seqno: unknown;
    name: unknown;
    key: unknown;
    coll: unknown;
  }>)
    .filter((column) => column.key === 1)
    .sort((left, right) => Number(left.seqno) - Number(right.seqno));
  if (
    indexColumns.length !== 1 ||
    indexColumns[0]?.name !== "request_id" ||
    indexColumns[0]?.coll !== "BINARY"
  ) {
    throw new AdmissionMigrationError("schema v3 lease process identity index columns do not match the migration contract");
  }
  for (const table of ["policy_state", "queued_owner_instances"]) {
    const indexes = db.pragma(`index_list('${table}')`) as Array<{ origin: unknown }>;
    if (indexes.some((index) => index.origin === "c")) {
      throw new AdmissionMigrationError(`schema v3 table ${table} has an unexpected named index`);
    }
  }

  const foreignKeys = (db.pragma("foreign_key_list('lease_process_identities')") as Array<{
    from: string;
    table: string;
    to: string;
    on_update: string;
    on_delete: string;
    match: string;
  }>).map((foreignKey) => JSON.stringify([
    foreignKey.from,
    foreignKey.table,
    foreignKey.to,
    foreignKey.on_update,
    foreignKey.on_delete,
    foreignKey.match
  ])).sort();
  const expectedForeignKeys = [
    JSON.stringify(["lease_id", "leases", "lease_id", "NO ACTION", "CASCADE", "NONE"]),
    JSON.stringify(["request_id", "turn_requests", "request_id", "NO ACTION", "NO ACTION", "NONE"])
  ].sort();
  if (JSON.stringify(foreignKeys) !== JSON.stringify(expectedForeignKeys)) {
    throw new AdmissionMigrationError("schema v3 lease process identity foreign keys do not match the migration contract");
  }
  for (const table of ["policy_state", "queued_owner_instances"]) {
    const unexpectedForeignKeys = db.pragma(`foreign_key_list('${table}')`);
    if (Array.isArray(unexpectedForeignKeys) && unexpectedForeignKeys.length > 0) {
      throw new AdmissionMigrationError(`schema v3 table ${table} has unexpected foreign keys`);
    }
  }
}

function assertMigrationSequence(db: Database.Database, applied: number): void {
  const rows = db
    .prepare("SELECT version, name FROM schema_migrations ORDER BY version ASC")
    .all() as Array<{ version: unknown; name: unknown }>;
  const versions = rows.map((row) => row.version);
  if (versions.some((version) => typeof version !== "number" || !Number.isSafeInteger(version))) {
    throw new AdmissionMigrationError("admission migration ledger contains a non-integer version");
  }
  const numericVersions = versions as number[];
  const complete = numericVersions.length === 4 && numericVersions.every((version, index) => version === index + 1);
  const fresh = numericVersions.length === 1 && numericVersions[0] === 4;
  const legacy = !complete && !fresh && numericVersions.length === applied && numericVersions.every(
    (version, index) => version === index + 1
  );
  if (!complete && !fresh && !legacy) {
    throw new AdmissionMigrationError("admission migration ledger is partial or unknown");
  }
  for (const row of rows) {
    const version = row.version as number;
    const name = ADMISSION_MIGRATION_NAMES[version - 1];
    if (name === undefined || row.name !== name) {
      throw new AdmissionMigrationError(`admission migration ${version} has an invalid name`);
    }
  }
}

function compareSqliteVersions(left: string, right: string): number {
  const leftParts = sqliteVersionParts(left);
  const rightParts = sqliteVersionParts(right);
  for (let index = 0; index < 3; index += 1) {
    const difference = leftParts[index]! - rightParts[index]!;
    if (difference !== 0) return difference;
  }
  return 0;
}

function sqliteVersionParts(value: string): [number, number, number] {
  const parts = value.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length < 2 || parts.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    throw new AdmissionMigrationError(`SQLite version ${value} could not be parsed`);
  }
  return [parts[0]!, parts[1]!, parts[2] ?? 0];
}

function isSqliteTransactionContention(error: unknown): boolean {
  if (!(error instanceof Error) || error.name !== "SqliteError") return false;
  const code = (error as { code?: unknown }).code;
  return (
    code === "SQLITE_BUSY" ||
    code === "SQLITE_BUSY_RECOVERY" ||
    code === "SQLITE_BUSY_SNAPSHOT" ||
    code === "SQLITE_BUSY_TIMEOUT" ||
    code === "SQLITE_LOCKED" ||
    code === "SQLITE_LOCKED_SHAREDCACHE"
  );
}

function normalizeVerifiedProcessRecord(
  value: unknown,
  platform: ProcessEvidencePlatform = "linux"
): VerifiedProcessRecord | null {
  try {
    const record = dataRecord(value, ["requestId", "leaseId", "generation", "ownerInstanceId", "processIdentity", "promptChannel"]);
    if (record === null) return null;
    const processIdentity = dataRecord(record.processIdentity, ["connector", "child"]);
    if (processIdentity === null) return null;

    const ownerInstanceId = normalizeOwnerInstanceId(record.ownerInstanceId);
    const connector = normalizeVerifiedConnectorIdentity(processIdentity.connector, platform);
    const child = normalizeVerifiedProcessIdentity(processIdentity.child, platform);
    if (connector.ownerInstanceId !== ownerInstanceId) return null;
    const promptChannel = record.promptChannel;
    if (promptChannel !== "stdin" && promptChannel !== "pty") return null;

    return Object.freeze({
      requestId: normalizeIdentifier(record.requestId, "process record request ID"),
      leaseId: normalizeIdentifier(record.leaseId, "process record lease ID"),
      generation: normalizePositiveSafeInteger(record.generation, "process record generation", Number.MAX_SAFE_INTEGER),
      ownerInstanceId,
      processIdentity: Object.freeze({ connector, child }),
      promptChannel
    });
  } catch {
    return null;
  }
}

function requireLinuxProcessEvidence(
  processEvidence: ProcessEvidence<PlatformProcessIdentity>
): ProcessEvidence<ProcessIdentity> {
  if (processEvidence.platform !== "linux") {
    throw new AdmissionRuntimeError("platform process evidence is not available through the Linux compatibility accessor");
  }
  return processEvidence as unknown as ProcessEvidence<ProcessIdentity>;
}

function captureControllerQueuedOwnerIdentity(
  processEvidence: ProcessEvidence<PlatformProcessIdentity>
): VerifiedConnectorIdentity {
  return normalizeVerifiedConnectorIdentity({
    ownerInstanceId: randomUUID(),
    createdAt: new Date().toISOString(),
    ...processEvidence.capture(process.pid)
  }, processEvidence.platform);
}

function normalizeVerifiedConnectorIdentity(
  value: unknown,
  platform: ProcessEvidencePlatform = "linux"
): VerifiedConnectorIdentity {
  const identityKeys = PLATFORM_PROCESS_IDENTITY_KEYS[platform];
  const record = dataRecord(value, ["ownerInstanceId", "createdAt", ...identityKeys]);
  if (record === null) throw new Error("connector identity is invalid");
  const identity = normalizeVerifiedProcessIdentity(copyPlatformProcessIdentityFields(record, platform), platform);
  return Object.freeze({
    ownerInstanceId: normalizeOwnerInstanceId(record.ownerInstanceId),
    createdAt: normalizeCanonicalUtcTimestamp(record.createdAt),
    ...identity
  });
}

function serializeVerifiedConnectorProcessIdentity(
  value: VerifiedConnectorIdentity,
  platform: ProcessEvidencePlatform
): string {
  const identityKeys = PLATFORM_PROCESS_IDENTITY_KEYS[platform];
  const record = dataRecord(value, ["ownerInstanceId", "createdAt", ...identityKeys]);
  if (record === null) throw new Error("connector identity is invalid");
  return serializePlatformProcessIdentity(copyPlatformProcessIdentityFields(record, platform), platform);
}

function copyPlatformProcessIdentityFields(
  record: Record<string, unknown>,
  platform: ProcessEvidencePlatform
): Record<string, unknown> {
  const identityRecord: Record<string, unknown> = Object.create(null);
  for (const key of PLATFORM_PROCESS_IDENTITY_KEYS[platform]) identityRecord[key] = record[key];
  return identityRecord;
}

function normalizeVerifiedProcessIdentity(
  value: unknown,
  platform: ProcessEvidencePlatform = "linux"
): VerifiedProcessIdentity {
  const record = dataRecord(value, PLATFORM_PROCESS_IDENTITY_KEYS[platform]);
  if (record === null) throw new Error("process identity is invalid");
  const identity = normalizePlatformProcessIdentity(record, platform);
  if (identity === null) throw new Error("process identity is invalid");
  return identity;
}

function sameLeaseProcessIdentity(
  row: LeaseProcessIdentityRow,
  record: VerifiedProcessRecord,
  platform: ProcessEvidencePlatform
): boolean {
  const { connector, child } = record.processIdentity;
  return (
    row.request_id === record.requestId &&
    row.lease_generation === record.generation &&
    row.owner_instance_id === record.ownerInstanceId &&
    row.prompt_channel === record.promptChannel &&
    row.connector_owner_instance_id === connector.ownerInstanceId &&
    row.connector_created_at === connector.createdAt &&
    row.connector_evidence_json === serializeVerifiedConnectorProcessIdentity(connector, platform) &&
    row.child_evidence_json === serializePlatformProcessIdentity(child, platform)
  );
}

function sameQueuedOwnerIdentity(
  row: QueuedOwnerIdentityRow,
  owner: VerifiedConnectorIdentity,
  platform: ProcessEvidencePlatform
): boolean {
  return (
    row.owner_instance_id === owner.ownerInstanceId &&
    row.created_at === owner.createdAt &&
    row.queued_owner_evidence_json === serializeVerifiedConnectorProcessIdentity(owner, platform)
  );
}

function dataRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const record = value as Record<string, unknown>;
    const keys = Object.getOwnPropertyNames(record);
    if (
      Object.getOwnPropertySymbols(record).length !== 0 ||
      keys.length !== expectedKeys.length ||
      keys.some((key) => !expectedKeys.includes(key))
    ) {
      return null;
    }
    for (const key of expectedKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) return null;
    }
    return record;
  } catch {
    return null;
  }
}

function normalizeIdentifier(value: unknown, label: string): string {
  validateIdentifier(value, label);
  return value;
}

function normalizeOwnerInstanceId(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw new Error("process record owner instance ID must be a canonical UUID v4");
  }
  return value;
}

function normalizeCanonicalUtcTimestamp(value: unknown): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error("connector creation timestamp must be canonical UTC");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error("connector creation timestamp is invalid");
  }
  return value;
}

function normalizePositiveSafeInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function validateSuspectReason(reason: LeaseSuspectReason): void {
  if (reason !== "heartbeat_expired" && reason !== "identity_unverifiable") {
    throw new Error("lease suspect reason is invalid");
  }
}

function isHeartbeatStale(heartbeatAt: number, now: number): boolean {
  return now - heartbeatAt > LEASE_HEARTBEAT_STALE_MS;
}

function isGoneIdentity(value: ProcessIdentityState): boolean {
  return value === "gone" || value === "pid_reused";
}

function toRecoverableQueuedOwner(
  row: RecoverableQueuedOwnerRow,
  platform: ProcessEvidencePlatform
): RecoverableQueuedOwner {
  try {
    return Object.freeze({
      requestId: normalizeIdentifier(row.request_id, "recoverable queued-owner request ID"),
      owner: normalizeQueuedOwnerIdentityRow(row, platform)
    });
  } catch {
    throw new RecoverableDispatchInventoryError();
  }
}

function normalizeQueuedOwnerIdentityRow(
  row: QueuedOwnerIdentityRow,
  platform: ProcessEvidencePlatform
): VerifiedConnectorIdentity {
  const identity = parsePlatformProcessIdentity(row.queued_owner_evidence_json, platform);
  if (identity === null) throw new Error("queued owner process evidence is invalid");
  return normalizeVerifiedConnectorIdentity({
    ownerInstanceId: row.owner_instance_id,
    createdAt: row.created_at,
    ...identity
  }, platform);
}

function toRecoverableDispatch(
  row: RecoverableDispatchRow,
  platform: ProcessEvidencePlatform
): RecoverableDispatch | null {
  try {
    const requestId = normalizeIdentifier(row.request_id, "recoverable dispatch request ID");
    const leaseRequestId = normalizeIdentifier(row.lease_request_id, "recoverable dispatch lease request ID");
    const sessionId = normalizeIdentifier(row.request_session_id, "recoverable dispatch session ID");
    const provider = normalizeIdentifier(row.request_provider, "recoverable dispatch provider");
    const model = normalizeIdentifier(row.request_model, "recoverable dispatch model");
    const fence = Object.freeze({
      leaseId: normalizeIdentifier(row.lease_id, "recoverable dispatch lease ID"),
      generation: normalizePositiveSafeInteger(
        row.lease_generation,
        "recoverable dispatch lease generation",
        Number.MAX_SAFE_INTEGER
      ),
      ownerInstanceId: normalizeIdentifier(row.lease_owner_instance_id, "recoverable dispatch lease owner")
    });
    const requestLeaseGeneration = normalizePositiveSafeInteger(
      row.request_lease_generation,
      "recoverable dispatch request lease generation",
      Number.MAX_SAFE_INTEGER
    );
    const phase = normalizeRequestState(row.lease_phase);
    const requestState = normalizeRequestState(row.request_state);
    validateTimestamp(row.lease_heartbeat_at, "recoverable dispatch heartbeat");
    validateTimestamp(row.request_enqueued_at, "recoverable dispatch enqueue timestamp");

    if (leaseRequestId !== requestId || requestLeaseGeneration !== fence.generation) {
      throw new Error("lease/request fence mismatch");
    }

    const processIdentity = toRecoverableDispatchProcessIdentity(row, requestId, fence, platform);
    if (processIdentity !== null && (phase === "admitted" || phase === "starting")) {
      throw new Error("process identity predates dispatch intent");
    }

    if (!isRecoverableDispatchPhase(phase) || requestState !== phase) {
      throw new Error("nonterminal lease/request state mismatch");
    }

    return Object.freeze({
      requestId,
      sessionId,
      provider,
      model,
      fence,
      phase,
      heartbeatAt: row.lease_heartbeat_at,
      processIdentity
    });
  } catch {
    throw new RecoverableDispatchInventoryError();
  }
}

function toRecoverableDispatchProcessIdentity(
  row: RecoverableDispatchRow,
  requestId: string,
  fence: LeaseFence,
  platform: ProcessEvidencePlatform
): RecoverableDispatchProcessIdentity | null {
  const values = [
    row.identity_lease_id,
    row.identity_request_id,
    row.identity_lease_generation,
    row.identity_owner_instance_id,
    row.identity_prompt_channel,
    row.identity_connector_owner_instance_id,
    row.identity_connector_created_at,
    row.identity_connector_evidence_json,
    row.identity_child_evidence_json
  ];
  if (values.every((value) => value === null)) return null;
  if (values.some((value) => value === null || value === undefined)) {
    throw new Error("partial process identity");
  }

  const identityLeaseId = normalizeIdentifier(row.identity_lease_id, "recoverable process identity lease ID");
  const identityRequestId = normalizeIdentifier(row.identity_request_id, "recoverable process identity request ID");
  const identityLeaseGeneration = normalizePositiveSafeInteger(
    row.identity_lease_generation,
    "recoverable process identity lease generation",
    Number.MAX_SAFE_INTEGER
  );
  const identityOwnerInstanceId = normalizeIdentifier(
    row.identity_owner_instance_id,
    "recoverable process identity owner"
  );
  if (
    identityLeaseId !== fence.leaseId ||
    identityRequestId !== requestId ||
    identityLeaseGeneration !== fence.generation ||
    identityOwnerInstanceId !== fence.ownerInstanceId
  ) {
    throw new Error("process identity fence mismatch");
  }
  if (row.identity_prompt_channel !== "stdin" && row.identity_prompt_channel !== "pty") {
    throw new Error("process identity prompt channel is invalid");
  }

  const connectorIdentity = parsePlatformProcessIdentity(row.identity_connector_evidence_json, platform);
  const childIdentity = parsePlatformProcessIdentity(row.identity_child_evidence_json, platform);
  if (connectorIdentity === null || childIdentity === null) {
    throw new Error("process evidence is malformed or belongs to another platform");
  }
  const connector = normalizeVerifiedConnectorIdentity({
    ownerInstanceId: row.identity_connector_owner_instance_id,
    createdAt: row.identity_connector_created_at,
    ...connectorIdentity
  }, platform);
  if (connector.ownerInstanceId !== fence.ownerInstanceId) {
    throw new Error("connector process identity owner mismatch");
  }
  return Object.freeze({ promptChannel: row.identity_prompt_channel, connector, child: childIdentity });
}

function normalizeRequestState(value: unknown): RequestState {
  switch (value) {
    case "queued":
    case "admitted":
    case "starting":
    case "dispatch_intent":
    case "dispatch_ambiguous":
    case "active":
    case "provider_terminal":
    case "completed":
    case "failed":
    case "cancelled":
    case "queue_timeout":
    case "recovery_required":
      return value;
    default:
      throw new Error("request state is invalid");
  }
}

function isRecoverableDispatchPhase(value: RequestState): value is RecoverableDispatchPhase {
  return (
    value === "admitted" ||
    value === "starting" ||
    value === "dispatch_intent" ||
    value === "dispatch_ambiguous" ||
    value === "active" ||
    value === "recovery_required"
  );
}

function validateLiveTurnCompletion(value: LiveTurnCompletion): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("live turn completion must be an object");
  }
  if (value.outcome !== "completed" && value.outcome !== "failed" && value.outcome !== "cancelled") {
    throw new Error("live turn completion outcome is invalid");
  }
  if (value.outcome !== "failed" && value.failure !== undefined) {
    throw new Error("live turn completion failure is inconsistent");
  }
  if (value.failure === undefined) return;
  const categories = new Set([
    "provider_capacity",
    "quota",
    "auth",
    "permission",
    "timeout",
    "transport",
    "unknown"
  ]);
  if (!categories.has(value.failure.category)) throw new Error("live turn failure category is invalid");
  if (
    value.failure.httpStatus !== undefined &&
    (!Number.isInteger(value.failure.httpStatus) || value.failure.httpStatus < 100 || value.failure.httpStatus > 599)
  ) {
    throw new Error("live turn failure HTTP status is invalid");
  }
  for (const signal of [value.failure.code, value.failure.reason]) {
    if (signal !== undefined) validateIdentifier(signal, "live turn failure signal");
  }
}

function validatePurposeKey(
  key: Buffer | undefined,
  purpose: "encryption" | "content fingerprint"
): Buffer | undefined {
  if (key === undefined) return undefined;
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error(`admission ${purpose} key must be exactly 32 bytes`);
  }
  return Buffer.from(key);
}

function toStoredRequest(row: RequestRow): StoredRequest {
  return {
    requestId: row.request_id,
    sessionId: row.session_id,
    agentId: row.agent_id,
    fingerprint: row.fingerprint,
    provider: row.provider,
    model: row.model,
    state: row.state,
    enqueuedAt: row.enqueued_at
  };
}
