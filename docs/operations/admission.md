# Admission operations

[English](./admission.md) | [中文](./admission.zh-CN.md)

Admission protects one Antigravity account from prompt bursts created by
multi-agent Paseo delegation. It is a durable, account-wide fence around the
official kernel's `session/prompt` write. It does not replace Paseo scheduling
or the official ACP session lifecycle.

## Platform support and default behavior

Admission is supported on Linux and macOS `arm64` and `x64` hosts. Admission
remains disabled by default; set `AGY_ACP_ADMISSION_ENABLED` to `true` or `1`
only when account-wide queueing, shared seats, startup recovery, and runtime
reaping are required. Running without Admission is appropriate only for a
deliberately isolated single agent.

Other operating systems are unsupported for enabled Admission. They fail
closed rather than running an official-kernel prompt without the configured
queue guarantees. The separate Linux-only official-kernel compatibility
lifecycle for Claude and GPT-OSS is not part of macOS Admission support.

## When to enable it

Enable Admission when multiple Paseo agents can use the same Antigravity
account concurrently. All connector processes for one account on one host must
use the same `AGY_ACP_STATE_DIR` and identical policy. Different accounts must
use different account state roots.

## Prepare a fresh account state root

Choose a new, unused root for each Antigravity account:

```bash
export AGY_ACP_STATE_DIR="$HOME/.local/state/paseo-agy-acp/account-name"
install -d -m 700 "$AGY_ACP_STATE_DIR"
npx -y --package=paseo-agy-acp@2.3.2 \
  agy-acp-prepare-state "$AGY_ACP_STATE_DIR"
export AGY_ACP_ADMISSION_ENABLED=true
```

The preflight creates or validates only the account state root. It requires an
absolute path owned by the current user with exact `0700` permissions and
rejects an existing directory with wider permissions rather than silently
changing it. When enabled Admission first opens the root, it creates the nested
ledger directory with `0700` permissions and new owner-only state files with
`0600` permissions.

The nested `official-kernel` ledger is created below
`$AGY_ACP_STATE_DIR/official-kernel`. Configure the account state root, not the
nested directory. Admission state is host-local and platform-bound: never copy
a live or existing ledger to another machine, from Linux to macOS, or from
macOS to Linux. Preserve the old root when changing policy or platform.

## Verify ownership and permissions

On Linux, inspect the account state root with:

```bash
stat -c '%U %a %n' "$AGY_ACP_STATE_DIR"
```

On macOS, use:

```bash
stat -f '%Su %Lp %N' "$AGY_ACP_STATE_DIR"
```

The path must be absolute, its owner must match the connector user, and its
mode must be `700`. After confirming that the path is the intended account
root, repair ownership or mode and rerun the preflight:

```bash
sudo chown "$(id -un)" "$AGY_ACP_STATE_DIR"
chmod 700 "$AGY_ACP_STATE_DIR"
npx -y --package=paseo-agy-acp@2.3.2 \
  agy-acp-prepare-state "$AGY_ACP_STATE_DIR"
```

Do not recursively change ownership or permissions until the account and path
have been verified.

## Required runtime identity

An enabled connector requires:

- `AGY_ACP_ADMISSION_ENABLED=true` or `1`;
- an absolute, prepared `AGY_ACP_STATE_DIR`;
- a valid `PASEO_AGENT_ID` supplied by Paseo;
- a supported evidence platform and a healthy host-matching native artifact on
  macOS.

Missing or malformed enabled configuration fails closed. Provider Discovery
before Paseo supplies `PASEO_AGENT_ID` does not open the Admission ledger or
load process evidence. `--login` does not initialize Admission or create the
nested ledger; official OAuth state remains owned by the official kernel.

## Policy defaults

| Behavior | Default | Environment override |
|---|---:|---|
| Shared active turns | `8` | `AGY_ACP_ADMISSION_MAX_ACTIVE_TURNS`, integer >= 1 |
| Concurrent starts | `8` | `AGY_ACP_ADMISSION_MAX_CONCURRENT_STARTS`, integer >= 1 |
| Minimum start spacing | `2000 ms` | `AGY_ACP_ADMISSION_MIN_START_INTERVAL_MS`, integer >= 2000 |
| Maximum queue wait | `1800000 ms` | `AGY_ACP_ADMISSION_QUEUE_TIMEOUT_MS`, integer 1-1800000 |
| Provider/model capacity cooldown | `30000 ms` | `AGY_ACP_ADMISSION_CAPACITY_COOLDOWN_MS`, integer >= 30000 |

These values are tested operating defaults, not a declared Google concurrency
limit. Increase them only with account-specific observation and keep the start
spacing floor. Invalid overrides stop the enabled connector before it can run
unfenced.

## Runtime behavior

1. A prompt requests an account seat before any official kernel write.
2. Eligible requests are scheduled oldest-first with agent fairness.
3. The start gate enforces concurrent-start and spacing policy.
4. The connector performs one fenced `session/prompt` write.
5. Completion, failure, or cancellation releases the seat.

Idle sessions do not occupy seats. Closing a session cancels queued work that
has not started. Running work uses the normal connector cancellation path.
Queue timeout removes the queued request and its protected payload in the same
transaction.

Trusted provider-capacity failures pause only the affected provider/model for
the configured cooldown. Authentication, permission, transport, timeout, and
other failures retain distinct classifications.

## Persistence and recovery

Policy, queued ownership, leases, and recovery state are persisted in the
host-local, platform-bound nested ledger so separate connector processes on
one host share one account pool. Startup recovery and the runtime reaper use
the same selected process-evidence adapter. They verify connector, child,
process-group, descendant, and PID-reuse evidence before reclaiming local
capacity.

Heartbeat expiry is only a suspicion signal. Missing, malformed, inaccessible,
incomplete, or ambiguous evidence is `unverifiable` and retains the local seat.
Do not delete or edit the state directory to force startup. Back up or inspect
it only when every connector using the account is stopped.

## Native artifact selection and source-build fallback

The Darwin loader selects by actual Node runtime platform and architecture, not
by a guessed Mac model. Check the runtime target with:

```bash
node -p '`${process.platform}/${process.arch}`'
```

| Runtime target | Selected evidence implementation |
|---|---|
| `darwin/arm64` | `prebuilds/darwin-arm64/darwin_process_evidence.node` |
| `darwin/x64` | `prebuilds/darwin-x64/darwin_process_evidence.node` |
| `linux/*` | Linux procfs evidence; no Darwin prebuild is loaded |

An x64 Node process under Rosetta therefore expects the reviewed x64 prebuild.
A missing, unreadable, invalid, or architecture-mismatched artifact is an
actionable startup error. Record the expected platform, actual platform,
expected architecture, actual architecture, and attempted artifact path, then
reinstall the same pinned package on the supported host. Do not copy an
artifact from another architecture.

The source-build fallback is for a source checkout with Xcode Command Line
Tools, not an automatic repair for an installed package:

```bash
npm run build:native
npm run test:native:source
```

The source build is written to `build/Release/` and is tested separately from
installed-package prebuild consumption. Contributors may use it to reproduce
the native process-evidence contract locally; operators should reinstall the
reviewed host-matching package instead of shipping or copying a locally built
artifact.

## Changing policy

Processes opening the same state directory must agree with the persisted
policy. A conflicting policy fails closed instead of creating a process-local
split.

For an intentional policy change:

1. stop every connector using the account;
2. record the old environment and state path;
3. choose a new owner-only `AGY_ACP_STATE_DIR`;
4. run `agy-acp-prepare-state` for the new directory;
5. start one connector and verify a simple turn;
6. restore normal multi-agent delegation.

Keep the previous directory untouched until the new policy has passed live
verification. Switching the provider environment back to the previous path is
the rollback.

## Safe troubleshooting

Stop additional dispatch for the affected account before inspecting durable
state. Preserve the account state root and collect only sanitized errors,
runtime target, policy values, owner names, and process status. Never include
prompt payloads, credentials, OAuth state, or encrypted database contents in an
issue.

### Connector refuses to start

Check the configured path, runtime target, and supplied agent identity:

```bash
printf '%s\n' "$AGY_ACP_STATE_DIR"
node -p '`${process.platform}/${process.arch}`'
printf '%s\n' "$PASEO_AGENT_ID"
```

Then use the Linux or macOS ownership command from the setup section. The path
must be absolute, owner must match the connector user, mode must be `700`, and
every numeric policy value must satisfy the policy table.

### Policy mismatch

Stop all connectors using the account and confirm they have identical Admission
environment. A policy mismatch means the same local ledger was opened with a
different normalized policy. Preserve the old ledger; do not overwrite its
fingerprint. When the transition is intentional, prepare a fresh account state
root, start one connector, verify a simple turn, and then restore normal
dispatch.

### Platform mismatch or unsupported operating system

A platform mismatch means Linux-owned state was opened on macOS or macOS-owned
state was opened on Linux. An unsupported operating system with Admission
explicitly enabled must also fail closed. Do not edit the stored platform tag
or evidence JSON. Keep unsupported platforms deliberately unfenced only for
an intentionally isolated single agent, or transition on a supported host with
a fresh local account state root.

### Malformed or unverifiable evidence

Malformed durable evidence or malformed platform-tagged JSON fails closed at
startup; preserve the ledger for diagnosis and do not replace the row by hand.
Inaccessible or incomplete live process evidence is `unverifiable`: retain the
local seat and retry observation later. Never treat `ps` output, PID existence,
or a timeout as proof that a process or turn is gone.

### Work remains queued

Check active agents, queue timeout, configured seats, start spacing, owner
liveness, and recent provider-capacity failures. Do not raise limits until
authentication, quota, native evidence, and official-kernel health are known.

### Recovery states

#### Queued-owner cancellation

If a connector owner is proven gone or its PID is proven reused before dispatch,
startup recovery or the runtime reaper changes the queued request to
`cancelled` and removes its protected payload. No business prompt write
occurred, and the request does not occupy a seat.

#### `recovery_required`

If delivery or local process state is ambiguous, the request remains visibly
`recovery_required`. This is not reported as provider success, known provider
failure, or a completed turn.

#### Local seat release

A local seat is released only after the connector and child are proven gone or
their PIDs are proven reused and the expected process group is verifiably
empty. The request remains `recovery_required`; local resource reconciliation
does not claim a remote provider outcome.

#### No-replay guarantee

Admission never replays the original business prompt after ambiguous delivery.
There is no manual requeue or second-delivery path for `recovery_required`.
If an operator intentionally starts the work again, submit a new user request;
do not edit SQLite or reuse internal recovery state as a replay mechanism.

## Security boundary

Admission state can contain encrypted queued prompt material and process
identity evidence. Keep the directory owner-only, never commit it, and never
place it in the npm package. The repository secret scan and package-content
checks reject database and runtime artifacts from release tarballs.
