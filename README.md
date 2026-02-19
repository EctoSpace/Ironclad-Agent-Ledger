# Ironclad Agent Ledger

<p align="center">
  <img src="assets/logo.png" alt="Ironclad Logo" width="120" />
</p>

**A cryptographically verified, state-driven agent framework for Automated Security Auditing.**

Ironclad gives you an immutable ledger and a verify-then-commit loop so every agent action is hashed, validated, and recorded. The agent's state lives in PostgreSQL, and a **3-layer semantic guard** significantly reduces the attack surface for prompt injection and off-goal actions.

---

## The Philosophy

**The Agent is the Database.** The Rust process is a transient worker. All durable state — the event log and snapshots — lives in PostgreSQL. The binary has no long-term memory; it restores state from the ledger on each run.

**Verify Then Commit.** Proposed actions from the LLM are never trusted directly. A **3-Layer Semantic Guard** validates every intent before it is committed or executed:

1. **Ledger Goal Anchoring.** The session goal is hashed and stored at session creation (`goal_hash`); it is verified on every `append_event`. The agent's action log is its only source of truth — no mutable chat buffer that attackers can hijack. Each event is SHA-256-chained to the previous one; any tampered record is detected on startup.

2. **Guard Process (Dual-LLM).** A configurable secondary LLM (`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`) runs in a **separate process** (`guard-worker` binary), communicating over stdin/stdout JSON. It evaluates each proposed action against the stated goal and returns `ALLOW` or `DENY: <reason>`. In production, set `GUARD_REQUIRED=true` and use a different model (e.g. primary `anthropic`/`claude-3-5-sonnet`, guard `ollama`/`phi3`). Use `--no-guard` (with `--no-guard-confirmed`) to disable for development.

3. **Output Content Scanning (Layer A — Hybrid).** Execution observations go through two passes:
   - **Regex pass:** NFKC normalization, then 18 patterns covering injection phrases, Unicode homoglyphs, zero-width chars, LLM template tags, embedded action JSON, data/javascript URIs, role-injection, markdown code-fence JSON, base64-encoded JSON blobs, and prompt continuation markers.
   - **Structural JSON/AST pass:** a bracket-depth extraction + `serde_json` parse of every `{...}` candidate to detect action-shaped objects (`"action": "run_command"`, goal-hijacking keys like `system_prompt`/`new_goal`) that regex alone would miss. A further pass decodes `eyJ…` base64 candidates and re-runs the structural check. Suspicious content is redacted before being appended to the ledger. SSE streams are also redacted (paths, credentials, IPs) for the Observer.

In addition, a pure Rust **Tripwire** enforces structural rules:

- **Paths:** Component-level `..` rejection, path normalization without relying on `canonicalize()` for missing paths, and symlink-escape detection. Only paths under allowed directories (e.g. workspace) are permitted.
- **Networks:** Only allowlisted domains, HTTPS by default.
- **Commands:** A blocklist (e.g. `sudo`, `rm -rf`) blocks dangerous shell commands.
- **Justification:** Every non-complete action must include a justification of at least 5 characters; empty or missing justifications are rejected.

**Policy, evidence, and approvals.** An optional **policy file** (TOML) can enforce max steps, required checks, and allowed/forbidden actions; its hash is stored in the session. Findings can link to **evidence** (event sequence IDs and quotes), verified at session finish. **Approval gates** can pause the agent and require human accept/deny via the dashboard and `/api/approvals` endpoints. The policy DSL also supports **conditional command rules** (regex on arguments), **observation content rules** (redact/flag/abort on patterns), and **policy-driven approval gate triggers** (simple `action == 'x' && command_contains('y')` expressions).

Together these layers raise the bar for prompt injection without claiming unconditional immunity — no software defence is absolute. Intents that pass all checks are appended to the hash-chained PostgreSQL ledger and executed; nothing is ever updated or deleted.

---

## Architecture

The cognitive loop is a strict pipeline: **Perceive -> Propose -> Verify -> Commit -> Execute.**

```mermaid
flowchart LR
  Perceive[Perceive State]
  Propose[Propose Intent]
  Policy[Policy Engine]
  Guard[Guard Process]
  Tripwire[Tripwire]
  Commit[Commit to Ledger]
  Execute[Execute Side Effect]
  LLM[Primary LLM]
  DB[(PostgreSQL)]
  Host[Host]
  Perceive -->|restore from DB| Propose
  Propose -->|LLM JSON| LLM
  LLM --> Propose
  Propose --> Policy
  Policy --> Guard
  Guard --> Tripwire
  Tripwire -->|allowed only| Commit
  Commit -->|append_event goal_hash + sign| DB
  Commit --> Execute
  Execute -->|run/read/http| Host
  Execute -->|observation scanned| DB
```

1. **Perceive:** Restore agent state from the ledger (latest snapshot + replayed events).
2. **Propose:** Send state to the primary LLM; receive a single JSON intent (e.g. `run_command`, `read_file`, `http_get`, `complete`).
3. **Verify:** Policy engine (if `--policy` is set), then Guard process (separate binary), then Tripwire (paths, domains, commands, justification); reject or accept.
4. **Commit:** Verify goal hash, append the action to the ledger (hash-chained, optionally Ed25519-signed), then run the side effect.
5. **Execute:** Run the command, read the file, or perform the HTTP GET; scan observation; append to the ledger. Loop until the agent returns `complete` or `max_steps` is reached.

---

## Zero Friction Setup

Ironclad is **self-deploying**. You do not need to:

- Manually create a PostgreSQL database or run migrations.
- Configure a `.env` file (optional; defaults work out of the box).
- Run `sqlx migrate` or any CLI migration tool.

**What happens when you run the binary:**

- If `DATABASE_URL` is unset, the app defaults to `postgres://ironclad:ironclad@localhost:5432/ironclad`.
- It checks for a Docker container named `ironclad-postgres`. If missing or stopped, it starts one with the correct user, password, and database.
- It polls until PostgreSQL accepts connections, then runs migrations and creates the genesis block.
- If `OBSERVER_TOKEN` is unset, a random token is generated and printed with the dashboard URL; use it to access the Observer.
- For **audit**, the primary LLM (Ollama/OpenAI/Anthropic) must be reachable. If the Guard is enabled, the `guard-worker` binary (built with the project) is spawned and must have `GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL` set when `GUARD_REQUIRED=true`.

You can still set `DATABASE_URL` and `OBSERVER_TOKEN` (and optionally `.env`) to use your own Postgres and fixed auth.

---

## Usage

### Serve: dashboard only

Run the database, migrations, and the **Observer Dashboard** on port 3000. The agent is not started; the dashboard shows the current ledger (and will show new events if you run an audit in another process). If `OBSERVER_TOKEN` is unset, a one-time token is printed at startup — use it as `?token=...` or in the `Authorization` header.

```bash
cargo run -- serve
```

Then open **http://localhost:3000** to view the real-time Observer.

### Audit: run an audit with a prompt

Run a full audit with a required prompt. The Observer starts in the background; the cognitive loop runs with your instruction so the agent has a clear goal.

```bash
cargo run -- audit "Read server_config.txt"
```

With optional policy and guard control:

```bash
cargo run -- audit "Audit Cargo.toml dependencies" --policy audit_policy.toml
cargo run -- audit "Quick read" --no-guard --no-guard-confirmed   # development only
```

View the **Real Time Observer Dashboard** at **http://localhost:3000** while the audit runs. New ledger events (thoughts, actions, observations, approval gates) stream in via Server-Sent Events (content redacted for paths/credentials/IPs).

- **Prometheus metrics:** **http://localhost:3000/metrics**
- **Security metrics (JSON):** **http://localhost:3000/api/metrics/security** — injection attempts by layer (tripwire, guard), session aborts, chain verification failures.

### Report: export session to SARIF, JSON, or HTML

Generate an audit report with ledger hash and findings. Evidence-linked findings are included when present.

```bash
cargo run -- report <session_id> --format sarif --output report.sarif
cargo run -- report <session_id> --format html --output report.html
```

### Verify-session: verify Ed25519 event signatures

If the session was created with signing enabled, verify that every event’s `content_hash` signature matches the session key.

```bash
cargo run -- verify-session <session_id>
```

### Replay: replay a session (with optional injection)

Replay recorded events; useful for debugging and adversarial testing. Optionally inject observations at specific sequence positions.

```bash
cargo run -- replay <session_id>
cargo run -- replay <session_id> --inject-observation "seq=3:injected content"
```

### DiffAudit: compare two sessions

Produce a summary comparing baseline and current session (ledger hashes, finding counts). Output can be written to a file.

```bash
cargo run -- diff-audit --baseline <session_id> --current <session_id> [--output path]
```

### Orchestrate: multi-agent security audit

Runs three sequential sub-agents — **Recon → Analysis → Verify** — each in an independent ledger session with role-specific policy constraints. On completion, a `CrossLedgerSeal` event (`sha256(recon_tip || analysis_tip || verify_tip)`) is appended to every session, cryptographically binding them together.

```bash
cargo run -- orchestrate "Audit the Rust dependency tree for known vulnerabilities"
# With options:
cargo run -- orchestrate "Audit Nginx config" --policy shared_policy.toml --max-steps 25
```

Sub-agent roles:
- **Recon** — `read_file` + `run_command` only; `http_get` is forbidden.
- **Analysis** — receives Recon observations as goal context; `read_file` only; produces findings.
- **Verify** — receives Analysis findings; independently confirms each before completing.

After a run, generate per-session certificates:

```bash
cargo run -- report --format certificate --output audit-recon.iac <recon_session_id>
cargo run -- report --format certificate --output audit-analysis.iac <analysis_session_id>
cargo run -- report --format certificate --output audit-verify.iac <verify_session_id>
```

### Anchor-session: Bitcoin timestamp via OpenTimestamps

Submits the session ledger tip hash to the OpenTimestamps aggregator and appends an `Anchor` event with the raw OTS proof. The proof is pending Bitcoin confirmation until you upgrade it with the OTS toolchain.

```bash
cargo run -- anchor-session <session_id>
```

The `Anchor` event is appended to the ledger (cryptographic proof of submission). Once the aggregator commits to a Bitcoin block you can verify the timestamp with `ots upgrade <stamp>`.

### IronClad Audit Certificate (.iac)

Generate a self-contained, cryptographically verifiable audit record from a completed session:

```bash
cargo run -- report <session_id> --format certificate [--output audit.iac] [--no-ots]
```

Verify an existing certificate (five checks: Ed25519 signature, hash-chain, Merkle proofs, goal hash, OTS stamp):

```bash
cargo run -- verify-certificate audit.iac
# or use the standalone binary:
./target/release/verify-cert audit.iac
```

### Deferred commands — not yet implemented

- **red-team** `[Deferred]` — Adversarial agent to test the ledger's defences. Use `replay --inject-observation` for manual adversarial testing.
- **prove-audit** `[Deferred]` — ZK proof-of-audit (SNARK over the hash chain + policy commitment). The `.iac` certificate with Merkle proofs and OTS anchoring provides verifiable audit provenance in the interim.

### Enhanced Policy DSL

The TOML policy file supports four rule categories. All sections are optional.

```toml
name = "my-policy"
max_steps = 30

# 1. Allowed / forbidden action lists (existing)
[[allowed_actions]]
action = "read_file"

[[forbidden_actions]]
action = "http_get"

# 2. Conditional command rules (new) — evaluated in order; first match wins
[[command_rules]]
program = "curl"
arg_pattern = "^https://(internal\\.corp|api\\.example)\\.com"
decision = "allow"

[[command_rules]]
program = "curl"
arg_pattern = ".*"
decision = "deny"
reason = "curl only permitted to approved internal domains"

# 3. Observation content rules (new) — applied after each execution
[[observation_rules]]
pattern = "(?i)(password|secret|api.key)\\s*[:=]\\s*\\S+"
action = "redact"     # redact | flag | abort
label = "credential_leak"

# 4. Approval gate triggers (new) — policy-driven approval before execution
[[approval_gates]]
trigger = "action == 'run_command' && command_contains('nmap')"
require_approval = true
timeout_seconds = 300
on_timeout = "deny"
```

**`command_rules`** — Applied only to `run_command` actions. `program` matches the first token; `arg_pattern` is a regex over the remaining argument string. Decisions: `allow`, `deny`, `require_approval`.

**`observation_rules`** — Applied to the raw observation text after every tool execution. `redact` replaces matches with `[REDACTED:<label>]`; `flag` logs a warning but continues; `abort` terminates the session.

**`approval_gates`** — Simple boolean trigger expressions (`action == 'x'`, `command_contains('y')`, joined by `&&`). When triggered, an `ApprovalRequired` event is appended to the ledger and the agent waits for a human decision via `POST /api/approvals/<session_id>`.

### Environment variables (see `.env.example`)

- `DATABASE_URL` — PostgreSQL connection URL (defaults to local Docker `ironclad` DB if unset).
- `OBSERVER_TOKEN` — Optional. If unset, a random token is generated and printed at startup for the Observer.
- `OLLAMA_BASE_URL`, `OLLAMA_MODEL` — For Ollama backend.
- `LLM_BACKEND` — `ollama`, `openai`, or `anthropic`; default `ollama`.
- `GUARD_LLM_BACKEND`, `GUARD_LLM_MODEL` — Guard runs in a separate process (`guard-worker`); use a lighter model (e.g. `ollama`/`phi3`). Required when `GUARD_REQUIRED=true`.
- `GUARD_REQUIRED` — Set to `true` in production; startup fails if Guard env is missing. Default `false`.
- `AGENT_ALLOWED_DOMAINS` — Comma-separated domains for Tripwire `http_get`.
- `AGENT_MAX_STEPS` — Max loop iterations; default 20.
- `AGENT_LLM_ERROR_LIMIT`, `AGENT_GUARD_DENIAL_LIMIT` — Circuit breaker thresholds.
- `IRONCLAD_DATA_DIR` — Directory for encrypted session key files (default `.ironclad/keys/`). Set `IRONCLAD_KEY_PASSWORD` to skip the interactive password prompt.

### Running integration tests

Integration tests require a live Postgres instance. Use the bundled script (requires Docker):

```bash
./scripts/test-integration.sh
```

This spins up an ephemeral Postgres container on port 5433 via `docker-compose.test.yml`, runs `cargo test --features integration`, then tears the container down. Alternatively run against your own DB:

```bash
DATABASE_URL=postgres://... cargo test --features integration
```

---

## Prerequisites

- **Rust** (e.g. 1.70+; `rustup` recommended)
- **Docker** (for default Postgres when `DATABASE_URL` is not set)
- **Ollama** (for `audit` with default backend; must be running and will pull the model if missing). Alternatively use OpenAI or Anthropic via `LLM_BACKEND` and API keys.

---

## Project layout

- `assets/logo.png` — Project logo (README and Windows binary icon)
- `src/main.rs` — CLI entry: serve, audit, orchestrate, anchor-session, report, replay, verify-session, verify-certificate, diff-audit
- `src/orchestrator.rs` — Multi-agent orchestrator: Recon → Analysis → Verify with cross-ledger seal
- `src/ots.rs` — OpenTimestamps integration: submit SHA-256 digest to OTS aggregator pool
- `src/server.rs` — Axum server: GET `/` (Observer), GET `/api/stream` (SSE, redacted), GET `/api/metrics/security`, GET/POST `/api/approvals/...`
- `src/agent.rs` — Cognitive loop (perceive → propose → policy → guard → tripwire → commit → execute)
- `src/ledger.rs` — Append-only event log (hash chain, goal_hash, genesis, verify_findings, verify_session_signatures)
- `src/tripwire.rs` — Intent validation (strict path canonicalization, symlink escape, domains, commands, justification, policy violation)
- `src/guard.rs` — Guard trait; in-process fallback when guard process is disabled
- `src/guard_process.rs` — Spawns `guard-worker` and communicates via stdin/stdout JSON
- `src/bin/guard_worker.rs` — Standalone Guard binary (one JSON line in → ALLOW/DENY out)
- `src/policy.rs` — Policy-as-code (TOML): allowed/forbidden actions, command_rules (regex), observation_rules (redact/flag/abort), approval_gates (expression triggers)
- `src/certificate.rs` — IronClad Audit Certificate (.iac): Merkle tree, OTS, Ed25519 signing
- `src/merkle.rs` — Binary Merkle tree (SHA-256, odd-leaf duplication, inclusion proofs)
- `src/bin/verify_cert.rs` — Standalone 5-check certificate verifier binary
- `src/report.rs` — AuditReport, SARIF 2.1 and HTML export with ledger hash proof
- `src/approvals.rs` — Approval gates state and session pause/resume
- `src/signing.rs` — Ed25519 session keypair and per-event content_hash signing
- `src/sandbox.rs` — Linux Landlock child sandbox; production-ready main-process seccomp (Linux + `sandbox` feature); macOS warning stub
- `src/output_scanner.rs` — Layer A hybrid scanner: regex (18 patterns, NFKC) + structural JSON/AST analysis + base64-JSON detection
- `src/llm/` — LLM backends (Ollama, OpenAI, Anthropic)
- `src/executor.rs` — Run command / read file / HTTP GET
- `src/schema.rs` — Event types: Genesis, Thought, Action, Observation, ApprovalRequired, ApprovalDecision, CrossLedgerSeal, Anchor
- `migrations/` — SQL for `agent_events`, `agent_snapshots`, `agent_sessions` (goal_hash, policy_hash, session_public_key), `agent_event_signatures`, and related tables
- `audit_policy.example.toml` — Example policy file for `--policy`

---

## License

You may view and use the source code for personal or internal use, with attribution. You do **not** have permission to distribute, sublicense, or sell copies (or derivatives) without express written permission from the copyright holder. See [LICENSE](LICENSE).
