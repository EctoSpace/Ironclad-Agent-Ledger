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

With optional policy, guard control, cloud credentials, and interactive approvals:

```bash
cargo run -- audit "Audit Cargo.toml dependencies" --policy audit_policy.toml
cargo run -- audit "Quick read" --no-guard --no-guard-confirmed   # development only

# Cloud architecture audit with ephemeral AWS credentials:
AGENT_CLOUD_CREDS_FILE=~/.ironclad/aws-audit.json \
  cargo run -- audit "Audit the S3 bucket policy for public exposure" --policy cloud_policy.toml

# Terminal-native approval gates (no dashboard required):
cargo run -- audit "Run nmap scan" --policy gate_policy.toml --interactive
```

View the **Real Time Observer Dashboard** at **http://localhost:3000** while the audit runs. New ledger events (thoughts, actions, observations, approval gates) stream in via Server-Sent Events (content redacted for paths/credentials/IPs).

- **Prometheus metrics:** **http://localhost:3000/metrics**
- **Security metrics (JSON):** **http://localhost:3000/api/metrics/security** — injection attempts by layer (tripwire, guard), session aborts, chain verification failures.

### Report: export session to SARIF, JSON, or HTML

Generate an audit report with ledger hash and findings. Evidence-linked findings are included when present.

```bash
cargo run -- report <session_id> --format sarif --output report.sarif
cargo run -- report <session_id> --format html --output report.html
cargo run -- report <session_id> --format github_actions          # GitHub Actions annotation lines
cargo run -- report <session_id> --format gitlab_codequality --output codequality.json
```

Supported formats: `json` (default), `sarif` (SARIF 2.1), `html`, `certificate` (.iac), `github_actions` (GitHub Actions workflow annotations), `gitlab_codequality` (GitLab Code Quality JSON). The command exits with code 1 when any finding is `high` or `critical` severity, making it suitable as a CI gate.

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

Verify an existing certificate offline:

```bash
cargo run -- verify-certificate audit.iac
# or use the standalone binary:
./target/release/verify-cert audit.iac
```

The `verify-cert` binary is a static, dependency-free binary (&lt;5 MB) intended to be shipped to customers, auditors, or regulators — they run it without needing Rust, Postgres, or Ollama.

**Five Verification Pillars**

Every `.iac` file is verifiable offline against these five guarantees:

1. **Ed25519 signature** — tamper-resistance. The entire certificate payload is signed with the session Ed25519 keypair generated at audit start. The public key is embedded in the certificate itself; no trusted third party is needed to verify.
2. **SHA-256 hash chain** — gap and mutation detection. Every event is chained to the previous one using `sha256(previous_hash || sequence || payload_json)`. Any insertion, deletion, or modification anywhere in the chain is detected offline without replaying execution.
3. **Merkle inclusion proofs** — efficient finding spot-checks. Each finding carries a sibling-hash path to the Merkle root built over all event `content_hash` values. A verifier confirms a specific finding's evidence in O(log n) steps — no need to replay the full session.
4. **OpenTimestamps / Bitcoin anchor** — temporal non-repudiation. The ledger tip hash is submitted to the OTS aggregator pool and committed into a Bitcoin block. This proves the audit completed before block N, independently of the issuer, verifiable by anyone.
5. **Goal hash integrity** — session integrity. `sha256(goal)` is stored at session creation and re-verified on every event append during execution. The verifier re-derives it from the certificate and confirms the agent's goal was never redirected mid-session.

A sixth, optional proof is available when the certificate is generated with `prove-audit --features zk`: an **SP1 ZK validity proof** over the full hash chain and policy commitment. This proof lets a third party confirm policy compliance without access to the raw event payloads and can be independently verified with `sp1_sdk::ProverClient::verify`.

### Red-team: adversarial defense testing

Run an adversarial agent that loads a completed audit session, asks an LLM to generate injection payloads, and tests each candidate against the existing defense layers (output scanner + tripwire) in isolation. Exit code 1 when any payload passes all checks — integrate directly into CI.

```bash
cargo run -- red-team --target-session <session_id>
cargo run -- red-team --target-session <session_id> --attack-budget 100 --output red-team-report.json
```

The JSON report contains per-candidate results (`caught_by_scanner`, `caught_by_tripwire`, `passed_all`) and aggregate counts (`total`, `caught`, `passed_all`). For single-payload manual testing, use `replay --inject-observation` instead.

### Prove-audit: SP1 zero-knowledge proof

Generate a cryptographic SP1 ZK validity proof over the full event hash chain and policy commitment, then embed it in a `.iac` certificate. A verifier can confirm the agent followed its policy *without ever seeing the raw event payloads* — the right tool for regulated industries (healthcare, finance) where audited data cannot leave the client's perimeter.

Build with the `zk` feature to enable the SP1 prover, then run:

```bash
cargo build --features zk
cargo run --features zk -- prove-audit <session_id>
cargo run --features zk -- prove-audit <session_id> --policy crates/host/policies/soc2-audit.toml --output audit.iac
```

Proof time scales with event count and available hardware. The embedded proof can be independently verified with `sp1_sdk::ProverClient::verify`. Without the `zk` feature, the command prints a helpful error with recompile instructions rather than silently skipping.

For all other use cases the standard `.iac` certificate (five-pillar verification) already provides cryptographically verifiable audit provenance without the proof generation overhead.

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

**`approval_gates`** — Simple boolean trigger expressions (`action == 'x'`, `command_contains('y')`, joined by `&&`). When triggered, an `ApprovalRequired` event is appended to the ledger and the agent waits for a human decision via `POST /api/approvals/<session_id>` (dashboard) or stdin (`--interactive`).

### Plugin system — third-party security tools

Register external security tools in the policy file to extend the executor allowlist and forward environment variables into the tool process only:

```toml
# audit_policy.toml

[[plugins]]
name = "trivy"
binary = "trivy"
description = "Container and filesystem vulnerability scanner"
# Only these argument patterns are permitted (regex over the full arg string).
arg_patterns = ["^image\\s+\\S+", "^fs\\s+\\."]
# Host env vars forwarded into the trivy child process only (never to other tools).
env_passthrough = ["TRIVY_USERNAME", "TRIVY_PASSWORD"]

[[plugins]]
name = "semgrep"
binary = "semgrep"
description = "Static analysis tool"
arg_patterns = ["^--config\\s+\\S+\\s+\\."]
env_passthrough = []
```

Plugin binaries are added to the executor allowlist only when declared here. `arg_patterns` act as a whitelist over the argument string; an empty list allows any arguments. `env_passthrough` names are taken from the host environment and injected into the plugin child process only — the parent process environment is never modified.

### Industry policy packs

Pre-configured policies for common security and compliance standards live in the `policies/` directory. Each file is a valid `audit_policy.toml` that can be passed directly to `--policy`:

| File | Standard | Focus |
|------|----------|-------|
| `crates/host/policies/soc2-audit.toml` | SOC 2 | Access management, logging, encryption at rest |
| `crates/host/policies/pci-dss-audit.toml` | PCI-DSS v4.0 | Cardholder data scope, network segmentation |
| `crates/host/policies/owasp-top10.toml` | OWASP Top 10 2021 | Injection, auth, crypto, SSRF, misconfiguration |

```bash
# SOC 2 audit
cargo run -- audit "Audit SOC2 controls" --policy crates/host/policies/soc2-audit.toml

# PCI-DSS audit
cargo run -- audit "Audit cardholder data environment" --policy crates/host/policies/pci-dss-audit.toml

# OWASP Top 10
cargo run -- audit "Audit web app for OWASP Top 10" --policy crates/host/policies/owasp-top10.toml
```

All three packs use the extended policy predicates — `path_extension_matches`, `url_host_in_cidr`, and `command_matches_regex` — in their approval gates and command rules. See `crates/host/policies/README.md` for customisation guidance.

The policy DSL now supports three additional trigger predicates for `[[approval_gates]]`:

| Predicate | Example | Description |
|-----------|---------|-------------|
| `path_extension_matches(ext)` | `path_extension_matches('.key')` | Matches `read_file` paths by extension or regex |
| `url_host_in_cidr(cidr)` | `url_host_in_cidr('10.0.0.0/8')` | Matches `http_get` when URL host IP falls in CIDR |
| `command_matches_regex(pattern)` | `command_matches_regex('^nmap\\s')` | Full command string must match regex |

These predicates can be joined with `&&` alongside the existing `action == 'x'` and `command_contains('y')` predicates.

### Cloud credential injection

Safely audit AWS, GCP, Azure, or Kubernetes environments by supplying short-lived credentials in a JSON file. The file path is read from `AGENT_CLOUD_CREDS_FILE`; credentials are injected only into matching cloud CLI child processes and never appear in the parent environment or audit logs.

**Credential file format (`~/.ironclad/aws-audit.json`):**

```json
{
  "name": "aws-audit-role",
  "provider": "aws",
  "env_vars": {
    "AWS_ACCESS_KEY_ID": "ASIA...",
    "AWS_SECRET_ACCESS_KEY": "...",
    "AWS_SESSION_TOKEN": "..."
  }
}
```

Supported provider binaries (added to allowlist only when creds are present): `aws`, `gcloud`, `az`, `kubectl`, `terraform`, `eksctl`, `helm`.

The credential set `name` and `provider` are recorded as an auditable `Thought` event at session start. Credential values are never logged.

### Terminal-native interactive approval gates

By default, approval gates require a human decision via the Observer dashboard REST API. The `--interactive` flag enables stdin-based approvals — useful for local runs or CI pipelines without a running dashboard:

```
[APPROVAL REQUIRED]
  Action : run_command
  Params : {"command":"nmap -sV 192.168.1.0/24"}
Approve? [y/N] (auto-deny in 300s):
```

Unanswered prompts apply the `on_timeout` policy (`deny` by default). The approval source (`operator:cli` or `operator:api`) is recorded in the `ApprovalDecision` ledger event for auditing.

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
- `AGENT_CLOUD_CREDS_FILE` — Path to a JSON file with cloud credentials (`name`, `provider`, `env_vars`). When set, cloud CLI binaries (`aws`, `gcloud`, `az`, `kubectl`, `terraform`, `eksctl`, `helm`) are added to the executor allowlist and credentials injected into matching child processes only.
- `WEBHOOK_URL` — Optional. HTTP endpoint for async SIEM/webhook egress on flagged/abort policy outcomes.
- `WEBHOOK_BEARER_TOKEN` — Optional bearer token for webhook egress.
- `SIEM_FORMAT` — Webhook egress format: `json` (default), `cef`, or `leef`.

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

The project is a Cargo workspace with three crates:

**`crates/core/`** — Pure logic with no I/O; shared by the host and the SP1 zkVM guest.
- `crates/core/src/hash.rs` — SHA-256 helpers (`sha256_hex`, `compute_content_hash`, `GENESIS_PREVIOUS_HASH`)
- `crates/core/src/merkle.rs` — Binary Merkle tree (SHA-256, odd-leaf duplication, inclusion proofs)
- `crates/core/src/intent.rs` — `ProposedIntent` and `ValidatedIntent` types
- `crates/core/src/policy.rs` — `PolicyEngine`, all policy structs, `policy_hash_bytes`
- `crates/core/src/schema.rs` — SP1 zkVM guest/host protocol types: `ChainEvent`, `GuestInput`, `GuestOutput` (bincode-serializable)

**`crates/guest/`** — SP1 RISC-V zkVM guest program (compiled separately with `--features zk`).
- `crates/guest/src/main.rs` — Reads `GuestInput`, verifies genesis hash, full hash chain, Merkle root, and policy patterns; panics on any failure; commits `GuestOutput` to SP1 public values.

**`crates/host/`** — Full application (`ironclad-agent-ledger` binary, `guard-worker`, `verify-cert`).
- `assets/logo.png` — Project logo (README and Windows binary icon)
- `crates/host/src/main.rs` — CLI entry: serve, audit, orchestrate, anchor-session, report, replay, verify-session, verify-certificate, diff-audit, red-team, prove-audit
- `crates/host/src/orchestrator.rs` — Multi-agent orchestrator: Recon → Analysis → Verify with cross-ledger seal
- `crates/host/src/ots.rs` — OpenTimestamps integration: submit SHA-256 digest to OTS aggregator pool
- `crates/host/src/server.rs` — Axum server: GET `/` (Observer), GET `/api/stream` (SSE, redacted), GET `/api/metrics/security`, GET/POST `/api/approvals/...`
- `crates/host/src/agent.rs` — Cognitive loop (perceive → propose → policy → guard → tripwire → commit → execute)
- `crates/host/src/ledger.rs` — Append-only event log (hash chain, goal_hash, genesis, verify_findings, verify_session_signatures)
- `crates/host/src/tripwire.rs` — Intent validation (strict path canonicalization, symlink escape, domains, commands, justification, policy violation)
- `crates/host/src/guard.rs` — Guard trait; in-process fallback when guard process is disabled
- `crates/host/src/guard_process.rs` — Spawns `guard-worker` and communicates via stdin/stdout JSON
- `crates/host/src/bin/guard_worker.rs` — Standalone Guard binary (one JSON line in → ALLOW/DENY out)
- `crates/host/src/cloud_creds.rs` — Ephemeral cloud credential injection: `CloudCredentialSet` loaded from `AGENT_CLOUD_CREDS_FILE`; injected into matching child processes only
- `crates/host/src/policy.rs` — Thin wrapper over `ironclad_core::policy`; adds `load_policy_engine()` for host I/O
- `crates/host/src/certificate.rs` — IronClad Audit Certificate (.iac): Merkle tree, OTS, Ed25519 signing, optional SP1 ZK proof embedding
- `crates/host/src/bin/verify_cert.rs` — Standalone 5-check certificate verifier binary
- `crates/host/src/report.rs` — AuditReport; SARIF 2.1, HTML, GitHub Actions annotations, GitLab Code Quality JSON, and certificate export
- `crates/host/src/red_team.rs` — Adversarial agent: generates injection payloads via LLM and tests them against output scanner and tripwire
- `crates/host/src/approvals.rs` — Approval gates state and session pause/resume
- `crates/host/src/signing.rs` — Ed25519 session keypair and per-event content_hash signing
- `crates/host/src/sandbox.rs` — Linux Landlock + production seccomp (main process + guard worker); macOS `sandbox_init` Seatbelt FFI (deny network, read-only workspace); Windows Job Object with `KILL_ON_JOB_CLOSE` and full UI restrictions
- `crates/host/src/webhook.rs` — Async webhook/SIEM egress dispatcher (JSON / CEF / LEEF); fire-and-forget HTTP POST on Flagged/Abort policy outcomes
- `crates/host/src/output_scanner.rs` — Layer A hybrid scanner: regex (18 patterns, NFKC) + structural JSON/AST analysis + base64-JSON detection
- `crates/host/src/llm/` — LLM backends (Ollama, OpenAI, Anthropic)
- `crates/host/src/executor.rs` — Run command / read file / HTTP GET
- `crates/host/src/schema.rs` — Event types: Genesis, Thought, Action, Observation, ApprovalRequired, ApprovalDecision, CrossLedgerSeal, Anchor
- `crates/host/migrations/` — SQL for `agent_events`, `agent_snapshots`, `agent_sessions` (goal_hash, policy_hash, session_public_key), `agent_event_signatures`, and related tables
- `crates/host/policies/` — Industry policy packs (SOC 2, PCI-DSS, OWASP Top 10)
- `audit_policy.example.toml` — Example policy file for `--policy`

---

## Commercial Licensing

Apache 2.0 for personal/internal/research/open-source use.  
Commercial redistribution or enterprise support requires a paid license — see [COMMERCIAL.md](COMMERCIAL.md) and contact bironclad@pm.me.
