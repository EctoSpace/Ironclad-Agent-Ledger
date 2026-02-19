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

1. **Ledger Goal Anchoring.** The session goal is embedded in every prompt. The agent's action log is its only source of truth — no mutable chat buffer that attackers can hijack. Each event is SHA-256-chained to the previous one; any tampered record is detected on startup.

2. **Dual-LLM Guard.** A configurable secondary LLM (`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`) evaluates each proposed action against the stated goal and returns `ALLOW` or `DENY: <reason>`. The Guard runs in complete environment isolation from the primary reasoning model.

3. **Output Content Scanning.** Execution observations are scanned for injection patterns (exfiltration URLs, embedded prompts, shell escape sequences). Suspicious content is redacted before being appended to the ledger.

In addition, a pure Rust **Tripwire** enforces structural rules:

- **Paths:** Only under allowed directories (e.g. workspace).
- **Networks:** Only allowlisted domains, HTTPS by default.
- **Commands:** A blocklist (e.g. `sudo`, `rm -rf`) blocks dangerous shell commands.
- **Justification:** Every non-complete action must include a justification of at least 5 characters; empty or missing justifications are rejected.

Together these layers raise the bar for prompt injection without claiming unconditional immunity — no software defence is absolute. Intents that pass all checks are appended to the hash-chained PostgreSQL ledger and executed; nothing is ever updated or deleted.

---

## Architecture

The cognitive loop is a strict pipeline: **Perceive -> Propose -> Verify -> Commit -> Execute.**

```mermaid
flowchart LR
  Perceive[Perceive State]
  Propose[Propose Intent]
  Verify[Verify Intent]
  Commit[Commit to Ledger]
  Execute[Execute Side Effect]
  Ollama[Ollama]
  Tripwire[Tripwire + Guard]
  DB[(PostgreSQL)]
  Host[Host]
  Perceive -->|restore from DB| Propose
  Propose -->|LLM JSON| Ollama
  Ollama --> Propose
  Propose --> Verify
  Verify --> Tripwire
  Tripwire -->|allowed only| Commit
  Commit -->|append_event| DB
  Commit --> Execute
  Execute -->|run/read/http| Host
  Execute -->|observation| DB
```

1. **Perceive:** Restore agent state from the ledger (latest snapshot + replayed events).
2. **Propose:** Send state to Ollama; receive a single JSON intent (e.g. `run_command`, `read_file`, `http_get`, `complete`).
3. **Verify:** Tripwire validates paths, domains, commands, and justification; Guard LLM checks goal alignment; reject or accept.
4. **Commit:** Append the action to the ledger (hash-chained), then run the side effect.
5. **Execute:** Run the command, read the file, or perform the HTTP GET; append the observation to the ledger. Loop until the agent returns `complete` or `max_steps` is reached.

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
- For **audit**, it ensures Ollama is reachable and pulls the configured model (e.g. `mistral`) in the background if needed.

You can still set `DATABASE_URL` (and optionally `.env`) to use your own Postgres and skip Docker.

---

## Usage

### Serve: dashboard only

Run the database, migrations, and the **Observer Dashboard** on port 3000. The agent is not started; the dashboard shows the current ledger (and will show new events if you run an audit in another process).

```bash
cargo run -- serve
```

Then open **http://localhost:3000** to view the real-time Observer.

### Audit: run an audit with a prompt

Run a full audit with a required prompt. The Observer starts in the background; the cognitive loop runs with your instruction (e.g. "Read server_config.txt") so the agent has a clear goal.

```bash
cargo run -- audit "Read server_config.txt"
```

View the **Real Time Observer Dashboard** at **http://localhost:3000** while the audit runs. New ledger events (thoughts, actions, observations) stream in via Server-Sent Events.

View the **Prometheus metrics** at **http://localhost:3000/metrics**.

Optional environment variables (see `.env.example`):

- `OLLAMA_BASE_URL` (default: `http://localhost:11434`)
- `OLLAMA_MODEL` (default: `mistral`)
- `LLM_BACKEND` (`ollama`, `openai`, or `anthropic`; default: `ollama`)
- `GUARD_LLM_BACKEND` (backend for the Guard LLM; defaults to `LLM_BACKEND`)
- `GUARD_LLM_MODEL` (model for the Guard LLM; defaults to primary model)
- `AGENT_ALLOWED_DOMAINS` (comma-separated; for Tripwire `http_get`)
- `AGENT_MAX_STEPS` (max loop iterations; no limit if unset)

---

## Prerequisites

- **Rust** (e.g. 1.70+; `rustup` recommended)
- **Docker** (for default Postgres when `DATABASE_URL` is not set)
- **Ollama** (for `audit`; must be running and will pull the model if missing)

---

## Project layout

- `assets/logo.png` — Project logo (README and Windows binary icon)
- `src/main.rs` — CLI entry (serve / audit)
- `src/server.rs` — Axum server: GET `/` (embedded HTML), GET `/api/stream` (SSE)
- `src/agent.rs` — Cognitive loop (perceive -> propose -> verify -> commit -> execute)
- `src/ledger.rs` — Append-only event log (hash chain, genesis)
- `src/tripwire.rs` — Intent validation (paths, domains, commands, justification)
- `src/guard.rs` — Dual-LLM Guard (secondary LLM goal alignment check)
- `src/sandbox.rs` — Linux Landlock sandbox for child processes
- `src/llm/` — LLM backends (Ollama, OpenAI, Anthropic)
- `src/executor.rs` — Run command / read file / HTTP GET
- `migrations/` — SQL for `agent_events`, `agent_snapshots`, and related tables

---

## License

MIT OR Apache-2.0
