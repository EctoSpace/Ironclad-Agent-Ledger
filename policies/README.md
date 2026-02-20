# Ironclad Policy Packs

Pre-configured `audit_policy.toml` files for common security and compliance standards.
Each pack is a valid policy file that can be passed directly to the `audit` command.

## Available packs

| File                   | Standard  | Focus                                               |
| ---------------------- | --------- | --------------------------------------------------- |
| `soc2-audit.toml`      | SOC 2     | Access management, logging, encryption at rest      |
| `pci-dss-audit.toml`   | PCI-DSS   | Cardholder data scope, network segmentation         |
| `owasp-top10.toml`     | OWASP Top 10 | Injection, broken auth, sensitive data exposure  |

## Usage

```bash
cargo run -- audit "Verify SOC2 controls on this server" \
  --policy policies/soc2-audit.toml

cargo run -- audit "Audit cardholder data environment" \
  --policy policies/pci-dss-audit.toml

cargo run -- audit "Check OWASP Top 10 vulnerabilities" \
  --policy policies/owasp-top10.toml
```

Or with a pre-built binary:

```bash
ironclad audit "Verify SOC2 controls" --policy policies/soc2-audit.toml
```

## Customising a pack

Copy the relevant file and adjust the sections:

- `name` / `goal` — describe your specific audit scope
- `max_steps` — raise or lower the step budget
- `required_checks` — list the controls the agent must verify
- `allowed_actions` / `forbidden_actions` — restrict the action surface
- `[[command_rules]]` — fine-grained command allow/deny with regex
- `[[observation_rules]]` — redact or flag sensitive patterns in output
- `[[approval_gates]]` — require human sign-off before high-risk steps
- `[[plugins]]` — integrate third-party security tools (Nessus, Metasploit, etc.)
