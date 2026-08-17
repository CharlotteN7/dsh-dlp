---
title: Configuration
nav_order: 3
---

# Configuration

[← dsh-dlp docs](index.md)

## Configure

```yaml
- id: dsh-dlp
  name: 'dsh-dlp'
  config:
    auditLog: /var/log/dsh-dlp.audit.jsonl
    redactionKeyFile: /var/lib/dsh/dsh-dlp.redaction-key
    policyFile: ./.dsh-dlp.yml        # optional, lowest trust — see below
    maxScanBytes: 1048576
    breadthTier: true
    resultRedaction: true
    telemetryRedaction: true
    remoteImageNeutralization: true
    redactTelemetryWorkspacePaths: true
    configWriteAsk: true
    approvalSuppressionAsk: true
```

`redactionKeyFile` is created on first mount with 32 random bytes at mode `0600`. Keep it out
of version control: it is what makes a placeholder's hash keyed rather than a bare digest that
anyone holding a candidate secret could confirm.

**The guard floor has no configuration.** Credential-path denial and secret-argument denial are
security invariants, not deployment-varying tunables, so there is no switch that turns them off.

### Configuration trust ranking

| Rank | Source | May |
|---|---|---|
| 1 | invariants compiled into the package | everything; not configurable |
| 2 | `cordis.yml` / bundle patch config | set every field |
| 3 | `policyFile` — a repo-local YAML file | **tighten only** |

Rank 3 is attacker-controlled — a hostile repository ships one, and a prompt-injected agent can
write one — so it may only add deny patterns, add egress-capable tool names, raise a severity,
and switch a redaction pass on:

```yaml
v: 1
addCredentialPaths:
  - id: acme/vault-token
    pattern: '(^|/)\.vault-token$'
addEgressTools: [acme_publish]
raiseSeverity:
  dsh-dlp/secret-assignment: high
enable: [telemetryRedaction, configWriteAsk, approvalSuppressionAsk]
```

Any other key, and any downgrade, makes the **whole file invalid**: it is reported on
`process.stderr` and the deployment's logger, then ignored, never obeyed in part. There is no
`disable`, no `removeCredentialPaths`, and no way to redirect the audit sink. The file is
parsed with `js-yaml` under `JSON_SCHEMA`, so a `!!js/function` tag is a parse error rather
than code execution, and it never goes near the Cordis loader.

A missing `policyFile` is not an error — it means the workspace ships no policy. The
recommended value is workspace-relative, so failing the mount would stop `dsh` from starting in
every repository without one, and would let a hostile repository remove the floor by shipping a
broken file. An added `pattern` is capped at 200 characters and rejected if it nests a
quantifier inside a quantified group: `^(a+)+$` blocks the synchronous guard for seconds on a
27-character path. That check is a heuristic, not a proof of linear-time matching.

---
