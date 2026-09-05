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
    aggressiveness: medium            # low | medium | high — see below
    maxScanBytes: 1048576
    breadthTier: true
    resultRedaction: true
    telemetryRedaction: true
    stepContextRedaction: true
    claimedInputRedaction: true
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

## Aggressiveness

One word for how far redaction reaches. It is not a tenth switch beside the nine toggles: the
level states what the deployment guarantees, the toggles state which passes carry it out, and the
two are not allowed to disagree.

| Level | What it guarantees |
|---|---|
| `low` | Nothing. Every pass is exactly its own toggle, which still defaults to `true`. This is the level to set when a pass has to be switched off. |
| `medium` (default) | Every pass this package ships is on, and no toggle can take one away. The user's own typing stays exempt. |
| `high` | `medium`, plus **the prompt the user typed themselves is scanned and redacted** like any other message. |

At `medium` and `high`, a toggle set to `false` contradicts the guarantee and **fails the mount**
rather than quietly losing:

```
dsh-dlp policy: aggressiveness: high requires every pass this package ships, but
resultRedaction is set to false. Set aggressiveness: low to choose passes individually,
or drop the false setting.
```

### When to set `high`

Set it when requests leave your network. This plugin cannot know where the model is: the provider
comes from the deployment's model selection, it can be any OpenAI-compatible base URL, and it can
change between turns. A card number a person types on purpose is still cardholder data at whatever
endpoint the request reaches, and "the user chose to" is not a defence a PCI assessor accepts on
that person's behalf.

Leave it at `medium` when the endpoint is one you control — a self-hosted model, an internal
gateway, a developer's own machine. At `high` a user who types a credential and then watches the
model reason about `[REDACTED:dsh-dlp:…]` has lost the turn, and that cost only buys something when
the request actually leaves.

What `high` does **not** change:

- tool arguments, which are never rewritten (they are already logged and presented to the user);
- the `agent/inbox/spliced` delivery record, which keeps every claimed message's original text —
  so the local session log on disk still holds what the user typed. Nothing derives a model
  message from that event, so nothing is sent anywhere, but a compliance boundary that includes
  the session file needs to know;
- the web client's queue view, which renders that same record, so a prompt still queued is shown
  as typed.

### Upgrading to 0.10.0

The default is `medium`, whose floor is exactly the nine toggle defaults, so **an install that
never wrote a toggle behaves identically to 0.9.0.**

**One class of install must change a line.** If your `cordis.yml` sets any of `breadthTier`,
`resultRedaction`, `telemetryRedaction`, `stepContextRedaction`, `claimedInputRedaction`,
`remoteImageNeutralization`, `redactTelemetryWorkspacePaths`, `configWriteAsk` or
`approvalSuppressionAsk` to `false`, the plugin now **refuses to mount** and `dsh` exits non-zero
with the message above. Add `aggressiveness: low` to that same row and the configuration means
exactly what it meant before. Stopping with an explanation is deliberate: the alternative was
switching a pass you turned off back on without telling you.

Nothing else changes on upgrade. `high` is opt-in and no default moves to it.

## Configuration trust ranking

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
enable: [telemetryRedaction, claimedInputRedaction, configWriteAsk, approvalSuppressionAsk]
```

**`aggressiveness` is not among them.** Every other tightening a workspace can ask for acts on
text the workspace does not own. Raising the level would act on the user's own words, replacing
pieces of their prompt on the strength of a detector with a measured false-positive rate, so the
repo-local tier gets no key for it and no `enable` entry that reaches it.

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
