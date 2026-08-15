# dsh-dlp

Data-loss prevention for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness),
built as an out-of-repo plugin.

It does four things:

1. **Denies credential-file access and secrets bound for the network** — unconditionally, from
   `ctx.tools.guard()`.
2. **Redacts secrets out of tool results** before the model reads them and before the session
   log records them.
3. **Redacts secrets out of exported telemetry**, patching a hole where `DSH_TELEMETRY_MODE=FULL`
   ships message text, tool arguments, tool results and workspace paths in the clear.
4. **Writes an audit record for every decision** to its own sink — rule id, rule version,
   offsets, and a keyed hash. Never the secret.

---

## What this is not

**This is not a containment boundary.** The plugin runs in-process, in the agent's own process,
at the agent's own uid. Anything the agent can execute — a `bash` command, a `run_code`
program, a mounted MCP server — can read every file the guard denies and can open its own
sockets without the plugin seeing anything. The guard closes the path where *the model* asks
for credential material through a tool. It does not stop code that is already running.

If you need containment, that is the sandbox, `landlock-run`, filesystem permissions, and
egress firewalling. Use this alongside them, not instead of them.

Three more limits worth stating up front:

- **Tool arguments are never masked.** Model-visible implies logged: arguments are already in
  the session log and already presented to the model, so rewriting them would desynchronise
  the log from what actually ran. Argument-level DLP here is *denial with a reason the model
  can act on*.
- **Outbound prompts cannot be rewritten.** `llm/stream` options are deep-frozen and `next()`
  takes no arguments. A secret already in the conversation reaches the provider.
- **Detection is pattern-based.** A password, an internal token format, or a customer record
  has no recognisable structure and is not detected.

The full list is in [PLAN.md §8](PLAN.md).

---

## Install

```sh
dsh plugin --profile <name> add dsh-dlp
```

The package ships a `cordis.patch.yml` bundle layer, so listing it in a profile's
`dsh.profile.bundles` is enough to mount it with working defaults.

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
    redactTelemetryWorkspacePaths: true
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
enable: [telemetryRedaction]
```

Any other key, and any downgrade, is a **load-time error**. There is no `disable`, no
`removeCredentialPaths`, and no way to redirect the audit sink. The file is parsed with
`js-yaml` under `JSON_SCHEMA`, so a `!!js/function` tag is a parse error rather than code
execution, and it never goes near the Cordis loader.

---

## What gets denied

**Credential paths**, for every tool: `.env` (but not `.env.example`), anything under `.ssh/`,
`id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`, `~/.aws/credentials`, `$DSH_HOME/.credentials.yaml`,
`.netrc`, `.npmrc`, `.pypirc`, `~/.kube/config`, `~/.docker/config.json`, gcloud credential
files, and `*.pem`/`*.p12`/`*.pfx`/`*.jks`/`*.keystore`. Paths are normalised first, so `..`
traversal, `~`, Windows separators and quoting do not evade the table; a shell command is also
split into tokens, so `cat ~/.ssh/id_rsa && echo ok` matches.

`$DSH_HOME/.credentials.yaml` is on that list because core permits reading it. The harness has
no file-read restriction in any mode — reads pass through untouched in every permission mode —
so the provider token the agent authenticates with is agent-readable. That is the specific gap
this plugin closes.

**Secrets in arguments**, for tools that can move data off the machine. Local tools (`read`,
`glob`, `grep`, `write`, `edit`, `todo_write`, the session-query tools, …) are exempt.
Everything else — every shell, `run_code`, the web tools, every `mcp__*` tool, and any tool
this build has never heard of — is treated as egress-capable. Unknown defaults to the safe side.

A denial reads like this, and reaches the model as the tool's error result:

```
dsh-dlp denied "read": "/home/dev/.aws/credentials" is credential material (rule
dsh-dlp/path-aws). Reading or passing credential files through a tool is blocked by policy
and cannot be overridden. Ask the user to supply the value you need, or use a path that is
not a credential store.
```

---

## What gets redacted

A redacted region becomes:

```
[REDACTED:dsh-dlp:slack-token:ca9cad27f2b5]
```

The hash is `HMAC-SHA256(installation key, replaced text)` truncated to 12 hex characters. It
is **stable**: the same secret produces the same placeholder everywhere, so an operator can see
that one token appeared in four different tool results without the plugin ever writing the
token down.

For a successful tool result the plugin replaces the canonical `value`, which makes the registry
re-validate the tool's `output.schema`, re-run `output.render()` and re-derive
`presentationMeta()` — so the value, the model-facing content and the persisted card are all
redacted from one replacement. For a failed result it replaces `content` instead, because
replacing the value of a failed result throws. On that arm the canonical value keeps the
original text: content replacement is presentation policy, not confidentiality policy.

Replacement runs before the `tool/result` session event is appended, so the durable log records
the redacted copy.

## Detection

Two tiers:

- **Tier 1**, synchronous and owned by this package: prefix-anchored token formats (AWS,
  GitHub, Slack, Stripe, OpenAI, Anthropic, Google, npm), PEM private-key blocks, JWTs,
  credential-bearing URLs, and high-signal secret assignments. This is the tier the guard and
  the telemetry listener use, because both of those seams are synchronous.
- **Tier 2**, [`@secretlint/core`](https://github.com/secretlint/secretlint) with the
  recommended preset — 28 maintained rules, in-process, no subprocess. Used at
  `tools/pre-execute` and `tools/post-execute`, the two seams that can await.

Measured cost of a tier-2 scan: 0.78 ms at 1 KB, 0.91 ms at 16 KB, 2.22 ms at 128 KB, 5.11 ms
at 512 KB. `maxScanBytes` caps it; input past the cap is scanned by tier 1 only and the audit
record says `truncatedScan: true`.

---

## Audit output

One JSON object per line in `auditLog`. Nothing is ever written to the session log: the
harness's `Session.append()` cannot set the envelope's `ignorable` flag, and an out-of-repo
event type makes the user's next resume refuse the whole session. Each record therefore carries
its own identity.

```json
{
  "v": 1,
  "time": "2026-08-15T19:44:33.861Z",
  "kind": "result-redaction",
  "decisionId": "dlp-1e8ab1bb-5c8d-4410-b98d-39b83037ea63",
  "tool": "read",
  "callId": "mock-call-1",
  "rootCallId": "mock-call-1",
  "sessionId": "session-880b9ece-3633-427d-b0a8-cf202ea09917",
  "turn": 1,
  "step": 1,
  "spans": [
    {
      "ruleId": "dsh-dlp/slack-token",
      "ruleVersion": 1,
      "severity": "critical",
      "start": 17,
      "end": 73,
      "hash": "ca9cad27f2b5",
      "path": "/lines/1/text"
    }
  ]
}
```

`kind` is one of `guard-deny`, `pre-execute-deny`, `result-redaction`, `telemetry-redaction`.
An audit write failure is logged and swallowed rather than turned into a denial: the sink is
evidence, not enforcement, and a full disk should not take the agent down.

---

## Development

```sh
. ../env.sh          # Node 22.23.2 + pnpm 11.7.0
pnpm install
pnpm run typecheck
pnpm run test        # unit
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

`DSH_REPO` points the E2E harness at a harness checkout (default
`../dsh`); it needs `pnpm run build:lib:host` to have run there at least once.
