# dsh-dlp

Data-loss prevention for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness),
built as an out-of-repo plugin.

It does four things:

1. **Denies credential-file access and secrets bound for the network** — unconditionally, from
   `ctx.tools.guard()`. It tests the path-typed arguments of a call against a table of
   credential stores, following symlinks first.
2. **Redacts secrets out of tool results** before the model reads them and before the session
   log records them, and withholds a result it cannot clean.
3. **Redacts secrets out of exported telemetry**, patching a hole where `DSH_TELEMETRY_MODE=FULL`
   ships message text, tool arguments, tool results and workspace paths in the clear.
4. **Writes an audit record for every decision** to its own sink — rule id, rule version,
   offsets, and a keyed hash. Never the secret, and never the path or command that matched.

---

## What this is not

**This is not a containment boundary.** The plugin runs in-process, in the agent's own process,
at the agent's own uid. Anything the agent can execute — a `bash` command, a `run_code`
program, a mounted MCP server — can read every file the guard denies and can open its own
sockets without the plugin seeing anything. The guard closes the path where *the model* asks
for credential material through a tool. It does not stop code that is already running.

If you need containment, that is the sandbox, `landlock-run`, filesystem permissions, and
egress firewalling. Use this alongside them, not instead of them.

More limits worth stating up front:

- **The shell-command arm is advisory pattern-matching.** A `bash` command line is split on
  shell-ish separators and each token is tested as a path. That catches an unobfuscated
  `cat ~/.ssh/id_rsa`. It catches nothing that tries: `cat ~/.netr?` (one glob character),
  `cat ~/.s""sh/id_r""sa`, `find ~ -name 'id_*' -exec cat {} +`, a `$(printf ...)`
  reassembly, a base64 round-trip of the path, or `python3 -c` opening the file — every one
  of those was verified to read the file with the guard abstaining. **Do not count this arm
  as a control.** A shell command is a program, not a path, and the only way to decide what
  it will open is to run it. If the agent has a shell, credential files need filesystem
  permissions or a sandbox, not this plugin.
- **Tool arguments are never masked.** Model-visible implies logged: arguments are already in
  the session log and already presented to the model, so rewriting them would desynchronise
  the log from what actually ran. Argument-level DLP here is *denial with a reason the model
  can act on*.
- **Outbound prompts cannot be rewritten.** `llm/stream` options are deep-frozen and `next()`
  takes no arguments. A secret already in the conversation reaches the provider.
- **Detection is pattern-based.** A password, an internal token format, or a customer record
  has no recognisable structure and is not detected. Neither is any encoded form: base64,
  hex, URL-escaping and reversal all pass both tiers, as does a secret split across two
  content blocks.

The full list is in [PLAN.md §8](PLAN.md).

---

## Install

A profile carrying only `@deepseek-ai/dsh-base` has no agent loop. Add a runnable
bundle alongside it, or the profile boots with nothing for this plugin to guard:

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-dlp
dsh --profile <name> --dump-config      # the dsh-dlp row should appear
```

Pin `@deepseek-ai/dsh-headless` explicitly: its npm `latest` tag still points at
`0.0.1-rc.1`, so an unpinned install silently resolves to a much older harness.

The package ships a `cordis.patch.yml` bundle layer, so listing it in a profile's
`dsh.profile.bundles` is enough to mount it with working defaults.

**Install from the registry or a packed tarball, not from a git spec.**
`dsh plugin add github:CharlotteN7/dsh-dlp` resolves and writes the dependency,
but `lib/` is a build output that git does not carry and no `prepare` script
rebuilds it, so the row mounts and then fails to load. To install from a
checkout, build first and add the tarball:

```sh
git clone https://github.com/CharlotteN7/dsh-dlp && cd dsh-dlp
pnpm install && pnpm run build && pnpm pack
dsh plugin --profile <name> add ./dsh-dlp-0.1.0.tgz
```

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

Any other key, and any downgrade, makes the **whole file invalid**: it is logged on the
deployment's logger and ignored, never obeyed in part. There is no `disable`, no
`removeCredentialPaths`, and no way to redirect the audit sink. The file is parsed with
`js-yaml` under `JSON_SCHEMA`, so a `!!js/function` tag is a parse error rather than code
execution, and it never goes near the Cordis loader.

A missing `policyFile` is not an error — it means the workspace ships no policy. The
recommended value is workspace-relative, so failing the mount would stop `dsh` from starting in
every repository without one, and would let a hostile repository remove the floor by shipping a
broken file. An added `pattern` is capped at 200 characters and rejected if it nests a
quantifier inside a quantified group: `^(a+)+$` blocks the synchronous guard for seconds on a
27-character path. That check is a heuristic, not a proof of linear-time matching.

---

## What gets denied

**Credential paths named in a path-typed argument**, for every tool: `.env` and `.env.*`
directories (but not `.env.example`), anything under `.ssh/`,
`id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa` and their backups, `~/.aws/` and `~/.azure/`,
`$DSH_HOME/.credentials.yaml`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`,
`~/.config/gh/`, `~/.kube/` and `kubeconfig*`, `/etc/kubernetes/*.conf`,
`~/.docker/config.json` and `.dockercfg`, gcloud credential files, `rclone.conf`, `.pgpass`,
`.my.cnf`, `*service-account*.json`, `*.pem`/`*.p12`/`*.pfx`/`*.jks`/`*.keystore`/`*.key`/
`*.asc`/`*.gpg`, and any file whose name ends in a delimited `credential(s)`, `secret(s)` or
`token(s)` — which covers `.vault-token`, `.gem/credentials`, `.cargo/credentials.toml`,
`.terraform.d/credentials.tfrc.json` and a Kubernetes service-account `token`. Source and
documentation extensions are excluded from that last rule, so `src/auth/token.ts` stays
readable.

Also denied for every tool: this plugin's own `redactionKeyFile` and `auditLog`.

**`$DSH_HOME` is split by direction.** Every *write* under the harness home is denied, for
every tool: editing a profile's `cordis.yml` mounts an arbitrary plugin, which is the exact
threat that makes the directory worth protecting. *Reads* are denied only where the contents
are credentials — `$DSH_HOME/.credentials.yaml`, `$DSH_HOME/sessions/**`, `$DSH_HOME/.env`,
this plugin's key file and audit log, and any `*.key` — so the installed plugin tree under
`profiles/node_modules/` and every profile manifest stay readable. A blanket read denial there
made debugging a plugin, reading a profile, and running the sibling `dsh-plugin-inspector`
against an installed tree impossible, with a message saying the denial could not be overridden.

Which side of that split a call lands on is decided by the tool's name, from a table of tools
that can only look: `read`, `read_image`, `glob`, `grep`, `lsp`, the session-query tools,
`job_list`, `job_output`, `terminal_list`, `terminal_read`, `list_agents`, `get_goal`.
Every other name — every shell, every editor, every `mcp__*` tool, and any tool this build has
never heard of — is treated as able to write, so a new tool is denied until it is classified.
A shell is never on the read side even for a command that only reads: a shell that can `cat` a
profile can also rewrite it.

Paths are normalised first — `..` traversal, `~`, Windows separators, quoting and a trailing
slash do not evade the table — and then resolved with `realpathSync`, so a symlink named
`notes.txt` pointing at `~/.ssh/id_rsa` is denied by what it resolves to. Only path-typed
argument keys are tested (`file_path`, `path`, `paths`, `notebook_path`, `cwd`, `command`, …).
File content is never treated as a path: writing a `.gitignore` that lists `.env` is ordinary
work, not an attempt to read a credential store.

`$DSH_HOME/.credentials.yaml` is on that list because core permits reading it. The harness has
no file-read restriction in any mode — reads pass through untouched in every permission mode —
so the provider token the agent authenticates with is agent-readable. That is the specific gap
this plugin closes.

**Some secrets in arguments**, for tools that can move data off the machine. Local tools
(`read`, `glob`, `grep`, `write`, `edit`, `todo_write`, the session-query tools, …) are exempt.
Everything else — every shell, `run_code`, the web tools, every `mcp__*` tool, and any tool
this build has never heard of — is treated as egress-capable. Unknown defaults to the safe side.

What this arm actually catches is a whole, unencoded secret of `high` severity or above sitting
in one argument string. `A=ghp_firsthalf; B=…; curl -H "Bearer $A$B"`, a base64 round-trip, and
`$(cat ~/.token)` all defeat it; a `password=` assignment is `medium` and is redacted rather
than denied. Treat it as a guard against accident, not against an adversary.

A denial reads like this, and reaches the model as the tool's error result. It names the rule
and a keyed hash, never the path — a path is itself sensitive, and this string is written to
the model and, in hashed form, to the audit sink:

```
dsh-dlp denied "read": one of its path arguments is credential material (rule
dsh-dlp/path-aws, keyed hash ca9cad27f2b5). Reading or passing credential files through a
tool is blocked by policy and cannot be overridden. Ask the user to supply the value you
need, or use a path that is not a credential store.
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
redacted from one replacement. That arm is not a preference: the alternative, replacing
`content`, leaves `{...result}` in place, and `value` and `meta` go into the session log
exactly as the tool produced them. A successful result therefore never settles for the content
arm, which is used only for a failed result (where replacing the value throws) or where the
persisted surfaces are already clean.

When neither works — a failed result whose `meta` carries a secret, or a value that still scans
dirty after redaction — the result is **withheld**: the plugin returns a `block` decision, the
model gets an error naming the rule and the hash, and nothing dirty reaches the log. Blocking
is the only decision that replaces the whole result, so it is the only way to drop `meta`.

Two consequences worth knowing:

- Replacing a value re-validates it against the tool's `output.schema`. A schema that
  constrains that string (a length, a pattern, an enum) rejects the placeholder and the call
  fails with a `ToolOutputError`. A failed call is the intended outcome; the alternative is
  writing the secret to the log.
- Redaction is per-detection, and each span grows to the nearest delimiter — whitespace,
  quotes, `=`, `:`, `,`, brackets. A line of minified JSON loses the field that matched, not
  the whole line.

Replacement runs before the `tool/result` session event is appended, so the durable log records
the redacted copy.

## Detection

Two tiers:

- **Tier 1**, synchronous and owned by this package: prefix-anchored token formats (AWS,
  GitHub, Slack, Stripe, OpenAI, Anthropic, Google, npm), PEM private-key blocks, JWTs,
  credential-bearing URLs, Slack/Discord/Teams webhook URLs, and high-signal secret
  assignments. This is the tier the guard and the telemetry listener use, because both of
  those seams are synchronous, and it is never capped.
- **Tier 2**, [`@secretlint/core`](https://github.com/secretlint/secretlint) with the
  recommended preset — 28 maintained rules, in-process, no subprocess. Used at
  `tools/pre-execute` and `tools/post-execute`, the two seams that can await. **The telemetry
  seam cannot reach it**: `session-telemetry/record` returns a record synchronously, so a
  secret only secretlint recognises survives telemetry export.

A tool result is scanned twice: each of its strings on its own by tier 1, and all of them
joined by newlines through both tiers. The joined pass finds what no single string reproduces —
a PEM block arriving as one line per array element, which is exactly the shape `read` produces.

Measured cost of a tier-2 scan: 0.78 ms at 1 KB, 0.91 ms at 16 KB, 2.22 ms at 128 KB, 5.11 ms
at 512 KB. `maxScanBytes` caps **tier 2 only**, once per result, over the joined rendering;
tier 1 always scans everything. When tier 2 saw less than the whole result the audit record
says `truncatedScan: true`, and that record is written even when nothing was found, so a
partial scan never looks like a clean one.

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
A record carries no free-text reason: the spans are the whole description of what matched, so
nothing built from a candidate path or command line can reach the file. An audit write failure
is logged and swallowed rather than turned into a denial: the sink is evidence, not
enforcement, and a full disk should not take the agent down.

---

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test        # unit
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

The E2E harness boots a `dsh` checkout beside this one (`../dsh`); point `DSH_REPO` elsewhere
to override. That checkout needs `pnpm run build:lib:host` to have run at least once. Set
`DSH_CLI` to an installed `node_modules/@deepseek-ai/dsh/lib/bin.js` to run against the
published CLI instead, which needs no monorepo — that is what CI does.
