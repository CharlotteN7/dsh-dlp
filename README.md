# dsh-dlp

Data-loss prevention for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness),
built as an out-of-repo plugin.

It does five things:

1. **Denies credential-file access and secrets bound for the network** — unconditionally, from
   `ctx.tools.guard()`. It tests the path-typed arguments of a call against a table of
   credential stores, following symlinks first.
2. **Redacts secrets out of tool results** before the model reads them and before the session
   log records them, and withholds a result it cannot clean.
3. **Redacts secrets out of exported telemetry**, patching a hole where `DSH_TELEMETRY_MODE=FULL`
   ships message text, tool arguments, tool results and workspace paths in the clear.
4. **Strips the invisible characters that carry hidden instructions** out of tool results —
   the Tags block and bidi overrides — and counts the classes it will not touch because they
   also appear in legitimate text.
5. **Writes an audit record for every decision** to its own sink — rule id, rule version,
   offsets, and a keyed hash. Never the secret, and never the path or command that matched.
   `dsh-dlp report` reads that sink back.

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

- **Only the guard floor is unconditional.** Every other seam can be neutralised by a listener
  registered ahead of ours: a `tools/pre-execute` listener that returns without calling `next()`
  disables the breadth tier, and a `tools/post-execute` listener ahead of ours can replace a
  result after it was redacted. `ctx.tools.guard()` is order-independent only because it has no
  allow arm. A `tools/pre-execute` deny also skips guards entirely, so the audit sink cannot
  claim to have seen every call.
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
- **Already-logged history cannot be rewritten; a not-yet-logged inbound message can.** At
  `llm/stream` the options are deep-frozen and `next()` takes no arguments, so a request the
  agent has assembled goes out as it stands and a secret already in the conversation reaches
  the provider. That is not the whole rule, though: `agent/pre-step` is an async waterfall
  returning `{ kind: 'enter'; messages }`, and the only production append of `user/message`
  happens *after* it, so a message arriving from outside can still be rewritten before it is
  logged or presented. This release does not do that; it is recorded here because the earlier
  flat claim that outbound redaction is impossible was too strong.
- **A redacted value is not restored when the agent runs a command.** `ctx.shellEnv` rebuilds a
  trusted `DSH_*` namespace for every model shell call, which is a way to hand `bash` and
  `pwsh` — and only those two — the real value behind a placeholder without the model ever
  seeing it. Planned work, not implemented here.
- **Detection is pattern-based.** A password, an internal token format, or a customer record
  has no recognisable structure and is not detected. Neither is any encoded form: base64,
  hex, URL-escaping and reversal all pass both tiers, as does a secret split across two
  content blocks. **A homoglyph defeats every rule in this package**, including the
  invisible-character ones.
- **There is no entropy rule, and that was measured rather than assumed.** Shannon entropy is
  bounded by log₂L for a string of length L, so a 20-character token cannot score above 4.32
  bits per character however random it is. At the threshold where ordinary tool output —
  hashes, minified bundles, base64 blobs, UUIDs — produces no false positives, the miss rate
  is 100% for anything up to 22 characters, which is most of the credential formats worth
  catching. A detector that fires on the long ones the prefix rules already catch and misses
  the rest is not worth the false positives it costs.
- **A secret containing a delimiter can still be split across two redactions.** Every reported
  span grows outward to the nearest delimiter, which over-redacts in the safe direction, but a
  secret whose own text contains one of those delimiters is covered by two placeholders with the
  delimiter left between them.
- **`additionalContexts` are not scanned.** They are model-visible `UserMessage` payloads and
  this release does not redact them.
- **Local writes are out of scope.** A `write` or `edit` into a synced directory moves data off
  the machine without going through an egress-capable tool.
- **Telemetry redaction covers a mounted backend's records only.** A second exporter mounted
  outside the `session-telemetry/record` waterfall is not covered.
- **`$DSH_HOME` is readable by a read-only tool.** Profile manifests and the installed plugin
  tree are ordinary work to read, so which plugins a profile loads is model-visible. Only writes
  are denied wholesale there, plus reads of the credential material inside it.

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

- Replacing a value re-validates it against the tool's `output.schema`, and a schema that pins
  that string — an `enum`, a `const`, a `oneOf` branch it selects — would reject the
  placeholder. The plugin asks that question first and withholds the result with the message
  above, rather than letting the registry raise a `ToolOutputError` that names a validation
  failure and tells the model nothing it can act on. The call still fails; it fails
  comprehensibly. Where the plugin cannot answer the question — no schema resolved, or a
  schema whose own value it cannot validate — the registry decides as before.
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

### Invisible characters

Tier 1 also looks for characters that hide text from the person reading a tool result while
the model still reads it. The harness strips directional controls in exactly one place —
session titles — and never on the tool-result path.

| Class | Code points | What happens |
|---|---|---|
| Tags block | `U+E0000–U+E007F` | replaced |
| Bidi overrides and isolates | `U+202A–U+202E`, `U+2066–U+2069` | replaced |
| Zero-width | `U+200B–U+200D`, `U+2060`, `U+FEFF` | counted only |
| Bidi marks | `U+061C`, `U+200E–U+200F` | counted only |
| Variation selectors | `U+FE00–U+FE0F`, `U+E0100–U+E01EF` | counted only |

The first two have no legitimate use in tool output — the Tags block is a full invisible ASCII
alphabet, which is what makes it the standard carrier for a hidden instruction. The last three
do: `U+200D` joins an emoji sequence and a variation selector picks a glyph, so replacing them
would corrupt ordinary text. They are counted in the audit record's `unicode` field and left
alone, as a `medium` finding.

Every class is `medium`, below the severity at which the guard floor denies, so an invisible
character is never turned into a denial. A replaced run becomes an ordinary placeholder and,
unlike a secret, is replaced exactly: an invisible character is not widened to its surrounding
delimiters, so the visible word it hid inside survives.

**A homoglyph defeats all of this**, and every other rule in this plugin. A Cyrillic `а` in
`аdmin` is a normal, visible, legitimately-encoded character; detecting it means UTS #39
confusable tables, which is a data set and a different cost class. This plugin does not attempt
it, and no rule here should be read as covering it.

Measured cost of the invisible-character scan over 512 KB, median of 30 runs on an i9-12900H
under Node 22.23.2:

| Input | Cost |
|---|---|
| clean Latin-1 text | 0.002 ms |
| one hidden instruction (69 characters) | 0.355 ms |
| 7,653 separate runs | 7.9 ms |
| 512 KB of alternating invisible characters (524,286 runs) | 56–113 ms |

Clean text is free because every character in the table is above `U+00FF`: the regular
expression engine rejects a Latin-1 string on its encoding without scanning it. The last row is
a crafted input, not a plausible one, and it is the only case that leaves the ≤10 ms per result
budget; `maxScanBytes` caps tier 2 only, so tier 1 always sees the whole result.

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
A `result-redaction` record may also carry `unicode`, a count of invisible-character runs per
class — counts only, because a hidden instruction is exactly the content this file must not
repeat. A record is written whenever there is something to say, including a result that was
only counted and a result whose tier-2 scan was truncated.
A record carries no free-text reason: the spans are the whole description of what matched, so
nothing built from a candidate path or command line can reach the file. An audit write failure
is reported and swallowed rather than turned into a denial: the sink is evidence, not
enforcement, and a full disk should not take the agent down.

Reported means `process.stderr` **and** `ctx.logger`, for that failure and for an invalid
policy file. The logger alone is not enough: its default exporter is an in-memory 1000-entry
ring buffer and no shipped bundle mounts a console exporter, so a message sent only there is
invisible on a stock install. `process.stderr` is what the headless runner itself writes to.

---

## Reading the audit log

The package installs a `dsh-dlp` command that reads the JSONL sink and summarises it. It
imports nothing from the harness, so it runs wherever the package is installed, with no profile
and no `dsh` on the path:

```sh
dsh-dlp report                      # everything in $DSH_HOME/dsh-dlp.audit.jsonl
dsh-dlp report --since 24h          # or an ISO timestamp
dsh-dlp report --session <id>
dsh-dlp report --would-have         # only the calls that were let through
dsh-dlp report --log /var/log/dsh-dlp.audit.jsonl
```

It prints counts by decision, by rule, by tool and by invisible-character class, then the ten
most recent decisions. `--would-have` drops the denials and leaves the redactions and the
invisible-character findings: those are the calls that ran, with their results rewritten, and
they are what a policy that denied instead of rewriting would have blocked.

The sink is append-only and a run can be interrupted mid-append, so a line that does not parse
as a record is counted and reported rather than trusted. If the deployment set `auditLog` to
somewhere other than the default, pass `--log`; the command says which file it looked at.

A plugin installed into a profile puts its bin in that profile's `node_modules/.bin`, which is
not on `PATH`. Run it from there, or install the package globally:

```sh
"$DSH_HOME/profiles/<name>/node_modules/.bin/dsh-dlp" report
```

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
