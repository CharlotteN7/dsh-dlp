# dsh-dlp — execution plan

Data-loss-prevention plugin for DeepSeek Harness, developed out-of-repo per
`../CONVENTIONS.md`. Written before implementation; the ADR records the decisions that
survived contact with the code.

---

## 1. Scope

### In scope

| Capability | Seam | Enforceability |
|---|---|---|
| Deny reads of credential files | `ctx.tools.guard()` (global) | invariant, non-configurable |
| Deny secrets in arguments to egress-capable tools | `ctx.tools.guard()` (global) | invariant, non-configurable |
| Broader (async) argument scan | `tools/pre-execute` | best-effort, neutralizable |
| Redact secrets out of tool results | `tools/post-execute` | best-effort, neutralizable |
| Redact secrets out of exported telemetry | `session-telemetry/record` | fail-closed within the waterfall |
| Durable audit of every decision | our own JSONL sink | always |

### Explicit non-goals

- **Containment.** The plugin runs in-process at the agent's own uid. Any code the agent
  can run — `bash`, `run_code`, a mounted MCP server — can read the same files the guard
  denies and can open its own sockets. This closes a *model-mediated* gap, not a kernel one.
- **Outbound prompt redaction.** `llm/stream` options are deep-frozen and `next()` takes no
  arguments. Rewriting an outbound request is impossible; only blocking is available, and
  blocking a whole request on a detection is a worse failure mode than the leak it prevents
  for the messages the model itself authored. Not implemented in this phase.
- **Rewriting tool arguments.** Model-visible ⟺ logged: arguments are already in the log and
  already presented, so masking them would desynchronise the log from what ran. Argument-level
  DLP is *deny with a structured reason*, never mask.
- **Writing to the session log.** `Session.append()` cannot set `ignorable: true`; an
  out-of-repo event type makes the user's next resume throw `SessionFormatUnsupportedError`
  and refuse the whole session. All durable output goes to our own sink.
- **File-write DLP.** `write`/`edit`/`str_replace_editor` put data on local disk, not on a
  socket. Treated as non-egress; a synced or shared directory defeats that assumption and the
  README says so.
- **Entropy-only detection.** No generic "looks random" rule in phase 1: the false-positive
  cost on a coding agent's tool results (hashes, minified bundles, base64 blobs) is too high
  for a redactor that rewrites what the model reads.

---

## 2. Component layout

```
src/
  index.ts       plugin entry: name, inject, Config, apply(); wires the four seams
  policy.ts      Config schema, repo-local policy loading, tighten-only merge
  detectors.ts   synchronous rule table + sync scanner; async @secretlint/core engine
  redaction.ts   span expansion/merge, keyed-hash placeholder, text and JSON redaction
  paths.ts       credential-path matcher; egress-capable tool classification
  guard.ts       the unconditional guard floor
  results.ts     tools/pre-execute breadth tier + tools/post-execute redaction
  telemetry.ts   session-telemetry/record fail-closed redaction
  sink.ts        our own JSONL audit sink + tool/call turn/step correlation
```

Every registration goes through `ctx.on()` / `ctx.effect()`; disposers stay private.

---

## 3. Seam selection, with rationale

### 3.1 Guard floor — `ctx.tools.guard()`, registered **unscoped/global**

`ToolGuard` is `(execution: Readonly<ToolExecution>) => string | undefined`. Deny-or-abstain
with no allow arm, so no ordering of registrations can turn a denial back into permission,
and first denial wins. It runs *after* the whole `tools/pre-execute` waterfall and *after*
`ctx.approval`, which means it reads `exec.arguments` as they finally are.

That last point is the reason the floor lives here and not in `tools/pre-execute`.
`exec.arguments` is deep-frozen, **but `exec` itself is not frozen until after execution** —
a `tools/pre-execute` listener can reassign `exec.arguments = {...}` or `exec.name = '...'`
and the assignment succeeds. A pre-execute check therefore validates a value a later listener
can replace. The guard reads after every listener has had its turn, so a swap cannot slip past
it.

Registered on the plugin's plain context, not through `agent.ctx`. Verified: global guards
apply to every agent, every `run_code` inner sub-call, and every subagent child; a
parent-agent-scoped listener does **not** see subagent child calls, because a child agent is a
sibling, not a descendant. `run_code` inner calls traverse the full pipeline
(`tools/pre-execute` → approval → guards) with no bypass.

The guard must not throw: a throwing guard fails the call closed *and* skips
`tools/post-execute`, which would silently drop the redaction pass for that call. Every guard
body is wrapped so an internal fault becomes a denial string, not an exception.

**Why the guard cannot use `@secretlint/core`.** `ToolGuard` returns `string | undefined`,
synchronously. `lintSource` returns a Promise, and the runner beneath it is a
`PromiseEventEmitter` (`@secretlint/core/module/RunningEvents.js`) whose rule handlers are
awaited. It cannot be driven synchronously without reimplementing the core's rule context and
message cleanup. The guard therefore uses the owned synchronous rule table (§4.1); secretlint
supplies breadth at the two async seams. This is the one place where CONVENTIONS §3's
"prefer maintained dependencies" loses to a seam's type.

### 3.2 Breadth tier — `tools/pre-execute`

Async, so `@secretlint/core`'s full rule set applies to arguments here. The listener calls
`next()` first and only converts an `allow` into a `deny` — it never converts a deny into an
allow. It is explicitly **not** an invariant: a listener registered ahead of ours can return
without calling `next()` and neutralise it, and a `tools/pre-execute` deny short-circuits
guards entirely. It exists to catch what the narrow sync table misses, and the plan says so
rather than claiming coverage the seam cannot give.

### 3.3 Result redaction — `tools/post-execute`

```ts
type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[]; value?: never; additionalContexts?: UserMessage[] }
  | { kind: 'accept'; value: JsonValue; content?: never; additionalContexts?: UserMessage[] }
  | { kind: 'block'; feedback: ContentBlock[]; additionalContexts?: UserMessage[] }
```

Arm selection:

- **Success whose `value` or `meta` carries anything** → `accept{value}`. The registry
  re-validates `output.schema`, re-runs `output.render()`, and re-derives
  `output.presentationMeta()`, so the canonical value, the model-facing content, and the
  persisted meta are all redacted from one replacement. This is the only arm that keeps a
  secret out of the durable log, so a success never settles for `accept{content}`: the
  content arm leaves `{...result}` in place, and `value` and `meta` are appended to the
  session log exactly as the tool produced them.
- **Failed result, or a success whose secret exists only in the rendered content** →
  `accept{content}`. `accept{value}` throws a `TypeError` on a failed result, and error text
  is exactly where a leaked secret hides — a stack trace quoting the command line, a provider
  error echoing a token. This arm is only taken when the persisted surfaces are already clean.
- **A dirty `meta` on a failed result, or a value that still scans dirty after redaction** →
  `block`. No accept arm can rewrite `meta`, and `block` is the one decision that replaces the
  whole result, so it is the only way to keep such a result out of the log.
- **Downstream `block`** → the corrective `feedback` blocks are redacted in place.

Detection runs over the strings of `value`, `content` and `meta` twice: each string on its own
with tier 1, and all of them joined with newlines through both tiers. The joined pass is what
finds a secret no single string reproduces — a PEM block arriving as one `lines[i].text` per
line, which is exactly the shape `read` produces — and its offsets are mapped back onto the
individual strings before splicing.

The two `accept` arms are mutually exclusive at runtime (`Object.hasOwn` check throws
`TypeError`), so the implementation builds exactly one.

Composition: the listener `await next()` first and redacts *the decision that came back*, not
the original `result`. Redacting the original would clobber a downstream listener's own
replacement.

Replacement happens **before** the `tool/result` session event is appended, so the durable log
records the redacted copy. That is the property the E2E test asserts.

Guard denials arrive here too — a guard denial produces `kind: 'post-result'`, which still runs
post-execute — so the deny reason itself passes through the redactor.

### 3.4 Telemetry redaction — `session-telemetry/record`

`DSH_TELEMETRY_MODE=FULL` mounts the OTel backend with a *live* coordinator, which exports a
deep copy of every session event's `data` — user and assistant message text, tool arguments,
tool results — plus identity attributes including `session.cwd`. The waterfall ships **no
rules of its own**; with nothing mounted, records reach the exporter exactly as captured. That
is the documented hole this listener patches.

The waterfall is **synchronous** (`next: () => SessionTelemetryRecord`), so this seam also
uses the sync rule table. It is fail-closed by construction: the coordinator dispatches inside
its own containment, and a throwing listener withholds that one record and never reaches the
agent loop. Our listener therefore throws rather than passing a record through when redaction
cannot complete.

Only tier 1 is reachable here, and there is no other seam on the export path that can await:
a secret only `@secretlint/core` recognises survives telemetry export. The sync table carries
webhook URLs for that reason.

Ledger records mirroring `tool/result` have been through §3.3, which ran before the event was
appended — but only over what that seam could reach, so this listener re-scans every record
rather than trusting the event type. Beyond that its value is on the events §3.3 never sees:
`user/message`, `assistant/message`, `tool/call` arguments, and the `session.cwd` attribute.

### 3.5 Durable output — our own sink

A line-delimited JSON file opened from config. Every record carries
`{ v, time, kind, decisionId, sessionId, turn, step, callId, rootCallId }` itself, because the
`SessionEvent` envelope carries no such identity and we never write to the log anyway.
`turn`/`step` are not on `Agent`, so a small `session/event` observer keeps a bounded
`callId → { turn, step }` map fed by `tool/call` events (`data.turn`, `data.step`,
`data.callId`) and evicted on `tool/result`.

---

## 4. Detector stack and latency budget

### 4.1 Tier 1 — synchronous rule table (owned)

Used by the guard floor and the telemetry listener. Deliberately narrow: only
prefix-anchored, structurally unambiguous token formats plus PEM blocks and credential URLs.
Each rule carries `{ id, version, severity, pattern }`; `version` is bumped whenever a
pattern changes, and is written into every audit record so a finding stays interpretable
after a rule edit.

Initial set: AWS access key id, AWS secret access key assignment, GitHub tokens
(`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`), Slack tokens (`xox[abprs]-`), Stripe live
keys, OpenAI `sk-`, Anthropic `sk-ant-`, Google API keys (`AIza`), npm tokens (`npm_`),
PEM private-key blocks, JWTs, and credential-bearing URLs (`scheme://user:pass@host`).

### 4.2 Tier 2 — `@secretlint/core` (async)

Used at `tools/pre-execute` and `tools/post-execute`. Verified in-process, no subprocess, 8
packages installed total, MIT. The `@secretlint/secretlint-rule-preset-recommend` creator is
passed directly as `{ id, rule: creator }`; its 28 child rules register themselves through the
preset context.

**Verified defect, and the mitigation.** Reported `range` values are advisory, not exact. For
`aws_secret_access_key = kL9xQ2mZ7pR4tY6wA1sD3fG5hJ8kL0nM2bV4cX6z` the AWS rule reports
`[0, 40]`, which is the *prefix* `aws_secret_access_key = kL9xQ2mZ7pR4tY6w` — splicing that
span alone would leave 24 characters of the secret in place. Redaction therefore never uses a
reported span directly: every span is **expanded outward to whitespace boundaries** and
overlapping spans are merged before replacement. Over-redaction (the key name disappears with
its value) is the safe direction; under-redaction is not.

### 4.3 Latency budget

`tools/post-execute` is hot. Measured on this machine, `lintSource` with the recommended
preset, steady state:

| Input | Per scan |
|---|---|
| 1 KB | 0.78 ms |
| 16 KB | 0.91 ms |
| 128 KB | 2.22 ms |
| 512 KB | 5.11 ms |

Budget: **≤ 10 ms per tool result**, enforced by a configurable `maxScanBytes` (default 1 MiB).
The cap applies to tier 2 only. Tier 1 is pure `RegExp.exec` and always scans the whole input;
capping it would fail open on the cheap tier for no benefit. `maxScanBytes` is the single
budget: one `lintSource` call per result over the joined rendering, so how many strings a tool
split its output into never changes how much of it is examined. Whenever tier 2 saw less than
the whole rendering the audit record carries `truncatedScan: true` — and that record is written
even when nothing was found, so "clean" and "not fully scanned" stay distinguishable. No
subprocess, no I/O, no network on any scan path.

---

## 5. Policy and configuration

### 5.1 Source-trust ranking

| Rank | Source | May |
|---|---|---|
| 1 (highest) | Security invariants compiled into the plugin | everything; not configurable |
| 2 | `cordis.yml` / bundle patch config (deployment-controlled) | set every field |
| 3 (lowest) | `policyFile` — a repo-local YAML file inside the workspace | **tighten only** |

Rank 3 is attacker-controlled: a hostile repository ships one, and a prompt-injected agent can
write one. It may only:

- add credential-path deny patterns,
- add tool names to the egress-capable set,
- **raise** a detector's severity,
- **enable** a redaction pass the deployment left off.

Every other key, and any attempt to remove a pattern, disable a detector, lower a severity, or
redirect the audit sink, makes the **whole file invalid**: it is reported on the deployment's
logger and ignored, never obeyed in part. A missing file is simply no repo-local policy —
`policyFile` names a path inside the workspace, and most repositories will not have one, so
refusing to mount would stop `dsh` from starting in every such repository and would hand a
hostile repository a way to remove the floor by shipping a broken file. Neither outcome ever
loosens the floor.

An added pattern is also checked before it is compiled: at most 200 characters, and no
quantifier nested inside a quantified group. `^(a+)+$` blocks the synchronous guard for
seconds on a 27-character input, which any workspace could otherwise ship.

Parsed with `js-yaml` under `JSON_SCHEMA`, so `!!js/function` is a parse error rather than code
execution. Never routed through the Cordis loader.

### 5.2 Deployment config (`Config`, schemastery)

```yaml
- id: dsh-dlp
  name: 'dsh-dlp'
  config:
    auditLog: <path>           # required; our sink
    redactionKeyFile: <path>   # required; 32 random bytes, mode 0600, created if absent
    policyFile: <path>         # optional; rank-3 source
    maxScanBytes: 1048576
    breadthTier: true          # the tools/pre-execute secretlint pass
    resultRedaction: true      # the tools/post-execute pass
    telemetryRedaction: true   # the session-telemetry/record pass
    redactTelemetryWorkspacePaths: true
```

The guard floor has no switch. Per CONVENTIONS §2, security invariants stay fixed, and per
§6.1 anything that must hold under attack is an unconditional deny.

### 5.3 Redaction placeholder

```
[REDACTED:dsh-dlp:<shortRuleId>:<h12>]
```

`h12` is the first 12 hex characters of `HMAC-SHA256(key, matchedBytes)`. Stable, not random:
the same secret produces the same placeholder in every record, so an operator can correlate
"this token appeared in four tool results" without the plugin ever writing the token. The key
comes from `redactionKeyFile` — per-installation, created with 32 random bytes at mode 0600 if
missing, never committed. A random placeholder would destroy correlation; an unkeyed hash
would let anyone holding a candidate secret confirm it from the audit log.

### 5.4 What is logged about a finding

`ruleId`, rule `version`, `start`/`end` offsets, `severity`, and the keyed hash. **Never the
matched value**, never a prefix of it, never its length beyond the offsets — and never the
candidate that matched, because a path is itself sensitive: a tenant directory, a customer
database name, or a whole shell command line that happens to end in `.pem`. This holds in the
audit sink, in deny reasons handed to the model, and in any log line. The sink records no
free-text reason at all; the spans are the whole description.

---

## 6. Test matrix

### 6.1 Unit (`pnpm run test`, keyless, no subprocess)

**`tests/unit/detectors.spec.ts`**
- `sync scanner finds a Slack bot token and reports its rule id and offsets` — finding has the
  right `ruleId`/`version`, offsets bracket the token.
- `sync scanner leaves ordinary prose alone` — no findings on a paragraph of English text.
- `sync scanner reports every match in a multi-secret string` — two findings, distinct rules.
- `secretlint engine finds a secret the sync table does not carry` — a rule only the preset
  has (Stripe live key) is reported by tier 2.
- `secretlint engine reports nothing for clean text`.
- `scan of input above the byte cap is marked truncated` — `truncatedScan` set.

**`tests/unit/redaction.spec.ts`**
- `placeholder is stable for the same secret and key` — two calls, identical placeholder.
- `placeholder differs for a different key` — the hash is keyed, not a bare digest.
- `placeholder never contains the secret` — assert the matched value is absent from the output.
- `an advisory span that under-covers a secret is expanded to whitespace boundaries` — the
  verified AWS `[0,40]` case; the full 40-character secret is absent from the redacted text.
- `overlapping spans are merged into one placeholder`.
- `JSON redaction rewrites strings at every depth and leaves non-strings alone`.
- `JSON redaction preserves object keys` — keys are not values; renaming them would break
  output schemas.

**`tests/unit/paths.spec.ts`**
- `denies .env, id_rsa, ~/.aws/credentials, anything under ~/.ssh, and $DSH_HOME/.credentials.yaml`
  — one case per required pattern.
- `denies a credential path reached through .. traversal` — normalisation happens before match.
- `allows an ordinary source file`.
- `allows a file merely named environment.ts` — the `.env` rule is not a substring match.
- `classifies bash, web_fetch, run_code and mcp__* as egress-capable`.
- `classifies read, glob, grep and todo_write as local`.
- `classifies an unknown tool name as egress-capable` — unknown defaults to the safe side.

**`tests/unit/policy.spec.ts`**
- `a repo-local policy that adds a deny path is accepted`.
- `a repo-local policy that adds an egress tool is accepted`.
- `a repo-local policy that raises a severity is accepted`.
- `a repo-local policy that disables a detector is rejected at load`.
- `a repo-local policy that removes a deny path is rejected at load`.
- `a repo-local policy that lowers a severity is rejected at load`.
- `a repo-local policy that redirects the audit sink is rejected at load`.
- `a policy file containing !!js/function fails to parse` — no code execution.
- `an unknown key fails loud rather than being ignored`.

**`tests/unit/guard.spec.ts`**
- `denies a read of a credential path and names the path in the reason`.
- `denies a bash command carrying a token`.
- `allows the same token in an argument to a local tool` — no egress, no deny.
- `abstains on an ordinary call` — returns `undefined`.
- `a fault inside the guard becomes a denial, never a throw` — a throwing guard would also skip
  post-execute.
- `the deny reason contains no secret material`.

**`tests/unit/sink.spec.ts`**
- `writes one JSON line per decision carrying v, sessionId, callId and decisionId`.
- `never writes a matched secret value`.
- `correlates turn and step from a preceding tool/call event`.

**`tests/unit/telemetry.spec.ts`**
- `redacts a secret in a ledger record body`.
- `redacts a secret in an ops record body`.
- `replaces the session.cwd attribute when path redaction is on`.
- `leaves a clean record untouched and still delegates to next()`.
- `throws rather than emitting when redaction cannot complete` — fail-closed.

**`tests/unit/results.spec.ts`**
- `a successful structured result is replaced through the value arm`.
- `a failed result is replaced through the content arm`.
- `a downstream block decision has its feedback redacted`.
- `a clean result is passed through unchanged`.
- `the decision never carries both value and content` — the runtime check would `TypeError`.

### 6.2 E2E (`pnpm run test:e2e`, keyless, real `dsh` subprocess)

On the template's harness: a real profile, the plugin copied into
`$DSH_HOME/profiles/e2e/node_modules/dsh-dlp`, `@deepseek-ai/dsh-llm-mock-server` driving the
real DeepSeek adapter, `session-persistence-jsonl` at `compression: none` /
`packChunks: false`, one spare `success` in the sequence for the session-title request, a
fresh mock server per test.

**(a) `credential read is denied by the guard and the model is told why`**
Mock issues `read` with `file_path` under `~/.ssh/id_rsa`. Assertions:
1. the process exits 0;
2. a `tool/result` row in the session log carries our deny reason;
3. the reason text appears in a subsequent request body captured by the mock — the model
   actually received it and can act on it;
4. the audit sink holds one `guard-deny` record with `sessionId` and `callId`;
5. the file is never opened (the deny reason, not file content, is what came back).

**(b) `a secret in a tool result is redacted before the model and before the log`**
A seeded file inside the throwaway `$DSH_HOME` holds a Slack bot token; the mock issues a
`read` of it, so the token appears only in the *result*, never in the arguments. Assertions:
1. the process exits 0;
2. no `tool/result` row in the session log contains the raw token;
3. some `tool/result` row contains a `[REDACTED:dsh-dlp:...]` placeholder;
4. no request body captured by the mock contains the raw token;
5. the audit sink holds a `result-redaction` record whose findings carry `ruleId` and a hash
   and **not** the token.

**(c) `an ordinary tool call is not disturbed`**
The template's own round-trip: `bash` printing a marker, no secret. Asserts the marker still
reaches the log, so the plugin is not a blanket denier.

### 6.3 What each surface is evidence for

Unit tests are evidence about detector and policy behaviour. Only the E2E tests are evidence
that the plugin works: a booted harness, our plugin mounted, a mock model driving a real tool
call, and an assertion on the resulting session log (CONVENTIONS §5).

---

## 7. Phasing

1. **Scaffold** — `package.json`, `cordis.patch.yml`, tsconfig/vitest copied from the template;
   pinned versions; the harness copy with `{{DSH_HOME}}` substitution and file seeding.
2. **Detection core** — `detectors.ts`, `redaction.ts`, `paths.ts` + their unit tests. No
   harness dependency; runs on its own.
3. **Guard floor** — `guard.ts`, `sink.ts` + unit tests, then E2E (a). The invariant lands
   before anything optional.
4. **Result redaction** — `results.ts` + unit tests, then E2E (b).
5. **Telemetry** — `telemetry.ts` + unit tests.
6. **Policy** — `policy.ts` tighten-only merge + unit tests.
7. **Docs** — `README.md` (with the non-containment limit stated plainly), `ADR.md`.

Each phase is one conventional commit. Commits stay local.

---

## 8. Limitations — what this cannot enforce

1. **It is not a containment boundary.** In-process, same uid as the agent. `bash`,
   `run_code`, and any MCP server can read every file the guard denies and can open sockets the
   plugin never sees. Real containment is the sandbox, `landlock-run`, and filesystem
   permissions. This plugin closes the *model-mediated* path.
2. **Everything except the guard floor is neutralizable.** A `tools/pre-execute` listener that
   returns without calling `next()` disables the breadth tier; a `tools/post-execute` listener
   ahead of ours can replace a result after we redacted it. Only `ctx.tools.guard()` is
   order-independent, and only because it has no allow arm.
3. **A `tools/pre-execute` deny skips guards entirely.** Guards are a deny floor, not a
   universal audit hook — the sink cannot claim to have seen every call.
4. **Tool arguments are never masked.** They are already logged and presented. A secret the
   model itself typed into an argument to a *local* tool is recorded verbatim in `tool/call`.
   The only lever for egress-capable tools is denial.
5. **Outbound prompts cannot be rewritten.** `llm/stream` options are deep-frozen and `next()`
   takes no arguments. A secret already in the conversation history reaches the provider.
6. **Content replacement is presentation policy.** The `content` arm leaves the canonical
   `value` and the persisted `meta` untouched, which is why a success with anything to redact
   takes the `value` arm and an unrewritable `meta` is blocked instead.
7. **Detection is pattern-based and therefore incomplete.** A secret with no recognisable
   structure — a password, an internal token format, a customer record — is not detected. No
   entropy rule in phase 1. Any encoding (base64, hex, URL-escaping, reversal) defeats both
   tiers, as does splitting a secret across two content blocks.
8. **Reported spans from `@secretlint/core` are advisory.** Mitigated by expansion to the
   nearest delimiter (whitespace, quotes, `=`, `:`, `,`, brackets), which over-redacts. A
   secret containing a delimiter could still be split across expansions.
12. **The shell-command arm is advisory.** Tokenising a `bash` command line and testing the
    tokens as paths catches an unobfuscated `cat ~/.ssh/id_rsa` and nothing more; one glob
    character, a quote, a `$(...)`, or a different binary defeats it. It is not a control.
13. **Replacing a value can fail the call.** The placeholder is re-validated against the
    tool's `output.schema`; a schema constraining that string turns the redaction into a
    `ToolOutputError`. A failed call is the intended outcome — the alternative is logging the
    secret.
14. **The repo-local pattern check is a heuristic.** A length cap and a nested-quantifier
    rejection stop the shapes that are easy to write and expensive to run; no syntactic check
    can prove a pattern runs in linear time.
9. **`additionalContexts` are not redacted.** They are model-visible `UserMessage` payloads;
   scanning them is future work.
10. **Local writes are out of scope.** `write`/`edit` to a synced directory exfiltrate without
    touching an egress-capable tool.
11. **Telemetry redaction only covers a mounted backend's records.** A second exporter mounted
    outside the `session-telemetry/record` waterfall is not covered.
