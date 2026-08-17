# Architecture decisions — dsh-dlp

Decisions that are not obvious from the code, and the evidence behind them.

---

## 1. The deny floor lives in `ctx.tools.guard()`, not in `tools/pre-execute`

`ToolGuard` is `(execution: Readonly<ToolExecution>) => string | undefined`. Deny-or-abstain,
no allow arm, first denial wins — so no registration order can turn a denial back into
permission. `tools/pre-execute` is a waterfall, and any listener registered ahead of ours can
return without calling `next()` and delete our decision entirely.

There is a second, sharper reason. **`exec.arguments` is deep-frozen, but `exec` itself is not
frozen until after execution.** A `tools/pre-execute` listener can execute
`exec.arguments = { file_path: '/tmp/harmless' }` or `exec.name = 'read'` and the assignment
succeeds. A check that runs inside the waterfall therefore validates a value a later listener
can swap. The guard stage runs after the entire waterfall and after `ctx.approval`, so it reads
what every listener finally left behind. That is the only place a floor can stand.

Consequences accepted:

- A `tools/pre-execute` **deny short-circuits guards entirely**. Guards are a deny floor, not a
  universal audit hook, and the audit sink cannot claim to have seen every call.
- A guard that **throws** fails the call closed *and* skips `tools/post-execute`, which would
  silently disable redaction for that call. `safeEvaluateGuard` therefore converts any internal
  fault into a denial *string*. Failing closed without losing the redaction stage.

## 2. The guard is registered unscoped, on a plain context

Verified: a global guard applies to every agent, to every `run_code` inner sub-call, and to
every subagent child. An agent-scoped listener registered through `agent.ctx` does **not** see
a subagent child's calls, because a child agent is a sibling of its parent, not a descendant.
A floor registered per-agent would therefore have a hole exactly where a prompt-injected agent
would spawn a helper.

`run_code` inner calls traverse the full pipeline (`tools/pre-execute` → approval → guards)
with no bypass, so nothing extra is needed to cover Code Mode.

## 3. `@secretlint/core` cannot be used in two of the three seams

CONVENTIONS §3 says to prefer a maintained dependency over hand-rolled detectors. Two of this
plugin's three enforcement seams make that impossible:

- `ToolGuard` returns `string | undefined`, synchronously.
- `session-telemetry/record` is declared
  `(record: SessionTelemetryRecord, next: () => SessionTelemetryRecord): SessionTelemetryRecord`
  — also synchronous.

`lintSource` returns a promise, and the runner beneath it is a `PromiseEventEmitter`
(`@secretlint/core/module/RunningEvents.js`) whose per-rule `file()` handlers are awaited.
Driving it synchronously would mean reimplementing the core's rule context, report collection
and message cleanup — a fork, not a dependency.

So the design is two tiers: an owned synchronous table for the synchronous seams, and
`@secretlint/core` at `tools/pre-execute` and `tools/post-execute`, where awaiting is allowed.
The owned table is deliberately narrow — prefix-anchored formats, PEM blocks, credential URLs
— because a false positive there costs a *denial*, not a redaction.

Rejected alternative: precompute the async scan in a `tools/pre-execute` listener and have the
guard read a cache. A floor that depends on an earlier waterfall listener having run is not a
floor — one short-circuiting listener ahead of ours empties the cache and the guard abstains.

Rejected alternative: `@visulima/secret-scanner`, a Rust port of gitleaks over NAPI that would
give a synchronous scan. Single maintainer, native binaries, 1.0 six weeks old at the time of
writing. Adding a native binary to the trusted computing base of a security floor is a worse
trade than a narrow owned regex table.

## 4. Reported spans from `@secretlint/core` are advisory, and we verified it

For the input `aws_secret_access_key = kL9xQ2mZ7pR4tY6wA1sD3fG5hJ8kL0nM2bV4cX6z`, the
`@secretlint/secretlint-rule-aws` rule reports `range: [0, 40]`. That slice is
`aws_secret_access_key = kL9xQ2mZ7pR4tY6w` — the assignment prefix plus 16 characters of the
secret. Splicing the reported span alone leaves the remaining 24 characters of the key in
place.

Redaction therefore never uses a reported span directly. Every span is expanded outward until
both edges sit on a delimiter or a string boundary, and overlapping spans merge into one
placeholder attributed to the strictest rule that touched it. Over-redaction — the key's name
disappearing along with its value — is the safe direction. `tests/unit/redaction.spec.ts`
pins the behaviour against the real scanner output rather than a fixture, so a future
secretlint release that fixes the range will not silently un-pin it.

The delimiter set is whitespace, quotes, `=`, `:`, `,`, `;`, `&`, `?` and brackets, not
whitespace alone. A line of minified JSON contains no whitespace at all, so expanding to
whitespace replaced the entire record — every other field on the line — for one matched token.
Bounding a secret at the syntax that separates values keeps the surrounding data intact while
still covering the match.

Residual: a secret containing a delimiter could still be split across two expansions.

## 5. Arm selection at `tools/post-execute`

```ts
type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[]; value?: never; … }
  | { kind: 'accept'; value: JsonValue; content?: never; … }
  | { kind: 'block'; feedback: ContentBlock[]; … }
```

A successful result whose `value` or `meta` carries anything takes the **value** arm. The
registry re-validates `output.schema`, re-runs `output.render()` and re-derives
`output.presentationMeta()`, so one replacement redacts the canonical value, the model-facing
content, and the card the UI persists in `meta`. The E2E run confirms all three: the
`tool/result` event's rendered text and its `meta` both carry the placeholder.

The value arm is not a preference, it is the only arm that reaches the session log. Returning
`accept{content}` leaves the registry with `{...result}`, so `value` and `meta` are appended
exactly as the tool produced them while the model sees a placeholder — a redaction that reports
success and writes the secret down. A successful result therefore never settles for the content
arm.

A failed result takes the **content** arm, because `accept{value}` throws a `TypeError` on a
failed result. Error text is exactly where a leaked token hides — a stack trace quoting a
command line, a provider error echoing a token. A success whose secret exists only in the
rendered content takes it too, since the persisted surfaces are already clean there.

When neither arm can clean what will be persisted — a failed result whose `meta` carries a
secret, or a value that still scans dirty after redaction — the listener returns **block**.
`block` is the only decision that replaces the whole result, and therefore the only one that
drops `meta`. The model gets an error naming the rule and the keyed hash.

Two costs, both recorded rather than papered over:

- Replacing a value re-validates it against `output.schema`, so a schema pinning that string
  would turn a redaction into a `ToolOutputError`. The listener resolves the live definition
  through `ctx.tools.get(name, exec.agent)` and asks first, then blocks with its own message;
  see §14. The call still fails, because the alternative is writing the secret to the log.
- Blocking discards a result the user may have wanted. It happens only where the alternative is
  a durable leak.

The two accept arms are mutually exclusive at runtime — the registry runs an `Object.hasOwn`
check and throws a `TypeError` if both are present — so the implementation builds exactly one,
and a unit test asserts it never builds both.

**Composition:** the listener `await next()` first and redacts *the decision that came back*,
never the original `result`. Redacting the original would silently discard a downstream
listener's own replacement. The one exception is a downstream `accept{content}` over a value
that is dirty: the value arm overrules it, because keeping the content replacement would leave
the value in the session log. The harness re-renders from the redacted value.

### Scanning the rendering, not only the strings

A per-string walk cannot see a secret that no single string reproduces, and that is the common
case rather than an exotic one: `read` hands back one string per line, so a PEM block matches
nothing anywhere. The listener therefore scans twice — every string on its own with tier 1, and
all of them joined with newlines through both tiers — and maps the joined pass's offsets back
onto the individual strings before splicing.

That also fixes the budget. Tier 2 runs once per result over the joined rendering, capped by
`maxScanBytes`, so how many pieces a tool split its output into no longer decides how much of
it is examined. Tier 1 is never capped: it is a linear pass over the same text, and capping the
cheap tier fails open for nothing. Whenever tier 2 saw less than the whole rendering the audit
record carries `truncatedScan: true`, and that record is written even when nothing was found —
without it an operator cannot tell a clean result from an unscanned one.

## 6. Redaction placeholders are keyed hashes, and the key is per-installation

`[REDACTED:dsh-dlp:<rule>:<12 hex>]` where the hash is `HMAC-SHA256(key, replaced text)`.

- **Not random**, because a random placeholder destroys correlation: an operator could not tell
  that the same token appeared in four tool results.
- **Not an unkeyed digest**, because the audit log is exactly the artefact an attacker reads
  after the fact, and an unkeyed digest lets anyone holding a candidate secret confirm it.

The key comes from `redactionKeyFile`, created on first mount with 32 random bytes at mode
`0600`. An existing file shorter than 16 bytes fails the mount loud rather than being padded or
regenerated — a silently weak key is worse than a refused start.

The hash covers the **expanded** span, not the raw match, so it stays stable across contexts
with the same delimiters even where the reported range is imprecise (§4).

## 7. Durable output goes to our own sink, and carries its own identity

`Session.append()` builds the envelope literally as `{ type, seq, time, data, …surfaceMetadata }`
and accepts no way to set `ignorable: true`. An out-of-repo event type is written without the
flag, and the next resume throws `SessionFormatUnsupportedError` and refuses the entire
session — while the session still appears in `list()`, so the user sees it in the picker and it
then fails to open. The plugin is therefore read-side with respect to the session log, and an
E2E assertion checks that no row in the log carries a `dsh-dlp`-prefixed type.

The `SessionEvent` envelope carries no session id, turn, step or call id, so every record we
write carries `{ v, time, kind, decisionId, sessionId, turn, step, callId, rootCallId }`
itself. `sessionId` comes from `exec.agent.session.id`.

`turn` and `step` are not on `Agent` and are not on `ToolExecution`. The only place they appear
together with a `callId` is the `tool/call` session event, so a small `session/event` observer
keeps a bounded `callId → { turn, step }` map, evicted on `tool/result` and capped at 512
entries. That is why the plugin registers a `session/event` listener at all.

**A record carries no free-text reason.** The model-facing denial string used to be stored
verbatim, and that string used to quote the candidate that matched. For `bash` the candidate is
the whole command line, so a command carrying a token and ending in `.pem` wrote the token into
the audit file; for `read` it wrote the tenant and customer names in the path. A path is
sensitive on its own. The spans — rule id, rule version, severity, offsets, keyed hash — are
the whole description of what matched, in the record and in the reason handed to the model.

**A sink write failure is reported and swallowed.** Turning it into a denial would trade a
confidentiality control for an availability outage — a full disk would make every tool call
fail — and a throwing guard would also skip `tools/post-execute` and disable redaction. The
verdict never depends on whether the record was written.

Reported means `ctx.logger` **and** `process.stderr`. `ctx.logger`'s default exporter is an
in-memory 1000-entry ring buffer (`vendor/cordis/src/logger.ts`) and no shipped bundle mounts a
console exporter, so a message that goes only to the logger is invisible on every stock
install: this failure and an invalid policy file were both silently swallowed. `process.stderr`
is what the headless runner itself writes to.

## 8. The path table runs over path-typed arguments only, after `realpathSync`

A shell that can `cat` a key can also copy it, so the path table is enforced regardless of the
tool's name. *Which strings* it runs over is a different question, and running it over every
string argument was wrong: `content`, `new_string` and `pattern` are file content, not paths,
so writing a `.gitignore` listing `.env` was denied with a message saying the denial could not
be overridden. The floor now reads a fixed allowlist of path-typed keys (`file_path`, `path`,
`paths`, `notebook_path`, `cwd`, `command`, …) at any depth of the arguments. The allowlist is
by key rather than by tool, because the tool registry is open: a per-tool table would abstain
on every plugin and MCP tool this build has never heard of.

Each candidate is matched twice — as written, and as `realpathSync` resolves it. A symlink
named `notes.txt` pointing at `~/.ssh/id_rsa` is otherwise read in full, and the matcher never
touched the filesystem. Resolution failure (a path being created, a broken link, an unreadable
parent) falls back to the literal spelling.

The table itself covers the credential stores of the tools an agent actually runs, including a
filename heuristic for a delimited `credential(s)`, `secret(s)` or `token(s)`. That heuristic
excludes source and documentation extensions: denying `src/auth/token.ts` would make any
repository with an auth module unworkable, and an unusable floor gets switched off.

`$DSH_HOME`, the plugin's own `redactionKeyFile` and its `auditLog` are appended to the
resolved table at `apply()`. All three are known then, and none of them had any defence: the
key file is what makes every placeholder hash keyed, the sink is the only evidence a decision
happened, and the harness home holds the provider credentials, the session logs, and the
profiles that decide which plugins load at all.

The harness home is denied by *direction*, not wholesale. Denying reads of the whole directory
also denied `profiles/node_modules/` — the entire installed plugin tree — and every profile's
`cordis.yml`, so debugging a plugin, reading a profile, or pointing the sibling
`dsh-plugin-inspector` at an installed tree hit an unoverridable denial. That is a reason to
uninstall, and uninstalling removes the whole floor. Writes stay denied everywhere under it,
because a prompt-injected agent editing a profile mounts an arbitrary plugin; reads are denied
only for the credential material inside it (`.credentials.yaml`, `sessions/**`, `.env`,
`*.key`, and our own two files), which the built-in table already covered by filename.

The coding-agent entries added later follow the same reasoning applied to a newer set of files.
An `auth.json` or an `mcp.json` under an agent's own directory holds nothing but credentials —
an MCP manifest's `env` is where a server's API keys live — so both are `every-call`, as are
Cursor's `state.vscdb`, `Library/Keychains/**`, `*.tfvars` and `terraform.tfstate`.

A `settings.json` under `~/.claude` or `~/.gemini` is not that. It is configuration, and a user
asking the agent why their own agent behaves a certain way is an ordinary request, so it is
`writes-only`. It is anchored at the *home directory*, resolved at mount for the same reason
`$DSH_HOME` is: the repository-local copy of that file name is edited legitimately and often,
and putting it on an unoverridable floor is how a floor gets switched off. The repository-local
copies are governed by the `ask` tier instead (§18).

A rule therefore carries an `enforcement` field, and `writes-only` is lifted for a tool named
in `READ_ONLY_TOOLS` — an allowlist of query-only tools with the same deny-by-default tail as
`LOCAL_TOOLS`. A shell is not on it: a shell that can `cat` a profile can also rewrite it, and
deciding which of the two a command line does would mean running it. The repo-local policy tier
cannot set `enforcement`, so a workspace can add a deny rule but not narrow one.

Argument secrets are the opposite case. Denying `write` because the content it was asked to
save contains a token would break ordinary work without closing an exfiltration path — the
bytes are going to local disk either way. So argument denial is scoped to tools that can move
data off the machine, and the classification is an **allowlist of local tools with a
deny-by-default tail**: every shell, `run_code`, the web tools, all `mcp__*` tools, and any
tool this build has never heard of are treated as egress-capable.

The shell-command arm inside all of this is advisory and the README says so. Tokenising a
command line catches `cat ~/.ssh/id_rsa` and loses to one glob character. Deciding what a
program will open requires running it.

## 9. The telemetry listener throws rather than degrading

The coordinator dispatches `session-telemetry/record` inside its own containment, and a
throwing listener withholds that one record without reaching the agent loop. That makes
throwing the correct failure mode: a record the plugin could not fully process is a record that
must not be exported. The listener walks `record.body` as JSON rather than switching on the
event type, because `body` is whatever package declared the event and new event types appear
without this plugin knowing them — a total walker is what keeps the listener from being wrong
about a type it has never seen.

Ledger records mirroring `tool/result` have been through §5, which ran before the event was
appended, but only over what that seam could reach; the listener re-scans every record rather
than trusting the event type. Beyond that its value is on `user/message`, `assistant/message`,
`tool/call` arguments, and the `session.cwd` attribute.

Only tier 1 is reachable here — `next()` returns a record, not a promise — so a secret only
`@secretlint/core` recognises survives telemetry export. Webhook URLs are in the sync table for
that reason; the general case is a documented limit, not a fixable one at this seam.

## 10. The repo-local policy tier can only tighten, and a bad one is ignored loudly

A `policyFile` lives in the workspace, so a hostile repository ships one and a prompt-injected
agent can write one. It may add deny patterns, add egress tool names, raise a severity, and
switch a redaction pass on. There is no `disable` key, no removal key, and no way to name
`auditLog`.

Such a key does not make the plugin fail to mount, though — it invalidates the whole file,
which is reported on `process.stderr` and the deployment's logger, then ignored. Aborting
`apply()` was worse in both directions: the README recommends a workspace-relative
`policyFile`, so `dsh` refused to start in every repository that shipped none, and a hostile
repository could remove the entire floor by committing two malformed lines. Neither outcome
can loosen the floor now, and neither is silent.

An added `pattern` is checked before it is compiled: at most 200 characters, and no quantifier
nested inside a quantified group. A repo-authored regular expression runs inside the
**synchronous** guard, where `^(a+)+$` on a 27-character path blocked the event loop for 3.1
seconds — a denial of service any workspace could ship. The check is a heuristic and is
documented as one: no syntactic test proves a pattern runs in linear time, and `(a|a)+` still
backtracks. It rejects the shape that is both easy to write and expensive to run, and the
length cap bounds the rest.

Parsed with `js-yaml` under `JSON_SCHEMA`, so `!!js/function` is a parse error rather than code
execution, and never through the Cordis loader, whose `!!js` support is the reason it must not
read workspace-authored files.

## 11. The E2E harness copies the runtime dependency closure

The template harness copies the plugin into `$DSH_HOME/profiles/e2e/node_modules/<name>` rather
than symlinking, because Node resolves a symlink to its real path and the parent walk would
leave the profile tree. That also puts the plugin's own pnpm store out of reach: a plugin with
runtime dependencies (`@secretlint/core`, `js-yaml`, `@deepseek-ai/schemastery`) cannot resolve
them from there.

The harness therefore walks this package's `dependencies` transitively and copies each
package's real directory (dereferencing pnpm's symlinks) into a flat `node_modules` beside the
installed plugin. Peer dependencies are deliberately excluded: every harness type this package
uses is imported with `import type`, so nothing from `@deepseek-ai/cordis` or the `dsh-*`
packages is emitted as a runtime import, and Cordis must come from the running installation
rather than a copy.

## 12. Coverage: 100% of `src/`, with explicit exemptions

CONVENTIONS §4 adopts upstream's per-file 100% bar for security code, and `vitest.config.ts`
enforces it with `thresholds.perFile`. The aggregate form it used before did not: a project-wide
total lets one uncovered module hide behind every covered one, which is exactly the failure the
per-file bar exists to prevent. These arms use `/* v8 ignore */` with a stated reason, matching
upstream's own convention:

- `mapSecretlintSeverity`'s non-`error` arms — the recommended preset reports only `error`;
  the other arms exist for rules a deployment adds.
- the `Map` emptiness check in `CallCorrelator`'s eviction — reached only past the limit, so
  the map is never empty there.
- the `?? []` fallback in the prepared-scan memo — every string handed to the walkers was
  collected for that memo.
- the `default` arm of the `RepoPolicyLoad` and `AuditFileRead` switches — unreachable while
  those unions stay closed; the arms exist so that adding a variant fails the build.
- the process entry at the bottom of `cli.ts` — instrumenting it would mean importing the
  module as a program. `tests/e2e/report.e2e.ts` runs the built `lib/cli.js` as a subprocess
  instead, which is the only form that proves the `bin` entry and its shebang work.

**Coverage is not evidence that a rule table is right.** A single `it.each` over a table reaches
100% of it while proving only that it was iterated, and the entries are most of what this
package is. `tests/unit/rule-tables.spec.ts` therefore drives every exported table — the tier-1
detectors, the invisible-character classes, the credential paths, the home-anchored rules and
the behaviour-changing config paths — from its own export, with one positive and one near miss
per rule id and a key-set assertion in both directions. A rule added without a fixture fails
three tests rather than shipping untested.

The guard floor's own tests had the opposite defect: `plugin.guards[0]?.(…)` yields `undefined`
when nothing registered a guard, which is also what an abstaining floor returns, so every
"the floor abstains" test passed against no floor at all. The mount helper binds the single
registered guard and throws when it is missing.

## 13. Invisible characters are split into a strip half and a report half

Both halves are `medium`, deliberately: the guard floor denies at `high` and above, so an
invisible character in an argument is never a denial. They are injection *indicators*, not
credentials, and a denial for one would be a false denial with no leak behind it.

What separates the halves is whether the class has a legitimate use. The Tags block is an
invisible ASCII alphabet and a bidi override reorders the display without changing what the
model reads; neither belongs in tool output, so both are replaced. `U+200D` joins emoji
sequences, `U+200E`/`U+200F` appear in real right-to-left text, and a variation selector picks
a glyph — replacing those corrupts legitimate content, so they are counted and left alone. The
count goes into the audit record because a class that is never replaced otherwise leaves no
trace at all.

A replaced run is spliced **exactly**, which is why `Detection` carries `exact`. Every other
span is expanded to the nearest delimiter because tier-2 spans under-cover a secret (§4); doing
that to an invisible character would delete the visible word it hid inside, which is both a
worse result and a false positive an operator cannot check.

The scan is one pass with a combined character class built from the same table the per-class
patterns come from, so the two cannot drift. Cost is in README.md, measured rather than
estimated: clean Latin-1 text is free because every character in the table is above `U+00FF`
and the regular-expression engine rejects the string on its encoding. A crafted 512 KB result
of alternating invisible characters costs 56–113 ms, over the per-result budget; it is
recorded rather than capped, because capping tier 1 would leave a hidden instruction past the
cap unstripped and unreported.

UTS #39 confusables are not attempted. A homoglyph is a visible, legitimately-encoded
character, detecting it needs a data table, and it defeats every rule in this package. README
says so instead of implying coverage.

### Variation selectors split by run length, not by class

The class is `report` because one selector is glyph selection: VS15/VS16 after a base character,
one selector after one ideograph in an Ideographic Variation Sequence. That reasoning does not
extend to a run. GlassWorm encoded executable JavaScript one byte per selector across five
waves — 73 sleeper extensions, the first MCP package compromises — which is the same code
points used as a container rather than as a modifier.

So the isolated rule now matches a *whole* run of one to three, and a second rule strips a run of
four or more. The threshold is justified rather than guessed: an emoji ZWJ sequence separates its
selectors with a joiner, so a legitimate consecutive run stops at one; two has no standard
meaning; four leaves no reading but "these are bytes"; and a payload worth hiding is hundreds of
selectors long, so 4 is a conservative floor rather than a tight one. The isolated rule's
lookarounds are what keep the two from both firing on the same characters, so a long run is one
finding rather than two.

### Terminal control sequences split by lane, not by class

CVE-2026-35651: ANSI sequences in tool titles reached approval prompts **and permission logs**,
so a malicious tool could spoof what the human saw when approving *and* forge the record of it.
The upstream fix was explicitly "strip full CSI, not just SGR". CVE-2026-50642 is the same shape
in filenames and diff metadata. Separately, an `OSC 7` in model output makes a terminal resolve a
host with no tool call at all.

The class does not fit the per-class strip/report split, because whether it is safe to replace
depends on where the string is going:

- **Tool-result text: `report`.** `git diff`, `rg` and `pytest` colourise by default. A `strip`
  action here would rewrite the output of half the commands an agent runs, and the cost of that
  is the plugin being switched off.
- **Anything reaching an audit record: `strip`.** `AuditSink.write` replaces every sequence in
  every string of a record before serialising. This is not redundant with JSON escaping: the
  file holds the six characters `\u001b`, but `dsh-dlp report`, `jq -r` and any log viewer
  parse that back into a live escape, and the strings in a record are not all ours — a tool's
  registered name comes from whatever registered it, including an MCP server.
- **Model-facing and approval-facing reasons.** A denial quotes the tool name through
  `JSON.stringify`, which escapes the byte, and otherwise quotes only rule ids and hex hashes.
  Rule ids can come from the attacker-controlled repo-local tier, so one carrying a control
  sequence invalidates that file at parse time rather than being sanitised later — the same
  fail-loud treatment the rest of that parser gives.

The pattern is the full CSI form (parameter bytes, intermediate bytes, one final byte), the
string-introducer families (OSC, DCS, SOS, PM, APC) with their bodies, every other escape
sequence, and the 8-bit C1 equivalents. An unterminated string introducer matches to the end of
the input, because that is exactly how much of the display it swallows on a real terminal.

Replacement is a visible marker rather than deletion: the lanes that strip are the ones an
operator reads as evidence, and silently deleting the bytes would hide that a forgery was
attempted. `\r`, `\b` and `\f` are deliberately left alone — they have ordinary uses in tool
output and `JSON.stringify` escapes them in the sink.

The class cannot be expressed as a character range, so `UnicodeRule.ranges` is now optional: a
rule without ranges is scanned over the whole input instead of within a combined-class run.

## 14. The output schema is checked before a redacted value is handed back

`ctx.tools.get(name, scope)` returns the live `ToolDefinition`, and `exec.agent` is the scope
key, so `output.schema` is readable from the `tools/post-execute` listener. A schema that pins
the redacted string rejects the placeholder on re-validation, and the registry reports that as
a `ToolOutputError` listing validation violations — an opaque failure for something the plugin
chose to do. Asking first turns it into the same `block` a result that cannot be cleaned
already gets, with the rule id and the keyed hash in the message.

The check re-implements the harness's own validation instead of calling it. Every harness type
this package uses is imported with `import type`, so nothing from `@deepseek-ai/dsh-*` is
emitted as a runtime import; a plugin installed under `$DSH_HOME/profiles/<name>/node_modules`
cannot resolve those packages from there, and the E2E harness deliberately does not copy them
(§11). Importing `validateJsonSchemaValue` would make the plugin fail to load. The enforced
subset is small — `type`, `oneOf`, `properties`, `required`, `additionalProperties`, `items`,
`enum`, `const`, with no `pattern`, `minLength` or `format` — which is what makes a second
implementation reasonable rather than a fork.

It is guarded against being wrong in the direction that costs the user a result: the *original*
value is validated first, and a schema this module rejects before redaction is one it does not
model, so it abstains and the registry decides exactly as it did before. Verified against the
real `read` tool's compiled schema: the original validates, so the check is live rather than
abstaining, and the placeholder passes.

## 15. Remote markdown images are neutralised on `llm/stream`, not left to the client

Finding 001: the web UI renders any absolute `http(s)` markdown image as an `<img src>`
(`packages/client/ui-primitives/src/markdown/render.tsx:54` → `:471-487`), and the repository
sets no Content-Security-Policy. The fetch is issued by the user's browser, so every host-side
surface this plugin owns — the guard, both redaction tiers, the audit sink — is on the wrong
side of it.

**`llm/stream`, and specifically its response side.** The request side of that waterfall is
useless for this: `options` is deep-frozen and `next()` takes no arguments. The returned
`AsyncIterable<StreamChunk>` is not, and a listener may map it. Rewriting there happens before
the agent loop appends `assistant/chunk` and assembles `assistant/message`
(`packages/core/agent-loop/src/agent.ts:349`, `:382`), so the durable log and what the renderer
receives are the same text. Rewriting anywhere later would desynchronise them, and there is no
seam between the log append and the client.

**Per-delta matching alone would not have worked, and we measured that rather than assuming
it.** Adapters stream text in small pieces — the keyless mock uses eight characters — so
`![receipt](https://host/p?d=…)` arrives spread over eight chunks, none of which contains a
whole destination, while the browser renders the accumulation. The listener therefore holds
back a suffix that could still become an image and releases it once the syntax resolves,
flushing before `block-end` and before the terminal `finish` so no text is lost and the emitted
chunks still satisfy the stream grammar (`packages/llm/llm/src/invariant.ts:36-84`, which runs
prepended and therefore validates ours). The holdback is capped: held text is text the user
cannot see, and an unbounded wait would be a worse failure than a missed match.

**The replacement is a non-URL.** `dsh-dlp-blocked-remote-image` makes `new URL()` throw, which
is the renderer's own "not an absolute destination" arm, and that arm renders the alt text in a
`<span>`. Nothing about the response has to be understood for the fetch to stop happening.

**What this does not close, and why it ships anyway.** Reference-style images still render: the
definition they resolve through is shared with ordinary links, so neutralising definitions
would break links, and neutralising every image reference would change output for
destinations the renderer would not have fetched. Alt text containing `]`, and any syntax the
pattern does not model, get through too. Rewriting model output is also a genuine behaviour
change — an answer that legitimately links an image loses it — which is why this is the one
mitigation here with a switch. **The upstream fix is one `img-src` directive**, applied through
the `tapIndex` seam the webserver already has; it covers every syntax, every client and several
neighbouring channels at once. README says so beside the feature.

Raw HTML needed no handling: the renderer emits it as literal text (`render.tsx:261-263`) and
upstream's own fixture pins that (`tests/fixtures/markdown-dom/raw-html-dropped.settled.txt`).
Reasoning text needed none either — the UI renders it as plain text through `ReasoningRow`, not
through `MarkdownText`.

## 16. Tool-call mutation is detected in the guard, and deliberately not prevented

Finding 002: `exec.arguments` is deep-frozen at mint (`packages/core/tools/src/index.ts:1416`)
but the execution object is frozen only at `notifyResult` (`:1660`), so a `tools/pre-execute`
listener can reassign `exec.name` — changing which body runs — after `tool/call` was appended
from the model's own response block (`packages/core/agent-loop/src/tool-calls.ts:167`).

**Snapshot early, compare in the guard.** The guard is the only stage that runs after the whole
waterfall and cannot be out-ordered, and `guardReason(exec)` receives the same object identity
(`packages/core/tools/src/index.ts:1487`), so a `WeakMap` keyed on it — the way the registry
keys its own per-execution state — carries the snapshot across the two stages. The comparison
is synchronous because `ToolGuard` is, which is why the argument comparison is a keyed digest
of a canonical JSON rendering rather than a structural walk.

**Detection, not prevention.** Preventing the rewrite means freezing an object this plugin does
not own, and a blanket freeze is wrong for the same reason upstream's own remediation note
says it is: `dispatchScheduledExecution` deliberately replaces `exec.signal`. So the mutation
still happens; what changes is that the call does not run and the operator finds out.

**Three deliberate abstentions.** A call with no snapshot is not a finding — absence means this
listener never saw the call, and denying on absence would deny traffic we did not observe. A
`deny` or `ask` from another listener is not a finding either: a deny skips the guard entirely,
and an approved ask reaches the guard with an unchanged object. And the snapshot's
`{ prepend: true }` is best-effort by construction, because a later registration with the same
option runs ahead of it; README states that rather than implying a floor.

Not configurable, like the rest of the floor: a deployment that wants the mutation allowed is
asking for a session log that does not describe what ran.

**The upstream fix is better** — `Object.defineProperty(execution, 'name', { writable: false })`
at the mint site, or a scheduler-invariant throw naming the plugin. Either fails at the source
instead of denying downstream of it.

## 17. The telemetry seam's state is reported from the backend's own disclosure

Finding 008: a `session-telemetry/record` listener mounts and never runs under the shipped
`DSH_TELEMETRY_MODE=DISABLED`, because the coordinator that dispatches the waterfall is built
only in `FULL`/`FEEDBACK_ONLY` (`packages/session/session-telemetry-otel/src/index.ts:160-168`,
`:239`, `:243`). Nothing is exported, so nothing leaks; what is lost is the evidence that a
mounted redactor works.

**The mode is read, not guessed.** `SessionTelemetryBackend` declares
`abstract readonly sharing: SessionTelemetrySharingStatus`
(`packages/session/session-telemetry/src/index.ts:160`) precisely so a consumer can ask
backend-independently, and `ctx.get('sessionTelemetry')` reads it without an inject
requirement. `DSH_TELEMETRY_MODE` would have been the wrong thing to read: it is only the base
bundle's default expression for a `mode` a deployment can set directly, and the CLI's
`DSH_TELEMETRY_DISABLED` switch removes the row altogether
(`apps/cli/src/profile-boot.ts:80-83`) — which our own E2E harness sets, and which is how we
found that the absent-backend case needed its own message.

**Two evaluation points, because one is not conclusive.** At mount, only a backend that is
already there answers the question; absence cannot be told from a load order. So absence defers
to the first `session/event`, by which point the harness is running sessions and an absent
backend really means no dispatcher. It reports once either way.

**Informational, on both channels.** `DISABLED` is the correct posture for most deployments, so
refusing to mount would be user-hostile and wrong. It goes to `process.stderr` as well as
`ctx.logger` for the reason §7 already records: the logger's default exporter is an in-memory
ring buffer and no shipped bundle mounts a console exporter, so a logger-only message is
invisible on a stock install. The wording says "nothing is being exported, so this is not a
leak" first, because the failure mode of a scary message here is an operator turning telemetry
*on* to make it stop.

**The upstream fix is better**: one warning from the disabled branch when a hook exists on that
waterfall — the same shape as the `feedback/record` warning already there — helps every
listener, not only this one.

## 18. Behaviour-changing config writes ask, and are deliberately not on the floor

Everything in §8 governs reads. The dominant technique of 2026 is the agent *writing* a file
that changes what happens next time: the Miasma worm's `SessionStart` hooks in
`.claude/settings.json` and `.gemini/settings.json`, an always-apply `.cursor/rules/setup.mdc`,
a `folderOpen` task in `.vscode/tasks.json`, a hijacked `npm test` in `Azure/durabletask` —
GitHub disabled 73 repositories across Azure, microsoft and Azure-Samples over it, 39 of them
inside 38 seconds. CVE-2025-53773, CVE-2026-25725, CVE-2026-33068, CVE-2026-48124,
CVE-2026-26268 and CVE-2025-59041 are the same shape.

**This tier is `ask`, at `tools/pre-execute`, and that is the decision.** The floor is deny-only
and non-negotiable by construction: `ToolGuard` returns `string | undefined` and has no ask arm.
A rule belongs there only if a developer never legitimately trips it. Editing `CLAUDE.md`,
adding a `.github/workflows` job and extending `.vscode/settings.json` are things a developer
asks for constantly, so an unoverridable denial on them produces one outcome — the plugin gets
uninstalled, taking the floor with it. **The cost is that this tier is neutralizable**, exactly
like the breadth tier: a `tools/pre-execute` listener registered ahead of ours can return
without calling `next()` and it never runs. README says so beside the feature rather than
implying a floor.

**Registered ahead of the breadth tier.** Registration order is execution order and each
listener sees what the rest of the chain settled on, so the tier that can only ask has to be
outermost; the other way round, a call that both writes a hook and carries a token would be
asked about instead of denied.

**With no approval service, it abstains.** The registry resolves an `ask` through
`ctx.get('approval')` and keeps the historical degrade to *deny* when nothing is composed. A tier
whose whole justification is "these rules are too false-positive-prone to deny on" must not
become a denial because a deployment has no UI, so it reports once and lets the call through.
The check is at decision time rather than at mount, because by then the harness is running and
an absent service is conclusive rather than a load order — the opposite of §17's problem, and
the reason it needs no deferred evaluation.

**A call the floor will deny is left to the floor.** Any non-allow decision from this waterfall
skips guards entirely (§1), so asking about a call the guard would deny replaces an
unconditional denial with a prompt the user can grant, and files the decision as an ask rather
than as a `guard-deny`. The E2E run found this: a write to `$DSH_HOME/profiles/e2e/cordis.yml`
matches `config-harness-bundle` *and* the floor's `path-dsh-home`, and the transcript came back
saying the user rejected the tool instead of naming the rule. The listener therefore evaluates
the floor first and abstains when it would deny. It is also why the home copy of an agent
settings file (§8) and the repository-local copy behave differently in the same run.

**Matched by name, never against the filesystem.** CVE-2026-25725 worked precisely because the
path did not exist yet, so a rule that only fires on files that are already there misses the
technique entirely.

**Shell command lines are not tokenised here**, unlike in the floor. The floor can afford it
because a credential path in a command line is worth a denial either way; this tier cannot,
because a command line cannot be told apart from a *read* of the same file, and prompting on
`cat .github/workflows/ci.yml` is the false positive that gets the tier switched off. A shell
redirection into one of these files is therefore not covered.

**CVE-2026-21852 is in this table rather than in the detector tiers.** A repo-local settings file
that sets `ANTHROPIC_BASE_URL` — or any `*_BASE_URL` / `*_API_BASE` — sends the user's own key to
whatever host it names. It is neither a path nor a secret: it is a config key whose *value*
redirects a credential. So it is the one rule matched against content-typed arguments, and
content-typed keys are a set of their own, kept away from the floor's path keys in both
directions: the floor must never run its path table over file content (§8), and this rule must
run over nothing else.
