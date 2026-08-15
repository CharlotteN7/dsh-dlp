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
both edges sit on whitespace or a string boundary, and overlapping spans merge into one
placeholder attributed to the strictest rule that touched it. Over-redaction — the key's name
disappearing along with its value — is the safe direction. `tests/unit/redaction.spec.ts`
pins the behaviour against the real scanner output rather than a fixture, so a future
secretlint release that fixes the range will not silently un-pin it.

Residual: a secret containing whitespace could still be split across two expansions. Recorded
in PLAN.md §8.

## 5. Arm selection at `tools/post-execute`

```ts
type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[]; value?: never; … }
  | { kind: 'accept'; value: JsonValue; content?: never; … }
  | { kind: 'block'; feedback: ContentBlock[]; … }
```

A successful result with a `value` takes the **value** arm. The registry re-validates
`output.schema`, re-runs `output.render()` and re-derives `output.presentationMeta()`, so one
replacement redacts the canonical value, the model-facing content, and the card the UI persists
in `meta`. The E2E run confirms all three: the `tool/result` event's rendered text and its
`meta.lines[1].text` both carry the placeholder.

A failed result takes the **content** arm, because `accept{value}` throws a `TypeError` on a
failed result. Error text is exactly where a leaked token hides — a stack trace quoting a
command line, a provider error echoing a token — so the content arm is not a consolation
prize. The documented cost is that the canonical `value` is untouched on that arm ("content
replacement is presentation policy, not confidentiality policy"), which matters for a
`run_code` program that receives the value directly. Recorded as a limitation rather than
papered over.

The two arms are mutually exclusive at runtime — the registry runs an `Object.hasOwn` check and
throws a `TypeError` if both are present — so the implementation builds exactly one, and a unit
test asserts it never builds both.

**Composition:** the listener `await next()` first and redacts *the decision that came back*,
never the original `result`. Redacting the original would silently discard a downstream
listener's own replacement.

### The probe

A bare `accept` on a clean result is the common case and must stay cheap. The listener first
scans one probe string — the serialized value plus the rendered text — and returns immediately
when it is clean. That is a single `lintSource` call per tool result. Only when the probe hits
does it scan the individual strings, capped at 128 tier-2 scans per result (a `read` of a large
file arrives as thousands of separate line strings); the rest fall back to tier 1 and the audit
record is marked `truncatedScan`.

A probe hit that no individual string reproduces — a secret split across two JSON fields, so it
exists only in the serialization — falls through to the content arm rather than being dropped.
A unit test pins that path with a PEM block split across three fields.

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

**A sink write failure is logged and swallowed.** Turning it into a denial would trade a
confidentiality control for an availability outage — a full disk would make every tool call
fail — and a throwing guard would also skip `tools/post-execute` and disable redaction. The
verdict never depends on whether the record was written.

## 8. Credential-path denial applies to every tool, argument denial only to egress tools

A shell that can `cat` a key can also copy it, so the path table is enforced regardless of the
tool's name. That does deny `write` to `.env`, which is an ordinary setup operation; the
over-denial is deliberate and documented rather than carved out, because a carve-out on a
security invariant is an attack surface.

Argument secrets are the opposite case. Denying `write` because the content it was asked to
save contains a token would break ordinary work without closing an exfiltration path — the
bytes are going to local disk either way. So argument denial is scoped to tools that can move
data off the machine, and the classification is an **allowlist of local tools with a
deny-by-default tail**: every shell, `run_code`, the web tools, all `mcp__*` tools, and any
tool this build has never heard of are treated as egress-capable.

## 9. The telemetry listener throws rather than degrading

The coordinator dispatches `session-telemetry/record` inside its own containment, and a
throwing listener withholds that one record without reaching the agent loop. That makes
throwing the correct failure mode: a record the plugin could not fully process is a record that
must not be exported. The listener walks `record.body` as JSON rather than switching on the
event type, because `body` is whatever package declared the event and new event types appear
without this plugin knowing them — a total walker is what keeps the listener from being wrong
about a type it has never seen.

Ledger records mirroring `tool/result` are already clean, because §5 ran before the event was
appended. The value the listener adds is on `user/message`, `assistant/message`, `tool/call`
arguments, and the `session.cwd` attribute.

## 10. The repo-local policy tier can only tighten, and says so loudly

A `policyFile` lives in the workspace, so a hostile repository ships one and a prompt-injected
agent can write one. It may add deny patterns, add egress tool names, raise a severity, and
switch a redaction pass on. There is no `disable` key, no removal key, and no way to name
`auditLog` — those are not ignored, they are **load-time errors**, because an ignored key looks
like a working configuration to whoever wrote it.

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

## 12. Coverage: 100% of `src/`, with three explicit exemptions

CONVENTIONS §4 adopts upstream's per-file 100% bar for security code, and `vitest.config.ts`
enforces it. Three arms use `/* v8 ignore */` with a stated reason, matching upstream's own
convention:

- `mapSecretlintSeverity`'s non-`error` arms — the recommended preset reports only `error`;
  the other arms exist for rules a deployment adds.
- the `Map` emptiness check in `CallCorrelator`'s eviction — reached only past the limit, so
  the map is never empty there.
- the `?? []` fallback in the prepared-scan memo — every string handed to the walkers was
  collected for that memo.
