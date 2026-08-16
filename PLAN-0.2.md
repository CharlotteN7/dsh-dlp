# dsh-dlp 0.2 — "safe to leave on"

Theme: remove false denials and add visibility. No new detection surface, because the
research measured that hygiene and storage features out-adopt cleverer detectors by an
order of magnitude, and because every false denial is a reason to uninstall.

Scope is deliberately small and entirely on verified seams. Sentinel substitution
(`ctx.shellEnv`) is the strategic feature and is **out of scope here** — it lands in 0.4
once the friction items below are done.

## Bar for every item

Unit tests to the existing 100% per-file coverage gate, plus a keyless E2E assertion where
behaviour is user-visible (`CONVENTIONS.md` §5). A regression test must fail before the fix
and pass after; prove it by stashing the change. Never weaken an existing assertion.

---

## D1 — Narrow the `$DSH_HOME` blanket deny into a read/write split

**Problem.** `$DSH_HOME` is denied wholesale to every tool. That directory holds
`profiles/node_modules/` — the entire installed plugin tree — and every profile's
`cordis.yml`. Anyone debugging a plugin, reading a profile, or running our own sibling
`dsh-plugin-inspector` against an installed tree hits an unoverridable denial. This is the
most likely reason a user removes the plugin.

**Change.** In `src/paths.ts` and the table appended at `apply()`:

- **Writes stay denied wholesale.** A prompt-injected agent editing `profiles/*/cordis.yml`
  mounts an arbitrary plugin — the exact threat `dsh-plugin-inspector` documents.
- **Reads narrow to** `$DSH_HOME/.credentials.yaml`, `$DSH_HOME/sessions/**`,
  `$DSH_HOME/.env`, our own `redactionKeyFile` and `auditLog`, and `**/*.key`.

Read vs write is decided by the tool-name classification `paths.ts` already maintains for
egress. **Unknown tools default to the deny side** — a new tool must be classified before it
is trusted with a read.

**Tests.** A read of `$DSH_HOME/profiles/x/cordis.yml` succeeds; a read of
`$DSH_HOME/.credentials.yaml` is denied; a write anywhere under `$DSH_HOME` is denied; an
unclassified tool name is denied.

---

## D2 — Unicode injection indicators

**Problem.** Invisible-character and bidi obfuscation is undetected. The harness strips
directional controls in exactly one place — session titles — never on the tool-result path.

**Change.** A tier-1 (synchronous) single-pass scan, so the telemetry seam gets it free.

- **Strip**: Tags block `U+E0000–U+E007F`, and bidi overrides `U+202A–U+202E`,
  `U+2066–U+2069`. Neither has a legitimate use in tool output.
- **Report but do not strip**: zero-width `U+200B–U+200D`, `U+2060`, `U+FEFF`, and
  variation selectors. `U+200D` appears in legitimate emoji sequences, so stripping it has a
  real false positive. Surface as a `medium` finding.
- Record the whole class in the audit sink as counts, never content.

**Do not** attempt UTS #39 confusables here — it needs a data table and is a different cost
class. A homoglyph defeats every rule we have; say so in the README rather than implying
coverage.

**Budget.** Measured at 0.001 ms per 512 KB clean, 0.92 ms with 7,653 hits. Well inside the
≤10 ms/result budget. Re-measure and record the number.

---

## D3 — `dsh-dlp report` CLI, plus the logger fix

**Problem A.** The audit JSONL is the only evidence a decision happened, and nothing reads
it. A user cannot answer "what did this block today?"

**Problem B — a live defect.** `ctx.logger`'s default exporter is an in-memory 1000-entry
ring buffer and **no shipped bundle mounts a console exporter**. Our invalid-policy report
and swallowed audit-sink write failures are therefore silently invisible on every stock
install. This contradicts two ADR claims.

**Change.**

- Add a `bin` entry `dsh-dlp report [--since] [--session] [--would-have]` that reads the
  audit JSONL directly. No harness dependency at all — precedented by `dsh-inspect`.
- Route `apply()`-time misconfiguration and audit-sink write failures to `process.stderr`
  **in addition to** `ctx.logger`. `process.stderr` is what the headless runner itself uses.
- Correct the two ADR claims that say these are "reported on the deployment's logger".

**Out of scope.** A `/dsh-dlp` slash command. `ctx.commands` is registered in the base
bundle, but the only callers of `commands.execute` are browser-client packages — headless,
ACP and the JSON-RPC SDK have no command surface. It would be a Web-client-only bonus, so it
is not worth the surface in this release.

---

## D4 — Pre-validate the placeholder against `output.schema`

**Problem.** Replacing a canonical value can violate a constrained `output.schema` and turn
a redaction into an opaque `ToolOutputError`. That is a bad failure for something the plugin
chose to do.

**Change.** `ctx.tools.get(name, exec.agent)` returns the live `ToolDefinition`, so
`output.schema` is readable from the `tools/post-execute` listener. Validate the redacted
value first; on failure return `block` with the existing `withheldFeedback` text instead of
letting the registry throw. Same security outcome, comprehensible message.

---

## D5 — Documentation corrections

Three statements in `README.md`/`PLAN.md` are now known to be too strong or wrong:

1. **"Outbound prompt redaction is impossible"** is imprecise. It is true for `llm/stream`
   (options arrive deep-frozen, `next()` takes no arguments). It is **not** true for inbound
   messages: `agent/pre-step` is an async waterfall returning
   `{ kind: 'enter'; messages }`, and the only production append of `user/message` happens
   *after* it. State the accurate rule: already-logged history cannot be rewritten; a
   not-yet-logged inbound message can.
2. **The `ctx.logger` claims** — see D3.
3. **Restore-at-execution is achievable** via `ctx.shellEnv`, for `bash`/`pwsh` only. Record
   it as planned work rather than leaving the README implying it is impossible.

Also: state plainly that a homoglyph defeats every injection rule, and that entropy
detection was measured and rejected as a default (Shannon entropy is bounded by log₂L, so a
20-char token can never exceed 4.32; at zero-FP thresholds the miss rate is 100% for
anything ≤22 chars).
