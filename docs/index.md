---
title: Scope and limits
nav_order: 1
---

# Scope and limits

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
- **The shell-command arm is advisory pattern-matching.** A `bash` command line is tested
  whole, and then split on shell-ish separators with each token tested as a path. What that
  covers is any command *spelling* a credential path, whatever program would open it:
  `python3 -c "import os;print(open(os.path.expanduser('~/.ssh/id_rsa')).read())"`,
  `node -e "…readFileSync('~/.aws/credentials')…"`, `curl -F f=@~/.ssh/id_rsa` and
  `cat $(printf '%s' ~/.ssh/id_rsa)` are all denied — the interpreter is irrelevant, and so is
  a substitution that still ends up quoting the path in full. What defeats it is anything that
  changes the spelling, each verified to read the file with the guard abstaining:
  `cat ~/.netr?` (one glob character), `cat ~/.s""sh/id_r""sa` (quote-splitting),
  `find ~ -name 'id_*' -exec cat {} +` (the path is never written), `a=~/.ss; b=h/id_r; c=sa;
  cat $a$b$c` (assembled from pieces), and a base64 round-trip of the path. **Do not count
  this arm as a control.** A shell command is a program, not a path, and the only way to
  decide what it will open is to run it. If the agent has a shell, credential files need
  filesystem permissions or a sandbox, not this plugin.
- **Tool arguments are never masked.** Model-visible implies logged: arguments are already in
  the session log and already presented to the model, so rewriting them would desynchronise
  the log from what actually ran. Argument-level DLP here is *denial with a reason the model
  can act on*.
- **Already-logged history cannot be rewritten; a not-yet-logged inbound message can.** At
  `llm/stream` the options are deep-frozen and `next()` takes no arguments, so a request the
  agent has assembled goes out as it stands and a secret already in the conversation reaches
  the provider. (The same waterfall's *response* side is writable, and that is where remote
  image destinations are neutralised — see below.) That is not the whole rule, though: `agent/pre-step` is an async waterfall
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
- **An approval-suppressing argument is recognised by name.** `non_interactive`,
  `approval_mode` and an `apply` beside a pending `approvalPolicy` are the three published
  shapes; a tool that skips its confirmation under some other argument name is not covered, and
  the registry is open, so this list is a floor on what is known rather than a description of
  what exists.
- **`additionalContexts` are not scanned.** They are model-visible `UserMessage` payloads and
  this release does not redact them.
- **Local writes are out of scope.** A `write` or `edit` into a synced directory moves data off
  the machine without going through an egress-capable tool.
- **Telemetry redaction covers a mounted backend's records only.** A second exporter mounted
  outside the `session-telemetry/record` waterfall is not covered.
- **`$DSH_HOME` is readable by a read-only tool.** Profile manifests and the installed plugin
  tree are ordinary work to read, so which plugins a profile loads is model-visible. Only writes
  are denied wholesale there, plus reads of the credential material inside it.
