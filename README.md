# dsh-dlp

Data-loss prevention for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness),
built as an out-of-repo plugin.

📖 **[Full documentation](https://charlotten7.github.io/dsh-dlp/)**

## What it does

1. **Denies credential-file access and secrets bound for the network** — unconditionally, from
   `ctx.tools.guard()`, testing path-typed arguments against a table of credential stores and
   following symlinks first.
2. **Redacts secrets out of tool results** before the model reads them and before the session log
   records them, withholding a result it cannot clean.
3. **Redacts secrets out of the messages a step enters with** — the context a listener splices
   in (the workspace `AGENTS.md`/`CLAUDE.md` chain, a captured tmux pane, a hook's
   `additionalContext`, a skill body a `/name` token loaded) and the input the loop claimed from
   the inbox that the user did not type (a `dsh-webhook` delivery's third-party payload, a
   settled subagent result, an agent relay). All of it reaches the model and the durable log
   through `agent/pre-step` without ever being a tool result. A message whose `source.kind` is
   `user` is exempt below `aggressiveness: high`; at `high` the user's own typed prompt is
   redacted too, because this plugin cannot know which provider the request is bound for. The
   `agent/inbox/spliced` delivery record keeps a delivery's original text, which is deliberate —
   it derives no model message, and an operator investigating a webhook incident needs to read
   what was actually delivered.
4. **Redacts secrets out of exported telemetry**, closing a hole where `DSH_TELEMETRY_MODE=FULL`
   ships message text, tool arguments, results and workspace paths in the clear.
5. **Detects payment card numbers** — issuer range, a length that issuer assigns, and a Luhn
   check digit — so cardholder data does not reach a third-party model in a tool result, a
   spliced file, exported telemetry, or (at `aggressiveness: high`) a prompt someone typed.
6. **Strips invisible characters that carry hidden instructions** — the Tags block, bidi
   overrides, runs of variation selectors — and strips terminal control sequences from the audit
   lane so a tool result cannot forge its own audit record.
7. **Neutralises remote markdown images in assistant output** and detects a tool call another
   plugin rewrote after the session log recorded it.
8. **Asks before the agent writes a file that changes future behaviour** — agent settings and
   hooks, `CLAUDE.md`, `.claude/rules/**` and the other agent rules directories, prompt
   templates, `.vscode/tasks.json`, `.mcp.json`, git hooks, CI workflows, shell startup files,
   `pnpm-workspace.yaml` — and before it writes a `*_BASE_URL` that would redirect a provider
   credential.
9. **Asks before a call switches off its own confirmation** — `non_interactive: true`,
   `approval_mode: auto`, an `apply` whose approval is still pending. Both `ask` tiers are
   prompts rather than controls: they live at `tools/pre-execute`, they can be neutralised, and
   they abstain wherever the approval seam prompts nobody — which includes every install under
   `DSH_PERMISSION_MODE=danger-full-access` and a stock headless install under any mode.
10. **Writes an audit record for every decision.** A redaction or denial names the rule, its
    version, the offsets and a keyed hash; the three kinds with no matched region to describe —
    an ask, a rewritten call, a neutralised image — carry a rule id, the changed field names or
    the destination hostname instead. Never the secret, never the path or command that matched.
    `dsh-dlp report` reads it back.

## What this is not

**This is not a containment boundary.** The plugin runs in-process, at the agent's own uid.
Anything the agent can execute — a `bash` command, a `run_code` program, a mounted MCP server —
can read every file the guard denies and open its own sockets without the plugin seeing anything.
It closes the path where *the model* asks for credential material through a tool. It does not stop
code that is already running. If you need containment, that is the sandbox, `landlock-run`,
filesystem permissions and egress firewalling.

Three limits worth knowing before you rely on it:

- **Only the guard floor is unconditional.** Every other seam can be neutralised by a listener
  registered ahead of ours. `ctx.tools.guard()` is order-independent only because it has no allow
  arm. Result redaction registers with `{ prepend: true }` so it gets the last word over
  listeners already registered — but a listener registering after it with the same option lands
  ahead of it again.
- **The shell-command arm is advisory pattern-matching.** It tests the whole command line and
  each of its tokens, so a credential path left *spelled* in the command is caught whatever
  program would open it: `python3 -c "open('~/.ssh/id_rsa')"` is denied. Changing the spelling
  defeats it — one glob character, quote-splitting, `find -exec`, a substitution that assembles
  the path from pieces, a base64 round-trip, each verified. **Do not count this arm as a
  control.**
- **Detection is pattern-based.** No entropy rule (measured, not assumed: the lowest
  false-positive-free threshold cannot flag anything shorter than 64–66 characters). Encoded
  forms pass. A homoglyph defeats every rule in this package. The card rule is Luhn-validated
  and range-checked and found nothing across 272,635 lines of real source and docs, but
  a *uniformly random* 16-digit number trips it 2.7% of the time and Maestro is not covered.

[The full list of limits →](https://charlotten7.github.io/dsh-dlp/)

## Install

A profile carrying only `@deepseek-ai/dsh-base` has no agent loop, so add a runnable bundle
alongside it or there is nothing for this plugin to guard:

```sh
dsh plugin --profile <name> add @deepseek-ai/dsh-headless@0.1.0-rc.6
dsh plugin --profile <name> add dsh-dlp
dsh --profile <name> --dump-config      # the dsh-dlp row should appear
```

Any harness from `0.1.0-rc.6` onwards in the `0.1.x` line works, prereleases included. CI drives
the end-to-end suite against every published rc the peer ranges admit — `0.1.0-rc.6`, `rc.7`,
`rc.8`, `0.1.1-rc.1`, `0.1.1-rc.2`. The `0.1.2` prerelease line is watched by a non-blocking job
line without running it end to end.

Pin `@deepseek-ai/dsh-headless` explicitly — its npm `latest` tag still points at `0.0.1-rc.1`.
The package ships a `cordis.patch.yml` bundle layer, so listing it in `dsh.profile.bundles` mounts
it with working defaults.

**Install from the registry or a packed tarball, not from a git spec:** `lib/` is a build output
git does not carry and no `prepare` script rebuilds it, so a git-spec row mounts and then fails to
load.

## Configure

```yaml
- id: dsh-dlp
  config:
    auditLog: /var/log/dsh-dlp.audit.jsonl
    redactionKeyFile: /var/lib/dsh/dsh-dlp.redaction-key
    policyFile: ./.dsh-dlp.yml        # optional, lowest trust
    aggressiveness: medium            # low | medium | high
    breadthTier: true
    resultRedaction: true
    telemetryRedaction: true
    stepContextRedaction: true
    claimedInputRedaction: true
    configWriteAsk: true
    approvalSuppressionAsk: true
```

`redactionKeyFile` is created on first mount with 32 random bytes at mode `0600`. Keep it out of
version control — it is what makes a placeholder's hash keyed rather than a bare digest anyone
holding a candidate secret could confirm.

**`aggressiveness` is one word for how far redaction reaches.** `low` guarantees nothing and lets
each toggle stand alone; `medium` — the default — guarantees every pass is on and that no toggle
can take one away; `high` adds the user's own typed prompt to what is redacted. It composes with
the toggles rather than overriding them: at `medium` and `high` a toggle set to `false`
contradicts the level and **fails the mount** with the fix in the message, rather than one setting
quietly beating the other.

> **Upgrading from 0.9.0.** The default `medium` matches the shipped toggle defaults exactly, so
> an install that never wrote a toggle is unchanged. An install that set any redaction toggle to
> `false` now refuses to mount; add `aggressiveness: low` to the same row and it means what it
> meant before. `high` is opt-in.

**The guard floor has no configuration.** Credential-path denial and secret-argument denial are
security invariants, not deployment-varying tunables. A repo-local `policyFile` is the lowest
trust rank and may only *tighten*: add deny patterns, add egress tool names, raise a severity,
switch a pass on. It cannot reach `aggressiveness` — raising the level would let a hostile
workspace put placeholders into the user's own prompt. Any downgrade makes the whole file
invalid.

[Configuration reference →](https://charlotten7.github.io/dsh-dlp/configuration.html) ·
[What gets denied →](https://charlotten7.github.io/dsh-dlp/denials.html) ·
[Redaction and detection →](https://charlotten7.github.io/dsh-dlp/redaction.html)

## Reading the audit log

```sh
dsh-dlp report                       # everything in the audit sink
dsh-dlp report --since 24h
dsh-dlp report --session <id>
dsh-dlp report --would-have          # everything except the denials
```

A redaction or denial record carries a rule id, rule version, span offsets and a keyed hash —
never the matched value. An ask carries its rule id, a rewritten call the names of the fields
that changed, and a neutralised remote image the destination hostname in the clear; none of
those has a matched region to hash.

[Audit record format →](https://charlotten7.github.io/dsh-dlp/audit.html)

## Mitigations for defects in the harness itself

Three registrations work around defects in DeepSeek Harness rather than in your configuration:
remote markdown images in assistant output, a tool call rewritten between `tools/pre-execute` and
the guard, and a telemetry redactor that cannot run under the shipped default. **None of them
closes its channel** and an upstream fix is better in all three cases.

[What each one does and does not close →](https://charlotten7.github.io/dsh-dlp/harness-mitigations.html)

## Development

```sh
nvm use 22           # Node ^22.19.0 || >=24, and pnpm 11
pnpm install
pnpm run typecheck
pnpm run test:coverage
pnpm run test:e2e    # boots a real dsh against a mock model; no API key
```

Coverage is gated at 100% per file: this is a security control, so an untested branch in a deny
path is an unproven deny path.

Design decisions and their rationale live in [ADR.md](ADR.md). Security policy is in
[SECURITY.md](SECURITY.md).

## License

MIT
