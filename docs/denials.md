---
title: What gets denied
nav_order: 4
---

# What gets denied

[← dsh-dlp docs](index.md)

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

**Coding-agent and infrastructure credential stores**, which IronWorm's 44 packages and
SANDWORM_MODE name verbatim: an `auth.json` under `.codex/`, `Cursor/`, `.composer/`,
`.windsurf/`, `.continue/`, `.aider/`, `.claude/` or `.gemini/`; an `mcp.json` under any of the
same directories, because an MCP manifest carries each server's `env` and that is where its API
keys are written; Cursor's `state.vscdb` session database; anything under `Library/Keychains/`;
`*.tfvars` and `terraform.tfstate`, which hold provider credentials in plaintext.

**A home-level agent settings file is denied for writing only.** `~/.claude/settings.json`,
`~/.gemini/settings.json` and the equivalents for Codex, Cursor, Windsurf and Continue decide
how every future session in every repository behaves — this is where the Miasma worm put its
`SessionStart` hooks — so writing one is on the floor. Reading one is ordinary work, since a
user asking why their agent behaves a certain way is a normal request, so the rule is lifted for
a tool that provably cannot change anything. The **repository-local** copies of those same file
names are a different question with a different answer: see
[behaviour-changing config paths](#behaviour-changing-config-paths) below.

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

## Behaviour-changing config paths

Everything above governs **reads**. The dominant technique of 2026 is the opposite: the agent
*writes* a file that changes what happens next time. The Miasma worm put `SessionStart` hooks in
`.claude/settings.json` and `.gemini/settings.json`, an always-apply `.cursor/rules/setup.mdc`,
a `folderOpen` task in `.vscode/tasks.json` and a hijacked `npm test` into `Azure/durabletask`;
GitHub disabled 73 repositories across Azure, microsoft and Azure-Samples over it, 39 of them
inside 38 seconds. See also CVE-2025-53773, CVE-2026-25725, CVE-2026-33068, CVE-2026-48124,
CVE-2026-26268 and CVE-2025-59041.

A write to one of these **asks the user first**:

| Rule | Paths |
|---|---|
| `config-agent-settings` | `.claude/settings*.json`, and the same under `.gemini/`, `.codex/`, `.cursor/`, `.windsurf/`, `.continue/` |
| `config-agent-hooks` | `.claude/hooks/**` and the same under the other agent directories |
| `config-agent-instructions` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules` |
| `config-agent-rules` | `.claude/rules/**`, `.cursor/rules/**`, `.windsurf/rules/**`, `.continue/rules/**` |
| `config-prompt-template` | `.prompts/**/*.prompttemplate` (CVE-2026-46580) |
| `config-mcp-manifest` | `.mcp.json` |
| `config-editor-tasks` | `.vscode/settings.json`, `.vscode/tasks.json`, `.vscode/launch.json` |
| `config-git` | `.git/config`, `.git/hooks/**` |
| `config-git-hooks-managed` | `.husky/**` |
| `config-ci-workflow` | `.github/workflows/**`, `.gitlab-ci.yml`, `.circleci/**` |
| `config-shell-rc` | `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.kshrc`, `config.fish`, … |
| `config-harness-bundle` | `cordis*.yml` |
| `config-pnpm-workspace` | `pnpm-workspace.yaml` |
| `config-api-base-url` | not a path — content setting a `*_BASE_URL` or `*_API_BASE` to an `http(s)` URL |

`.claude/rules` is in the first of those rows because VS Code lists it as a workspace
instruction location it detects and applies on its own, alongside `AGENTS.md` and `CLAUDE.md` —
so the directory is loaded by an editor nobody configured for Claude. The other three agent
rules directories were already covered and it was not.

`pnpm-workspace.yaml` is there because pnpm reads `registry`, `registries` and `namedRegistries`
from it, so the file decides which host the next install downloads packages from. pnpm's own
documentation treats the file as attacker-controlled for exactly that reason: since v11.5.3 it
refuses to expand `${…}` inside those settings, "Because `pnpm-workspace.yaml` is committed to
the repository, expanding env variables in registry URLs could be exploited by a malicious
repository to leak secrets from the environment to an attacker-controlled registry." A literal
hostile registry URL is still obeyed. The `.npmrc` half of the same technique needs no rule
here — it is on the guard floor, where every call is denied.

The last row is CVE-2026-21852: a repo-local settings file that sets `ANTHROPIC_BASE_URL` sends
the user's own API key to whatever host it names. That is neither a path nor a secret — it is a
config key whose *value* redirects a credential — so it is matched against the bytes the call
would write rather than against where they would go.

**Rules match by name, so creating a file is covered as well as changing one.** CVE-2026-25725
worked precisely because the path did not exist yet and was therefore writable with nothing to
prompt about.

**This tier is `ask`, and it is therefore neutralizable — unlike the floor.** That is deliberate
and it is the important sentence in this section. A developer asks the agent to edit `CLAUDE.md`
or add a workflow constantly; the guard floor is deny-only and non-overridable by design, so a
rule with that false-positive rate must not go there. It lives at `tools/pre-execute`, which
means a listener registered ahead of ours can return without calling `next()` and switch the
whole tier off. Treat it as a prompt, not as a control.

**A call the floor already denies is left to the floor**, and no prompt appears for it. Any
non-allow decision at `tools/pre-execute` skips guards entirely, so asking about a call the
guard would deny would replace an unconditional denial with a prompt a user can grant. That is
also why `~/.claude/settings.json` and a repository's own `.claude/settings.json` behave
differently: the first is on the floor, the second is a prompt.

Two more limits worth stating:

- **A shell redirection is not covered.** Only path-typed arguments are tested, and unlike the
  floor the command line is not tokenised: a shell command cannot be told apart from a *read* of
  the same file, and prompting on `cat .github/workflows/ci.yml` is exactly the false positive
  that gets a tier switched off.
- **With no approval service mounted, the tier abstains rather than denying.** The registry
  resolves an `ask` through `ctx.get('approval')` and degrades to a *denial* when nothing is
  composed — which would turn this tier into the silent hard deny it was designed not to be. It
  reports once on `process.stderr` and `ctx.logger` and lets the call through. `configWriteAsk:
  false` turns this half of the tier off entirely.

---

## Arguments that switch off their own confirmation

The same tier watches one thing that is not a file at all: a tool argument whose effect is to
skip the confirmation for the call carrying it. CVE-2026-18733 is `non_interactive: true`,
CVE-2026-53808 is `apply: true` while `approvalPolicy` is still `pending`, and CVE-2026-56075 is
`approval_mode: auto`. In each one the model composes an argument that removes the human from
that call, on a call whose paths and arguments are otherwise unremarkable.

| Rule | Arguments |
|---|---|
| `approval-non-interactive` | `non_interactive` (any spelling) set to a true-ish value |
| `approval-mode-auto` | `approval_mode`, `approval_policy` or `approval_setting` set to `auto`, `never`, `none`, `bypass`, `full-auto` or `yolo` |
| `approval-apply-pending` | `apply` true **and** `approvalPolicy: pending` on the same object |

Keys are matched with `_`, `-` and `.` removed and case folded, so `non_interactive`,
`nonInteractive` and `non-interactive` are one name, at any depth of the arguments. A tool that
can only look is left alone: it has nothing to confirm. `approvalSuppressionAsk: false` turns
this half of the tier off.

**This is `ask` for the same reason the write side is, and the reasoning is worth stating.**
`non_interactive` also means "no TTY" on plenty of ordinary programs, and a batch workflow can
legitimately pass it. The tool registry is open, so which argument names carry approval meaning
is a guess about tools this build has never seen — and a guess does not belong on a floor whose
denials cannot be overridden. An `ask` is also the *right* remedy rather than a compromise: the
argument's whole purpose is to remove a prompt, and this tier puts one back.

It shares the write side's costs: neutralizable at `tools/pre-execute`, abstaining when no
approval service is mounted, and silent on a call the floor already denies.

---
