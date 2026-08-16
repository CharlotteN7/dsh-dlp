/**
 * The two classifications the guard floor runs on: which paths are credential
 * material, and which tools can move data off the machine.
 *
 * Both tables are security invariants. Neither is settable from `cordis.yml`;
 * the repo-local policy tier may only add to them.
 * @module dsh-dlp/paths
 */

import { realpathSync } from 'node:fs'
import { posix } from 'node:path'

/**
 * Which calls a credential-path rule is enforced for.
 *
 * `every-call` is the default and the only setting a rule protecting
 * credential *contents* may use. `writes-only` exempts the tools
 * {@link READ_ONLY_TOOLS} classifies as unable to change anything: it exists
 * for a directory whose contents are ordinary work to read and dangerous to
 * modify, which is `$DSH_HOME` — it holds the installed plugin tree and every
 * profile's `cordis.yml`.
 */
export type RuleEnforcement = 'every-call' | 'writes-only'

/** One credential-path pattern. */
export interface CredentialPathRule {
  readonly id: string
  readonly version: number
  /** Matched against a normalized, forward-slash path. */
  readonly pattern: RegExp
  /** Defaults to `every-call`; the repo-local tier cannot set it. */
  readonly enforcement?: RuleEnforcement
}

/**
 * File extensions that name source code or documentation rather than a
 * credential store, used by {@link CREDENTIAL_PATH_RULES}'s filename
 * heuristic. Without them `src/auth/token.ts` would be undeniable-file
 * material and ordinary work would stop.
 */
const CODE_EXTENSIONS = 'ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|h|hpp|cc|cpp|cs|swift|kt|md|rst|txt|html|css|scss|sh|bash|zsh|sql|lock|snap|map'

/**
 * Paths whose contents are credentials. Reading any of them through a tool is
 * denied unconditionally.
 *
 * Order matters only for reporting: the first match wins, so the specific
 * rules precede the filename heuristic and an operator sees the precise rule
 * id in the audit record.
 *
 * `$DSH_HOME/.credentials.yaml` is here because core permits it: the harness
 * has no file-read restriction in any mode ("Reads pass through untouched:
 * every mode permits reading"), so the provider token the agent itself
 * authenticates with is agent-readable. That is the gap this table closes.
 */
export const CREDENTIAL_PATH_RULES: readonly CredentialPathRule[] = [
  { id: 'dsh-dlp/path-dotenv', version: 2, pattern: /(^|\/)\.env(\.(?!(?:example|sample|template|dist)(?:\/|$))[^/]*)?(\/|$)/i },
  { id: 'dsh-dlp/path-ssh-dir', version: 2, pattern: /(^|\/)\.ssh[^/]*(\/|$)/i },
  { id: 'dsh-dlp/path-ssh-key', version: 2, pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)([._-][^/]*)?$/i },
  { id: 'dsh-dlp/path-aws', version: 2, pattern: /(^|\/)\.aws(\/|$)/i },
  { id: 'dsh-dlp/path-azure', version: 1, pattern: /(^|\/)\.azure(\/|$)/i },
  { id: 'dsh-dlp/path-dsh-credentials', version: 1, pattern: /(^|\/)\.credentials\.yaml$/i },
  { id: 'dsh-dlp/path-netrc', version: 1, pattern: /(^|\/)\.netrc$/i },
  { id: 'dsh-dlp/path-npmrc', version: 1, pattern: /(^|\/)\.npmrc$/i },
  { id: 'dsh-dlp/path-pypirc', version: 1, pattern: /(^|\/)\.pypirc$/i },
  { id: 'dsh-dlp/path-git-credentials', version: 1, pattern: /(^|\/)\.git-credentials$/i },
  { id: 'dsh-dlp/path-gh-config', version: 1, pattern: /(^|\/)\.config\/gh(\/|$)/i },
  { id: 'dsh-dlp/path-kubeconfig', version: 2, pattern: /(^|\/)(\.kube\/[^/]*|kubeconfig[^/]*)$/i },
  { id: 'dsh-dlp/path-kubernetes-conf', version: 1, pattern: /(^|\/)kubernetes\/[^/]*\.conf$/i },
  { id: 'dsh-dlp/path-docker-config', version: 2, pattern: /(^|\/)(\.docker\/config\.json|\.dockercfg)$/i },
  { id: 'dsh-dlp/path-gcloud-credentials', version: 1, pattern: /(^|\/)\.config\/gcloud\/[^/]*credential[^/]*$/i },
  { id: 'dsh-dlp/path-rclone-config', version: 1, pattern: /(^|\/)rclone\.conf$/i },
  { id: 'dsh-dlp/path-pgpass', version: 1, pattern: /(^|\/)\.pgpass$/i },
  { id: 'dsh-dlp/path-mysql-config', version: 1, pattern: /(^|\/)\.my\.cnf$/i },
  { id: 'dsh-dlp/path-service-account', version: 1, pattern: /(^|\/)[^/]*service[._-]?account[^/]*\.json$/i },
  { id: 'dsh-dlp/path-keystore', version: 2, pattern: /\.(pem|p12|pfx|jks|keystore|key|asc|gpg)$/i },
  { id: 'dsh-dlp/path-credential-name', version: 1, pattern: new RegExp(String.raw`(^|\/)(?!.*\.(?:${CODE_EXTENSIONS})$)[^/]*(credentials?|secrets?|tokens?)([._-][^/]*)?$`, 'i') },
] as const

/**
 * Normalize one candidate path for matching: Windows separators become
 * forward slashes, surrounding quotes come off, `~` expands to a
 * root-anchored marker, `..` segments collapse so a traversal cannot hide a
 * credential path from the table, and a trailing slash is dropped so `.env/`
 * matches the same rule as `.env`.
 * @param candidate - a raw string from tool arguments.
 * @returns the normalized form the rules are matched against.
 */
export function normalizeCandidatePath(candidate: string): string {
  const slashed = candidate.replace(/\\/g, '/')
  const stripped = slashed.replace(/^["']|["']$/g, '')
  const homeExpanded = stripped.startsWith('~/') ? `/~/${stripped.slice(2)}` : stripped
  const normalized = posix.normalize(homeExpanded)
  return normalized.length > 1 ? normalized.replace(/\/+$/, '') : normalized
}

/**
 * Whether one string names credential material. Pure: it never touches the
 * filesystem, so a symlink is matched by the name it was given. The guard
 * calls {@link matchPathArgument} instead, which resolves first.
 * @param candidate - a raw string from tool arguments.
 * @param rules - the rule table; defaults to {@link CREDENTIAL_PATH_RULES}.
 * @returns the first matching rule, or `undefined`.
 */
export function matchCredentialPath(
  candidate: string,
  rules: readonly CredentialPathRule[] = CREDENTIAL_PATH_RULES,
): CredentialPathRule | undefined {
  const normalized = normalizeCandidatePath(candidate)
  return rules.find(rule => rule.pattern.test(normalized))
}

/**
 * Resolve one candidate through the filesystem so a symlink cannot rename a
 * credential file out of the table.
 * @param candidate - a raw string from tool arguments.
 * @returns the canonical path, or `undefined` when it does not resolve.
 */
export function resolveCandidatePath(candidate: string): string | undefined {
  try {
    return realpathSync(normalizeCandidatePath(candidate))
  } catch {
    // ENOENT for a path being created, ELOOP for a broken link, EACCES for an
    // unreadable parent: in every case the literal spelling is all we have.
    return undefined
  }
}

/**
 * Match one path-typed argument against the credential table, by the name the
 * caller used and by what that name resolves to.
 * @param candidate - a raw string from a path-typed tool argument.
 * @param rules - the rule table; defaults to {@link CREDENTIAL_PATH_RULES}.
 * @returns the first matching rule, or `undefined`.
 */
export function matchPathArgument(
  candidate: string,
  rules: readonly CredentialPathRule[] = CREDENTIAL_PATH_RULES,
): CredentialPathRule | undefined {
  const literal = matchCredentialPath(candidate, rules)
  if (literal !== undefined) return literal
  const resolved = resolveCandidatePath(candidate)
  return resolved === undefined ? undefined : matchCredentialPath(resolved, rules)
}

/**
 * Split one shell command into the substrings worth testing as paths: the
 * whole string, plus each shell-ish token. A `bash` command is a single string
 * argument, so without tokenization `cat ~/.ssh/id_rsa && echo ok` would not
 * match a rule anchored at the end of a path.
 *
 * This is advisory only. A shell command is a program, not a path, and any
 * quoting, globbing, substitution or encoding defeats the split — see the
 * "what this is not" section of README.md.
 * @param text - one shell command line taken from tool arguments.
 * @returns the whole string followed by its tokens.
 */
export function pathCandidates(text: string): string[] {
  const tokens = text.split(/[\s;|&<>()"'`,]+/).filter(token => token.length > 0)
  return [text, ...tokens]
}

/**
 * Argument keys whose values name filesystem paths.
 *
 * The guard tests these and nothing else. Running the credential-path table
 * over every string argument matches file *content* — a `.gitignore` listing
 * `.env`, an edit that mentions `id_rsa`, a grep pattern — and denies ordinary
 * work with a message saying it cannot be overridden.
 */
export const PATH_ARGUMENT_KEYS: ReadonlySet<string> = new Set([
  // Names the shipped tools use: `file_path` (read, write, edit), `path` and
  // `paths` (search, lsp, terminal), `cwd` and `workdir` (the shells), `root`.
  'file_path', 'filePath', 'path', 'paths', 'file', 'files', 'filename', 'file_name',
  'notebook_path', 'notebookPath', 'target_file', 'source_path', 'destination_path',
  'source', 'destination', 'directory', 'dir', 'cwd', 'workdir', 'root',
  'output_path', 'input_path',
])

/**
 * Argument keys whose values are shell command lines. Their tokens are tested
 * as paths; see {@link pathCandidates} for why that is advisory.
 */
export const SHELL_ARGUMENT_KEYS: ReadonlySet<string> = new Set(['command', 'cmd', 'script', 'shell_command'])

/** One string worth testing as a path, and how to split it. */
export interface PathArgument {
  readonly text: string
  /** Whether the string is a shell command line rather than a single path. */
  readonly shell: boolean
}

/**
 * Collect the path-typed strings inside one tool's arguments, at any depth.
 *
 * A key names paths for every tool that uses it: the tool registry is open, so
 * a per-tool table would abstain on every plugin and MCP tool this build has
 * never heard of.
 * @param args - the pending call's parsed arguments.
 * @returns each path-typed string, labelled with whether it is a command line.
 */
export function pathArguments(args: unknown): PathArgument[] {
  const found: PathArgument[] = []

  const collect = (node: unknown, shell: boolean): void => {
    if (typeof node === 'string') {
      found.push({ text: node, shell })
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) collect(item, shell)
      return
    }
    if (typeof node === 'object' && node !== null) {
      for (const item of Object.values(node)) collect(item, shell)
    }
  }

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (typeof node !== 'object' || node === null) return
    for (const [key, value] of Object.entries(node)) {
      if (PATH_ARGUMENT_KEYS.has(key)) {
        collect(value, false)
        continue
      }
      if (SHELL_ARGUMENT_KEYS.has(key)) {
        collect(value, true)
        continue
      }
      walk(value)
    }
  }

  walk(args)
  return found
}

/**
 * Tools that provably cannot move data off the machine: they read local
 * state, edit local files, or talk only to the session itself.
 *
 * Anything absent from this set — every shell, `run_code`, the web tools,
 * every `mcp__*` tool, and any plugin tool this build has never heard of — is
 * treated as egress-capable. Unknown defaults to the safe side.
 */
export const LOCAL_TOOLS: ReadonlySet<string> = new Set([
  'read', 'read_image', 'glob', 'grep',
  'write', 'edit', 'str_replace_editor',
  'todo_write', 'ask_user_question',
  'create_goal', 'get_goal', 'update_goal',
  'session_search', 'session_trace',
  'session_event_read', 'session_event_search', 'session_event_trace',
  'list_agents', 'job_list', 'job_output',
  'terminal_list', 'terminal_read',
  'lsp',
])

/**
 * Whether a tool can move data off the machine.
 * @param toolName - the executing tool's registered name.
 * @param extraEgressTools - names the repo-local policy tier added.
 * @returns `true` when the tool is not a known local-only tool.
 */
export function isEgressCapable(toolName: string, extraEgressTools: ReadonlySet<string> = new Set()): boolean {
  if (extraEgressTools.has(toolName)) return true
  return !LOCAL_TOOLS.has(toolName)
}

/**
 * Tools that can only look: they query the filesystem, the language server,
 * the session store or a running job, and have no operation that changes
 * anything.
 *
 * A `writes-only` rule is lifted for these names and for no others. Every
 * shell, `run_code`, every editor, every `mcp__*` tool and any tool this build
 * has never heard of stays on the deny side, so a new tool is denied until it
 * is classified — the same default as {@link LOCAL_TOOLS}, in the same
 * direction.
 */
export const READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  'read', 'read_image', 'glob', 'grep', 'lsp',
  'session_search', 'session_trace',
  'session_event_read', 'session_event_search', 'session_event_trace',
  'list_agents', 'job_list', 'job_output',
  'terminal_list', 'terminal_read',
  'get_goal',
])

/**
 * Whether a tool is known to be incapable of changing anything.
 * @param toolName - the executing tool's registered name.
 * @returns `true` only for a name in {@link READ_ONLY_TOOLS}.
 */
export function isReadOnlyTool(toolName: string): boolean {
  return READ_ONLY_TOOLS.has(toolName)
}

/**
 * The credential-path rules one tool is judged against.
 * @param toolName - the executing tool's registered name.
 * @param rules - the effective rule table.
 * @returns every rule, minus the `writes-only` ones for a read-only tool.
 */
export function rulesForTool(
  toolName: string,
  rules: readonly CredentialPathRule[],
): readonly CredentialPathRule[] {
  if (!isReadOnlyTool(toolName)) return rules
  return rules.filter(rule => rule.enforcement !== 'writes-only')
}
