/**
 * The two classifications the guard floor runs on: which paths are credential
 * material, and which tools can move data off the machine.
 *
 * Both tables are security invariants. Neither is settable from `cordis.yml`;
 * the repo-local policy tier may only add to them.
 * @module dsh-dlp/paths
 */

import { posix } from 'node:path'

/** One credential-path pattern. */
export interface CredentialPathRule {
  readonly id: string
  readonly version: number
  /** Matched against a normalized, forward-slash path. */
  readonly pattern: RegExp
}

/**
 * Paths whose contents are credentials. Reading any of them through a tool is
 * denied unconditionally.
 *
 * `$DSH_HOME/.credentials.yaml` is here because core permits it: the harness
 * has no file-read restriction in any mode ("Reads pass through untouched:
 * every mode permits reading"), so the provider token the agent itself
 * authenticates with is agent-readable. That is the gap this table closes.
 */
export const CREDENTIAL_PATH_RULES: readonly CredentialPathRule[] = [
  { id: 'dsh-dlp/path-dotenv', version: 1, pattern: /(^|\/)\.env(\.(?!example$|sample$|template$|dist$)[^/]*)?$/i },
  { id: 'dsh-dlp/path-ssh-dir', version: 1, pattern: /(^|\/)\.ssh(\/|$)/i },
  { id: 'dsh-dlp/path-ssh-key', version: 1, pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i },
  { id: 'dsh-dlp/path-aws', version: 1, pattern: /(^|\/)\.aws\/(credentials|config)$/i },
  { id: 'dsh-dlp/path-dsh-credentials', version: 1, pattern: /(^|\/)\.credentials\.yaml$/i },
  { id: 'dsh-dlp/path-netrc', version: 1, pattern: /(^|\/)\.netrc$/i },
  { id: 'dsh-dlp/path-npmrc', version: 1, pattern: /(^|\/)\.npmrc$/i },
  { id: 'dsh-dlp/path-pypirc', version: 1, pattern: /(^|\/)\.pypirc$/i },
  { id: 'dsh-dlp/path-kubeconfig', version: 1, pattern: /(^|\/)\.kube\/config$/i },
  { id: 'dsh-dlp/path-docker-config', version: 1, pattern: /(^|\/)\.docker\/config\.json$/i },
  { id: 'dsh-dlp/path-gcloud-credentials', version: 1, pattern: /(^|\/)\.config\/gcloud\/[^/]*credential[^/]*$/i },
  { id: 'dsh-dlp/path-keystore', version: 1, pattern: /\.(pem|p12|pfx|jks|keystore)$/i },
] as const

/**
 * Normalize one candidate path for matching: Windows separators become
 * forward slashes, `~` expands to a root-anchored marker, and `..` segments
 * collapse so a traversal cannot hide a credential path from the table.
 * @param candidate - a raw string from tool arguments.
 * @returns the normalized form the rules are matched against.
 */
export function normalizeCandidatePath(candidate: string): string {
  const slashed = candidate.replace(/\\/g, '/')
  const homeExpanded = slashed.startsWith('~/') ? `/~/${slashed.slice(2)}` : slashed
  const stripped = homeExpanded.replace(/^["']|["']$/g, '')
  return posix.normalize(stripped)
}

/**
 * Whether one string names credential material.
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
 * Split one argument string into the substrings worth testing as paths: the
 * whole string, plus each shell-ish token. A `bash` command is a single
 * string argument, so without tokenization `cat ~/.ssh/id_rsa && echo ok`
 * would not match a rule anchored at the end of a path.
 * @param text - one string value taken from tool arguments.
 * @returns the whole string followed by its tokens.
 */
export function pathCandidates(text: string): string[] {
  const tokens = text.split(/[\s;|&<>()"'`,]+/).filter(token => token.length > 0)
  return [text, ...tokens]
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
