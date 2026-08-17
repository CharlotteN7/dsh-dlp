/**
 * The `ask` tier: files whose contents decide how the agent, the editor or CI
 * behaves next time, and the one config *key* whose value redirects a
 * credential.
 *
 * This tier is deliberately **not** on the guard floor, and that is the whole
 * design. `ctx.tools.guard()` has no `ask` arm and cannot be overridden, so a
 * rule that lands there must be one a developer never legitimately trips. A
 * developer asks the agent to edit `CLAUDE.md`, add a `.github/workflows`
 * job or extend `.vscode/settings.json` constantly. Putting those on an
 * unoverridable floor produces a plugin that gets uninstalled, which removes
 * the floor as well.
 *
 * The cost is stated rather than hidden: `tools/pre-execute` is neutralizable.
 * A listener registered ahead of this one can return without calling `next()`
 * and this tier never runs. Only the guard floor is order-independent.
 * @module dsh-dlp/config-writes
 */

import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { isReadOnlyTool, normalizeCandidatePath, pathArguments } from './paths.ts'
import { nestedStrings } from './redaction.ts'

/** What a behaviour-config rule is matched against. */
export type ConfigMatch =
  /** A path-typed argument: the file the call would create or change. */
  | 'path'
  /** A content-typed argument: the bytes the call would write. */
  | 'content'

/** One file, or one written value, that changes what happens next time. */
export interface ConfigWriteRule {
  readonly id: string
  readonly version: number
  readonly match: ConfigMatch
  readonly pattern: RegExp
  /** What the file or value does, quoted in the prompt the user answers. */
  readonly effect: string
}

/**
 * Paths whose contents change future behaviour, and the config key whose value
 * redirects credentials.
 *
 * Every path here was used in the wild. The Miasma worm wrote `SessionStart`
 * hooks into `.claude/settings.json` and `.gemini/settings.json`, an
 * always-apply `.cursor/rules/setup.mdc`, a `folderOpen` task into
 * `.vscode/tasks.json`, and a hijacked `npm test` into `Azure/durabletask`;
 * GitHub disabled 73 repositories across Azure, microsoft and Azure-Samples
 * over it, 39 of them inside 38 seconds. See also CVE-2025-53773,
 * CVE-2026-25725, CVE-2026-33068, CVE-2026-48124, CVE-2026-26268 and
 * CVE-2025-59041.
 *
 * The rules match by name, never by what is on disk, so a file the call is
 * about to *create* is matched exactly like one it would change:
 * CVE-2026-25725 worked precisely because the path did not exist yet and was
 * therefore writable without any prompt.
 */
export const CONFIG_WRITE_RULES: readonly ConfigWriteRule[] = [
  {
    id: 'dsh-dlp/config-agent-settings',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.(claude|gemini|codex|cursor|windsurf|continue)\/settings[^/]*\.json$/i,
    effect: 'agent settings, which can register hooks that run on every future session',
  },
  {
    id: 'dsh-dlp/config-agent-hooks',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.(claude|gemini|codex|windsurf|continue)\/hooks(\/|$)/i,
    effect: 'an agent hook, which runs on a session event without the model asking for it',
  },
  {
    id: 'dsh-dlp/config-agent-instructions',
    version: 1,
    match: 'path',
    pattern: /(^|\/)(CLAUDE|AGENTS|GEMINI|\.cursorrules|\.windsurfrules)(\.md)?$/i,
    effect: 'standing instructions every future session in this repository reads',
  },
  {
    id: 'dsh-dlp/config-agent-rules',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.(cursor|windsurf|continue)\/rules(\/|$)/i,
    effect: 'an always-apply rules file every future session in this repository reads',
  },
  {
    id: 'dsh-dlp/config-mcp-manifest',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.mcp\.json$/i,
    effect: 'the MCP manifest, which decides which servers the agent starts and with what environment',
  },
  {
    id: 'dsh-dlp/config-editor-tasks',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.vscode\/(settings|tasks|launch)\.json$/i,
    effect: 'editor configuration, which can run a task the moment the folder is opened',
  },
  {
    id: 'dsh-dlp/config-git',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.git\/(config$|hooks(\/|$))/i,
    effect: 'git configuration or a git hook, which runs on the next commit, checkout or push',
  },
  {
    id: 'dsh-dlp/config-git-hooks-managed',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.husky(\/|$)/i,
    effect: 'a managed git hook, which runs on the next commit or push',
  },
  {
    id: 'dsh-dlp/config-ci-workflow',
    version: 1,
    match: 'path',
    pattern: /(^|\/)\.(github\/workflows|gitlab-ci\.yml|circleci)(\/|$)/i,
    effect: 'a CI workflow, which runs on the shared runner with the repository\'s secrets',
  },
  {
    id: 'dsh-dlp/config-shell-rc',
    version: 1,
    match: 'path',
    pattern: /(^|\/)(\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.kshrc|config\.fish)$/i,
    effect: 'a shell startup file, which runs on every future shell this agent opens',
  },
  {
    id: 'dsh-dlp/config-harness-bundle',
    version: 1,
    match: 'path',
    pattern: /(^|\/)cordis[^/]*\.ya?ml$/i,
    effect: 'a harness bundle manifest, which decides which plugins load',
  },
  // CVE-2026-21852: a repo-local settings file setting `ANTHROPIC_BASE_URL`
  // sends the user's own API key to whatever host it names. This is neither a
  // path nor a secret — it is a key whose *value* redirects a credential — so
  // it is matched against what would be written rather than against where.
  {
    id: 'dsh-dlp/config-api-base-url',
    version: 1,
    match: 'content',
    pattern: /\b[A-Z][A-Z0-9_]*(?:_BASE_URL|_API_BASE)\b["']?\s*[=:]\s*["']?\s*https?:\/\//,
    effect: 'a provider base URL, which sends the credential for that provider to whatever host it names',
  },
]

/**
 * Argument keys whose values are the bytes a call would write.
 *
 * Deliberately separate from the floor's path-typed keys: the floor must never
 * run its path table over file content, and this tier must run its one content
 * rule over nothing else.
 */
export const CONTENT_ARGUMENT_KEYS: ReadonlySet<string> = new Set([
  'content', 'contents', 'text', 'file_text', 'fileText',
  'new_string', 'newString', 'new_str', 'replacement', 'body',
])

/**
 * The strings one call would write.
 * @param args - the pending call's parsed arguments.
 * @returns every string under a content-typed key, at any depth.
 */
export function contentArguments(args: unknown): string[] {
  const found: string[] = []
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (typeof node !== 'object' || node === null) return
    for (const [key, value] of Object.entries(node)) {
      if (CONTENT_ARGUMENT_KEYS.has(key)) found.push(...nestedStrings(value))
      else walk(value)
    }
  }
  walk(args)
  return found
}

/** A call this tier wants a human to confirm. */
export interface ConfigWriteFinding {
  readonly rule: ConfigWriteRule
  /** Model- and user-facing text; names the rule and what the file does, never the path. */
  readonly reason: string
}

/**
 * Prompt text for one behaviour-changing write.
 *
 * The path is not quoted, for the same reason the floor never quotes one: this
 * string is model-visible and a path carries tenant and customer names. What
 * the user needs in order to answer is which tool, which rule, and what the
 * file does.
 */
function configWriteReason(toolName: string, rule: ConfigWriteRule): string {
  return `dsh-dlp is asking before ${JSON.stringify(toolName)} writes ${rule.effect} (rule ${rule.id}). `
    + 'This kind of file changes what happens on a later session, commit or CI run rather than now, so it is worth '
    + 'one look. Approve it if you asked for this change; decline it if you did not.'
}

/**
 * Decide whether one call should be confirmed by a human.
 *
 * Only calls that can change something are examined: a tool
 * {@link isReadOnlyTool} classifies as query-only cannot write a hook. Shell
 * command lines are deliberately **not** tokenised here, unlike in the floor:
 * a command line cannot be told apart from a read of the same path, and
 * prompting on `cat .github/workflows/ci.yml` is exactly the false positive
 * that gets a tier switched off. A shell redirection into one of these files
 * is therefore not covered, which README.md says beside the feature.
 * @param exec - the pending call.
 * @param rules - the rule table; defaults to {@link CONFIG_WRITE_RULES}.
 * @returns the finding, or `undefined` to leave the call alone.
 */
export function evaluateConfigWrite(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  rules: readonly ConfigWriteRule[] = CONFIG_WRITE_RULES,
): ConfigWriteFinding | undefined {
  if (isReadOnlyTool(exec.name)) return undefined

  const targets = pathArguments(exec.arguments).filter(argument => !argument.shell)
  for (const rule of rules) {
    if (rule.match !== 'path') continue
    for (const target of targets) {
      if (rule.pattern.test(normalizeCandidatePath(target.text))) {
        return { rule, reason: configWriteReason(exec.name, rule) }
      }
    }
  }

  const written = contentArguments(exec.arguments)
  for (const rule of rules) {
    if (rule.match !== 'content') continue
    for (const text of written) {
      if (rule.pattern.test(text)) return { rule, reason: configWriteReason(exec.name, rule) }
    }
  }
  return undefined
}
