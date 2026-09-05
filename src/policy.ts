/**
 * Deployment configuration, the repo-local policy tier, and the tighten-only
 * merge between them.
 *
 * Trust ranking, highest first:
 *
 * 1. invariants compiled into this package — the guard floor's tables; not configurable;
 * 2. `cordis.yml` / bundle patch config — deployment-controlled; sets every field;
 * 3. `policyFile` — a repo-local YAML file; **attacker-controlled**, may only tighten.
 *
 * Rank 3 is a file inside the workspace, so a hostile repository ships one and
 * a prompt-injected agent can write one. It may add deny patterns, add egress
 * tools, raise a severity, and switch a redaction pass on. Every other key,
 * and every downgrade, is a load-time error rather than a silent ignore. It
 * cannot reach {@link Config.aggressiveness}: the level's own lever is
 * redacting what the user typed, and a workspace that could force that could
 * garble the user's own words on their way to the model.
 * @module dsh-dlp/policy
 */

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { resolve } from 'node:path'
import { JSON_SCHEMA, load } from 'js-yaml'
import z from '@deepseek-ai/schemastery'
import { SYNC_RULES, severityRank, stripControlSequences, type Severity, type SyncRule } from './detectors.ts'
import { resolveDshHome } from './home.ts'
import { CREDENTIAL_PATH_RULES, escapePathPattern, homeCredentialPathRules, type CredentialPathRule } from './paths.ts'

/**
 * How far redaction reaches, as one word.
 *
 * The level is not a tenth switch beside the nine below it. It states what the
 * deployment guarantees, the toggles state which passes carry it out, and the
 * two may not disagree: at `medium` and `high` a toggle set to `false`
 * contradicts the guarantee and is a load-time error rather than a setting
 * that quietly loses.
 *
 * - `low` guarantees nothing. Every pass is exactly its own toggle, which is
 *   still `true` unless the deployment says otherwise. This is the level to
 *   pick when a pass has to be switched off.
 * - `medium` guarantees that every pass this package ships is on and that no
 *   toggle can take one away. The user's own typing stays exempt.
 * - `high` is `medium` plus the one thing no toggle can express: the exemption
 *   in `isUserTyped` stops applying, so a secret in the user's own prompt is
 *   redacted before the request is built from it.
 */
export type Aggressiveness = 'low' | 'medium' | 'high'

/** Deployment configuration, validated from `cordis.yml`. */
export interface Config {
  /**
   * How far redaction reaches. See {@link Aggressiveness}; `high` is the only
   * value that puts the user's own typed prompt in scope.
   */
  aggressiveness: Aggressiveness
  /** Absolute path of this plugin's own JSONL audit sink. Never the session log. */
  auditLog: string
  /** Absolute path of the installation's redaction key; created with 32 random bytes if absent. */
  redactionKeyFile: string
  /** Optional repo-local policy file; the lowest-trust source. */
  policyFile?: string
  /** Cap on characters handed to a detector in one scan. */
  maxScanBytes: number
  /** Whether the async `tools/pre-execute` secretlint pass runs. */
  breadthTier: boolean
  /** Whether `tools/post-execute` redaction runs. */
  resultRedaction: boolean
  /** Whether `session-telemetry/record` redaction runs. */
  telemetryRedaction: boolean
  /**
   * Whether the context an `agent/pre-step` listener splices into a step —
   * the workspace instruction chain, captured terminal panes, a hook's
   * `additionalContext`, a skill body a `/name` token asked for — is redacted
   * before the loop logs it and builds the next request from it.
   */
  stepContextRedaction: boolean
  /**
   * Whether the messages the loop claimed from the inbox are redacted before
   * the step logs them and builds its request from them, for every message the
   * user did not type: a `dsh-webhook` delivery's third-party payload, a
   * subagent's settled result, an agent-to-agent relay, anything
   * `agent.inject()` seeded. A message whose `source.kind` is `user` is exempt.
   */
  claimedInputRedaction: boolean
  /** Whether remote markdown image destinations are neutralised in assistant output. */
  remoteImageNeutralization: boolean
  /** Whether telemetry's `session.cwd` attribute is replaced with a keyed hash. */
  redactTelemetryWorkspacePaths: boolean
  /**
   * Whether a write to a behaviour-changing config path asks the user first.
   * Needs an approval service; without one the tier abstains rather than
   * letting an `ask` degrade into a denial.
   */
  configWriteAsk: boolean
  /**
   * Whether a call carrying an argument that switches its own confirmation off
   * asks the user first. Shares the `ask` tier, and its approval service, with
   * {@link Config.configWriteAsk}.
   */
  approvalSuppressionAsk: boolean
}

export const Config: z<Config> = z.object({
  aggressiveness: z.union([z.const('low'), z.const('medium'), z.const('high')]).default('medium'),
  auditLog: z.string().required(),
  redactionKeyFile: z.string().required(),
  policyFile: z.string(),
  maxScanBytes: z.number().default(1024 * 1024),
  breadthTier: z.boolean().default(true),
  resultRedaction: z.boolean().default(true),
  telemetryRedaction: z.boolean().default(true),
  stepContextRedaction: z.boolean().default(true),
  claimedInputRedaction: z.boolean().default(true),
  remoteImageNeutralization: z.boolean().default(true),
  redactTelemetryWorkspacePaths: z.boolean().default(true),
  configWriteAsk: z.boolean().default(true),
  approvalSuppressionAsk: z.boolean().default(true),
})

/** Config toggles a repo-local policy may switch on, and never off. */
const ENABLEABLE = [
  'breadthTier',
  'resultRedaction',
  'telemetryRedaction',
  'stepContextRedaction',
  'claimedInputRedaction',
  'remoteImageNeutralization',
  'redactTelemetryWorkspacePaths',
  'configWriteAsk',
  'approvalSuppressionAsk',
] as const

/** One toggle name a repo-local policy may name in `enable`. */
export type EnableableToggle = typeof ENABLEABLE[number]

/**
 * Passes each level requires, whatever the toggles say.
 *
 * `low` requires none, which is what makes it the level a deployment moves to
 * when it needs a pass off — and what makes every configuration that was legal
 * before this field existed still legal. `medium` and `high` require all of
 * them, so the one-word setting and the nine booleans can never describe
 * different plugins.
 */
const LEVEL_REQUIRES: Readonly<Record<Aggressiveness, readonly EnableableToggle[]>> = {
  low: [],
  medium: ENABLEABLE,
  high: ENABLEABLE,
}

/**
 * Reject a configuration whose level and whose toggles describe different
 * behaviour.
 *
 * Loud at load rather than silently resolved either way: two
 * deployment-controlled settings disagreeing is self-contained
 * misconfiguration, and whichever of them lost would be a pass an operator
 * believes is running and is not, or one they believe is off and is not.
 * @param config - the deployment-controlled configuration.
 * @throws PolicyError naming every toggle that contradicts the level.
 */
function assertLevelAgrees(config: Config): void {
  const contradicted = LEVEL_REQUIRES[config.aggressiveness].filter(toggle => !config[toggle])
  if (contradicted.length === 0) return
  throw new PolicyError(
    `aggressiveness: ${config.aggressiveness} requires every pass this package ships, but`
    + ` ${contradicted.join(', ')} ${contradicted.length === 1 ? 'is' : 'are'} set to false.`
    + ' Set aggressiveness: low to choose passes individually, or drop the false setting.',
  )
}

/** Keys a repo-local policy file may carry; anything else fails the load. */
const POLICY_KEYS = ['v', 'addCredentialPaths', 'addEgressTools', 'raiseSeverity', 'enable'] as const

/** Payload version this package writes and accepts for repo-local policy files. */
export const POLICY_VERSION = 1

/** A repo-local policy file after parsing and validation. */
export interface RepoPolicy {
  readonly addCredentialPaths: readonly CredentialPathRule[]
  readonly addEgressTools: readonly string[]
  readonly raiseSeverity: ReadonlyMap<string, Severity>
  readonly enable: readonly EnableableToggle[]
}

/** Everything the seams read after both tiers have been merged. */
export interface ResolvedPolicy {
  readonly credentialPathRules: readonly CredentialPathRule[]
  readonly extraEgressTools: ReadonlySet<string>
  readonly syncRules: readonly SyncRule[]
  readonly maxScanBytes: number
  readonly aggressiveness: Aggressiveness
  /**
   * Whether a message the user typed themselves is scanned like any other.
   *
   * Set by the level alone, at `high` only, and by nothing else: there is no
   * toggle for it and a repo-local policy cannot reach it. `isUserTyped` still
   * decides which messages this applies to; this decides whether that answer
   * exempts them.
   */
  readonly userTypedInputRedaction: boolean
  readonly breadthTier: boolean
  readonly resultRedaction: boolean
  readonly telemetryRedaction: boolean
  readonly stepContextRedaction: boolean
  readonly claimedInputRedaction: boolean
  readonly remoteImageNeutralization: boolean
  readonly redactTelemetryWorkspacePaths: boolean
  readonly configWriteAsk: boolean
  readonly approvalSuppressionAsk: boolean
}

/** Thrown when a policy file is malformed or attempts to loosen the policy. */
export class PolicyError extends Error {
  /**
   * @param message - what the file did and why it is rejected.
   */
  constructor(message: string) {
    super(`dsh-dlp policy: ${message}`)
    this.name = 'PolicyError'
  }
}

/** Narrow one parsed YAML node to a plain object. */
function requireObject(node: unknown, what: string): Record<string, unknown> {
  if (typeof node !== 'object' || node === null || Array.isArray(node)) {
    throw new PolicyError(`${what} must be a mapping`)
  }
  return node as Record<string, unknown>
}

/** Narrow one parsed YAML node to an array of strings. */
function requireStringArray(node: unknown, what: string): string[] {
  if (!Array.isArray(node) || node.some(item => typeof item !== 'string')) {
    throw new PolicyError(`${what} must be a list of strings`)
  }
  return node as string[]
}

/** Narrow one parsed YAML node to a known severity. */
function requireSeverity(node: unknown, what: string): Severity {
  if (typeof node !== 'string' || severityRank(node as Severity) < 0) {
    throw new PolicyError(`${what} must be one of low, medium, high, critical`)
  }
  return node as Severity
}

/**
 * Longest repo-authored pattern accepted. A credential path is a short,
 * anchored expression; length past this buys nothing and grows the search
 * space a catastrophic pattern can backtrack over.
 */
const MAX_PATTERN_LENGTH = 200

/**
 * A quantifier applied to a group that already contains one — `(a+)+`,
 * `(?:[a-z]*)*`. That shape is what turns a 27-character input into seconds of
 * backtracking, and the guard runs synchronously on the agent's event loop.
 *
 * This is a heuristic, not a decision procedure: no regular-expression syntax
 * check can prove a pattern runs in linear time, and other shapes
 * (`(a|a)+`, `a*a*`) still backtrack. It rejects the shape that is both easy
 * to write and expensive to run; the length cap bounds the rest.
 */
const NESTED_QUANTIFIER = /\((?:\?[:=!<]*)?[^()]*[*+?}][^()]*\)\s*[*+{]/

/**
 * Reject a repo-authored pattern that would let a hostile repository stall the
 * agent through the synchronous guard.
 * @param pattern - the pattern text from the policy file.
 * @param where - the field being validated, for the error message.
 * @throws PolicyError when the pattern is too long or nests quantifiers.
 */
function assertSafePattern(pattern: string, where: string): void {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    throw new PolicyError(`${where} is ${pattern.length} characters; at most ${MAX_PATTERN_LENGTH} are allowed`)
  }
  if (NESTED_QUANTIFIER.test(pattern)) {
    throw new PolicyError(
      `${where} nests a quantifier inside a quantified group, which can take exponential time to match;`
      + ' the guard runs synchronously, so such a pattern is rejected',
    )
  }
}

/** Compile one repo-local credential-path entry, rejecting a pattern that cannot be built. */
function parseCredentialPathEntry(node: unknown, index: number): CredentialPathRule {
  const entry = requireObject(node, `addCredentialPaths[${index}]`)
  const { id, pattern } = entry
  const extra = Object.keys(entry).filter(key => key !== 'id' && key !== 'pattern')
  if (extra.length > 0) {
    throw new PolicyError(`addCredentialPaths[${index}] has unknown keys: ${extra.join(', ')}`)
  }
  if (typeof id !== 'string' || id.length === 0) {
    throw new PolicyError(`addCredentialPaths[${index}].id must be a non-empty string`)
  }
  // A rule id is quoted verbatim in a model-facing denial and in every audit
  // record the rule produces, and this file is attacker-controlled.
  if (stripControlSequences(id) !== id) {
    throw new PolicyError(
      `addCredentialPaths[${index}].id carries a terminal control sequence; a rule id is quoted in a denial`
      + ' the user reads and in the audit record, so it may not rewrite what is on screen',
    )
  }
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new PolicyError(`addCredentialPaths[${index}].pattern must be a non-empty string`)
  }
  assertSafePattern(pattern, `addCredentialPaths[${index}].pattern`)
  try {
    return { id, version: POLICY_VERSION, pattern: new RegExp(pattern, 'i') }
  } catch (error: unknown) {
    throw new PolicyError(`addCredentialPaths[${index}].pattern is not a valid regular expression: ${String(error)}`)
  }
}

/**
 * Parse and validate one repo-local policy document.
 *
 * Loaded under `js-yaml`'s `JSON_SCHEMA`, so a `!!js/function` tag is a parse
 * error rather than code execution. This path deliberately never touches the
 * Cordis loader, whose `!!js` support is the whole reason it must not see
 * workspace-authored files.
 * @param text - the file's contents.
 * @returns the validated policy.
 * @throws PolicyError on an unknown key, a bad value, or any attempt to loosen.
 */
export function parseRepoPolicy(text: string): RepoPolicy {
  let parsed: unknown
  try {
    parsed = load(text, { schema: JSON_SCHEMA })
  } catch (error: unknown) {
    throw new PolicyError(`file is not safe-schema YAML: ${String(error)}`)
  }
  const document = requireObject(parsed, 'file')
  const unknown = Object.keys(document).filter(key => !(POLICY_KEYS as readonly string[]).includes(key))
  if (unknown.length > 0) {
    throw new PolicyError(
      `unknown keys: ${unknown.join(', ')}. A repo-local policy may only tighten:`
      + ` ${POLICY_KEYS.join(', ')}`,
    )
  }
  if (document['v'] !== POLICY_VERSION) {
    throw new PolicyError(`v must be ${POLICY_VERSION}`)
  }

  const addCredentialPaths = document['addCredentialPaths'] === undefined
    ? []
    : (Array.isArray(document['addCredentialPaths'])
        ? document['addCredentialPaths'].map(parseCredentialPathEntry)
        : (() => { throw new PolicyError('addCredentialPaths must be a list') })())

  const addEgressTools = document['addEgressTools'] === undefined
    ? []
    : requireStringArray(document['addEgressTools'], 'addEgressTools')

  const raiseSeverity = new Map<string, Severity>()
  if (document['raiseSeverity'] !== undefined) {
    for (const [ruleId, value] of Object.entries(requireObject(document['raiseSeverity'], 'raiseSeverity'))) {
      const rule = SYNC_RULES.find(candidate => candidate.id === ruleId)
      if (rule === undefined) throw new PolicyError(`raiseSeverity names an unknown rule: ${ruleId}`)
      const severity = requireSeverity(value, `raiseSeverity.${ruleId}`)
      if (severityRank(severity) < severityRank(rule.severity)) {
        throw new PolicyError(
          `raiseSeverity.${ruleId} would lower ${rule.severity} to ${severity};`
          + ' a repo-local policy may only tighten',
        )
      }
      raiseSeverity.set(ruleId, severity)
    }
  }

  const enable = requireStringArray(document['enable'] ?? [], 'enable')
  for (const toggle of enable) {
    if (!(ENABLEABLE as readonly string[]).includes(toggle)) {
      throw new PolicyError(`enable names an unknown toggle: ${toggle}. Known toggles: ${ENABLEABLE.join(', ')}`)
    }
  }

  return { addCredentialPaths, addEgressTools, raiseSeverity, enable: enable as EnableableToggle[] }
}

/** Outcome of reading the file named by `policyFile`. */
export type RepoPolicyLoad =
  /** No file at that path: the workspace ships no policy. */
  | { readonly kind: 'absent' }
  | { readonly kind: 'loaded'; readonly policy: RepoPolicy }
  /** Present but unreadable or invalid; `problem` is what to log. */
  | { readonly kind: 'invalid'; readonly problem: string }

/**
 * Read a repo-local policy file from disk.
 *
 * Absence is not a misconfiguration here, which is the one place this package
 * departs from "never silently skip a missing referent": `policyFile` names a
 * path inside the *workspace*, and the recommended value is workspace-relative,
 * so most repositories will not have one. Failing the mount would refuse to
 * start `dsh` in every repository lacking the file — and would hand a hostile
 * repository a way to remove the guard floor by deleting or breaking it.
 * A malformed file is loud and ignored, never obeyed in part.
 * @param path - the file to read.
 * @returns the validated policy, its absence, or the problem to report.
 */
export function loadRepoPolicy(path: string): RepoPolicyLoad {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'invalid', problem: `cannot read ${path}: ${String(error)}` }
  }
  try {
    return { kind: 'loaded', policy: parseRepoPolicy(text) }
  } catch (error: unknown) {
    return { kind: 'invalid', problem: String(error) }
  }
}

/**
 * Deny rules protecting this plugin's own state and the harness home.
 *
 * Every one of these is known at mount: the key file whose bytes make a
 * placeholder hash keyed rather than a bare digest, the append-only sink that
 * is the only evidence a decision happened, and the harness home holding the
 * provider credentials, the session logs and the profiles that decide which
 * plugins load at all.
 *
 * The harness home is split. **Writing** anywhere under it is denied for every
 * tool: a prompt-injected agent editing a profile's `cordis.yml` mounts an
 * arbitrary plugin. **Reading** it is denied only where the contents are
 * credentials — `.credentials.yaml`, `.env` and `*.key` are already in the
 * built-in table, and the session logs get a rule here. Everything else under
 * that directory is the installed plugin tree and the profile manifests, which
 * a user debugging a plugin has every reason to read; a blanket read denial
 * there was unoverridable and was the plugin's most likely uninstall reason.
 * @param config - the deployment-controlled configuration.
 * @param dshHome - the resolved harness home.
 * @returns rules appended after the built-in table.
 */
function selfProtectionRules(config: Config, dshHome: string): CredentialPathRule[] {
  const home = escapePathPattern(resolve(dshHome))
  return [
    { id: 'dsh-dlp/path-own-redaction-key', version: 1, pattern: new RegExp(`^${escapePathPattern(resolve(config.redactionKeyFile))}$`, 'i') },
    { id: 'dsh-dlp/path-own-audit-log', version: 1, pattern: new RegExp(`^${escapePathPattern(resolve(config.auditLog))}$`, 'i') },
    { id: 'dsh-dlp/path-dsh-sessions', version: 1, pattern: new RegExp(`^${home}/sessions(/|$)`, 'i') },
    { id: 'dsh-dlp/path-dsh-home', version: 2, enforcement: 'writes-only', pattern: new RegExp(`^${home}(/|$)`, 'i') },
  ]
}

/**
 * Merge the deployment config with an optional repo-local policy.
 * @param config - the deployment-controlled configuration.
 * @param repo - the repo-local policy, when one is mounted.
 * @returns the effective policy every seam reads.
 */
export function resolvePolicy(config: Config, repo?: RepoPolicy): ResolvedPolicy {
  assertLevelAgrees(config)
  const enabled = (toggle: EnableableToggle): boolean => config[toggle] || (repo?.enable.includes(toggle) ?? false)
  return {
    credentialPathRules: [
      ...CREDENTIAL_PATH_RULES,
      ...homeCredentialPathRules(resolve(homedir())),
      ...selfProtectionRules(config, resolveDshHome()),
      ...repo?.addCredentialPaths ?? [],
    ],
    extraEgressTools: new Set(repo?.addEgressTools ?? []),
    syncRules: SYNC_RULES.map((rule) => {
      const raised = repo?.raiseSeverity.get(rule.id)
      return raised === undefined ? rule : { ...rule, severity: raised }
    }),
    maxScanBytes: config.maxScanBytes,
    aggressiveness: config.aggressiveness,
    userTypedInputRedaction: config.aggressiveness === 'high',
    breadthTier: enabled('breadthTier'),
    resultRedaction: enabled('resultRedaction'),
    telemetryRedaction: enabled('telemetryRedaction'),
    stepContextRedaction: enabled('stepContextRedaction'),
    claimedInputRedaction: enabled('claimedInputRedaction'),
    remoteImageNeutralization: enabled('remoteImageNeutralization'),
    redactTelemetryWorkspacePaths: enabled('redactTelemetryWorkspacePaths'),
    configWriteAsk: enabled('configWriteAsk'),
    approvalSuppressionAsk: enabled('approvalSuppressionAsk'),
  }
}
