/**
 * The guard floor: the one part of this plugin that holds under attack.
 *
 * It tests the path-typed arguments of a call — never file content — against
 * the credential table, resolving symlinks first, and the whole argument set
 * against the tier-1 detectors when the tool can move data off the machine.
 * The `command` arm inside that is advisory pattern-matching: tokenising a
 * shell command line catches `cat ~/.ssh/id_rsa` and loses to one glob
 * character. README.md says so plainly and so does this comment.
 *
 * `ctx.tools.guard()` takes a synchronous `(exec) => string | undefined`. It
 * has no allow arm, so no registration order can turn a denial back into
 * permission, and the first denial wins. It runs after the whole
 * `tools/pre-execute` waterfall and after `ctx.approval`, which is why the
 * floor lives here rather than in a listener: `exec.arguments` is deep-frozen
 * but `exec` itself is not frozen until after execution, so a pre-execute
 * listener can reassign `exec.arguments` or `exec.name` and succeed. The guard
 * reads what every listener finally left behind.
 *
 * Registered on a plain context, never through `agent.ctx`: a global guard
 * covers every agent, every `run_code` inner sub-call, and every subagent
 * child, while an agent-scoped listener never sees a subagent child's calls
 * because a child agent is a sibling, not a descendant.
 *
 * The floor is not configurable. Per CONVENTIONS, security invariants stay
 * fixed; the repo-local policy tier may only add to its tables.
 * @module dsh-dlp/guard
 */

import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { DENY_SEVERITY, scanSync, severityRank } from './detectors.ts'
import { isEgressCapable, matchPathArgument, pathArguments, pathCandidates, rulesForTool } from './paths.ts'
import type { ResolvedPolicy } from './policy.ts'
import { nestedStrings, type RedactedSpan, type SpanHasher } from './redaction.ts'

/** Why the floor denied one call. */
export interface GuardVerdict {
  readonly kind: 'credential-path' | 'secret-argument' | 'internal-fault'
  /** Model-facing text; carries rule identities and keyed hashes, never matched values. */
  readonly reason: string
  /** The offending regions, described by rule identity, offsets, and keyed hash only. */
  readonly spans: readonly RedactedSpan[]
}

/**
 * Denial text for a credential-path match.
 *
 * The matched path is named by rule id and keyed hash, never quoted. A path is
 * itself sensitive — a tenant name, a customer directory, a shell command that
 * happens to end in `.pem` — and this string is both model-visible and written
 * to the audit sink.
 */
function credentialPathReason(toolName: string, ruleId: string, hash: string): string {
  return `dsh-dlp denied ${JSON.stringify(toolName)}: one of its path arguments is credential material `
    + `(rule ${ruleId}, keyed hash ${hash}). Reading or passing credential files through a tool is blocked by `
    + 'policy and cannot be overridden. Ask the user to supply the value you need, or use a path that is not a '
    + 'credential store.'
}

/** Denial text for secrets found in arguments heading to an egress-capable tool. */
function secretArgumentReason(toolName: string, ruleIds: readonly string[], hashes: readonly string[]): string {
  return `dsh-dlp denied ${JSON.stringify(toolName)}: its arguments contain credential material matching `
    + `${ruleIds.join(', ')} (${hashes.length} finding(s), keyed hash ${hashes.join(', ')}). `
    + `${JSON.stringify(toolName)} can send data off this machine, so secrets in its arguments are blocked by policy `
    + 'and cannot be overridden. Remove the credential from the call — reference an environment variable the tool '
    + 'already has, or ask the user to run the command themselves.'
}

/**
 * Decide whether the floor denies one call.
 *
 * Credential paths are denied for every tool, not only readers: a shell that
 * can `cat` a key can also copy it. Only path-typed arguments are tested —
 * running the table over every string matches file content and denies writing
 * a `.gitignore` that mentions `.env`. The one exception is a `writes-only`
 * rule, which a tool classified read-only is exempt from; that is how
 * `$DSH_HOME` stays readable while every write to it is denied. Argument
 * secrets are denied only for egress-capable tools, because denying a local
 * editor for holding the text it was asked to write would break ordinary work
 * without closing an exfiltration path.
 * @param exec - the pending call as the guard stage sees it.
 * @param policy - the effective policy after the tighten-only merge.
 * @param hasher - mints the keyed hashes quoted in a denial reason.
 * @returns the denial, or `undefined` to abstain.
 */
export function evaluateGuard(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): GuardVerdict | undefined {
  const rules = rulesForTool(exec.name, policy.credentialPathRules)
  for (const argument of pathArguments(exec.arguments)) {
    const candidates = argument.shell ? pathCandidates(argument.text) : [argument.text]
    for (const candidate of candidates) {
      const rule = matchPathArgument(candidate, rules)
      if (rule === undefined) continue
      const hash = hasher.hash(candidate)
      return {
        kind: 'credential-path',
        reason: credentialPathReason(exec.name, rule.id, hash),
        spans: [{
          ruleId: rule.id,
          ruleVersion: rule.version,
          severity: 'critical',
          start: 0,
          end: candidate.length,
          hash,
        }],
      }
    }
  }

  if (!isEgressCapable(exec.name, policy.extraEgressTools)) return undefined

  const spans: RedactedSpan[] = []
  for (const text of nestedStrings(exec.arguments)) {
    for (const detection of scanSync(text, policy.syncRules).detections) {
      if (severityRank(detection.severity) < severityRank(DENY_SEVERITY)) continue
      spans.push({ ...detection, hash: hasher.hash(text.slice(detection.start, detection.end)) })
    }
  }
  if (spans.length === 0) return undefined

  const ruleIds = [...new Set(spans.map(span => span.ruleId))]
  return {
    kind: 'secret-argument',
    reason: secretArgumentReason(exec.name, ruleIds, spans.map(span => span.hash)),
    spans,
  }
}

/**
 * Wrap {@link evaluateGuard} so an internal fault becomes a denial.
 *
 * A guard that throws fails the call closed *and* skips `tools/post-execute`,
 * which would silently disable result redaction for that call. Converting the
 * fault into a denial string keeps the post-execute stage running.
 * @param exec - the pending call.
 * @param policy - the effective policy.
 * @param hasher - mints the keyed hashes quoted in a denial reason.
 * @returns the denial, or `undefined` to abstain.
 */
export function safeEvaluateGuard(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): GuardVerdict | undefined {
  try {
    return evaluateGuard(exec, policy, hasher)
  } catch (error: unknown) {
    return {
      kind: 'internal-fault',
      reason: `dsh-dlp denied ${JSON.stringify(exec.name)}: the data-loss-prevention floor failed to evaluate `
        + `this call (${String(error)}) and denies by default. Report this to the deployment operator.`,
      spans: [],
    }
  }
}
