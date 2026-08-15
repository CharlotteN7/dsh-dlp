/**
 * The two result-side seams: the async argument breadth tier at
 * `tools/pre-execute`, and result redaction at `tools/post-execute`.
 *
 * Both are best-effort by construction. A `tools/pre-execute` listener
 * registered ahead of ours can return without calling `next()` and neutralize
 * the breadth tier; a `tools/post-execute` listener ahead of ours can replace a
 * result after we redacted it. Only `ctx.tools.guard()` is order-independent.
 * What these seams buy is breadth: they can await, so `@secretlint/core`'s
 * whole rule set applies here and not in the guard.
 * @module dsh-dlp/results
 */

import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import {
  DENY_SEVERITY,
  scanAll,
  scanSync,
  severityRank,
  type Detection,
} from './detectors.ts'
import { isEgressCapable } from './paths.ts'
import type { ResolvedPolicy } from './policy.ts'
import { nestedStrings, redactContent, redactJson, type RedactedSpan, type SpanHasher } from './redaction.ts'

/**
 * Tier-2 scans allowed per tool result. Beyond it, remaining strings are
 * scanned by tier 1 only and the audit record is marked `truncatedScan`. A
 * `read` of a large file arrives as thousands of separate line strings, and
 * one `lintSource` call each would leave the hot path.
 */
const SECRETLINT_STRING_BUDGET = 128

/** A scan function over already-scanned strings, plus how complete the scan was. */
interface PreparedScan {
  readonly scan: (text: string) => readonly Detection[]
  readonly truncated: boolean
}

/**
 * Scan a set of strings once and hand back a synchronous lookup, so the
 * redaction walkers stay synchronous while detection stays async.
 * @param strings - every string that will be redacted.
 * @param policy - the effective policy.
 * @returns a memoized lookup and whether any string fell back to tier 1 only.
 */
async function prepareScan(strings: readonly string[], policy: ResolvedPolicy): Promise<PreparedScan> {
  const memo = new Map<string, readonly Detection[]>()
  let budget = SECRETLINT_STRING_BUDGET
  let truncated = false
  for (const text of new Set(strings)) {
    if (budget > 0) {
      budget -= 1
      const result = await scanAll(text, policy.syncRules, policy.maxScanBytes)
      truncated ||= result.truncated
      memo.set(text, result.detections)
      continue
    }
    truncated = true
    memo.set(text, scanSync(text, policy.syncRules, policy.maxScanBytes).detections)
  }
  /* v8 ignore next -- every string handed to the walkers was collected for this memo. */
  return { scan: text => memo.get(text) ?? [], truncated }
}

/** Text carried by a content array's text blocks. */
function contentStrings(blocks: readonly ContentBlock[]): string[] {
  return blocks.flatMap(block => block.type === 'text' ? [block.text] : [])
}

/** What a redaction pass produced, before an arm is chosen. */
export interface ResultRedaction {
  readonly decision: PostToolDecision
  readonly spans: readonly RedactedSpan[]
  readonly truncatedScan: boolean
}

/**
 * Redact whatever the downstream decision settled on.
 *
 * Arm selection follows what the seam can carry, not preference:
 * `accept{value}` re-validates `output.schema`, re-runs `output.render()` and
 * re-derives `presentationMeta()`, so one replacement redacts the canonical
 * value, the model-facing content and the persisted meta together. It throws
 * on a failed result, so failures — where a leaked token most often hides, in
 * an error message quoting the command — take `accept{content}`. The docs are
 * explicit that content replacement is presentation policy, not
 * confidentiality policy: on that arm the canonical value keeps the original
 * text.
 *
 * The two `accept` arms are mutually exclusive at runtime (`Object.hasOwn`
 * check throws a `TypeError`), so exactly one is ever populated.
 * @param decision - what the rest of the waterfall returned.
 * @param result - the dispatch outcome the waterfall was called with.
 * @param policy - the effective policy.
 * @param hasher - mints each span's keyed hash.
 * @returns the decision to return, the spans replaced, and scan completeness.
 */
export async function redactDecision(
  decision: PostToolDecision,
  result: Readonly<ToolExecutionResult>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): Promise<ResultRedaction> {
  if (decision.kind === 'block') {
    const prepared = await prepareScan(contentStrings(decision.feedback), policy)
    const redacted = redactContent(decision.feedback, prepared.scan, hasher)
    return {
      decision: redacted.changed ? { ...decision, feedback: redacted.content } : decision,
      spans: redacted.spans,
      truncatedScan: prepared.truncated,
    }
  }

  const replacedValue = Object.hasOwn(decision, 'value') ? decision.value : undefined
  const replacedContent = Object.hasOwn(decision, 'content') ? decision.content : undefined
  const contexts = decision.additionalContexts === undefined
    ? {}
    : { additionalContexts: decision.additionalContexts }

  if (replacedValue !== undefined) {
    const prepared = await prepareScan(nestedStrings(replacedValue), policy)
    const redacted = redactJson(replacedValue, prepared.scan, hasher)
    return {
      decision: redacted.changed ? { kind: 'accept', value: redacted.value, ...contexts } : decision,
      spans: redacted.spans,
      truncatedScan: prepared.truncated,
    }
  }

  if (replacedContent !== undefined) {
    const prepared = await prepareScan(contentStrings(replacedContent), policy)
    const redacted = redactContent(replacedContent, prepared.scan, hasher)
    return {
      decision: redacted.changed ? { kind: 'accept', content: redacted.content, ...contexts } : decision,
      spans: redacted.spans,
      truncatedScan: prepared.truncated,
    }
  }

  // A bare accept: the original dispatch outcome is what reaches the model.
  const value = result.isError ? undefined : result.value
  const probeText = `${value === undefined ? '' : JSON.stringify(value)}\n${contentStrings(result.content).join('\n')}`
  const probe = await scanAll(probeText, policy.syncRules, policy.maxScanBytes)
  if (probe.detections.length === 0) {
    return { decision, spans: [], truncatedScan: probe.truncated }
  }

  if (value !== undefined) {
    const prepared = await prepareScan(nestedStrings(value), policy)
    const redacted = redactJson(value, prepared.scan, hasher)
    if (redacted.changed) {
      return {
        decision: { kind: 'accept', value: redacted.value, ...contexts },
        spans: redacted.spans,
        truncatedScan: prepared.truncated || probe.truncated,
      }
    }
  }

  // Either a failed result, or a probe hit that no individual string reproduces
  // (a secret split across two fields shows up only in the rendered text).
  const prepared = await prepareScan(contentStrings(result.content), policy)
  const redacted = redactContent(result.content, prepared.scan, hasher)
  return {
    decision: redacted.changed ? { kind: 'accept', content: redacted.content, ...contexts } : decision,
    spans: redacted.spans,
    truncatedScan: prepared.truncated || probe.truncated,
  }
}

/**
 * Decide whether the breadth tier denies one call before dispatch.
 *
 * Only ever narrows: the caller has already delegated, and a decision that is
 * not `allow` is returned untouched.
 * @param exec - the pending call.
 * @param policy - the effective policy.
 * @param hasher - mints the keyed hashes quoted in a denial reason.
 * @returns the denial reason and its rule ids, or `undefined` to leave the call allowed.
 */
export async function evaluateBreadthTier(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): Promise<{ reason: string; ruleIds: readonly string[]; hashes: readonly string[] } | undefined> {
  if (!isEgressCapable(exec.name, policy.extraEgressTools)) return undefined
  const ruleIds: string[] = []
  const hashes: string[] = []
  for (const text of new Set(nestedStrings(exec.arguments))) {
    const { detections } = await scanAll(text, policy.syncRules, policy.maxScanBytes)
    for (const detection of detections) {
      if (severityRank(detection.severity) < severityRank(DENY_SEVERITY)) continue
      ruleIds.push(detection.ruleId)
      hashes.push(hasher.hash(text.slice(detection.start, detection.end)))
    }
  }
  if (ruleIds.length === 0) return undefined
  const unique = [...new Set(ruleIds)]
  return {
    reason: `dsh-dlp denied ${JSON.stringify(exec.name)}: its arguments contain credential material matching `
      + `${unique.join(', ')} (keyed hash ${hashes.join(', ')}). Remove the credential from the call.`,
    ruleIds: unique,
    hashes,
  }
}

/** A `PreToolDecision` denial built from a breadth-tier finding. */
export function breadthTierDenial(reason: string): PreToolDecision {
  return { kind: 'deny', reason }
}
