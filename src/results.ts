/**
 * The two result-side seams: the async argument breadth tier at
 * `tools/pre-execute`, and result redaction at `tools/post-execute`.
 *
 * Both are best-effort by construction. A `tools/pre-execute` listener
 * registered ahead of ours can return without calling `next()` and neutralize
 * the breadth tier. Result redaction registers with `{ prepend: true }`, so it
 * redacts whatever the rest of the waterfall settled on rather than having its
 * own decision replaced afterwards — but `prepend` unshifts, so a listener
 * that registers later with the same option still lands ahead of it. Only
 * `ctx.tools.guard()` is order-independent, and it cannot rewrite a result.
 * What these seams buy is breadth: they can await, so `@secretlint/core`'s
 * whole rule set applies here and not in the guard.
 * @module dsh-dlp/results
 */

import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type {
  JsonSchemaNode,
  PostToolDecision,
  PreToolDecision,
  ToolExecution,
  ToolExecutionResult,
} from '@deepseek-ai/dsh-tools'
import {
  DENY_SEVERITY,
  countUnicodeIndicators,
  scanAll,
  scanSync,
  severityRank,
  type Detection,
} from './detectors.ts'
import { isEgressCapable } from './paths.ts'
import type { ResolvedPolicy } from './policy.ts'
import { nestedStrings, redactContent, redactJson, type RedactedSpan, type SpanHasher } from './redaction.ts'
import { redactionBreaksSchema } from './schema.ts'

/**
 * Separator the strings of one result are rendered with before the
 * cross-string scan. A newline is what the reader of a tool result sees
 * between two lines of a file, and it keeps every `\b` and `^` anchor a
 * per-string scan would have honoured.
 */
const RENDER_SEPARATOR = '\n'

/** A scan function over already-scanned strings, plus how complete the scan was. */
interface PreparedScan {
  readonly scan: (text: string) => readonly Detection[]
  readonly truncated: boolean
  /** Runs of each invisible-character class in the whole rendering, by rule id. */
  readonly indicators: Readonly<Record<string, number>>
}

/**
 * Scan a set of strings once and hand back a synchronous lookup, so the
 * redaction walkers stay synchronous while detection stays async.
 *
 * The strings are scanned twice over: each on its own by tier 1, and all of
 * them joined by both tiers. The joined pass is what finds a secret split
 * across strings — a PEM block arriving as one `lines[i].text` per line, a
 * token spanning two content blocks — which no per-string walk can see; its
 * offsets are then mapped back onto the individual strings, because that is
 * what the redaction walkers splice.
 *
 * Tier 2 runs once, over the joined text, and is budgeted by characters
 * through `maxScanBytes`. One `lintSource` call per string would multiply a
 * fixed per-call cost by however many pieces the tool happened to split its
 * output into, and a budget counted in strings would make how much of a result
 * is scanned depend on the same accident.
 * @param strings - every string that will be redacted, in render order.
 * @param policy - the effective policy.
 * @returns a memoized lookup, the invisible-character counts, and whether tier 2 saw less than the whole rendering.
 */
async function prepareScan(strings: readonly string[], policy: ResolvedPolicy): Promise<PreparedScan> {
  const rendered = strings.join(RENDER_SEPARATOR)
  const { detections, truncated } = await scanAll(rendered, policy.syncRules, policy.maxScanBytes)
  const memo = new Map<string, Detection[]>()
  const found = (text: string): Detection[] => {
    const existing = memo.get(text)
    if (existing !== undefined) return existing
    const created = [...scanSync(text, policy.syncRules).detections]
    memo.set(text, created)
    return created
  }

  let offset = 0
  for (const text of strings) {
    const start = offset
    const end = start + text.length
    offset = end + RENDER_SEPARATOR.length
    const local = found(text)
    for (const detection of detections) {
      if (detection.end <= start || detection.start >= end) continue
      local.push({
        ...detection,
        start: Math.max(0, detection.start - start),
        end: Math.min(text.length, detection.end - start),
      })
    }
  }
  /* v8 ignore next -- every string handed to the walkers was collected for this memo. */
  return { scan: text => memo.get(text) ?? [], truncated, indicators: countUnicodeIndicators(rendered) }
}

/** Text carried by a content array's text blocks. */
function contentStrings(blocks: readonly ContentBlock[]): string[] {
  return blocks.flatMap(block => block.type === 'text' ? [block.text] : [])
}

/**
 * Strings the harness keeps in the durable result when the decision does not
 * replace the canonical value.
 *
 * `tools/post-execute` returning `accept{content}` leaves `{...result}` in
 * place, so both `value` and the `presentationMeta()` projection reach
 * `session.append('tool/result', ...)` exactly as the tool produced them. They
 * are never model-visible and therefore never redacted by a content
 * replacement — which is why a content arm is not an option for a dirty
 * success.
 * @param result - the dispatch outcome the waterfall was called with.
 * @returns every string that would be persisted verbatim.
 */
function persistedStrings(result: Readonly<ToolExecutionResult>): string[] {
  return [
    ...result.isError ? [] : nestedStrings(result.value),
    ...result.meta === undefined ? [] : nestedStrings(result.meta),
  ]
}

/** What a redaction pass produced, before an arm is chosen. */
export interface ResultRedaction {
  readonly decision: PostToolDecision
  readonly spans: readonly RedactedSpan[]
  readonly truncatedScan: boolean
  /**
   * Runs of each invisible-character class the result carried, by rule id.
   * The `strip` classes also appear in `spans`; the `report` classes appear
   * only here, because rewriting them would corrupt legitimate emoji and
   * right-to-left text.
   */
  readonly indicators: Readonly<Record<string, number>>
}

/** Feedback for a result this plugin refuses to let through in any arm. */
function withheldFeedback(spans: readonly RedactedSpan[]): ContentBlock[] {
  const rules = [...new Set(spans.map(span => span.ruleId))].join(', ')
  const hashes = [...new Set(spans.map(span => span.hash))].join(', ')
  return [{
    type: 'text',
    text: 'dsh-dlp withheld this tool result: it carries credential material '
      + `(rule ${rules}, keyed hash ${hashes}) in a part of the result that cannot be rewritten without `
      + 'discarding it. Do not retry the same call. Ask the user for the value you need, or work from a source '
      + 'that is not a credential store.',
  }]
}

/**
 * Redact whatever the downstream decision settled on.
 *
 * Arm selection follows what each arm can actually clean:
 *
 * - `accept{value}` re-validates `output.schema`, re-runs `output.render()`
 *   and re-derives `presentationMeta()`, so one replacement redacts the
 *   canonical value, the model-facing content and the persisted meta together.
 *   It is the only arm that keeps a secret out of the durable log, so every
 *   successful result with anything to redact takes it.
 * - `accept{content}` replaces presentation only. It is used when the
 *   persisted surfaces are already clean — a failed result, which has no
 *   value, or a success whose secret exists only in the rendered content.
 * - `block` is the fallback when neither works: a failed result whose `meta`
 *   carries a secret, or a value that still scans dirty after redaction.
 *   Blocking replaces the whole result, which is the only way to drop `meta`.
 *
 * Replacing the value is re-validated by the registry against the tool's
 * `output.schema`, and a schema that pins the redacted string rejects it. That
 * surfaces as a `ToolOutputError` naming a validation failure, which tells the
 * model nothing it can act on, so the schema is checked here first and the
 * result is withheld with this plugin's own explanation instead.
 *
 * A downstream `accept{content}` over a dirty value is overruled by the value
 * arm, which discards that listener's presentation choice. Keeping it would
 * put the value in the session log; the harness re-renders from the redacted
 * value instead.
 * @param decision - what the rest of the waterfall returned.
 * @param result - the dispatch outcome the waterfall was called with.
 * @param policy - the effective policy.
 * @param hasher - mints each span's keyed hash.
 * @param outputSchema - the executing tool's declared output schema, when one could be resolved.
 * @returns the decision to return, the spans replaced, and scan completeness.
 */
export async function redactDecision(
  decision: PostToolDecision,
  result: Readonly<ToolExecutionResult>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
  outputSchema?: JsonSchemaNode,
): Promise<ResultRedaction> {
  if (decision.kind === 'block') {
    const prepared = await prepareScan(contentStrings(decision.feedback), policy)
    const redacted = redactContent(decision.feedback, prepared.scan, hasher)
    return {
      decision: redacted.changed ? { ...decision, feedback: redacted.content } : decision,
      spans: redacted.spans,
      truncatedScan: prepared.truncated,
      indicators: prepared.indicators,
    }
  }

  const replacedValue = Object.hasOwn(decision, 'value') ? decision.value : undefined
  const replacedContent = Object.hasOwn(decision, 'content') ? decision.content : undefined
  const contexts = decision.additionalContexts === undefined
    ? {}
    : { additionalContexts: decision.additionalContexts }

  // The value the harness will persist: a downstream replacement when there is
  // one, otherwise the tool's own. A failed result has no value at all.
  const value = replacedValue ?? (result.isError ? undefined : result.value)
  const visible = contentStrings(replacedContent ?? result.content)
  const persisted = replacedValue === undefined
    ? persistedStrings(result)
    : [...nestedStrings(replacedValue), ...result.meta === undefined ? [] : nestedStrings(result.meta)]

  const prepared = await prepareScan([...persisted, ...visible], policy)
  const dirty = (strings: readonly string[]): boolean => strings.some(text => prepared.scan(text).length > 0)

  if (value !== undefined && dirty(nestedStrings(value))) {
    const redacted = redactJson(value, prepared.scan, hasher)
    if (redactionBreaksSchema(outputSchema, value, redacted.value)) {
      return {
        decision: { kind: 'block', feedback: withheldFeedback(redacted.spans) },
        spans: redacted.spans,
        truncatedScan: prepared.truncated,
        indicators: prepared.indicators,
      }
    }
    const remaining = nestedStrings(redacted.value)
    const residual = await prepareScan(remaining, policy)
    if (remaining.some(text => residual.scan(text).length > 0)) {
      return {
        decision: { kind: 'block', feedback: withheldFeedback(redacted.spans) },
        spans: redacted.spans,
        truncatedScan: prepared.truncated || residual.truncated,
        indicators: prepared.indicators,
      }
    }
    return {
      decision: { kind: 'accept', value: redacted.value, ...contexts },
      spans: redacted.spans,
      truncatedScan: prepared.truncated,
      indicators: prepared.indicators,
    }
  }

  // The value is clean, so the durable result is clean unless `meta` — which
  // no accept arm can rewrite — carries something of its own.
  if (result.meta !== undefined && dirty(nestedStrings(result.meta))) {
    const spans = redactJson(result.meta, prepared.scan, hasher).spans
    return {
      decision: { kind: 'block', feedback: withheldFeedback(spans) },
      spans,
      truncatedScan: prepared.truncated,
      indicators: prepared.indicators,
    }
  }

  const blocks = replacedContent ?? result.content
  const redacted = redactContent(blocks, prepared.scan, hasher)
  if (!redacted.changed) {
    return { decision, spans: [], truncatedScan: prepared.truncated, indicators: prepared.indicators }
  }
  return {
    decision: { kind: 'accept', content: redacted.content, ...contexts },
    spans: redacted.spans,
    truncatedScan: prepared.truncated,
    indicators: prepared.indicators,
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
 * @returns the denial reason and its spans, or `undefined` to leave the call allowed.
 */
export async function evaluateBreadthTier(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): Promise<{ reason: string; spans: readonly RedactedSpan[] } | undefined> {
  if (!isEgressCapable(exec.name, policy.extraEgressTools)) return undefined
  const spans: RedactedSpan[] = []
  for (const text of new Set(nestedStrings(exec.arguments))) {
    const { detections } = await scanAll(text, policy.syncRules, policy.maxScanBytes)
    for (const detection of detections) {
      if (severityRank(detection.severity) < severityRank(DENY_SEVERITY)) continue
      spans.push({ ...detection, hash: hasher.hash(text.slice(detection.start, detection.end)) })
    }
  }
  if (spans.length === 0) return undefined
  const ruleIds = [...new Set(spans.map(span => span.ruleId))]
  return {
    reason: `dsh-dlp denied ${JSON.stringify(exec.name)}: its arguments contain credential material matching `
      + `${ruleIds.join(', ')} (keyed hash ${spans.map(span => span.hash).join(', ')}). `
      + 'Remove the credential from the call.',
    spans,
  }
}

/** A `PreToolDecision` denial built from a breadth-tier finding. */
export function breadthTierDenial(reason: string): PreToolDecision {
  return { kind: 'deny', reason }
}
