/**
 * Turning {@link Detection}s into redacted text, and the keyed hash that lets
 * an operator correlate two placeholders without the plugin ever writing the
 * secret.
 *
 * Two properties this module exists to hold:
 *
 * - **Spans are expanded before they are spliced.** Tier-2 spans are advisory
 *   and verified to under-cover a secret, so every span grows outward to
 *   whitespace boundaries and overlapping spans merge. Over-redaction is the
 *   safe direction.
 * - **The placeholder is deterministic.** `HMAC-SHA256(key, span)` truncated
 *   to 12 hex characters — stable for the same secret under the same
 *   installation key, useless to anyone without the key.
 * @module dsh-dlp/redaction
 */

import { createHmac } from 'node:crypto'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import { severityRank, type Detection, type Severity } from './detectors.ts'

/**
 * A value that round-trips through JSON without loss.
 *
 * Declared here rather than imported. Upstream moved this alias out of
 * `@deepseek-ai/dsh-session` and into `@deepseek-ai/dsh-util-values` in
 * `0.1.2-alpha.2`; the new package does not exist in any release the peer
 * ranges also admit, and a TypeScript import cannot name two homes, so either
 * import breaks half the supported range. The alias is structural and carries
 * no runtime, so a local copy is assignable in both directions wherever it
 * meets upstream's — and nothing outside this package is handed one.
 */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

/** One replaced region, described without disclosing what it held. */
export interface RedactedSpan {
  /** Rule that justified the replacement; the strictest one when spans merged. */
  readonly ruleId: string
  readonly ruleVersion: number
  readonly severity: Severity
  readonly start: number
  readonly end: number
  /** Keyed hash of the replaced text; never the text itself. */
  readonly hash: string
  /** JSON pointer to the string this span came from, when the scan walked a structure. */
  readonly path?: string
}

/** Result of redacting one string. */
export interface RedactedText {
  readonly text: string
  readonly spans: readonly RedactedSpan[]
}

/** Number of hex characters kept from the HMAC digest. */
const HASH_LENGTH = 12

/**
 * Mints the keyed hashes that appear in placeholders and audit records. Holds
 * the installation key; the key never leaves this object.
 */
export class SpanHasher {
  readonly #key: Buffer

  /**
   * @param key - installation secret, at least 16 bytes, read from `redactionKeyFile`.
   */
  constructor(key: Buffer) {
    if (key.length < 16) throw new Error('dsh-dlp: redaction key must be at least 16 bytes')
    this.#key = Buffer.from(key)
  }

  /**
   * Keyed hash of one replaced region.
   * @param text - the exact text being replaced.
   * @returns 12 lowercase hex characters.
   */
  hash(text: string): string {
    return createHmac('sha256', this.#key).update(text, 'utf8').digest('hex').slice(0, HASH_LENGTH)
  }
}

/**
 * Shorten a rule id for the placeholder. Secretlint's package-qualified ids
 * are long enough to dominate the replacement text.
 * @param ruleId - the full rule identity.
 * @returns the readable tail of the id.
 */
export function shortRuleId(ruleId: string): string {
  return ruleId
    .replace('@secretlint/secretlint-rule-', '')
    .replace('dsh-dlp/', '')
}

/**
 * The text substituted for one redacted span.
 * @param span - the span being replaced.
 * @returns a stable placeholder carrying the rule and the keyed hash.
 */
export function placeholderFor(span: Pick<RedactedSpan, 'ruleId' | 'hash'>): string {
  return `[REDACTED:dsh-dlp:${shortRuleId(span.ruleId)}:${span.hash}]`
}

/**
 * Characters that end a secret. Whitespace alone is not enough: one detection
 * inside a line of minified JSON would expand to the whole line and destroy
 * every other field on it, so quotes and the JSON, query-string and
 * assignment separators bound a span too.
 */
const SPAN_DELIMITERS = /[\s"'`=:,;&?<>(){}[\]]/

/** Grow one span outward until both edges sit on a delimiter or a string boundary. */
function expand(text: string, start: number, end: number): { start: number; end: number } {
  let left = Math.max(0, start)
  let right = Math.min(text.length, end)
  while (left > 0 && !SPAN_DELIMITERS.test(text.charAt(left - 1))) left -= 1
  while (right < text.length && !SPAN_DELIMITERS.test(text.charAt(right))) right += 1
  return { start: left, end: right }
}

/** Detections merged into non-overlapping regions, each attributed to its strictest rule. */
function mergeSpans(text: string, detections: readonly Detection[]): Omit<RedactedSpan, 'hash'>[] {
  const expanded = detections
    .map(({ ruleId, ruleVersion, severity, exact, start, end }) => ({
      ruleId,
      ruleVersion,
      severity,
      // An exact detection covers precisely what must go: widening an
      // invisible character to its delimiters would delete the visible word
      // around it.
      ...exact === true ? { start, end } : expand(text, start, end),
    }))
    .sort((left, right) => left.start - right.start || left.end - right.end)
  const merged: Omit<RedactedSpan, 'hash'>[] = []
  for (const candidate of expanded) {
    const previous = merged.at(-1)
    if (previous === undefined || candidate.start > previous.end) {
      merged.push(candidate)
      continue
    }
    const stricter = severityRank(candidate.severity) > severityRank(previous.severity)
    merged[merged.length - 1] = {
      ruleId: stricter ? candidate.ruleId : previous.ruleId,
      ruleVersion: stricter ? candidate.ruleVersion : previous.ruleVersion,
      severity: stricter ? candidate.severity : previous.severity,
      start: previous.start,
      end: Math.max(previous.end, candidate.end),
    }
  }
  return merged
}

/**
 * Replace every detected region of one string with its placeholder.
 * @param text - the string to redact.
 * @param detections - matches reported by either detection tier.
 * @param hasher - mints each span's keyed hash.
 * @param path - JSON pointer recorded on every span, when scanning a structure.
 * @returns the redacted string and the spans that were replaced.
 */
export function redactText(
  text: string,
  detections: readonly Detection[],
  hasher: SpanHasher,
  path?: string,
): RedactedText {
  if (detections.length === 0) return { text, spans: [] }
  const spans: RedactedSpan[] = []
  const pieces: string[] = []
  let cursor = 0
  for (const region of mergeSpans(text, detections)) {
    const span: RedactedSpan = {
      ...region,
      hash: hasher.hash(text.slice(region.start, region.end)),
      ...path === undefined ? {} : { path },
    }
    pieces.push(text.slice(cursor, span.start), placeholderFor(span))
    spans.push(span)
    cursor = span.end
  }
  pieces.push(text.slice(cursor))
  return { text: pieces.join(''), spans }
}

/**
 * Every string reachable inside a value, at any depth. Object keys are not
 * included: a key is structure, not payload.
 * @param value - parsed tool arguments, a tool's canonical output, or any JSON value.
 * @returns each string found, in traversal order.
 */
export function nestedStrings(value: unknown): string[] {
  const found: string[] = []
  const walk = (node: unknown): void => {
    if (typeof node === 'string') {
      found.push(node)
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (typeof node === 'object' && node !== null) {
      for (const item of Object.values(node)) walk(item)
    }
  }
  walk(value)
  return found
}

/** Escape one JSON pointer segment per RFC 6901. */
function pointerSegment(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1')
}

/**
 * Redact every string inside a JSON value, at any depth.
 *
 * Object *keys* are left alone: a key is structure, not payload, and renaming
 * one would break the owning tool's `output.schema` on re-validation.
 * @param value - the structure to redact.
 * @param scan - synchronous detector applied to each string.
 * @param hasher - mints each span's keyed hash.
 * @returns the redacted structure, the spans replaced, and whether anything changed.
 */
export function redactJson(
  value: JsonValue,
  scan: (text: string) => readonly Detection[],
  hasher: SpanHasher,
): { value: JsonValue; spans: readonly RedactedSpan[]; changed: boolean } {
  const spans: RedactedSpan[] = []
  let changed = false

  const walk = (node: JsonValue, path: string): JsonValue => {
    if (typeof node === 'string') {
      const redacted = redactText(node, scan(node), hasher, path)
      if (redacted.spans.length === 0) return node
      changed = true
      spans.push(...redacted.spans)
      return redacted.text
    }
    if (Array.isArray(node)) {
      return node.map((item, index) => walk(item, `${path}/${index}`))
    }
    if (typeof node === 'object' && node !== null) {
      return Object.fromEntries(
        Object.entries(node).map(([key, item]) => [key, walk(item, `${path}/${pointerSegment(key)}`)]),
      )
    }
    return node
  }

  const result = walk(value, '')
  return { value: result, spans, changed }
}

/**
 * Redact the text blocks of one model-facing content array. Non-text blocks
 * pass through: this plugin has no detector for image or audio payloads and
 * silently dropping them would be worse than leaving them.
 * @param blocks - the content blocks to redact.
 * @param scan - synchronous detector applied to each block's text.
 * @param hasher - mints each span's keyed hash.
 * @returns the redacted blocks, the spans replaced, and whether anything changed.
 */
export function redactContent(
  blocks: readonly ContentBlock[],
  scan: (text: string) => readonly Detection[],
  hasher: SpanHasher,
): { content: ContentBlock[]; spans: readonly RedactedSpan[]; changed: boolean } {
  const spans: RedactedSpan[] = []
  let changed = false
  const content = blocks.map((block, index): ContentBlock => {
    if (block.type !== 'text') return block
    const redacted = redactText(block.text, scan(block.text), hasher, `/${index}/text`)
    if (redacted.spans.length === 0) return block
    changed = true
    spans.push(...redacted.spans)
    return { ...block, text: redacted.text }
  })
  return { content, spans, changed }
}
