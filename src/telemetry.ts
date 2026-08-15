/**
 * Fail-closed redaction for exported telemetry.
 *
 * `DSH_TELEMETRY_MODE=FULL` mounts the OTel backend with a live coordinator
 * that exports a deep copy of every session event's `data` — user and
 * assistant message text, tool arguments, tool results — plus identity
 * attributes including `session.cwd`. The `session-telemetry/record` waterfall
 * is the documented redaction seam and it ships **no rules of its own**: with
 * nothing mounted, records reach the exporter exactly as captured. This
 * listener is the missing rule set.
 *
 * The waterfall is synchronous (`next: () => SessionTelemetryRecord`), so only
 * tier 1 is reachable here. It is fail-closed by construction: the coordinator
 * dispatches inside its own containment, and a throwing listener withholds
 * that one record and never reaches the agent loop. This module therefore
 * throws rather than returning a record it could not fully process.
 *
 * Records mirroring `tool/result` are already clean, because
 * `tools/post-execute` redaction runs before the event is appended. The value
 * added here is on `user/message`, `assistant/message`, `tool/call` arguments,
 * and the workspace path.
 * @module dsh-dlp/telemetry
 */

import type { SessionTelemetryRecord } from '@deepseek-ai/dsh-session-telemetry'
import type { JsonValue } from '@deepseek-ai/dsh-session'
import { scanSync, type Detection } from './detectors.ts'
import type { ResolvedPolicy } from './policy.ts'
import { placeholderFor, redactJson, redactText, type RedactedSpan, type SpanHasher } from './redaction.ts'

/** Attribute keys whose values are filesystem paths rather than payload text. */
const PATH_ATTRIBUTES = ['session.cwd'] as const

/** Rule identity recorded when a workspace path is replaced. */
export const WORKSPACE_PATH_RULE = 'dsh-dlp/telemetry-workspace-path'

/** One redacted telemetry record and what was replaced in it. */
export interface RedactedRecord {
  readonly record: SessionTelemetryRecord
  readonly spans: readonly RedactedSpan[]
}

/**
 * Redact one outbound telemetry record.
 *
 * The record is treated as data, not as a typed structure: `body` is the
 * event's own `data`, whose shape is owned by whichever package declared the
 * event, and new event types appear without this plugin knowing them. Walking
 * it as JSON is what makes the listener total.
 * @param record - the candidate record, already the coordinator's own deep copy.
 * @param policy - the effective policy.
 * @param hasher - mints each span's keyed hash.
 * @returns the record to hand onward and the spans replaced.
 */
export function redactRecord(
  record: SessionTelemetryRecord,
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): RedactedRecord {
  const spans: RedactedSpan[] = []
  const scan = (text: string): readonly Detection[] => scanSync(text, policy.syncRules, policy.maxScanBytes).detections

  // `body` is `unknown` on the seam but is always the append-time-validated,
  // JSON-serializable `data` of a session event.
  const body = redactJson(record.body as JsonValue, scan, hasher)
  spans.push(...body.spans)

  const attributes: Record<string, string | number> = {}
  for (const [key, value] of Object.entries(record.attributes)) {
    if (typeof value !== 'string') {
      attributes[key] = value
      continue
    }
    if (policy.redactTelemetryWorkspacePaths && (PATH_ATTRIBUTES as readonly string[]).includes(key)) {
      const span: RedactedSpan = {
        ruleId: WORKSPACE_PATH_RULE,
        ruleVersion: 1,
        severity: 'medium',
        start: 0,
        end: value.length,
        hash: hasher.hash(value),
        path: `/attributes/${key}`,
      }
      spans.push(span)
      attributes[key] = placeholderFor(span)
      continue
    }
    const redacted = redactText(value, scan(value), hasher, `/attributes/${key}`)
    spans.push(...redacted.spans)
    attributes[key] = redacted.text
  }

  if (spans.length === 0) return { record, spans }
  return { record: { ...record, body: body.value, attributes }, spans }
}
