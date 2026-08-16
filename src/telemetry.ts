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
 * tier 1 is reachable here — there is no seam on this path that can await, and
 * a secret only `@secretlint/core` recognises survives it. It is fail-closed
 * by construction: the coordinator dispatches inside its own containment, and a
 * throwing listener withholds that one record and never reaches the agent
 * loop. This module therefore throws rather than returning a record it could
 * not fully process.
 *
 * Records mirroring `tool/result` have already been through
 * `tools/post-execute` redaction, which runs before the event is appended —
 * but only for what that seam could reach, so this listener re-scans every
 * record rather than trusting the event type. The value it adds beyond that is
 * on `user/message`, `assistant/message`, `tool/call` arguments, and the
 * workspace path.
 * @module dsh-dlp/telemetry
 */

import type { SessionTelemetryRecord, SessionTelemetrySharingStatus } from '@deepseek-ai/dsh-session-telemetry'
import type { JsonValue } from '@deepseek-ai/dsh-session'
import { scanSync, type Detection } from './detectors.ts'
import type { ResolvedPolicy } from './policy.ts'
import { placeholderFor, redactJson, redactText, type RedactedSpan, type SpanHasher } from './redaction.ts'

/**
 * What to tell the operator when the redaction seam will never dispatch.
 *
 * A `session-telemetry/record` listener mounts successfully and never runs
 * unless a backend built a coordinator, and the shipped default builds none:
 * the mode is `DISABLED`, so nothing is exported and nothing is dispatched.
 * That is the safe posture, not a leak — but an operator who mounts a redactor
 * under it sees every signal of success and has verified nothing. The
 * backend's own `sharing` disclosure is the resolved answer, so this never
 * guesses at `DSH_TELEMETRY_MODE`, which is only the base patch's default
 * expression for a `mode` a deployment can also set directly.
 * @param sharing - the mounted backend's disclosure, or `undefined` when no backend is mounted.
 * @returns the line to report, or `undefined` when the seam does dispatch.
 */
export function telemetrySeamNotice(sharing: SessionTelemetrySharingStatus | undefined): string | undefined {
  const consequence = 'nothing dispatches the session-telemetry/record waterfall and this plugin\'s telemetry'
    + ' redaction never runs. Nothing is exported in this state, so this is not a leak — it means the redaction'
    + ' rules are unverified, and they begin running the moment telemetry is turned on. Informational only: the'
    + ' plugin\'s other seams are unaffected.'
  switch (sharing) {
    case 'disabled':
      return 'dsh-dlp: telemetryRedaction is enabled, but the mounted session-telemetry backend reports sharing'
        + ` "disabled", so ${consequence}`
    case undefined:
      return `dsh-dlp: telemetryRedaction is enabled, but no session-telemetry backend is mounted, so ${consequence}`
    default:
      return undefined
  }
}

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
  const scan = (text: string): readonly Detection[] => scanSync(text, policy.syncRules).detections

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
