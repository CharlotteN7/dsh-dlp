/**
 * This plugin's own durable output, and the call correlation that makes a
 * record locatable.
 *
 * Nothing here touches the session log. `Session.append()` offers no way to
 * set the envelope's `ignorable` flag, so an out-of-repo event type is written
 * without it and the user's next resume throws `SessionFormatUnsupportedError`
 * and refuses the whole session. The plugin is therefore read-side with
 * respect to the log, and every durable record goes to the JSONL file named by
 * `auditLog`.
 *
 * Because the `SessionEvent` envelope carries only `type`, `seq`, `time` and
 * `data`, each record carries its own identity: `sessionId`, `turn`, `step`,
 * `callId`, and a producer-minted `decisionId`.
 * @module dsh-dlp/sink
 */

import { appendFileSync, chmodSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { stripControlSequences } from './detectors.ts'
import type { AskUnreachable } from './approval-reach.ts'
import type { RedactedSpan } from './redaction.ts'

declare const decisionIdBrand: unique symbol

/** Producer-minted id correlating one decision across records. */
export type DecisionId = string & { readonly [decisionIdBrand]: true }

/**
 * Mint a decision id.
 * @returns an id unique to one guard verdict or redaction pass.
 */
export function newDecisionId(): DecisionId {
  return `dlp-${randomUUID()}` as DecisionId
}

/** Payload version carried inside every record this plugin writes. */
export const RECORD_VERSION = 1

/**
 * Mode the sink file is kept at.
 *
 * The records hold rule ids, keyed hashes, tool names and call identity — no
 * matched value ever reaches them — but they are the evidence that a decision
 * happened, so they are readable by the operator's group and never by the
 * world. This is the mode the sibling packages keep their spools at.
 */
export const AUDIT_MODE = 0o640

/** What produced one audit record. */
export type AuditKind =
  | 'guard-deny'
  | 'pre-execute-deny'
  | 'pre-execute-ask'
  | 'pre-execute-ask-abstained'
  | 'execution-mutation'
  | 'result-redaction'
  | 'telemetry-redaction'
  | 'assistant-image-neutralized'
  | 'audit-failure'

/** One durable record. Never carries matched secret text. */
export interface AuditRecord {
  readonly v: number
  /** ISO-8601 capture time. */
  readonly time: string
  readonly kind: AuditKind
  readonly decisionId: DecisionId
  readonly sessionId?: string
  readonly turn?: number
  readonly step?: number
  readonly callId?: string
  readonly rootCallId?: string
  readonly tool?: string
  /**
   * Redacted or denied regions: rule identity, offsets, and a keyed hash only.
   *
   * This is the whole description of what matched. The model-facing denial
   * text is deliberately not recorded: it names a tool and quotes nothing, but
   * a reason built from a candidate would put the candidate — a shell command
   * line, a tenant directory — into a durable file, which is exactly what this
   * sink exists to avoid.
   */
  readonly spans?: readonly RedactedSpan[]
  /** Set when the scanned input exceeded the byte cap. */
  readonly truncatedScan?: boolean
  /**
   * Runs of each invisible-character class the scanned text carried, by rule
   * id. Counts only: the characters themselves are content, and a hidden
   * instruction is exactly the content this file must not repeat.
   */
  readonly unicode?: Readonly<Record<string, number>>
  /**
   * The single rule behind a decision that has no matched region to describe,
   * which is every `pre-execute-ask`: the finding is that a path names a
   * behaviour-changing file, not that any part of it matched a secret.
   */
  readonly ruleId?: string
  /**
   * Which state left the ask tier with nowhere to ask, for a
   * `pre-execute-ask-abstained`. An abstention allowed a call the tier would
   * otherwise have asked about, so the state that caused it is the field an
   * operator needs to change to get the prompt back.
   */
  readonly askUnreachable?: AskUnreachable
  /** Telemetry record channel, for `telemetry-redaction`. */
  readonly channel?: string
  /** Fields another plugin rewrote after the call was logged, for `execution-mutation`. */
  readonly mutatedFields?: readonly string[]
  /** Tool name the session log recorded, when a rewrite changed it. */
  readonly originalTool?: string
  /**
   * Hostname of a neutralised remote image destination, for
   * `assistant-image-neutralized`. The hostname only: a path and a query
   * string are where an exfiltration payload rides, and this file must not
   * carry it.
   */
  readonly host?: string
}

/**
 * One record with every string cleaned of terminal control sequences.
 *
 * A record carries strings this plugin did not author — a tool's registered
 * name, a call id, a rule id from the repo-local policy tier — and a reader
 * gets them back unescaped: `JSON.stringify` writes `\u001b` to the file, but
 * `dsh-dlp report`, `jq -r` and any log viewer parse that back into a live
 * escape. A tool named with a CSI sequence could then overwrite the line
 * describing it, which is the forged-audit-record half of CVE-2026-35651.
 * Cleaning here means every consumer of the file gets the cleaned form.
 * @param value - any part of a record.
 * @returns the same structure with control sequences replaced.
 */
function cleaned(value: unknown): unknown {
  if (typeof value === 'string') return stripControlSequences(value)
  if (Array.isArray(value)) return value.map(cleaned)
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [stripControlSequences(key), cleaned(item)]))
  }
  return value
}

/** Append-only JSONL sink for this plugin's decisions. */
export class AuditSink {
  readonly #path: string
  readonly #onFailure: (error: unknown) => void

  /**
   * @param path - absolute path of the JSONL file to append to.
   * @param onFailure - notified when a write fails; a broken sink never changes a verdict.
   */
  constructor(path: string, onFailure: (error: unknown) => void) {
    this.#path = path
    this.#onFailure = onFailure
  }

  /**
   * Append one record.
   *
   * A write failure is reported and swallowed on purpose: the sink is
   * evidence, not enforcement, and letting a full disk turn every tool call
   * into a denial trades a confidentiality control for an availability
   * outage. A guard that throws would also skip `tools/post-execute` and so
   * disable redaction for that call. A failure to hold
   * {@link AUDIT_MODE} is reported on the same terms: the record is written
   * either way, and an operator who cannot see the mode cannot know who else
   * can read the file.
   * @param record - the decision to record.
   */
  write(record: AuditRecord): void {
    try {
      appendFileSync(this.#path, `${JSON.stringify(cleaned(record))}\n`, { mode: AUDIT_MODE })
      // `appendFileSync`'s `mode` applies only when the call creates the file,
      // and even then the umask masks it, so the mode is forced afterwards.
      // Forcing it on every append also takes back a loosening applied to an
      // existing sink.
      chmodSync(this.#path, AUDIT_MODE)
    } catch (error: unknown) {
      this.#onFailure(error)
    }
  }
}

/** Turn and step of one in-flight tool call. */
export interface CallPosition {
  readonly turn: number
  readonly step: number
}

/**
 * Remembers where each in-flight tool call sits in the session.
 *
 * `Agent` exposes no turn or step, and the tool pipeline hands listeners only
 * a `ToolExecution`. The `tool/call` session event carries `turn`, `step` and
 * `callId` together, so following the session firehose is the only way to
 * label a record with its position.
 */
export class CallCorrelator {
  readonly #positions = new Map<string, CallPosition>()
  readonly #limit: number

  /**
   * @param limit - maximum remembered calls; the oldest entry is dropped past it.
   */
  constructor(limit = 512) {
    this.#limit = limit
  }

  /**
   * Record one call's position.
   * @param callId - the call's id from the `tool/call` event.
   * @param position - the turn and step that event reported.
   */
  note(callId: string, position: CallPosition): void {
    this.#positions.set(callId, position)
    if (this.#positions.size > this.#limit) {
      const oldest = this.#positions.keys().next()
      /* v8 ignore next -- reached only past the limit, so the map is never empty here. */
      if (!oldest.done) this.#positions.delete(oldest.value)
    }
  }

  /**
   * Forget one call.
   * @param callId - the call whose result has been committed.
   */
  forget(callId: string): void {
    this.#positions.delete(callId)
  }

  /**
   * Look one call's position up.
   * @param callId - the call to locate.
   * @returns its turn and step, or `undefined` when the call was never seen.
   */
  lookup(callId: string): CallPosition | undefined {
    return this.#positions.get(callId)
  }
}
