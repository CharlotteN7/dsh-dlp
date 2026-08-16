/**
 * Detecting a tool call that was rewritten after it was logged.
 *
 * The registry deep-freezes `exec.arguments` but does not freeze the execution
 * object until results are notified, so a `tools/pre-execute` listener can
 * reassign `exec.arguments` or `exec.name` — and reassigning `exec.name`
 * changes which tool body runs. The agent loop appended `tool/call` from the
 * model's own response block before the waterfall ran, so nothing in the
 * session log records the change: the durable record then describes a
 * different call than the one about to execute.
 *
 * This module snapshots the call as early in the waterfall as it can and
 * compares in the guard, which runs after the whole waterfall and cannot be
 * out-ordered. It is detection, not prevention: preventing the rewrite would
 * mean freezing an object this plugin does not own, and the snapshot itself is
 * best-effort — a later `{ prepend: true }` registration runs ahead of ours and
 * would be snapshotted after its own rewrite.
 * @module dsh-dlp/mutation
 */

import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import type { SpanHasher } from './redaction.ts'

/** The parts of an execution this module compares. */
type Comparable = Pick<ToolExecution, 'name' | 'arguments'>

/** What the snapshot recorded before the rest of the waterfall ran. */
interface Snapshot {
  readonly name: string
  /** Keyed hash of the canonical rendering of the arguments. */
  readonly digest: string
}

/** One rewritten field. */
export type MutatedField = 'name' | 'arguments'

/** A call whose identity changed between the snapshot and the guard. */
export interface ExecutionMutation {
  /** Which fields differ, in a stable order. */
  readonly fields: readonly MutatedField[]
  /** The tool name the session log recorded. */
  readonly originalTool: string
}

/**
 * Render a JSON value with object keys in a fixed order, so two equal argument
 * sets hash equally whatever order a listener rebuilt them in.
 * @param value - the argument value; JSON-serializable by the registry's own snapshot step.
 * @returns a canonical string for hashing.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object' && value !== null) {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(',')}}`
  }
  // `undefined` has no JSON rendering; it reaches here only for an execution
  // whose arguments never materialized, which the registry fails before the
  // waterfall. A fixed token keeps the digest total either way.
  return JSON.stringify(value) ?? 'undefined'
}

/**
 * Remembers what each pending call looked like before the rest of the
 * `tools/pre-execute` waterfall ran.
 *
 * Keyed by the execution object's identity in a `WeakMap`, the way the
 * registry keys its own per-execution state, so the entry is found again in
 * the guard and released with the execution.
 */
export class ExecutionSnapshots {
  readonly #snapshots = new WeakMap<object, Snapshot>()
  readonly #hasher: SpanHasher

  /**
   * @param hasher - mints the keyed digest of the arguments; the values themselves are never stored.
   */
  constructor(hasher: SpanHasher) {
    this.#hasher = hasher
  }

  /**
   * Snapshot one pending call.
   * @param exec - the execution as the earliest listener sees it.
   */
  record(exec: Comparable): void {
    this.#snapshots.set(exec, { name: exec.name, digest: this.#hasher.hash(canonicalJson(exec.arguments)) })
  }

  /**
   * Compare one call against its snapshot.
   *
   * A call with no snapshot is not a finding: the listener may never have run
   * for it, and reporting absence as mutation would deny calls this plugin
   * simply did not observe.
   * @param exec - the execution as the guard stage sees it.
   * @returns what changed, or `undefined` when nothing did.
   */
  detect(exec: Comparable): ExecutionMutation | undefined {
    const snapshot = this.#snapshots.get(exec)
    if (snapshot === undefined) return undefined
    const fields: MutatedField[] = []
    if (exec.name !== snapshot.name) fields.push('name')
    if (this.#hasher.hash(canonicalJson(exec.arguments)) !== snapshot.digest) fields.push('arguments')
    return fields.length === 0 ? undefined : { fields, originalTool: snapshot.name }
  }
}

/**
 * Denial text for a rewritten call.
 *
 * Both tool names are named: a tool name is already in the session log and in
 * every other denial this plugin writes, and naming them is the whole point —
 * the operator needs to know which call the log describes and which one was
 * about to run. No argument value appears.
 * @param exec - the call as the guard sees it, after the rewrite.
 * @param mutation - the fields that changed and the recorded tool name.
 * @returns the model-facing reason.
 */
export function mutationReason(exec: Comparable, mutation: ExecutionMutation): string {
  const changed = mutation.fields.join(' and ')
  const renamed = mutation.fields.includes('name')
    ? ` The session log records a call to ${JSON.stringify(mutation.originalTool)}.`
    : ''
  return `dsh-dlp denied ${JSON.stringify(exec.name)}: another mounted plugin rewrote this call's ${changed} `
    + `after the session log recorded it, so the log and the presented call describe something other than what `
    + `would have run.${renamed} The call is denied because a tool call that cannot be reconstructed from the log `
    + 'is not auditable. This is a defect in a mounted plugin, not in the call; report it to the deployment operator.'
}
