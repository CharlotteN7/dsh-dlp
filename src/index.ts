/**
 * `dsh-dlp` — data-loss prevention for DeepSeek Harness.
 *
 * Four registrations, in descending order of how much they can be trusted:
 *
 * 1. `ctx.tools.guard()` — an unconditional, non-configurable deny floor for
 *    credential paths named in a path-typed argument and for secrets heading
 *    into an egress-capable tool. Order-independent, because the guard seam
 *    has no allow arm.
 * 2. `tools/pre-execute` — the async breadth tier, which can await
 *    `@secretlint/core`. Neutralizable by any listener registered ahead of it.
 * 3. `tools/post-execute` — result redaction, applied before the `tool/result`
 *    session event is appended, so the durable log records the redacted copy;
 *    a result that cannot be cleaned is withheld rather than accepted.
 * 4. `session-telemetry/record` — fail-closed redaction of exported telemetry,
 *    reaching tier 1 only because the waterfall is synchronous.
 * 5. `llm/stream` — neutralising remote markdown image destinations in
 *    assistant output, before the text becomes a session event.
 *
 * Two of those registrations mitigate defects in the harness rather than in a
 * deployment's own configuration: the missing Content-Security-Policy behind
 * (5), and the mutable execution object behind the guard's mutation check.
 * Both are partial, neither closes its channel, and README.md says so beside
 * the feature.
 *
 * This plugin is not a containment boundary. It runs in-process at the agent's
 * own uid; anything the agent can execute can read the same files the guard
 * denies. See README.md.
 * @module dsh-dlp
 */

import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type { SessionTelemetryRecord } from '@deepseek-ai/dsh-session-telemetry'
import { loadRepoPolicy, resolvePolicy, type Config, type RepoPolicy } from './policy.ts'
import { SpanHasher } from './redaction.ts'
import { safeEvaluateGuard } from './guard.ts'
import { neutralizeImageStream } from './images.ts'
import { ExecutionSnapshots, mutationReason } from './mutation.ts'
import { breadthTierDenial, evaluateBreadthTier, redactDecision } from './results.ts'
import { redactRecord } from './telemetry.ts'
import { AuditSink, CallCorrelator, newDecisionId, RECORD_VERSION } from './sink.ts'

export { Config } from './policy.ts'

/** Display metadata; labels the plugin in Cordis diagnostics. */
export const name = 'dsh-dlp'

/** Services required before `apply` runs. */
export const inject = ['tools']

/** Bytes generated for a new installation redaction key. */
const KEY_BYTES = 32

/**
 * Read the installation's redaction key, creating it on first mount.
 *
 * The key makes every placeholder a keyed hash rather than a bare digest:
 * without it, anyone holding a candidate secret could confirm it against the
 * audit log.
 * @param path - the key file named by `redactionKeyFile`.
 * @returns the key bytes.
 * @throws when an existing key file is too short to be a key.
 */
export function loadOrCreateKey(path: string): Buffer {
  let existing: Buffer | undefined
  try {
    existing = readFileSync(path)
  } catch (error: unknown) {
    // Only absence means "first mount". A permission or I/O failure on an
    // existing key must not mint a new one: every placeholder and every audit
    // hash would change, silently breaking correlation with the whole history.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw new Error(`dsh-dlp: cannot read the redaction key at ${path}: ${String(error)}`)
    }
    existing = undefined
  }
  if (existing !== undefined) {
    if (existing.length < 16) {
      throw new Error(`dsh-dlp: redaction key at ${path} is ${existing.length} bytes; at least 16 are required`)
    }
    return existing
  }
  const created = randomBytes(KEY_BYTES)
  writeFileSync(path, created, { mode: 0o600 })
  return created
}

/**
 * Report a plugin fault on both the deployment's logger and `process.stderr`.
 *
 * `ctx.logger`'s default exporter is an in-memory 1000-entry ring buffer and
 * no shipped bundle mounts a console exporter, so a message that goes only to
 * the logger is invisible on a stock install — which is what an invalid policy
 * file and a failed audit write were. `process.stderr` is what the headless
 * runner itself writes to.
 * @param ctx - the plugin's context, used for its logger.
 * @param message - the whole line to report; never carries a matched value.
 */
function report(ctx: Context, message: string): void {
  ctx.logger.error(message)
  process.stderr.write(`${message}\n`)
}

/**
 * Load the repo-local policy tier, if the deployment named one.
 *
 * A missing file is no policy at all, and a malformed one is reported and
 * ignored. The floor never depends on a workspace file being present or
 * well-formed: the recommended `policyFile` is workspace-relative, so failing
 * the mount would refuse to start `dsh` in every repository without one, and
 * would let a hostile repository disable the plugin by shipping a broken file.
 * @param ctx - the plugin's context, used only to report a bad file.
 * @param policyFile - the configured path, or `undefined` when the deployment named none.
 * @returns the validated policy, or `undefined` when there is none to apply.
 */
function loadConfiguredPolicy(ctx: Context, policyFile: string | undefined): RepoPolicy | undefined {
  if (policyFile === undefined) return undefined
  const load = loadRepoPolicy(policyFile)
  switch (load.kind) {
    case 'absent':
      return undefined
    case 'loaded':
      return load.policy
    case 'invalid':
      report(ctx, `dsh-dlp: ignoring the repo-local policy at ${policyFile}: ${load.problem}`)
      return undefined
    /* v8 ignore next 4 -- unreachable while `RepoPolicyLoad` stays closed; the arm exists so adding a variant fails the build. */
    default: {
      const unhandled: never = load
      throw new TypeError(`dsh-dlp: unhandled repo policy load ${JSON.stringify(unhandled)}`)
    }
  }
}

/**
 * Mount the plugin.
 * @param ctx - the plugin's context; every registration is undone on unload.
 * @param config - validated `cordis.yml` configuration.
 */
export function apply(ctx: Context, config: Config): void {
  const policy = resolvePolicy(config, loadConfiguredPolicy(ctx, config.policyFile))
  const hasher = new SpanHasher(loadOrCreateKey(config.redactionKeyFile))
  const correlator = new CallCorrelator()
  const sink = new AuditSink(config.auditLog, (error) => {
    report(ctx, `dsh-dlp: audit sink write failed: ${String(error)}`)
  })

  /** Identity every audit record carries; the session-log envelope carries none of it. */
  const identity = (exec: Pick<ToolExecution, 'name' | 'callId' | 'rootCallId' | 'agent'>) => {
    const position = correlator.lookup(exec.callId)
    return {
      tool: exec.name,
      callId: exec.callId,
      rootCallId: exec.rootCallId,
      ...exec.agent === undefined ? {} : { sessionId: String(exec.agent.session.id) },
      ...position === undefined ? {} : { turn: position.turn, step: position.step },
    }
  }

  const snapshots = new ExecutionSnapshots(hasher)

  ctx.on('session/event', (_session: Session, event: SessionEvent) => {
    if (event.type === 'tool/call') {
      correlator.note(event.data.callId, { turn: event.data.turn, step: event.data.step })
      return
    }
    if (event.type === 'tool/result') {
      correlator.forget(event.data.message.source.callId)
    }
  })

  // Snapshot each call before the rest of the waterfall can rewrite it. The
  // prepend is best-effort by construction: a listener registered later with
  // the same option runs ahead of this one.
  ctx.on('tools/pre-execute', (exec: ToolExecution, next: () => Promise<PreToolDecision>) => {
    snapshots.record(exec)
    return next()
  }, { prepend: true })

  // The floor. Registered on a plain context so it applies globally: to every
  // agent, every `run_code` inner sub-call, and every subagent child.
  ctx.effect(() => ctx.tools.guard((exec) => {
    // Integrity first: a call whose name or arguments changed after `tool/call`
    // was appended is denied whatever the policy tables say about it, because
    // the log no longer describes what would run.
    const mutation = snapshots.detect(exec)
    if (mutation !== undefined) {
      sink.write({
        v: RECORD_VERSION,
        time: new Date().toISOString(),
        kind: 'execution-mutation',
        decisionId: newDecisionId(),
        ...identity(exec),
        mutatedFields: mutation.fields,
        ...mutation.fields.includes('name') ? { originalTool: mutation.originalTool } : {},
      })
      return mutationReason(exec, mutation)
    }
    const verdict = safeEvaluateGuard(exec, policy, hasher)
    if (verdict === undefined) return undefined
    sink.write({
      v: RECORD_VERSION,
      time: new Date().toISOString(),
      kind: 'guard-deny',
      decisionId: newDecisionId(),
      ...identity(exec),
      spans: verdict.spans,
    })
    return verdict.reason
  }), 'dsh-dlp guard floor')

  if (policy.breadthTier) {
    ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>) => {
      const decision = await next()
      if (decision.kind !== 'allow') return decision
      const finding = await evaluateBreadthTier(exec, policy, hasher)
      if (finding === undefined) return decision
      sink.write({
        v: RECORD_VERSION,
        time: new Date().toISOString(),
        kind: 'pre-execute-deny',
        decisionId: newDecisionId(),
        ...identity(exec),
        spans: finding.spans,
      })
      return breadthTierDenial(finding.reason)
    })
  }

  if (policy.resultRedaction) {
    ctx.on('tools/post-execute', async (
      exec: ToolExecution,
      result: Readonly<ToolExecutionResult>,
      next: () => Promise<PostToolDecision>,
    ) => {
      // The live definition, so a schema the deployment's own tool declares is
      // read from the registry rather than assumed. `exec.agent` is the scope
      // key: a scoped tool shadows a global one of the same name.
      const outputSchema = ctx.tools.get(exec.name, exec.agent)?.output.schema
      const redacted = await redactDecision(await next(), result, policy, hasher, outputSchema)
      const indicators = Object.keys(redacted.indicators).length > 0
        ? { unicode: redacted.indicators }
        : {}
      // A truncated scan is recorded even with nothing found: without a record
      // an operator cannot tell "this result was clean" from "this result was
      // only partly examined". An invisible-character run is recorded on the
      // same terms, because the `report` classes are never replaced and the
      // count is the only trace they leave.
      if (redacted.spans.length > 0 || redacted.truncatedScan || Object.keys(indicators).length > 0) {
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'result-redaction',
          decisionId: newDecisionId(),
          ...identity(exec),
          spans: redacted.spans,
          ...redacted.truncatedScan ? { truncatedScan: true } : {},
          ...indicators,
        })
      }
      return redacted.decision
    })
  }

  if (policy.remoteImageNeutralization) {
    ctx.on('llm/stream', (options: GenerateOptions, next: () => AsyncIterable<StreamChunk>) =>
      neutralizeImageStream(next(), (host) => {
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'assistant-image-neutralized',
          decisionId: newDecisionId(),
          ...options.sessionId === undefined ? {} : { sessionId: String(options.sessionId) },
          host,
        })
      }))
  }

  if (policy.telemetryRedaction) {
    ctx.on('session-telemetry/record', (
      _record: SessionTelemetryRecord,
      next: () => SessionTelemetryRecord,
    ) => {
      // Throwing here withholds this one record; the coordinator contains it
      // and the agent loop never sees the failure. That is the fail-closed
      // behavior this listener wants.
      const redacted = redactRecord(next(), policy, hasher)
      if (redacted.spans.length > 0) {
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'telemetry-redaction',
          decisionId: newDecisionId(),
          channel: redacted.record.channel,
          ...typeof redacted.record.attributes['session.id'] === 'string'
            ? { sessionId: redacted.record.attributes['session.id'] }
            : {},
          spans: redacted.spans,
        })
      }
      return redacted.record
    })
  }
}
