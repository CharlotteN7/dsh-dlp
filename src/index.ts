/**
 * `dsh-dlp` — data-loss prevention for DeepSeek Harness.
 *
 * Four registrations, in descending order of how much they can be trusted:
 *
 * 1. `ctx.tools.guard()` — an unconditional, non-configurable deny floor for
 *    credential-path access and for secrets heading into an egress-capable
 *    tool. Order-independent, because the guard seam has no allow arm.
 * 2. `tools/pre-execute` — the async breadth tier, which can await
 *    `@secretlint/core`. Neutralizable by any listener registered ahead of it.
 * 3. `tools/post-execute` — result redaction, applied before the `tool/result`
 *    session event is appended, so the durable log records the redacted copy.
 * 4. `session-telemetry/record` — fail-closed redaction of exported telemetry.
 *
 * This plugin is not a containment boundary. It runs in-process at the agent's
 * own uid; anything the agent can execute can read the same files the guard
 * denies. See README.md.
 * @module dsh-dlp
 */

import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import type { Session, SessionEvent } from '@deepseek-ai/dsh-session'
import type { SessionTelemetryRecord } from '@deepseek-ai/dsh-session-telemetry'
import { loadRepoPolicy, resolvePolicy, type Config } from './policy.ts'
import { SpanHasher } from './redaction.ts'
import { safeEvaluateGuard } from './guard.ts'
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
  } catch {
    // ENOENT on first mount; any other read failure resurfaces from the write below.
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
 * Mount the plugin.
 * @param ctx - the plugin's context; every registration is undone on unload.
 * @param config - validated `cordis.yml` configuration.
 */
export function apply(ctx: Context, config: Config): void {
  const repo = config.policyFile === undefined ? undefined : loadRepoPolicy(config.policyFile)
  const policy = resolvePolicy(config, repo)
  const hasher = new SpanHasher(loadOrCreateKey(config.redactionKeyFile))
  const correlator = new CallCorrelator()
  const sink = new AuditSink(config.auditLog, (error) => {
    ctx.logger.error(`dsh-dlp: audit sink write failed: ${String(error)}`)
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

  ctx.on('session/event', (_session: Session, event: SessionEvent) => {
    if (event.type === 'tool/call') {
      correlator.note(event.data.callId, { turn: event.data.turn, step: event.data.step })
      return
    }
    if (event.type === 'tool/result') {
      correlator.forget(event.data.message.source.callId)
    }
  })

  // The floor. Registered on a plain context so it applies globally: to every
  // agent, every `run_code` inner sub-call, and every subagent child.
  ctx.effect(() => ctx.tools.guard((exec) => {
    const verdict = safeEvaluateGuard(exec, policy, hasher)
    if (verdict === undefined) return undefined
    sink.write({
      v: RECORD_VERSION,
      time: new Date().toISOString(),
      kind: 'guard-deny',
      decisionId: newDecisionId(),
      ...identity(exec),
      reason: verdict.reason,
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
        reason: finding.reason,
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
      const redacted = await redactDecision(await next(), result, policy, hasher)
      if (redacted.spans.length > 0) {
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'result-redaction',
          decisionId: newDecisionId(),
          ...identity(exec),
          spans: redacted.spans,
          ...redacted.truncatedScan ? { truncatedScan: true } : {},
        })
      }
      return redacted.decision
    })
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
