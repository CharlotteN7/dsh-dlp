/**
 * `dsh-dlp` — data-loss prevention for DeepSeek Harness.
 *
 * Seven registrations, in descending order of how much they can be trusted:
 *
 * 1. `ctx.tools.guard()` — an unconditional, non-configurable deny floor for
 *    credential paths named in a path-typed argument and for secrets heading
 *    into an egress-capable tool. Order-independent, because the guard seam
 *    has no allow arm.
 * 2. `tools/pre-execute` — the async breadth tier, which can await
 *    `@secretlint/core`. Neutralizable by any listener registered ahead of it.
 * 2b. `tools/pre-execute` — the `ask` tier, for writes to behaviour-changing
 *    config paths and for calls carrying an argument that switches their own
 *    confirmation off. Deliberately here rather than on the floor: its rules
 *    have a real false-positive rate and the floor cannot ask. Neutralizable,
 *    and it abstains entirely wherever the approval seam cannot prompt anyone.
 * 3. `tools/post-execute` — result redaction, applied before the `tool/result`
 *    session event is appended, so the durable log records the redacted copy;
 *    a result that cannot be cleaned is withheld rather than accepted.
 *    Prepended, so it redacts what the rest of the waterfall returned; a
 *    listener registering later with the same option still runs ahead of it.
 * 3b. `agent/pre-step` — redaction of the messages one step enters with: the
 *    context a listener splices in (the workspace instruction chain, the
 *    session skill catalog, a captured terminal pane, a hook's
 *    `additionalContext`) and the input the loop claimed from the inbox that
 *    the user did not type (a `dsh-webhook` delivery, a subagent's settled
 *    result, an agent relay). The loop appends what this waterfall returns as
 *    the `user/message` surface events every request is derived from, so the
 *    model-visible durable copy is the redacted one. A claimed message's
 *    earlier `agent/inbox/spliced` delivery record keeps the original; it
 *    derives no model message, and ADR §30 says why that is the wanted
 *    asymmetry. `source.kind: 'user'` is exempt.
 * 4. `session-telemetry/record` — fail-closed redaction of exported telemetry,
 *    reaching tier 1 only because the waterfall is synchronous.
 * 5. `llm/stream` — neutralising remote markdown image destinations in
 *    assistant output, before the text becomes a session event.
 *
 * Three of those registrations mitigate defects in the harness rather than in
 * a deployment's own configuration: the missing Content-Security-Policy behind
 * (5), the mutable execution object behind the guard's mutation check, and the
 * silently inert telemetry seam behind the notice reported at mount. Each one
 * is partial, none closes its channel, and README.md says so beside the
 * feature.
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
import { evaluateConfigWrite } from './config-writes.ts'
import { evaluateApprovalSuppression } from './approvals.ts'
import { approvalSeamNotice, askReach, type AskUnreachable } from './approval-reach.ts'
import { breadthTierDenial, evaluateBreadthTier, redactDecision } from './results.ts'
import { redactStepContext } from './steps.ts'
import { redactRecord, telemetrySeamNotice } from './telemetry.ts'
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
 * Report something the operator should know that is not a fault, on the same
 * two channels and for the same reason as {@link report}.
 * @param ctx - the plugin's context, used for its logger.
 * @param message - the whole line to report.
 */
function notice(ctx: Context, message: string): void {
  ctx.logger.warn(message)
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

  /**
   * Report the telemetry seam's state once.
   *
   * At mount only a backend that is already there answers the question: the
   * backend can load after this plugin, and calling that absence "inert" would
   * be a false alarm. `conclusive` marks the later call, made once the harness
   * is running sessions, where an absent backend really means no dispatcher.
   */
  let telemetrySeamReported = false
  const discloseTelemetrySeam = (conclusive: boolean): void => {
    if (telemetrySeamReported) return
    const backend = ctx.get('sessionTelemetry')
    if (backend === undefined && !conclusive) return
    telemetrySeamReported = true
    const line = telemetrySeamNotice(backend?.sharing)
    if (line !== undefined) notice(ctx, line)
  }

  ctx.on('session/event', (_session: Session, event: SessionEvent) => {
    if (policy.telemetryRedaction) discloseTelemetrySeam(true)
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

  /**
   * Report once per state that the `ask` tier has nowhere to ask.
   *
   * Latched per state rather than once overall: the three states have
   * different fixes, a session can move between them mid-run by switching its
   * approval policy, and a single latch would leave the first one reported
   * standing for a different one afterwards. `approval-reach.ts` records why
   * each is a state in which an ask reaches nobody.
   */
  const approvalSeamReported = new Set<AskUnreachable>()
  const discloseApprovalSeam = (cause: AskUnreachable): void => {
    if (approvalSeamReported.has(cause)) return
    approvalSeamReported.add(cause)
    notice(ctx, approvalSeamNotice(cause))
  }

  if (policy.configWriteAsk || policy.approvalSuppressionAsk) {
    // Registered ahead of the breadth tier, so a call that is both a config
    // write and carries a secret is denied rather than merely asked about:
    // this listener sees whatever the rest of the waterfall settled on and
    // only ever narrows `allow` into `ask`.
    ctx.on('tools/pre-execute', async (exec: ToolExecution, next: () => Promise<PreToolDecision>) => {
      const decision = await next()
      if (decision.kind !== 'allow') return decision
      // The argument that switches a confirmation off is reported ahead of the
      // file it would write: it describes the call itself rather than what the
      // call touches, and it is the one the user has least reason to expect.
      const finding = (policy.approvalSuppressionAsk ? evaluateApprovalSuppression(exec) : undefined)
        ?? (policy.configWriteAsk ? evaluateConfigWrite(exec) : undefined)
      if (finding === undefined) return decision
      // A call the floor will deny anyway is left to the floor. Any non-allow
      // decision from this waterfall skips guards entirely, so asking here
      // would replace an unconditional denial with a prompt a user can grant,
      // and would file the decision as an ask rather than as a guard denial.
      if (safeEvaluateGuard(exec, policy, hasher) !== undefined) return decision
      // Asked at decision time, never at mount: the session's policy is a fold
      // over its own log and can change mid-run, and an answerer can be
      // composed or disposed while the harness runs.
      const reach = askReach(ctx, exec.agent?.session)
      if (reach.kind === 'unreachable') {
        discloseApprovalSeam(reach.cause)
        // An abstention allowed a call this tier would have asked about, so it
        // is recorded rather than left silent. Its own kind, not a flag on
        // `pre-execute-ask`: `dsh-dlp report` counts by kind, and an ask that
        // reached nobody must not be counted as a prompt that happened.
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'pre-execute-ask-abstained',
          decisionId: newDecisionId(),
          ...identity(exec),
          ruleId: finding.rule.id,
          askUnreachable: reach.cause,
        })
        return decision
      }
      sink.write({
        v: RECORD_VERSION,
        time: new Date().toISOString(),
        kind: 'pre-execute-ask',
        decisionId: newDecisionId(),
        ...identity(exec),
        ruleId: finding.rule.id,
      })
      return { kind: 'ask', reason: finding.reason }
    })
  }

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
    // Prepended for the same reason as the snapshot listener above, and with
    // the same limit: listeners run outermost-first, so registering ahead of
    // the chain is what lets this one redact the decision the rest of the
    // waterfall settled on rather than have its own replaced afterwards. A
    // listener registered later with the same option still lands ahead of it.
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
    }, { prepend: true })
  }

  if (policy.stepContextRedaction || policy.claimedInputRedaction) {
    // One listener for both toggles: they cover two classes of message
    // entering the same waterfall, and scanning them in one pass is what finds
    // a secret split across the boundary between them. `redactStepContext`
    // reads both flags and leaves an out-of-scope message as the object it
    // arrived as.
    //
    // Prepended for the reason the result and telemetry seams are: listeners
    // run outermost-first, so registering ahead of the chain is what lets this
    // one redact the messages the rest of the waterfall spliced in rather than
    // have its own replacement discarded afterwards.
    ctx.on('agent/pre-step', async (payload, next) => {
      const redacted = await redactStepContext(await next(), payload.messages, policy, hasher)
      const indicators = Object.keys(redacted.indicators).length > 0
        ? { unicode: redacted.indicators }
        : {}
      if (redacted.spans.length > 0 || redacted.truncatedScan || Object.keys(indicators).length > 0) {
        sink.write({
          v: RECORD_VERSION,
          time: new Date().toISOString(),
          kind: 'step-context-redaction',
          decisionId: newDecisionId(),
          sessionId: String(payload.agent.session.id),
          turn: payload.turn,
          step: payload.step,
          spans: redacted.spans,
          ...redacted.truncatedScan ? { truncatedScan: true } : {},
          ...indicators,
          // Only when the pass covered claimed input: an operator counting
          // deliveries must not have to read an empty list as "none arrived"
          // on every workspace-instruction record.
          ...redacted.claimedSources.length > 0 ? { claimedSources: redacted.claimedSources } : {},
        })
      }
      return redacted.decision
    }, { prepend: true })
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
    discloseTelemetrySeam(false)
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
      // Prepended for the reason the other seams are: a listener that returns
      // without calling `next()` vetoes every listener behind it for that
      // dispatch — `Events.dispatch()` hands the waterfall a fresh array, so
      // the registration survives and runs again on the next dispatch — and
      // this one is the only thing standing between an exported telemetry
      // record and the wire. One vetoed dispatch is one record exported in the
      // clear, which is why position matters here. Best-effort, as at the
      // mutation snapshot: another plugin registering later with the same
      // option lands ahead again.
    }, { prepend: true })
  }
}
