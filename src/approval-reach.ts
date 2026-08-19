/**
 * Whether an `ask` this plugin returns can still reach a human.
 *
 * The `ask` tier is documented as a prompt and never a block: its rules have a
 * real false-positive rate, so a developer who is asked about `CLAUDE.md` or
 * `.github/workflows/**` says yes and carries on. The tool registry resolves an
 * `ask` through `ctx.get('approval')`, and three states of that seam turn the
 * prompt into a denial nobody ever saw:
 *
 * 1. **No service composed.** `ToolRegistry.serviceAsk` keeps the historical
 *    degrade to `deny` when `ctx.get('approval')` is `undefined`.
 * 2. **The policy in force is `'never'`.** `ApprovalService.decide` resolves
 *    `'rejected'` before any dispatch — its own JSDoc calls this "never prompt
 *    anyone". The shipped `dsh-base` bundle selects it for every install under
 *    `DSH_PERMISSION_MODE=danger-full-access`, which is the unattended posture.
 * 3. **Nothing composed on `approval/request`.** The waterfall falls through to
 *    the fail-closed `'unavailable'`, which the registry maps to `deny`. The
 *    shipped `dsh-headless` bundle composes no answerer, so this is the state
 *    of a stock headless install under every other permission mode.
 *
 * In all three the call is stopped with no human involved, which is exactly
 * what this tier was designed not to do. Each is decided here so the caller can
 * abstain instead — the same thing it already did for (1) alone.
 *
 * **Every check reports "reachable" when it cannot tell.** Abstaining removes a
 * prompt, so an unreadable service, a missing session, or a `ctx.get` that
 * returned something other than the service read here all keep the ask. Only a
 * positive reading of one of the three states above abstains.
 * @module dsh-dlp/approval-reach
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Session } from '@deepseek-ai/dsh-session'

/** The event `ApprovalService.decide` dispatches its answerer waterfall on. */
const APPROVAL_REQUEST = 'approval/request'

/** Which of the three states stopped an ask from reaching a human. */
export type AskUnreachable =
  /** Nothing is composed on `ctx.approval`. */
  | 'no-service'
  /** The policy in force for this session is `'never'`. */
  | 'policy-never'
  /** Nothing is composed on the `approval/request` waterfall. */
  | 'no-answerer'

/** Whether an ask can reach a human, and when it cannot, which state stopped it. */
export type AskReach =
  | { readonly kind: 'reachable' }
  | { readonly kind: 'unreachable'; readonly cause: AskUnreachable }

/**
 * The parts of `ApprovalService` this module reads.
 *
 * `ctx.get('approval')` is typed `any` — the service's declaration merging
 * lives in `@deepseek-ai/dsh-user-approval`, which this package deliberately
 * does not take as a peer for a diagnostic read — so what comes back is
 * validated here rather than trusted. Both members are public API:
 * `overrideOf(session)` is the session's own `approval/policy` fold and
 * `config.policy` the deployment default the service applies without one,
 * which together are `effectivePolicy`, its private counterpart.
 */
interface ApprovalSurface {
  readonly config?: { readonly policy?: unknown }
  readonly overrideOf?: (session: Session) => unknown
}

/**
 * Whether every ask for this session resolves without prompting anyone.
 *
 * `'never'` is the only policy whose outcome is knowable without asking, and
 * the service decides it before dispatch, so no composed answerer can change
 * it. Anything else — including a value this build does not recognise — leaves
 * the answerers to decide and is therefore not a positive reading.
 * @param approval - whatever `ctx.get('approval')` returned.
 * @param session - the calling agent's session, or `undefined` when the call has no agent.
 * @returns `true` only when the policy in force was read and is `'never'`.
 */
function policyIsNever(approval: unknown, session: Session | undefined): boolean {
  // Without a session there is no override to fold, and the configured default
  // alone cannot tell a session that never switched from one that switched to
  // 'ask' — so an agent-less call keeps its prompt.
  if (session === undefined) return false
  const service = approval as ApprovalSurface
  let policy: unknown
  try {
    policy = service.overrideOf === undefined ? undefined : service.overrideOf(session) ?? service.config?.policy
  } catch {
    // Only a service without the members ApprovalSurface describes reaches
    // here. It answers nothing about whether a human can be asked, and
    // this runs inside a live tool call: a diagnostic read must not fail it.
    return false
  }
  return policy === 'never'
}

/**
 * How many listeners are composed on the answerer waterfall.
 *
 * The count is read across the whole context tree, before the scope filter
 * `ApprovalService.decide` applies. That over-counts — an agent-scoped answerer
 * belonging to a different agent is included — and over-counting is the safe
 * direction here, because only a count of zero abstains and zero listeners
 * cannot be filtered into some.
 *
 * `EventsService._hooks` is a declared public field of the exported class, so a
 * Cordis that stops carrying it fails `typecheck` and `build` in this package
 * rather than being misread at a user's install; `@deepseek-ai/cordis` is
 * pinned to one exact version (ADR §19) for the same reason.
 * @param ctx - the plugin's context; every context in one tree shares the bus.
 * @returns the number of composed answerers.
 */
function composedAnswerers(ctx: Context): number {
  return ctx.events._hooks[APPROVAL_REQUEST]?.length ?? 0
}

/**
 * Decide whether an ask would reach a human, at the moment of the decision.
 *
 * Evaluated per call rather than at mount: a session switches policy mid-run
 * through `approval/policy`, the override is per session, and an answerer can
 * be composed or disposed while the harness runs. A mount-time answer would be
 * a cached guess at all three.
 * @param ctx - the plugin's context, for the service and the event bus.
 * @param session - the calling agent's session, or `undefined` when the call has no agent.
 * @returns whether to ask, or which state stopped the ask from reaching anyone.
 */
export function askReach(ctx: Context, session: Session | undefined): AskReach {
  const approval: unknown = ctx.get('approval')
  if (approval === undefined) return { kind: 'unreachable', cause: 'no-service' }
  // Policy first, matching the service's own order: it decides 'never' before
  // dispatching, so that is the state an operator sees reported.
  if (policyIsNever(approval, session)) return { kind: 'unreachable', cause: 'policy-never' }
  if (composedAnswerers(ctx) === 0) return { kind: 'unreachable', cause: 'no-answerer' }
  return { kind: 'reachable' }
}

/** What abstaining does, said once and identically for all three states. */
const CONSEQUENCE = 'This tier abstains rather than becoming the silent hard deny it was designed not to be: a'
  + ' write to a behaviour-changing config path, and a call that switches its own confirmation off, are allowed'
  + ' through with no prompt, and each one is recorded in the audit sink as "pre-execute-ask-abstained". The'
  + ' guard floor is unaffected. Set configWriteAsk: false and approvalSuppressionAsk: false to turn this tier'
  + ' off entirely.'

/**
 * What to tell the operator when the ask tier has nowhere to ask.
 *
 * Each line names the state, what to change to get the prompt back, and the
 * consequence. Reported on `process.stderr` as well as `ctx.logger` for the
 * reason ADR §7 records: the logger's default exporter is an in-memory ring
 * buffer and no shipped bundle mounts a console exporter.
 * @param cause - the state {@link askReach} read.
 * @returns the whole line to report.
 */
export function approvalSeamNotice(cause: AskUnreachable): string {
  const prefix = 'dsh-dlp: the ask tier (configWriteAsk, approvalSuppressionAsk) is enabled, but'
  switch (cause) {
    case 'no-service':
      return `${prefix} no approval service is mounted, so the tool registry would resolve an ask as a denial`
        + ' with nothing shown to anyone. Composing an approval service and an answerer puts the prompt back.'
        + ` ${CONSEQUENCE}`
    case 'policy-never':
      return `${prefix} the approval policy in force is "never", which resolves every ask as rejected without`
        + ' prompting anyone. DSH_PERMISSION_MODE=danger-full-access selects that policy in the shipped dsh-base'
        + ' bundle; run under another permission mode, or set the approval row\'s policy to "ask", for these'
        + ` calls to be asked about. ${CONSEQUENCE}`
    case 'no-answerer':
      return `${prefix} nothing is composed on the approval/request waterfall, which fails every ask closed as`
        + ' unavailable and denies the call with nothing shown to anyone. The shipped dsh-headless bundle'
        + ' composes no answerer; a surface that answers approvals, such as the Host API proxy or the ACP'
        + ` bridge, puts the prompt back. ${CONSEQUENCE}`
    /* v8 ignore next 4 -- unreachable while `AskUnreachable` stays closed; the arm exists so adding a variant fails the build. */
    default: {
      const unhandled: never = cause
      throw new TypeError(`dsh-dlp: unhandled ask-tier state ${JSON.stringify(unhandled)}`)
    }
  }
}
