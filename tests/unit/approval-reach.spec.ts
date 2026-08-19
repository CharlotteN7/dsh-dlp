/**
 * Whether an ask can reach a human, read off a real Cordis context.
 *
 * The two things this module reads live on other packages: `ctx.get('approval')`
 * returns whatever `@deepseek-ai/dsh-user-approval` composed, and the composed
 * answerers are counted off `EventsService._hooks`. Every test here therefore
 * drives a real `Context` rather than an object shaped like one, so a Cordis
 * that stops publishing those fails this suite instead of a user's install.
 */

import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { Session } from '@deepseek-ai/dsh-session'
import { approvalSeamNotice, askReach, type AskUnreachable } from '../../src/approval-reach.ts'

/** A session, which is only ever an identity handed back to `overrideOf`. */
function session(): Session {
  return { id: 'session-1', events: [] } as unknown as Session
}

/** A live context, optionally carrying an approval service. */
function context(approval?: unknown): Context {
  const ctx = new Context()
  if (approval !== undefined) {
    ctx.provide('approval')
    ctx.set('approval', approval)
  }
  return ctx
}

/** Compose one listener on the answerer waterfall; the returned call removes it. */
function composeAnswerer(ctx: Context): () => void {
  const dispose = ctx.events.on('approval/request', () => Promise.resolve('allowed-once'))
  return () => { dispose() }
}

describe('reading whether an ask reaches a human', () => {
  it('reports the composed service missing when nothing provides one', () => {
    expect(askReach(context(), session())).toEqual({ kind: 'unreachable', cause: 'no-service' })
  })

  it('reports the policy when the deployment default is "never"', () => {
    const ctx = context({ config: { policy: 'never' }, overrideOf: () => undefined })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'unreachable', cause: 'policy-never' })
  })

  it('reports the policy when the session switched to "never" under an "ask" default', () => {
    const ctx = context({ config: { policy: 'ask' }, overrideOf: () => 'never' })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'unreachable', cause: 'policy-never' })
  })

  it('lets a session that switched to "ask" override a "never" default', () => {
    // The override is the last `approval/policy` event in that session's own
    // log, and the service applies the configured default only without one.
    const ctx = context({ config: { policy: 'ask' }, overrideOf: () => 'ask' })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })
  })

  it('reports no answerer when nothing is composed on the waterfall', () => {
    const ctx = context({ config: { policy: 'ask' }, overrideOf: () => undefined })

    expect(askReach(ctx, session())).toEqual({ kind: 'unreachable', cause: 'no-answerer' })
  })

  it('reports no answerer again once the last composed one is disposed', () => {
    // Read per call rather than once, so a surface that unmounts mid-session
    // is seen. A stale count would keep asking into a seam that answers
    // nothing, which is the denial this abstention exists to avoid.
    const ctx = context({ config: { policy: 'ask' }, overrideOf: () => undefined })
    const dispose = composeAnswerer(ctx)
    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })

    dispose()

    expect(askReach(ctx, session())).toEqual({ kind: 'unreachable', cause: 'no-answerer' })
  })

  it('counts an answerer composed anywhere in the context tree', () => {
    // The service dispatches from its own context, and every context in one
    // tree shares the bus, so a child's registration is one this can find.
    const ctx = context({ config: { policy: 'ask' }, overrideOf: () => undefined })
    composeAnswerer(ctx.extend({}))

    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })
  })

  it.each([
    ['a call with no agent, and so no session to fold an override from', undefined],
    ['a session under a service that publishes no override fold', session()],
  ])('keeps asking for %s', (_label, given) => {
    const ctx = context({ config: { policy: 'never' } })
    composeAnswerer(ctx)

    expect(askReach(ctx, given)).toEqual({ kind: 'reachable' })
  })

  it('keeps asking when the service publishes an override fold but no configured default', () => {
    const ctx = context({ overrideOf: () => undefined })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })
  })

  it('keeps asking when the override fold throws', () => {
    // A diagnostic read that fails answers nothing about whether a human can
    // be asked, and it runs inside a live tool call it must not fail.
    const ctx = context({ overrideOf: () => { throw new Error('not the fold read here') } })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })
  })

  it('keeps asking when the policy is a value this build does not recognise', () => {
    // The service compares its effective policy against `'never'` and
    // dispatches otherwise, so anything else leaves the answerers to decide.
    const ctx = context({ config: { policy: 'sometimes' }, overrideOf: () => undefined })
    composeAnswerer(ctx)

    expect(askReach(ctx, session())).toEqual({ kind: 'reachable' })
  })

  it('reports the policy ahead of the missing answerer, as the service decides it', () => {
    // Both hold on a stock headless install under danger-full-access. The
    // service settles `'never'` before dispatching, so that is the state whose
    // fix an operator needs.
    const ctx = context({ config: { policy: 'never' }, overrideOf: () => undefined })

    expect(askReach(ctx, session())).toEqual({ kind: 'unreachable', cause: 'policy-never' })
  })
})

describe('what the operator is told', () => {
  it.each([
    ['no-service', 'no approval service is mounted'],
    ['policy-never', 'DSH_PERMISSION_MODE=danger-full-access'],
    ['no-answerer', 'nothing is composed on the approval/request waterfall'],
  ] as const)('names %s and what to change', (cause: AskUnreachable, expected) => {
    const line = approvalSeamNotice(cause)

    expect(line).toContain(expected)
    // Every line says the same three things: which tier, what happens now, and
    // that the floor is not what changed.
    expect(line).toContain('configWriteAsk')
    expect(line).toContain('pre-execute-ask-abstained')
    expect(line).toContain('The guard floor is unaffected')
  })
})
