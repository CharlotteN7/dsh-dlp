/**
 * Redaction of the messages one step enters with: the context a
 * `agent/pre-step` listener splices in, and the input the loop claimed from
 * the inbox that the user did not type.
 *
 * A tool result is not the only text that reaches the model. The agent loop
 * dispatches `agent/pre-step` as a waterfall, appends every message the
 * returned decision carries as a `user/message` surface event, and derives the
 * next request from that surface. Two classes of text arrive that way.
 *
 * The first is what the waterfall itself adds, and nothing else scans it:
 * `dsh-agent-instructions` splices the workspace `AGENTS.md`/`CLAUDE.md`
 * chain, `dsh-tmux-context` splices captured pane text, the Claude Code and
 * Codex hook bridges splice a hook command's `additionalContext`, and
 * `dsh-tool-skill` splices a skill body a `/name` token asked for.
 *
 * The second is what the loop claimed from the inbox. Most of that is not the
 * user typing either: `dsh-webhook` admits a verified third-party delivery's
 * payload with `agent.followup()`, a subagent's settled result and an
 * agent-to-agent relay arrive the same way, and so does anything
 * `agent.inject()` seeded. {@link isUserTyped} is the exemption, and it is the
 * only one: a secret a person deliberately types into their own prompt is not
 * a leak this plugin intercepts.
 *
 * A claimed message differs from an added one in exactly one way, and it is
 * narrower than it looks. Its delivery was already recorded as
 * `agent/inbox/spliced` before this waterfall ran, and no seam can rewrite a
 * committed event. That event is not a surface event — `SurfaceEventType` is
 * `user/message | assistant/message | tool/result` — so it derives no model
 * message and no request is built from it. The copy the model reads is the
 * `user/message` the loop appends after this waterfall, which is the copy this
 * pass rewrites. "Model-visible ⟺ logged" therefore still holds; what the
 * delivery record keeps is the original text of an untrusted delivery, which
 * is evidence rather than a disagreement. ADR §30 states that asymmetry, and
 * `tests/e2e/step-context.e2e.ts` pins it.
 *
 * Best-effort, like every seam here that is not `ctx.tools.guard()`: this
 * listener registers with `{ prepend: true }` so it sees what the rest of the
 * waterfall settled on, and a listener registering later with the same option
 * lands ahead of it again.
 * @module dsh-dlp/steps
 */

import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import type { ResolvedPolicy } from './policy.ts'
import { messageStrings, prepareScan } from './results.ts'
import { redactUserMessages, type RedactedSpan, type SpanHasher } from './redaction.ts'

/** What one pass over a step's entering messages produced. */
export interface StepRedaction {
  /** The decision to return: the same object when nothing was replaced. */
  readonly decision: PreStepDecision
  /** The regions replaced, described by rule identity, offsets and keyed hash only. */
  readonly spans: readonly RedactedSpan[]
  /** Set when the scanned text exceeded `maxScanBytes` and tier 2 saw less than all of it. */
  readonly truncatedScan: boolean
  /** Runs of each invisible-character class the scanned messages carried, by rule id. */
  readonly indicators: Readonly<Record<string, number>>
  /**
   * The distinct `source.kind` of every inbox-claimed message this pass
   * scanned, in first-seen order. Empty when the pass only covered messages
   * the waterfall added. An operator reading the sink needs this to tell a
   * redacted workspace instruction from a redacted third-party delivery.
   */
  readonly claimedSources: readonly string[]
}

/**
 * Whether one message the loop claimed from the inbox is the user's own
 * typing, and therefore exempt.
 *
 * `MessageSourceMap` is merge-extensible and every producer picks its own
 * `kind`, so the exemption is a single allowed value rather than a list of
 * denied ones: a source kind added by a package this plugin has never heard of
 * is redacted rather than trusted. In the installed harness `kind: 'user'` is
 * what the interactive entry points supply — `dsh-headless` for a CLI task,
 * `dsh-acp` for an ACP prompt, `dsh-sdk-jsonrpc-server` for an SDK one, and
 * `dsh-api-session-controller`'s `user-rpc` source for a browser prompt, which
 * adds `rpcId` beside the same `kind`. `dsh-webhook`'s deliveries carry
 * `kind: 'webhook'`, and the harness's own webhook invariant discriminates on
 * exactly that value.
 *
 * Two producers borrow the value for text a person did not type: `dsh-subagent`
 * and `dsh-subagent-in-process-driver` open a child agent with the parent's
 * prompt under `kind: 'user'`. Those stay exempt here. Distinguishing them
 * needs a fact the source does not carry, and inventing one would put a
 * guessed value in a security decision.
 * @param message - one message the loop claimed from the inbox.
 * @returns whether the message came from a person typing into their own prompt.
 */
export function isUserTyped(message: UserMessage): boolean {
  return message.source.kind === 'user'
}

/**
 * Redact the messages entering one step.
 *
 * @param decision - what the rest of the waterfall settled on.
 * @param claimed - the messages the loop claimed from the inbox.
 * @param policy - the effective policy after the tighten-only merge.
 * @param hasher - mints each span's keyed hash.
 * @returns the decision to return, plus what the pass found.
 */
export async function redactStepContext(
  decision: PreStepDecision,
  claimed: readonly UserMessage[],
  policy: ResolvedPolicy,
  hasher: SpanHasher,
): Promise<StepRedaction> {
  const nothing = { spans: [], truncatedScan: false, indicators: {}, claimedSources: [] } as const
  if (decision.kind !== 'enter') return { decision, ...nothing }
  // Object identity, which is what the loop and the shipped providers use: a
  // provider splices its own message into the array it was handed, so a
  // claimed message is the same object it arrived as.
  const claimedSet = new Set<UserMessage>(claimed)
  const inScope = (message: UserMessage): boolean => claimedSet.has(message)
    ? policy.claimedInputRedaction && !isUserTyped(message)
    : policy.stepContextRedaction
  const selected = decision.messages.filter(inScope)
  if (selected.length === 0) return { decision, ...nothing }

  const claimedSources = [...new Set(
    selected.filter(message => claimedSet.has(message)).map(message => message.source.kind),
  )]
  const prepared = await prepareScan(messageStrings(selected), policy)
  const redacted = redactUserMessages(selected, prepared.scan, hasher, '/messages')
  const base = {
    spans: redacted.spans,
    truncatedScan: prepared.truncated,
    indicators: prepared.indicators,
    claimedSources,
  }
  if (!redacted.changed) return { decision, ...base }

  // Rebuilt position by position so every message keeps the place it had:
  // ordering is what decides whether a workspace instruction reads before or
  // after the user's request.
  const replacements: UserMessage[] = [...redacted.messages]
  const messages = decision.messages.map((message): UserMessage => {
    if (!inScope(message)) return message
    const replacement = replacements.shift()
    /* v8 ignore next -- `redactUserMessages` returns one message per input, so this never runs short. */
    return replacement ?? message
  })
  return { decision: { ...decision, messages }, ...base }
}
