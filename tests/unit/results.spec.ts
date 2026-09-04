/**
 * Arm selection at `tools/post-execute`, and the breadth tier's refusal to
 * widen a decision it was handed.
 */

import { describe, expect, it } from 'vitest'
import type { ToolCallBlock, UserMessage } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { breadthTierDenial, evaluateBreadthTier, redactDecision } from '../../src/results.ts'
import { resolvePolicy, type Config } from '../../src/policy.ts'
import { SpanHasher } from '../../src/redaction.ts'

/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
/** Shaped like a Shopify access token; invented for this test, never a live credential. */
const SHOPIFY = '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'
/** A PEM block with an invented body; the header and footer are what the rule matches. */
const PEM_LINES = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEowIBAAKCAQEAtESTKEYLINEONE0000000000000000000000000000000000',
  'MIIEowIBAAKCAQEAtESTKEYLINETWO1111111111111111111111111111111111',
  '-----END RSA PRIVATE KEY-----',
]
const hasher = new SpanHasher(Buffer.from('dsh-dlp-unit-test-key-000000000000', 'utf8'))
const policy = resolvePolicy({
  auditLog: '/dev/null',
  redactionKeyFile: '/dev/null',
  maxScanBytes: 1024 * 1024,
  breadthTier: true,
  resultRedaction: true,
  telemetryRedaction: true,
  stepContextRedaction: true,
  claimedInputRedaction: true,
  remoteImageNeutralization: true,
  redactTelemetryWorkspacePaths: true,
  configWriteAsk: true,
  approvalSuppressionAsk: true,
} satisfies Config)

const success = (value: unknown, text: string): ToolExecutionResult => ({
  isError: false,
  value: value as never,
  content: [{ type: 'text', text }],
})

const failure = (text: string): ToolExecutionResult => ({
  isError: true,
  error: { message: text },
  content: [{ type: 'text', text }],
})

const accept: PostToolDecision = { kind: 'accept' }

/** One `additionalContexts` entry, as a listener or a tool body attaches it. */
function context(text: string, source: UserMessage['source']): UserMessage {
  return { id: 'context-1' as UserMessage['id'], role: 'user', content: [{ type: 'text', text }], source }
}

/** The text of one message's first block, for comparing a source's copy of it. */
function firstText(message: UserMessage): string | undefined {
  const block = message.content[0]
  return block?.type === 'text' ? block.text : undefined
}

describe('a successful structured result', () => {
  it('is replaced through the value arm, so content and meta are re-derived', async () => {
    const result = success({ stdout: { text: `token ${SLACK}` } }, `token ${SLACK}`)

    const { decision, spans } = await redactDecision(accept, result, policy, hasher)

    expect(Object.hasOwn(decision, 'value')).toBe(true)
    expect(Object.hasOwn(decision, 'content')).toBe(false)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
    expect(spans[0]?.ruleId).toBe('dsh-dlp/slack-token')
  })

  it('is left alone when it carries no secret', async () => {
    const result = success({ stdout: { text: 'all clear' } }, 'all clear')

    const { decision, spans } = await redactDecision(accept, result, policy, hasher)

    expect(decision).toBe(accept)
    expect(spans).toEqual([])
  })

  it('picks up a secret only the secretlint tier knows', async () => {
    const result = success({ key: SHOPIFY }, SHOPIFY)

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(JSON.stringify(decision)).not.toContain(SHOPIFY)
  })
})

describe('a failed result', () => {
  it('is replaced through the content arm, because the value arm would throw', async () => {
    const result = failure(`connect failed for postgres://admin:${SLACK}@db/prod`)

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(Object.hasOwn(decision, 'content')).toBe(true)
    expect(Object.hasOwn(decision, 'value')).toBe(false)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })
})

describe('a result carrying a block the plugin has no detector for', () => {
  it('redacts the text beside it and leaves the other block alone', async () => {
    const result: ToolExecutionResult = {
      isError: true,
      error: { message: 'failed' },
      content: [
        { type: 'text', text: `failed with ${SLACK}` },
        { type: 'tool-call', id: 'call-1' as ToolCallBlock['id'], name: 'read', arguments: '{}' },
      ],
    }

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(JSON.stringify(decision)).not.toContain(SLACK)
    expect(JSON.stringify(decision)).toContain('tool-call')
  })
})

describe('composing with the rest of the waterfall', () => {
  it('redacts a downstream value replacement in place', async () => {
    const downstream: PostToolDecision = { kind: 'accept', value: { note: SLACK } }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(Object.hasOwn(decision, 'value')).toBe(true)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })

  it('scans the result meta alongside a downstream value replacement', async () => {
    const downstream: PostToolDecision = { kind: 'accept', value: { note: 'fine' } }
    const result: ToolExecutionResult = {
      isError: false,
      value: {} as never,
      content: [],
      meta: { note: SLACK } as never,
    }

    const { decision, spans } = await redactDecision(downstream, result, policy, hasher)

    expect(decision.kind).toBe('block')
    expect(spans[0]?.ruleId).toBe('dsh-dlp/slack-token')
  })

  it('redacts a downstream content replacement in place', async () => {
    const downstream: PostToolDecision = { kind: 'accept', content: [{ type: 'text', text: SLACK }] }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(Object.hasOwn(decision, 'content')).toBe(true)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })

  it('redacts a downstream block decision feedback', async () => {
    const downstream: PostToolDecision = { kind: 'block', feedback: [{ type: 'text', text: `bad ${SLACK}` }] }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(decision.kind).toBe('block')
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })

  it('leaves a clean downstream decision identical', async () => {
    const downstream: PostToolDecision = { kind: 'accept', content: [{ type: 'text', text: 'fine' }] }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(decision).toBe(downstream)
  })

  it('leaves a clean downstream value replacement identical', async () => {
    const downstream: PostToolDecision = { kind: 'accept', value: { note: 'fine' } }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(decision).toBe(downstream)
  })

  it('leaves a clean downstream block decision identical', async () => {
    const downstream: PostToolDecision = { kind: 'block', feedback: [{ type: 'text', text: 'try again' }] }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(decision).toBe(downstream)
  })

  it('carries a clean downstream additionalContext onto the replacement by reference', async () => {
    const contexts = [context('note', { kind: 'plugin', plugin: 'hooks' })]
    const downstream: PostToolDecision = { kind: 'accept', value: { note: SLACK }, additionalContexts: contexts }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect((decision as { additionalContexts?: unknown }).additionalContexts).toBe(contexts)
  })

  it('redacts a secret a downstream listener attached as an additionalContext', async () => {
    const contexts = [context(`hook says ${SLACK}`, { kind: 'plugin', plugin: 'hooks' })]
    const downstream: PostToolDecision = { kind: 'accept', additionalContexts: contexts }

    const { decision, spans } = await redactDecision(downstream, success({ ok: true }, 'fine'), policy, hasher)

    expect(JSON.stringify(decision)).not.toContain(SLACK)
    expect(JSON.stringify(decision)).toContain('[REDACTED:dsh-dlp:slack-token:')
    expect(spans.map(span => span.ruleId)).toContain('dsh-dlp/slack-token')
  })

  it('redacts the source text a context repeats beside its blocks', async () => {
    // A `snapshot` source repeats the block text in `sections[].text` and a
    // `notice` source repeats its opening in `summary`; both are appended to
    // the session log with the message, so redacting the blocks alone leaves
    // a copy behind.
    const contexts = [context(`hook says ${SLACK}`, {
      kind: 'plugin',
      plugin: 'hooks',
      form: 'snapshot',
      sections: [{ name: 'hooks', text: `hook says ${SLACK}` }],
    })]
    const downstream: PostToolDecision = { kind: 'accept', additionalContexts: contexts }

    const { decision } = await redactDecision(downstream, success({ ok: true }, 'fine'), policy, hasher)
    const carried = (decision as { additionalContexts: UserMessage[] }).additionalContexts[0]
    const source = carried?.source as { kind: string; plugin: string; form: string; sections: { text: string }[] }

    expect(JSON.stringify(decision)).not.toContain(SLACK)
    // The discriminants still say what the message is.
    expect(source).toMatchObject({ kind: 'plugin', plugin: 'hooks', form: 'snapshot' })
    // Same text, same scan, same key: the copies stay in step.
    expect(source.sections[0]?.text).toBe(carried === undefined ? undefined : firstText(carried))
  })

  it('redacts a context attached to a downstream block decision', async () => {
    const contexts = [context(SLACK, { kind: 'plugin', plugin: 'hooks' })]
    const downstream: PostToolDecision = {
      kind: 'block',
      feedback: [{ type: 'text', text: 'try again' }],
      additionalContexts: contexts,
    }

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })

  it('withholds a successful result whose deferred context no accept arm can rewrite', async () => {
    // The registry concatenates `result.additionalContexts` ahead of the
    // decision's own on every accept arm, so nothing an accept can say drops
    // or rewrites them. Only a block does, which is `meta`'s case exactly.
    const result: ToolExecutionResult = {
      ...success({ ok: true }, 'fine'),
      additionalContexts: [context(SLACK, { kind: 'plugin', plugin: 'hooks' })],
    }

    const { decision, spans } = await redactDecision(accept, result, policy, hasher)

    expect(decision.kind).toBe('block')
    expect(JSON.stringify(decision)).not.toContain(SLACK)
    expect(spans.map(span => span.ruleId)).toContain('dsh-dlp/slack-token')
  })

  it('keeps a clean deferred context out of the decision entirely', async () => {
    const result: ToolExecutionResult = {
      ...success({ ok: true }, 'fine'),
      additionalContexts: [context('nothing here', { kind: 'plugin', plugin: 'hooks' })],
    }

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(decision).toBe(accept)
  })

  it('never produces a decision carrying both value and content', async () => {
    const result = success({ stdout: SLACK }, SLACK)

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(Object.hasOwn(decision, 'value') && Object.hasOwn(decision, 'content')).toBe(false)
  })
})

describe('the breadth tier', () => {
  it('reports a secret bound for an egress-capable tool', async () => {
    const finding = await evaluateBreadthTier({ name: 'web_fetch', arguments: { url: `https://x/?k=${SHOPIFY}` } }, policy, hasher)

    expect(finding?.spans.map(span => span.ruleId)).toContain('@secretlint/secretlint-rule-shopify')
    expect(finding?.reason).not.toContain(SHOPIFY)
  })

  it('says nothing about a local tool', async () => {
    expect(await evaluateBreadthTier({ name: 'read', arguments: { file_path: SHOPIFY } }, policy, hasher))
      .toBeUndefined()
  })

  it('says nothing about a clean call', async () => {
    expect(await evaluateBreadthTier({ name: 'bash', arguments: { command: 'ls' } }, policy, hasher))
      .toBeUndefined()
  })

  it('turns a finding into a pre-execute denial', () => {
    expect(breadthTierDenial('because')).toEqual({ kind: 'deny', reason: 'because' })
  })
})

describe('a secret that only the assembled result reveals', () => {
  it('is redacted out of the value, which no per-string walk would have reached', async () => {
    // The private-key block spans three fields. Every one of them scans clean
    // on its own; only the rendered result carries the match.
    const value = {
      begin: '-----BEGIN RSA PRIVATE KEY-----',
      body: 'MIIEowIBAAKCAQEA',
      end: '-----END RSA PRIVATE KEY-----',
    }

    const { decision, spans } = await redactDecision(accept, success(value, ''), policy, hasher)

    expect(Object.hasOwn(decision, 'value')).toBe(true)
    expect(JSON.stringify(decision)).not.toContain('MIIEowIBAAKCAQEA')
    expect(spans.map(span => span.ruleId)).toContain('dsh-dlp/private-key-block')
  })

  it('takes the value arm for a multi-line secret arriving one line per field', async () => {
    // `read` hands back one string per line and renders the file whole. Before
    // this, the per-string walk found nothing, the content arm won, and
    // `{...result}` carried the untouched value and presentationMeta into the
    // durable log while the model saw a placeholder.
    const value = { lines: PEM_LINES.map((text, index) => ({ line: index + 1, text })) }
    const rendered = PEM_LINES.join('\n')
    const result: ToolExecutionResult = {
      isError: false,
      value: value as never,
      content: [{ type: 'text', text: rendered }],
      meta: { text: rendered } as never,
    }

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(Object.hasOwn(decision, 'value')).toBe(true)
    expect(Object.hasOwn(decision, 'content')).toBe(false)
    expect(JSON.stringify(decision)).not.toContain('MIIEowIBAAKCAQEAtESTKEYLINETWO')
  })

  it('reports every occurrence of a repeated line, not only the first', async () => {
    const value = { lines: [`token ${SLACK}`, 'unrelated', `token ${SLACK}`] }

    const { decision } = await redactDecision(accept, success(value, ''), policy, hasher)

    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })
})

describe('a result whose meta carries a secret', () => {
  it('is withheld entirely, because no accept arm can rewrite meta', async () => {
    // `meta` is persisted verbatim by `session.append('tool/result', ...)` and
    // is not model-visible, so a content replacement cannot clean it.
    const result: ToolExecutionResult = {
      isError: true,
      error: { message: 'boom' },
      content: [{ type: 'text', text: 'command failed' }],
      meta: { diffs: [{ path: 'a.env', oldText: '', newText: `SLACK=${SLACK}` }] } as never,
    }

    const { decision, spans } = await redactDecision(accept, result, policy, hasher)

    expect(decision.kind).toBe('block')
    expect(JSON.stringify(decision)).not.toContain(SLACK)
    expect(spans[0]?.ruleId).toBe('dsh-dlp/slack-token')
  })

  it('is accepted through the value arm when the value carries the same secret', async () => {
    const result: ToolExecutionResult = {
      isError: false,
      value: { text: `token ${SLACK}` } as never,
      content: [{ type: 'text', text: `token ${SLACK}` }],
      meta: { text: `token ${SLACK}` } as never,
    }

    const { decision } = await redactDecision(accept, result, policy, hasher)

    expect(Object.hasOwn(decision, 'value')).toBe(true)
  })

  it('is left alone when neither the value nor the meta carries anything', async () => {
    const result: ToolExecutionResult = {
      isError: false,
      value: { text: 'fine' } as never,
      content: [{ type: 'text', text: 'fine' }],
      meta: { text: 'fine' } as never,
    }

    expect((await redactDecision(accept, result, policy, hasher)).decision).toBe(accept)
  })
})

describe('a value that cannot be cleaned', () => {
  it('is withheld rather than accepted with the secret still in it', async () => {
    // A rule matching the placeholder itself: redaction cannot converge, so
    // blocking is the only arm that keeps the value out of the session log.
    const stubborn = resolvePolicy({
      auditLog: '/dev/null',
      redactionKeyFile: '/dev/null',
      maxScanBytes: 1024 * 1024,
      breadthTier: true,
      resultRedaction: true,
      telemetryRedaction: true,
      stepContextRedaction: true,
      claimedInputRedaction: true,
      remoteImageNeutralization: true,
      redactTelemetryWorkspacePaths: true,
      configWriteAsk: true,
      approvalSuppressionAsk: true,
    } satisfies Config)
    const rules = [
      ...stubborn.syncRules,
      { id: 'test/always', version: 1, severity: 'critical' as const, pattern: /REDACTED|ALWAYS/g },
    ]

    const { decision, spans } = await redactDecision(
      accept,
      success({ text: 'ALWAYS' }, 'ALWAYS'),
      { ...stubborn, syncRules: rules },
      hasher,
    )

    expect(decision.kind).toBe('block')
    expect(JSON.stringify(decision)).toContain('withheld')
    expect(spans[0]?.ruleId).toBe('test/always')
  })
})

describe('the breadth tier and severity', () => {
  it('ignores a match below the denial threshold', async () => {
    const finding = await evaluateBreadthTier(
      { name: 'bash', arguments: { command: 'export password=abcdefghijklmnopqrst' } },
      policy,
      hasher,
    )

    expect(finding).toBeUndefined()
  })
})

describe('a result larger than the tier-2 budget', () => {
  it('is scanned by tier 1 throughout and reports the partial scan', async () => {
    // How many strings a tool split its output into must not decide how much
    // of it is examined: the budget is characters of rendered result.
    const capped = resolvePolicy({
      auditLog: '/dev/null',
      redactionKeyFile: '/dev/null',
      maxScanBytes: 1000,
      breadthTier: true,
      resultRedaction: true,
      telemetryRedaction: true,
      stepContextRedaction: true,
      claimedInputRedaction: true,
      remoteImageNeutralization: true,
      redactTelemetryWorkspacePaths: true,
      configWriteAsk: true,
      approvalSuppressionAsk: true,
    } satisfies Config)
    const lines = Array.from({ length: 400 }, (_, index) => `line ${index}`)
    lines[399] = `token ${SLACK}`
    const result = success({ lines }, lines.join('\n'))

    const { decision, truncatedScan } = await redactDecision(accept, result, capped, hasher)

    expect(truncatedScan).toBe(true)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })

  it('reports a partial scan even when it found nothing', async () => {
    const capped = resolvePolicy({
      auditLog: '/dev/null',
      redactionKeyFile: '/dev/null',
      maxScanBytes: 100,
      breadthTier: true,
      resultRedaction: true,
      telemetryRedaction: true,
      stepContextRedaction: true,
      claimedInputRedaction: true,
      remoteImageNeutralization: true,
      redactTelemetryWorkspacePaths: true,
      configWriteAsk: true,
      approvalSuppressionAsk: true,
    } satisfies Config)
    const result = success({ text: 'x'.repeat(400) }, 'x'.repeat(400))

    const { spans, truncatedScan } = await redactDecision(accept, result, capped, hasher)

    expect(spans).toEqual([])
    expect(truncatedScan).toBe(true)
  })
})
