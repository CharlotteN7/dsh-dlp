/**
 * Arm selection at `tools/post-execute`, and the breadth tier's refusal to
 * widen a decision it was handed.
 */

import { describe, expect, it } from 'vitest'
import type { ToolCallBlock } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { breadthTierDenial, evaluateBreadthTier, redactDecision } from '../../src/results.ts'
import { resolvePolicy, type Config } from '../../src/policy.ts'
import { SpanHasher } from '../../src/redaction.ts'

const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
const SHOPIFY = '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'
const hasher = new SpanHasher(Buffer.from('dsh-dlp-unit-test-key-000000000000', 'utf8'))
const policy = resolvePolicy({
  auditLog: '/dev/null',
  redactionKeyFile: '/dev/null',
  maxScanBytes: 1024 * 1024,
  breadthTier: true,
  resultRedaction: true,
  telemetryRedaction: true,
  redactTelemetryWorkspacePaths: true,
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

  it('carries downstream additionalContexts onto the replacement', async () => {
    const contexts = [{ content: [{ type: 'text' as const, text: 'note' }], source: { kind: 'plugin' } }]
    const downstream = { kind: 'accept', value: { note: SLACK }, additionalContexts: contexts } as PostToolDecision

    const { decision } = await redactDecision(downstream, success({}, ''), policy, hasher)

    expect((decision as { additionalContexts?: unknown }).additionalContexts).toBe(contexts)
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

    expect(finding?.ruleIds).toContain('@secretlint/secretlint-rule-shopify')
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
  it('leaves the value alone when no single field reproduces the match', async () => {
    // The private-key block spans three fields; the probe sees it in the
    // serialized form, and no individual string carries it.
    const value = {
      begin: '-----BEGIN RSA PRIVATE KEY-----',
      body: 'MIIEowIBAAKCAQEA',
      end: '-----END RSA PRIVATE KEY-----',
    }

    const { decision, spans } = await redactDecision(accept, success(value, ''), policy, hasher)

    expect(decision).toBe(accept)
    expect(spans).toEqual([])
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

describe('a result with more strings than the tier-2 budget', () => {
  it('falls back to the synchronous tier and says the scan was partial', async () => {
    const lines = Array.from({ length: 400 }, (_, index) => `line ${index}`)
    lines[399] = `token ${SLACK}`
    const result = success({ lines }, lines.join('\n'))

    const { decision, truncatedScan } = await redactDecision(accept, result, policy, hasher)

    expect(truncatedScan).toBe(true)
    expect(JSON.stringify(decision)).not.toContain(SLACK)
  })
})
