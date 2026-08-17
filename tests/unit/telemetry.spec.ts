/**
 * The `session-telemetry/record` listener. The waterfall ships no rules of its
 * own, so with nothing mounted a `FULL` deployment exports message text, tool
 * arguments, tool results and workspace paths in the clear.
 */

import { describe, expect, it } from 'vitest'
import type { SessionTelemetryRecord } from '@deepseek-ai/dsh-session-telemetry'
import { redactRecord, WORKSPACE_PATH_RULE } from '../../src/telemetry.ts'
import { resolvePolicy, type Config } from '../../src/policy.ts'
import { SpanHasher } from '../../src/redaction.ts'

/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
const hasher = new SpanHasher(Buffer.from('dsh-dlp-unit-test-key-000000000000', 'utf8'))
const config: Config = {
  auditLog: '/dev/null',
  redactionKeyFile: '/dev/null',
  maxScanBytes: 1024 * 1024,
  breadthTier: true,
  resultRedaction: true,
  telemetryRedaction: true,
  remoteImageNeutralization: true,
  redactTelemetryWorkspacePaths: true,
  configWriteAsk: true,
}
const policy = resolvePolicy(config)
const withoutPathRedaction = resolvePolicy({ ...config, redactTelemetryWorkspacePaths: false })

const ledger = (body: unknown, attributes: Record<string, string | number> = {}): SessionTelemetryRecord => ({
  channel: 'ledger',
  time: 1,
  severity: 'info',
  attributes: { 'session.id': 'abc', 'event.type': 'user/message', 'event.seq': 4, ...attributes },
  body,
})

describe('a ledger record', () => {
  it('has a secret in its body replaced', () => {
    const { record, spans } = redactRecord(ledger({ message: { content: [{ type: 'text', text: SLACK }] } }), policy, hasher)

    expect(JSON.stringify(record.body)).not.toContain(SLACK)
    expect(spans[0]?.ruleId).toBe('dsh-dlp/slack-token')
    expect(spans[0]?.path).toBe('/message/content/0/text')
  })

  it.each([
    ['a GitLab personal access token', 'glpat-ABCdefGHIjklMNOpqrST', 'dsh-dlp/gitlab-token'],
    ['a HuggingFace token', `hf_${'d'.repeat(34)}`, 'dsh-dlp/huggingface-token'],
    ['an OpenRouter key', `sk-or-v1-${'0123456789abcdef'.repeat(4)}`, 'dsh-dlp/openrouter-api-key'],
    ['a SendGrid key', `SG.${'h'.repeat(22)}.${'i'.repeat(43)}`, 'dsh-dlp/sendgrid-api-key'],
  ])('has %s replaced, which only tier 1 can do on this seam', (_label, secret, ruleId) => {
    // This waterfall returns a record rather than a promise, so tier 2 is
    // unreachable here and a format missing from tier 1 is exported in the
    // clear.
    const { record, spans } = redactRecord(ledger({ text: `export TOKEN=${secret}` }), policy, hasher)

    expect(JSON.stringify(record.body)).not.toContain(secret)
    expect(spans.map(span => span.ruleId)).toContain(ruleId)
  })

  it('has a secret in an attribute value replaced', () => {
    const { record } = redactRecord(ledger({}, { 'agent.note': `key ${SLACK}` }), policy, hasher)

    expect(record.attributes['agent.note']).not.toContain(SLACK)
  })

  it('keeps numeric attributes as numbers', () => {
    const { record } = redactRecord(ledger({ text: SLACK }), policy, hasher)

    expect(record.attributes['event.seq']).toBe(4)
  })

  it('is returned untouched when it carries nothing to redact', () => {
    const clean = ledger({ message: 'hello' })

    expect(redactRecord(clean, withoutPathRedaction, hasher).record).toBe(clean)
  })
})

describe('the workspace path', () => {
  it('is replaced with a keyed hash when path redaction is on', () => {
    const { record, spans } = redactRecord(ledger({}, { 'session.cwd': '/home/dev/projects/acme' }), policy, hasher)

    expect(record.attributes['session.cwd']).not.toContain('acme')
    expect(record.attributes['session.cwd']).toContain('[REDACTED:dsh-dlp:telemetry-workspace-path:')
    expect(spans[0]?.ruleId).toBe(WORKSPACE_PATH_RULE)
  })

  it('survives untouched when path redaction is off', () => {
    const { record } = redactRecord(
      ledger({}, { 'session.cwd': '/home/dev/projects/acme' }),
      withoutPathRedaction,
      hasher,
    )

    expect(record.attributes['session.cwd']).toBe('/home/dev/projects/acme')
  })
})

describe('an ops record', () => {
  it('has a secret in its body replaced', () => {
    const record: SessionTelemetryRecord = {
      channel: 'ops',
      time: 2,
      severity: 'error',
      attributes: { 'telemetry.op': 'agent-error', 'session.id': 'abc' },
      body: { message: `request failed with ${SLACK}` },
    }

    expect(JSON.stringify(redactRecord(record, policy, hasher).record.body)).not.toContain(SLACK)
  })
})

describe('failing closed', () => {
  it('throws rather than emitting a record it cannot process', () => {
    const broken = { ...policy, syncRules: null as never }

    expect(() => redactRecord(ledger({ text: 'anything' }), broken, hasher)).toThrow()
  })
})
