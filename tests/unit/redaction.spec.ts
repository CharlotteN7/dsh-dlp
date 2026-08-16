/** Placeholder stability, span expansion, and the two structural walkers. */

import { describe, expect, it } from 'vitest'
import type { ContentBlock, ToolCallBlock } from '@deepseek-ai/dsh-llm'
import { scanSync, scanWithSecretlint } from '../../src/detectors.ts'
import {
  nestedStrings,
  placeholderFor,
  redactContent,
  redactJson,
  redactText,
  shortRuleId,
  SpanHasher,
} from '../../src/redaction.ts'

const KEY = Buffer.from('dsh-dlp-unit-test-key-000000000000', 'utf8')
const OTHER_KEY = Buffer.from('a-completely-different-unit-key-01', 'utf8')
/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'

const hasher = new SpanHasher(KEY)
const detect = (text: string) => scanSync(text).detections

describe('the span hasher', () => {
  it('rejects a key too short to be a key', () => {
    expect(() => new SpanHasher(Buffer.alloc(8))).toThrow(/at least 16 bytes/)
  })

  it('produces the same hash for the same secret', () => {
    expect(hasher.hash(SLACK)).toBe(hasher.hash(SLACK))
  })

  it('produces a different hash under a different key', () => {
    expect(new SpanHasher(OTHER_KEY).hash(SLACK)).not.toBe(hasher.hash(SLACK))
  })
})

describe('the placeholder', () => {
  it('shortens a package-qualified secretlint rule id', () => {
    expect(shortRuleId('@secretlint/secretlint-rule-stripe')).toBe('stripe')
    expect(shortRuleId('dsh-dlp/slack-token')).toBe('slack-token')
  })

  it('carries the rule and the keyed hash', () => {
    expect(placeholderFor({ ruleId: 'dsh-dlp/slack-token', hash: 'abc123abc123' }))
      .toBe('[REDACTED:dsh-dlp:slack-token:abc123abc123]')
  })
})

describe('redacting one string', () => {
  it('replaces the secret and never emits it', () => {
    const { text, spans } = redactText(`token=${SLACK} rest`, detect(`token=${SLACK} rest`), hasher)

    expect(text).not.toContain(SLACK)
    expect(text).toContain('[REDACTED:dsh-dlp:slack-token:')
    expect(text.endsWith(' rest')).toBe(true)
    expect(spans).toHaveLength(1)
  })

  it('returns the input untouched when nothing matched', () => {
    const clean = 'nothing to see here'

    expect(redactText(clean, [], hasher)).toEqual({ text: clean, spans: [] })
  })

  it('expands an advisory span that under-covers the secret', async () => {
    // Verified behavior of @secretlint/secretlint-rule-aws: the reported range
    // covers the assignment prefix, not the whole 40-character secret.
    // 40 invented characters in an AWS secret key's shape; never a live credential.
    const secret = 'kL9xQ2mZ7pR4tY6wA1sD3fG5hJ8kL0nM2bV4cX6z'
    const source = `aws_secret_access_key = ${secret}`
    const { detections } = await scanWithSecretlint(source)

    expect(detections[0]?.end).toBeLessThan(source.length)

    const { text } = redactText(source, detections, hasher)

    expect(text).not.toContain(secret)
    expect(text).not.toContain(secret.slice(-8))
  })

  it('grows a span leftward only to the nearest delimiter', () => {
    const source = `id=abc${SLACK}`
    const advisory = [{ ruleId: 'test/mid-token', ruleVersion: 1, severity: 'critical' as const, start: 6, end: source.length }]

    const { text, spans } = redactText(source, advisory, hasher)

    expect(text).toBe(`id=[REDACTED:dsh-dlp:test/mid-token:${spans[0]?.hash}]`)
  })

  it('keeps the rest of a line of minified JSON', () => {
    // Expanding to whitespace replaced the whole record: a JSON line has none.
    const line = `{"user":"alice","token":"${SLACK}","order_id":12345}`

    const { text } = redactText(line, detect(line), hasher)

    expect(text).not.toContain(SLACK)
    expect(text).toContain('"user":"alice"')
    expect(text).toContain('"order_id":12345')
  })

  it('merges overlapping spans into one placeholder', () => {
    const source = `postgres://user:${SLACK}@db.example.com/prod`
    const { text, spans } = redactText(source, detect(source), hasher)

    expect(spans).toHaveLength(1)
    expect(text.match(/\[REDACTED:/g)).toHaveLength(1)
    expect(text).not.toContain(SLACK)
  })

  it('attributes a merged span to its strictest rule', () => {
    const source = `password: ${SLACK}`
    const { spans } = redactText(source, detect(source), hasher)

    expect(spans).toHaveLength(1)
    expect(spans[0]?.severity).toBe('critical')
  })
})

describe('redacting a JSON value', () => {
  it('rewrites strings at every depth and leaves other types alone', () => {
    const value = { count: 3, ok: true, nested: { list: [SLACK, 'clean'], nothing: null } }

    const result = redactJson(value, detect, hasher)

    expect(result.changed).toBe(true)
    expect(JSON.stringify(result.value)).not.toContain(SLACK)
    expect(result.value).toMatchObject({ count: 3, ok: true })
    expect((result.value as { nested: { nothing: unknown } }).nested.nothing).toBeNull()
  })

  it('records a JSON pointer for each replaced string', () => {
    const result = redactJson({ 'a/b': [SLACK] }, detect, hasher)

    expect(result.spans[0]?.path).toBe('/a~1b/0')
  })

  it('leaves object keys alone', () => {
    const result = redactJson({ [SLACK]: 'value' }, detect, hasher)

    expect(Object.keys(result.value as object)).toEqual([SLACK])
    expect(result.changed).toBe(false)
  })

  it('reports no change for a clean structure', () => {
    const value = { a: 'one', b: [1, 2, 3] }

    expect(redactJson(value, detect, hasher)).toMatchObject({ value, changed: false })
  })
})

describe('redacting content blocks', () => {
  it('rewrites text blocks and passes other block types through', () => {
    const blocks: ContentBlock[] = [
      { type: 'text', text: `leaked ${SLACK}` },
      { type: 'tool-call', id: 'call-1' as ToolCallBlock['id'], name: 'read', arguments: '{}' },
    ]

    const result = redactContent(blocks, detect, hasher)

    expect(result.changed).toBe(true)
    expect(JSON.stringify(result.content)).not.toContain(SLACK)
    expect(result.content[1]).toBe(blocks[1])
    expect(result.spans[0]?.path).toBe('/0/text')
  })

  it('reports no change for clean blocks', () => {
    const blocks = [{ type: 'text' as const, text: 'all clear' }]

    expect(redactContent(blocks, detect, hasher).changed).toBe(false)
  })
})

describe('collecting nested strings', () => {
  it('finds strings at every depth and ignores keys', () => {
    expect(nestedStrings({ file_path: '/a', nested: { list: ['/b', 7], flag: true } })).toEqual(['/a', '/b'])
  })

  it('handles a payload that is not an object', () => {
    expect(nestedStrings('bare')).toEqual(['bare'])
    expect(nestedStrings(null)).toEqual([])
  })
})
