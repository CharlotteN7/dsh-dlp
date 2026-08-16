/** What each detection tier reports, and what it refuses to report. */

import { describe, expect, it } from 'vitest'
import { scanAll, scanSync, scanWithSecretlint, SYNC_RULES } from '../../src/detectors.ts'

/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
/** Shaped like a Shopify access token; invented for this test, never a live credential. */
const SHOPIFY = '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'
/** AWS's own published example access key id, which their scanners treat as fake. */
const AWS_EXAMPLE_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'

describe('the synchronous rule table', () => {
  it('finds a Slack bot token and reports where it sits', () => {
    const { detections } = scanSync(`token is ${SLACK} ok`)

    expect(detections).toHaveLength(1)
    expect(detections[0]?.ruleId).toBe('dsh-dlp/slack-token')
    expect(detections[0]?.ruleVersion).toBe(1)
    expect(detections[0]?.severity).toBe('critical')
    expect('token is '.length).toBe(detections[0]?.start)
    expect(detections[0]?.end).toBe('token is '.length + SLACK.length)
  })

  it('leaves ordinary prose alone', () => {
    const prose = 'The deployment reads its configuration from the profile directory and then starts.'

    expect(scanSync(prose).detections).toEqual([])
  })

  it('reports every match in a string carrying more than one secret', () => {
    const { detections } = scanSync(`${SLACK} and ${AWS_EXAMPLE_KEY_ID}`)

    expect(detections.map(detection => detection.ruleId).sort()).toEqual([
      'dsh-dlp/aws-access-key-id',
      'dsh-dlp/slack-token',
    ])
  })

  it('finds a private key block spanning several lines', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----'

    expect(scanSync(pem).detections[0]?.ruleId).toBe('dsh-dlp/private-key-block')
  })

  it('finds credentials embedded in a URL', () => {
    expect(scanSync('postgres://admin:Sup3rS3cret@db.example.com:5432/prod').detections[0]?.ruleId)
      .toBe('dsh-dlp/credential-url')
  })

  it('finds a webhook URL whose path segment is the credential', () => {
    const webhook = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'

    expect(scanSync(`SLACK_WEBHOOK=${webhook}`).detections[0]?.ruleId).toBe('dsh-dlp/slack-webhook-url')
  })

  it('orders two matches that start together by where they end', () => {
    const rules = [
      { id: 'test/long', version: 1, severity: 'high' as const, pattern: /ABC/g },
      { id: 'test/short', version: 1, severity: 'high' as const, pattern: /AB/g },
    ]

    const { detections } = scanSync('ABC', rules)

    expect(detections.map(detection => detection.ruleId)).toEqual(['test/short', 'test/long'])
  })

  it('does not carry its own lastIndex between scans', () => {
    const first = scanSync(SLACK).detections
    const second = scanSync(SLACK).detections

    expect(second).toEqual(first)
  })
})

describe('the secretlint tier', () => {
  it('finds a secret the synchronous table does not carry', async () => {
    expect(scanSync(SHOPIFY).detections).toEqual([])

    const { detections } = await scanWithSecretlint(SHOPIFY)

    expect(detections[0]?.ruleId).toBe('@secretlint/secretlint-rule-shopify')
    expect(detections[0]?.severity).toBe('high')
  })

  it('reports nothing for clean text', async () => {
    const { detections } = await scanWithSecretlint('a paragraph about nothing in particular')

    expect(detections).toEqual([])
  })

  it('marks a scan that hit the byte cap', async () => {
    const result = await scanWithSecretlint(`${'x'.repeat(64)} ${SHOPIFY}`, 16)

    expect(result.truncated).toBe(true)
  })
})

describe('both tiers together', () => {
  it('returns the union, ordered by position', async () => {
    const { detections } = await scanAll(`${SLACK} then ${SHOPIFY}`)
    const ruleIds = detections.map(detection => detection.ruleId)

    expect(ruleIds).toContain('dsh-dlp/slack-token')
    expect(ruleIds).toContain('@secretlint/secretlint-rule-shopify')
    expect([...detections].sort((a, b) => a.start - b.start)).toEqual(detections)
  })

  it('reports truncation when tier 2 saw only part of the input', async () => {
    const result = await scanAll('x'.repeat(64), SYNC_RULES, 16)

    expect(result.truncated).toBe(true)
  })

  it('still runs tier 1 past the cap that stops tier 2', async () => {
    const text = `${'x'.repeat(2000)} ${SLACK}`

    const result = await scanAll(text, SYNC_RULES, 1000)

    expect(result.truncated).toBe(true)
    expect(result.detections.map(detection => detection.ruleId)).toContain('dsh-dlp/slack-token')
  })
})
