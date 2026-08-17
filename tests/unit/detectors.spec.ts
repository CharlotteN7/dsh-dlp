/** What each detection tier reports, and what it refuses to report. */

import { describe, expect, it } from 'vitest'
import {
  countUnicodeIndicators,
  DENY_SEVERITY,
  scanAll,
  scanSync,
  scanUnicode,
  scanWithSecretlint,
  severityRank,
  stripControlSequences,
  SYNC_RULES,
} from '../../src/detectors.ts'

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

  // Cloudflare's scannable format gives every credential type the same body
  // and a different prefix, so one rule covers all three.
  it.each([
    ['a user API token', 'cfut_'],
    ['an account API token', 'cfat_'],
    ['a global API key', 'cfk_'],
  ])('finds %s in the current prefixed format', (_label, prefix) => {
    const token = `${prefix}${'0123456789abcdefghij'.repeat(2)}Ab12Cd`

    expect(scanSync(`CLOUDFLARE_API_TOKEN=${token}`).detections[0]?.ruleId).toBe('dsh-dlp/cloudflare-api-token')
  })

  it('leaves the legacy Cloudflare token to tier 2, having no prefix to anchor on', () => {
    // 40 alphanumeric characters with no prefix is a word, and tier 1 denies.
    expect(scanSync(`CLOUDFLARE_API_TOKEN ${'0123456789abcdefghij'.repeat(2)}`).detections
      .map(detection => detection.ruleId)).toEqual([])
  })

  it('finds a Supabase secret key in the format issued today', () => {
    expect(scanSync(`SUPABASE_SECRET_KEY=sb_secret_${'N'.repeat(30)}`).detections[0]?.ruleId)
      .toBe('dsh-dlp/supabase-secret-key')
  })

  it('still finds the superseded Supabase format, which is deprecated rather than retired', () => {
    expect(scanSync(`sbp_${'0123456789'.repeat(4)}`).detections[0]?.ruleId).toBe('dsh-dlp/supabase-service-key')
  })

  it('leaves a Supabase publishable key alone, which is meant to reach a browser', () => {
    // Same reasoning as Stripe's `pk_live_`, which this table also skips: a key
    // published in every frontend bundle is not a finding, and denying a call
    // for carrying one would stop ordinary work.
    expect(scanSync('sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgx7Qb').detections).toEqual([])
    expect(scanSync(`pk_live_${'5'.repeat(24)}`).detections).toEqual([])
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

describe('invisible and direction-changing characters', () => {
  /** Tag-block encoding of "hi": the carrier for instructions only the model reads. */
  const TAGS = '\u{E0068}\u{E0069}'
  /** Right-to-left override, which reorders what a reader sees but not what a model reads. */
  const BIDI_OVERRIDE = '\u202E'
  /** Zero-width joiner, which also joins legitimate emoji sequences. */
  const ZWJ = '\u200D'

  it('reports a tag-block run as one strippable finding', () => {
    const findings = scanUnicode(`report${TAGS} ok`)

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      ruleId: 'dsh-dlp/unicode-tag-characters',
      severity: 'medium',
      action: 'strip',
      exact: true,
      start: 'report'.length,
      end: 'report'.length + TAGS.length,
    })
  })

  it('reports a bidi override as strippable and a bidi mark as report-only', () => {
    const findings = scanUnicode(`a${BIDI_OVERRIDE}b\u200Fc`)

    expect(findings.map(finding => [finding.ruleId, finding.action])).toEqual([
      ['dsh-dlp/unicode-bidi-override', 'strip'],
      ['dsh-dlp/unicode-bidi-mark', 'report'],
    ])
  })

  it.each([
    ['a zero-width space', '\u200B', 'dsh-dlp/unicode-zero-width'],
    ['a zero-width joiner', ZWJ, 'dsh-dlp/unicode-zero-width'],
    ['a word joiner', '\u2060', 'dsh-dlp/unicode-zero-width'],
    ['a byte-order mark', '\uFEFF', 'dsh-dlp/unicode-zero-width'],
    ['an Arabic letter mark', '\u061C', 'dsh-dlp/unicode-bidi-mark'],
    ['a variation selector', '\uFE0F', 'dsh-dlp/unicode-variation-selector'],
    ['a supplementary variation selector', '\u{E0100}', 'dsh-dlp/unicode-variation-selector'],
  ])('reports %s without stripping it', (_label, character, ruleId) => {
    const findings = scanUnicode(`x${character}y`)

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ ruleId, action: 'report' })
  })

  describe('a run of variation selectors', () => {
    /** VS16, the selector an emoji presentation sequence uses. */
    const VS = '\uFE0F'
    /** A supplementary selector, the half of the class an Ideographic Variation Sequence uses. */
    const IVS = '\u{E0100}'

    it.each([
      ['one selector, which picks a glyph', 1],
      ['two, which no standard sequence produces but which is not yet a payload', 2],
      ['three', 3],
    ])('leaves %s alone', (_label, length) => {
      const findings = scanUnicode(`base${VS.repeat(length)} text`)

      expect(findings).toHaveLength(1)
      expect(findings[0]).toMatchObject({ ruleId: 'dsh-dlp/unicode-variation-selector', action: 'report' })
      expect(scanSync(`base${VS.repeat(length)}`).detections).toEqual([])
    })

    it.each([
      ['at the threshold', 4],
      ['well past it, as a real payload is', 200],
    ])('strips a run %s', (_label, length) => {
      const text = `base${VS.repeat(length)} text`

      const findings = scanUnicode(text)

      expect(findings).toHaveLength(1)
      expect(findings[0]).toMatchObject({
        ruleId: 'dsh-dlp/unicode-variation-selector-run',
        action: 'strip',
        start: 'base'.length,
        end: 'base'.length + length,
      })
      expect(scanSync(text).detections.map(detection => detection.ruleId))
        .toEqual(['dsh-dlp/unicode-variation-selector-run'])
    })

    it('strips a run written in the supplementary half of the class', () => {
      // GlassWorm used both halves; the supplementary selectors are two UTF-16
      // units each, so a run of four is eight units long.
      const text = `base${IVS.repeat(4)}`

      expect(scanUnicode(text)).toMatchObject([{ ruleId: 'dsh-dlp/unicode-variation-selector-run', end: text.length }])
    })

    it('reports the isolated selector beside a run as its own finding', () => {
      const findings = scanUnicode(`a${VS.repeat(4)}b${VS}c`)

      expect(findings.map(finding => finding.ruleId)).toEqual([
        'dsh-dlp/unicode-variation-selector-run',
        'dsh-dlp/unicode-variation-selector',
      ])
    })

    it('is a run even when another invisible class sits beside it', () => {
      expect(scanUnicode(`${ZWJ}${VS.repeat(4)}`).map(finding => finding.ruleId)).toEqual([
        'dsh-dlp/unicode-zero-width',
        'dsh-dlp/unicode-variation-selector-run',
      ])
    })
  })

  it('splits one run into its classes rather than reporting the run', () => {
    const findings = scanUnicode(`${TAGS}${ZWJ}`)

    expect(findings.map(finding => finding.ruleId)).toEqual([
      'dsh-dlp/unicode-tag-characters',
      'dsh-dlp/unicode-zero-width',
    ])
    expect(findings[1]?.start).toBe(TAGS.length)
  })

  it('says nothing about text that carries none', () => {
    expect(scanUnicode('ordinary text, an em dash — and an emoji 🙂')).toEqual([])
    expect(countUnicodeIndicators('ordinary text')).toEqual({})
  })

  it('counts runs per class', () => {
    expect(countUnicodeIndicators(`${TAGS} a${ZWJ}b ${ZWJ} ${BIDI_OVERRIDE}`)).toEqual({
      'dsh-dlp/unicode-tag-characters': 1,
      'dsh-dlp/unicode-zero-width': 2,
      'dsh-dlp/unicode-bidi-override': 1,
    })
  })

  it('reaches the tier-1 seams for the strippable classes only', () => {
    const detections = scanSync(`a${TAGS}b${BIDI_OVERRIDE}c${ZWJ}d`).detections

    expect(detections.map(detection => detection.ruleId)).toEqual([
      'dsh-dlp/unicode-tag-characters',
      'dsh-dlp/unicode-bidi-override',
    ])
    expect(detections.every(detection => detection.exact === true)).toBe(true)
  })

  it.each([
    ['an SGR colour run', '\u001B[31m'],
    ['a cursor-movement CSI', '\u001B[2A'],
    ['a CSI with intermediate bytes, which an SGR-only rule misses', '\u001B[?25 h'],
    ['an OSC 8 hyperlink, terminated by BEL', '\u001B]8;;https://exfil.invalid\u0007'],
    ['an OSC terminated by ST', '\u001B]0;forged title\u001B\\'],
    ['a DCS string', '\u001BP0;1|17/ab\u001B\\'],
    ['an 8-bit CSI', '\u009B31m'],
  ])('reports %s as one control-sequence finding', (_label, sequence) => {
    const findings = scanUnicode(`ok ${sequence} done`)

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      ruleId: 'dsh-dlp/control-sequence',
      action: 'report',
      start: 'ok '.length,
      end: 'ok '.length + sequence.length,
    })
  })

  it('swallows the tail an unterminated OSC would swallow on a terminal', () => {
    const text = 'ok \u001B]7;file://exfil.invalid/ and everything after it'

    const findings = scanUnicode(text)

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ ruleId: 'dsh-dlp/control-sequence', start: 'ok '.length, end: text.length })
  })

  it('reports an escape that introduces nothing', () => {
    // Only at the end of a string: `ESC SP d` is itself a complete sequence,
    // so a trailing escape is the one form with nothing to consume.
    expect(scanUnicode('ok \u001B')).toMatchObject([{ ruleId: 'dsh-dlp/control-sequence', start: 3, end: 4 }])
  })

  it('leaves colourised tool output in place and only counts it', () => {
    // `git diff`, `rg` and `pytest` colourise by default. Replacing those runs
    // would corrupt the result of half the commands an agent runs.
    const colourised = '\u001B[32m+ added line\u001B[0m'

    expect(scanSync(colourised).detections).toEqual([])
    expect(countUnicodeIndicators(colourised)).toEqual({ 'dsh-dlp/control-sequence': 2 })
  })

  it('replaces every control sequence on the lanes that must not carry them', () => {
    const forged = 'read\u001B[1A\u001B[2Kwrite'

    const stripped = stripControlSequences(forged)

    expect(stripped).not.toContain('\u001B')
    expect(stripped).toBe('read[REDACTED:dsh-dlp:control-sequence][REDACTED:dsh-dlp:control-sequence]write')
    expect(stripControlSequences('ordinary text')).toBe('ordinary text')
  })

  it('stays below the severity at which the guard floor denies', () => {
    // An invisible character is an injection indicator, not credential
    // material: it is redacted and recorded, never turned into a denial.
    for (const detection of scanSync(`${TAGS}${BIDI_OVERRIDE}`).detections) {
      expect(severityRank(detection.severity)).toBeLessThan(severityRank(DENY_SEVERITY))
    }
  })
})
