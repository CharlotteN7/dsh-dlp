/**
 * `dsh-dlp report`: what it reads out of the audit file and what it refuses to
 * trust in it. The packaged command itself is run as a subprocess in
 * tests/e2e/report.e2e.ts.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  formatReport,
  main,
  parseArguments,
  parseRecord,
  parseSince,
  readAuditFile,
  USAGE,
  type ReportRecord,
} from '../../src/cli.ts'

const home = mkdtempSync(join(tmpdir(), 'dsh-dlp-cli-'))
afterAll(() => { rmSync(home, { recursive: true, force: true }) })

/** Epoch milliseconds the relative-span tests count back from. */
const NOW = Date.parse('2026-08-16T12:00:00.000Z')

/** One audit line, as the sink writes it. */
function line(record: Record<string, unknown>): string {
  return JSON.stringify({ v: 1, decisionId: 'dlp-1', ...record })
}

/** Write an audit file and hand back its path. */
let counter = 0
function auditFile(...lines: string[]): string {
  counter += 1
  const path = join(home, `audit-${counter}.jsonl`)
  writeFileSync(path, lines.map(text => `${text}\n`).join(''))
  return path
}

/** Run `main` and collect what it wrote where. */
function run(argv: readonly string[]): { code: number; out: string; err: string } {
  const out: string[] = []
  const err: string[] = []
  const code = main(argv, text => out.push(text), text => err.push(text), { DSH_HOME: home }, NOW)
  return { code, out: out.join('\n'), err: err.join('\n') }
}

const GUARD_DENY = line({
  time: '2026-08-15T10:00:00.000Z',
  kind: 'guard-deny',
  tool: 'read',
  sessionId: 'session-a',
  spans: [{ ruleId: 'dsh-dlp/path-ssh-dir', ruleVersion: 2, severity: 'critical', start: 0, end: 9, hash: 'a'.repeat(12) }],
})

const REDACTION = line({
  time: '2026-08-16T11:00:00.000Z',
  kind: 'result-redaction',
  tool: 'read',
  sessionId: 'session-b',
  spans: [{ ruleId: 'dsh-dlp/slack-token', ruleVersion: 1, severity: 'critical', start: 3, end: 40, hash: 'b'.repeat(12) }],
  unicode: { 'dsh-dlp/unicode-zero-width': 2 },
})

describe('reading one audit line', () => {
  it('keeps the fields the report is built from', () => {
    expect(parseRecord(GUARD_DENY)).toEqual({
      time: Date.parse('2026-08-15T10:00:00.000Z'),
      kind: 'guard-deny',
      tool: 'read',
      sessionId: 'session-a',
      ruleIds: ['dsh-dlp/path-ssh-dir'],
      unicode: {},
    })
  })

  it('names each rule once however many spans quoted it', () => {
    const record = parseRecord(line({
      time: '2026-08-15T10:00:00.000Z',
      kind: 'result-redaction',
      spans: [{ ruleId: 'dsh-dlp/slack-token' }, { ruleId: 'dsh-dlp/slack-token' }, { ruleId: 'dsh-dlp/npm-token' }],
    }))

    expect(record?.ruleIds).toEqual(['dsh-dlp/slack-token', 'dsh-dlp/npm-token'])
    expect(record?.tool).toBeUndefined()
    expect(record?.sessionId).toBeUndefined()
  })

  it('reads the rule of a decision that has no matched region, which every ask is', () => {
    const record = parseRecord(line({
      time: '2026-08-15T10:00:00.000Z',
      kind: 'pre-execute-ask',
      tool: 'write',
      ruleId: 'dsh-dlp/config-ci-workflow',
    }))

    expect(record?.ruleIds).toEqual(['dsh-dlp/config-ci-workflow'])
  })

  it('names a top-level rule ahead of the spans, when a record carries both', () => {
    const record = parseRecord(line({
      time: '2026-08-15T10:00:00.000Z',
      kind: 'result-redaction',
      ruleId: 'dsh-dlp/config-ci-workflow',
      spans: [{ ruleId: 'dsh-dlp/slack-token' }],
    }))

    expect(record?.ruleIds).toEqual(['dsh-dlp/config-ci-workflow', 'dsh-dlp/slack-token'])
  })

  it.each([
    ['a torn final append', '{"kind":"guard-deny"'],
    ['a line that is not an object', '"guard-deny"'],
    ['a line that is an array', '[1,2]'],
    ['a record with no kind', line({ time: '2026-08-15T10:00:00.000Z' })],
    ['a record with no time', line({ kind: 'guard-deny' })],
    ['a record with an unparseable time', line({ time: 'the other day', kind: 'guard-deny' })],
  ])('refuses %s', (_label, text) => {
    expect(parseRecord(text)).toBeUndefined()
  })

  it.each([
    ['spans that are not a list', { spans: 'dsh-dlp/slack-token' }],
    ['a span that is not an object', { spans: ['dsh-dlp/slack-token'] }],
    ['a span with no rule id', { spans: [{ start: 0 }] }],
  ])('reads no rule from %s', (_label, extra) => {
    expect(parseRecord(line({ time: '2026-08-15T10:00:00.000Z', kind: 'guard-deny', ...extra }))?.ruleIds).toEqual([])
  })

  it.each([
    ['a count field that is not a mapping', { unicode: 3 }],
    ['a count field that is a list', { unicode: ['x'] }],
    ['a count that is not a number', { unicode: { 'dsh-dlp/unicode-zero-width': 'many' } }],
  ])('reads no counts from %s', (_label, extra) => {
    expect(parseRecord(line({ time: '2026-08-15T10:00:00.000Z', kind: 'guard-deny', ...extra }))?.unicode).toEqual({})
  })
})

describe('reading --since', () => {
  it.each([
    ['30s', 30_000],
    ['30m', 1_800_000],
    ['24h', 86_400_000],
    ['7d', 604_800_000],
  ])('counts %s back from now', (value, back) => {
    expect(parseSince(value, NOW)).toBe(NOW - back)
  })

  it('takes an absolute timestamp', () => {
    expect(parseSince('2026-08-15T00:00:00.000Z', NOW)).toBe(Date.parse('2026-08-15T00:00:00.000Z'))
  })

  it('refuses anything else', () => {
    expect(parseSince('last tuesday', NOW)).toBeUndefined()
  })
})

describe('reading the command line', () => {
  const parse = (...argv: string[]) => parseArguments(argv, { DSH_HOME: home }, NOW)

  it('defaults the audit file to the one the bundle patch configures', () => {
    expect(parse('report')).toEqual({
      kind: 'report',
      options: { log: join(home, 'dsh-dlp.audit.jsonl'), wouldHave: false },
    })
  })

  it.each([[[]], [['-h']], [['--help']], [['report', '--help']], [['report', '-h']]])('prints usage for %j', (argv) => {
    expect(parse(...argv)).toEqual({ kind: 'help' })
  })

  it('takes every filter', () => {
    expect(parse('report', '--log', '/tmp/a.jsonl', '--since', '24h', '--session', 'session-a', '--would-have'))
      .toEqual({
        kind: 'report',
        options: {
          log: '/tmp/a.jsonl',
          since: NOW - 86_400_000,
          session: 'session-a',
          wouldHave: true,
        },
      })
  })

  it.each([
    ['an unknown command', ['inspect'], 'unknown command "inspect"'],
    ['an unknown option', ['report', '--everything'], 'unknown option "--everything"'],
    ['a flag with no value', ['report', '--log'], '--log needs a value'],
    ['a --since it cannot read', ['report', '--since', 'soon'], 'is neither a timestamp nor a span'],
  ])('refuses %s', (_label, argv, message) => {
    const invocation = parse(...argv)

    expect(invocation.kind).toBe('error')
    expect(invocation.kind === 'error' ? invocation.message : '').toContain(message)
  })

  it('does not read a flag value as a flag', () => {
    expect(parse('report', '--session', '--would-have')).toEqual({
      kind: 'report',
      options: { log: join(home, 'dsh-dlp.audit.jsonl'), session: '--would-have', wouldHave: false },
    })
  })
})

describe('reading the audit file', () => {
  it('reports absence separately from emptiness', () => {
    expect(readAuditFile(join(home, 'no-such-file.jsonl'))).toEqual({ kind: 'absent' })
    expect(readAuditFile(auditFile())).toEqual({ kind: 'read', records: [], unreadable: 0 })
  })

  it('counts the lines it could not read instead of failing on them', () => {
    const read = readAuditFile(auditFile(GUARD_DENY, '{"torn', ''))

    expect(read).toMatchObject({ kind: 'read', unreadable: 1 })
    expect(read.kind === 'read' ? read.records : []).toHaveLength(1)
  })

  it('reports a file it cannot read at all', () => {
    const directory = join(home, 'audit-is-a-directory')
    mkdirSync(directory, { recursive: true })

    expect(readAuditFile(directory)).toMatchObject({ kind: 'unreadable', problem: expect.stringContaining('cannot read') })
  })
})

describe('the report', () => {
  const records = [GUARD_DENY, REDACTION].flatMap((text) => {
    const record = parseRecord(text)
    return record === undefined ? [] : [record]
  }) as ReportRecord[]

  it('counts by decision, rule, tool and invisible-character class', () => {
    const report = formatReport(records, 0, { log: '/tmp/a.jsonl', wouldHave: false }).join('\n')

    expect(report).toContain('2 decision(s) in /tmp/a.jsonl')
    expect(report).toContain('guard-deny')
    expect(report).toContain('dsh-dlp/path-ssh-dir')
    expect(report).toContain('read')
    expect(report).toContain('dsh-dlp/unicode-zero-width')
    expect(report).toContain('most recent 2')
  })

  it('lists the newest decision first', () => {
    const report = formatReport(records, 0, { log: '/tmp/a.jsonl', wouldHave: false })
    const recent = report.slice(report.indexOf('most recent 2') + 1)

    expect(recent[0]).toContain('2026-08-16T11:00:00.000Z')
    expect(recent[1]).toContain('2026-08-15T10:00:00.000Z')
  })

  it('says which lines it could not read', () => {
    expect(formatReport(records, 2, { log: '/tmp/a.jsonl', wouldHave: false }).join('\n'))
      .toContain('2 line(s) were not readable as records')
  })

  it('leaves out what the filters exclude, and says which filters ran', () => {
    const report = formatReport(records, 0, {
      log: '/tmp/a.jsonl',
      since: Date.parse('2026-08-16T00:00:00.000Z'),
      session: 'session-b',
      wouldHave: true,
    }).join('\n')

    expect(report).toContain('1 decision(s)')
    expect(report).toContain('since 2026-08-16T00:00:00.000Z')
    expect(report).toContain('session session-b')
    expect(report).toContain('decisions that stopped a call left out')
    expect(report).not.toContain('guard-deny')
  })

  it('leaves out every denial when only the calls that got through are asked for', () => {
    const report = formatReport(records, 0, { log: '/tmp/a.jsonl', wouldHave: true }).join('\n')

    expect(report).toContain('1 decision(s)')
    expect(report).not.toContain('dsh-dlp/path-ssh-dir')
  })

  it('stops after the header when nothing is left', () => {
    expect(formatReport(records, 0, { log: '/tmp/a.jsonl', session: 'session-z', wouldHave: false }))
      .toEqual(['dsh-dlp: 0 decision(s) in /tmp/a.jsonl', '  session session-z'])
  })

  it('shows a decision that named no rule and no tool', () => {
    const telemetry = parseRecord(line({ time: '2026-08-16T11:30:00.000Z', kind: 'telemetry-redaction' }))

    const report = formatReport(telemetry === undefined ? [] : [telemetry], 0, { log: '/tmp/a.jsonl', wouldHave: false })

    expect(report.at(-1)).toBe('  2026-08-16T11:30:00.000Z  telemetry-redaction  -  -')
  })
})

describe('the command', () => {
  it('prints usage and succeeds when asked for help', () => {
    expect(run(['--help'])).toEqual({ code: 0, out: USAGE, err: '' })
  })

  it('prints usage on stderr and exits 2 on a usage error', () => {
    const result = run(['report', '--nope'])

    expect(result.code).toBe(2)
    expect(result.err).toContain('unknown option')
    expect(result.err).toContain('Usage: dsh-dlp report')
  })

  it('says where it looked when the deployment put the sink elsewhere', () => {
    const result = run(['report'])

    expect(result.code).toBe(0)
    expect(result.out).toContain(`no audit file at ${join(home, 'dsh-dlp.audit.jsonl')}`)
    expect(result.out).toContain('--log')
  })

  it('exits 1 when the file is there but unreadable', () => {
    const directory = join(home, 'unreadable-audit')
    mkdirSync(directory, { recursive: true })

    const result = run(['report', '--log', directory])

    expect(result.code).toBe(1)
    expect(result.err).toContain('cannot read')
  })

  it('prints the report for a file it can read', () => {
    const result = run(['report', '--log', auditFile(GUARD_DENY, REDACTION)])

    expect(result.code).toBe(0)
    expect(result.out).toContain('2 decision(s)')
    expect(result.out).toContain('dsh-dlp/slack-token')
  })
})
