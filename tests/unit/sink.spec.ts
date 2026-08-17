/**
 * The plugin's own durable output. Nothing here writes to the session log:
 * `Session.append()` cannot set the envelope's `ignorable` flag, and an
 * out-of-repo event type makes the next resume refuse the whole session.
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it, vi } from 'vitest'
import { AuditSink, CallCorrelator, newDecisionId, RECORD_VERSION } from '../../src/sink.ts'

const home = mkdtempSync(join(tmpdir(), 'dsh-dlp-sink-'))
afterAll(() => { rmSync(home, { recursive: true, force: true }) })

/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'

describe('the audit sink', () => {
  it('writes one JSON line per decision, carrying its own identity', () => {
    const file = join(home, 'audit.jsonl')
    const sink = new AuditSink(file, () => { throw new Error('unexpected failure') })

    sink.write({
      v: RECORD_VERSION,
      time: '2026-08-15T00:00:00.000Z',
      kind: 'guard-deny',
      decisionId: newDecisionId(),
      sessionId: 'session-1',
      turn: 2,
      step: 3,
      callId: 'call-1',
      tool: 'bash',
    })
    sink.write({
      v: RECORD_VERSION,
      time: '2026-08-15T00:00:01.000Z',
      kind: 'result-redaction',
      decisionId: newDecisionId(),
      callId: 'call-2',
    })

    const rows = readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line) as Record<string, unknown>)

    expect(rows).toHaveLength(2)
    expect(rows[0]).toMatchObject({ v: 1, kind: 'guard-deny', sessionId: 'session-1', turn: 2, step: 3 })
    expect(String(rows[0]?.['decisionId'])).toMatch(/^dlp-/)
    expect(rows[1]?.['decisionId']).not.toBe(rows[0]?.['decisionId'])
  })

  it('records spans without their matched text', () => {
    const file = join(home, 'spans.jsonl')
    const sink = new AuditSink(file, () => { throw new Error('unexpected failure') })

    sink.write({
      v: RECORD_VERSION,
      time: '2026-08-15T00:00:00.000Z',
      kind: 'result-redaction',
      decisionId: newDecisionId(),
      spans: [{ ruleId: 'dsh-dlp/slack-token', ruleVersion: 1, severity: 'critical', start: 0, end: SLACK.length, hash: 'abc123abc123' }],
    })

    const text = readFileSync(file, 'utf8')

    expect(text).not.toContain(SLACK)
    expect(text).toContain('abc123abc123')
  })

  it('strips a terminal control sequence out of every string it writes', () => {
    // `JSON.stringify` escapes the byte in the file, but every consumer parses
    // it back into a live escape: `dsh-dlp report` prints the tool name, and a
    // tool named with a CSI sequence would rewrite the line describing it.
    const file = join(home, 'control-sequences.jsonl')
    const sink = new AuditSink(file, () => { throw new Error('unexpected failure') })
    const forged = '\u001B[1A\u001B[2Kread'

    sink.write({
      v: RECORD_VERSION,
      time: '2026-08-15T00:00:00.000Z',
      kind: 'execution-mutation',
      decisionId: newDecisionId(),
      tool: forged,
      originalTool: 'read',
      unicode: { '\u001B]8;;https://exfil.invalid\u0007': 1 },
    })

    const row = JSON.parse(readFileSync(file, 'utf8').trim()) as Record<string, unknown>

    expect(JSON.stringify(row)).not.toContain('\u001B')
    expect(row['tool']).toBe('[REDACTED:dsh-dlp:control-sequence][REDACTED:dsh-dlp:control-sequence]read')
    expect(Object.keys(row['unicode'] as object)).toEqual(['[REDACTED:dsh-dlp:control-sequence]'])
  })

  it('reports a write failure instead of turning it into a denial', () => {
    const onFailure = vi.fn()
    const sink = new AuditSink(join(home, 'no-such-directory', 'audit.jsonl'), onFailure)

    sink.write({ v: RECORD_VERSION, time: 't', kind: 'audit-failure', decisionId: newDecisionId() })

    expect(onFailure).toHaveBeenCalledOnce()
  })
})

describe('call correlation', () => {
  it('labels a call with the turn and step its tool/call event reported', () => {
    const correlator = new CallCorrelator()
    correlator.note('call-1', { turn: 4, step: 2 })

    expect(correlator.lookup('call-1')).toEqual({ turn: 4, step: 2 })
  })

  it('forgets a call once its result is committed', () => {
    const correlator = new CallCorrelator()
    correlator.note('call-1', { turn: 1, step: 1 })
    correlator.forget('call-1')

    expect(correlator.lookup('call-1')).toBeUndefined()
  })

  it('knows nothing about a call it never saw', () => {
    expect(new CallCorrelator().lookup('call-x')).toBeUndefined()
  })

  it('drops the oldest entry rather than growing without bound', () => {
    const correlator = new CallCorrelator(2)
    correlator.note('a', { turn: 1, step: 1 })
    correlator.note('b', { turn: 1, step: 2 })
    correlator.note('c', { turn: 1, step: 3 })

    expect(correlator.lookup('a')).toBeUndefined()
    expect(correlator.lookup('c')).toEqual({ turn: 1, step: 3 })
  })
})
