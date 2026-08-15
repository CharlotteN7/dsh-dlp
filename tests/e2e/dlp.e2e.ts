/**
 * The evidence bar from CONVENTIONS.md §5: a booted harness, this plugin
 * mounted, a mock model driving a real tool call, and an assertion on the
 * resulting session log. A unit test proving a regular expression matches is
 * not evidence that the plugin works.
 */

import { describe, expect, it } from 'vitest'
import { runAgent } from './harness.ts'

/** A Slack bot token shaped like the real thing; not a live credential. */
const SLACK_TOKEN = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'

/** Rows the agent persisted for completed tool calls. */
function toolResults(log: readonly Record<string, unknown>[]): Record<string, unknown>[] {
  return log.filter(row => row['type'] === 'tool/result')
}

describe('dsh-dlp mounted into a real dsh profile', () => {
  it('denies a model-issued read of a credential file and tells the model why', async () => {
    const result = await runAgent({
      task: 'read the deploy key',
      // One request per entry: the model asks for a tool, then answers.
      // The session-title provider issues a third request, so the script
      // carries a spare success.
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'read',
      toolArguments: JSON.stringify({ file_path: '{{DSH_HOME}}/.ssh/id_rsa' }),
      successText: 'I cannot read that file.',
      seedFiles: { '.ssh/id_rsa': `-----BEGIN OPENSSH PRIVATE KEY-----\nDEPLOY_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----\n` },
    })

    expect(result.code, result.stderr).toBe(0)

    // The guard denied before dispatch, so the file body never became a result.
    const results = toolResults(result.sessionLog)
    expect(results.length).toBeGreaterThan(0)
    expect(JSON.stringify(results)).toContain('dsh-dlp denied')
    expect(JSON.stringify(results)).toContain('dsh-dlp/path-ssh-dir')
    expect(JSON.stringify(results)).not.toContain('DEPLOY_KEY_BODY')

    // The reason reached the model: it appears in a later request body.
    const laterRequests = result.modelRequests.slice(1).map(request => JSON.stringify(request.body)).join('\n')
    expect(laterRequests).toContain('dsh-dlp denied')
    expect(laterRequests).toContain('Ask the user')

    // The decision is in this plugin's own sink, with its own identity, and
    // the session log gained no plugin-owned event type.
    const denials = result.auditRecords.filter(record => record['kind'] === 'guard-deny')
    expect(denials).toHaveLength(1)
    expect(denials[0]).toMatchObject({ v: 1, tool: 'read' })
    expect(String(denials[0]?.['decisionId'])).toMatch(/^dlp-/)
    expect(String(denials[0]?.['sessionId']).length).toBeGreaterThan(0)
    expect(result.sessionLog.every(row => !String(row['type']).startsWith('dsh-dlp'))).toBe(true)
  }, 120_000)

  it('redacts a secret out of a tool result before the model and the session log see it', async () => {
    const result = await runAgent({
      task: 'read the service notes',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'read',
      toolArguments: JSON.stringify({ file_path: '{{DSH_HOME}}/notes.txt' }),
      successText: 'the notes mention a redacted token',
      // The token lives only in the file, so it can only reach the model
      // through the tool RESULT. Arguments are never rewritten — they are
      // already logged and presented — so a secret placed there would prove
      // nothing about redaction.
      seedFiles: { 'notes.txt': `deployment notes\nslack bot token: ${SLACK_TOKEN}\nend of notes\n` },
    })

    expect(result.code, result.stderr).toBe(0)

    // Replacement happens before the tool/result event is appended, so the
    // durable log holds the redacted copy.
    const results = toolResults(result.sessionLog)
    expect(results.length).toBeGreaterThan(0)
    expect(JSON.stringify(results)).not.toContain(SLACK_TOKEN)
    expect(JSON.stringify(results)).toContain('[REDACTED:dsh-dlp:slack-token:')
    expect(JSON.stringify(results)).toContain('deployment notes')

    // Nothing the agent sent to the provider carried the token.
    expect(JSON.stringify(result.modelRequests)).not.toContain(SLACK_TOKEN)

    // The audit record names the rule and a keyed hash, never the token.
    const redactions = result.auditRecords.filter(record => record['kind'] === 'result-redaction')
    expect(redactions.length).toBeGreaterThan(0)
    const spans = redactions[0]?.['spans'] as { ruleId: string; hash: string }[]
    expect(spans[0]?.ruleId).toBe('dsh-dlp/slack-token')
    expect(spans[0]?.hash).toMatch(/^[0-9a-f]{12}$/)
    expect(JSON.stringify(result.auditRecords)).not.toContain(SLACK_TOKEN)
  }, 120_000)

  it('leaves an ordinary tool call alone', async () => {
    const result = await runAgent({
      task: 'print the round-trip marker',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'bash',
      toolArguments: JSON.stringify({
        command: 'printf E2E_ROUND_TRIP',
        description: 'Print the round-trip marker',
      }),
      successText: 'round trip complete',
    })

    expect(result.code, result.stderr).toBe(0)
    expect(JSON.stringify(toolResults(result.sessionLog))).toContain('E2E_ROUND_TRIP')
    expect(result.auditRecords).toEqual([])
  }, 120_000)
})
