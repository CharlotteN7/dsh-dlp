/**
 * The packaged `dsh-dlp report` command, run the way a user runs it: the built
 * `lib/cli.js` in its own Node process, over an audit file a real run produced.
 */

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { runAgent } from './harness.ts'

/** Package root of the plugin under test. */
const PLUGIN_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/** The built command, as the `bin` entry names it. */
const CLI = fileURLToPath(new URL('../../lib/cli.js', import.meta.url))

/** Somewhere to keep the audit bytes a run produced; the run's own home is deleted. */
const scratch = mkdtempSync(join(tmpdir(), 'dsh-dlp-report-'))
afterAll(() => { rmSync(scratch, { recursive: true, force: true }) })

/** Run the built command and hand back what it printed. */
function report(args: readonly string[]): { code: number; stdout: string } {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' }) }
  } catch (error: unknown) {
    const failure = error as { status?: number; stdout?: string }
    return { code: failure.status ?? -1, stdout: failure.stdout ?? '' }
  }
}

describe('dsh-dlp report', () => {
  it('is the package bin, and prints its usage', () => {
    const manifest = JSON.parse(readFileSync(`${PLUGIN_ROOT}package.json`, 'utf8')) as { bin: Record<string, string> }

    expect(manifest.bin).toEqual({ 'dsh-dlp': 'lib/cli.js' })
    expect(report(['--help']).stdout).toContain('Usage: dsh-dlp report')
  })

  it('reads back the decisions a real run recorded', async () => {
    // The agent's own audit file, written by the mounted plugin during a run
    // that was denied a credential path.
    const result = await runAgent({
      task: 'read the deploy key',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'read',
      toolArguments: JSON.stringify({ file_path: '{{WORKSPACE}}/.ssh/id_rsa' }),
      successText: 'I cannot read that file.',
      seedFiles: { '.ssh/id_rsa': 'PRIVATE-KEY-BODY\n' },
    })

    expect(result.code, result.stderr).toBe(0)
    const auditLog = join(scratch, 'dsh-dlp.audit.jsonl')
    writeFileSync(auditLog, result.auditLogText)

    const printed = report(['report', '--log', auditLog]).stdout

    expect(printed).toContain('decision(s) in')
    expect(printed).toContain('guard-deny')
    expect(printed).toContain('dsh-dlp/path-ssh-dir')
    expect(printed).toContain('read')
    expect(printed).not.toContain('PRIVATE-KEY-BODY')
  }, 120_000)

  it('names the state that left an ask with nobody to prompt', async () => {
    // The abstention is the state an operator most needs to see: a documented
    // prompt did not happen and the call ran. The sink recorded which state
    // caused it from the first release; nothing printed it.
    const result = await runAgent({
      task: 'add the session hook',
      sequence: ['tool_call_success', 'success', 'success'],
      toolName: 'write',
      toolArguments: JSON.stringify({
        file_path: '{{WORKSPACE}}/.claude/settings.json',
        content: `${JSON.stringify({
          hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'echo e2e-hook-body' }] }] },
        })}\n`,
      }),
      successText: 'added',
    })

    expect(result.code, result.stderr).toBe(0)
    const auditLog = join(scratch, 'abstained.audit.jsonl')
    writeFileSync(auditLog, result.auditLogText)

    const printed = report(['report', '--log', auditLog]).stdout

    expect(printed).toContain('pre-execute-ask-abstained')
    expect(printed).toContain('asks that reached nobody')
    expect(printed).toContain('policy-never')
    expect(printed).toContain('no prompt: policy-never')
  }, 120_000)

  it('says where it looked when there is no audit file', () => {
    const result = report(['report', '--log', '/nonexistent/dsh-dlp.audit.jsonl'])

    expect(result.code).toBe(0)
    expect(result.stdout).toContain('no audit file at /nonexistent/dsh-dlp.audit.jsonl')
  })

  it('exits 2 on a usage error', () => {
    expect(report(['report', '--nope']).code).toBe(2)
  })
})
