/**
 * Comparing a tool call against the snapshot taken at the head of the
 * `tools/pre-execute` waterfall.
 */

import { describe, expect, it } from 'vitest'
import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { ExecutionSnapshots, canonicalJson, mutationReason } from '../../src/mutation.ts'
import { SpanHasher } from '../../src/redaction.ts'

const hasher = new SpanHasher(Buffer.alloc(32, 7))

const execution = (name: string, args: unknown): ToolExecution =>
  ({ name, arguments: args } as unknown as ToolExecution)

describe('the canonical rendering', () => {
  it('is insensitive to key order and total over every JSON value', () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] })).toBe(canonicalJson({ a: [2, { c: 3, d: 4 }] as unknown, b: 1 }))
    expect(canonicalJson(undefined)).toBe('undefined')
    expect(canonicalJson(null)).toBe('null')
  })
})

describe('snapshot comparison', () => {
  it('names the field a listener rewrote, and the tool the log recorded', () => {
    const snapshots = new ExecutionSnapshots(hasher)
    const exec = execution('safe', { path: 'notes.txt' })
    snapshots.record(exec)

    ;(exec as { name: string }).name = 'dangerous'

    expect(snapshots.detect(exec)).toEqual({ fields: ['name'], originalTool: 'safe' })
  })

  it('sees an argument rewrite through a rebuilt object', () => {
    const snapshots = new ExecutionSnapshots(hasher)
    const exec = execution('write', { path: 'a.txt', text: 'one' })
    snapshots.record(exec)

    ;(exec as { arguments: unknown }).arguments = { text: 'two', path: 'a.txt' }

    expect(snapshots.detect(exec)).toEqual({ fields: ['arguments'], originalTool: 'write' })
  })

  it('says nothing about a call that was left alone, or one it never saw', () => {
    const snapshots = new ExecutionSnapshots(hasher)
    const untouched = execution('read', { path: 'a.txt' })
    snapshots.record(untouched)
    // Same values, rebuilt in another order: not a rewrite anyone can observe.
    ;(untouched as { arguments: unknown }).arguments = { path: 'a.txt' }

    expect(snapshots.detect(untouched)).toBeUndefined()
    expect(snapshots.detect(execution('read', { path: 'a.txt' }))).toBeUndefined()
  })
})

describe('the denial text', () => {
  it('names both tools when the name changed, and neither value ever', () => {
    const reason = mutationReason(
      execution('dangerous', { token: 'sk-secret-value' }),
      { fields: ['name', 'arguments'], originalTool: 'safe' },
    )

    expect(reason).toContain('"dangerous"')
    expect(reason).toContain('records a call to "safe"')
    expect(reason).toContain('name and arguments')
    expect(reason).not.toContain('sk-secret-value')
  })

  it('leaves the recorded tool out when only the arguments changed', () => {
    const reason = mutationReason(execution('write', {}), { fields: ['arguments'], originalTool: 'write' })

    expect(reason).not.toContain('records a call to')
  })
})
