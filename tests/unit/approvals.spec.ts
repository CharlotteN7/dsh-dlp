/**
 * The `ask` tier's second classification: which calls switch off the
 * confirmation they would otherwise get. What the plugin does with a finding is
 * in `plugin.spec.ts`; the rule table itself is driven from its export in
 * `rule-tables.spec.ts`.
 */

import { describe, expect, it } from 'vitest'
import {
  APPROVAL_SUPPRESSION_RULES,
  evaluateApprovalSuppression,
  matchApprovalSuppression,
  normalizeArgumentToken,
} from '../../src/approvals.ts'

describe('the spelling a key or a value is matched under', () => {
  it.each(['non_interactive', 'nonInteractive', 'non-interactive', 'NON_INTERACTIVE'])(
    'reads %s as one name',
    (key) => {
      expect(normalizeArgumentToken(key)).toBe('noninteractive')
    },
  )

  it.each(['full-auto', 'full_auto', 'fullAuto', 'FULL-AUTO'])('reads %s as one value', (value) => {
    expect(normalizeArgumentToken(value)).toBe('fullauto')
  })
})

describe('an argument that turns off its own confirmation', () => {
  it.each([
    ['a boolean', true],
    ['the string a JSON-schema-free tool sends instead', 'true'],
    ['an affirmative word', 'YES'],
    ['a flag rendered as a number', 1],
  ])('reports %s', (_label, value) => {
    expect(matchApprovalSuppression({ non_interactive: value })?.id).toBe('dsh-dlp/approval-non-interactive')
  })

  it.each([
    ['the value that leaves the prompt in place', false],
    ['its string spelling', 'false'],
    ['a value naming no mode at all', 'ask'],
  ])('abstains on %s', (_label, value) => {
    expect(matchApprovalSuppression({ non_interactive: value })).toBeUndefined()
  })

  // Codex spells the mode `full-auto`, and a tool is free to send `full_auto`
  // for the same setting.
  it.each(['fullauto', 'full-auto', 'full_auto', 'FULL-AUTO', 'auto-approve', 'auto_edit'])(
    'reads %s as the mode that approves on the model\'s behalf',
    (value) => {
      expect(matchApprovalSuppression({ approval_mode: value })?.id).toBe('dsh-dlp/approval-mode-auto')
    },
  )

  it.each(['on-demand', 'ask-every-time', 'read-only'])('abstains on the mode %s, which keeps the prompt', (value) => {
    expect(matchApprovalSuppression({ approval_mode: value })).toBeUndefined()
  })

  it('is found under any depth of the arguments, because a batch nests its items', () => {
    const nested = { edits: [{ path: '/srv/repo/a' }, { path: '/srv/repo/b', approval_mode: 'auto' }] }

    expect(matchApprovalSuppression(nested)?.id).toBe('dsh-dlp/approval-mode-auto')
  })

  it('stops at the first finding, so the prompt names one thing', () => {
    const both = { non_interactive: true, approval_mode: 'never' }

    expect(matchApprovalSuppression(both)?.id).toBe('dsh-dlp/approval-non-interactive')
  })

  it('keeps the first finding when a later item of the same batch carries another', () => {
    const batch = { edits: [{ non_interactive: true }, { approval_mode: 'auto' }] }

    expect(matchApprovalSuppression(batch)?.id).toBe('dsh-dlp/approval-non-interactive')
  })

  it('says nothing about arguments carrying no object at all', () => {
    expect(matchApprovalSuppression('bare')).toBeUndefined()
    expect(matchApprovalSuppression({ cwd: null, timeout: 30, label: 'deploy' })).toBeUndefined()
  })

  it('reads a value only where it is a scalar, so a key naming an object is not a flag', () => {
    expect(matchApprovalSuppression({ apply: { mode: true }, approvalPolicy: 'pending' })).toBeUndefined()
  })
})

describe('the pair CVE-2026-53808 describes', () => {
  it('reports an apply that commits while the approval is still pending', () => {
    expect(matchApprovalSuppression({ apply: true, approvalPolicy: 'pending' })?.id)
      .toBe('dsh-dlp/approval-apply-pending')
  })

  it.each([
    ['an apply with no approval policy beside it', { apply: true }],
    ['an apply whose approval already came back', { apply: true, approvalPolicy: 'approved' }],
    ['a pending approval with nothing applying it', { approvalPolicy: 'pending' }],
  ])('abstains on %s', (_label, args) => {
    expect(matchApprovalSuppression(args)).toBeUndefined()
  })

  it('requires both halves on the same object, because two items are two requests', () => {
    const separate = { changes: [{ apply: true }, { approvalPolicy: 'pending' }] }

    expect(matchApprovalSuppression(separate)).toBeUndefined()
  })
})

describe('which calls the approval-suppression tier examines', () => {
  const suppressing = { non_interactive: true }

  it.each(['bash', 'run_code', 'acme_apply_patch', 'mcp__acme__deploy', 'write'])(
    'examines %s, because it has something to confirm',
    (tool) => {
      expect(evaluateApprovalSuppression({ name: tool, arguments: suppressing })?.rule.id)
        .toBe('dsh-dlp/approval-non-interactive')
    },
  )

  it.each(['read', 'glob', 'grep', 'lsp', 'job_output'])('leaves %s alone, because it has nothing to', (tool) => {
    expect(evaluateApprovalSuppression({ name: tool, arguments: suppressing })).toBeUndefined()
  })

  it('names the tool, the rule and what the argument does', () => {
    const finding = evaluateApprovalSuppression({ name: 'mcp__acme__deploy', arguments: suppressing })

    expect(finding?.reason).toContain('"mcp__acme__deploy"')
    expect(finding?.reason).toContain('dsh-dlp/approval-non-interactive')
    expect(finding?.reason).toContain('non-interactive flag')
  })

  it('accepts a rule table of its own', () => {
    const only = [{
      id: 'acme/unattended',
      version: 1,
      condition: { key: /^unattended$/, value: /^true$/ },
      effect: 'the deployment tool\'s unattended flag',
    }]

    expect(evaluateApprovalSuppression({ name: 'bash', arguments: suppressing }, only)).toBeUndefined()
    expect(evaluateApprovalSuppression({ name: 'bash', arguments: { unattended: true } }, only)?.rule.id)
      .toBe('acme/unattended')
  })

  it('carries a version on every rule, so an old audit record stays interpretable', () => {
    expect(APPROVAL_SUPPRESSION_RULES.every(rule => rule.version >= 1)).toBe(true)
  })
})
