/**
 * The `ask` tier's classification: which calls are behaviour-changing writes.
 * What the plugin does with a finding is in `plugin.spec.ts`; the rule table
 * itself is driven from its export in `rule-tables.spec.ts`.
 */

import { describe, expect, it } from 'vitest'
import { contentArguments, evaluateConfigWrite } from '../../src/config-writes.ts'

describe('the strings a call would write', () => {
  it('takes the content-typed keys and nothing else', () => {
    expect(contentArguments({ file_path: '/srv/repo/a.md', content: 'hello', pattern: 'ignored' }))
      .toEqual(['hello'])
  })

  it('finds a content-typed key nested in a list of edits', () => {
    expect(contentArguments({ edits: [{ new_string: 'first' }, { new_string: 'second' }] }))
      .toEqual(['first', 'second'])
  })

  it('collects every string under one content-typed key', () => {
    expect(contentArguments({ content: ['a', { nested: 'b' }, 7] })).toEqual(['a', 'b'])
  })

  it('says nothing about arguments that are not an object', () => {
    expect(contentArguments('bare')).toEqual([])
    expect(contentArguments([{ content: 'a' }])).toEqual(['a'])
  })
})

describe('which calls the ask tier examines', () => {
  const workflow = { file_path: '/srv/repo/.github/workflows/ci.yml' }

  it.each(['write', 'edit', 'str_replace_editor', 'acme_apply_patch', 'mcp__github__push_files'])(
    'examines %s, because it can change something',
    (tool) => {
      expect(evaluateConfigWrite({ name: tool, arguments: workflow })?.rule.id).toBe('dsh-dlp/config-ci-workflow')
    },
  )

  it.each(['read', 'glob', 'grep', 'lsp', 'job_output'])('leaves %s alone, because it cannot', (tool) => {
    expect(evaluateConfigWrite({ name: tool, arguments: workflow })).toBeUndefined()
  })

  it('normalises the path first, so a Windows spelling reaches the same rule', () => {
    expect(evaluateConfigWrite({ name: 'write', arguments: { file_path: String.raw`C:\repo\.husky\pre-push` } })?.rule.id)
      .toBe('dsh-dlp/config-git-hooks-managed')
  })

  it('reports the first rule that matches, so the prompt names one thing', () => {
    const finding = evaluateConfigWrite({
      name: 'write',
      arguments: { file_path: '/srv/repo/.claude/settings.json', content: 'OPENAI_API_BASE: https://collector.invalid' },
    })

    expect(finding?.rule.id).toBe('dsh-dlp/config-agent-settings')
  })

  // Three of the four were covered and `.claude/rules` was not, which VS Code
  // lists as a workspace instruction location it detects and applies on its own.
  it.each([
    '/srv/repo/.claude/rules/a.md',
    '/srv/repo/.cursor/rules/a.mdc',
    '/srv/repo/.windsurf/rules/a.md',
    '/srv/repo/.continue/rules/a.md',
  ])('asks before a write to %s', (file_path) => {
    expect(evaluateConfigWrite({ name: 'write', arguments: { file_path } })?.rule.id)
      .toBe('dsh-dlp/config-agent-rules')
  })

  it('asks before a prompt template nested under the prompts directory', () => {
    expect(evaluateConfigWrite({ name: 'write', arguments: { file_path: '/srv/repo/.prompts/team/review.prompttemplate' } })
      ?.rule.id).toBe('dsh-dlp/config-prompt-template')
  })

  it.each(['/srv/repo/pnpm-workspace.yaml', '/srv/repo/pnpm-workspace.yml'])(
    'asks before %s, which decides the registry the next install downloads from',
    (file_path) => {
      expect(evaluateConfigWrite({ name: 'write', arguments: { file_path } })?.rule.id)
        .toBe('dsh-dlp/config-pnpm-workspace')
    },
  )

  it('accepts a rule table of its own', () => {
    const only = [{
      id: 'acme/deploy-script',
      version: 1,
      match: 'path' as const,
      pattern: /(^|\/)deploy\.sh$/i,
      effect: 'the deployment script',
    }]

    expect(evaluateConfigWrite({ name: 'write', arguments: workflow }, only)).toBeUndefined()
    expect(evaluateConfigWrite({ name: 'write', arguments: { file_path: '/srv/repo/deploy.sh' } }, only)?.rule.id)
      .toBe('acme/deploy-script')
  })
})
