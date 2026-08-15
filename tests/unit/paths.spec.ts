/** The two guard-floor classifications: credential paths and egress capability. */

import { describe, expect, it } from 'vitest'
import {
  isEgressCapable,
  matchCredentialPath,
  normalizeCandidatePath,
  pathCandidates,
} from '../../src/paths.ts'

describe('credential paths', () => {
  it.each([
    ['/srv/app/.env', 'dsh-dlp/path-dotenv'],
    ['/srv/app/.env.production', 'dsh-dlp/path-dotenv'],
    ['/home/dev/.ssh/config', 'dsh-dlp/path-ssh-dir'],
    ['/home/dev/keys/id_rsa', 'dsh-dlp/path-ssh-key'],
    ['/home/dev/.aws/credentials', 'dsh-dlp/path-aws'],
    ['/home/dev/.dsh/.credentials.yaml', 'dsh-dlp/path-dsh-credentials'],
    ['/home/dev/.netrc', 'dsh-dlp/path-netrc'],
    ['/home/dev/.kube/config', 'dsh-dlp/path-kubeconfig'],
    ['/home/dev/certs/server.pem', 'dsh-dlp/path-keystore'],
  ])('denies %s', (candidate, ruleId) => {
    expect(matchCredentialPath(candidate)?.id).toBe(ruleId)
  })

  it('denies a credential path reached through a traversal', () => {
    expect(matchCredentialPath('/srv/app/../../home/dev/keys/id_ed25519')?.id).toBe('dsh-dlp/path-ssh-key')
  })

  it('denies a home-relative credential path', () => {
    expect(matchCredentialPath('~/.aws/credentials')?.id).toBe('dsh-dlp/path-aws')
  })

  it('denies a Windows-style credential path', () => {
    expect(matchCredentialPath('C:\\Users\\dev\\.aws\\credentials')?.id).toBe('dsh-dlp/path-aws')
  })

  it.each([
    'src/index.ts',
    'docs/environment.md',
    '/srv/app/.env.example',
    '/srv/app/.env.sample',
    'README.md',
  ])('allows %s', (candidate) => {
    expect(matchCredentialPath(candidate)).toBeUndefined()
  })

  it('strips surrounding quotes before matching', () => {
    expect(normalizeCandidatePath('"/srv/app/.env"')).toBe('/srv/app/.env')
  })
})

describe('path candidates from one argument string', () => {
  it('offers the whole string and each shell token', () => {
    const candidates = pathCandidates('cat ~/.ssh/id_rsa && echo done')

    expect(candidates[0]).toBe('cat ~/.ssh/id_rsa && echo done')
    expect(candidates).toContain('~/.ssh/id_rsa')
  })

  it('finds a credential path a shell command would otherwise hide', () => {
    const denied = pathCandidates('cat ~/.ssh/id_rsa && echo done')
      .some(candidate => matchCredentialPath(candidate) !== undefined)

    expect(denied).toBe(true)
  })
})

describe('egress capability', () => {
  it.each(['bash', 'pwsh', 'run_code', 'web_fetch', 'web_search', 'mcp__github__create_issue', 'send_message'])(
    'treats %s as able to move data off the machine',
    (toolName) => {
      expect(isEgressCapable(toolName)).toBe(true)
    },
  )

  it.each(['read', 'glob', 'grep', 'todo_write', 'write', 'edit'])('treats %s as local', (toolName) => {
    expect(isEgressCapable(toolName)).toBe(false)
  })

  it('treats a tool it has never heard of as egress-capable', () => {
    expect(isEgressCapable('acme_publish')).toBe(true)
  })

  it('accepts an extra egress tool from the repo-local tier', () => {
    expect(isEgressCapable('read', new Set(['read']))).toBe(true)
  })
})
