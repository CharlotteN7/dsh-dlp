/** The two guard-floor classifications: credential paths and egress capability. */

import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  isEgressCapable,
  isReadOnlyTool,
  matchCredentialPath,
  matchPathArgument,
  normalizeCandidatePath,
  pathArguments,
  pathCandidates,
  resolveCandidatePath,
  rulesForTool,
  type CredentialPathRule,
} from '../../src/paths.ts'

const home = mkdtempSync(join(tmpdir(), 'dsh-dlp-paths-'))
afterAll(() => { rmSync(home, { recursive: true, force: true }) })

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

  // Every entry here was reachable through the guard floor before the table
  // was extended: each names a real credential store for a shipped tool.
  it.each([
    ['/home/dev/.git-credentials', 'dsh-dlp/path-git-credentials'],
    ['/home/dev/.config/gh/hosts.yml', 'dsh-dlp/path-gh-config'],
    ['/home/dev/kubeconfig', 'dsh-dlp/path-kubeconfig'],
    ['/etc/kubernetes/admin.conf', 'dsh-dlp/path-kubernetes-conf'],
    ['/home/dev/credentials.json', 'dsh-dlp/path-credential-name'],
    ['/home/dev/service-account.json', 'dsh-dlp/path-service-account'],
    ['/home/dev/.pgpass', 'dsh-dlp/path-pgpass'],
    ['/home/dev/.my.cnf', 'dsh-dlp/path-mysql-config'],
    ['/home/dev/secrets/tls.key', 'dsh-dlp/path-keystore'],
    ['/home/dev/.gem/credentials', 'dsh-dlp/path-credential-name'],
    ['/home/dev/.cargo/credentials.toml', 'dsh-dlp/path-credential-name'],
    ['/home/dev/.terraform.d/credentials.tfrc.json', 'dsh-dlp/path-credential-name'],
    ['/home/dev/.config/rclone/rclone.conf', 'dsh-dlp/path-rclone-config'],
    ['/home/dev/.azure/accessTokens.json', 'dsh-dlp/path-azure'],
    ['/home/dev/.aws/sso/cache/abc.json', 'dsh-dlp/path-aws'],
    ['/home/dev/id_rsa.bak', 'dsh-dlp/path-ssh-key'],
    ['/home/dev/.ssh_backup/id_rsa_old', 'dsh-dlp/path-ssh-dir'],
    ['/var/run/secrets/kubernetes.io/serviceaccount/token', 'dsh-dlp/path-credential-name'],
    ['/home/dev/.docker/.dockercfg', 'dsh-dlp/path-docker-config'],
    ['/home/dev/.vault-token', 'dsh-dlp/path-credential-name'],
  ])('denies %s', (candidate, ruleId) => {
    expect(matchCredentialPath(candidate)?.id).toBe(ruleId)
  })

  // An MCP manifest carries each server's `env`, so it is credential material
  // under every agent directory the sibling `auth.json` rule already names,
  // including the two the manifest rule left out and Cursor's no-dot spelling.
  it.each([
    '/home/dev/.cursor/mcp.json',
    '/home/dev/.composer/mcp.json',
    '/home/dev/.aider/mcp.json',
    '/home/dev/.config/Cursor/mcp.json',
  ])('denies %s', (candidate) => {
    expect(matchCredentialPath(candidate)?.id).toBe('dsh-dlp/path-agent-mcp-config')
  })

  // `~/.aws/` and `~/.azure/` match at any depth and `~/.kube/` did not, so a
  // cached credential one directory deeper was reachable.
  it.each(['/home/dev/.kube/config', '/home/dev/.kube/cache/oidc-login/abc', '/home/dev/.kube'])(
    'denies %s',
    (candidate) => {
      expect(matchCredentialPath(candidate)?.id).toBe('dsh-dlp/path-kubeconfig')
    },
  )

  it.each([
    ['a trailing slash', '/home/dev/.env/'],
    ['a renamed ssh directory', '/home/dev/.ssh_x/id_rsa2'],
    ['a suffix directory', '/home/dev/.env.d/prod'],
  ])('denies a path shape that %s hides', (_label, candidate) => {
    expect(matchCredentialPath(candidate)).toBeDefined()
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
    // The filename heuristic must not swallow ordinary source files, or every
    // repository with an auth module becomes unworkable.
    'src/auth/token.ts',
    'src/auth/tokenizer.py',
    'packages/core/src/secrets.test.ts',
    'docs/secrets.md',
  ])('allows %s', (candidate) => {
    expect(matchCredentialPath(candidate)).toBeUndefined()
  })

  it('strips surrounding quotes before matching', () => {
    expect(normalizeCandidatePath('"/srv/app/.env"')).toBe('/srv/app/.env')
  })

  it('leaves the filesystem root alone', () => {
    expect(normalizeCandidatePath('/')).toBe('/')
  })
})

describe('a symlink pointing at credential material', () => {
  it('is denied under the name it resolves to, not the name it was given', () => {
    mkdirSync(join(home, '.ssh'), { recursive: true })
    writeFileSync(join(home, '.ssh', 'id_rsa'), 'PRIVATE-KEY-BODY\n', { mode: 0o600 })
    symlinkSync(join(home, '.ssh', 'id_rsa'), join(home, 'notes.txt'))

    expect(matchCredentialPath(join(home, 'notes.txt'))).toBeUndefined()
    expect(matchPathArgument(join(home, 'notes.txt'))?.id).toBe('dsh-dlp/path-ssh-dir')
  })

  it('is matched by its own name before the filesystem is consulted', () => {
    expect(matchPathArgument('/srv/app/.env')?.id).toBe('dsh-dlp/path-dotenv')
  })

  it('falls back to the literal spelling when the path does not resolve', () => {
    expect(resolveCandidatePath(join(home, 'no-such-file'))).toBeUndefined()
    expect(matchPathArgument(join(home, 'no-such-file'))).toBeUndefined()
  })
})

describe('path candidates from one shell command', () => {
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

describe('which arguments are tested as paths', () => {
  it('takes the path-typed keys and labels a command line as a shell string', () => {
    expect(pathArguments({ file_path: '/a/b', command: 'ls /c' })).toEqual([
      { text: '/a/b', shell: false },
      { text: 'ls /c', shell: true },
    ])
  })

  it('ignores file content, replacement text and search patterns', () => {
    const args = {
      file_path: '/srv/app/.gitignore',
      content: 'node_modules/\n.env\n',
      new_string: 'cp ~/.ssh/id_rsa /tmp',
      pattern: 'id_rsa',
    }

    expect(pathArguments(args)).toEqual([{ text: '/srv/app/.gitignore', shell: false }])
  })

  it('finds a path-typed key nested inside a structured argument', () => {
    expect(pathArguments({ edits: [{ file_path: '/a' }, { file_path: '/b' }] }))
      .toEqual([{ text: '/a', shell: false }, { text: '/b', shell: false }])
  })

  it('collects every string under a path-typed key', () => {
    expect(pathArguments({ paths: ['/a', { nested: '/b' }, 7] }))
      .toEqual([{ text: '/a', shell: false }, { text: '/b', shell: false }])
  })

  it('says nothing about arguments that are not an object', () => {
    expect(pathArguments('bare')).toEqual([])
    expect(pathArguments([{ path: '/a' }])).toEqual([{ text: '/a', shell: false }])
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

describe('which rules one tool is judged against', () => {
  const always: CredentialPathRule = { id: 'test/always', version: 1, pattern: /always/ }
  const writes: CredentialPathRule = { id: 'test/writes', version: 1, enforcement: 'writes-only', pattern: /writes/ }
  const table = [always, writes]

  it.each(['read', 'glob', 'grep', 'lsp', 'session_search', 'job_output'])('treats %s as read-only', (toolName) => {
    expect(isReadOnlyTool(toolName)).toBe(true)
    expect(rulesForTool(toolName, table)).toEqual([always])
  })

  it.each(['write', 'edit', 'bash', 'pwsh', 'run_code', 'mcp__github__create_issue'])(
    'keeps every rule for %s',
    (toolName) => {
      expect(isReadOnlyTool(toolName)).toBe(false)
      expect(rulesForTool(toolName, table)).toEqual(table)
    },
  )

  it('keeps every rule for a tool it has never heard of', () => {
    // A new tool must be classified before it is trusted with a read.
    expect(rulesForTool('acme_inspect', table)).toEqual(table)
  })
})
