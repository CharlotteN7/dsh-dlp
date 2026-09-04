/**
 * The tighten-only rule for the lowest-trust configuration source. A
 * repo-local policy file is attacker-controlled: a hostile repository ships
 * one, and a prompt-injected agent can write one.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import {
  loadRepoPolicy,
  parseRepoPolicy,
  PolicyError,
  resolvePolicy,
  type Config,
} from '../../src/policy.ts'
import { SYNC_RULES } from '../../src/detectors.ts'
import { resolveDshHome } from '../../src/home.ts'

const home = mkdtempSync(join(tmpdir(), 'dsh-dlp-policy-'))
afterAll(() => { rmSync(home, { recursive: true, force: true }) })

const baseConfig: Config = {
  auditLog: '/var/log/dsh-dlp.jsonl',
  redactionKeyFile: '/var/lib/dsh-dlp.key',
  maxScanBytes: 1024,
  breadthTier: false,
  resultRedaction: false,
  telemetryRedaction: false,
  stepContextRedaction: false,
  claimedInputRedaction: false,
  remoteImageNeutralization: false,
  redactTelemetryWorkspacePaths: false,
  configWriteAsk: false,
  approvalSuppressionAsk: false,
}

describe('a repo-local policy that tightens', () => {
  it('adds a credential-path pattern', () => {
    const policy = parseRepoPolicy([
      'v: 1',
      'addCredentialPaths:',
      '  - id: acme/vault-token',
      "    pattern: '(^|/)\\.vault-token$'",
    ].join('\n'))

    expect(policy.addCredentialPaths[0]?.id).toBe('acme/vault-token')
    expect(policy.addCredentialPaths[0]?.pattern.test('/home/dev/.vault-token')).toBe(true)
  })

  it('adds an egress-capable tool', () => {
    expect(parseRepoPolicy('v: 1\naddEgressTools: [acme_publish]\n').addEgressTools).toEqual(['acme_publish'])
  })

  it('raises a rule severity', () => {
    const policy = parseRepoPolicy('v: 1\nraiseSeverity:\n  dsh-dlp/secret-assignment: high\n')

    expect(policy.raiseSeverity.get('dsh-dlp/secret-assignment')).toBe('high')
  })

  it('switches a redaction pass on', () => {
    expect(parseRepoPolicy('v: 1\nenable: [resultRedaction]\n').enable).toEqual(['resultRedaction'])
  })
})

describe('a repo-local policy that would loosen', () => {
  it('is rejected for lowering a severity', () => {
    expect(() => parseRepoPolicy('v: 1\nraiseSeverity:\n  dsh-dlp/slack-token: low\n'))
      .toThrow(/may only tighten/)
  })

  it('is rejected for naming a rule that does not exist', () => {
    expect(() => parseRepoPolicy('v: 1\nraiseSeverity:\n  acme/invented: high\n'))
      .toThrow(/unknown rule/)
  })

  it('is rejected for trying to disable a detector', () => {
    expect(() => parseRepoPolicy('v: 1\ndisable: [resultRedaction]\n')).toThrow(/unknown keys: disable/)
  })

  it('is rejected for trying to remove a credential path', () => {
    expect(() => parseRepoPolicy('v: 1\nremoveCredentialPaths: [dsh-dlp/path-dotenv]\n'))
      .toThrow(/unknown keys: removeCredentialPaths/)
  })

  it('is rejected for trying to redirect the audit sink', () => {
    expect(() => parseRepoPolicy('v: 1\nauditLog: /tmp/elsewhere.jsonl\n')).toThrow(/unknown keys: auditLog/)
  })

  it('is rejected for naming an unknown toggle', () => {
    expect(() => parseRepoPolicy('v: 1\nenable: [somethingElse]\n')).toThrow(/unknown toggle/)
  })
})

describe('a malformed repo-local policy', () => {
  it('fails to parse a !!js tag rather than executing it', () => {
    expect(() => parseRepoPolicy("v: 1\naddEgressTools: !!js/function 'function(){return 1}'\n"))
      .toThrow(PolicyError)
  })

  it('rejects a document that is not a mapping', () => {
    expect(() => parseRepoPolicy('- one\n- two\n')).toThrow(/must be a mapping/)
  })

  it('rejects a payload version it does not know', () => {
    expect(() => parseRepoPolicy('v: 99\n')).toThrow(/v must be 1/)
  })

  it('rejects a non-list addCredentialPaths', () => {
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths: nope\n')).toThrow(/must be a list/)
  })

  it('rejects a credential-path entry with an unknown key', () => {
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths:\n  - id: a\n    pattern: b\n    allow: true\n'))
      .toThrow(/unknown keys: allow/)
  })

  it('rejects a credential-path entry missing its id', () => {
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths:\n  - pattern: x\n')).toThrow(/id must be/)
  })

  it('rejects a credential-path entry whose id carries a terminal control sequence', () => {
    // The id is quoted verbatim in the denial the user reads and in every
    // audit record the rule produces, and this file is attacker-controlled.
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths:\n  - id: "acme/\\u001B[2Kok"\n    pattern: x\n'))
      .toThrow(/terminal control sequence/)
  })

  it('rejects a credential-path entry missing its pattern', () => {
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths:\n  - id: x\n')).toThrow(/pattern must be/)
  })

  it('rejects a credential-path entry whose pattern will not compile', () => {
    expect(() => parseRepoPolicy('v: 1\naddCredentialPaths:\n  - id: x\n    pattern: "([unclosed"\n'))
      .toThrow(/not a valid regular expression/)
  })

  it('rejects a non-list addEgressTools', () => {
    expect(() => parseRepoPolicy('v: 1\naddEgressTools: 7\n')).toThrow(/list of strings/)
  })

  it('rejects a severity value outside the ordering', () => {
    expect(() => parseRepoPolicy('v: 1\nraiseSeverity:\n  dsh-dlp/slack-token: extreme\n'))
      .toThrow(/one of low, medium, high, critical/)
  })

  it('rejects a raiseSeverity that is not a mapping', () => {
    expect(() => parseRepoPolicy('v: 1\nraiseSeverity: [a]\n')).toThrow(/must be a mapping/)
  })
})

describe('a repo-local policy that would stall the agent', () => {
  it('is rejected for nesting a quantifier inside a quantified group', () => {
    // `^(a+)+$` against 27 characters blocks the synchronous guard for
    // seconds, which is a denial-of-service any workspace could ship.
    expect(() => parseRepoPolicy("v: 1\naddCredentialPaths:\n  - id: acme/evil\n    pattern: '^(a+)+$'\n"))
      .toThrow(/exponential time/)
  })

  it('is rejected for a pattern longer than a credential path needs', () => {
    const pattern = `(^|/)${'a'.repeat(220)}$`

    expect(() => parseRepoPolicy(`v: 1\naddCredentialPaths:\n  - id: acme/long\n    pattern: '${pattern}'\n`))
      .toThrow(/at most 200 are allowed/)
  })

  it('still accepts an ordinary anchored path pattern', () => {
    const policy = parseRepoPolicy("v: 1\naddCredentialPaths:\n  - id: acme/x\n    pattern: '(^|/)acme-deploy\\.dat$'\n")

    expect(policy.addCredentialPaths[0]?.pattern.test('/srv/acme-deploy.dat')).toBe(true)
  })
})

describe('loading from disk', () => {
  it('reads and validates a file', () => {
    const file = join(home, 'ok.yml')
    writeFileSync(file, 'v: 1\naddEgressTools: [acme_publish]\n')

    const load = loadRepoPolicy(file)

    expect(load).toMatchObject({ kind: 'loaded' })
    expect(load.kind === 'loaded' && load.policy.addEgressTools).toEqual(['acme_publish'])
  })

  it('reports absence rather than failing, because most workspaces ship no policy', () => {
    expect(loadRepoPolicy(join(home, 'absent.yml'))).toEqual({ kind: 'absent' })
  })

  it('reports a malformed file rather than obeying part of it', () => {
    const file = join(home, 'broken.yml')
    writeFileSync(file, 'v: 1\nunknownKey: [oops]\n')

    const load = loadRepoPolicy(file)

    expect(load.kind).toBe('invalid')
    expect(load.kind === 'invalid' && load.problem).toContain('unknown keys')
  })

  it('reports a path it cannot read for a reason other than absence', () => {
    const load = loadRepoPolicy(home)

    expect(load.kind).toBe('invalid')
    expect(load.kind === 'invalid' && load.problem).toContain('cannot read')
  })
})

describe('the merged policy', () => {
  it('keeps the deployment values when no repo-local policy is mounted', () => {
    const resolved = resolvePolicy(baseConfig)

    expect(resolved.breadthTier).toBe(false)
    expect(resolved.extraEgressTools.size).toBe(0)
    expect(resolved.syncRules).toEqual(SYNC_RULES)
  })

  it('appends repo-local deny patterns after the built-in table', () => {
    const repo = parseRepoPolicy("v: 1\naddCredentialPaths:\n  - id: acme/x\n    pattern: 'acme-deploy\\.dat$'\n")
    const resolved = resolvePolicy(baseConfig, repo)

    expect(resolved.credentialPathRules.at(-1)?.id).toBe('acme/x')
    expect(resolved.credentialPathRules.length).toBeGreaterThan(1)
  })

  it('defends this plugin\'s own key, its sink, and the harness home', () => {
    const resolved = resolvePolicy({
      ...baseConfig,
      auditLog: '/var/log/dsh-dlp.jsonl',
      redactionKeyFile: '/var/lib/dsh-dlp.redaction-key',
    })
    const rules = (candidate: string): string | undefined =>
      resolved.credentialPathRules.find(rule => rule.pattern.test(candidate))?.id

    expect(rules('/var/lib/dsh-dlp.redaction-key')).toBe('dsh-dlp/path-own-redaction-key')
    expect(rules('/var/log/dsh-dlp.jsonl')).toBe('dsh-dlp/path-own-audit-log')
    expect(rules(join(resolveDshHome(), 'profiles', 'default', 'package.json'))).toBe('dsh-dlp/path-dsh-home')
    expect(rules(resolveDshHome())).toBe('dsh-dlp/path-dsh-home')
  })

  it('follows $DSH_HOME when the deployment sets one', () => {
    expect(resolveDshHome({ DSH_HOME: '/srv/harness-home' })).toBe('/srv/harness-home')
    expect(resolveDshHome({ DSH_HOME: '   ' })).toBe(resolveDshHome({}))
  })

  it('lets a repo-local policy switch a pass on but never off', () => {
    const repo = parseRepoPolicy('v: 1\nenable: [telemetryRedaction]\n')
    const resolved = resolvePolicy({ ...baseConfig, resultRedaction: true }, repo)

    expect(resolved.telemetryRedaction).toBe(true)
    expect(resolved.resultRedaction).toBe(true)
  })

  it('applies a raised severity to the rule table the seams read', () => {
    const repo = parseRepoPolicy('v: 1\nraiseSeverity:\n  dsh-dlp/secret-assignment: critical\n')
    const resolved = resolvePolicy(baseConfig, repo)

    expect(resolved.syncRules.find(rule => rule.id === 'dsh-dlp/secret-assignment')?.severity).toBe('critical')
  })
})
