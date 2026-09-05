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
  Config,
  loadRepoPolicy,
  parseRepoPolicy,
  PolicyError,
  resolvePolicy,
} from '../../src/policy.ts'
import { SYNC_RULES } from '../../src/detectors.ts'
import { resolveDshHome } from '../../src/home.ts'

const home = mkdtempSync(join(tmpdir(), 'dsh-dlp-policy-'))
afterAll(() => { rmSync(home, { recursive: true, force: true }) })

const baseConfig: Config = {
  auditLog: '/var/log/dsh-dlp.jsonl',
  redactionKeyFile: '/var/lib/dsh-dlp.key',
  aggressiveness: 'low',
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

/** The nine per-seam toggles, all on, which is what a deployment gets by default. */
const everyPassOn: Config = {
  ...baseConfig,
  breadthTier: true,
  resultRedaction: true,
  telemetryRedaction: true,
  stepContextRedaction: true,
  claimedInputRedaction: true,
  remoteImageNeutralization: true,
  redactTelemetryWorkspacePaths: true,
  configWriteAsk: true,
  approvalSuppressionAsk: true,
}

/**
 * Validate a `cordis.yml` row the way the loader does. The row is parsed YAML
 * rather than a typed object, which is exactly what the schema is for, and the
 * schema's declared input type is the validated shape it produces.
 * @param row - the deployment's configuration row before validation.
 * @returns the validated configuration.
 */
function validate(row: Record<string, unknown>): Config {
  return Config(row as unknown as Config)
}

describe('the aggressiveness level', () => {
  it('defaults to medium, which is what the shipped toggle defaults already describe', () => {
    const validated = validate({ auditLog: '/var/log/a.jsonl', redactionKeyFile: '/var/lib/k' })

    expect(validated.aggressiveness).toBe('medium')
    expect(resolvePolicy(validated).userTypedInputRedaction).toBe(false)
    expect(resolvePolicy(validated).telemetryRedaction).toBe(true)
  })

  it('rejects a word that is not one of the three levels', () => {
    expect(() => validate({ auditLog: '/a', redactionKeyFile: '/k', aggressiveness: 'paranoid' }))
      .toThrow(/aggressiveness/)
  })

  it('puts the user\'s own typed prompt in scope at high, and at no other level', () => {
    expect(resolvePolicy({ ...everyPassOn, aggressiveness: 'high' }).userTypedInputRedaction).toBe(true)
    expect(resolvePolicy({ ...everyPassOn, aggressiveness: 'medium' }).userTypedInputRedaction).toBe(false)
    expect(resolvePolicy({ ...baseConfig, aggressiveness: 'low' }).userTypedInputRedaction).toBe(false)
  })

  it('reports the level the seams resolved under', () => {
    expect(resolvePolicy({ ...everyPassOn, aggressiveness: 'high' }).aggressiveness).toBe('high')
  })

  it('refuses to load when a toggle contradicts the level, naming both', () => {
    // Two deployment-controlled settings describing different plugins. Either
    // one losing quietly leaves an operator believing a pass runs that does
    // not, or the reverse.
    expect(() => resolvePolicy({ ...everyPassOn, aggressiveness: 'medium', telemetryRedaction: false }))
      .toThrow(/telemetryRedaction is set to false/)
    expect(() => resolvePolicy({ ...everyPassOn, aggressiveness: 'high', breadthTier: false }))
      .toThrow(/aggressiveness: high/)
  })

  it('names every contradicting toggle at once, so the fix takes one pass', () => {
    expect(() => resolvePolicy({
      ...everyPassOn,
      aggressiveness: 'medium',
      breadthTier: false,
      configWriteAsk: false,
    })).toThrow(/breadthTier, configWriteAsk are set to false/)
  })

  it('is the level a deployment moves to when it needs a pass off', () => {
    // Every configuration that was legal before the level existed is still
    // legal at low, which is what keeps an upgrade from rewriting behaviour.
    const resolved = resolvePolicy({ ...baseConfig, aggressiveness: 'low' })

    expect(resolved.breadthTier).toBe(false)
    expect(resolved.resultRedaction).toBe(false)
  })

  it('cannot be raised by a repo-local policy, which has no key for it', () => {
    // The level's own lever is redacting what the user typed. A workspace that
    // could force it could garble the user's words on the way to the model.
    expect(() => parseRepoPolicy('v: 1\naggressiveness: high\n')).toThrow(/unknown keys: aggressiveness/)
    expect(() => parseRepoPolicy('v: 1\nenable: [userTypedInputRedaction]\n')).toThrow(/unknown toggle/)
  })
})
