/**
 * Every entry of every exported rule table, one positive and one near-miss
 * each.
 *
 * The tables are iterated from their exports rather than listed here, so a rule
 * added without a fixture fails this file instead of shipping untested: the
 * coverage gate proves a table was iterated, not that its entries match what
 * they claim to.
 */

import { describe, expect, it } from 'vitest'
import { APPROVAL_SUPPRESSION_RULES, evaluateApprovalSuppression } from '../../src/approvals.ts'
import { CONFIG_WRITE_RULES, evaluateConfigWrite, type ConfigWriteRule } from '../../src/config-writes.ts'
import { SYNC_RULES, UNICODE_RULES, scanSync, scanUnicode, type UnicodeAction } from '../../src/detectors.ts'
import {
  CREDENTIAL_PATH_RULES,
  homeCredentialPathRules,
  matchCredentialPath,
  normalizeCandidatePath,
} from '../../src/paths.ts'

/** One rule's evidence: a string it must match, and a near one it must not. */
interface Fixture {
  /** Exactly the text the rule is expected to cover, framed in prose by the test. */
  readonly match: string
  /** A neighbouring string the same rule must leave alone. */
  readonly miss: string
}

/** Every credential shape below is invented for this file and is never a live credential. */
const SYNC_FIXTURES: Readonly<Record<string, Fixture>> = {
  'dsh-dlp/aws-access-key-id': {
    match: 'AKIAIOSFODNN7EXAMPLE',
    miss: 'AKIAIOSFODNN7EXAMPL',
  },
  'dsh-dlp/aws-secret-access-key': {
    match: 'aws_secret_access_key = kL9xQ2mZ7pR4tY6wA1sD3fG5hJ8kL0nM2bV4cX6z',
    miss: 'aws_secret_access_key = kL9xQ2mZ7pR4tY6w',
  },
  'dsh-dlp/github-token': {
    match: `ghp_${'B'.repeat(36)}`,
    miss: `ghp_${'B'.repeat(20)}`,
  },
  'dsh-dlp/slack-token': {
    match: 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
    miss: 'xoxb-1234',
  },
  'dsh-dlp/stripe-secret-key': {
    match: `sk_live_${'5'.repeat(24)}`,
    miss: 'sk_test_51H8xQ2mZ7pR4tY6wA1sD3fG5',
  },
  'dsh-dlp/anthropic-api-key': {
    match: `sk-ant-api03-${'a'.repeat(24)}`,
    miss: 'sk-ant-api03-short',
  },
  'dsh-dlp/openai-api-key': {
    match: `sk-proj-${'a'.repeat(40)}`,
    miss: 'sk-proj-tooshort',
  },
  'dsh-dlp/google-api-key': {
    match: `AIza${'Sy0'.repeat(11)}xy`,
    miss: 'AIzaSyD-shortened-key',
  },
  'dsh-dlp/npm-token': {
    match: `npm_${'c'.repeat(36)}`,
    miss: `npm_${'c'.repeat(20)}`,
  },
  'dsh-dlp/gitlab-token': {
    match: 'glpat-ABCdefGHIjklMNOpqrST',
    miss: 'glpat-ABCdefGHIj',
  },
  'dsh-dlp/huggingface-token': {
    match: `hf_${'d'.repeat(34)}`,
    miss: `hf_${'d'.repeat(20)}`,
  },
  'dsh-dlp/groq-api-key': {
    match: `gsk_${'e'.repeat(52)}`,
    miss: `gsk_${'e'.repeat(20)}`,
  },
  'dsh-dlp/xai-api-key': {
    match: `xai-${'f'.repeat(80)}`,
    miss: `xai-${'f'.repeat(20)}`,
  },
  'dsh-dlp/google-oauth-client-secret': {
    match: `GOCSPX-${'g'.repeat(28)}`,
    miss: 'GOCSPX-short',
  },
  'dsh-dlp/databricks-token': {
    match: `dapi${'0123456789abcdef'.repeat(2)}`,
    miss: 'dapi0123456789abcdef',
  },
  'dsh-dlp/sendgrid-api-key': {
    match: `SG.${'h'.repeat(22)}.${'i'.repeat(43)}`,
    miss: `SG.${'h'.repeat(22)}`,
  },
  'dsh-dlp/supabase-service-key': {
    match: `sbp_${'0123456789'.repeat(4)}`,
    miss: 'sbp_0123456789',
  },
  // The shape Supabase's announcement discussion shows: a 22-character
  // base64url body, a separator, and a checksum.
  'dsh-dlp/supabase-secret-key': {
    match: `sb_secret_${'N'.repeat(30)}`,
    miss: `sb_secret_${'N'.repeat(6)}`,
  },
  // The documented scannable format: the prefix, 40 characters, and a checksum
  // whose length the provider does not publish. The near miss is the same
  // token one character short of the documented 40.
  'dsh-dlp/cloudflare-api-token': {
    match: `cfut_${'0123456789abcdefghij'.repeat(2)}Ab12Cd`,
    miss: `cfut_${'0123456789abcdefghij'.repeat(2).slice(0, 39)}`,
  },
  'dsh-dlp/openrouter-api-key': {
    match: `sk-or-v1-${'0123456789abcdef'.repeat(4)}`,
    miss: 'sk-or-v1-0123456789abcdef',
  },
  'dsh-dlp/notion-token': {
    match: `ntn_${'j'.repeat(46)}`,
    miss: `ntn_${'j'.repeat(20)}`,
  },
  'dsh-dlp/private-key-block': {
    match: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
    miss: '-----BEGIN CERTIFICATE-----\nMIIEowIBAAKCAQEA\n-----END CERTIFICATE-----',
  },
  'dsh-dlp/json-web-token': {
    match: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    miss: 'eyJhbGciOiJIUzI1NiJ9',
  },
  'dsh-dlp/credential-url': {
    match: 'postgres://admin:Sup3rS3cret@db.example.com:5432',
    miss: 'postgres://db.example.com:5432',
  },
  'dsh-dlp/slack-webhook-url': {
    match: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    miss: 'https://hooks.slack.com/services/T0',
  },
  'dsh-dlp/discord-webhook-url': {
    match: 'https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz',
    miss: 'https://discord.com/api/webhooks/123456789012345678',
  },
  'dsh-dlp/teams-webhook-url': {
    match: 'https://acme.webhook.office.com/webhookb2/00000000-1111-2222-3333-444444444444@tenant',
    miss: 'https://acme.webhook.office.com/webhookb2/short',
  },
  'dsh-dlp/secret-assignment': {
    match: 'api_key = "0123456789abcdef0123"',
    miss: 'api_key = "0123456789"',
  },
}

/**
 * Frame a fixture in prose, so a rule whose word-boundary anchors are wrong
 * fails rather than passing on a bare string.
 */
const FRAME_PREFIX = 'context before '

describe('the tier-1 rule table', () => {
  it('carries a fixture for every rule, and no fixture for a rule that is gone', () => {
    expect(Object.keys(SYNC_FIXTURES).sort()).toEqual(SYNC_RULES.map(rule => rule.id).sort())
  })

  it.each(SYNC_RULES.map(rule => [rule.id, rule] as const))('%s covers exactly what it matched', (id, rule) => {
    const fixture = SYNC_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()
    const framed = `${FRAME_PREFIX}${fixture?.match} context after`

    const { detections } = scanSync(framed, [rule])

    expect(detections).toHaveLength(1)
    expect(detections[0]).toMatchObject({ ruleId: id, ruleVersion: rule.version, severity: rule.severity })
    expect(framed.slice(detections[0]?.start, detections[0]?.end)).toBe(fixture?.match)
  })

  it.each(SYNC_RULES.map(rule => [rule.id, rule] as const))('%s abstains on its near miss', (id, rule) => {
    const fixture = SYNC_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    expect(scanSync(`${FRAME_PREFIX}${fixture?.miss} context after`, [rule]).detections).toEqual([])
  })
})

/** One invisible-character class's evidence. */
interface UnicodeFixture extends Fixture {
  /** What the scan must do with the matching run. */
  readonly action: UnicodeAction
}

const UNICODE_FIXTURES: Readonly<Record<string, UnicodeFixture>> = {
  // Tag-block encoding of "hi", the carrier for instructions only the model reads.
  'dsh-dlp/unicode-tag-characters': { match: '\u{E0068}\u{E0069}', miss: '\u{E0080}', action: 'strip' },
  // Each near miss is the code point beside the class, so a class whose range
  // grows by one fails here.
  'dsh-dlp/unicode-bidi-override': { match: '\u202E', miss: '\u202F', action: 'strip' },
  'dsh-dlp/unicode-zero-width': { match: '\u200B', miss: '\u200A', action: 'report' },
  'dsh-dlp/unicode-bidi-mark': { match: '\u200F', miss: '\u061B', action: 'report' },
  'dsh-dlp/unicode-variation-selector': { match: '\uFE0F', miss: '\uFE10', action: 'report' },
  // Four in a row is not glyph selection; three still is.
  'dsh-dlp/unicode-variation-selector-run': { match: '\uFE0F'.repeat(4), miss: '\uFE0F'.repeat(3), action: 'strip' },
  // A full CSI, not the SGR subset: parameter bytes, an intermediate byte and
  // a final byte. The near miss is the same text with no introducer.
  'dsh-dlp/control-sequence': { match: '\u001B[?25 h', miss: '[?25 h', action: 'report' },
}

describe('the invisible-character table', () => {
  it('carries a fixture for every class, and no fixture for a class that is gone', () => {
    expect(Object.keys(UNICODE_FIXTURES).sort()).toEqual(UNICODE_RULES.map(rule => rule.id).sort())
  })

  it.each(UNICODE_RULES.map(rule => [rule.id] as const))('%s reports its own class', (id) => {
    const fixture = UNICODE_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    const findings = scanUnicode(`visible${fixture?.match}text`)

    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      ruleId: id,
      action: fixture?.action,
      exact: true,
      start: 'visible'.length,
      end: 'visible'.length + (fixture?.match.length ?? 0),
    })
  })

  it.each(UNICODE_RULES.map(rule => [rule.id] as const))('%s abstains on the character beside its class', (id) => {
    const fixture = UNICODE_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    const found = scanUnicode(`visible${fixture?.miss}text`).map(finding => finding.ruleId)

    expect(found).not.toContain(id)
  })
})

const PATH_FIXTURES: Readonly<Record<string, Fixture>> = {
  'dsh-dlp/path-dotenv': { match: '/srv/app/.env', miss: '/srv/app/.env.example' },
  'dsh-dlp/path-ssh-dir': { match: '/home/dev/.ssh/config', miss: '/etc/sshd_config' },
  'dsh-dlp/path-ssh-key': { match: '/home/dev/keys/id_rsa', miss: '/home/dev/src/id_generator.ts' },
  'dsh-dlp/path-aws': { match: '/home/dev/.aws/credentials', miss: '/home/dev/docs/aws-setup.md' },
  'dsh-dlp/path-azure': { match: '/home/dev/.azure/accessTokens.json', miss: '/home/dev/azure-pipeline.yml' },
  'dsh-dlp/path-dsh-credentials': { match: '/home/dev/.dsh/.credentials.yaml', miss: '/home/dev/.dsh/profiles/dev/cordis.yml' },
  'dsh-dlp/path-netrc': { match: '/home/dev/.netrc', miss: '/home/dev/docs/netrc.md' },
  'dsh-dlp/path-npmrc': { match: '/srv/app/.npmrc', miss: '/srv/app/npmrc.example' },
  'dsh-dlp/path-pypirc': { match: '/home/dev/.pypirc', miss: '/home/dev/pypi-upload.py' },
  'dsh-dlp/path-git-credentials': { match: '/home/dev/.git-credentials', miss: '/home/dev/.gitconfig' },
  'dsh-dlp/path-gh-config': { match: '/home/dev/.config/gh/hosts.yml', miss: '/home/dev/.config/ghostty/config' },
  'dsh-dlp/path-kubeconfig': { match: '/home/dev/.kube/config', miss: '/home/dev/docs/kube-setup.md' },
  'dsh-dlp/path-kubernetes-conf': { match: '/etc/kubernetes/admin.conf', miss: '/etc/kubernetes/README.md' },
  'dsh-dlp/path-docker-config': { match: '/home/dev/.docker/config.json', miss: '/home/dev/.docker/daemon.json' },
  'dsh-dlp/path-gcloud-credentials': {
    match: '/home/dev/.config/gcloud/application_default_credentials.json',
    miss: '/home/dev/.config/gcloud/configurations/config_default',
  },
  'dsh-dlp/path-rclone-config': { match: '/home/dev/.config/rclone/rclone.conf', miss: '/home/dev/docs/rclone.md' },
  'dsh-dlp/path-pgpass': { match: '/home/dev/.pgpass', miss: '/home/dev/bin/pg_dump.sh' },
  'dsh-dlp/path-mysql-config': { match: '/home/dev/.my.cnf', miss: '/home/dev/my.cnf.example' },
  'dsh-dlp/path-service-account': { match: '/srv/app/service-account.json', miss: '/srv/app/service-registry.json' },
  'dsh-dlp/path-agent-auth': { match: '/home/dev/.codex/auth.json', miss: '/srv/app/src/auth.json' },
  'dsh-dlp/path-agent-mcp-config': { match: '/home/dev/.cursor/mcp.json', miss: '/srv/app/.mcp.json' },
  'dsh-dlp/path-editor-state-db': {
    match: '/home/dev/.config/Cursor/User/globalStorage/state.vscdb',
    miss: '/home/dev/.config/Cursor/User/globalStorage/storage.json',
  },
  'dsh-dlp/path-macos-keychain': {
    match: '/Users/dev/Library/Keychains/login.keychain-db',
    miss: '/Users/dev/Library/Preferences/com.apple.finder.plist',
  },
  'dsh-dlp/path-terraform-vars': { match: '/srv/infra/prod.tfvars', miss: '/srv/infra/main.tf' },
  'dsh-dlp/path-terraform-state': { match: '/srv/infra/terraform.tfstate', miss: '/srv/infra/terraform.tfstate.example' },
  'dsh-dlp/path-keystore': { match: '/home/dev/certs/server.pem', miss: '/home/dev/certs/server.csr' },
  'dsh-dlp/path-credential-name': { match: '/home/dev/.vault-token', miss: '/home/dev/src/auth/token.ts' },
}

describe('the credential-path table', () => {
  it('carries a fixture for every rule, and no fixture for a rule that is gone', () => {
    expect(Object.keys(PATH_FIXTURES).sort()).toEqual(CREDENTIAL_PATH_RULES.map(rule => rule.id).sort())
  })

  // The reported rule is the first one that matches, so this pins the table's
  // order as well as each pattern: a new rule shadowing an older one fails here.
  it.each(CREDENTIAL_PATH_RULES.map(rule => [rule.id] as const))('%s is what its own path reports', (id) => {
    const fixture = PATH_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    expect(matchCredentialPath(fixture?.match ?? '')?.id).toBe(id)
  })

  it.each(CREDENTIAL_PATH_RULES.map(rule => [rule.id, rule] as const))(
    '%s leaves the ordinary path beside it alone',
    (id, rule) => {
      const fixture = PATH_FIXTURES[id]
      expect(fixture, `no fixture for ${id}`).toBeDefined()

      expect(rule.pattern.test(normalizeCandidatePath(fixture?.miss ?? ''))).toBe(false)
      // Nothing else in the table may claim it either: a near miss is ordinary
      // work, and ordinary work that the floor denies is why a floor gets
      // switched off.
      expect(matchCredentialPath(fixture?.miss ?? '')).toBeUndefined()
    },
  )
})

const CONFIG_WRITE_FIXTURES: Readonly<Record<string, Fixture>> = {
  'dsh-dlp/config-agent-settings': {
    match: '/srv/repo/.claude/settings.local.json',
    miss: '/srv/repo/.claude/README.md',
  },
  'dsh-dlp/config-agent-hooks': {
    match: '/srv/repo/.claude/hooks/session-start.sh',
    miss: '/srv/repo/src/hooks/use-thing.ts',
  },
  'dsh-dlp/config-agent-instructions': { match: '/srv/repo/AGENTS.md', miss: '/srv/repo/docs/agents-guide.md' },
  'dsh-dlp/config-agent-rules': { match: '/srv/repo/.cursor/rules/setup.mdc', miss: '/srv/repo/src/rules/index.ts' },
  'dsh-dlp/config-prompt-template': {
    match: '/srv/repo/.prompts/review.prompttemplate',
    miss: '/srv/repo/.prompts/README.md',
  },
  'dsh-dlp/config-pnpm-workspace': {
    match: '/srv/repo/pnpm-workspace.yaml',
    miss: '/srv/repo/pnpm-lock.yaml',
  },
  'dsh-dlp/config-mcp-manifest': { match: '/srv/repo/.mcp.json', miss: '/srv/repo/docs/mcp.json' },
  'dsh-dlp/config-editor-tasks': { match: '/srv/repo/.vscode/tasks.json', miss: '/srv/repo/.vscode/extensions.json' },
  'dsh-dlp/config-git': { match: '/srv/repo/.git/hooks/pre-commit', miss: '/srv/repo/.gitignore' },
  'dsh-dlp/config-git-hooks-managed': { match: '/srv/repo/.husky/pre-push', miss: '/srv/repo/src/husky-setup.ts' },
  'dsh-dlp/config-ci-workflow': {
    match: '/srv/repo/.github/workflows/release.yml',
    miss: '/srv/repo/.github/ISSUE_TEMPLATE/bug.md',
  },
  'dsh-dlp/config-shell-rc': { match: '/home/dev/.zshrc', miss: '/home/dev/notes/zshrc-tips.md' },
  'dsh-dlp/config-harness-bundle': { match: '/srv/repo/cordis.patch.yml', miss: '/srv/repo/src/cordis-helpers.ts' },
  'dsh-dlp/config-api-base-url': {
    match: '"ANTHROPIC_BASE_URL": "https://collector.invalid/v1"',
    miss: 'ANTHROPIC_BASE_URL=$UPSTREAM',
  },
}

describe('the behaviour-changing config table', () => {
  /** The call one fixture describes: a write of that path, or a write of that content. */
  const call = (rule: ConfigWriteRule, text: string): Parameters<typeof evaluateConfigWrite>[0] => ({
    name: 'write',
    arguments: rule.match === 'path' ? { file_path: text } : { file_path: '/srv/repo/notes.txt', content: text },
  })

  it('carries a fixture for every rule, and no fixture for a rule that is gone', () => {
    expect(Object.keys(CONFIG_WRITE_FIXTURES).sort()).toEqual(CONFIG_WRITE_RULES.map(rule => rule.id).sort())
  })

  it.each(CONFIG_WRITE_RULES.map(rule => [rule.id, rule] as const))('%s is what its own write reports', (id, rule) => {
    const fixture = CONFIG_WRITE_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    expect(evaluateConfigWrite(call(rule, fixture?.match ?? ''))?.rule.id).toBe(id)
  })

  it.each(CONFIG_WRITE_RULES.map(rule => [rule.id, rule] as const))(
    '%s leaves the ordinary write beside it alone',
    (id, rule) => {
      const fixture = CONFIG_WRITE_FIXTURES[id]
      expect(fixture, `no fixture for ${id}`).toBeDefined()

      // Nothing else in the table may claim it either: this tier prompts a
      // human, and a tier that prompts on ordinary work gets switched off.
      expect(evaluateConfigWrite(call(rule, fixture?.miss ?? ''))).toBeUndefined()
    },
  )
})

/** One approval-suppression rule's evidence, which is an argument object rather than a string. */
interface ArgumentFixture {
  /** Arguments the rule must report. */
  readonly match: Record<string, unknown>
  /** Neighbouring arguments the same rule must leave alone. */
  readonly miss: Record<string, unknown>
}

const APPROVAL_FIXTURES: Readonly<Record<string, ArgumentFixture>> = {
  // Each near miss is the same argument set with the confirmation left in
  // place, so a rule that fires on the value asking *for* a prompt fails here.
  'dsh-dlp/approval-non-interactive': {
    match: { path: '/srv/repo/main.tf', non_interactive: true },
    miss: { path: '/srv/repo/main.tf', non_interactive: false },
  },
  'dsh-dlp/approval-mode-auto': {
    match: { approval_mode: 'auto' },
    miss: { approval_mode: 'prompt' },
  },
  // Neither half is a finding alone: `apply: true` is how most infrastructure
  // tools are driven, and a pending approval is the ordinary state of one.
  'dsh-dlp/approval-apply-pending': {
    match: { apply: true, approvalPolicy: 'pending' },
    miss: { apply: true, approvalPolicy: 'approved' },
  },
}

describe('the approval-suppression table', () => {
  it('carries a fixture for every rule, and no fixture for a rule that is gone', () => {
    expect(Object.keys(APPROVAL_FIXTURES).sort()).toEqual(APPROVAL_SUPPRESSION_RULES.map(rule => rule.id).sort())
  })

  it.each(APPROVAL_SUPPRESSION_RULES.map(rule => [rule.id] as const))('%s is what its own call reports', (id) => {
    const fixture = APPROVAL_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    expect(evaluateApprovalSuppression({ name: 'mcp__acme__deploy', arguments: fixture?.match })?.rule.id).toBe(id)
  })

  it.each(APPROVAL_SUPPRESSION_RULES.map(rule => [rule.id] as const))(
    '%s leaves the call beside it alone',
    (id) => {
      const fixture = APPROVAL_FIXTURES[id]
      expect(fixture, `no fixture for ${id}`).toBeDefined()

      // Nothing else in the table may claim it either: this tier prompts a
      // human, and a tier that prompts on ordinary work gets switched off.
      expect(evaluateApprovalSuppression({ name: 'mcp__acme__deploy', arguments: fixture?.miss })).toBeUndefined()
    },
  )
})

/** The home directory the rules under test are anchored at. */
const HOME = '/home/dev'

const HOME_PATH_FIXTURES: Readonly<Record<string, Fixture>> = {
  // Home-level agent configuration decides how every future session behaves;
  // the repository-local copy of the same file name is edited legitimately and
  // is handled by the `ask` tier instead.
  'dsh-dlp/path-agent-home-settings': {
    match: `${HOME}/.claude/settings.json`,
    miss: '/srv/repo/.claude/settings.json',
  },
}

describe('the home-anchored credential-path rules', () => {
  const rules = homeCredentialPathRules(HOME)

  it('carries a fixture for every rule, and no fixture for a rule that is gone', () => {
    expect(Object.keys(HOME_PATH_FIXTURES).sort()).toEqual(rules.map(rule => rule.id).sort())
  })

  it.each(rules.map(rule => [rule.id, rule] as const))('%s matches under the home directory only', (id, rule) => {
    const fixture = HOME_PATH_FIXTURES[id]
    expect(fixture, `no fixture for ${id}`).toBeDefined()

    expect(matchCredentialPath(fixture?.match ?? '', rules)?.id).toBe(id)
    expect(matchCredentialPath(fixture?.miss ?? '', rules)).toBeUndefined()
    // Every rule here is lifted for a tool that cannot change anything: the
    // files are ordinary reading and dangerous writing.
    expect(rule.enforcement).toBe('writes-only')
  })

  it('matches the home-relative spelling of the same path', () => {
    expect(matchCredentialPath('~/.gemini/settings.json', rules)?.id).toBe('dsh-dlp/path-agent-home-settings')
  })
})
