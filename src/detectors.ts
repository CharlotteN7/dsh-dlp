/**
 * Two detection tiers and the vocabulary they share.
 *
 * Tier 1 is a synchronous table of prefix-anchored token formats, owned here
 * because two of the three seams this plugin uses are synchronous:
 * `ToolGuard` returns `string | undefined` and the `session-telemetry/record`
 * waterfall returns a record, neither of which can await. Tier 2 wraps
 * `@secretlint/core`, which runs in-process with no subprocess but resolves a
 * promise, so it is reachable only from `tools/pre-execute` and
 * `tools/post-execute`.
 *
 * Neither tier ever returns the matched text. A {@link Detection} carries
 * offsets; turning offsets into a keyed hash is `redaction.ts`'s job.
 * @module dsh-dlp/detectors
 */

import { lintSource } from '@secretlint/core'
import { creator as recommendedPreset } from '@secretlint/secretlint-rule-preset-recommend'

/**
 * How badly a match should be treated. Ordered: {@link severityRank} compares
 * two values, and the repo-local policy tier may only move a rule upward.
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical'

/** Order two detections by position, so a caller can splice them left to right. */
function byPosition(left: Detection, right: Detection): number {
  return left.start - right.start || left.end - right.end
}

/** Ascending comparison order for {@link Severity}. */
const SEVERITY_ORDER: readonly Severity[] = ['low', 'medium', 'high', 'critical']

/**
 * Position of a severity in the ordering.
 * @param severity - the value to rank.
 * @returns its index in the ascending order; higher means stricter.
 */
export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity)
}

/** Severity at or above which the guard floor denies rather than only redacting. */
export const DENY_SEVERITY: Severity = 'high'

/** One match, described without disclosing what matched. */
export interface Detection {
  /** Rule identity, stable across versions of this package. */
  readonly ruleId: string
  /** Bumped whenever the rule's pattern changes, so an old audit record stays interpretable. */
  readonly ruleVersion: number
  readonly severity: Severity
  /** Inclusive start offset into the scanned string. */
  readonly start: number
  /** Exclusive end offset into the scanned string. */
  readonly end: number
}

/** Outcome of one scan. */
export interface ScanResult {
  readonly detections: readonly Detection[]
  /** Whether tier 2 saw only part of the input because of the byte cap. */
  readonly truncated: boolean
}

/** One synchronous rule in tier 1. */
export interface SyncRule {
  readonly id: string
  readonly version: number
  readonly severity: Severity
  /** Global-flagged; matched through `matchAll`, which never mutates this instance's `lastIndex`. */
  readonly pattern: RegExp
}

/**
 * Tier 1's rule table. Deliberately narrow: only formats whose prefix or
 * delimiters make a match structurally unambiguous, plus PEM blocks and
 * credential-bearing URLs. Anything requiring entropy heuristics is left to
 * tier 2, where a false positive costs a redaction rather than a denial.
 */
export const SYNC_RULES: readonly SyncRule[] = [
  { id: 'dsh-dlp/aws-access-key-id', version: 1, severity: 'critical', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { id: 'dsh-dlp/aws-secret-access-key', version: 1, severity: 'critical', pattern: /\baws_secret_access_key\b\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi },
  { id: 'dsh-dlp/github-token', version: 1, severity: 'critical', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,251})\b/g },
  { id: 'dsh-dlp/slack-token', version: 1, severity: 'critical', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { id: 'dsh-dlp/stripe-secret-key', version: 1, severity: 'critical', pattern: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g },
  { id: 'dsh-dlp/anthropic-api-key', version: 1, severity: 'critical', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: 'dsh-dlp/openai-api-key', version: 1, severity: 'critical', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g },
  { id: 'dsh-dlp/google-api-key', version: 1, severity: 'critical', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'dsh-dlp/npm-token', version: 1, severity: 'critical', pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'dsh-dlp/private-key-block', version: 1, severity: 'critical', pattern: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/g },
  { id: 'dsh-dlp/json-web-token', version: 1, severity: 'high', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: 'dsh-dlp/credential-url', version: 1, severity: 'high', pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s/@]+@[^\s/]+/gi },
  // Webhook URLs are bearer credentials whose path segment is the secret. They
  // are in tier 1 rather than left to secretlint because the telemetry seam is
  // synchronous and cannot reach tier 2 at all.
  { id: 'dsh-dlp/slack-webhook-url', version: 1, severity: 'critical', pattern: /\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_+-]{10,}/g },
  { id: 'dsh-dlp/discord-webhook-url', version: 1, severity: 'critical', pattern: /\bhttps:\/\/(?:\w+\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]{10,}/g },
  { id: 'dsh-dlp/teams-webhook-url', version: 1, severity: 'critical', pattern: /\bhttps:\/\/[A-Za-z0-9.-]*webhook\.office\.com\/webhookb2\/[A-Za-z0-9@/_-]{10,}/g },
  { id: 'dsh-dlp/secret-assignment', version: 1, severity: 'medium', pattern: /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[=:]\s*["']?[A-Za-z0-9/+=_-]{16,}["']?/gi },
] as const

/**
 * Scan text with tier 1. Pure, synchronous, no I/O, and never capped: a table
 * of anchored regular expressions costs a linear pass, so there is no reason
 * to stop scanning where tier 2 has to. `truncated` is therefore always
 * `false` here and only tier 2 can set it.
 * @param text - the string to scan.
 * @param rules - the rule table to apply; defaults to {@link SYNC_RULES}.
 * @returns every match, ordered by start offset.
 */
export function scanSync(
  text: string,
  rules: readonly SyncRule[] = SYNC_RULES,
): ScanResult {
  const detections: Detection[] = []
  for (const rule of rules) {
    for (const match of text.matchAll(rule.pattern)) {
      // `matchAll` on a global pattern always reports an index.
      const start = match.index
      detections.push({
        ruleId: rule.id,
        ruleVersion: rule.version,
        severity: rule.severity,
        start,
        end: start + match[0].length,
      })
    }
  }
  detections.sort(byPosition)
  return { detections, truncated: false }
}

/**
 * Major version of the pinned `@secretlint/core` rule set, recorded as the
 * rule version of every tier-2 detection. The exact dependency version is
 * pinned in this package's manifest; the major is what changes a rule's
 * meaning.
 */
export const SECRETLINT_RULE_VERSION = 13

/** Config passed to every `lintSource` call; the preset registers its own child rules. */
const SECRETLINT_CONFIG = {
  rules: [{ id: recommendedPreset.meta.id, rule: recommendedPreset }],
}

/** Map secretlint's message severity onto this plugin's ordering. */
function mapSecretlintSeverity(severity: string): Severity {
  /* v8 ignore next -- the recommended preset reports only `error`; the other arms serve rules a deployment adds. */
  return severity === 'error' ? 'high' : severity === 'warning' ? 'medium' : 'low'
}

/**
 * Scan text with tier 2 (`@secretlint/core`, recommended preset). Runs
 * in-process; no subprocess and no network.
 *
 * The reported spans are advisory. `@secretlint/secretlint-rule-aws` reports
 * `[0, 40]` for `aws_secret_access_key = <40 chars>`, which covers the
 * assignment prefix rather than the whole secret, so a caller must never
 * splice a reported span directly — {@link redactText} expands every span to
 * whitespace boundaries first.
 * @param text - the string to scan.
 * @param maxScanBytes - cap on scanned characters; input beyond it is not examined.
 * @returns every match, ordered by start offset, and whether the input was capped.
 */
export async function scanWithSecretlint(
  text: string,
  maxScanBytes = Number.POSITIVE_INFINITY,
): Promise<ScanResult> {
  const truncated = text.length > maxScanBytes
  const window = truncated ? text.slice(0, maxScanBytes) : text
  const result = await lintSource({
    source: { filePath: '/dsh-dlp/scan.txt', content: window, ext: '.txt', contentType: 'text' },
    options: { config: SECRETLINT_CONFIG, noPhysicFilePath: true },
  })
  const detections = result.messages.map((message): Detection => ({
    ruleId: message.ruleId,
    ruleVersion: SECRETLINT_RULE_VERSION,
    severity: mapSecretlintSeverity(message.severity),
    start: message.range[0],
    end: message.range[1],
  }))
  detections.sort(byPosition)
  return { detections, truncated }
}

/**
 * Run both tiers over one string and merge their detections. Tier 1 sees the
 * whole string; only tier 2 is capped.
 * @param text - the string to scan.
 * @param rules - tier-1 rule table.
 * @param maxScanBytes - cap on characters handed to tier 2.
 * @returns the union of both tiers, ordered by start offset.
 */
export async function scanAll(
  text: string,
  rules: readonly SyncRule[] = SYNC_RULES,
  maxScanBytes = Number.POSITIVE_INFINITY,
): Promise<ScanResult> {
  const tier1 = scanSync(text, rules)
  const tier2 = await scanWithSecretlint(text, maxScanBytes)
  const detections = [...tier1.detections, ...tier2.detections]
  detections.sort(byPosition)
  return { detections, truncated: tier2.truncated }
}
