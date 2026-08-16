/**
 * Where the harness keeps its state, and where this plugin's audit sink lands
 * by default.
 *
 * Its own module so the `dsh-dlp report` command can resolve the sink without
 * importing the plugin: `policy.ts` pulls in `@secretlint/core`, `js-yaml` and
 * the schema library, none of which a reader of a JSONL file needs.
 * @module dsh-dlp/home
 */

import { homedir } from 'node:os'
import { join, resolve } from 'node:path'

/**
 * File name the bundle patch gives the audit sink under the harness home.
 * `cordis.patch.yml` spells the same name; a deployment that sets `auditLog`
 * itself must tell `dsh-dlp report` where it put it.
 */
export const DEFAULT_AUDIT_LOG_NAME = 'dsh-dlp.audit.jsonl'

/**
 * Resolve the harness home the same way the harness does: `$DSH_HOME` when it
 * is set to something other than whitespace, otherwise `~/.dsh`. Read here
 * rather than through `@deepseek-ai/dsh-home-paths` to keep the plugin's
 * runtime imports to the ones a profile is guaranteed to resolve.
 * @param env - environment consulted for `DSH_HOME`; defaults to `process.env`.
 * @returns the absolute harness home.
 */
export function resolveDshHome(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env['DSH_HOME']
  return resolve(configured !== undefined && configured.trim().length > 0 ? configured : join(homedir(), '.dsh'))
}

/**
 * Where the audit sink sits when the deployment did not name one.
 * @param env - environment consulted for `DSH_HOME`; defaults to `process.env`.
 * @returns the absolute path the bundle patch configures.
 */
export function defaultAuditLog(env: NodeJS.ProcessEnv = process.env): string {
  return join(resolveDshHome(env), DEFAULT_AUDIT_LOG_NAME)
}
