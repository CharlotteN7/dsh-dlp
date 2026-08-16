#!/usr/bin/env node
/**
 * `dsh-dlp report` — read this plugin's audit JSONL and say what it decided.
 *
 * The sink is the only evidence a decision happened, and nothing read it: a
 * user could not answer "what did this block today?". This command reads the
 * file directly and imports nothing from the harness, so it runs wherever the
 * package is installed, with no profile and no `dsh` on the path.
 *
 * The file is a durable boundary — written by an older version of this
 * package, appended to under crash — so every line is parsed defensively and a
 * line that is not a record is counted rather than trusted.
 * @module dsh-dlp/cli
 */

import { readFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { defaultAuditLog } from './home.ts'

/** Decision kinds that stopped a call, as opposed to rewriting its result. */
const DENYING_KINDS: ReadonlySet<string> = new Set(['guard-deny', 'pre-execute-deny'])

/** How many decisions the report lists individually. */
const RECENT_LIMIT = 10

/** One line of the audit file, after the fields this command reads are checked. */
export interface ReportRecord {
  /** Epoch milliseconds parsed from the record's ISO time. */
  readonly time: number
  readonly kind: string
  readonly tool?: string
  readonly sessionId?: string
  /** Rule ids named by the record's spans, without repeats. */
  readonly ruleIds: readonly string[]
  /** Invisible-character runs by rule id. */
  readonly unicode: Readonly<Record<string, number>>
}

/** Read one string field, or `undefined` when the line does not carry it. */
function stringField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key]
  return typeof value === 'string' ? value : undefined
}

/** Rule ids named by a record's spans, in file order and without repeats. */
function ruleIdsOf(record: Record<string, unknown>): string[] {
  const spans = record['spans']
  if (!Array.isArray(spans)) return []
  const ids = spans.flatMap((span: unknown) => {
    if (typeof span !== 'object' || span === null) return []
    const ruleId = (span as Record<string, unknown>)['ruleId']
    return typeof ruleId === 'string' ? [ruleId] : []
  })
  return [...new Set(ids)]
}

/** Invisible-character counts a record carries, keeping only numeric entries. */
function unicodeOf(record: Record<string, unknown>): Record<string, number> {
  const counts = record['unicode']
  if (typeof counts !== 'object' || counts === null || Array.isArray(counts)) return {}
  return Object.fromEntries(
    Object.entries(counts).flatMap(([key, value]) => typeof value === 'number' ? [[key, value] as const] : []),
  )
}

/**
 * Parse one JSONL line into the fields this command reports on.
 * @param line - one line of the audit file.
 * @returns the record, or `undefined` when the line is not one.
 */
export function parseRecord(line: string): ReportRecord | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    // A torn final line from an interrupted append is the expected cause.
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined
  const record = parsed as Record<string, unknown>
  const kind = stringField(record, 'kind')
  const written = stringField(record, 'time')
  if (kind === undefined || written === undefined) return undefined
  const time = Date.parse(written)
  if (Number.isNaN(time)) return undefined
  const tool = stringField(record, 'tool')
  const sessionId = stringField(record, 'sessionId')
  return {
    time,
    kind,
    ...tool === undefined ? {} : { tool },
    ...sessionId === undefined ? {} : { sessionId },
    ruleIds: ruleIdsOf(record),
    unicode: unicodeOf(record),
  }
}

/** What `report` was asked for. */
export interface ReportOptions {
  readonly log: string
  /** Epoch milliseconds; records before it are left out. */
  readonly since?: number
  readonly session?: string
  /** Keep only the decisions that let the call through. */
  readonly wouldHave: boolean
}

/** The outcome of reading the command line. */
export type Invocation =
  | { readonly kind: 'report'; readonly options: ReportOptions }
  | { readonly kind: 'help' }
  | { readonly kind: 'error'; readonly message: string }

/** Text printed for `--help` and alongside a usage error. */
export const USAGE = [
  'Usage: dsh-dlp report [options]',
  '',
  'Reads the JSONL audit sink this plugin writes and summarises what it decided.',
  '',
  'Options:',
  '  --log <path>     audit file to read (default: $DSH_HOME/dsh-dlp.audit.jsonl)',
  '  --since <when>   only decisions at or after an ISO timestamp, or a span back',
  '                   from now written as 30m, 24h or 7d',
  '  --session <id>   only decisions from one session',
  '  --would-have     only the decisions that let the call through: the redactions',
  '                   and invisible-character findings, which is what a policy that',
  '                   denied instead of rewriting would have blocked',
  '  -h, --help       print this text',
].join('\n')

/** Milliseconds in one `--since` suffix; {@link parseSince} accepts no other. */
function spanUnitMs(unit: string): number {
  switch (unit) {
    case 's': return 1000
    case 'm': return 60_000
    case 'h': return 3_600_000
    default: return 86_400_000
  }
}

/**
 * Read `--since`: an ISO timestamp, or a span back from now.
 * @param value - the argument as written.
 * @param now - epoch milliseconds a relative span counts back from.
 * @returns epoch milliseconds, or `undefined` when the value is neither.
 */
export function parseSince(value: string, now: number): number | undefined {
  if (/^\d+[smhd]$/.test(value)) return now - Number(value.slice(0, -1)) * spanUnitMs(value.slice(-1))
  const absolute = Date.parse(value)
  return Number.isNaN(absolute) ? undefined : absolute
}

/**
 * Read the command line.
 * @param argv - arguments after the program name.
 * @param env - environment used for the default sink path.
 * @param now - epoch milliseconds a relative `--since` counts back from.
 * @returns what to run, or the usage error to print.
 */
export function parseArguments(argv: readonly string[], env: NodeJS.ProcessEnv, now: number): Invocation {
  const [command, ...rest] = argv
  if (command === undefined || command === '-h' || command === '--help') return { kind: 'help' }
  if (command !== 'report') return { kind: 'error', message: `dsh-dlp: unknown command ${JSON.stringify(command)}` }

  let log = defaultAuditLog(env)
  let since: number | undefined
  let session: string | undefined
  let wouldHave = false
  let consumed = false

  for (const [index, flag] of rest.entries()) {
    if (consumed) {
      consumed = false
      continue
    }
    switch (flag) {
      case '--log':
      case '--since':
      case '--session': {
        const value = rest[index + 1]
        if (value === undefined) return { kind: 'error', message: `dsh-dlp: ${flag} needs a value` }
        consumed = true
        if (flag === '--log') log = value
        else if (flag === '--session') session = value
        else {
          const parsed = parseSince(value, now)
          if (parsed === undefined) {
            return {
              kind: 'error',
              message: `dsh-dlp: --since ${JSON.stringify(value)} is neither a timestamp nor a span like 24h`,
            }
          }
          since = parsed
        }
        break
      }
      case '--would-have':
        wouldHave = true
        break
      case '-h':
      case '--help':
        return { kind: 'help' }
      default:
        return { kind: 'error', message: `dsh-dlp: unknown option ${JSON.stringify(flag)}` }
    }
  }

  return {
    kind: 'report',
    options: {
      log,
      ...since === undefined ? {} : { since },
      ...session === undefined ? {} : { session },
      wouldHave,
    },
  }
}

/** Outcome of reading the audit file. */
export type AuditFileRead =
  /** No file at that path: nothing has been recorded, or the sink is elsewhere. */
  | { readonly kind: 'absent' }
  | { readonly kind: 'unreadable'; readonly problem: string }
  | {
    readonly kind: 'read'
    readonly records: readonly ReportRecord[]
    /** Lines that were not records; a torn final append is the expected cause. */
    readonly unreadable: number
  }

/**
 * Read and parse the audit file.
 * @param path - the file to read.
 * @returns its records, its absence, or the problem to print.
 */
export function readAuditFile(path: string): AuditFileRead {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'unreadable', problem: `dsh-dlp: cannot read ${path}: ${String(error)}` }
  }
  const lines = text.split('\n').filter(line => line.trim().length > 0)
  const records = lines.flatMap((line) => {
    const record = parseRecord(line)
    return record === undefined ? [] : [record]
  })
  return { kind: 'read', records, unreadable: lines.length - records.length }
}

/** Count each label over the records, most frequent first. */
function tally(
  records: readonly ReportRecord[],
  label: (record: ReportRecord) => readonly string[],
): [string, number][] {
  const counts = new Map<string, number>()
  for (const record of records) {
    for (const key of label(record)) counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
}

/** One `name  count` line per entry, padded so the column lines up. */
function countLines(entries: readonly [string, number][]): string[] {
  const width = Math.max(...entries.map(([name]) => name.length))
  return entries.map(([name, count]) => `  ${name.padEnd(width)}  ${count}`)
}

/** A heading and its counts, or nothing when there are none. */
function section(heading: string, entries: readonly [string, number][]): string[] {
  return entries.length === 0 ? [] : ['', heading, ...countLines(entries)]
}

/**
 * Render the report.
 * @param records - every record the file yielded.
 * @param unreadable - how many of its lines were not records.
 * @param options - the filters the invocation asked for.
 * @returns the lines to print.
 */
export function formatReport(
  records: readonly ReportRecord[],
  unreadable: number,
  options: ReportOptions,
): string[] {
  const selected = records.filter((record) => {
    if (options.since !== undefined && record.time < options.since) return false
    if (options.session !== undefined && record.sessionId !== options.session) return false
    if (options.wouldHave && DENYING_KINDS.has(record.kind)) return false
    return true
  })

  const lines = [`dsh-dlp: ${selected.length} decision(s) in ${options.log}`]
  if (options.since !== undefined) lines.push(`  since ${new Date(options.since).toISOString()}`)
  if (options.session !== undefined) lines.push(`  session ${options.session}`)
  if (options.wouldHave) lines.push('  only decisions that let the call through')
  if (unreadable > 0) lines.push(`  ${unreadable} line(s) were not readable as records`)
  if (selected.length === 0) return lines

  lines.push(
    ...section('by decision', tally(selected, record => [record.kind])),
    ...section('by rule', tally(selected, record => record.ruleIds)),
    ...section('by tool', tally(selected, record => record.tool === undefined ? [] : [record.tool])),
    ...section(
      'results carrying invisible characters',
      tally(selected, record => Object.keys(record.unicode)),
    ),
  )

  const recent = [...selected].sort((left, right) => right.time - left.time).slice(0, RECENT_LIMIT)
  lines.push('', `most recent ${recent.length}`)
  for (const record of recent) {
    const rules = record.ruleIds.length === 0 ? '-' : record.ruleIds.join(', ')
    lines.push(`  ${new Date(record.time).toISOString()}  ${record.kind}  ${record.tool ?? '-'}  ${rules}`)
  }
  return lines
}

/**
 * Run one invocation.
 * @param argv - arguments after the program name.
 * @param write - receives each line of output.
 * @param fail - receives each line of error output.
 * @param env - environment used for the default sink path.
 * @param now - epoch milliseconds a relative `--since` counts back from.
 * @returns the process exit code.
 */
export function main(
  argv: readonly string[],
  write: (line: string) => void,
  fail: (line: string) => void,
  env: NodeJS.ProcessEnv = process.env,
  now: number = Date.now(),
): number {
  const invocation = parseArguments(argv, env, now)
  if (invocation.kind === 'help') {
    write(USAGE)
    return 0
  }
  if (invocation.kind === 'error') {
    fail(invocation.message)
    fail(USAGE)
    return 2
  }
  const file = readAuditFile(invocation.options.log)
  switch (file.kind) {
    case 'absent':
      write(`dsh-dlp: no audit file at ${invocation.options.log}`)
      write('Nothing has been recorded yet, or the deployment set `auditLog` elsewhere — pass --log <path>.')
      return 0
    case 'unreadable':
      fail(file.problem)
      return 1
    case 'read':
      for (const line of formatReport(file.records, file.unreadable, invocation.options)) write(line)
      return 0
    /* v8 ignore next 4 -- unreachable while `AuditFileRead` stays closed; the arm exists so adding a variant fails the build. */
    default: {
      const unhandled: never = file
      throw new TypeError(`dsh-dlp: unhandled audit file read ${JSON.stringify(unhandled)}`)
    }
  }
}

/* v8 ignore start -- the process entry, exercised by tests/e2e/report.e2e.ts against the built CLI rather than by the instrumented unit run. */
if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(
    process.argv.slice(2),
    line => process.stdout.write(`${line}\n`),
    line => process.stderr.write(`${line}\n`),
  )
}
/* v8 ignore stop */
