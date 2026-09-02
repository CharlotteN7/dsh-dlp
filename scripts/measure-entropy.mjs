#!/usr/bin/env node
/**
 * Measure what a Shannon-entropy rule would cost this package, so the claim in
 * `docs/redaction.md` is a measurement rather than an assumption.
 *
 * Method
 * ------
 * A candidate token is a maximal run of `[A-Za-z0-9+/=_-]` at least
 * MIN_TOKEN_LENGTH characters long — the character class every published
 * entropy scanner uses, because it is the alphabet of base64, hex, and every
 * common token format. Each token's score is Shannon entropy over its own
 * character frequencies, in bits per character.
 *
 * A threshold `t` flags every token scoring at or above it. Shannon entropy of
 * a length-L string is bounded by log2(L), so a threshold also implies a length
 * floor: no string shorter than 2^t characters can reach `t`, whatever it
 * holds. That is what makes "the shortest secret this threshold could ever
 * catch" a derived number rather than a second parameter.
 *
 * The corpus is this package's own installed tree, which `pnpm-lock.yaml` pins,
 * so the run reproduces: every UTF-8 text file under the directories named on
 * the command line.
 *
 * Usage: node scripts/measure-entropy.mjs <dir-or-file>...
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/** Shortest run this counts as a candidate; below it no threshold is interesting. */
const MIN_TOKEN_LENGTH = 16

/** Candidate token: base64/hex/token alphabet, greedy. */
const TOKEN = new RegExp(`[A-Za-z0-9+/=_-]{${String(MIN_TOKEN_LENGTH)},}`, 'g')

/** Bytes past which a file is read as a binary blob and skipped. */
const MAX_FILE_BYTES = 4 * 1024 * 1024

/** Thresholds the sweep reports, in bits per character. */
const SWEEP = [3.5, 4.0, 4.2, 4.46, 4.6, 4.8, 5.0, 5.2, 5.4, 5.6, 5.75, 5.8, 6.0, 6.04, 6.2]

/** Shannon entropy of one string, in bits per character. */
function entropy(text) {
  const counts = new Map()
  for (const character of text) counts.set(character, (counts.get(character) ?? 0) + 1)
  let bits = 0
  for (const count of counts.values()) {
    const probability = count / text.length
    bits -= probability * Math.log2(probability)
  }
  return bits
}

/**
 * Every real file under one path.
 *
 * Symbolic links are skipped rather than followed: a pnpm tree reaches the
 * same file through several names, and a store with a cycle in it walks
 * forever. Counting one file once is also what makes the per-file rate mean
 * what it says.
 */
function filesUnder(path) {
  let stats
  try {
    stats = statSync(path)
  } catch {
    // ENOENT only: a corpus root the caller named but this tree does not have.
    return []
  }
  if (!stats.isDirectory()) return [path]
  return readdirSync(path, { withFileTypes: true }).flatMap(entry =>
    entry.isSymbolicLink() ? [] : filesUnder(join(path, entry.name)))
}

/** Read one file as UTF-8, or nothing when it is too large or not text. */
function readText(file) {
  let stats
  try {
    stats = statSync(file)
  } catch {
    // ENOENT only: a symlink whose target left between listing and reading.
    return undefined
  }
  if (stats.size > MAX_FILE_BYTES || stats.size === 0) return undefined
  const buffer = readFileSync(file)
  if (buffer.includes(0)) return undefined
  return buffer.toString('utf8')
}

const roots = process.argv.slice(2)
if (roots.length === 0) {
  process.stderr.write('usage: node scripts/measure-entropy.mjs <dir-or-file>...\n')
  process.exit(2)
}

/** One entry per candidate token: its length and its score. */
const scores = []
/** Highest score any candidate in each file reached; one entry per file. */
const perFile = []
let bytes = 0
for (const root of roots) {
  for (const file of filesUnder(root)) {
    const text = readText(file)
    if (text === undefined) continue
    bytes += text.length
    let best = 0
    for (const [token] of text.matchAll(TOKEN)) {
      const score = entropy(token)
      scores.push([token.length, score])
      best = Math.max(best, score)
    }
    perFile.push(best)
  }
}

const total = scores.length
const files = perFile.length
process.stdout.write(`corpus: ${String(files)} files, ${String(bytes)} characters, ${String(total)} candidate tokens\n`)
process.stdout.write(`token class: /${TOKEN.source}/\n\n`)
process.stdout.write('threshold  length floor  tokens flagged  share of tokens  share of files\n')
for (const threshold of SWEEP) {
  const flagged = scores.filter(([, score]) => score >= threshold).length
  const hitFiles = perFile.filter(score => score >= threshold).length
  const floor = Math.ceil(2 ** threshold)
  process.stdout.write([
    threshold.toFixed(2).padStart(9),
    String(floor).padStart(14),
    String(flagged).padStart(16),
    `${(100 * flagged / total).toFixed(2)}%`.padStart(17),
    `${(100 * hitFiles / files).toFixed(2)}%`.padStart(16),
  ].join('') + '\n')
}

// The lowest threshold that flags nothing, to two decimals: the only threshold
// a security control could ship without a false-positive budget.
let clean
for (let threshold = 3; threshold <= 8; threshold += 0.01) {
  if (!scores.some(([, score]) => score >= threshold)) {
    clean = threshold
    break
  }
}
const highest = scores.reduce((best, [, score]) => Math.max(best, score), 0)
process.stdout.write(`\nhighest score in the corpus: ${highest.toFixed(3)} bits/char\n`)
if (clean !== undefined) {
  process.stdout.write(`lowest false-positive-free threshold: ${clean.toFixed(2)} bits/char\n`)
  process.stdout.write(`  shortest string that threshold could ever flag: ${String(Math.ceil(2 ** clean))} characters\n`)
}
const twentyTwo = Math.log2(22)
const flaggedAt22 = scores.filter(([, score]) => score >= twentyTwo).length
const filesAt22 = perFile.filter(score => score >= twentyTwo).length
process.stdout.write(`\nthreshold whose length floor is 22 characters: ${twentyTwo.toFixed(3)} bits/char\n`)
process.stdout.write(`  flags ${String(flaggedAt22)} of ${String(total)} tokens (${(100 * flaggedAt22 / total).toFixed(2)}%)\n`)
process.stdout.write(`  hits ${String(filesAt22)} of ${String(files)} files (${(100 * filesAt22 / files).toFixed(2)}%)\n`)

// The corpus is dominated by whichever root holds the most files, so the same
// two rates are reported per root: a reader reproducing this needs to see that
// the answer does not hang on one directory.
process.stdout.write('\nper corpus root, at the 22-character threshold:\n')
for (const root of roots) {
  const rootScores = []
  const rootFiles = []
  for (const file of filesUnder(root)) {
    const text = readText(file)
    if (text === undefined) continue
    let best = 0
    for (const [token] of text.matchAll(TOKEN)) {
      const score = entropy(token)
      rootScores.push(score)
      best = Math.max(best, score)
    }
    rootFiles.push(best)
  }
  if (rootScores.length === 0) continue
  const flagged = rootScores.filter(score => score >= twentyTwo).length
  const hit = rootFiles.filter(score => score >= twentyTwo).length
  process.stdout.write(
    `  ${root.padEnd(18)}${String(rootScores.length).padStart(8)} tokens  `
    + `${`${(100 * flagged / rootScores.length).toFixed(2)}%`.padStart(7)} of tokens  `
    + `${`${(100 * hit / rootFiles.length).toFixed(2)}%`.padStart(7)} of files\n`,
  )
}
