/**
 * The `ask` tier's second rule class: a tool argument whose effect is to switch
 * off the confirmation for the call carrying it.
 *
 * Three 2026 advisories are the same technique. CVE-2026-18733 is
 * `non_interactive: true`; CVE-2026-53808 is `apply: true` while
 * `approvalPolicy` is still `pending`; CVE-2026-56075 is
 * `approval_mode: auto`. In each one the model composes an argument that
 * removes the human from that call, and nothing about the file paths or the
 * secrets involved says so.
 *
 * This is not the mutation check in `mutation.ts` and not the neutralizable
 * seam of the guard floor. Those are about *this plugin's* decision being
 * deleted by something else in the process. This is the model asking a tool to
 * skip the tool's *own* prompt, which every one of those seams would let
 * through as an ordinary, unmodified, secret-free call.
 *
 * It is an `ask` and deliberately not a denial, for the reason the write side
 * is: `non_interactive` also means "no TTY" on plenty of ordinary programs, the
 * tool registry is open, and an unoverridable denial on an argument name is a
 * false denial nobody can work around. ADR.md records the whole weighing.
 * @module dsh-dlp/approvals
 */

import type { ToolExecution } from '@deepseek-ai/dsh-tools'
import { isReadOnlyTool } from './paths.ts'

/** One argument key and the value that makes it a finding. */
export interface ArgumentCondition {
  /** Matched against the key lowercased with `_`, `-` and `.` removed. */
  readonly key: RegExp
  /** Matched against the value's scalar rendering, lowercased. */
  readonly value: RegExp
}

/** One argument, or pair of arguments, that suppresses a confirmation. */
export interface ApprovalSuppressionRule {
  readonly id: string
  readonly version: number
  readonly condition: ArgumentCondition
  /**
   * A second pair that must be present on the same object for the rule to
   * fire. `apply: true` on its own is how half the infrastructure tools in
   * existence are driven; it is the pending approval beside it that makes the
   * call skip a decision someone else had not made yet.
   */
  readonly alongside?: ArgumentCondition
  /** What the argument does, quoted in the prompt the user answers. */
  readonly effect: string
}

/**
 * Values that mean the confirmation does not happen.
 *
 * Only the affirmative spellings: `false`, `0` and `no` leave the prompt in
 * place, and a rule that fired on them would prompt on the argument that asks
 * for the prompt.
 */
const SUPPRESSING_TRUE = /^(?:true|yes|on|1)$/

/** Values of an approval-mode argument that name the absence of a prompt. */
const SUPPRESSING_MODE = /^(?:auto|autoapprove|autoedit|never|none|bypass|fullauto|yolo)$/

/**
 * Arguments that turn off the human confirmation for the call carrying them.
 *
 * Matched by argument name and value, at any depth of the arguments object,
 * never against the filesystem and never against the tool's name: the registry
 * is open, so a table keyed on tool names would abstain on every MCP tool this
 * build has never heard of — which is where these arguments live.
 */
export const APPROVAL_SUPPRESSION_RULES: readonly ApprovalSuppressionRule[] = [
  // CVE-2026-18733.
  {
    id: 'dsh-dlp/approval-non-interactive',
    version: 1,
    condition: { key: /^noninteractive$/, value: SUPPRESSING_TRUE },
    effect: 'a non-interactive flag, which runs the call without the confirmation it would otherwise ask for',
  },
  // CVE-2026-56075.
  {
    id: 'dsh-dlp/approval-mode-auto',
    version: 1,
    condition: { key: /^approval(?:mode|policy|setting)$/, value: SUPPRESSING_MODE },
    effect: 'an approval mode that approves on the model\'s behalf instead of asking',
  },
  // CVE-2026-53808: applying while the approval for that change is still
  // pending is what skips the decision, so neither half is a finding alone.
  {
    id: 'dsh-dlp/approval-apply-pending',
    version: 1,
    condition: { key: /^apply$/, value: SUPPRESSING_TRUE },
    alongside: { key: /^approvalpolicy$/, value: /^pending$/ },
    effect: 'an instruction to apply a change whose approval is still pending, which commits it before the answer',
  },
]

/**
 * The spelling one argument key is matched under: lowercase, with the
 * separators that distinguish `non_interactive`, `nonInteractive` and
 * `non-interactive` removed.
 * @param key - the key as the tool declared it.
 * @returns the normalized spelling.
 */
export function normalizeArgumentKey(key: string): string {
  return key.toLowerCase().replace(/[_.-]/g, '')
}

/**
 * One argument value as a string, for the values a flag can take.
 * @param node - the value under one argument key.
 * @returns the lowercased rendering, or `undefined` for an object or a list.
 */
function scalarValue(node: unknown): string | undefined {
  if (typeof node === 'boolean' || typeof node === 'number') return String(node)
  if (typeof node === 'string') return node.trim().toLowerCase()
  return undefined
}

/** Whether one object carries a key and value the condition describes. */
function satisfies(entries: ReadonlyMap<string, string>, condition: ArgumentCondition): boolean {
  for (const [key, value] of entries) {
    if (condition.key.test(key) && condition.value.test(value)) return true
  }
  return false
}

/**
 * The first rule any object inside the arguments satisfies.
 *
 * Both halves of a two-part rule must sit on the *same* object: an `apply` in
 * one element of a batch and an `approvalPolicy` in another are two different
 * requests, and pairing them across objects would report a call nobody made.
 * @param args - the pending call's parsed arguments.
 * @param rules - the rule table; defaults to {@link APPROVAL_SUPPRESSION_RULES}.
 * @returns the first matching rule, or `undefined`.
 */
export function matchApprovalSuppression(
  args: unknown,
  rules: readonly ApprovalSuppressionRule[] = APPROVAL_SUPPRESSION_RULES,
): ApprovalSuppressionRule | undefined {
  let found: ApprovalSuppressionRule | undefined
  const walk = (node: unknown): void => {
    if (found !== undefined) return
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (typeof node !== 'object' || node === null) return
    const entries = new Map<string, string>()
    for (const [key, value] of Object.entries(node)) {
      const scalar = scalarValue(value)
      if (scalar !== undefined) entries.set(normalizeArgumentKey(key), scalar)
    }
    found = rules.find(rule =>
      satisfies(entries, rule.condition)
      && (rule.alongside === undefined || satisfies(entries, rule.alongside)))
    if (found !== undefined) return
    for (const value of Object.values(node)) walk(value)
  }
  walk(args)
  return found
}

/** A call this tier wants a human to confirm, because the call asked not to be. */
export interface ApprovalSuppressionFinding {
  readonly rule: ApprovalSuppressionRule
  /** Model- and user-facing text; names the tool, the rule and what the argument does. */
  readonly reason: string
}

/**
 * Prompt text for one approval-suppressing argument.
 *
 * The argument's own value is not quoted, for the reason the write side does
 * not quote a path: this string is model-visible, and what the user needs in
 * order to answer is which tool, which rule, and what the argument does.
 */
function approvalSuppressionReason(toolName: string, rule: ApprovalSuppressionRule): string {
  return `dsh-dlp is asking before ${JSON.stringify(toolName)} runs with ${rule.effect} (rule ${rule.id}). `
    + 'The call carries an argument that turns off the confirmation for this call, so the prompt you would '
    + 'normally see is this one. Approve it if you asked for an unattended run; decline it if you did not.'
}

/**
 * Decide whether one call suppresses its own confirmation.
 *
 * A tool {@link isReadOnlyTool} classifies as query-only is left alone: it has
 * nothing to confirm, so an argument switching a confirmation off changes
 * nothing there.
 * @param exec - the pending call.
 * @param rules - the rule table; defaults to {@link APPROVAL_SUPPRESSION_RULES}.
 * @returns the finding, or `undefined` to leave the call alone.
 */
export function evaluateApprovalSuppression(
  exec: Pick<ToolExecution, 'name' | 'arguments'>,
  rules: readonly ApprovalSuppressionRule[] = APPROVAL_SUPPRESSION_RULES,
): ApprovalSuppressionFinding | undefined {
  if (isReadOnlyTool(exec.name)) return undefined
  const rule = matchApprovalSuppression(exec.arguments, rules)
  return rule === undefined ? undefined : { rule, reason: approvalSuppressionReason(exec.name, rule) }
}
