/**
 * Whether a redacted value still satisfies the tool's declared `output.schema`.
 *
 * Replacing a canonical value makes the registry re-validate it, so a schema
 * that pins the redacted string turns a redaction into a `ToolOutputError` the
 * model cannot act on. Asking the question first lets the listener withhold
 * the result with its own explanation instead.
 *
 * This is a re-implementation of the harness's own check rather than a call
 * into it: every harness type this package uses is imported with `import
 * type`, so nothing from `@deepseek-ai/dsh-*` is emitted as a runtime import
 * and the plugin resolves from a profile directory that has none of them
 * installed. The enforced subset is small — `type`, `oneOf`, `properties`,
 * `required`, `additionalProperties`, `items`, `enum`, `const` — and the
 * caller guards against any disagreement by checking the *original* value
 * first: a value this module rejects before redaction means the answer cannot
 * be trusted, and the redaction proceeds as it did before.
 * @module dsh-dlp/schema
 */

import type { JsonSchemaNode, JsonSchemaScalar } from '@deepseek-ai/dsh-tools'

/** Whether a value is a plain JSON object rather than an array or a null. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Whether a scalar passes the node's `enum` and `const` constraints. */
function allowsScalar(node: JsonSchemaNode, value: JsonSchemaScalar): boolean {
  if (node.enum !== undefined && !node.enum.includes(value)) return false
  return node.const === undefined || value === node.const
}

/** Whether every declared property of an object node is satisfied. */
function satisfiesObject(node: JsonSchemaNode, value: Record<string, unknown>): boolean {
  const properties = node.properties ?? {}
  for (const key of node.required ?? []) {
    if (!Object.hasOwn(value, key) || value[key] === undefined) return false
  }
  if (node.additionalProperties === false) {
    for (const key of Object.keys(value)) {
      if (!Object.hasOwn(properties, key)) return false
    }
  }
  return Object.entries(properties).every(([key, child]) =>
    !Object.hasOwn(value, key) || value[key] === undefined || satisfiesJsonSchema(child, value[key]))
}

/**
 * Whether one value satisfies one schema node.
 * @param node - a node of the tool's declared output schema.
 * @param value - the candidate value.
 * @returns `true` when the registry's own validation would accept it.
 */
export function satisfiesJsonSchema(node: JsonSchemaNode, value: unknown): boolean {
  if (node.oneOf !== undefined) {
    return node.oneOf.filter(branch => satisfiesJsonSchema(branch, value)).length === 1
  }
  switch (node.type) {
    case undefined:
      return true
    case 'object':
      return isRecord(value) && satisfiesObject(node, value)
    case 'array': {
      const items = node.items
      return Array.isArray(value) && (items === undefined || value.every(item => satisfiesJsonSchema(items, item)))
    }
    case 'string':
      return typeof value === 'string' && allowsScalar(node, value)
    case 'number':
      return typeof value === 'number' && Number.isFinite(value) && allowsScalar(node, value)
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value) && allowsScalar(node, value)
    case 'boolean':
      return typeof value === 'boolean' && allowsScalar(node, value)
    case 'null':
      return value === null && allowsScalar(node, value)
    /* v8 ignore next 4 -- unreachable while `JsonSchemaType` stays closed; the arm exists so adding a type fails the build. */
    default: {
      const unhandled: never = node.type
      throw new TypeError(`dsh-dlp: unhandled JSON schema type ${JSON.stringify(unhandled)}`)
    }
  }
}

/**
 * Whether replacing a value with its redacted copy would fail the tool's
 * output validation.
 *
 * A schema this module already rejects for the original value is one it does
 * not model correctly, so the answer is `false` and the registry decides — the
 * check can withhold a result, and it must never do so on its own confusion.
 * @param schema - the tool's declared output schema, when one could be resolved.
 * @param original - the value the tool produced.
 * @param redacted - the value the redaction pass produced.
 * @returns `true` only when the original validates and the redacted one does not.
 */
export function redactionBreaksSchema(
  schema: JsonSchemaNode | undefined,
  original: unknown,
  redacted: unknown,
): boolean {
  if (schema === undefined) return false
  if (!satisfiesJsonSchema(schema, original)) return false
  return !satisfiesJsonSchema(schema, redacted)
}
