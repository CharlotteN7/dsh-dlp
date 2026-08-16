/**
 * The output-schema question asked before a redacted value is handed back:
 * would replacing it fail the tool's own validation?
 */

import { describe, expect, it } from 'vitest'
import type { JsonSchemaNode } from '@deepseek-ai/dsh-tools'
import { redactionBreaksSchema, satisfiesJsonSchema } from '../../src/schema.ts'

/** Shaped like a Slack bot token; invented for this test, never a live credential. */
const SLACK = 'xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'

describe('the enforced schema subset', () => {
  it('accepts anything for a node with no type', () => {
    expect(satisfiesJsonSchema({}, { anything: [1, 'two', null] })).toBe(true)
  })

  it.each([
    ['a string', { type: 'string' } as JsonSchemaNode, 'text', 7],
    ['a number', { type: 'number' } as JsonSchemaNode, 1.5, '1.5'],
    ['an integer', { type: 'integer' } as JsonSchemaNode, 7, 7.5],
    ['a boolean', { type: 'boolean' } as JsonSchemaNode, true, 'true'],
    ['null', { type: 'null' } as JsonSchemaNode, null, 0],
    ['an array', { type: 'array' } as JsonSchemaNode, [1, 2], { 0: 1 }],
    ['an object', { type: 'object' } as JsonSchemaNode, { a: 1 }, [1]],
  ])('checks that a value is %s', (_label, node, accepted, rejected) => {
    expect(satisfiesJsonSchema(node, accepted)).toBe(true)
    expect(satisfiesJsonSchema(node, rejected)).toBe(false)
  })

  it('rejects a number that is not finite', () => {
    expect(satisfiesJsonSchema({ type: 'number' }, Number.POSITIVE_INFINITY)).toBe(false)
  })

  it.each([
    ['an enum', { type: 'string', enum: ['ok', 'error'] } as JsonSchemaNode, 'ok', 'other'],
    ['a const', { type: 'string', const: 'ok' } as JsonSchemaNode, 'ok', 'other'],
  ])('checks %s on a scalar', (_label, node, accepted, rejected) => {
    expect(satisfiesJsonSchema(node, accepted)).toBe(true)
    expect(satisfiesJsonSchema(node, rejected)).toBe(false)
  })

  it('checks each declared property, and skips one the value omits', () => {
    const node: JsonSchemaNode = {
      type: 'object',
      properties: { name: { type: 'string' }, count: { type: 'integer' } },
    }

    expect(satisfiesJsonSchema(node, { name: 'a' })).toBe(true)
    expect(satisfiesJsonSchema(node, { name: 'a', count: 2 })).toBe(true)
    expect(satisfiesJsonSchema(node, { name: 'a', count: 'two' })).toBe(false)
  })

  it('requires the properties the schema marks required', () => {
    const node: JsonSchemaNode = { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] }

    expect(satisfiesJsonSchema(node, { name: 'a' })).toBe(true)
    expect(satisfiesJsonSchema(node, {})).toBe(false)
    expect(satisfiesJsonSchema(node, { name: undefined })).toBe(false)
  })

  it('rejects an undeclared key only when additionalProperties is false', () => {
    const closed: JsonSchemaNode = { type: 'object', properties: { a: { type: 'string' } }, additionalProperties: false }
    const open: JsonSchemaNode = { type: 'object', properties: { a: { type: 'string' } } }

    expect(satisfiesJsonSchema(closed, { a: 'x', b: 'y' })).toBe(false)
    expect(satisfiesJsonSchema(closed, { a: 'x' })).toBe(true)
    expect(satisfiesJsonSchema(open, { a: 'x', b: 'y' })).toBe(true)
  })

  it('checks every item against the item schema, and any item without one', () => {
    expect(satisfiesJsonSchema({ type: 'array', items: { type: 'string' } }, ['a', 'b'])).toBe(true)
    expect(satisfiesJsonSchema({ type: 'array', items: { type: 'string' } }, ['a', 2])).toBe(false)
    expect(satisfiesJsonSchema({ type: 'array' }, ['a', 2])).toBe(true)
  })

  it('requires exactly one oneOf branch, as the registry does', () => {
    const node: JsonSchemaNode = {
      oneOf: [
        { type: 'object', properties: { kind: { type: 'string', const: 'text' } }, required: ['kind'] },
        { type: 'object', properties: { kind: { type: 'string', const: 'binary' } }, required: ['kind'] },
      ],
    }

    expect(satisfiesJsonSchema(node, { kind: 'text' })).toBe(true)
    expect(satisfiesJsonSchema(node, { kind: 'other' })).toBe(false)
    expect(satisfiesJsonSchema({ oneOf: [{ type: 'string' }, { type: 'string' }] }, 'x')).toBe(false)
  })
})

describe('whether a redaction breaks the tool output', () => {
  const pinned: JsonSchemaNode = {
    type: 'object',
    properties: { token: { type: 'string', const: SLACK } },
    required: ['token'],
  }

  it('says nothing when the tool declared no schema this listener could resolve', () => {
    expect(redactionBreaksSchema(undefined, { token: SLACK }, { token: '[REDACTED]' })).toBe(false)
  })

  it('reports a placeholder the schema will reject', () => {
    expect(redactionBreaksSchema(pinned, { token: SLACK }, { token: '[REDACTED]' })).toBe(true)
  })

  it('stays quiet when the placeholder is as acceptable as what it replaced', () => {
    const open: JsonSchemaNode = { type: 'object', properties: { token: { type: 'string' } } }

    expect(redactionBreaksSchema(open, { token: SLACK }, { token: '[REDACTED]' })).toBe(false)
  })

  it('defers to the registry when it cannot even validate the original', () => {
    // Disagreeing with the registry here would withhold a result over this
    // module's own confusion, so an original it rejects means the answer is no.
    expect(redactionBreaksSchema(pinned, { token: 'something else' }, { token: '[REDACTED]' })).toBe(false)
  })
})
