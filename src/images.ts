/**
 * Neutralising remote markdown images in assistant output, on the `llm/stream`
 * waterfall.
 *
 * The web UI renders any absolute `http:`/`https:` markdown image a model
 * emits as a real `<img src>`, and the harness sets no Content-Security-Policy,
 * so the fetch happens in the user's browser where no host-side listener can
 * see it. This module rewrites the destination out of the assistant's text
 * before it becomes an `assistant/chunk` or `assistant/message` session event,
 * so the log and the rendered answer stay in agreement.
 *
 * Two properties this module exists to hold:
 *
 * - **A destination split across chunks is still caught.** The mock and real
 *   adapters both emit text in small deltas, so `![alt](https://host/x)` is
 *   routinely spread over several of them and the browser renders the
 *   accumulation. Text that could still be the start of an image is held back
 *   until it either completes or exceeds {@link MAX_HELD_CHARACTERS}.
 * - **Only the destination is replaced.** The alt text survives, so the
 *   sentence the model wrote still reads, and the renderer's own
 *   non-absolute-URL arm shows that alt text instead of fetching anything.
 *
 * This does not close the channel. It matches inline image syntax only:
 * reference-style images, an alt text carrying a `]`, and any destination form
 * the pattern does not model still reach the renderer. Raw HTML needs no
 * handling — the renderer keeps it as literal text and no HTML enters the DOM
 * (`packages/client/ui-primitives/src/markdown/render.tsx:261-263`). The
 * upstream fix is one `img-src` directive.
 * @module dsh-dlp/images
 */

import type { StreamChunk } from '@deepseek-ai/dsh-llm'

/**
 * Destination substituted for a remote image URL.
 *
 * It is deliberately not a URL: `new URL()` throws on it, which is the
 * renderer's own "not an absolute destination" arm, and that arm renders the
 * alt text as a `<span>` instead of emitting an `<img>`.
 */
export const BLOCKED_IMAGE_DESTINATION = 'dsh-dlp-blocked-remote-image'

/**
 * One inline image: alt text, destination, optional title.
 *
 * The destination is either an angle-bracketed form or a run of characters
 * with no whitespace and no parenthesis, which is what CommonMark accepts
 * without balanced-parenthesis nesting.
 */
const INLINE_IMAGE = /!\[([^\]]*)\]\(\s*(<[^<>\n]*>|[^\s()]*)((?:\s+(?:"[^"]*"|'[^']*'|\([^()]*\)))?)\s*\)/g

/**
 * Text that could still become an inline image once more of the stream
 * arrives: an alt text still open, a closed alt text followed by `(`, or a
 * destination not yet closed.
 */
const PARTIAL_IMAGE = /^!\[[^\]]*(?:\](?:\((?:\s*(?:<[^<>\n]*|[^\s()]*))?)?)?$/

/**
 * Longest suffix held back waiting for an image to complete.
 *
 * Held text is text the user cannot see yet, so the wait is bounded: past this
 * many characters the suffix is emitted as it stands and a destination that
 * completes later is caught only by the assembled block. A protocol bound on
 * this module's own buffering, not a deployment choice.
 */
export const MAX_HELD_CHARACTERS = 4096

/** One string after its remote image destinations were replaced. */
export interface NeutralizedText {
  readonly text: string
  /** Hostnames of the replaced destinations, in match order; never the full URL. */
  readonly hosts: readonly string[]
}

/**
 * The hostname of an absolute `http(s)` destination.
 * @param destination - the image destination exactly as the model wrote it.
 * @returns the hostname, or `undefined` when the destination is not an absolute HTTP(S) URL.
 */
function remoteHost(destination: string): string | undefined {
  const trimmed = destination.startsWith('<') && destination.endsWith('>')
    ? destination.slice(1, -1)
    : destination
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    // The only failure mode for a string: not an absolute URL, which the
    // renderer also refuses, so there is nothing to neutralise.
    return undefined
  }
  return url.protocol === 'http:' || url.protocol === 'https:' ? url.hostname : undefined
}

/**
 * Replace every absolute HTTP(S) inline image destination in one string.
 * @param text - assistant text, whole or partial.
 * @returns the rewritten text and the hosts whose destinations were replaced.
 */
export function neutralizeRemoteImages(text: string): NeutralizedText {
  const hosts: string[] = []
  const rewritten = text.replace(INLINE_IMAGE, (match, alt: string, destination: string, title: string) => {
    const host = remoteHost(destination)
    if (host === undefined) return match
    hosts.push(host)
    return `![${alt}](${BLOCKED_IMAGE_DESTINATION}${title})`
  })
  return { text: rewritten, hosts }
}

/**
 * Where the held suffix of a partially streamed string starts.
 * @param text - everything accumulated for one block and not yet emitted.
 * @returns the offset to emit up to; the string's length when nothing is held.
 */
export function heldSuffixStart(text: string): number {
  const marker = text.lastIndexOf('![')
  if (marker !== -1 && text.length - marker <= MAX_HELD_CHARACTERS && PARTIAL_IMAGE.test(text.slice(marker))) {
    return marker
  }
  return text.endsWith('!') ? text.length - 1 : text.length
}

/**
 * Wrap one model stream, replacing remote image destinations in its text.
 *
 * Text deltas are rewritten as they pass, with a possible image start held
 * back until it resolves, and the assembled block on `block-end` — which is
 * what the agent loop turns into the assistant message — is rewritten too. A
 * held suffix is always flushed as a delta before the block closes and before
 * the terminal finish, so no text is lost and the emitted chunks still satisfy
 * the stream grammar.
 * @param source - the stream from the rest of the waterfall.
 * @param onNeutralized - notified once per host per text block.
 * @returns the rewritten stream.
 */
export async function* neutralizeImageStream(
  source: AsyncIterable<StreamChunk>,
  onNeutralized: (host: string) => void,
): AsyncIterable<StreamChunk> {
  const held = new Map<number, string>()
  const reported = new Map<number, Set<string>>()

  /** Report each host once per block: the deltas and the assembled block carry the same text. */
  const report = (index: number, hosts: readonly string[]): void => {
    let seen = reported.get(index)
    if (seen === undefined) {
      seen = new Set()
      reported.set(index, seen)
    }
    for (const host of hosts) {
      if (seen.has(host)) continue
      seen.add(host)
      onNeutralized(host)
    }
  }

  /** Emit whatever one block is still holding, so a close or a finish loses nothing. */
  function* flush(index: number): Generator<StreamChunk> {
    const pending = held.get(index)
    held.delete(index)
    if (pending !== undefined && pending.length > 0) yield { type: 'text-delta', index, text: pending }
  }

  for await (const chunk of source) {
    switch (chunk.type) {
      case 'text-delta': {
        const { text, hosts } = neutralizeRemoteImages((held.get(chunk.index) ?? '') + chunk.text)
        report(chunk.index, hosts)
        const cut = heldSuffixStart(text)
        held.set(chunk.index, text.slice(cut))
        if (cut > 0) yield { ...chunk, text: text.slice(0, cut) }
        break
      }
      case 'block-end': {
        yield* flush(chunk.index)
        if (chunk.block.type !== 'text') {
          yield chunk
          break
        }
        const { text, hosts } = neutralizeRemoteImages(chunk.block.text)
        report(chunk.index, hosts)
        yield text === chunk.block.text ? chunk : { ...chunk, block: { ...chunk.block, text } }
        break
      }
      case 'finish': {
        for (const index of [...held.keys()]) yield* flush(index)
        yield chunk
        break
      }
      default:
        yield chunk
    }
  }
  // Only a stream that ended without a terminal finish reaches this: the
  // grammar forbids emitting after one, so the flush above already ran.
  for (const index of [...held.keys()]) yield* flush(index)
}
