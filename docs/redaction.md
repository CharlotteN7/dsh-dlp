---
title: Redaction and detection
nav_order: 5
---

# Redaction and detection

[← dsh-dlp docs](index.md)

## What gets redacted

A redacted region becomes:

```
[REDACTED:dsh-dlp:slack-token:ca9cad27f2b5]
```

The hash is `HMAC-SHA256(installation key, replaced text)` truncated to 12 hex characters. It
is **stable**: the same secret produces the same placeholder everywhere, so an operator can see
that one token appeared in four different tool results without the plugin ever writing the
token down.

For a successful tool result the plugin replaces the canonical `value`, which makes the registry
re-validate the tool's `output.schema`, re-run `output.render()` and re-derive
`presentationMeta()` — so the value, the model-facing content and the persisted card are all
redacted from one replacement. That arm is not a preference: the alternative, replacing
`content`, leaves `{...result}` in place, and `value` and `meta` go into the session log
exactly as the tool produced them. A successful result therefore never settles for the content
arm, which is used only for a failed result (where replacing the value throws) or where the
persisted surfaces are already clean.

When neither works — a failed result whose `meta` carries a secret, or a value that still scans
dirty after redaction — the result is **withheld**: the plugin returns a `block` decision, the
model gets an error naming the rule and the hash, and nothing dirty reaches the log. Blocking
is the only decision that replaces the whole result, so it is the only way to drop `meta`.

Two consequences worth knowing:

- Replacing a value re-validates it against the tool's `output.schema`, and a schema that pins
  that string — an `enum`, a `const`, a `oneOf` branch it selects — would reject the
  placeholder. The plugin asks that question first and withholds the result with the message
  above, rather than letting the registry raise a `ToolOutputError` that names a validation
  failure and tells the model nothing it can act on. The call still fails; it fails
  comprehensibly. Where the plugin cannot answer the question — no schema resolved, or a
  schema whose own value it cannot validate — the registry decides as before.
- Redaction is per-detection, and each span grows to the nearest delimiter — whitespace,
  quotes, `=`, `:`, `,`, brackets. A line of minified JSON loses the field that matched, not
  the whole line.

Replacement runs before the `tool/result` session event is appended, so the durable log records
the redacted copy.

## Detection

Two tiers:

- **Tier 1**, synchronous and owned by this package: prefix-anchored token formats (AWS,
  GitHub, GitLab, Slack, Stripe, OpenAI, OpenRouter, Anthropic, Google API keys and
  `GOCSPX-` OAuth client secrets, npm, HuggingFace, Groq, xAI, Databricks, SendGrid,
  Supabase, Cloudflare, Notion), PEM private-key blocks, JWTs, credential-bearing URLs,
  Slack/Discord/Teams webhook URLs, and high-signal secret assignments. This is the tier the
  guard and the telemetry listener use, because both of those seams are synchronous, and it is
  never capped.

  Prefix-anchored is the whole criterion for being in this tier, and the reason the table keeps
  growing rather than deferring to tier 2 is the line below: **the telemetry seam cannot reach
  tier 2**, so a format missing from tier 1 is exported in the clear when telemetry is on.

  A superseded format stays in the table beside the one that replaced it. Supabase's `sbp_`
  keys are deprecated rather than switched off, so a credential in that format is still live;
  removing the rule would also make every audit record already carrying its id
  uninterpretable. Cloudflare's pre-2026 tokens go the other way: a bare 40-character
  alphanumeric string has no prefix to anchor on, so the legacy format is tier 2's and only the
  `cfut_`/`cfat_`/`cfk_` scannable format is here.

  A key a provider means to publish is deliberately absent. Supabase's `sb_publishable_` is the
  browser-facing replacement for `anon` and ships in every frontend bundle, so matching it would
  cost a denial for something that is not a secret — the same reason this table has always
  matched Stripe's `sk_live_` and not `pk_live_`.
- **Tier 2**, [`@secretlint/core`](https://github.com/secretlint/secretlint) with the
  recommended preset — 28 maintained rules, in-process, no subprocess. Used at
  `tools/pre-execute` and `tools/post-execute`, the two seams that can await. **The telemetry
  seam cannot reach it**: `session-telemetry/record` returns a record synchronously, so a
  secret only secretlint recognises survives telemetry export.

A tool result is scanned twice: each of its strings on its own by tier 1, and all of them
joined by newlines through both tiers. The joined pass finds what no single string reproduces —
a PEM block arriving as one line per array element, which is exactly the shape `read` produces.

### Invisible characters

Tier 1 also looks for characters that hide text from the person reading a tool result while
the model still reads it. The harness strips directional controls in exactly one place —
session titles — and never on the tool-result path.

| Class | Code points | What happens |
|---|---|---|
| Tags block | `U+E0000–U+E007F` | replaced |
| Bidi overrides and isolates | `U+202A–U+202E`, `U+2066–U+2069` | replaced |
| Zero-width | `U+200B–U+200D`, `U+2060`, `U+FEFF` | counted only |
| Bidi marks | `U+061C`, `U+200E–U+200F` | counted only |
| Variation selectors, 1–3 in a row | `U+FE00–U+FE0F`, `U+E0100–U+E01EF` | counted only |
| Variation selectors, 4 or more in a row | the same class | replaced |
| Terminal control sequences | CSI, OSC, DCS, SOS, PM, APC, other `ESC` forms, C1 `U+0080–U+009F` | counted in tool results, **replaced in the audit sink** |

The first two have no legitimate use in tool output — the Tags block is a full invisible ASCII
alphabet, which is what makes it the standard carrier for a hidden instruction. The last three
do: `U+200D` joins an emoji sequence and a variation selector picks a glyph, so replacing them
would corrupt ordinary text. They are counted in the audit record's `unicode` field and left
alone, as a `medium` finding.

Every class is `medium`, below the severity at which the guard floor denies, so an invisible
character is never turned into a denial. A replaced run becomes an ordinary placeholder and,
unlike a secret, is replaced exactly: an invisible character is not widened to its surrounding
delimiters, so the visible word it hid inside survives.

**Variation selectors are split by run length.** One selector picks a glyph — VS15/VS16 after a
base character, one selector after one ideograph in an Ideographic Variation Sequence — so an
isolated occurrence stays counted-only. A run of four or more is not glyph selection: it is a
byte string wearing the same code points, which is how GlassWorm hid executable JavaScript
across five waves. An emoji ZWJ sequence separates its
selectors with a joiner, so no legitimate sequence produces a run at all; four is a conservative
floor, and a real payload is hundreds of selectors long.

**Terminal control sequences are split by lane rather than by class.** A tool result carrying
SGR colour codes is the normal output of `git diff`, `rg` and `pytest`, so on that lane the
class is counted and left alone. On the lane that ends in an audit record it is **replaced**
with `[REDACTED:dsh-dlp:control-sequence]`, because a record is evidence and evidence must not
be able to rewrite itself: `JSON.stringify` escapes the byte in the file, but `dsh-dlp report`,
`jq -r` and every log viewer parse it back into a live escape, so a tool registered under a name
containing `ESC [ 1 A ESC [ 2 K` could overwrite the audit line describing it. The whole CSI
form is matched, not the SGR subset, along with OSC, DCS, SOS, PM, APC, the other escape forms
and the 8-bit C1 controls; an unterminated OSC is matched to the end of the string, because that
is how much of the display it would swallow. A repo-local `policyFile` whose rule `id` carries
one is rejected outright, since a rule id is quoted in the denial the user reads.

Not covered: a bare `\r`, `\b` or `\f` can still overprint a line on a terminal. Those have
ordinary uses in tool output and are escaped by `JSON.stringify` in the sink; the escape-driven
forms above are the ones with no benign use in a record.

**A homoglyph defeats all of this**, and every other rule in this plugin. A Cyrillic `а` in
`аdmin` is a normal, visible, legitimately-encoded character; detecting it means UTS #39
confusable tables, which is a data set and a different cost class. This plugin does not attempt
it, and no rule here should be read as covering it.

Measured cost of the invisible-character scan over 512 KB, median of 30 runs on an i9-12900H
under Node 22.23.2:

| Input | Cost |
|---|---|
| clean Latin-1 text | 0.002 ms |
| one hidden instruction (69 characters) | 0.355 ms |
| 7,653 separate runs | 7.9 ms |
| 512 KB of alternating invisible characters (524,286 runs) | 56–113 ms |

Clean text is free because every character in the table is above `U+00FF`: the regular
expression engine rejects a Latin-1 string on its encoding without scanning it. The last row is
a crafted input, not a plausible one, and it is the only case that leaves the ≤10 ms per result
budget; `maxScanBytes` caps tier 2 only, so tier 1 always sees the whole result.

Measured cost of a tier-2 scan: 0.78 ms at 1 KB, 0.91 ms at 16 KB, 2.22 ms at 128 KB, 5.11 ms
at 512 KB. `maxScanBytes` caps **tier 2 only**, once per result, over the joined rendering;
tier 1 always scans everything. When tier 2 saw less than the whole result the audit record
says `truncatedScan: true`, and that record is written even when nothing was found, so a
partial scan never looks like a clean one.

---
