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

## Contexts attached to a result

A tool result can carry `additionalContexts` — `UserMessage`s the agent loop hands to the inbox,
which appends an `agent/inbox/spliced` event carrying the whole message and presents it at the
next step. They are model-visible *and* durable, so they are scanned like anything else. They
arrive from two places, and only one of them is reachable:

| Where it came from | What the plugin can do |
|---|---|
| the `tools/post-execute` decision this plugin returns | redacted in place |
| deferred by the tool body (`exec.deferContext`) | withheld, because no accept arm can rewrite or drop it |

Redacting a downstream listener's contexts is a rewrite of another listener's data. It is the
same thing the value arm already does to a downstream `accept{content}`, it costs a placeholder
rather than a lost result, and the alternative — blocking a successful result because a listener
attached a dirty note — is heavier than what it buys.

The deferred half has no such choice. `postExecute` builds every accept arm as
`[...result.additionalContexts, ...decision.additionalContexts]`, so a context the tool body
deferred rides through untouched whatever the decision says; a `block` exposes only the blocking
decision's own. That is `meta`'s position exactly, and it takes `meta`'s answer. This is the one
place where scanning contexts can cost a successful result, and Code Mode's parallel tool calling
re-defers a nested result's contexts onto the outer one, so it is not a rare shape.

Within one message, the model-facing `content` blocks and the text its `source` records are
redacted together: a `snapshot` source repeats the block text in `sections[].text` and a `notice`
source repeats its opening in `summary`, both of which go into the log with the message.
Redacting the blocks alone would leave a copy. The same scan and the same key run over both, so
identical text yields an identical placeholder and the copies stay in step. A message's `id` and
`role`, and its source's `kind`, `form` and `plugin`, say what the message *is* rather than what
it says, and are left alone.

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

## Context spliced into a step

A tool result is not the only text that reaches the model. The agent loop dispatches
`agent/pre-step` as a waterfall and appends whatever `messages` it returns to the session log
one by one, then derives the next request from the log — so a listener on that waterfall adds
model-visible, durably logged text without any tool call happening. Several shipped packages
do exactly that:

| Package | What it splices in |
|---|---|
| `@deepseek-ai/dsh-agent-instructions` | the workspace `AGENTS.md` / `CLAUDE.md` chain |
| `@deepseek-ai/dsh-tmux-context` | captured terminal pane text |
| `@deepseek-ai/dsh-hooks-claude-code`, `@deepseek-ai/dsh-hooks-codex` | a hook command's `additionalContext` |
| `@deepseek-ai/dsh-tool-skill` | the skill body a `/name` token asked for |

None of that passes `tools/post-execute`. A `.env` value pasted into a repository's `AGENTS.md`,
or a Tags-block instruction hidden in one, reached the provider and the durable log in the
clear. `stepContextRedaction` scans the same text with the same two tiers and the same
invisible-character classes as a tool result, and replaces it with the same placeholder.

The listener registers with `{ prepend: true }` for the reason the result and telemetry seams
do, and carries the same limit: a listener registering later with the same option lands ahead
of it again.

## Input the loop claimed from the inbox

The spliced context is only half of what enters a step. The other half is what the loop claimed
from the inbox, and most of that is not the user typing either:

| Package | What it puts in the inbox, and how | `source.kind` |
|---|---|---|
| `@deepseek-ai/dsh-webhook` | a verified third party's delivery payload, with `agent.followup()` | `webhook` |
| `@deepseek-ai/dsh-subagent` | an agent-to-agent relay and a settled subagent result, with `steer()`, `followup()` and `inject()` | `agent-message`, `subagent-settled` |
| `@deepseek-ai/dsh-goal-round-driver` | each goal round's prompt, with `followup()` and an inbox prepend | `goal` |
| any plugin calling `agent.inject()`, `steer()` or `followup()` | model-facing context of its own | that plugin's own kind |

A `UserMessage` a tool result carries as an `additionalContext` also travels through the inbox,
so it passes this seam on its way to the step; the `tools/post-execute` pass above already
redacts the ones it can reach, and this one covers the same text at the claim. Context a
listener splices straight into the pre-step decision — the instruction chain, the skill catalog,
a `/name` skill body — never enters the inbox at all and belongs to `stepContextRedaction`.

The webhook case is the one this exists for: the payload is attacker-supplied text carrying
whatever a hidden-instruction run or a leaked credential rides in on, and it reaches the model
with no tool call and no waterfall splice. `claimedInputRedaction` scans it with the same two
tiers, the same invisible-character classes and the same placeholder as everything else here.

**The user's own typing is exempt below `aggressiveness: high`, and it is the only exemption.**
A message whose `source.kind` is `user` is passed through untouched at `low` and `medium`. That
value is what every interactive entry point supplies — a CLI task, an ACP prompt, an SDK prompt,
and a browser prompt, whose source adds `rpcId` beside the same `kind`. `MessageSourceMap` is
merge-extensible, so the rule is one allowed value rather than a list of denied ones: a source
kind from a package this plugin has never heard of is scanned rather than trusted. Two producers
borrow `kind: 'user'` for a subagent's opening prompt, which the parent model composed; those
stay exempt too, and ADR §30 says why guessing a finer discriminant would be worse.

### The user's own typing, at `high`

At `aggressiveness: high` the exemption stops applying and a typed prompt is scanned like any
other message. The reason is one this plugin cannot reason its way around: **it does not know
where the model is.** The provider comes from the deployment's model selection, it can be any
OpenAI-compatible base URL, and it can change between turns. A card number a person typed on
purpose is cardholder data at whatever endpoint the request reaches.

Because it is a deployment judgement rather than a detection question, it is a deployment
setting — see [Aggressiveness](configuration.md#aggressiveness) for when to turn it on and what
it costs. Three things it does not reach:

- **tool arguments**, which are never rewritten anywhere in this plugin;
- **the `agent/inbox/spliced` delivery record**, which keeps every claimed message's original
  text, so the session log on disk holds what the user typed. Nothing derives a model message
  from that event, so nothing is sent anywhere;
- **anything before the claim** — the web client's queue view renders that same record.

One channel it does reach beyond the turn's own request, measured rather than assumed: the
harness builds its session-title request from the session's human messages, which are the
redacted `user/message` surface events, so the title request carries the placeholder too.

The audit record names `user` in `claimedSources`, so an operator can tell a redacted prompt from
a redacted webhook delivery.

### What the durable log holds

Redaction runs at the claim, inside `agent/pre-step`. The loop then appends every message the
decision carries as a `user/message` event, and that event is the surface the request is
derived from — so the model-visible durable copy is the redacted one, exactly as for a tool
result.

The delivery record is a different event and keeps the original. `agent/inbox/spliced` commits
when the message enters the inbox, before any seam runs, and no plugin can rewrite a committed
event. It is not one of the three surface event types, so it derives no model message and no
request is built from it. **That asymmetry is chosen, not tolerated**: for a webhook payload the
operator investigating an incident needs to read what a third party actually delivered, and this
plugin is read-side with respect to the session log, so the delivery record is the only durable
place that account survives.

Two consequences of redacting at the claim rather than at delivery:

- a resumed session rebuilds pending inbox state from the delivery records, so a delivery that
  was never claimed comes back with its original text — and is redacted again when it is
  claimed;
- the web client's queue view is fed from `agent/inbox/spliced`, so a delivery still waiting in
  the queue is shown unredacted until the loop claims it.

Both passes drive one listener, which registers when either toggle is on, and the scan is joint
across every in-scope message, so a secret split between a delivered payload and a workspace
instruction file is found. The exempt prompt is not part of the joined rendering. The audit
record names the source kinds a pass covered in `claimedSources`, present only when the pass
covered claimed input.

## Detection

Two tiers:

- **Tier 1**, synchronous and owned by this package: prefix-anchored token formats (AWS,
  GitHub, GitLab, Slack, Stripe, OpenAI, OpenRouter, Anthropic, Google API keys and
  `GOCSPX-` OAuth client secrets, npm, HuggingFace, Groq, xAI, Databricks, SendGrid,
  Supabase, Cloudflare, Notion), PEM private-key blocks, JWTs, credential-bearing URLs,
  Slack/Discord/Teams webhook URLs, high-signal secret assignments, and payment card numbers.
  This is the tier the guard and the telemetry listener use, because both of those seams are
  synchronous, and it is never capped.

  Prefix-anchored is the whole criterion for being in this tier, and the reason the table keeps
  growing rather than deferring to tier 2 is the line below: **the telemetry seam cannot reach
  tier 2**, so a format missing from tier 1 is exported in the clear when telemetry is on.

  A superseded format stays in the table beside the one that replaced it. Supabase's `sbp_`
  keys are deprecated rather than switched off, so a credential in that format is still live;
  removing the rule would also make every audit record already carrying its id
  uninterpretable. GitHub App installation tokens are the same case one format newer: the
  stateless `ghs_<app id>_<JWT>` form GitHub rolled out through June 2026 is matched beside the
  40-character opaque form, which is not revoked and stays valid until it expires. Cloudflare's pre-2026 tokens go the other way: a bare 40-character
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

### Payment card numbers

`dsh-dlp/payment-card-number` is the one tier-1 rule with no prefix to anchor on. Neither tier
had any card rule before 0.10.0 — `@secretlint/core`'s recommended preset registers 28 rules and
none of them is one — so a card number reached the model and the log through every seam.

A match must pass three tests, not one:

1. an **issuer range** — Visa, Mastercard including the 2-series, American Express, Discover,
   JCB, Diners Club, UnionPay;
2. **at a length that issuer assigns**, which is what stops a 4-prefixed order id of the wrong
   length;
3. the **Luhn check digit**.

It reads a number written plainly (`4111111111111111`) or printed in groups of three to six
digits separated by single spaces or hyphens (`4111 1111 1111 1111`, `3782 822463 10005`), and
it reports exactly the number — a card number typed beside its expiry date leaves the expiry
alone.

**Severity is `medium`, deliberately.** The guard floor denies at `high` and above, and a denial
from this rule could not be overridden by anyone. Its false positives are ordinary long numbers
rather than malformed credentials, so it redacts and audits rather than blocking. A deployment
that wants the denial raises the severity from its repo-local policy.

Measured against text that is not cardholder data: **zero** findings across the 272,635 lines
(16.9 MB) of the `deepseek-harness` checkout, none in this package's own sources and docs beyond
the published test numbers quoted there on purpose, and zero against epoch timestamps at every
resolution, ISO-8601 timestamps, `Math.random()` printouts, floats in JSON, ISBN-13 and IPv4
addresses. Against *uniformly random* digit runs the rate is structural and irreducible —
2.7% of random 16-digit runs, because one run in ten satisfies Luhn and about a quarter of the
space opens on an issuer range. Ordinary text does not contain uniformly random 16-digit numbers;
if yours does, that is the number to weigh.

**Maestro is not covered.** Its ranges run from `50` and `56`-`58` through a bare leading `6` at
lengths from 12 to 19, which is most of the six-prefixed numeric space at most of the lengths an
identifier uses; including it would cost more ordinary text than it catches.

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
| clean Latin-1 text | 0.33 ms |
| one hidden instruction (69 characters) | 0.355 ms |
| 7,653 separate runs | 7.9 ms |
| 512 KB of alternating invisible characters (524,286 runs) | 56–113 ms |

Clean text costs a third of a millisecond rather than nothing, and the split is worth stating.
The six character-class rules **are** free: every character they name is above `U+00FF`, so the
combined-class pass rejects a Latin-1 string on its encoding without scanning it — 0.0006 ms
over the same 512 KB. The `control-sequence` class cannot be expressed as a character range,
its body is ASCII, and it is therefore scanned over the whole input whatever the input holds;
that pass alone is 0.20 ms and is what the first row measures. The last row is a crafted input,
not a plausible one, and it is the only case that leaves the ≤10 ms per result budget;
`maxScanBytes` caps tier 2 only, so tier 1 always sees the whole result.

Measured cost of a tier-2 scan: 0.78 ms at 1 KB, 0.91 ms at 16 KB, 2.22 ms at 128 KB, 5.11 ms
at 512 KB. `maxScanBytes` caps **tier 2 only**, once per result, over the joined rendering;
tier 1 always scans everything. When tier 2 saw less than the whole result the audit record
says `truncatedScan: true`, and that record is written even when nothing was found, so a
partial scan never looks like a clean one.

### Why there is no entropy rule

The argument is arithmetic first and measurement second.

Shannon entropy of a string of length L is bounded by log₂L, because L characters cannot carry
more than L distinct symbols. So a threshold of *t* bits per character is also a **length floor**:
no string shorter than 2^*t* characters can reach it, whatever it holds. A 20-character token
cannot score above 4.32 bits per character even if every character in it is different. Picking a
threshold picks the shortest secret the rule could ever catch, and the two cannot be traded
against each other.

The measurement decides where that floor lands in practice.

**Corpus.** Two, so the answer does not hang on one tree:

1. this package's own installed tree — `src/`, `tests/`, `package.json`, `pnpm-lock.yaml` and
   `node_modules/`, which `pnpm-lock.yaml` pins exactly. It holds what a `read` or a `grep`
   returns in a JavaScript repository: source, shipped and minified bundles, the lockfile's
   base64 SHA-512 integrity hashes, hex digests and UUIDs. These docs are deliberately left out
   of it, so editing the page cannot move the number the page reports;
2. a checkout of the harness itself — `packages/` and `apps/`.

**Method.** A candidate token is a maximal run of `[A-Za-z0-9+/=_-]` of at least 16 characters —
the alphabet of base64, hex and every common token format, which is what a published entropy
scanner tokenizes on. Each token scores Shannon entropy over its own character frequencies.
Symbolic links are skipped, so a pnpm tree counts each real file once. Two rates are reported per
threshold: the share of candidate tokens flagged, and the share of files carrying at least one
flagged token — the second being the one that says how often a tool result would come back with a
spurious placeholder in it.

`scripts/measure-entropy.mjs` is the whole of it:

```sh
node scripts/measure-entropy.mjs src tests package.json pnpm-lock.yaml node_modules
```

**Result**, on an i9-12900H under Node 22.23.2:

| Corpus | Files | Candidate tokens | Lowest false-positive-free threshold | Its length floor |
|---|---|---|---|---|
| this package's installed tree | 3,572 | 217,651 | 6.03 bits/char | **66 characters** |
| the harness checkout | 10,294 | 393,485 | 5.99 bits/char | **64 characters** |

A rule set at either threshold cannot fire on anything shorter than 64 characters. Almost
every format tier 1 matches is shorter than that: an AWS access key id is 20 characters, a
Stripe `sk_live_` key 32, a GitHub `ghp_` token 40, a Slack bot token 56. The rule would fire on
PEM bodies and long base64 blobs — which the PEM and JWT rules already match by their
delimiters — and on nothing else.

Lowering the threshold to buy a shorter floor stops being free immediately:

| Threshold | Length floor | Tokens flagged (this tree / harness) | Files hit (this tree / harness) |
|---|---|---|---|
| 6.03 / 5.99 | 66 / 64 | 0.00% / 0.00% | 0.00% / 0.00% |
| 5.60 | 49 | 0.03% / 0.00% | 0.98% / 0.03% |
| 5.00 | 32 | 0.17% / 0.00% | 1.26% / 0.03% |
| 4.46 | 23 | 0.58% / 0.06% | 3.98% / 0.72% |
| 4.20 | 19 | 5.25% / 0.75% | 16.13% / 12.76% |
| 4.00 | 16 | 16.09% / 8.67% | 38.07% / 35.56% |

A 22-character floor costs 4.46 bits per character, where roughly one file in 25 already carries
a spurious match. A 16-character floor — the shortest that reaches most token formats — puts one
in better than a third of them.

That is the whole case: an entropy rule cheap enough in false positives to ship catches only
strings longer than every format this package cares about, and one short enough to catch them is
not cheap enough to ship. Either way it adds no detection the prefix rules do not already make.

---
