---
title: Audit output
nav_order: 6
---

# Audit output

[← dsh-dlp docs](index.md)

One JSON object per line in `auditLog`. Nothing is ever written to the session log: the
harness's `Session.append()` cannot set the envelope's `ignorable` flag, and an out-of-repo
event type makes the user's next resume refuse the whole session. Each record therefore carries
its own identity.

```json
{
  "v": 1,
  "time": "2026-08-15T19:44:33.861Z",
  "kind": "result-redaction",
  "decisionId": "dlp-1e8ab1bb-5c8d-4410-b98d-39b83037ea63",
  "tool": "read",
  "callId": "mock-call-1",
  "rootCallId": "mock-call-1",
  "sessionId": "session-880b9ece-3633-427d-b0a8-cf202ea09917",
  "turn": 1,
  "step": 1,
  "spans": [
    {
      "ruleId": "dsh-dlp/slack-token",
      "ruleVersion": 1,
      "severity": "critical",
      "start": 17,
      "end": 73,
      "hash": "ca9cad27f2b5",
      "path": "/lines/1/text"
    }
  ]
}
```

`kind` is one of `guard-deny`, `pre-execute-deny`, `pre-execute-ask`, `pre-execute-ask-abstained`,
`execution-mutation`, `result-redaction`, `telemetry-redaction`, `assistant-image-neutralized`. A
`pre-execute-ask` record carries a top-level `ruleId` instead of `spans`: the finding is that a
path names a behaviour-changing file, not that any region of it matched. A
`pre-execute-ask-abstained` record carries the same `ruleId` plus `askUnreachable` — one of
`no-service`, `policy-never` or `no-answerer` — and means the tier let the call through because
the approval seam could prompt nobody. It is a separate kind rather than a flag on
`pre-execute-ask` because the report counts by kind, and an ask that reached nobody must not be
counted as a prompt that happened. An `execution-mutation` record carries
`mutatedFields` and, when a tool substitution happened, the `originalTool` the log recorded. An
`assistant-image-neutralized` record carries `host` — the hostname of the blocked destination
and nothing else from the URL.
A `result-redaction` record may also carry `unicode`, a count of invisible-character runs per
class — counts only, because a hidden instruction is exactly the content this file must not
repeat. A record is written whenever there is something to say, including a result that was
only counted and a result whose tier-2 scan was truncated.
A record carries no free-text reason: the spans are the whole description of what matched, so
nothing built from a candidate path or command line can reach the file. An audit write failure
is reported and swallowed rather than turned into a denial: the sink is evidence, not
enforcement, and a full disk should not take the agent down.

The file is kept at **mode 0640** — owner read/write, group read, nothing for anyone else. The
mode is forced with an explicit `chmod` after every append, because `appendFileSync`'s own
`mode` argument applies only when the call creates the file and is masked by the process umask;
under an ordinary account's umask the sink was created 0664. Forcing it on every append also
takes back a loosening applied to an existing file. Nothing in a record is a secret — rule ids,
keyed hashes, tool names, call identity — but the records are the evidence that a decision
happened, and a failure to hold the mode is reported on the same two channels as a failed
write. The redaction key beside it is created 0600, which no umask can widen.

Reported means `process.stderr` **and** `ctx.logger`, for that failure and for an invalid
policy file. The logger alone is not enough: its default exporter is an in-memory 1000-entry
ring buffer and no shipped bundle mounts a console exporter, so a message sent only there is
invisible on a stock install. `process.stderr` is what the headless runner itself writes to.

---

## Reading the audit log

The package installs a `dsh-dlp` command that reads the JSONL sink and summarises it. It
imports nothing from the harness, so it runs wherever the package is installed, with no profile
and no `dsh` on the path:

```sh
dsh-dlp report                      # everything in $DSH_HOME/dsh-dlp.audit.jsonl
dsh-dlp report --since 24h          # or an ISO timestamp
dsh-dlp report --session <id>
dsh-dlp report --would-have         # everything except the denials
dsh-dlp report --log /var/log/dsh-dlp.audit.jsonl
```

It prints counts by decision, by rule, by tool and by invisible-character class, then the ten
most recent decisions. `--would-have` drops exactly the three kinds that stopped a call —
`guard-deny`, `pre-execute-deny` and `execution-mutation` — and keeps everything else: the
redactions and invisible-character findings, which are calls that ran with their results
rewritten, and also the `pre-execute-ask`, `pre-execute-ask-abstained` and
`assistant-image-neutralized` records, which are neither. The sink does not record how a user
answered an ask, so a kept `ask` record is not evidence that call ran — but a
`pre-execute-ask-abstained` record is: no prompt happened and the call went through.

The sink is append-only and a run can be interrupted mid-append, so a line that does not parse
as a record is counted and reported rather than trusted. If the deployment set `auditLog` to
somewhere other than the default, pass `--log`; the command says which file it looked at.

A plugin installed into a profile puts its bin in that profile's `node_modules/.bin`, which is
not on `PATH`. Run it from there, or install the package globally:

```sh
"$DSH_HOME/profiles/<name>/node_modules/.bin/dsh-dlp" report
```

---
