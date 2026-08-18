# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | yes |
| < 0.5 | no |

Only the latest published `0.5.x` receives fixes. There is no long-term-support branch while
the package is pre-1.0: each minor supersedes the one before it, and a fix ships as the next
`0.5.x` patch or, if the minor has already moved on, as the next minor.

## Reporting a vulnerability

Email **nsof@protonmail.com**. Please include:

- what an attacker gets — a credential reaching the model, the session log, the audit sink, or
  the network;
- the smallest reproduction you have, ideally a failing test against this repository;
- the versions of `dsh-dlp`, DeepSeek Harness, and Node you ran.

Do not open a public issue for a vulnerability first.

**Response window:** acknowledgement within 3 working days, an assessment with a fix or a
rejection within 14 days. If a fix ships, the release notes credit the reporter unless asked
otherwise.

## What counts as a vulnerability here

This plugin is **not a containment boundary**. It runs in-process at the agent's own uid, so
anything the agent can execute can read the same files the guard denies. The following are
documented limits, not vulnerabilities — they are described in README.md:

- shell-command obfuscation defeating the `bash` path arm — anything that stops the path being
  spelled in the command line: globbing, quote-splitting, `find -exec`, assembling the path
  from pieces, a base64 round-trip. A command that spells the path is caught whatever program
  it runs, so that is a gap worth reporting;
- encoded or split secrets passing both detection tiers;
- a secret with no recognisable structure going undetected;
- a secret reaching the provider because it was already in the conversation.

These do count, and we want to hear about them:

- a credential path the table should match and does not, in a **path-typed argument**;
- a raw secret, path, or command line written to the audit sink or a log line;
- a secret surviving into the session log through a `tools/post-execute` arm;
- a repo-local `policyFile` loosening any part of the floor, executing code, or stalling the
  agent;
- any way to make the guard abstain that does not require executing code;
- a terminal control sequence, or any other forgeable bytes, reaching the audit sink or a
  denial the user reads.

The `ask` tier for behaviour-changing config paths is **not** part of the floor and is
documented as neutralizable: it lives at `tools/pre-execute`, so a listener registered ahead of
it disables it. A missed path there is a gap worth reporting; the fact that another plugin can
switch the tier off is a stated design limit, not a vulnerability.
