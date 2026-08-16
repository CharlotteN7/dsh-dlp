# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no |

Only the latest published `0.1.x` receives fixes. There is no long-term-support branch while
the package is pre-1.0.

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

- shell-command obfuscation defeating the `bash` path arm (globbing, quoting, substitution, a
  different binary);
- encoded or split secrets passing both detection tiers;
- a secret with no recognisable structure going undetected;
- a secret reaching the provider because it was already in the conversation.

These do count, and we want to hear about them:

- a credential path the table should match and does not, in a **path-typed argument**;
- a raw secret, path, or command line written to the audit sink or a log line;
- a secret surviving into the session log through a `tools/post-execute` arm;
- a repo-local `policyFile` loosening any part of the floor, executing code, or stalling the
  agent;
- any way to make the guard abstain that does not require executing code.
