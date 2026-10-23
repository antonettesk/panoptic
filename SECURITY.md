# Security Policy

Panoptic is security software that runs with elevated privileges, so we take vulnerabilities in it very seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ |
| Older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately through [GitHub Security Advisories](../../security/advisories/new) (**Security → Report a vulnerability**). Please include:

- the affected version and operating system;
- the impact, for example privilege escalation, code execution, detection bypass, or a crash during scanning;
- reproduction steps or a proof of concept;
- any suggested fix.

We will:

1. acknowledge your report within **3 business days**;
2. confirm the issue and agree a disclosure timeline with you, normally **90 days or less**;
3. release a fix and publish an advisory crediting you, unless you prefer to remain anonymous.

## Scope

In scope:

- Vulnerabilities in Panoptic code: the core engine, CLI, desktop shell and installers.
- Unsafe handling of untrusted data. This includes registry values, file contents, process names and command lines, and report files rendered as HTML.
- Detection bypasses caused by a bug in Panoptic's logic.

Out of scope:

- Generic rootkit techniques that defeat all user-mode tools. These are a known limitation of any live-response tool; please discuss them in a regular issue.
- Vulnerabilities in third-party dependencies with no demonstrated impact on Panoptic. Please report those upstream.

## Hardening notes

- Scanning is read-only. Process actions and scheduling require explicit, confirmed user action.
- Panoptic makes no outbound network connections and has no telemetry or auto-update channel.
- Every string from the scanned system is escaped before it is rendered in HTML reports. CSV exports neutralise spreadsheet formula injection.
- Scheduled-scan commands are built from validated paths. Shell metacharacters are rejected.
