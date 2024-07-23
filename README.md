# egressleak

Outbound HTTP egress and context PII auditor for local Claude Code and Codex CLI sessions.

Coding agents read an email address out of `~/.claude.json` and paste it into outbound
`User-Agent` headers or URL query strings when they call third-party APIs. `egressleak`
replays your local `.jsonl` transcripts plus your agent config files and reports what left
the machine, with sensitive values masked in the output.

## Usage

```bash
npx egressleak
```

Fail CI or a pre-commit hook when anything `HIGH` or worse is found:

```bash
npx egressleak --fail-on HIGH
```

Machine-readable output:

```bash
npx egressleak --json
```

## Guardrail hook

An audit tells you what already leaked. To stop the next leak, emit a deterministic
`PreToolUse` hook that blocks the call before it runs:

```bash
npx egressleak --emit-hook
```

The command prints the hook script and the matching `~/.claude/settings.json` fragment
(telemetry opt-out plus the `Bash|WebFetch|WebSearch` matcher). Save the script to
`~/.claude/hooks/egress-guard-hook.mjs` and merge the settings block. The hook exits `2`
with a `BLOCKED` message on a `User-Agent` email, an email in a query string, or a secret
token in an outbound request, and exits `0` on everything else so it never stalls work.

## What it looks at

- `~/.claude.json` — `oauthAccount.emailAddress`, telemetry IDs, remote MCP servers
- `~/.claude/settings.json`, `~/.gitconfig`, `CLAUDE.md`, `AGENTS.md` — hardcoded identities
- `~/.claude/projects/**/*.jsonl`, `~/.codex/sessions/**/*.jsonl` — replayed tool calls

Nothing is written and no network requests are made.

## Rules

| Rule | Severity | What it detects |
| :--- | :--- | :--- |
| `EGL001` | `CRITICAL` | `oauthAccount.emailAddress` in `~/.claude.json` |
| `EGL002` | `HIGH` | Telemetry IDs active without an opt-out |
| `EGL003` | `HIGH` | Remote SSH or network-tunneled MCP server |
| `EGL004` | `MEDIUM` | Email hardcoded in git config or agent instructions |
| `EGL005` | `MEDIUM` | `/Users/<USER>` paths across transcripts |
| `EGL007` | `CRITICAL` | Email in an outbound `User-Agent` |
| `EGL008` | `CRITICAL` | Email in outbound URL query parameters |
| `EGL009` | `CRITICAL` | Bearer token or API key in an outbound request |
| `EGL010` | `HIGH` | Local file uploaded via HTTP POST |
| `EGL011` | `HIGH` | External domain contacted by a tool call |
| `EGL012` | `MEDIUM` | PII in a `WebSearch` query |
| `EGL013` | `MEDIUM` | Real emails persisted in plaintext transcripts |
| `EGL014` | `INFO` | Loopback requests, separated from external egress |

## Redaction
