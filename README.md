# agentlint

Find over-broad permissions in AI coding agent and MCP configurations before a prompt injection finds them.

```
$ python3 agentlint.py examples/risky --fail-on never
agentlint 0.1.1: 2 file(s) scanned, 19 finding(s)

[HIGH  ] CC001  examples/risky/.claude/settings.json  permissions.defaultMode
         Bypass mode: the agent runs every tool without asking, including shell and network.
         fix: Use 'default' or 'acceptEdits' and allow specific commands instead.
[HIGH  ] CC003  examples/risky/.claude/settings.json  permissions.allow[0] = 'Bash(python3:*)'
         'python3' with arbitrary arguments runs any code; this is Bash(*) in disguise.
         fix: Allow the concrete script or target, e.g. Bash(python scripts/check.py).
[HIGH  ] MCP001  examples/risky/.mcp.json  mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN
         Literal secret in the config (GitHub token, ghp_…(42 chars)). ...
...
summary: 6 high, 10 medium, 2 low, 1 info
```

Single Python file, standard library only, read-only, no network. Secrets are masked in the output.

## Usage

```bash
python3 agentlint.py                     # current project + configs in your home directory
python3 agentlint.py path/to/repo        # a project directory
python3 agentlint.py ~/.claude.json      # a single file
python3 agentlint.py --json              # for CI
python3 agentlint.py --fail-on medium    # exit 1 on medium or worse (default: high)
```

Scanned files: `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `~/.claude/settings.json`, `~/.claude.json` (incl. per-project servers and allowed tools),
`~/.cursor/mcp.json`, Claude Desktop `claude_desktop_config.json` (Linux, macOS, Windows).

## Rules

| Rule | Severity | What it finds |
|---|---|---|
| CC001 | high | `defaultMode: bypassPermissions`, bypass warning switched off |
| CC002 | high | `Bash` / `Bash(*)`: every shell command pre-approved |
| CC003 | high/medium | open-ended runners (`Bash(python3:*)`, `Bash(sudo:*)`, `Bash(npx:*)`), remote reach (`ssh`, `curl`, `docker`, `kubectl`, cloud CLIs), destructive commands (`rm`, `git push`) with wildcard arguments; exact commands pass |
| CC004 | low | `Edit`/`Write` allowed everywhere, including outside the project |
| CC005 | low | a whole MCP server allowed (`mcp__github`), including write tools it adds later |
| CC006 | medium | broad shell plus unrestricted `WebFetch`: read-and-exfiltrate path |
| CC007 | info | no deny rules for `.env`, `~/.ssh`, cloud credentials |
| CC008 | medium | `enableAllProjectMcpServers`: servers from any cloned repo start unreviewed |
| MCP001 | high | literal tokens in `env`, `headers` or `args` (GitHub, GitLab, Slack, Anthropic, OpenAI, AWS, Google, Stripe, private keys, `*_TOKEN`-style names); variable references (`${VAR}`, `${env:VAR}`, `${input:id}`, `${localEnv:VAR}`) are not flagged |
| MCP002 | medium | unpinned `npx`/`uvx`/`pipx` packages, container images without tag or digest |
| MCP003 | medium | remote MCP server over plain `http://` (not localhost) |
| MCP004 | high/medium/low | `--privileged`, Docker socket, host root/home mounted, host networking |
| MCP005 | medium | filesystem server rooted at `/` or a home directory |
| MCP006 | medium | servers that run shell commands or control containers/clusters (bypass your Bash rules) |

The rules are heuristics. A finding is a question to answer ("do I need this?"), not proof of a vulnerability.

The report ends with a link to my guide on approval gates for AI agents
([tobiaszander.de/agent-gates](https://tobiaszander.de/agent-gates/?ref=gh), German:
[/agent-gates/de/](https://tobiaszander.de/agent-gates/de/?ref=gh), picked automatically with a German locale): how to give agents enough rights to work
without handing them the keys. Set `AGENTLINT_GUIDE_URL=` (empty) to hide it. Nothing is sent anywhere, the link is
only printed.

## Development

```bash
python3 -m unittest discover tests
```

`examples/risky` triggers every rule family, `examples/tight` must stay clean.

## License

MIT
