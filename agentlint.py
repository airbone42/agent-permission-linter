#!/usr/bin/env python3
"""agentlint: find over-broad permissions in AI coding agent and MCP configurations.

Checks Claude Code settings (settings.json, settings.local.json, ~/.claude.json), MCP configs
(.mcp.json, Cursor, VS Code, Claude Desktop) for things like bypass mode, `Bash(*)`, literal tokens,
unpinned server packages and privileged containers. Read-only, no network, standard library only.

Usage:
  agentlint.py                 scan the current project and the user's home configs
  agentlint.py PATH [PATH ...] scan the given files or project directories
  agentlint.py --json          machine-readable output
  agentlint.py --fail-on high  exit 1 if a finding of this severity or worse exists (default: high)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.1.0"
# Companion guide, printed once below the report (German page when the locale is German).
# AGENTLINT_GUIDE_URL overrides it; set it empty to hide the line.


def _default_guide_url():
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        val = os.environ.get(var, "")
        if val:
            break
    else:
        try:  # Windows and others without locale variables, e.g. "German_Germany" or "de_DE"
            import locale
            val = locale.getlocale()[0] or ""
        except Exception:
            val = ""
    german = val.lower().startswith(("de", "german"))
    return "https://tobiaszander.de/agent-gates/" + ("de/" if german else "")


GUIDE_URL = os.environ.get("AGENTLINT_GUIDE_URL", _default_guide_url())

SEVERITIES = ["info", "low", "medium", "high"]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    where: str
    message: str
    fix: str


# ---------------------------------------------------------------- discovery

PROJECT_FILES = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
]


def home_files(home: Path) -> list[Path]:
    return [
        home / ".claude/settings.json",
        home / ".claude.json",
        home / ".cursor/mcp.json",
        home / ".config/Claude/claude_desktop_config.json",
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        Path(os.environ.get("APPDATA", str(home / "AppData/Roaming"))) / "Claude/claude_desktop_config.json",
    ]


def discover(paths: list[str], include_home: bool) -> list[Path]:
    found: list[Path] = []
    targets = [Path(p) for p in paths] or [Path.cwd()]
    for t in targets:
        if t.is_file():
            found.append(t)
        elif t.is_dir():
            found += [t / f for f in PROJECT_FILES if (t / f).is_file()]
    if include_home:
        found += [p for p in home_files(Path.home()) if p.is_file()]
    seen, out = set(), []
    for p in found:
        r = p.resolve()
        if r not in seen:
            seen.add(r)
            out.append(p)
    return out


# ---------------------------------------------------------------- helpers

SECRET_PATTERNS = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "GitLab token"),
    (re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "OpenAI-style API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}"), "Stripe live key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
]
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH)", re.I)
PLACEHOLDER = re.compile(r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\{input:[^}]+\}|<.*>|x+|\*+|changeme|your[-_ ].*|)$", re.I)

# Bash prefixes that are effectively "run anything" or reach outside the sandbox.
ANY_CODE = {"bash", "sh", "zsh", "fish", "python", "python3", "node", "deno", "bun", "ruby", "perl", "php",
            "eval", "exec", "xargs", "env", "npx", "uvx", "pipx", "make", "sudo", "su", "doas"}
REMOTE = {"ssh", "scp", "rsync", "curl", "wget", "nc", "ncat", "socat", "kubectl", "aws", "gcloud", "az",
          "terraform", "tofu", "docker", "podman", "gh"}
DESTRUCTIVE = {"rm", "dd", "mkfs", "chmod", "chown", "git push", "git reset", "git clean"}

SHELL_SERVERS = re.compile(r"(desktop-commander|mcp-server-commands|server-shell|mcp-shell|shell-server|"
                           r"terminal|cli-mcp-server|mcp-server-docker|kubernetes)", re.I)
LOCAL_HOST = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([:/]|$)", re.I)


def mask(s: str) -> str:
    return s[:4] + "…" + f"({len(s)} chars)" if len(s) > 8 else "…"


def looks_secret(name: str, value: str) -> str | None:
    for pat, label in SECRET_PATTERNS:
        if pat.search(value):
            return label
    if SECRET_NAME.search(name) and not PLACEHOLDER.match(value.strip()) and len(value) >= 12 \
            and not value.startswith(("http://", "https://", "/", "~")):
        return "value of " + name
    return None


def bash_prefix(rule: str) -> str | None:
    """'Bash(git push:*)' -> 'git push'; 'Bash' / 'Bash(*)' -> '*'."""
    m = re.fullmatch(r"\s*Bash\s*(?:\((.*)\))?\s*", rule)
    if not m:
        return None
    inner = (m.group(1) or "*").strip()
    inner = re.sub(r"(:\*|\s\*|\*)$", "", inner).strip()
    return inner or "*"


def is_wildcard(rule: str) -> bool:
    """Bash and Bash(*) and Bash(x:*) / Bash(x *) accept arbitrary further arguments."""
    m = re.fullmatch(r"\s*Bash\s*(?:\((.*)\))?\s*", rule)
    inner = ((m.group(1) if m else "") or "*").strip()
    return inner.endswith("*")


# ---------------------------------------------------------------- Claude Code settings

def check_settings(path: str, data: dict, scope: str, out: list[Finding]) -> None:
    perms = data.get("permissions") or {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        out.append(Finding("CC001", "high", path, f"{scope}permissions.defaultMode",
                           "Bypass mode: the agent runs every tool without asking, including shell and network.",
                           "Use 'default' or 'acceptEdits' and allow specific commands instead."))
    if data.get("skipDangerousModePermissionPrompt") or data.get("dangerouslySkipPermissions"):
        out.append(Finding("CC001", "high", path, f"{scope}skipDangerousModePermissionPrompt",
                           "The bypass-mode warning is switched off.",
                           "Remove the flag so bypass mode always needs a deliberate opt-in."))
    if data.get("enableAllProjectMcpServers"):
        out.append(Finding("CC008", "medium", path, f"{scope}enableAllProjectMcpServers",
                           "Every MCP server defined in a cloned repo's .mcp.json starts without review.",
                           "Set to false and approve servers per project (enabledMcpjsonServers)."))
    allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
    deny = [d for d in perms.get("deny") or [] if isinstance(d, str)]
    has_webfetch_any = False
    broad_shell = False
    for i, rule in enumerate(allow):
        where = f"{scope}permissions.allow[{i}] = {rule!r}"
        pre = bash_prefix(rule)
        if pre == "*":
            broad_shell = True
            out.append(Finding("CC002", "high", path, where,
                               "Any shell command is pre-approved; one prompt injection can run arbitrary code.",
                               "List the commands you need, e.g. Bash(npm test), Bash(git status)."))
            continue
        if pre:
            words = pre.split()
            first, two = words[0], " ".join(words[:2])
            wild = is_wildcard(rule)
            # an exact command (no trailing wildcard) only ever runs that command
            if not wild:
                continue
            # 'sudo which:*' is narrower than 'sudo:*'; flag the runner only when its target is open or itself a runner
            if first in ANY_CODE and len(words) > 1 and words[1] not in ANY_CODE:
                first = words[1]
            if first in ANY_CODE:
                broad_shell = True
                out.append(Finding("CC003", "high", path, where,
                                   f"'{first}' with arbitrary arguments runs any code; this is Bash(*) in disguise.",
                                   "Allow the concrete script or target, e.g. Bash(python scripts/check.py)."))
            elif first in REMOTE:
                broad_shell = True
                out.append(Finding("CC003", "medium", path, where,
                                   f"'{first}' with arbitrary arguments reaches other systems (network, cloud, containers).",
                                   "Narrow to read-only subcommands or route changes through a reviewed gate."))
            elif first in DESTRUCTIVE or two in DESTRUCTIVE:
                out.append(Finding("CC003", "medium", path, where,
                                   f"'{two if two in DESTRUCTIVE else first}' can destroy data or history without a prompt.",
                                   "Keep destructive commands behind a prompt."))
            continue
        if rule.strip() == "WebFetch":
            has_webfetch_any = True
        r = rule.strip()
        if r.startswith("mcp__") and ("__" not in r[5:] or r.endswith("__*")):
            out.append(Finding("CC005", "low", path, where,
                               "All tools of this MCP server are allowed, including any write or delete tools it adds later.",
                               "Allow the read tools by name (mcp__server__get_x) and keep write tools behind a prompt."))
        if rule.strip() in ("Write", "Edit", "Write(*)", "Edit(*)", "Write(/**)", "Edit(/**)", "Edit(~/**)", "Write(~/**)"):
            out.append(Finding("CC004", "low", path, where,
                               "File edits are allowed everywhere, including shell profiles and agent settings.",
                               "Scope edits to the project, e.g. Edit(./src/**)."))
    if broad_shell and has_webfetch_any:
        out.append(Finding("CC006", "medium", path, f"{scope}permissions.allow",
                           "Broad shell plus unrestricted WebFetch: an injected instruction can read files and send them out.",
                           "Restrict WebFetch to domains (WebFetch(domain:docs.example.com))."))
    if (allow or mode) and not any(re.search(r"\.env|secret|\.ssh|credential|\.aws", d, re.I) for d in deny):
        out.append(Finding("CC007", "info", path, f"{scope}permissions.deny",
                           "No deny rule for secrets (.env, ~/.ssh, cloud credentials).",
                           "Add e.g. Read(./.env*), Read(~/.ssh/**), Read(~/.aws/**) to permissions.deny."))


# ---------------------------------------------------------------- MCP servers

def check_server(path: str, where: str, name: str, srv: dict, out: list[Finding]) -> None:
    cmd = str(srv.get("command") or "")
    args = [str(a) for a in srv.get("args") or []]
    url = str(srv.get("url") or srv.get("serverUrl") or "")
    line = " ".join([cmd] + args)
    w = f"{where}.{name}"

    for k, v in (srv.get("env") or {}).items():
        label = looks_secret(k, str(v))
        if label:
            out.append(Finding("MCP001", "high", path, f"{w}.env.{k}",
                               f"Literal secret in the config ({label}, {mask(str(v))}). It ends up in backups, "
                               "dotfile repos and every agent that can read this file.",
                               "Reference an environment variable (${VAR}) or a secret store instead."))
    for k, v in (srv.get("headers") or {}).items():
        val = str(v)
        cred = re.sub(r"(?i)^(bearer|basic|token)\s+", "", val).strip()
        if not PLACEHOLDER.match(cred) and (cred != val or looks_secret(k, val)) and len(cred) >= 8:
            out.append(Finding("MCP001", "high", path, f"{w}.headers.{k}",
                               f"Literal credential in a request header ({mask(val)}).",
                               "Use ${VAR} expansion or OAuth instead of a pasted token."))
    for i, a in enumerate(args):
        label = looks_secret("", a)
        if not label and i > 0 and re.search(r"(?i)(token|key|secret|password)", args[i - 1]):
            label = looks_secret(args[i - 1].lstrip("-"), a)
        if label:
            out.append(Finding("MCP001", "high", path, f"{w}.args[{i}]",
                               f"Literal secret on the command line ({label}, {mask(a)}); visible in the process list.",
                               "Pass it via env with ${VAR} expansion."))

    base = os.path.basename(cmd)
    if base in ("npx", "bunx", "pnpm", "yarn") or (base == "npm" and "exec" in args):
        pkgs = [a for a in args if not a.startswith("-") and a not in ("exec", "dlx")]
        if pkgs:
            pkg = pkgs[0]
            ver = pkg.rsplit("@", 1)[1] if pkg.count("@") > (1 if pkg.startswith("@") else 0) else ""
            if not ver or ver in ("latest", "next"):
                out.append(Finding("MCP002", "medium", path, w,
                                   f"Unpinned package '{pkg}': every start runs whatever version was published last.",
                                   f"Pin an exact version, e.g. {pkg.split('@latest')[0]}@1.2.3."))
    if base in ("uvx", "pipx"):
        pkgs = [a for a in args if not a.startswith("-") and a != "run"]
        if pkgs and not re.search(r"(==|@)\d", " ".join(args)):
            out.append(Finding("MCP002", "medium", path, w,
                               f"Unpinned Python package '{pkgs[0]}' for {base}.",
                               f"Pin it, e.g. {base} {pkgs[0]}==1.2.3 (or --from {pkgs[0]}==1.2.3)."))
    if base in ("docker", "podman"):
        image = next((a for a in args[args.index("run") + 1:] if not a.startswith("-") and "=" not in a
                      and not re.match(r"^[\w.\-/]+:/", a)), "") if "run" in args else ""
        if image and ("@sha256:" not in image) and (":" not in image.split("/")[-1] or image.endswith(":latest")):
            out.append(Finding("MCP002", "medium", path, w, f"Container image '{image}' without a fixed tag or digest.",
                               "Pin a version tag or, better, an @sha256 digest."))
        if "--privileged" in args or "--cap-add=ALL" in args:
            out.append(Finding("MCP004", "high", path, w, "Privileged container: root on the host is one step away.",
                               "Drop --privileged; add only the capabilities the server needs."))
        if re.search(r"docker\.sock", line):
            out.append(Finding("MCP004", "high", path, w, "Docker socket mounted: equivalent to root on the host.",
                               "Do not mount the socket into an agent-facing server."))
        if re.search(r"(?:-v|--volume|--mount)[ =](?:type=bind,)?(?:source=)?(/|~|\$HOME|/home|/Users|C:\\)(?::|,|$)", line):
            out.append(Finding("MCP004", "medium", path, w, "Host root or home directory mounted into the container.",
                               "Mount only the project directory, read-only where possible (:ro)."))
        if "--network=host" in args or ("--network" in args and "host" in args) or "--net=host" in args:
            out.append(Finding("MCP004", "low", path, w, "Host networking: the server reaches every local service.",
                               "Use the default bridge network."))
    if re.search(r"server-filesystem|mcp-server-filesystem|filesystem", line, re.I):
        roots = [a for a in args if a.startswith(("/", "~", "C:\\", "$HOME"))]
        for r in roots:
            if r.rstrip("/\\") in ("", "~", "$HOME", "C:") or re.fullmatch(r"/(home|Users)(/[^/]+)?/?", r):
                out.append(Finding("MCP005", "medium", path, w,
                                   f"Filesystem server exposes '{r}' (whole disk or home: SSH keys, browser profiles, tokens).",
                                   "Point it at the project directory only."))
    if SHELL_SERVERS.search(line + " " + name):
        out.append(Finding("MCP006", "medium", path, w,
                           f"Server '{name}' can run commands or control containers/clusters; its tools bypass "
                           "your Bash allow/deny rules.",
                           "Keep its tools behind a prompt and do not combine it with bypass mode."))
    if url.startswith("http://") and not LOCAL_HOST.match(url):
        out.append(Finding("MCP003", "medium", path, w, f"Remote MCP server over plain HTTP ({url.split('?')[0]}).",
                           "Use HTTPS; tokens and tool results travel in clear text otherwise."))


def check_mcp(path: str, data: dict, scope: str, out: list[Finding]) -> None:
    for key in ("mcpServers", "servers"):
        servers = data.get(key)
        if isinstance(servers, dict):
            for name, srv in servers.items():
                if isinstance(srv, dict):
                    check_server(path, f"{scope}{key}", name, srv, out)


# ---------------------------------------------------------------- driver

def lint_file(p: Path) -> list[Finding]:
    out: list[Finding] = []
    path = str(p).replace(str(Path.home()), "~")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [Finding("E000", "info", path, "-", f"Could not parse: {e.__class__.__name__}", "Check the JSON syntax.")]
    if not isinstance(data, dict):
        return out
    check_settings(path, data, "", out)
    check_mcp(path, data, "", out)
    # ~/.claude.json keeps per-project settings and MCP servers under "projects"
    for proj, pdata in (data.get("projects") or {}).items():
        if isinstance(pdata, dict):
            scope = f"projects[{Path(proj).name}]."
            check_mcp(path, pdata, scope, out)
            tools = pdata.get("allowedTools")
            if isinstance(tools, list):
                check_settings(path, {"permissions": {"allow": tools, "deny": ["Read(.env)"]}}, scope, out)
    return out


def render(findings: list[Finding], files: list[Path]) -> str:
    lines = [f"agentlint {VERSION}: {len(files)} file(s) scanned, {len(findings)} finding(s)", ""]
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    for f in sorted(findings, key=lambda f: (order[f.severity], f.file, f.rule)):
        lines.append(f"[{f.severity.upper():6}] {f.rule}  {f.file}  {f.where}")
        lines.append(f"         {f.message}")
        lines.append(f"         fix: {f.fix}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    lines += ["", "summary: " + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES))]
    if not files:
        lines.append("No agent or MCP config found. Pass a path, e.g. agentlint.py ~/.claude/settings.json")
    if GUIDE_URL:
        lines.append(f"Guide to approval gates for AI agents: {GUIDE_URL}?ref=cli")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Find over-broad permissions in AI agent and MCP configs.")
    ap.add_argument("paths", nargs="*", help="files or project directories (default: current directory)")
    ap.add_argument("--no-home", action="store_true", help="do not scan configs in the home directory")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)
    files = discover(a.paths, include_home=not a.no_home and not a.paths)
    findings = [f for p in files for f in lint_file(p)]
    if a.json:
        print(json.dumps({"version": VERSION, "files": [str(f) for f in files],
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(render(findings, files))
    if a.fail_on == "never":
        return 0
    limit = SEVERITIES.index(a.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= limit for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
