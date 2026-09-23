"""MCP server: exposes host aliases and operations over stdio. No ports, no listening socket."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server  # type: ignore[attr-defined]
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[no-redef]

from . import __version__, client, guard
from .config import ConfigError, Host, load_hosts, resolve_alias

_mcp = _Server(
    name="ssh-hop",
    version=__version__,
    instructions=(
        "SSH/SFTP access to pre-configured hosts by alias. Always call ssh_list_hosts first to "
        "learn which aliases exist. Hostnames, users and credentials are intentionally hidden. "
        "Each host has allowCommands/denyCommands regex rules; a refusal names the rule that "
        "blocked it, and ssh_run_policy checks a command without running it."
    ),
)

_cache: dict[str, Host] | None = None
_cache_error: str | None = None


def all_hosts() -> dict[str, Host]:
    """Load hosts.json once, caching both success and the failure reason."""
    global _cache, _cache_error
    if _cache is None:
        try:
            _cache = load_hosts()
            _cache_error = None
        except ConfigError as exc:
            _cache_error = str(exc)
            return {}
    return _cache


def host_or_error(alias: str) -> tuple[Host | None, dict[str, Any] | None]:
    known = all_hosts()
    if not known:
        return None, failure(_cache_error or "no hosts configured", "config",
                             hint="Create hosts.json (copy hosts.example.json) then restart the server.")
    try:
        return resolve_alias(known, alias), None
    except ConfigError as exc:
        return None, failure(str(exc), "unknown-host")


def failure(message: str, kind: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "error": message, "kind": kind, **extra}


def ok(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, **payload}


def guard_call(fn, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
    """Run an operation, converting expected failures into a structured result."""
    try:
        return fn(*args, **kwargs)
    except guard.GuardDenied as exc:
        return failure(str(exc), "refused")
    except client.SSHError as exc:
        return failure(str(exc), "ssh")
    except ConfigError as exc:
        return failure(str(exc), "config")
    except Exception as exc:  # unexpected: report type, never a traceback
        return failure(f"{type(exc).__name__}: {exc}", "internal")


# --- tools ------------------------------------------------------------------

@_mcp.tool(
    name="ssh_list_hosts",
    description=(
        "List the remote hosts reachable through this server. Call this first whenever you need "
        "to touch a remote machine, to learn valid aliases and each host's permissions. "
        "Only aliases and descriptions are returned - never addresses or credentials."
    ),
)
def ssh_list_hosts() -> dict[str, Any]:
    known = all_hosts()
    if not known:
        return failure(_cache_error or "no hosts configured", "config")
    return ok({
        "hosts": [known[alias].public() for alias in sorted(known)],
        "note": (
            "commands: 'all' means every command is allowed; a list means only commands matching "
            "one of those regexes run. upload/download: 'any path' or the allowed root list, or "
            "false when disabled."
        ),
    })


@_mcp.tool(
    name="ssh_probe",
    description=(
        "Test connectivity to a host and return its identity (uname, uptime, id) plus round-trip "
        "latency. Use to diagnose 'cannot connect' problems before running real commands."
    ),
)
def ssh_probe(host: str) -> dict[str, Any]:
    target, problem = host_or_error(host)
    if problem:
        return problem
    return guard_call(lambda: ok(client.probe(target)))


@_mcp.tool(
    name="ssh_run",
    description=(
        "Execute a shell command on a remote host and return stdout, stderr and the exit code. "
        "Use for inspecting state (logs, processes, ports, containers, service status) and for "
        "changing it (deploy, restart, edit). Prefer one command per call; chain with && when steps "
        "must be ordered. Set background=true for long-running or daemonizing commands so the call "
        "returns at once. Each host has its own allowCommands/denyCommands rules; a refusal names "
        "the rule that blocked it."
    ),
)
def ssh_run(
    host: str,
    command: str,
    timeout: int | None = None,
    cwd: str | None = None,
    background: bool = False,
) -> dict[str, Any]:
    target, problem = host_or_error(host)
    if problem:
        return problem
    result = guard_call(
        lambda: ok(client.run(target, command, timeout=timeout, cwd=cwd, background=background).to_dict())
    )
    if not result.get("ok"):
        return result
    return ok({"alias": target.alias, **result})


@_mcp.tool(
    name="ssh_run_policy",
    description=(
        "Check whether a command would be allowed on a host, WITHOUT running it. Returns the rule "
        "that matched. Use before a risky or unfamiliar command, or when a previous command was "
        "refused and you want to know why."
    ),
)
def ssh_run_policy(host: str, command: str) -> dict[str, Any]:
    target, problem = host_or_error(host)
    if problem:
        return problem
    try:
        verdict = guard.check_command(target, command)
    except guard.GuardDenied as exc:
        return failure(str(exc), "refused",
                       allowCommands=list(target.allowCommands),
                       denyCommands=list(target.denyCommands))
    return ok({"alias": target.alias, "command": command, "allowed": True, "matchedRule": verdict.rule})


@_mcp.tool(
    name="ssh_run_many",
    description=(
        "Run the same command across several hosts in parallel and return one result per host. Use "
        "to compare versions, check a service fleet-wide, restart several boxes, or survey disk "
        "usage. Each host applies its own allowCommands/denyCommands, so one host may be refused "
        "while others run; per-host status is reported rather than failing the whole call."
    ),
)
def ssh_run_many(
    hosts: list[str],  # noqa: A002 - the name the model sees
    command: str,
    timeout: int | None = None,
    stop_on_error: bool = False,
) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor

    aliases = hosts or []
    if not aliases:
        return failure("pass a non-empty list of host aliases", "usage")
    targets: list[Host] = []
    for alias in aliases:
        target, problem = host_or_error(alias)
        if problem:
            return problem
        targets.append(target)

    def one(target: Host) -> dict[str, Any]:
        try:
            result = client.run(target, command, timeout=timeout)
            return {"ok": True, "status": "ok", "alias": target.alias, **result.to_dict()}
        except guard.GuardDenied as exc:
            return {"ok": False, "status": "refused", "alias": target.alias, "error": str(exc)}
        except client.SSHError as exc:
            return {"ok": False, "status": "ssh-error", "alias": target.alias, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        results = list(pool.map(one, targets))
    if stop_on_error and any(not item["ok"] for item in results):
        first = next(item for item in results if not item["ok"])
        kind = "refused" if first["status"] == "refused" else "ssh"
        return failure(f"{first['alias']}: {first['error']}", kind, results=results)
    return ok({"command": command, "results": results})


@_mcp.tool(
    name="sftp_upload",
    description=(
        "Upload a local file or directory to a remote host over SFTP. Use to ship code, config or "
        "binaries before running deploy commands. remotePath must be absolute; localPath is any "
        "readable local path. If the host sets uploadRoots, the remote path must sit inside one."
    ),
)
def sftp_upload(
    host: str,
    localPath: str,  # noqa: N803 - MCP-facing name
    remotePath: str,  # noqa: N803
    mode: str | None = None,
    overwrite: bool = True,
) -> dict[str, Any]:
    target, problem = host_or_error(host)
    if problem:
        return problem
    return guard_call(
        lambda: ok(client.upload(target, localPath, remotePath, mode=mode, overwrite=overwrite).to_dict())
    )


@_mcp.tool(
    name="sftp_download",
    description=(
        "Download a remote file or directory to the local machine over SFTP. Use to pull logs, "
        "config or artifacts for offline analysis. remotePath and localPath are both plain paths; "
        "if the host sets downloadRoots/localRoots, each must sit inside its list."
    ),
)
def sftp_download(
    host: str,
    remotePath: str,  # noqa: N803
    localPath: str,  # noqa: N803
    overwrite: bool = True,
) -> dict[str, Any]:
    target, problem = host_or_error(host)
    if problem:
        return problem
    return guard_call(lambda: ok(client.download(target, remotePath, localPath, overwrite=overwrite).to_dict()))


@_mcp.tool(
    name="sftp_list",
    description=(
        "List a directory on a remote host, or stat a single remote file. Use to check whether a "
        "deployment landed, inspect permissions, or find log files before downloading them."
    ),
)
def sftp_list(host: str, remotePath: str = "/", all: bool = False) -> dict[str, Any]:  # noqa: A002
    target, problem = host_or_error(host)
    if problem:
        return problem
    return guard_call(lambda: ok(client.listdir(target, remotePath, all_entries=all)))


def main() -> None:
    if os.environ.get("SSH_HOP_SELFTEST") == "1":
        print(json.dumps({"version": __version__, "hosts_file": os.environ.get("SSH_HOP_HOSTS", "")}))
        return
    try:
        all_hosts()
        if _cache_error:
            print(f"[ssh-hop] {_cache_error}", file=sys.stderr, flush=True)
    except Exception as exc:  # never crash the transport on startup
        print(f"[ssh-hop] startup warning: {exc}", file=sys.stderr, flush=True)
    _mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
