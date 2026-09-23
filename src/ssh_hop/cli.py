"""`ssh-hop` CLI: the same guarded operations without an MCP client.

Useful for testing on the spot (`ssh-hop run ubuntu-01 'docker ps'`) and as a
fallback when the AI client is not running.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__, client, guard
from .config import (
    ALLOW_ALL,
    ConfigError,
    app_home,
    find_hosts_file,
    load_hosts,
    resolve_alias,
    write_example,
)


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            print(f"{key}: {value}")
    else:
        print(payload)


def _targets(args: argparse.Namespace):
    known = load_hosts(args.hosts_file)
    names = args.alias if isinstance(args.alias, list) else [args.alias]
    return known, [resolve_alias(known, name) for name in names]


def _fail(message: str, code: int = 1) -> int:
    print(f"ssh-hop: {message}", file=sys.stderr)
    return code


def cmd_init(args: argparse.Namespace) -> int:
    """Write a starter hosts.json at the requested path (or the --hosts-file location)."""
    target = Path(args.path or args.hosts_file or "hosts.json").expanduser().resolve()
    try:
        created = write_example(target, force=args.force)
    except ConfigError as exc:
        return _fail(str(exc))
    print(f"created {created}")
    print("Edit it: replace the REPLACE_ME password (or the example keyFile path) with real values.")
    print("ssh-hop refuses to start while the example placeholders are still in place.")
    print("Then run: ssh-hop check --connect")
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    try:
        known = load_hosts(args.hosts_file)
    except ConfigError as exc:
        return _fail(str(exc))
    if args.json:
        _emit({"ok": True, "hosts": [known[alias].public() for alias in sorted(known)]}, True)
        return 0
    print(f"hosts file: {find_hosts_file(args.hosts_file)}")
    print(f"state dir:  {app_home()}")
    for alias in sorted(known):
        host = known[alias]
        flags = []
        if host.allowCommands == [ALLOW_ALL]:
            flags.append("all commands")
        else:
            flags.append(f"{len(host.allowCommands)} allow rule(s)")
        if host.denyCommands:
            flags.append(f"{len(host.denyCommands)} deny rule(s)")
        if not host.allowUpload:
            flags.append("no-upload")
        if not host.allowDownload:
            flags.append("no-download")
        suffix = f"  [{', '.join(flags)}]"
        print(f"  {alias:<16} {host.desc or '(no description)'}{suffix}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        known = load_hosts(args.hosts_file)
    except ConfigError as exc:
        return _fail(str(exc))
    print(f"hosts file OK: {find_hosts_file(args.hosts_file)} ({len(known)} host(s))")
    if args.connect:
        failures = 0
        for alias in sorted(known):
            result = client.probe(known[alias])
            first = result["identity"][0] if result["identity"] else "?"
            print(f"  {alias:<16} ok  {result['latencyMs']:>5}ms  {first}")
            if result["stderr"]:
                print(f"    stderr: {result['stderr'].strip()[:200]}")
        return 0 if not failures else 1
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    try:
        _, (host,) = _targets(args)
        result = client.probe(host)
    except (ConfigError, client.SSHError) as exc:
        return _fail(str(exc))
    _emit(result if args.json else result, args.json)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    try:
        _, (host,) = _targets(args)
        result = client.run(host, args.command, timeout=args.timeout, background=args.background)
    except (ConfigError, guard.GuardDenied, client.SSHError) as exc:
        return _fail(str(exc), 2 if isinstance(exc, guard.GuardDenied) else 1)
    if args.json:
        _emit(result.to_dict(), True)
    else:
        if result.stdout:
            sys.stdout.write(result.stdout)
            if not result.stdout.endswith("\n"):
                sys.stdout.write("\n")
        if result.stderr:
            sys.stderr.write(result.stderr)
        for warning in result.warnings:
            print(f"ssh-hop: {warning}", file=sys.stderr)
    if result.exit_code is None:
        return 1  # timed out, or the peer closed without a status: never report success
    return result.exit_code


def cmd_put(args: argparse.Namespace) -> int:
    try:
        _, (host,) = _targets(args)
        result = client.upload(host, args.local, args.remote, mode=args.mode)
    except (ConfigError, guard.GuardDenied, client.SSHError) as exc:
        return _fail(str(exc), 2 if isinstance(exc, guard.GuardDenied) else 1)
    _emit(result.to_dict() if args.json else f"uploaded {result.files} file(s), {result.bytes} bytes -> {result.target}", args.json)
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    try:
        _, (host,) = _targets(args)
        result = client.download(host, args.remote, args.local)
    except (ConfigError, guard.GuardDenied, client.SSHError) as exc:
        return _fail(str(exc), 2 if isinstance(exc, guard.GuardDenied) else 1)
    _emit(result.to_dict() if args.json else f"downloaded {result.files} file(s), {result.bytes} bytes -> {result.target}", args.json)
    return 0


def cmd_remote_ls(args: argparse.Namespace) -> int:
    try:
        _, (host,) = _targets(args)
        listing = client.listdir(host, args.path, all_entries=args.all)
    except (ConfigError, guard.GuardDenied, client.SSHError) as exc:
        return _fail(str(exc), 2 if isinstance(exc, guard.GuardDenied) else 1)
    if args.json:
        _emit({"ok": True, **listing}, True)
        return 0
    for item in listing["entries"]:
        size = item["size"] if item["type"] == "file" else "-"
        print(f"  {item['mode']:<7} {size:>10}  {item['type']:<4} {item['name']}")
    if not listing["entries"]:
        print(f"  (empty: {listing['path']})")
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    """Show which rule would allow or refuse a command, without connecting."""
    try:
        _, (host,) = _targets(args)
    except ConfigError as exc:
        return _fail(str(exc))
    print(f"host:      {host.alias}")
    print(f"command:   {args.command}")
    try:
        verdict = guard.check_command(host, args.command)
    except guard.GuardDenied as exc:
        print("verdict:   refused")
        print(f"reason:    {exc}")
        print(f"allow:     {', '.join(repr(r) for r in host.allowCommands) or '(none)'}")
        print(f"deny:      {', '.join(repr(r) for r in host.denyCommands) or '(none)'}")
        return 2
    print("verdict:   allowed")
    print(f"matched:   {verdict.rule!r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-hop",
        description="Guarded SSH/SFTP access to configured hosts, by alias.",
    )
    parser.add_argument("--version", action="version", version=f"ssh-hop {__version__}")
    parser.add_argument("--hosts-file", help="path to hosts.json (default: $SSH_HOP_HOSTS, ./hosts.json)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="write a starter hosts.json")
    init.add_argument("path", nargs="?", default=None,
                      help="where to write it (default: the --hosts-file path, else ./hosts.json)")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    ls = sub.add_parser("ls", aliases=["list"], help="list configured hosts")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=cmd_ls)

    check = sub.add_parser("check", help="validate hosts.json (and optionally connect)")
    check.add_argument("--connect", action="store_true", help="also probe every host")
    check.set_defaults(func=cmd_check)

    probe = sub.add_parser("probe", help="connect and identify one host")
    probe.add_argument("alias")
    probe.add_argument("--json", action="store_true")
    probe.set_defaults(func=cmd_probe)

    run = sub.add_parser("run", help="execute a command on one host")
    run.add_argument("alias")
    run.add_argument("command")
    run.add_argument("--timeout", type=int)
    run.add_argument("--background", action="store_true")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_run)

    put = sub.add_parser("put", help="upload a file or directory")
    put.add_argument("alias")
    put.add_argument("local")
    put.add_argument("remote")
    put.add_argument("--mode", help="octal mode to apply after upload, e.g. 755")
    put.add_argument("--json", action="store_true")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get", help="download a file or directory")
    get.add_argument("alias")
    get.add_argument("remote")
    get.add_argument("local")
    get.add_argument("--json", action="store_true")
    get.set_defaults(func=cmd_get)

    rls = sub.add_parser("rls", help="list a remote directory")
    rls.add_argument("alias")
    rls.add_argument("path", nargs="?", default="/")
    rls.add_argument("-a", "--all", action="store_true")
    rls.add_argument("--json", action="store_true")
    rls.set_defaults(func=cmd_remote_ls)

    cls = sub.add_parser("classify", help="show which allow/deny rule matches a command, without running it")
    cls.add_argument("alias")
    cls.add_argument("command")
    cls.set_defaults(func=cmd_classify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        return _fail(str(exc))
    except client.SSHError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        return 130
    finally:
        client.close_all()


if __name__ == "__main__":
    sys.exit(main())
