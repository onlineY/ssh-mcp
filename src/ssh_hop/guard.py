"""Command policy, path containment and output limits.

Command policy is a pair of regex lists (`allowCommands`, `denyCommands`) rather than a
classifier: `*` allows everything, `docker .*` allows docker only, and the first matching
deny rule wins. Whatever `allowCommands` does not match is refused, so the policy is exactly
as wide or narrow as the rules you write - nothing is inferred.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from pathlib import Path

from .config import Host, matching_rule

MAX_OUTPUT = 16 * 1024
TRUNCATE_KEEP = 6 * 1024
MAX_COMMAND = 32_000


class GuardDenied(Exception):
    """Raised when a command or path violates host policy. The message is user-facing."""


@dataclass
class Verdict:
    allowed: bool
    rule: str | None = None
    reason: str = ""


def check_command(host: Host, command: str) -> Verdict:
    """Raise GuardDenied unless a rule allows the command and none denies it."""
    if not command.strip():
        raise GuardDenied("empty command")
    if len(command) > MAX_COMMAND:
        raise GuardDenied(f"command too long (limit {MAX_COMMAND} characters)")

    denied = matching_rule(host.denyCommands, command)
    if denied is not None:
        raise GuardDenied(
            f"refused on {host.alias!r}: matches denyCommands rule {denied!r}. "
            "Remove that rule from hosts.json to allow it."
        )

    allowed = matching_rule(host.allowCommands, command)
    if allowed is None:
        configured = ", ".join(repr(rule) for rule in host.allowCommands) or "(none)"
        raise GuardDenied(
            f"refused on {host.alias!r}: no allowCommands rule matches this command. "
            f"Configured rules: {configured}. Add \"*\" to allow everything on this host."
        )
    return Verdict(True, allowed)


# --- path containment -------------------------------------------------------

def _within(path: str, root: str) -> bool:
    normalized = posixpath.normpath(path)
    root = root.rstrip("/") or "/"
    if root == "/":
        return True
    return normalized == root or normalized.startswith(root + "/")


def check_remote_path(host: Host, remote_path: str, roots: list[str], action: str) -> str:
    """Normalize a remote path and, when roots are configured, require it to sit inside one."""
    if not remote_path or not remote_path.strip():
        raise GuardDenied("remote path is empty")
    if not remote_path.startswith("/"):
        raise GuardDenied(f"remote path must be absolute: {remote_path!r}")
    normalized = posixpath.normpath(remote_path)
    if roots and not any(_within(normalized, root) for root in roots):
        raise GuardDenied(
            f"{action} outside allowed roots for {host.alias!r}: {normalized} "
            f"(allowed: {', '.join(roots)}; empty the root list on the host to allow any path)"
        )
    return normalized


def check_local_path(host: Host, local_path: str) -> str:
    """Resolve a local path and, when roots are configured, require it to sit inside one."""
    if not local_path or not local_path.strip():
        raise GuardDenied("local path is empty")
    resolved = Path(local_path).expanduser().resolve()
    if host.localRoots:
        for root in host.localRoots:
            try:
                resolved.relative_to(Path(root).expanduser().resolve())
                return str(resolved)
            except ValueError:
                continue
        raise GuardDenied(
            f"local path outside allowed roots: {resolved} "
            f"(allowed: {', '.join(host.localRoots)}; empty localRoots on the host to allow any path)"
        )
    return str(resolved)


# --- output limits ----------------------------------------------------------

def truncate_output(text: str, limit: int = MAX_OUTPUT) -> tuple[str, bool]:
    """Keep head and tail of oversized output so `tail -100` style reads survive."""
    if len(text) <= limit:
        return text, False
    head = text[:TRUNCATE_KEEP]
    tail = text[-(limit - TRUNCATE_KEEP):]
    omitted = len(text) - len(head) - len(tail)
    return f"{head}\n\n... [{omitted} bytes omitted by ssh-hop] ...\n\n{tail}", True
