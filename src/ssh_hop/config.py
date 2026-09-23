"""Host configuration: aliases, per-host policy, credentials.

The file is the only place credentials exist. Everything the AI sees is produced
by `Host.public()`, which never emits hostname, port, user, password or key path.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HOSTS_ENV = "SSH_HOP_HOSTS"
HOME_ENV = "SSH_HOP_HOME"

KNOWN_HOSTS_POLICIES = ("auto-add", "strict", "ignore")

ALLOW_ALL = "*"
"""Rule value that matches every command."""

_KNOWN_HOSTS = ("defaults", "hosts", "_comment", "_auth", "_readme", "_commands", "_note")


class ConfigError(Exception):
    """Raised for any unusable hosts file, with the offending alias in the message."""


def _expression(pattern: str) -> str:
    """`*` (or an empty rule) means everything; anything else is used as a regex."""
    return ".*" if pattern.strip() in ("", ALLOW_ALL) else pattern


def compile_patterns(patterns: list[str], where: str) -> list[str]:
    """Validate regex rules while loading hosts.json, so a typo fails on startup not mid-command."""
    for pattern in patterns:
        if not isinstance(pattern, str):
            raise ConfigError(f"{where} must contain only strings, got {type(pattern).__name__}")
        try:
            re.compile(_expression(pattern))
        except re.error as exc:
            raise ConfigError(f"{where} has an invalid regex {pattern!r}: {exc}") from exc
    return patterns


def matching_rule(patterns: list[str], command: str) -> str | None:
    """Return the first rule that matches anywhere in the command, or None.

    Matching is `re.search` with DOTALL: a rule is a substring unless anchored with `^`/`$`,
    and `.` spans newlines so a multi-line command still matches a bare `*`.
    """
    for pattern in patterns:
        if re.search(_expression(pattern), command, re.DOTALL):
            return pattern
    return None


def app_home() -> Path:
    """Writable state dir: audit log, learned host keys.

    Prefers `~/.ssh-hop` so config and state travel together; falls back to the per-OS data
    directory only when the home dir is not writable.
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    preferred = config_dir()
    parent = preferred.parent if preferred.parent != preferred else None
    if parent is None or os.access(parent, os.W_OK):
        return preferred
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "ssh-hop"


def config_dir() -> Path:
    """Conventional dotfile directory for hosts.json (`~/.ssh-hop`)."""
    return Path.home() / ".ssh-hop"


def find_hosts_file(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Locate hosts.json: explicit arg, $SSH_HOP_HOSTS, ./hosts.json, ~/.ssh-hop, then app_home()."""
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_file():
            raise ConfigError(f"hosts file not found: {candidate}")
        return candidate
    env = os.environ.get(HOSTS_ENV)
    if env:
        candidate = Path(env).expanduser()
        if not candidate.is_file():
            raise ConfigError(f"{HOSTS_ENV}={env} does not point at a readable file")
        return candidate
    # `~/.ssh-hop` is checked before the per-OS data dir so the same config works regardless of
    # what environment an MCP client happens to pass to the child process.
    for candidate in (Path.cwd() / "hosts.json", config_dir() / "hosts.json", app_home() / "hosts.json"):
        if candidate.is_file():
            return candidate
    raise ConfigError(
        "no hosts.json found; looked at $SSH_HOP_HOSTS, ./hosts.json, "
        f"{config_dir() / 'hosts.json'} and {app_home() / 'hosts.json'}. Run `ssh-hop init`."
    )


@dataclass
class Host:
    alias: str
    host: str
    user: str
    desc: str = ""
    port: int = 22
    password: str | None = None
    keyFile: str | None = None
    passphrase: str | None = None
    defaultCwd: str | None = None
    shell: str = "sh"
    timeout: int = 60
    connectTimeout: int = 10
    netTimeout: int = 20
    idleReuseSec: int = 30
    allowCommands: list[str] = field(default_factory=lambda: [ALLOW_ALL])
    denyCommands: list[str] = field(default_factory=list)
    allowUpload: bool = True
    allowDownload: bool = True
    uploadRoots: list[str] = field(default_factory=list)
    downloadRoots: list[str] = field(default_factory=list)
    localRoots: list[str] = field(default_factory=list)
    knownHosts: str = "auto-add"
    tags: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:  # never leak secrets into tracebacks or logs
        return f"Host(alias={self.alias!r}, host=<hidden>, user=<hidden>, port={self.port})"

    __str__ = __repr__

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def unrestricted_commands(self) -> bool:
        return matching_rule(self.allowCommands, "anything") is not None and not self.denyCommands

    def _transfer(self, enabled: bool, roots: list[str]) -> Any:
        if not enabled:
            return False
        return list(roots) if roots else "any path"

    def public(self) -> dict[str, Any]:
        """Everything the AI is allowed to know. No network or identity details."""
        auth = "key" if self.keyFile else "password" if self.password else "none"
        return {
            "alias": self.alias,
            "desc": self.desc,
            "cwd": self.defaultCwd or "~",
            "auth": auth,
            "commands": "all" if self.allowCommands == [ALLOW_ALL] else list(self.allowCommands),
            "denyCommands": list(self.denyCommands),
            "upload": self._transfer(self.allowUpload, self.uploadRoots),
            "download": self._transfer(self.allowDownload, self.downloadRoots),
            "tags": self.tags,
        }


def _as_str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConfigError(f"{where} must be a string or list of strings")


def _as_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def _as_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where} must be an integer")
    return value


_PLACEHOLDER_PASSWORDS = {"REPLACE_ME", "CHANGE_ME", "your-password"}
_PLACEHOLDER_KEY_PARTS = (
    "users/me/", "users/me\\", "/home/me/", "path/to/", "path\\to\\", "your_key", "id_ed25519_public.pub",
)


def _reject_template_values(alias: str, password: str | None, key_file: str | None) -> None:
    """Catch an unedited hosts.example.json here rather than as a confusing auth failure later."""
    if password in _PLACEHOLDER_PASSWORDS:
        raise ConfigError(
            f"host {alias!r} still has the example password {password!r}; edit hosts.json with the "
            "real credentials (this file was probably copied from hosts.example.json)"
        )
    if key_file:
        normalized = key_file.replace("\\", "/").lower()
        if any(part.replace("\\", "/") in normalized for part in _PLACEHOLDER_KEY_PARTS):
            raise ConfigError(
                f"host {alias!r} still points at the example key path {key_file!r}; edit hosts.json "
                "with your real key path (this file was probably copied from hosts.example.json)"
            )


def _build_host(alias: str, raw: Any, defaults: dict[str, Any], base_dir: Path) -> Host:
    if not isinstance(raw, dict):
        raise ConfigError(f"host {alias!r} must be a JSON object")
    merged = {**defaults, **raw}

    def need(name: str) -> Any:
        if not merged.get(name):
            raise ConfigError(f"host {alias!r} is missing required field {name!r}")
        return merged[name]

    port = _as_int(merged.get("port", 22), f"{alias}.port")
    if not 1 <= port <= 65535:
        raise ConfigError(f"{alias}.port out of range: {port}")

    password = merged.get("password") or None
    key_file = merged.get("keyFile") or None
    if not password and not key_file:
        raise ConfigError(f"host {alias!r} needs either 'password' or 'keyFile'")
    _reject_template_values(alias, password, str(key_file) if key_file else None)

    if key_file:
        key_path = Path(str(key_file)).expanduser()
        if not key_path.is_absolute():
            key_path = (base_dir / key_path).resolve()
        key_file = str(key_path)
        if not key_path.is_file():
            raise ConfigError(f"{alias}.keyFile not found: {key_path}")

    policy = merged.get("knownHosts", "auto-add")
    if policy not in KNOWN_HOSTS_POLICIES:
        raise ConfigError(f"{alias}.knownHosts must be one of {KNOWN_HOSTS_POLICIES}")

    env = merged.get("env") or {}
    if not isinstance(env, dict) or not all(isinstance(v, str) for v in env.values()):
        raise ConfigError(f"{alias}.env must be an object of string values")

    return Host(
        alias=alias,
        host=str(need("host")),
        user=str(need("user")),
        desc=str(merged.get("desc", "")),
        port=port,
        password=None if password is None else str(password),
        keyFile=key_file,
        passphrase=merged.get("passphrase") or None,
        defaultCwd=merged.get("defaultCwd") or None,
        shell=str(merged.get("shell", "sh")),
        timeout=_as_int(merged.get("timeout", 60), f"{alias}.timeout"),
        connectTimeout=_as_int(merged.get("connectTimeout", 10), f"{alias}.connectTimeout"),
        netTimeout=_as_int(merged.get("netTimeout", 20), f"{alias}.netTimeout"),
        idleReuseSec=max(0, _as_int(merged.get("idleReuseSec", 30), f"{alias}.idleReuseSec")),
        allowCommands=compile_patterns(
            _as_str_list(merged.get("allowCommands", [ALLOW_ALL]), f"{alias}.allowCommands"),
            f"{alias}.allowCommands",
        ) or [ALLOW_ALL],
        denyCommands=compile_patterns(
            _as_str_list(merged.get("denyCommands"), f"{alias}.denyCommands"), f"{alias}.denyCommands"
        ),
        allowUpload=_as_bool(merged.get("allowUpload", True), f"{alias}.allowUpload"),
        allowDownload=_as_bool(merged.get("allowDownload", True), f"{alias}.allowDownload"),
        uploadRoots=_as_str_list(merged.get("uploadRoots"), f"{alias}.uploadRoots"),
        downloadRoots=_as_str_list(merged.get("downloadRoots"), f"{alias}.downloadRoots"),
        localRoots=_as_str_list(merged.get("localRoots"), f"{alias}.localRoots"),
        knownHosts=policy,
        tags=_as_str_list(merged.get("tags"), f"{alias}.tags"),
        env={str(k): str(v) for k, v in env.items()},
    )


def load_hosts(path: str | os.PathLike[str] | None = None) -> dict[str, Host]:
    """Parse and validate hosts.json. Raises ConfigError listing every problem found."""
    hosts_file = find_hosts_file(path)
    try:
        raw = json.loads(hosts_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{hosts_file}: invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{hosts_file}: top level must be a JSON object")

    if "hosts" in raw:
        entries = raw["hosts"]
        defaults = raw.get("defaults") or {}
    else:  # bare {alias: {...}} mapping also accepted
        entries = {k: v for k, v in raw.items() if k not in _KNOWN_HOSTS}
        defaults = raw.get("defaults") or {}
    if not isinstance(entries, dict) or not entries:
        raise ConfigError(f"{hosts_file}: no hosts defined")
    if not isinstance(defaults, dict):
        raise ConfigError(f"{hosts_file}: 'defaults' must be an object")

    base_dir = hosts_file.parent
    hosts: dict[str, Host] = {}
    for alias, spec in entries.items():
        hosts[alias] = _build_host(alias, spec, defaults, base_dir)
    return hosts


def resolve_alias(hosts: dict[str, Host], alias: str) -> Host:
    """Exact alias only - no prefix guessing, so a typo can never hit the wrong box."""
    if alias in hosts:
        return hosts[alias]
    raise ConfigError(f"unknown host alias {alias!r}; known aliases: {', '.join(sorted(hosts))}")


def write_example(path: str | os.PathLike[str], force: bool = False) -> Path:
    """Create a starter hosts.json next to the given path."""
    target = Path(path).expanduser()
    if target.exists() and not force:
        raise ConfigError(f"refusing to overwrite existing file: {target}")
    template = Path(__file__).resolve().parent.parent.parent / "hosts.example.json"
    if template.is_file():
        target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        target.write_text(json.dumps({"hosts": {}}, indent=2) + "\n", encoding="utf-8")
    return target
