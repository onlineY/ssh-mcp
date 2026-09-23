"""Connection management, command execution and SFTP transfer.

Credentials never leave this module: nothing returned to the caller contains the
hostname, port, username, password or key path.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import stat as stat_module
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import paramiko
from paramiko.ssh_exception import NoValidConnectionsError

from . import guard
from .config import Host, app_home

OutputHook = Callable[[str, str], None]

_AUDIT_LOCK = threading.Lock()
_POOL_LOCK = threading.Lock()

_NET_TIMEOUT_MSG = (
    "connecting to {alias!r} exceeded netTimeout ({seconds}s) and was aborted. Raise netTimeout on "
    "the host if it is genuinely that slow; otherwise check the address, firewall, and whether the "
    "sshd banner is being sent."
)


class SSHError(Exception):
    """A remote operation failed. Message is safe to show the model and the user.

    `retryable` marks failures where the remote command never started (the pooled
    connection was dead before the channel opened), so reconnecting and retrying once
    cannot run anything twice.
    """

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class ExecResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    truncated: bool = False
    timed_out: bool = False
    killed: bool = False
    pid: str | None = None
    log_path: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "exitCode": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "durationMs": self.duration_ms,
            "truncated": self.truncated,
        }
        if self.timed_out:
            payload["timedOut"] = True
        if self.killed:
            payload["killed"] = True
        if self.pid:
            payload["pid"] = self.pid
        if self.log_path:
            payload["logPath"] = self.log_path
        if self.warnings:
            payload["warnings"] = self.warnings
        return payload


# --- host key handling ------------------------------------------------------

class _PersistingAutoAdd(paramiko.MissingHostKeyPolicy):
    """Accept an unknown host key, remember it, and persist it to the local store."""

    def __init__(self, store: "_HostKeyStore"):
        self._store = store

    def missing_host_key(self, client, hostname, key) -> None:  # noqa: ANN001
        self._store.remember(hostname, key)


class _WarnOnly(paramiko.MissingHostKeyPolicy):
    """Accepts any key but says so. Writes to stderr: stdout carries the MCP protocol."""

    def missing_host_key(self, client, hostname, key) -> None:  # noqa: ANN001
        print(f"[ssh-hop] warning: accepting unknown host key for {hostname}", file=sys.stderr, flush=True)


class _HostKeyStore:
    """known_hosts files: the user's ~/.ssh/known_hosts plus a private one we may write."""

    def __init__(self, writable: Path):
        self._writable = writable
        self._lock = threading.Lock()
        self._keys = paramiko.HostKeys()
        for path in (Path.home() / ".ssh" / "known_hosts", writable):
            if path.is_file():
                try:
                    self._keys.load(str(path))
                except (OSError, paramiko.SSHException):
                    pass

    @property
    def keys(self) -> paramiko.HostKeys:
        return self._keys

    def remember(self, hostname: str, key: paramiko.PKey) -> None:
        with self._lock:
            self._keys.add(hostname, key.get_name(), key)
            try:
                self._writable.parent.mkdir(parents=True, exist_ok=True)
                self._keys.save(str(self._writable))
            except OSError as exc:  # a read-only store must not break the connection
                print(f"[ssh-hop] warning: could not persist host key: {exc}", file=sys.stderr, flush=True)


_stores: dict[str, _HostKeyStore] = {}
_store_lock = threading.Lock()


def _store_for(host: Host) -> _HostKeyStore | None:
    if host.knownHosts == "ignore":
        return None
    path = str(app_home() / "known_hosts")
    with _store_lock:
        if path not in _stores:
            _stores[path] = _HostKeyStore(Path(path))
        return _stores[path]


# --- connection pool --------------------------------------------------------

class _Conn:
    """One pooled connection. `lock` serializes channel use; `users` guards teardown.

    A connection must never be closed while another thread is mid-command on it, so
    eviction marks it `retired` and the last user out closes the socket.
    """

    __slots__ = ("client", "sftp", "last_used", "lock", "users", "retired")

    def __init__(self, client: paramiko.SSHClient):
        self.client = client
        self.sftp: paramiko.SFTPClient | None = None
        self.last_used = time.monotonic()
        self.lock = threading.RLock()
        self.users = 0
        self.retired = False

    def alive(self) -> bool:
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            return False
        if self.sftp is not None and self.sftp.get_channel().closed:
            self.sftp = None
        return True

    def close(self) -> None:
        """Close unconditionally. Only safe when no other thread holds the connection."""
        if self.sftp is not None:
            try:
                self.sftp.close()
            except Exception:
                pass
            self.sftp = None
        try:
            self.client.close()
        except Exception:
            pass


def _acquire(host: Host) -> _Conn:
    """Take a connection for exclusive use. Pair every call with `_release`.

    The handshake happens outside `_POOL_LOCK`: connecting can take seconds, and holding the
    lock across it would stall operations on every other host.
    """
    while True:
        with _POOL_LOCK:
            entry = _pool.get(host.alias)
            if entry is not None:
                idle = time.monotonic() - entry.last_used
                # `idleReuseSec: 0` means never reuse. The explicit `> 0` check matters because
                # the monotonic clock can be coarse enough for two calls to report idle == 0.
                if host.idleReuseSec > 0 and idle <= host.idleReuseSec and entry.alive():
                    entry.users += 1
                    return entry
                del _pool[host.alias]
                if entry.users == 0:
                    entry.close()
                # else: busy in another thread; that thread closes it on release.

        client = _open(host)
        conn = _Conn(client)
        with _POOL_LOCK:
            current = _pool.get(host.alias)
            if current is not None and current.users > 0 and current.alive():
                # Another thread connected while we were negotiating: share its connection.
                current.users += 1
                winner = current
            else:
                if current is not None and current.users == 0:
                    current.close()
                conn.users = 1
                _pool[host.alias] = conn
                winner = conn
        if winner is conn:
            return conn
        client.close()
        return winner


def _release(conn: _Conn) -> None:
    """Drop a connection's in-use mark, closing it if it was retired while busy."""
    with _POOL_LOCK:
        conn.last_used = time.monotonic()
        conn.users -= 1
        if conn.users <= 0 and conn.retired:
            conn.close()


def _retire(host: Host, conn: _Conn | None = None) -> None:
    """Remove a host's connection from the pool without cutting off active users."""
    with _POOL_LOCK:
        entry = _pool.get(host.alias)
        if entry is None or (conn is not None and entry is not conn):
            return
        del _pool[host.alias]
        if entry.users == 0:
            entry.close()
        else:
            entry.retired = True


_pool: dict[str, _Conn] = {}


def _open(host: Host) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    store = _store_for(host)
    if store is not None:
        # The store already merges ~/.ssh/known_hosts with our writable file, so install it
        # directly. Calling load_system_host_keys() here would replace this keyring and
        # silently discard every key learned earlier.
        client._system_host_keys = store.keys  # noqa: SLF001
        client.set_missing_host_key_policy(
            _PersistingAutoAdd(store) if host.knownHosts == "auto-add" else paramiko.RejectPolicy()
        )
    else:
        client.set_missing_host_key_policy(_WarnOnly())

    kwargs: dict[str, Any] = {
        "hostname": host.host,
        "port": host.port,
        "username": host.user,
        "timeout": host.connectTimeout,
        "banner_timeout": host.connectTimeout,
        "auth_timeout": host.connectTimeout,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if host.keyFile:
        kwargs["key_filename"] = host.keyFile
        if host.passphrase:
            kwargs["passphrase"] = host.passphrase
    else:
        kwargs["password"] = host.password

    # paramiko's per-step timeouts do not bound the whole handshake: a peer can stall in a way
    # that leaves connect() blocked far past `connectTimeout`. A watchdog guarantees the call
    # returns even then, so a wedged host can never hang the agent.
    expired = threading.Event()
    abort = threading.Timer(host.netTimeout, lambda: (expired.set(), client.close()))
    abort.daemon = True
    abort.start()
    try:
        client.connect(**kwargs)
    except paramiko.BadHostKeyException as exc:
        raise SSHError(
            f"host key mismatch for {host.alias!r}: server presented a different key than the one "
            f"stored locally ({exc.key.get_name()}). Remove the stale entry from "
            f"{app_home() / 'known_hosts'} or ~/.ssh/known_hosts, then verify the new fingerprint "
            "out of band before reconnecting."
        ) from exc
    except paramiko.AuthenticationException as exc:
        mode = "key file" if host.keyFile else "password"
        raise SSHError(
            f"authentication failed for {host.alias!r} using the configured {mode}. "
            "Fix the credentials in hosts.json."
        ) from exc
    except (paramiko.SSHException, OSError, NoValidConnectionsError, socket.timeout,
            TimeoutError) as exc:
        if not expired.is_set():
            text = str(exc)
            if "not found in known_hosts" in text.lower():
                raise SSHError(
                    f"host key for {host.alias!r} is not in known_hosts and the host uses "
                    "knownHosts='strict'. Add the key, or set knownHosts to 'auto-add'."
                ) from exc
            if isinstance(exc, (socket.timeout, TimeoutError)):
                raise SSHError(
                    f"timed out connecting to {host.alias!r} after {host.connectTimeout}s "
                    "(host unreachable, firewall, or wrong LAN address)",
                    retryable=True,
                ) from exc
            raise SSHError(f"cannot reach {host.alias!r}: {text}", retryable=True) from exc
        raise SSHError(_NET_TIMEOUT_MSG.format(alias=host.alias, seconds=host.netTimeout),
                       retryable=True) from exc
    finally:
        abort.cancel()

    if expired.is_set():  # the timer fired as the handshake finished: discard the connection
        client.close()
        raise SSHError(_NET_TIMEOUT_MSG.format(alias=host.alias, seconds=host.netTimeout),
                       retryable=True)
    return client


@contextmanager
def _session(host: Host):
    """Hold the host's connection for the duration of one operation."""
    conn = _acquire(host)
    try:
        yield conn
    finally:
        _release(conn)


def _open_sftp(conn: _Conn, host: Host) -> paramiko.SFTPClient:
    """Return the connection's SFTP channel, opening it once and reusing it after."""
    if conn.sftp is not None:
        return conn.sftp
    try:
        conn.sftp = conn.client.open_sftp()
    except (paramiko.SSHException, OSError) as exc:
        message = str(exc)
        if "subsystem" in message.lower() or "unsupported" in message.lower():
            raise SSHError(
                f"this host does not offer SFTP: {message}. File transfer is unavailable on "
                f"{host.alias!r}; command execution still works."
            ) from exc
        raise SSHError(
            f"could not open an SFTP channel on {host.alias!r}: {message}", retryable=True
        ) from exc
    return conn.sftp


@contextmanager
def sftp_for(host: Host):
    """Yield the host's SFTP channel, retrying once if the connection or channel failed."""
    for attempt in (0, 1):
        conn = None
        try:
            conn = _acquire(host)
            sftp = _open_sftp(conn, host)
        except SSHError as exc:
            if conn is not None:
                _retire(host, conn)
                _release(conn)
            if exc.retryable and attempt == 0:
                continue
            raise
        try:
            yield sftp
        finally:
            _release(conn)
        return


def close_all() -> None:
    with _POOL_LOCK:
        entries = list(_pool.values())
        _pool.clear()
    for entry in entries:
        with entry.lock:
            entry.close()


def close_host(alias: str) -> None:
    with _POOL_LOCK:
        entry = _pool.pop(alias, None)
    if entry is not None:
        with entry.lock:
            entry.close()


def _drop(host: Host) -> None:
    """Forget a host's pooled connection without disturbing the others."""
    _retire(host)


# --- audit ------------------------------------------------------------------

_SECRET_HINTS = (
    (r"(?i)(password|passwd|pwd|secret|token|api[-_]?key)(\s*[=:]\s*)(\S+)", r"\1\2<redacted>"),
    (r"(?i)(-p|--password[= ])(\S+)", r"\1<redacted>"),
    (r"(?i)(Authorization:\s*Bearer\s+)\S+", r"\1<redacted>"),
)


def _redact(text: str) -> str:
    import re

    for pattern, repl in _SECRET_HINTS:
        text = re.sub(pattern, repl, text)
    return text


def audit(host: Host, action: str, **fields: Any) -> None:
    """Append one JSON line per remote operation. Never raises."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "eventId": str(uuid.uuid4()),
        "alias": host.alias,
        "action": action,
        **fields,
    }
    for key in ("command", "stderr"):
        if isinstance(record.get(key), str):
            record[key] = _redact(record[key])[:2000]
    try:
        path = app_home() / "audit.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with _AUDIT_LOCK, open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception:  # auditing must never break the operation
        pass


# --- command execution ------------------------------------------------------

def _build_command(host: Host, command: str, cwd: str | None, env: dict[str, str] | None) -> str:
    from shlex import quote

    parts: list[str] = []
    target_dir = cwd or host.defaultCwd
    if target_dir:
        parts.append(f"cd {quote(target_dir)}")
    merged_env = {**host.env, **(env or {})}
    if merged_env:
        prefix = " ".join(f"{key}={quote(value)}" for key, value in merged_env.items())
        command = f"{prefix} {command}"
    parts.append(command)
    return " && ".join(parts) if len(parts) > 1 else parts[0]


def run(
    host: Host,
    command: str,
    timeout: int | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    on_output: OutputHook | None = None,
    background: bool = False,
    audit_result: bool = True,
) -> ExecResult:
    """Run one shell command on the host through a guarded, reusable connection."""
    guard.check_command(host, command)  # raises GuardDenied when policy refuses it

    if background:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        log_path = f"/tmp/ssh-hop-{stamp}-{uuid.uuid4().hex[:6]}.log"
        inner = _build_command(host, command, cwd, env)
        from shlex import quote

        command = f"nohup {host.shell} -c {quote(inner)} > {quote(log_path)} 2>&1 & echo SSH_HOP_PID=$!"
        result = _execute(host, command, timeout or host.timeout, on_output, audit_result)
        for line in result.stdout.splitlines():
            if line.startswith("SSH_HOP_PID="):
                result.pid = line.split("=", 1)[1].strip()
        if result.pid:
            result.stdout = result.stdout.replace(f"SSH_HOP_PID={result.pid}\n", "").replace(
                f"SSH_HOP_PID={result.pid}", ""
            ).strip()
            result.log_path = log_path
        else:
            result.warnings.append("could not determine the background pid; check `ps` on the host")
        audit(host, "run_background", command=_redact(command), pid=result.pid, logPath=log_path)
        return result

    wrapped = _build_command(host, command, cwd, env)
    try:
        result = _execute(host, wrapped, timeout or host.timeout, on_output, audit_result)
    except SSHError as exc:
        # The pooled connection can die between calls (an idle NAT/firewall drop, a restarted
        # sshd). `retryable` is set only when the command never reached the remote, so
        # reconnecting and re-running still executes it exactly once.
        if not exc.retryable:
            raise
        _drop(host)
        result = _execute(host, wrapped, timeout or host.timeout, on_output, audit_result)
        result.warnings.append("the pooled connection had died; reconnected and ran once")
    return result


def _execute(
    host: Host,
    command: str,
    timeout: int,
    on_output: OutputHook | None,
    do_audit: bool,
) -> ExecResult:
    started = time.perf_counter()
    limit = max(1, min(int(timeout), 1800))
    exec_started = False
    exit_code: int | None = None
    timed_out = False
    closed_early = False
    out_chunks: list[str] = []
    err_chunks: list[str] = []

    with _session(host) as conn:
        with conn.lock:
            conn.last_used = time.monotonic()
            try:
                chan = conn.client.get_transport().open_session(timeout=host.connectTimeout)
            except (paramiko.SSHException, OSError) as exc:
                _retire(host, conn)
                # No channel exists, so nothing can have run: safe to reconnect and retry.
                raise SSHError(
                    f"could not open a session on {host.alias!r}: {exc}", retryable=True
                ) from exc

            def drain() -> bool:
                """Move whatever is buffered into the accumulators. False once the peer is gone."""
                moved = False
                while True:
                    try:
                        if not chan.recv_ready():
                            break
                        text = chan.recv(65536).decode("utf-8", errors="replace")
                    except (paramiko.SSHException, EOFError, OSError):
                        return moved
                    if not text:
                        break
                    out_chunks.append(text)
                    moved = True
                    if on_output:
                        on_output("stdout", text)
                while True:
                    try:
                        if not chan.recv_stderr_ready():
                            break
                        text = chan.recv_stderr(65536).decode("utf-8", errors="replace")
                    except (paramiko.SSHException, EOFError, OSError):
                        return moved
                    if not text:
                        break
                    err_chunks.append(text)
                    moved = True
                    if on_output:
                        on_output("stderr", text)
                return moved

            try:
                chan.exec_command(command)
                exec_started = True
                deadline = time.monotonic() + limit
                while True:
                    progressed = drain()
                    if chan.exit_status_ready():
                        break
                    # A peer that closes without an exit status is legitimate (killed process,
                    # `exec` without status). Treat it as end-of-stream instead of raising.
                    try:
                        is_closed = chan.closed
                    except (paramiko.SSHException, OSError):
                        is_closed = True
                    if is_closed:
                        closed_early = True
                        break
                    if time.monotonic() > deadline:
                        timed_out = True
                        break
                    if not progressed:
                        time.sleep(0.02)

                drain()
                if timed_out:
                    chan.close()
                    exit_code = None
                elif chan.exit_status_ready():
                    exit_code = chan.recv_exit_status()
                else:
                    exit_code = None
            except (paramiko.SSHException, EOFError, OSError) as exc:
                _retire(host, conn)
                # `exec_started` is only set once exec_command() returns. If it is still False
                # the request never completed, so re-running on a fresh connection cannot
                # execute the command twice. Once it is True we must not retry - the remote
                # may already be running it.
                raise SSHError(
                    f"session with {host.alias!r} failed mid-command: {exc}",
                    retryable=not exec_started,
                ) from exc
            finally:
                try:
                    chan.close()
                except Exception:
                    pass
                conn.last_used = time.monotonic()

    stdout = "".join(out_chunks)
    stderr = "".join(err_chunks)
    stdout, cut_out = guard.truncate_output(stdout)
    stderr, cut_err = guard.truncate_output(stderr, guard.MAX_OUTPUT // 2)
    result = ExecResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=int((time.perf_counter() - started) * 1000),
        truncated=cut_out or cut_err,
        timed_out=timed_out,
        killed=timed_out,
    )
    if timed_out:
        result.warnings.append(
            f"no exit within {limit}s; the channel was closed, but the remote process may still be "
            "running. Check with `ps` and kill it by pid if needed."
        )
    elif closed_early and exit_code is None:
        result.warnings.append(
            "the remote side closed the session without reporting an exit status; the command may "
            "have been killed. Re-run it or check the host's logs."
        )
    if do_audit:
        audit(
            host,
            "run",
            command=command,
            exitCode=exit_code,
            durationMs=result.duration_ms,
            timedOut=timed_out or None,
            stderr=stderr[-500:] or None,
        )
    return result


# --- probing ----------------------------------------------------------------

def probe(host: Host) -> dict[str, Any]:
    """Connect, identify the host, and report latency. Uses a fixed read-only command."""
    started = time.perf_counter()
    server = "unknown"
    with _session(host) as conn:
        transport = conn.client.get_transport()
        server = transport.remote_version if transport else "unknown"
    result = _execute(host, "uname -a; echo ---; uptime 2>/dev/null; echo ---; id", 20, None, False)
    latency = int((time.perf_counter() - started) * 1000)
    lines = [line for line in result.stdout.splitlines() if line.strip() != "---"]
    if not lines and result.exit_code is None:
        raise SSHError(
            f"connected to {host.alias!r} but the identification command produced no output"
        )
    return {
        "ok": True,
        "alias": host.alias,
        "server": server,
        "latencyMs": latency,
        "identity": lines,
        "stderr": result.stderr.strip() or None,
    }


# --- SFTP -------------------------------------------------------------------

def _ensure_remote_dir(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    parts: list[str] = []
    current = remote_dir
    while current not in ("", "/"):
        parts.append(current)
        current = os.path.dirname(current)
    for path in reversed(parts):
        try:
            sftp.stat(path)
        except FileNotFoundError:
            try:
                sftp.mkdir(path)
            except OSError as exc:
                raise SSHError(f"could not create remote directory {path}: {exc}") from exc


@dataclass
class TransferResult:
    ok: bool
    alias: str
    bytes: int
    source: str
    target: str
    files: int = 1
    skipped: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "ok": self.ok,
            "alias": self.alias,
            "bytes": self.bytes,
            "files": self.files,
            "source": self.source,
            "target": self.target,
            "durationMs": self.duration_ms,
        }
        if self.skipped:
            payload["skipped"] = self.skipped
        return payload


def upload(
    host: Host,
    local_path: str,
    remote_path: str,
    mode: str | None = None,
    overwrite: bool = True,
) -> TransferResult:
    """Copy a local file or directory to the host, inside the allowed remote roots."""
    if not host.allowUpload:
        raise guard.GuardDenied(f"uploads are disabled for host {host.alias!r} (allowUpload=false)")
    local = guard.check_local_path(host, local_path)
    source = Path(local)
    if not source.exists():
        raise SSHError(f"local path does not exist: {local}")
    remote = guard.check_remote_path(host, remote_path, host.uploadRoots, "upload")

    started = time.perf_counter()
    total = 0
    files = 0
    skipped: list[str] = []

    with sftp_for(host) as sftp:

        def put_one(local_file: Path, remote_file: str) -> None:
            nonlocal total, files
            if not overwrite:
                try:
                    sftp.stat(remote_file)
                    skipped.append(remote_file)
                    return
                except FileNotFoundError:
                    pass
            _ensure_remote_dir(sftp, os.path.dirname(remote_file) or "/")
            try:
                sftp.put(str(local_file), remote_file)
            except (OSError, paramiko.SSHException) as exc:
                raise SSHError(f"upload failed for {remote_file}: {exc}") from exc
            remote_size = sftp.stat(remote_file).st_size
            local_size = local_file.stat().st_size
            if remote_size != local_size:
                raise SSHError(
                    f"size mismatch after upload: {remote_file} is {remote_size} bytes remotely but "
                    f"{local_size} bytes locally; the file may be incomplete"
                )
            if mode:
                sftp.chmod(remote_file, int(mode, 8))
            total += remote_size
            files += 1

        if source.is_dir():
            _ensure_remote_dir(sftp, remote)
            base = source
            for path in sorted(source.rglob("*")):
                relative = path.relative_to(base).as_posix()
                if path.is_dir():
                    _ensure_remote_dir(sftp, f"{remote}/{relative}")
                elif path.is_file():
                    put_one(path, f"{remote}/{relative}")
        else:
            put_one(source, remote)

    result = TransferResult(
        ok=True,
        alias=host.alias,
        bytes=total,
        source=local,
        target=remote,
        files=files,
        skipped=skipped,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    audit(host, "upload", source=local, target=remote, bytes=total, files=files)
    return result


def download(
    host: Host,
    remote_path: str,
    local_path: str,
    overwrite: bool = True,
) -> TransferResult:
    """Copy a remote file or directory into the allowed local roots."""
    if not host.allowDownload:
        raise guard.GuardDenied(
            f"downloads are disabled for host {host.alias!r} (allowDownload=false)"
        )
    remote = guard.check_remote_path(host, remote_path, host.downloadRoots, "download")
    local = guard.check_local_path(host, local_path)
    target = Path(local)

    started = time.perf_counter()
    total = 0
    files = 0
    skipped: list[str] = []

    with sftp_for(host) as sftp:

        def fetch_one(remote_file: str, local_file: Path) -> None:
            nonlocal total, files
            if local_file.exists() and not overwrite:
                skipped.append(str(local_file))
                return
            local_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                sftp.get(remote_file, str(local_file))
            except (OSError, paramiko.SSHException) as exc:
                raise SSHError(f"download failed for {remote_file}: {exc}") from exc
            remote_size = sftp.stat(remote_file).st_size
            if local_file.stat().st_size != remote_size:
                raise SSHError(f"size mismatch after download: {local_file}")
            total += remote_size
            files += 1

        try:
            remote_is_dir = stat_module.S_ISDIR(sftp.stat(remote).st_mode)
        except FileNotFoundError as exc:
            raise SSHError(f"remote path does not exist: {remote}") from exc

        if remote_is_dir:
            target.mkdir(parents=True, exist_ok=True)
            for entry in _walk_remote(sftp, remote):
                fetch_one(entry, target / os.path.relpath(entry, remote).replace("\\", "/"))
        else:
            fetch_one(remote, target)

    result = TransferResult(
        ok=True,
        alias=host.alias,
        bytes=total,
        source=remote,
        target=str(target),
        files=files,
        skipped=skipped,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    audit(host, "download", source=remote, target=str(target), bytes=total, files=files)
    return result


def _walk_remote(sftp: paramiko.SFTPClient, root: str) -> Iterable[str]:
    stack = [root]
    while stack:
        current = stack.pop()
        for attr in sftp.listdir_attr(current):
            path = f"{current.rstrip('/')}/{attr.filename}"
            if stat_module.S_ISDIR(attr.st_mode or 0):
                stack.append(path)
            elif stat_module.S_ISREG(attr.st_mode or 0):
                yield path


def listdir(host: Host, remote_path: str, all_entries: bool = False) -> dict[str, Any]:
    """List a remote directory (or stat a single file)."""
    path = guard.check_remote_path(host, remote_path, [], "list")
    with sftp_for(host) as sftp:
        try:
            attr = sftp.stat(path)
        except FileNotFoundError:
            raise SSHError(f"remote path does not exist: {path}")
        if not stat_module.S_ISDIR(attr.st_mode or 0):
            return {"path": path, "type": "file", "size": attr.st_size,
                    "mtime": int(attr.st_mtime or 0), "entries": []}
        entries = []
        for item in sorted(sftp.listdir_attr(path), key=lambda a: a.filename):
            if not all_entries and item.filename.startswith("."):
                continue
            mode = item.st_mode or 0
            kind = "dir" if stat_module.S_ISDIR(mode) else "link" if stat_module.S_ISLNK(mode) else "file"
            entries.append({
                "name": item.filename,
                "type": kind,
                "size": item.st_size,
                "mode": oct(mode & 0o7777),
                "mtime": int(item.st_mtime or 0),
            })
    return {"path": path, "type": "dir", "count": len(entries), "entries": entries}
