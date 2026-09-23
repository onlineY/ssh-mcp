"""An in-process SSH server used by the tests.

Speaks real SSH and real SFTP (real paramiko transports, real channel EOF and exit
statuses) over a temporary directory, so the client is exercised end to end:
command wrapping, `cd`, env prefixes, redirection, backgrounding, timeouts, exit
codes and file transfers, without a live machine.

The exec side is a deliberately small shell interpreter. Only a fixed vocabulary
is implemented; anything else fails with status 127, so a test can assert that a
command really reached the wire instead of being swallowed locally.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

DEFAULT_USER = "tester"
DEFAULT_PASSWORD = "s3cret"

_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=")
_SPLITTERS = ("&&", "||", ";")

# Command wrappers the fake shell understands; values list flags that consume an argument.
_WRAPPER_FLAGS: dict[str, frozenset[str]] = {
    "nohup": frozenset(),
    "setsid": frozenset(),
    "time": frozenset({"-o", "--output", "-f", "--format"}),
    "nice": frozenset({"-n"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "sudo": frozenset({"-u", "--user", "-g", "--group", "-p"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
}


def split_top_level(text: str) -> list[str]:
    """Split on && / || / ; while ignoring anything inside quotes."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            buf.append(char)
            if char == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "'\"":
            quote = char
            buf.append(char)
            i += 1
            continue
        if text[i:i + 2] in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if char == ";":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    segments.append("".join(buf))
    return [segment.strip() for segment in segments if segment.strip()]


@dataclass
class Stage:
    """One command in a `;`/`&&`/`&` chain, with its own redirect."""

    words: list[str]
    redirect: str | None = None
    append: bool = False
    background: bool = False


def tokenize(segment: str) -> tuple[dict[str, str], list[Stage], list[str]]:
    """Split one segment into env assignments and stages carrying their own redirects.

    Mirrors bash scoping closely enough for the tests: `cmd > f & echo $!` sends only
    the first stage's output to `f`.
    """
    tokens = shlex.split(segment)
    env: dict[str, str] = {}
    stages: list[Stage] = []
    words: list[str] = []
    pending = Stage(words)
    i = 0

    def close(background: bool = False) -> None:
        nonlocal words, pending
        if words or pending.redirect:
            stage = Stage(words, pending.redirect, pending.append, background)
            stages.append(stage)
        words = []
        pending = Stage(words)
        pending.redirect = None

    while i < len(tokens):
        token = tokens[i]
        if token == "&":
            close(background=True)
            i += 1
            continue
        if token in (">", ">>", "1>", "1>>"):
            append = token.endswith(">>")
            i += 1
            if i < len(tokens):
                pending.redirect, pending.append = tokens[i], append
                i += 1
            continue
        if token.startswith("2>") or token.startswith("1>"):
            target = token[2:]
            if target and target != "&1":
                pending.redirect, pending.append = target, token.endswith(">>")
            i += 1
            continue
        if token in ("2>&1", "1>&2", "&>", "2>/dev/null"):
            i += 1
            continue
        if not words and "=" in token and _ASSIGNMENT.match(token):
            key, _, value = token.partition("=")
            env[key] = value
            i += 1
            continue
        words.append(token)
        pending.words = words
        i += 1
    if words:
        stages.append(Stage(words, pending.redirect, pending.append, False))
    return env, stages, tokens


class FakeSSHServer(paramiko.ServerInterface):
    """Fixed credentials; a mini shell for a whitelisted vocabulary."""

    def __init__(self, host_key: paramiko.PKey, chroot: Path, user: str, password: str):
        self.host_key = host_key
        self.chroot = Path(chroot).resolve()
        self.user = user
        self.password = password
        self.exec_log: list[str] = []
        self.env_seen: dict[str, str] = {}
        self.cwd_seen: list[str] = []
        self.files_written: list[str] = []
        self.cwd = "/"
        self._pid = 4000
        self._last_bg_pid = 0
        self.chmod_requests: list[tuple[str, int]] = []
        self._sftp_servers: list[paramiko.SFTPServer] = []

    # --- auth ---
    def check_auth_password(self, username, password):  # noqa: ANN001
        ok = (username, password) == (self.user, self.password)
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):  # noqa: ANN001
        return paramiko.AUTH_SUCCESSFUL if username == self.user else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):  # noqa: ANN001
        return "password,publickey"

    # --- channels ---
    def check_channel_request(self, kind, chanid):  # noqa: ANN001
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):  # noqa: ANN001
        self.exec_log.append(command.decode("utf-8", errors="replace"))
        threading.Thread(target=self._exec, args=(channel,), daemon=True).start()
        return True

    def check_channel_subsystem_request(self, channel, name):  # noqa: ANN001
        if name != "sftp":
            return False
        server = paramiko.SFTPServer(channel, name, self, FakeSFTPServer)
        self._sftp_servers.append(server)
        server.start()
        return True

    # --- shell plumbing ---
    def _local(self, remote_path: str) -> Path:
        return (self.chroot / remote_path.lstrip("/")).resolve()

    def _in_sandbox(self, remote_path: str) -> bool:
        local = self._local(remote_path)
        return local == self.chroot or self.chroot in local.parents

    def _resolve(self, target: str, cwd: str) -> str:
        return posixpath.normpath(target if target.startswith("/") else f"{cwd.rstrip('/')}/{target}")

    def _expand(self, text: str) -> str:
        text = re.sub(r"\$!", str(self._last_bg_pid or self._pid), text)

        def repl(match: re.Match[str]) -> str:
            return self.env_seen.get(match.group(1) or match.group(2), "")

        return re.sub(r"\$\{(\w+)\}|\$(\w+)", repl, text)

    def _exec(self, channel) -> None:  # noqa: ANN001
        raw = self.exec_log[-1]
        status = 0
        try:
            status = self._run_text(channel, raw, lambda text: channel.sendall(text.encode()))
        except (OSError, EOFError):
            return
        finally:
            # paramiko sends the exec-request success *after* check_channel_exec_request returns,
            # i.e. after this thread was already spawned. Closing the channel before that ack is
            # on the wire makes the client's exec_command() observe "Channel closed" instead of
            # the exit status. Output is safe to send early (the client buffers it); only the
            # status+close must wait for the ack to be flushed.
            time.sleep(0.05)
            try:
                channel.send_exit_status(status)
            except (OSError, EOFError):
                pass
            try:
                channel.close()
            except (OSError, EOFError):
                pass

    def _run_text(self, channel, text: str, sink, depth: int = 0) -> int:  # noqa: ANN001
        """Evaluate shell text, returning the last exit status."""
        status = 0
        for segment in split_top_level(text):
            env, stages, _tokens = tokenize(segment)
            self.env_seen.update(env)
            for stage in stages:
                if not stage.words:
                    continue
                self._pid += 1
                self._last_pid = self._pid
                if stage.background:
                    self._last_bg_pid = self._pid
                handle = None
                target = sink
                if stage.redirect and stage.redirect != "/dev/null":
                    resolved = self._resolve(stage.redirect, self.cwd)
                    if not self._in_sandbox(resolved):
                        channel.sendall_stderr(f"fake-ssh: write outside sandbox: {resolved}\n".encode())
                        return 1
                    local = self._local(resolved)
                    local.parent.mkdir(parents=True, exist_ok=True)
                    self.files_written.append(resolved)
                    handle = local.open("ab" if stage.append else "wb")
                    target = lambda text: handle.write(text.encode())  # noqa: E731
                try:
                    status = self._eval(channel, stage.words, target, depth)
                finally:
                    if handle is not None:
                        handle.close()
                if status != 0:
                    return status
        return status

    def _eval(self, channel, words: list[str], sink, depth: int) -> int:  # noqa: ANN001
        command, args = words[0], words[1:]

        if command in _WRAPPER_FLAGS:
            index = 0
            while index < len(args) and args[index].startswith("-"):
                index += 1 + (1 if args[index] in _WRAPPER_FLAGS[command] else 0)
            rest = args[index:]
            return self._eval(channel, rest, sink, depth) if rest else 0

        if command in ("sh", "bash", "dash", "ash", "zsh"):
            if "-c" in args:
                index = args.index("-c")
                script = args[index + 1] if index + 1 < len(args) else ""
                if depth > 4:
                    return 0
                return self._run_text(channel, script, sink, depth + 1)
            return 0

        if command == "echo":
            sink(self._expand(" ".join(args)) + "\n")
            return 0
        if command == "pwd":
            sink(self.cwd + "\n")
            return 0
        if command == "whoami":
            sink(self.user + "\n")
            return 0
        if command == "id":
            sink("uid=0(root) gid=0(root) groups=0(root)\n")
            return 0
        if command == "uname":
            sink("FakeKernel 6.6.6-fake #1 SMP x86_64 GNU/Linux\n")
            return 0
        if command == "cat":
            for name in args:
                if name.startswith("-"):
                    continue
                resolved = self._resolve(name, self.cwd)
                if not self._in_sandbox(resolved):
                    channel.sendall_stderr(f"cat: {name}: Permission denied\n".encode())
                    return 1
                local = self._local(resolved)
                if not local.is_file():
                    channel.sendall_stderr(f"cat: {name}: No such file or directory\n".encode())
                    return 1
                sink(local.read_text(encoding="utf-8", errors="replace"))
            return 0
        if command == "printf":
            sink(" ".join(args))
            return 0
        if command == "sleep":
            seconds = float(args[0]) if args else 1.0
            deadline = time.monotonic() + min(seconds, 30.0)
            while time.monotonic() < deadline:
                if channel.closed:
                    return 143
                time.sleep(0.05)
            return 0
        if command == "true":
            return 0
        if command == "false":
            return 7
        if command == "cd":
            target = args[0] if args else "/"
            resolved = self._resolve(target, self.cwd)
            if not self._in_sandbox(resolved):
                channel.sendall_stderr(f"fake-ssh: cd outside sandbox: {target}\n".encode())
                return 1
            self.cwd = resolved
            self.cwd_seen.append(resolved)
            return 0

        channel.sendall_stderr(f"fake-ssh: unknown command: {command}\n".encode())
        return 127


class FakeSFTPServer(paramiko.SFTPServerInterface):
    """SFTP view rooted at the chroot; refuses anything that escapes it."""

    def __init__(self, server: FakeSSHServer, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        # paramiko passes the ServerInterface instance here; it is not stored on the base class.
        self.host = server
        self.chroot = Path(server.chroot).resolve()

    def _real(self, path: str) -> Path:
        candidate = (self.chroot / str(path).lstrip("/")).resolve()
        if candidate != self.chroot and self.chroot not in candidate.parents:
            raise OSError(f"path escapes the sandbox: {path}")
        return candidate

    @staticmethod
    def _attrs(path: Path) -> paramiko.SFTPAttributes:
        attrs = paramiko.SFTPAttributes.from_stat(path.stat())
        attrs.filename = path.name
        return attrs

    def list_folder(self, path):  # noqa: ANN001
        try:
            return [self._attrs(item) for item in sorted(self._real(path).iterdir())]
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def stat(self, path):  # noqa: ANN001
        try:
            return self._attrs(self._real(path))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    lstat = stat

    def open(self, path, flags, attr):  # noqa: ANN001
        try:
            real = self._real(path)
            if flags & os.O_TRUNC:
                mode = "wb" if flags & (os.O_WRONLY | os.O_RDWR) else "rb"
            elif flags & os.O_APPEND:
                mode = "ab"
            elif flags & os.O_RDWR:
                mode = "r+b" if real.exists() else "w+b"
            elif flags & os.O_WRONLY:
                mode = "r+b" if real.exists() else "wb"
            else:
                mode = "rb"
            fileobj = real.open(mode)
            if attr is not None and attr.st_mode is not None:
                os.chmod(real, attr.st_mode & 0o7777)
            return _Handle(fileobj, flags)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def remove(self, path):  # noqa: ANN001
        try:
            self._real(path).unlink()
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def mkdir(self, path, attr):  # noqa: ANN001
        try:
            self._real(path).mkdir()
            if attr is not None and attr.st_mode is not None:
                os.chmod(self._real(path), attr.st_mode & 0o7777)
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def rmdir(self, path):  # noqa: ANN001
        try:
            self._real(path).rmdir()
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def rename(self, oldpath, newpath):  # noqa: ANN001
        try:
            self._real(oldpath).rename(self._real(newpath))
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def chattr(self, path, attr):  # noqa: ANN001
        try:
            real = self._real(path)
            if attr.st_mode is not None:
                self.host.chmod_requests.append((posixpath.normpath(str(path)), attr.st_mode & 0o7777))
                os.chmod(real, attr.st_mode & 0o7777)
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno or 2)

    def canonicalize(self, path):  # noqa: ANN001
        text = str(path)
        if not text.startswith("/"):
            text = f"/{text}"
        return posixpath.normpath(text)


class _Handle(paramiko.SFTPHandle):
    """SFTP handle over a plain file object."""

    def __init__(self, fileobj, flags: int):
        super().__init__(flags)
        self.readfile = fileobj
        self.writefile = fileobj

    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def chattr(self, attr):  # noqa: ANN001
        try:
            os.chmod(self.readfile.name, attr.st_mode & 0o7777)
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def close(self):
        try:
            self.readfile.close()
        except OSError:
            pass


class FakeSSHServerThread(threading.Thread):
    """Accept loop bound to 127.0.0.1 on an ephemeral port."""

    def __init__(self, chroot: Path, user: str = DEFAULT_USER, password: str = DEFAULT_PASSWORD,
                 host_key: paramiko.PKey | None = None):
        super().__init__(daemon=True)
        self.chroot = Path(chroot)
        self.user = user
        self.password = password
        self.host_key = host_key or paramiko.RSAKey.generate(2048)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(16)
        self.port = self.socket.getsockname()[1]
        self.instances: list[FakeSSHServer] = []
        self.transports: list[paramiko.Transport] = []
        self._shutdown = threading.Event()  # 不能叫 _stop：threading.Thread 内部有 _stop() 方法

    def run(self) -> None:
        # Blocking accept: stop() closes the listening socket to break out. Using a socket
        # timeout here would leak onto accepted sockets on Windows and break the transport.
        while not self._shutdown.is_set():
            try:
                conn, _ = self.socket.accept()
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        # Windows propagates the listening socket's timeout to accepted sockets, which would
        # make paramiko raise socket.timeout on idle reads and tear the transport down. Force
        # the accepted socket back to blocking mode before handing it over.
        conn.settimeout(None)
        conn.setblocking(True)
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        self.transports.append(transport)
        server = FakeSSHServer(self.host_key, self.chroot, self.user, self.password)
        self.instances.append(server)
        try:
            transport.start_server(server=server)
        except Exception:
            transport.close()
            return
        # start_server() can return before the client finishes negotiating, so is_active() is
        # briefly False. Closing on that would reset the connection; wait for it, then block
        # until the transport thread ends (i.e. the connection is really over).
        deadline = time.monotonic() + 10.0
        while not transport.is_active() and time.monotonic() < deadline and not self._shutdown.is_set():
            time.sleep(0.01)
        transport.join()
        transport.close()

    @property
    def exec_log(self) -> list[str]:
        return [entry for instance in self.instances for entry in instance.exec_log]

    def session(self, timeout: float = 5.0) -> FakeSSHServer:
        """The most recently established session; waits for it to appear."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.instances:
                return self.instances[-1]
            time.sleep(0.01)
        raise AssertionError("no SSH session was established")

    def stop(self) -> None:
        """Stop listening and drop every transport. Safe to call more than once."""
        self._shutdown.set()
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        for transport in self.transports:
            try:
                transport.close()
            except Exception:
                pass
        try:
            self.socket.close()
        except OSError:
            pass
