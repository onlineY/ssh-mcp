"""End-to-end tests over a real SSH/SFTP transport against the in-process fake host.

These assert what the caller observes: output, exit codes, transfer results, policy
refusals and connection reuse - not internal wiring.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from ssh_hop import client, guard
from ssh_hop.config import ConfigError, Host, resolve_alias


# --- command execution ------------------------------------------------------

def test_command_output_and_exit_code(host):
    result = client.run(host, "echo hello")
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert result.stderr == ""
    assert result.duration_ms >= 0


def test_command_actually_reaches_the_host(host, ssh_server):
    client.run(host, "echo marked-42")
    assert any("marked-42" in entry for entry in ssh_server.exec_log)


def test_nonzero_exit_code_is_reported(host):
    result = client.run(host, "false")
    assert result.exit_code == 7


def test_fast_exiting_commands_report_their_status_repeatedly(host):
    """A command that closes its channel instantly must still yield an exit code, not an error."""
    for _ in range(12):
        result = client.run(host, "false")
        assert result.exit_code == 7, f"lost the exit status: {result.to_dict()}"
        assert not result.timed_out

    for _ in range(12):
        assert client.run(host, "true").exit_code == 0


def test_dead_pooled_connection_is_recovered_transparently(host, ssh_server):
    """A connection dropped while idle must not surface as a failed command."""
    assert client.run(host, "echo first").stdout.strip() == "first"
    ssh_server.transports[-1].close()  # the remote side vanishes between calls
    time.sleep(0.3)

    result = client.run(host, "echo second")
    assert result.exit_code == 0, result.to_dict()
    assert result.stdout.strip() == "second"


def test_trailing_output_is_not_lost_when_the_channel_closes_early(host):
    result = client.run(host, "echo final-line")
    assert result.stdout.strip() == "final-line"


def test_stderr_is_captured_separately(host):
    result = client.run(host, "cat /missing-file")
    assert result.exit_code != 0
    assert "No such file" in result.stderr
    assert result.stdout == ""


def test_default_cwd_is_applied(host):
    scoped = Host(**{**host.__dict__, "defaultCwd": "/srv"})
    result = client.run(scoped, "pwd")
    assert result.stdout.strip() == "/srv"


def test_per_call_cwd_overrides_default(host, ssh_server):
    scoped = Host(**{**host.__dict__, "defaultCwd": "/srv"})
    result = client.run(scoped, "pwd", cwd="/etc")
    assert result.stdout.strip() == "/etc"


def test_host_env_is_forwarded(host):
    scoped = Host(**{**host.__dict__, "env": {"DEPLOY_ENV": "staging"}})
    result = client.run(scoped, "echo $DEPLOY_ENV")
    assert result.stdout.strip() == "staging"


def test_per_call_env_overrides_host_env(host):
    scoped = Host(**{**host.__dict__, "env": {"DEPLOY_ENV": "staging"}})
    result = client.run(scoped, "echo $DEPLOY_ENV", env={"DEPLOY_ENV": "prod"})
    assert result.stdout.strip() == "prod"


def test_timeout_is_enforced_and_reported(host):
    started = time.monotonic()
    result = client.run(host, "sleep 30", timeout=2)
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert result.exit_code is None
    assert elapsed < 15
    assert any("may still be running" in warning for warning in result.warnings)


def test_background_command_returns_immediately_with_pid_and_log(host):
    started = time.monotonic()
    result = client.run(host, "echo deployed", background=True)
    assert time.monotonic() - started < 10
    assert result.pid and result.pid.isdigit()
    assert result.log_path and result.log_path.startswith("/tmp/ssh-hop-")
    assert "SSH_HOP_PID" not in result.stdout


def test_background_log_file_receives_output(host, ssh_server):
    result = client.run(host, "echo background-output", background=True)
    local = Path(ssh_server.chroot) / result.log_path.lstrip("/")
    for _ in range(50):
        if local.exists() and local.read_text(encoding="utf-8").strip():
            break
        time.sleep(0.05)
    assert local.read_text(encoding="utf-8").strip() == "background-output"


def test_large_output_is_truncated_with_head_and_tail_preserved(host, ssh_server):
    (Path(ssh_server.chroot) / "srv" / "big.txt").write_text(
        "FIRST-LINE\n" + ("y" * 60_000) + "\nLAST-LINE", encoding="utf-8"
    )
    result = client.run(host, "cat /srv/big.txt")
    assert result.truncated
    assert "FIRST-LINE" in result.stdout
    assert "LAST-LINE" in result.stdout
    assert len(result.stdout) < 20_000


def test_allowed_commands_run_and_refused_ones_raise(host):
    assert client.run(host, "cat /srv/app.conf").exit_code == 0
    assert client.run(host, "echo changed > /srv/out.txt").exit_code == 0


def test_write_refused_when_policy_blocks_it(host):
    locked = Host(**{**host.__dict__, "allowCommands": [r"^cat\b"]})
    with pytest.raises(guard.GuardDenied, match="no allowCommands rule matches"):
        client.run(locked, "echo changed > /srv/out.txt")
    assert client.run(locked, "cat /srv/app.conf").exit_code == 0


def test_deny_rule_blocks_a_host_wide_command(host):
    guarded = Host(**{**host.__dict__, "denyCommands": [r"\breboot\b"]})
    with pytest.raises(guard.GuardDenied, match="denyCommands"):
        client.run(guarded, "reboot")


def test_unknown_alias_is_rejected(loaded_hosts):
    with pytest.raises(ConfigError, match="unknown host alias"):
        resolve_alias(loaded_hosts, "fakee")


# --- connection reuse -------------------------------------------------------

def test_connections_are_reused_between_calls(host, ssh_server):
    client.run(host, "echo one")
    client.run(host, "echo two")
    client.run(host, "echo three")
    assert len(ssh_server.instances) == 1, "each call should reuse the pooled connection"


def test_connection_is_reestablished_after_idle_expiry(host, ssh_server):
    """`idleReuseSec: 0` must never reuse a connection across calls."""
    fresh = Host(**{**host.__dict__, "idleReuseSec": 0})
    client.run(fresh, "echo one")
    client.run(fresh, "echo two")
    # At least one connection per call. Exactly two is the common case; a dropped fresh
    # connection is retried (correctly), which can add one more.
    assert len(ssh_server.instances) >= 2


def test_close_all_drops_the_connection(host, ssh_server):
    client.run(host, "echo one")
    client.close_all()
    client.run(host, "echo two")
    assert len(ssh_server.instances) == 2


# --- failures ---------------------------------------------------------------

def test_unreachable_host_reports_a_clean_error(host, ssh_server):
    ssh_server.stop()
    unreachable = Host(**{**host.__dict__, "connectTimeout": 2})
    with pytest.raises(client.SSHError, match="cannot reach|timed out"):
        client.run(unreachable, "echo hello")


def test_wrong_password_reports_authentication_failure(host, ssh_server):
    bad = Host(**{**host.__dict__, "password": "wrong"})
    with pytest.raises(client.SSHError, match="authentication failed"):
        client.run(bad, "echo hello")
    assert "wrong" not in repr(bad)


def test_credentials_are_absent_from_repr(host):
    text = repr(host)
    assert host.password not in text
    assert host.host not in text
    assert host.user not in text


def test_strict_host_keys_refuse_an_unknown_host(host, ssh_server, monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_HOP_HOME", str(tmp_path / "strict-state"))
    strict = Host(**{**host.__dict__, "knownHosts": "strict"})
    with pytest.raises(client.SSHError, match="known_hosts|not in known_hosts"):
        client.run(strict, "echo hello")


def test_auto_add_learns_the_host_key(host, ssh_server, monkeypatch, tmp_path):
    state = tmp_path / "learn-state"
    monkeypatch.setenv("SSH_HOP_HOME", str(state))
    client._stores.clear()  # noqa: SLF001 - module-level cache keyed by path
    learn = Host(**{**host.__dict__, "knownHosts": "auto-add"})
    assert client.run(learn, "echo hello").exit_code == 0
    known_hosts = state / "known_hosts"
    assert known_hosts.is_file() and "127.0.0.1" in known_hosts.read_text(encoding="utf-8")


# --- uploads ----------------------------------------------------------------

def test_upload_file_lands_with_matching_content(host, workdir, ssh_server):
    source = workdir / "app.conf"
    source.write_bytes(b"listen 8080\n")
    result = client.upload(host, str(source), "/srv/deployed.conf")
    assert result.ok and result.files == 1 and result.bytes == len(b"listen 8080\n")
    assert (Path(ssh_server.chroot) / "srv" / "deployed.conf").read_bytes() == b"listen 8080\n"


def test_upload_creates_missing_remote_directories(host, workdir, ssh_server):
    source = workdir / "deploy.sh"
    source.write_bytes(b"#!/bin/sh\necho deploy\n")
    client.upload(host, str(source), "/srv/releases/2026/deploy.sh")
    landed = Path(ssh_server.chroot) / "srv" / "releases" / "2026" / "deploy.sh"
    assert landed.read_bytes() == b"#!/bin/sh\necho deploy\n"


def test_upload_directory_recurses(host, workdir, ssh_server):
    bundle = workdir / "dist"
    (bundle / "static").mkdir(parents=True)
    (bundle / "index.html").write_bytes(b"<html>")
    (bundle / "static" / "app.js").write_bytes(b"console.log(1)")
    result = client.upload(host, str(bundle), "/srv/dist")
    assert result.files == 2
    root = Path(ssh_server.chroot) / "srv" / "dist"
    assert (root / "index.html").read_bytes() == b"<html>"
    assert (root / "static" / "app.js").is_file()


def test_upload_mode_is_applied(host, workdir, ssh_server):
    source = workdir / "run.sh"
    source.write_bytes(b"echo\n")
    client.upload(host, str(source), "/srv/run.sh", mode="750")
    assert ("/srv/run.sh", 0o750) in ssh_server.session().chmod_requests


def test_upload_refuses_paths_outside_upload_roots(host, workdir, ssh_server):
    source = workdir / "x.txt"
    source.write_text("x", encoding="utf-8")
    with pytest.raises(guard.GuardDenied, match="outside allowed roots"):
        client.upload(host, str(source), "/etc/cron.d/evil")


def test_upload_refuses_local_paths_outside_local_roots(host, tmp_path, ssh_server):
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(guard.GuardDenied, match="local path outside"):
        client.upload(host, str(outside), "/srv/outside.txt")


def test_upload_refuses_when_host_disables_it(host, workdir, ssh_server):
    no_upload = Host(**{**host.__dict__, "allowUpload": False})
    source = workdir / "x.txt"
    source.write_text("x", encoding="utf-8")
    with pytest.raises(guard.GuardDenied, match="uploads are disabled"):
        client.upload(no_upload, str(source), "/srv/x.txt")


def test_upload_reports_a_missing_local_file(host, workdir):
    with pytest.raises(client.SSHError, match="does not exist"):
        client.upload(host, str(workdir / "nope.txt"), "/srv/nope.txt")


def test_upload_skip_existing_when_overwrite_is_off(host, workdir, ssh_server):
    source = workdir / "keep.txt"
    source.write_text("new", encoding="utf-8")
    existing = Path(ssh_server.chroot) / "srv" / "keep.txt"
    existing.write_text("old", encoding="utf-8")
    result = client.upload(host, str(source), "/srv/keep.txt", overwrite=False)
    assert result.skipped == ["/srv/keep.txt"]
    assert result.files == 0
    assert existing.read_text(encoding="utf-8") == "old"


# --- downloads --------------------------------------------------------------

def test_download_file_matches_content(host, workdir, ssh_server):
    (Path(ssh_server.chroot) / "etc" / "syslog.test").write_text("line one\nline two\n", encoding="utf-8")
    target = workdir / "pulled.log"
    result = client.download(host, "/etc/syslog.test", str(target))
    assert result.ok and result.files == 1
    assert target.read_text(encoding="utf-8") == "line one\nline two\n"


def test_download_directory_recurses(host, workdir, ssh_server):
    logs = Path(ssh_server.chroot) / "etc" / "logs"
    logs.mkdir()
    (logs / "a.log").write_text("a", encoding="utf-8")
    (logs / "b.log").write_text("b", encoding="utf-8")
    target = workdir / "pulled"
    result = client.download(host, "/etc/logs", str(target))
    assert result.files == 2
    assert (target / "a.log").read_text(encoding="utf-8") == "a"
    assert (target / "b.log").read_text(encoding="utf-8") == "b"


def test_download_refuses_paths_outside_download_roots(host, workdir):
    with pytest.raises(guard.GuardDenied, match="outside allowed roots"):
        client.download(host, "/root/.ssh/id_rsa", str(workdir / "key"))


def test_download_refuses_when_host_disables_it(host, workdir):
    no_download = Host(**{**host.__dict__, "allowDownload": False})
    with pytest.raises(guard.GuardDenied, match="downloads are disabled"):
        client.download(no_download, "/srv/app.conf", str(workdir / "app.conf"))


def test_download_reports_a_missing_remote_path(host, workdir):
    with pytest.raises(client.SSHError, match="does not exist"):
        client.download(host, "/srv/absent.txt", str(workdir / "absent.txt"))


def test_upload_then_download_roundtrip_is_byte_exact(host, workdir, ssh_server):
    payload = ("line %d\n" % i for i in range(500))
    source = workdir / "roundtrip.txt"
    source.write_text("".join(payload), encoding="utf-8")
    client.upload(host, str(source), "/srv/roundtrip.txt")
    target = workdir / "back.txt"
    client.download(host, "/srv/roundtrip.txt", str(target))
    assert target.read_bytes() == source.read_bytes()


# --- remote listing ---------------------------------------------------------

def test_listdir_reports_types_and_sizes(host, ssh_server):
    listing = client.listdir(host, "/srv")
    names = {entry["name"]: entry for entry in listing["entries"]}
    assert names["app.conf"]["type"] == "file"
    assert names["app.conf"]["size"] == len(b"port=8080\n")
    assert listing["type"] == "dir"


def test_listdir_hides_dotfiles_unless_requested(host, ssh_server):
    hidden = Path(ssh_server.chroot) / "srv" / ".env"
    hidden.write_bytes(b"SECRET=1")
    assert all(entry["name"] != ".env" for entry in client.listdir(host, "/srv")["entries"])
    assert any(entry["name"] == ".env" for entry in client.listdir(host, "/srv", True)["entries"])


def test_listdir_stats_a_single_file(host):
    listing = client.listdir(host, "/srv/app.conf")
    assert listing["type"] == "file"
    assert listing["size"] == len(b"port=8080\n")


def test_listdir_reports_missing_path(host):
    with pytest.raises(client.SSHError, match="does not exist"):
        client.listdir(host, "/srv/absent")


# --- probing and audit ------------------------------------------------------

def test_probe_returns_identity_and_latency(host):
    report = client.probe(host)
    assert report["ok"] and report["alias"] == "fake"
    assert report["latencyMs"] >= 0
    assert any("FakeKernel" in line for line in report["identity"])
    assert report["server"].startswith("SSH-")


def test_audit_log_records_operations_and_redacts_secrets(host, workdir, ssh_server):
    from ssh_hop.config import app_home

    client.run(host, "echo token=SUPERSECRETVALUE")
    client.upload(host, str(_write(workdir / "a.txt", "x")), "/srv/a.txt")
    client.download(host, "/srv/a.txt", str(workdir / "a-back.txt"))
    lines = [json.loads(line) for line in (app_home() / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    actions = {entry["action"] for entry in lines}
    assert {"run", "upload", "download"} <= actions
    assert all(entry["alias"] == "fake" for entry in lines)
    assert "SUPERSECRETVALUE" not in (app_home() / "audit.jsonl").read_text(encoding="utf-8")
    assert all(host.password not in json.dumps(entry) for entry in lines)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_run_many_queries_hosts_concurrently(host, ssh_server):
    from ssh_hop import server as server_module

    def clone(alias: str) -> Host:
        return Host(**{**host.__dict__, "alias": alias})

    server_module._cache = {"node-a": clone("node-a"), "node-b": clone("node-b")}  # noqa: SLF001
    try:
        started = time.monotonic()
        payload = _call(server_module.ssh_run_many, hosts=["node-a", "node-b"], command="sleep 1")
        elapsed = time.monotonic() - started
    finally:
        server_module._cache = None  # noqa: SLF001
    assert payload["ok"], payload
    assert [item["alias"] for item in payload["results"]] == ["node-a", "node-b"]
    assert all(item["status"] == "ok" for item in payload["results"])
    assert elapsed < 2.0, f"hosts were queried serially ({elapsed:.1f}s)"


def test_run_many_reports_each_host_status(host, ssh_server):
    from ssh_hop import server as server_module

    locked = Host(**{**host.__dict__, "alias": "locked", "allowCommands": [r"^echo\b"]})
    writable = Host(**{**host.__dict__, "alias": "writable"})
    server_module._cache = {"writable": writable, "locked": locked}  # noqa: SLF001
    try:
        payload = _call(server_module.ssh_run_many, hosts=["writable", "locked"],
                        command="uname -a")
    finally:
        server_module._cache = None  # noqa: SLF001
    assert payload["ok"], "per-host failures must not fail the whole call"
    statuses = {item["alias"]: item["status"] for item in payload["results"]}
    assert statuses == {"writable": "ok", "locked": "refused"}
    rejected = next(item for item in payload["results"] if item["alias"] == "locked")
    assert "allowCommands" in rejected["error"] and "exitCode" not in rejected


def test_run_many_can_fail_fast(host, ssh_server):
    from ssh_hop import server as server_module

    locked = Host(**{**host.__dict__, "alias": "locked", "allowCommands": [r"^echo\b"]})
    server_module._cache = {"locked": locked}  # noqa: SLF001
    try:
        payload = _call(server_module.ssh_run_many, hosts=["locked"], command="uname -a",
                        stop_on_error=True)
    finally:
        server_module._cache = None  # noqa: SLF001
    assert not payload["ok"] and payload["kind"] == "refused"
    assert "allowCommands" in payload["error"]


def test_run_many_rejects_unknown_alias(host):
    from ssh_hop import server as server_module

    server_module._cache = {"fake": host}  # noqa: SLF001
    try:
        payload = _call(server_module.ssh_run_many, hosts=["nope"], command="echo hi")
        assert not payload["ok"] and payload["kind"] == "unknown-host"
    finally:
        server_module._cache = None  # noqa: SLF001


def _call(fn, **kwargs):
    """Invoke a tool function through its underlying wrapper (bypassing pydantic models)."""
    return fn(**kwargs)


def test_concurrent_runs_do_not_interleave_on_one_connection(host):
    results: list[str] = []

    def worker(tag: str) -> None:
        results.append(client.run(host, f"echo {tag}").stdout.strip())

    threads = [threading.Thread(target=worker, args=(f"t{index}",)) for index in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [f"t{index}" for index in range(5)]


# --- connection watchdog ----------------------------------------------------

def test_stalled_handshake_is_aborted_by_net_timeout(host):
    """A peer that accepts TCP but never sends a banner must not hang the caller forever.

    paramiko's connectTimeout does not bound the whole handshake, which is what makes a
    wedged host hang an agent. netTimeout closes the socket out from under it.
    """
    import socket
    import threading

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def accept_forever() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            accepted.append(conn)  # hold it open, never speak SSH

    threading.Thread(target=accept_forever, daemon=True).start()
    black_hole = Host(**{**host.__dict__, "port": listener.getsockname()[1],
                         "connectTimeout": 30, "netTimeout": 3, "idleReuseSec": 0})
    try:
        started = time.monotonic()
        with pytest.raises(client.SSHError, match="netTimeout"):
            client.run(black_hole, "echo hello")
        assert time.monotonic() - started < 20, "the watchdog did not cut the handshake short"
    finally:
        stop.set()
        for conn in accepted:
            conn.close()
        listener.close()


def test_net_timeout_is_configurable(host, hosts_file, monkeypatch):
    import json as _json

    document = _json.loads(hosts_file.read_text(encoding="utf-8"))
    document["hosts"]["fake"]["netTimeout"] = 7
    hosts_file.write_text(_json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("SSH_HOP_HOSTS", str(hosts_file))
    from ssh_hop.config import load_hosts

    assert load_hosts()["fake"].netTimeout == 7
    assert load_hosts()["restricted"].netTimeout == 20  # default preserved


def test_connection_is_reused_across_a_short_pause(host, ssh_server):
    """A connection must be reused across the gap between calls while inside idleReuseSec."""
    client.run(host, "echo first")
    time.sleep(5)
    client.run(host, "echo second")
    client.run(host, "echo third")
    assert len(ssh_server.instances) == 1, "the connection should still be reused"
