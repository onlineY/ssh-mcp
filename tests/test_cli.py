"""CLI tests: the same guarded operations driven from a shell, against the fake host."""

from __future__ import annotations

import json

import pytest

from ssh_hop import client
from ssh_hop.cli import main


@pytest.fixture
def cli_env(hosts_file, monkeypatch):
    monkeypatch.setenv("SSH_HOP_HOSTS", str(hosts_file))
    return hosts_file


def test_ls_lists_hosts_with_their_policy(cli_env, capsys):
    assert main(["ls"]) == 0
    out = capsys.readouterr().out
    assert "fake" in out and "restricted" in out
    assert "all commands" in out, "the permissive default should be visible"
    assert "2 allow rule(s)" in out and "no-upload" in out


def test_ls_json_exposes_no_credentials(cli_env, capsys, ssh_server):
    assert main(["ls", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    rendered = json.dumps(payload)
    assert {entry["alias"] for entry in payload["hosts"]} == {"fake", "restricted"}
    assert "127.0.0.1" not in rendered and ssh_server.password not in rendered


def test_check_validates_without_connecting(cli_env, capsys, ssh_server):
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "hosts file OK" in out and "2 host(s)" in out
    assert ssh_server.exec_log == [], "check must not connect unless asked"


def test_check_connect_probes_every_host(cli_env, capsys):
    assert main(["check", "--connect"]) == 0
    out = capsys.readouterr().out
    assert out.count("FakeKernel") == 2


def test_run_prints_stdout_and_propagates_exit_code(cli_env, capsys):
    assert main(["run", "fake", "echo from-cli"]) == 0
    assert capsys.readouterr().out.strip() == "from-cli"
    assert main(["run", "fake", "false"]) == 7


def test_run_refusal_exits_with_code_2(cli_env, capsys):
    assert main(["run", "restricted", "uname -a"]) == 2
    assert "allowCommands" in capsys.readouterr().err


def test_run_json_matches_the_mcp_shape(cli_env, capsys):
    assert main(["run", "fake", "echo shaped", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exitCode"] == 0 and payload["stdout"].strip() == "shaped"


def test_put_then_get_round_trips(cli_env, capsys, workdir):
    (workdir / "payload.txt").write_bytes(b"cli-round-trip\n")
    assert main(["put", "fake", str(workdir / "payload.txt"), "/srv/payload.txt"]) == 0
    assert "uploaded 1 file(s)" in capsys.readouterr().out
    assert main(["get", "fake", "/srv/payload.txt", str(workdir / "back.txt")]) == 0
    assert (workdir / "back.txt").read_bytes() == b"cli-round-trip\n"


def test_put_refuses_a_path_outside_upload_roots(cli_env, capsys, workdir):
    (workdir / "x.txt").write_bytes(b"x")
    assert main(["put", "fake", str(workdir / "x.txt"), "/etc/cron.d/x"]) == 2
    assert "outside allowed roots" in capsys.readouterr().err


def test_rls_lists_a_remote_directory(cli_env, capsys):
    assert main(["rls", "fake", "/srv"]) == 0
    assert "app.conf" in capsys.readouterr().out


def test_rls_reports_a_missing_directory(cli_env, capsys):
    assert main(["rls", "fake", "/srv/absent"]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_classify_shows_the_matching_rule_without_connecting(cli_env, capsys, ssh_server):
    assert main(["classify", "restricted", "echo hello"]) == 0
    out = capsys.readouterr().out
    assert "allowed" in out and "matched:" in out and "^echo" in out
    assert ssh_server.exec_log == [], "classify must not connect"


def test_classify_flags_a_refused_command_and_lists_rules(cli_env, capsys):
    assert main(["classify", "restricted", "systemctl restart nginx"]) == 2
    out = capsys.readouterr().out
    assert "refused" in out and "no allowCommands rule matches" in out
    assert "allow:" in out and "deny:" in out


def test_classify_reports_a_deny_rule(cli_env, capsys, tmp_path, monkeypatch):
    import json as _json

    hosts = _json.loads(cli_env.read_text(encoding="utf-8"))
    hosts["hosts"]["fake"]["denyCommands"] = [r"rm\s+-rf\s+/"]
    cli_env.write_text(_json.dumps(hosts), encoding="utf-8")
    assert main(["classify", "fake", "rm -rf /"]) == 2
    assert "denyCommands" in capsys.readouterr().out


def test_unknown_alias_fails_with_a_useful_message(cli_env, capsys):
    assert main(["run", "ghost", "echo hi"]) == 1
    assert "unknown host alias 'ghost'" in capsys.readouterr().err


def test_probe_reports_identity(cli_env, capsys):
    assert main(["probe", "fake"]) == 0
    out = capsys.readouterr().out
    assert "FakeKernel" in out and "latencyMs" in out


def test_background_run_returns_a_pid(cli_env, capsys):
    assert main(["run", "fake", "echo bg", "--background", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pid"].isdigit() and payload["logPath"].startswith("/tmp/ssh-hop-")


def test_missing_hosts_file_is_reported(cli_env, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_HOP_HOSTS", str(tmp_path / "nope.json"))
    assert main(["ls"]) == 1
    assert "does not point at a readable file" in capsys.readouterr().err


def test_init_creates_a_loadable_config(tmp_path, monkeypatch, capsys):
    target = tmp_path / "hosts.json"
    assert main(["--hosts-file", str(target), "init"]) == 0
    assert "created" in capsys.readouterr().out
    assert json.loads(target.read_text(encoding="utf-8"))["hosts"]


def test_cli_drops_connections_on_exit(cli_env):
    main(["run", "fake", "echo one"])
    assert client._pool == {}  # noqa: SLF001 - the CLI must not leave sockets behind
