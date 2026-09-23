"""End-to-end tests of the real MCP server over stdio.

Spawns `python -m ssh_hop` as a subprocess exactly as an MCP client would, then drives
it with the official client over the wire. Also asserts that stdout stays clean: a stray
print would corrupt the protocol channel.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

VENV_PYTHON = Path(sys.executable)
TOOL_NAMES = {
    "ssh_list_hosts", "ssh_probe", "ssh_run", "ssh_run_policy", "ssh_run_many",
    "sftp_upload", "sftp_download", "sftp_list",
}


def write_hosts(tmp_path: Path, ssh_server, staging: Path) -> Path:
    document = {
        "defaults": {"port": ssh_server.port, "connectTimeout": 5, "knownHosts": "ignore"},
        "hosts": {
            "fake": {
                "desc": "in-process test host",
                "host": "127.0.0.1",
                "user": ssh_server.user,
                "password": ssh_server.password,
                "localRoots": [str(staging)],
                "uploadRoots": ["/srv"],
                "downloadRoots": ["/srv"],
            },
            "restricted": {
                "desc": "only echo and cat are allowed",
                "host": "127.0.0.1",
                "user": ssh_server.user,
                "password": ssh_server.password,
                "allowCommands": [r"^echo\b", r"^cat\b"],
                "denyCommands": [r"^\s*echo\s+forbidden"],
                "allowUpload": False,
                "localRoots": [str(staging)],
            },
        },
    }
    path = tmp_path / "hosts.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class ServerProcess:
    """Runs the MCP server in-process-ish: same interpreter, its own stdio pipes."""

    def __init__(self, hosts_file: Path, state: Path):
        self.params = StdioServerParameters(
            command=str(VENV_PYTHON),
            args=["-m", "ssh_hop"],
            env={
                "SSH_HOP_HOSTS": str(hosts_file),
                "SSH_HOP_HOME": str(state),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                "PYTHONUNBUFFERED": "1",
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "APPDATA": os.environ.get("APPDATA", ""),
                "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
                "USERPROFILE": os.environ.get("USERPROFILE", ""),
                "TEMP": os.environ.get("TEMP", ""),
                "TMP": os.environ.get("TMP", ""),
            },
        )


async def call(session: ClientSession, name: str, **arguments):
    result = await session.call_tool(name, arguments)
    structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    # unstructured fallback: parse the single text block
    return json.loads(result.content[0].text)


@pytest.fixture
def staging(tmp_path):
    path = tmp_path / "files"
    path.mkdir()
    return path


def run_async(coro):
    """Run one coroutine against the server subprocess."""
    return asyncio.run(coro)


def test_server_advertises_the_documented_tools(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                info = await session.initialize()
                listed = await session.list_tools()
                return info, {tool.name for tool in listed.tools}

    info, names = run_async(scenario())
    server_info = getattr(info, "server_info", None) or getattr(info, "serverInfo")
    assert server_info.name == "ssh-hop"
    assert names == TOOL_NAMES


def test_list_hosts_hides_connection_details(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await call(session, "ssh_list_hosts")

    payload = run_async(scenario())
    assert payload["ok"]
    aliases = {entry["alias"] for entry in payload["hosts"]}
    assert aliases == {"fake", "restricted"}
    rendered = json.dumps(payload)
    assert "127.0.0.1" not in rendered
    assert ssh_server.password not in rendered
    permissive = next(entry for entry in payload["hosts"] if entry["alias"] == "fake")
    assert permissive["commands"] == "all" and permissive["denyCommands"] == []
    narrowed = next(entry for entry in payload["hosts"] if entry["alias"] == "restricted")
    assert narrowed["commands"] == [r"^echo\b", r"^cat\b"]
    assert narrowed["upload"] is False


def test_run_executes_on_the_remote_host(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await call(session, "ssh_run", host="fake", command="echo over-the-wire")

    payload = run_async(scenario())
    assert payload["ok"] and payload["exitCode"] == 0
    assert payload["stdout"].strip() == "over-the-wire"


def test_writes_are_allowed_on_a_permissive_host(tmp_path, ssh_server, staging):
    """The default policy must not block ordinary write commands."""
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await call(session, "ssh_run", host="fake", command="echo deployed > /srv/out.txt")

    payload = run_async(scenario())
    assert payload["ok"] and payload["exitCode"] == 0, payload
    assert (Path(ssh_server.chroot) / "srv" / "out.txt").read_bytes() == b"deployed\n"


def test_policy_refusal_is_structured_and_session_survives(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                refused = await call(session, "ssh_run", host="restricted", command="uname -a")
                allowed = await call(session, "ssh_run", host="restricted", command="cat /srv/app.conf")
                denied = await call(session, "ssh_run", host="restricted", command="echo forbidden thing")
                return refused, allowed, denied

    refused, allowed, denied = run_async(scenario())
    assert refused["ok"] is False and refused["kind"] == "refused"
    assert "no allowCommands rule matches" in refused["error"]
    # a deny rule wins even though ^echo matches the allow list
    assert denied["ok"] is False and "denyCommands" in denied["error"]
    # the server must keep serving after refusing
    assert allowed["ok"] and allowed["stdout"].strip() == "port=8080"


def test_run_policy_answers_without_running(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                allowed = await call(session, "ssh_run_policy", host="restricted", command="echo hi")
                refused = await call(session, "ssh_run_policy", host="restricted", command="rm -rf /")
                permissive = await call(session, "ssh_run_policy", host="fake", command="rm -rf /")
                return allowed, refused, permissive

    allowed, refused, permissive = run_async(scenario())
    assert allowed["ok"] and allowed["matchedRule"] == r"^echo\b"
    assert refused["ok"] is False and refused["allowCommands"] == [r"^echo\b", r"^cat\b"]
    assert permissive["ok"] and permissive["matchedRule"] == "*"
    assert ssh_server.exec_log == [], "ssh_run_policy must not run anything"


def test_unknown_alias_is_reported_without_breaking_the_session(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                bad = await call(session, "ssh_run", host="ghost", command="echo hi")
                good = await call(session, "ssh_probe", host="fake")
                return bad, good

    bad, good = run_async(scenario())
    assert bad["ok"] is False and bad["kind"] == "unknown-host"
    assert "fake" in bad["error"] and "restricted" in bad["error"]
    assert good["ok"] and any("FakeKernel" in line for line in good["identity"])


def test_upload_and_list_round_trip_through_stdio(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")
    (staging / "cfg.txt").write_bytes(b"deployed=yes\n")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                sent = await call(session, "sftp_upload", host="fake",
                                  localPath=str(staging / "cfg.txt"), remotePath="/srv/cfg.txt")
                listing = await call(session, "sftp_list", host="fake", remotePath="/srv")
                pulled = await call(session, "sftp_download", host="fake",
                                    remotePath="/srv/cfg.txt", localPath=str(staging / "back.txt"))
                return sent, listing, pulled

    sent, listing, pulled = run_async(scenario())
    assert sent["ok"] and sent["bytes"] == len(b"deployed=yes\n")
    assert any(entry["name"] == "cfg.txt" for entry in listing["entries"])
    assert pulled["ok"]
    assert (staging / "back.txt").read_bytes() == b"deployed=yes\n"


def test_run_many_reports_per_host_status(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    server = ServerProcess(hosts_file, tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                allowed = await call(session, "ssh_run_many", hosts=["fake", "fake"], command="id")
                mixed = await call(session, "ssh_run_many",
                                   hosts=["fake", "restricted"], command="uname -a")
                return allowed, mixed

    allowed, mixed = run_async(scenario())
    assert allowed["ok"]
    assert {entry["status"] for entry in allowed["results"]} == {"ok"}

    # one host refuses, the other runs: the call still succeeds and reports both
    assert mixed["ok"]
    statuses = {entry["alias"]: entry["status"] for entry in mixed["results"]}
    assert statuses == {"fake": "ok", "restricted": "refused"}
    rejected = next(entry for entry in mixed["results"] if entry["alias"] == "restricted")
    assert "allowCommands" in rejected["error"]


def test_audit_log_is_written_by_the_server_process(tmp_path, ssh_server, staging):
    hosts_file = write_hosts(tmp_path, ssh_server, staging)
    state = tmp_path / "state"
    server = ServerProcess(hosts_file, state)

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await call(session, "ssh_run", host="fake", command="echo audited")

    assert run_async(scenario())["ok"]
    log = state / "audit.jsonl"
    assert log.is_file(), "the server did not write its audit log"
    entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert any(entry["action"] == "run" and entry["alias"] == "fake" for entry in entries)


def test_server_starts_with_a_broken_config_and_reports_it(tmp_path, ssh_server):
    """A missing hosts.json must not crash the transport: tools explain what is wrong."""
    server = ServerProcess(tmp_path / "absent.json", tmp_path / "state")

    async def scenario():
        async with stdio_client(server.params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await call(session, "ssh_list_hosts")

    payload = run_async(scenario())
    assert payload["ok"] is False and payload["kind"] == "config"
    assert "hosts" in payload["error"].lower()
