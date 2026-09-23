"""Shared fixtures: an isolated state dir, a hosts.json, and a live fake SSH host."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_ssh import FakeSSHServerThread  # noqa: E402

from ssh_hop import client  # noqa: E402
from ssh_hop.config import Host, load_hosts  # noqa: E402


@pytest.fixture(autouse=True)
def state_dir(tmp_path_factory, monkeypatch):
    """Point the audit log, staging dir, learned host keys and home dir at temp locations.

    Redirecting HOME matters because hosts.json and the host-key store are discovered relative
    to the user's home directory; without this the suite would read the developer's real config.
    """
    home = tmp_path_factory.mktemp("ssh-hop-state")
    fake_home = tmp_path_factory.mktemp("ssh-hop-home")
    (fake_home / ".ssh").mkdir()
    monkeypatch.setenv("SSH_HOP_HOME", str(home))
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    yield home


@pytest.fixture
def workdir(tmp_path):
    staging = tmp_path / "files"
    staging.mkdir()
    return staging


def make_host(ssh: FakeSSHServerThread, staging: Path, **overrides) -> Host:
    defaults = dict(
        alias="fake",
        host="127.0.0.1",
        user=ssh.user,
        password=ssh.password,
        port=ssh.port,
        connectTimeout=5,
        timeout=15,
        idleReuseSec=30,
        knownHosts="ignore",
        localRoots=[str(staging)],
        uploadRoots=["/srv"],
        downloadRoots=["/srv", "/etc"],
    )
    defaults.update(overrides)
    return Host(**defaults)


@pytest.fixture
def ssh_server(tmp_path):
    root = tmp_path / "remote"
    (root / "srv").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "srv" / "app.conf").write_bytes(b"port=8080\n")
    (root / "etc" / "hostname").write_bytes(b"fake-host\n")
    server = FakeSSHServerThread(root)
    server.start()
    yield server
    server.stop()
    client.close_all()


@pytest.fixture
def host(ssh_server, workdir):
    return make_host(ssh_server, workdir)


@pytest.fixture
def hosts_file(tmp_path, ssh_server, workdir):
    """A real hosts.json wired to the fake server, for config/loader tests."""
    document = {
        "defaults": {"port": ssh_server.port, "connectTimeout": 5, "knownHosts": "ignore"},
        "hosts": {
            "fake": {
                "desc": "test host",
                "host": "127.0.0.1",
                "user": ssh_server.user,
                "password": ssh_server.password,
                "localRoots": [str(workdir)],
                "uploadRoots": ["/srv"],
                "downloadRoots": ["/srv"],
            },
            "restricted": {
                "desc": "only echo and cat are allowed here",
                "host": "127.0.0.1",
                "user": ssh_server.user,
                "password": ssh_server.password,
                "allowCommands": [r"^echo\b", r"^cat\b"],
                "allowUpload": False,
                "localRoots": [str(workdir)],
            },
        },
    }
    path = tmp_path / "hosts.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.fixture
def loaded_hosts(hosts_file, monkeypatch):
    monkeypatch.setenv("SSH_HOP_HOSTS", str(hosts_file))
    return load_hosts()
