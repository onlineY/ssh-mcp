"""Tests for the hosts.json loader and its validation messages."""

from __future__ import annotations

import json

import pytest

from ssh_hop.config import (
    ConfigError,
    Host,
    find_hosts_file,
    load_hosts,
    resolve_alias,
)


def write(tmp_path, document, name="hosts.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def minimal(tmp_path, **host_overrides):
    spec = {"host": "10.0.0.5", "user": "deploy", "password": "pw"}
    spec.update(host_overrides)
    return write(tmp_path, {"hosts": {"box": spec}})


def test_loads_defaults_merged_into_each_host(tmp_path):
    path = write(tmp_path, {
        "defaults": {"port": 2222, "timeout": 90, "allowCommands": ["^docker"]},
        "hosts": {"box": {"host": "10.0.0.5", "user": "deploy", "password": "pw"}},
    })
    host = load_hosts(path)["box"]
    assert (host.port, host.timeout, host.allowCommands) == (2222, 90, ["^docker"])


def test_per_host_values_override_defaults(tmp_path):
    path = write(tmp_path, {
        "defaults": {"port": 2222, "allowCommands": ["^docker"]},
        "hosts": {"box": {"host": "h", "user": "u", "password": "pw", "port": 22,
                          "allowCommands": ["*"]}},
    })
    host = load_hosts(path)["box"]
    assert (host.port, host.allowCommands) == (22, ["*"])


def test_flat_mapping_without_hosts_key_is_accepted(tmp_path):
    path = write(tmp_path, {"box": {"host": "h", "user": "u", "password": "pw"}})
    assert "box" in load_hosts(path)


def test_public_view_hides_connection_details(tmp_path):
    path = minimal(tmp_path, desc="app server", defaultCwd="/opt/app")
    public = load_hosts(path)["box"].public()
    assert public == {
        "alias": "box", "desc": "app server", "cwd": "/opt/app",
        "auth": "password", "commands": "all", "denyCommands": [],
        "upload": "any path", "download": "any path", "tags": [],
    }
    assert "10.0.0.5" not in json.dumps(public)
    assert "deploy" not in json.dumps(public)


def test_public_view_reports_narrowed_policy(tmp_path):
    path = minimal(tmp_path, allowCommands=[r"^docker\b"], denyCommands=[r"reboot"],
                   uploadRoots=["/srv"], downloadRoots=[])
    public = load_hosts(path)["box"].public()
    assert public["commands"] == [r"^docker\b"]
    assert public["denyCommands"] == [r"reboot"]
    assert public["upload"] == ["/srv"]
    assert public["download"] == "any path"


def test_public_view_reports_disabled_transfers(tmp_path):
    path = minimal(tmp_path, allowUpload=False, allowDownload=False, uploadRoots=["/srv"])
    public = load_hosts(path)["box"].public()
    assert public["upload"] is False
    assert public["download"] is False


def test_key_auth_is_reported_and_file_resolved_relative_to_config(tmp_path):
    key = tmp_path / "keys" / "id_ed25519"
    key.parent.mkdir()
    key.write_text("private", encoding="utf-8")
    path = write(tmp_path, {"hosts": {"box": {
        "host": "h", "user": "u", "keyFile": "keys/id_ed25519",
    }}})
    host = load_hosts(path)["box"]
    assert host.keyFile == str(key.resolve())
    assert host.public()["auth"] == "key"


def test_missing_key_file_is_reported(tmp_path):
    path = write(tmp_path, {"hosts": {"box": {"host": "h", "user": "u", "keyFile": "absent.key"}}})
    with pytest.raises(ConfigError, match="keyFile not found"):
        load_hosts(path)


def test_host_without_credentials_is_rejected(tmp_path):
    path = write(tmp_path, {"hosts": {"box": {"host": "h", "user": "u"}}})
    with pytest.raises(ConfigError, match="needs either 'password' or 'keyFile'"):
        load_hosts(path)


def test_missing_required_field_names_the_alias(tmp_path):
    path = write(tmp_path, {"hosts": {"box": {"user": "u", "password": "pw"}}})
    with pytest.raises(ConfigError, match=r"host 'box' is missing required field 'host'"):
        load_hosts(path)


@pytest.mark.parametrize("spec,fragment", [
    ({"port": "22"}, "port must be an integer"),
    ({"port": 70000}, "port out of range"),
    ({"allowUpload": "yes"}, "allowUpload must be true or false"),
    ({"knownHosts": "maybe"}, "knownHosts must be one of"),
    ({"uploadRoots": 5}, "uploadRoots must be a string or list of strings"),
    ({"env": {"A": 1}}, "env must be an object of string values"),
    ({"allowCommands": ["["]}, "invalid regex"),
    ({"denyCommands": [")"]}, "invalid regex"),
    ({"allowCommands": 5}, "allowCommands must be a string or list of strings"),
])
def test_invalid_values_are_rejected_with_a_useful_message(tmp_path, spec, fragment):
    path = minimal(tmp_path, **spec)
    with pytest.raises(ConfigError, match=fragment):
        load_hosts(path)


def test_empty_allow_list_falls_back_to_allow_all(tmp_path):
    """An empty list would otherwise refuse every command on that host."""
    path = minimal(tmp_path, allowCommands=[])
    assert load_hosts(path)["box"].allowCommands == ["*"]


def test_invalid_json_is_reported_with_the_path(tmp_path):
    path = tmp_path / "hosts.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_hosts(path)


def test_empty_hosts_is_rejected(tmp_path):
    path = write(tmp_path, {"hosts": {}})
    with pytest.raises(ConfigError, match="no hosts defined"):
        load_hosts(path)


def test_local_roots_default_to_unrestricted(tmp_path):
    """No localRoots means any local path is readable/writable, matching the permissive default."""
    path = minimal(tmp_path)
    assert load_hosts(path)["box"].localRoots == []


def test_explicit_local_roots_are_kept(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    path = minimal(tmp_path, localRoots=[str(staging)])
    assert load_hosts(path)["box"].localRoots == [str(staging)]


def test_transfer_roots_default_to_unrestricted(tmp_path):
    """Uploads/downloads must be able to touch any path out of the box."""
    host = load_hosts(minimal(tmp_path))["box"]
    assert host.uploadRoots == [] and host.downloadRoots == []
    assert host.public()["upload"] == "any path"
    assert host.public()["download"] == "any path"


def test_hosts_file_discovery_order(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SSH_HOP_HOSTS", raising=False)
    monkeypatch.setenv("SSH_HOP_HOME", str(tmp_path / "state"))
    (tmp_path / "state").mkdir()
    with pytest.raises(ConfigError, match="no hosts.json found"):
        find_hosts_file()
    target = tmp_path / "hosts.json"
    target.write_text("{}", encoding="utf-8")
    assert find_hosts_file() == target


def test_environment_variable_selects_the_file(tmp_path, monkeypatch):
    target = minimal(tmp_path, name="custom.json")
    monkeypatch.setenv("SSH_HOP_HOSTS", str(target))
    monkeypatch.chdir(tmp_path)
    assert find_hosts_file() == target


def test_environment_variable_pointing_nowhere_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SSH_HOP_HOSTS", str(tmp_path / "absent.json"))
    with pytest.raises(ConfigError, match="does not point at a readable file"):
        find_hosts_file()


def test_explicit_path_wins(tmp_path, monkeypatch):
    explicit = minimal(tmp_path, name="explicit.json")
    monkeypatch.setenv("SSH_HOP_HOSTS", str(minimal(tmp_path, name="other.json")))
    assert find_hosts_file(explicit) == explicit


def test_resolve_alias_lists_valid_names_on_a_typo(tmp_path):
    path = write(tmp_path, {"hosts": {
        "web-01": {"host": "h", "user": "u", "password": "pw"},
        "db-01": {"host": "h", "user": "u", "password": "pw"},
    }})
    hosts = load_hosts(path)
    with pytest.raises(ConfigError, match=r"unknown host alias 'web-1'; known aliases: db-01, web-01"):
        resolve_alias(hosts, "web-1")


def test_host_repr_never_exposes_credentials():
    host = Host(alias="box", host="10.0.0.5", user="deploy", password="hunter2")
    text = repr(host)
    assert "hunter2" not in text and "10.0.0.5" not in text and "deploy" not in text
    assert "box" in text


def test_unedited_template_password_is_rejected(tmp_path):
    path = write(tmp_path, {"hosts": {"box": {"host": "h", "user": "u", "password": "REPLACE_ME"}}})
    with pytest.raises(ConfigError, match="still has the example password"):
        load_hosts(path)


def test_unedited_template_key_path_is_rejected(tmp_path):
    path = write(tmp_path, {"hosts": {"box": {
        "host": "h", "user": "u", "keyFile": "C:/Users/me/.ssh/id_ed25519",
    }}})
    with pytest.raises(ConfigError, match="still points at the example key path"):
        load_hosts(path)


def test_shipped_example_config_is_rejected_until_edited(tmp_path, monkeypatch):
    """The template that `init` writes must not silently load with placeholder values."""
    from ssh_hop.config import write_example

    monkeypatch.setenv("SSH_HOP_HOME", str(tmp_path / "state"))
    target = tmp_path / "hosts.json"
    write_example(target)
    with pytest.raises(ConfigError, match="example"):
        load_hosts(target)


def test_init_writes_a_template_that_loads(tmp_path, monkeypatch):
    from ssh_hop.config import write_example

    monkeypatch.setenv("SSH_HOP_HOME", str(tmp_path / "state"))
    target = tmp_path / "hosts.json"
    write_example(target)
    document = json.loads(target.read_text(encoding="utf-8"))
    assert "hosts" in document and "defaults" in document


def test_init_refuses_to_clobber_without_force(tmp_path):
    from ssh_hop.config import write_example

    target = tmp_path / "hosts.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(ConfigError, match="refusing to overwrite"):
        write_example(target)
    write_example(target, force=True)
    assert "hosts" in json.loads(target.read_text(encoding="utf-8"))
