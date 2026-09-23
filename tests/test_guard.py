"""Policy tests: allow/deny regex rules, rule precedence, and path containment."""

from __future__ import annotations

import pytest

from ssh_hop import guard
from ssh_hop.config import ALLOW_ALL, ConfigError, Host


def host(**overrides) -> Host:
    defaults = dict(
        alias="h", host="10.0.0.1", user="u", password="p",
        localRoots=[], uploadRoots=[], downloadRoots=[],
    )
    defaults.update(overrides)
    return Host(**defaults)


# --- the permissive default -------------------------------------------------

@pytest.mark.parametrize("command", [
    "ls -la /srv",
    "rm -rf /opt/app/old",
    "systemctl restart nginx",
    "docker compose up -d",
    "apt-get install -y nginx",
    "echo x > /etc/nginx/nginx.conf",
    "reboot",
    "dd if=/dev/zero of=/dev/sda",
    "useradd someone",
    "cat /etc/shadow && chmod 400 /etc/shadow",
])
def test_default_host_allows_everything(command):
    """Out of the box nothing is restricted - this is a personal, trusted-LAN tool."""
    verdict = guard.check_command(host(), command)
    assert verdict.allowed
    assert verdict.rule == ALLOW_ALL


def test_default_host_configures_allow_all():
    assert host().allowCommands == [ALLOW_ALL]
    assert host().denyCommands == []
    assert host().unrestricted_commands


def test_empty_command_is_still_refused():
    with pytest.raises(guard.GuardDenied, match="empty command"):
        guard.check_command(host(), "   ")


def test_oversized_command_is_refused():
    with pytest.raises(guard.GuardDenied, match="too long"):
        guard.check_command(host(), "echo " + "a" * 40_000)


# --- allow lists ------------------------------------------------------------

def test_allow_list_permits_matching_commands():
    scoped = host(allowCommands=[r"^docker\b", r"^systemctl status\b"])
    assert guard.check_command(scoped, "docker ps").rule == r"^docker\b"
    assert guard.check_command(scoped, "systemctl status nginx").rule == r"^systemctl status\b"


def test_allow_list_refuses_everything_else_and_lists_the_rules():
    scoped = host(allowCommands=[r"^docker\b"])
    with pytest.raises(guard.GuardDenied) as excinfo:
        guard.check_command(scoped, "rm -rf /srv")
    message = str(excinfo.value)
    assert "no allowCommands rule matches" in message
    assert "docker" in message, "the refusal should name the configured rules"
    assert 'Add "*" to allow everything on this host' in message


def test_wildcard_rule_allows_everything():
    assert guard.check_command(host(allowCommands=["*"]), "rm -rf /").rule == "*"
    assert guard.check_command(host(allowCommands=[""]), "anything at all").rule == ""


def test_first_matching_allow_rule_wins():
    scoped = host(allowCommands=[r"^docker (ps|logs)", r"^docker"])
    assert guard.check_command(scoped, "docker logs x").rule == r"^docker (ps|logs)"
    assert guard.check_command(scoped, "docker rm x").rule == r"^docker"


def test_rules_match_anywhere_unless_anchored():
    unanchored = host(allowCommands=["docker"])
    assert guard.check_command(unanchored, "sudo docker ps").rule == "docker"
    anchored = host(allowCommands=["^docker"])
    with pytest.raises(guard.GuardDenied):
        guard.check_command(anchored, "sudo docker ps")


def test_dot_matches_newlines_in_a_multiline_command():
    """DOTALL: a bare `*` must still allow a heredoc-style multi-line command."""
    scoped = host(allowCommands=["*"])
    assert guard.check_command(scoped, "cat <<EOF\nhello\nEOF").allowed


def test_alternation_and_character_classes_work():
    scoped = host(allowCommands=[r"^systemctl (start|stop|restart|status) (nginx|postgresql)$"])
    assert guard.check_command(scoped, "systemctl restart nginx").allowed
    with pytest.raises(guard.GuardDenied):
        guard.check_command(scoped, "systemctl restart sshd")


# --- deny lists win ---------------------------------------------------------

def test_deny_rule_overrides_allow_all():
    guarded = host(denyCommands=[r"\breboot\b"])
    with pytest.raises(guard.GuardDenied) as excinfo:
        guard.check_command(guarded, "sudo reboot now")
    message = str(excinfo.value)
    assert "matches denyCommands rule" in message
    assert "reboot" in message
    assert guard.check_command(guarded, "uname -a").allowed


def test_deny_rule_overrides_a_specific_allow_rule():
    guarded = host(allowCommands=[r"^rm"], denyCommands=[r"^rm\s+-rf\s+/$"])
    assert guard.check_command(guarded, "rm /tmp/x").allowed
    with pytest.raises(guard.GuardDenied, match="denyCommands"):
        guard.check_command(guarded, "rm -rf /")


def test_first_matching_deny_rule_is_reported():
    guarded = host(denyCommands=[r"mkfs", r"mkfs\.ext4"])
    with pytest.raises(guard.GuardDenied, match="mkfs'"):
        guard.check_command(guarded, "mkfs.ext4 /dev/sda1")


def test_deny_rules_are_case_sensitive_by_default():
    guarded = host(denyCommands=[r"DROP DATABASE"])
    with pytest.raises(guard.GuardDenied):
        guard.check_command(guarded, "psql -c 'DROP DATABASE x'")
    # use (?i) to match case-insensitively, as with any Python regex
    relaxed = host(denyCommands=[r"(?i)drop database"])
    with pytest.raises(guard.GuardDenied):
        guard.check_command(relaxed, "psql -c 'drop database x'")


# --- pattern validation -----------------------------------------------------

def test_compile_patterns_reports_an_invalid_regex():
    from ssh_hop.config import compile_patterns

    with pytest.raises(ConfigError, match=r"invalid regex '\['"):
        compile_patterns(["["], "box.allowCommands")


def test_compile_patterns_rejects_non_strings():
    from ssh_hop.config import compile_patterns

    with pytest.raises(ConfigError, match="must contain only strings"):
        compile_patterns([5], "box.allowCommands")


def test_compile_patterns_accepts_valid_regex():
    from ssh_hop.config import compile_patterns

    assert compile_patterns([r"^docker\b", "*"], "box.allowCommands") == [r"^docker\b", "*"]


# --- path containment -------------------------------------------------------

def test_remote_path_is_unrestricted_when_no_roots_are_set():
    assert guard.check_remote_path(host(), "/anywhere/x", [], "upload") == "/anywhere/x"


def test_remote_path_must_be_absolute():
    with pytest.raises(guard.GuardDenied, match="absolute"):
        guard.check_remote_path(host(), "relative/path", [], "upload")


def test_remote_path_roots_are_enforced_when_set():
    scoped = host(uploadRoots=["/srv/app"])
    assert guard.check_remote_path(scoped, "/srv/app/bin/x", scoped.uploadRoots, "upload") == "/srv/app/bin/x"
    with pytest.raises(guard.GuardDenied, match="outside allowed roots"):
        guard.check_remote_path(scoped, "/etc/passwd", scoped.uploadRoots, "upload")


def test_remote_path_traversal_is_resolved_before_the_check():
    scoped = host(uploadRoots=["/srv/app"])
    with pytest.raises(guard.GuardDenied, match="outside allowed roots"):
        guard.check_remote_path(scoped, "/srv/app/../../etc/passwd", scoped.uploadRoots, "upload")


def test_remote_path_prefix_collision_is_not_confused():
    scoped = host(uploadRoots=["/srv/app"])
    with pytest.raises(guard.GuardDenied):
        guard.check_remote_path(scoped, "/srv/application/secret", scoped.uploadRoots, "upload")


def test_empty_remote_path_is_refused():
    with pytest.raises(guard.GuardDenied, match="remote path is empty"):
        guard.check_remote_path(host(), "", [], "upload")


def test_local_path_is_unrestricted_when_no_roots_are_set(tmp_path):
    outside = tmp_path / "anywhere.txt"
    outside.write_text("x", encoding="utf-8")
    assert guard.check_local_path(host(), str(outside)) == str(outside.resolve())


def test_local_path_roots_are_enforced_when_set(tmp_path):
    allowed = tmp_path / "staging"
    allowed.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    scoped = host(localRoots=[str(allowed)])
    assert guard.check_local_path(scoped, str(allowed / "a.txt")) == str((allowed / "a.txt").resolve())
    with pytest.raises(guard.GuardDenied, match="local path outside"):
        guard.check_local_path(scoped, str(outside / "a.txt"))


# --- output limits ----------------------------------------------------------

def test_truncation_keeps_head_and_tail():
    payload = "START\n" + ("x" * 50_000) + "\nEND"
    text, truncated = guard.truncate_output(payload, limit=2000)
    assert truncated
    assert text.startswith("START")
    assert text.endswith("END")
    assert "bytes omitted by ssh-hop" in text


def test_small_output_is_untouched():
    assert guard.truncate_output("hello", limit=100) == ("hello", False)
