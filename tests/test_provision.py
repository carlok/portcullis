"""
Unit tests for provision.py helper functions.

Integration with Hetzner Cloud API and live SSH connections are NOT tested here —
those require real credentials and a running VM. Only pure-Python logic and
functions that accept injectable dependencies (ssh_client, firewall) are covered.
"""
import logging
import pytest
from unittest.mock import MagicMock, patch

from provision import (
    _ColorFormatter,
    generate_random_password,
    generate_ssh_keypair,
    lockdown_firewall,
    execute_remote_script,
    upload_string,
    wait_for_ssh,
)


# ─────────────────────────────────────────────────────────────
# generate_ssh_keypair
# ─────────────────────────────────────────────────────────────

class TestGenerateSshKeypair:
    def test_returns_two_strings(self):
        priv, pub = generate_ssh_keypair()
        assert isinstance(priv, str) and isinstance(pub, str)

    def test_private_key_is_openssh_pem(self):
        priv, _ = generate_ssh_keypair()
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" in priv

    def test_public_key_starts_with_ssh_rsa(self):
        _, pub = generate_ssh_keypair()
        assert pub.startswith("ssh-rsa ")

    def test_each_call_produces_unique_keypair(self):
        _, pub1 = generate_ssh_keypair()
        _, pub2 = generate_ssh_keypair()
        assert pub1 != pub2


# ─────────────────────────────────────────────────────────────
# generate_random_password
# ─────────────────────────────────────────────────────────────

class TestGenerateRandomPassword:
    def test_default_length_is_20(self):
        assert len(generate_random_password()) == 20

    def test_custom_length_honoured(self):
        assert len(generate_random_password(32)) == 32

    def test_has_lowercase(self):
        assert any(c.islower() for c in generate_random_password())

    def test_has_uppercase(self):
        assert any(c.isupper() for c in generate_random_password())

    def test_has_at_least_3_digits(self):
        assert sum(c.isdigit() for c in generate_random_password()) >= 3

    def test_passwords_are_unique(self):
        assert generate_random_password() != generate_random_password()


# ─────────────────────────────────────────────────────────────
# _ColorFormatter
# ─────────────────────────────────────────────────────────────

class TestColorFormatter:
    def setup_method(self):
        self.fmt = _ColorFormatter()

    def _record(self, level, msg="test message"):
        return logging.LogRecord(
            name="test", level=level, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None,
        )

    def test_output_contains_ansi_reset(self):
        assert "\033[0m" in self.fmt.format(self._record(logging.INFO))

    def test_debug_uses_grey(self):
        assert "\033[38;5;244m" in self.fmt.format(self._record(logging.DEBUG))

    def test_info_uses_green(self):
        assert "\033[32m" in self.fmt.format(self._record(logging.INFO))

    def test_warning_uses_yellow(self):
        assert "\033[33m" in self.fmt.format(self._record(logging.WARNING))

    def test_error_uses_red(self):
        assert "\033[31m" in self.fmt.format(self._record(logging.ERROR))

    def test_critical_uses_bold_red(self):
        assert "\033[1;31m" in self.fmt.format(self._record(logging.CRITICAL))

    def test_message_preserved_in_output(self):
        assert "hello world" in self.fmt.format(self._record(logging.INFO, "hello world"))


# ─────────────────────────────────────────────────────────────
# upload_string
# ─────────────────────────────────────────────────────────────

class TestUploadString:
    def _mock_ssh(self):
        ssh = MagicMock()
        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp
        mock_file = MagicMock()
        sftp.file.return_value.__enter__ = lambda s: mock_file
        sftp.file.return_value.__exit__ = MagicMock(return_value=False)
        return ssh, sftp

    def test_opens_sftp_and_writes_file(self):
        ssh, sftp = self._mock_ssh()
        upload_string(ssh, "hello", "/tmp/test.txt")
        ssh.open_sftp.assert_called_once()
        sftp.file.assert_called_once_with("/tmp/test.txt", "w")

    def test_closes_sftp_after_upload(self):
        ssh, sftp = self._mock_ssh()
        upload_string(ssh, "hello", "/tmp/test.txt")
        sftp.close.assert_called_once()


# ─────────────────────────────────────────────────────────────
# execute_remote_script
# ─────────────────────────────────────────────────────────────

class TestExecuteRemoteScript:
    def _mock_ssh(self, exit_code=0, output_lines=None):
        ssh = MagicMock()
        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp

        stdout = MagicMock()
        stderr = MagicMock()
        lines = list(output_lines or ["output line\n"])
        lines.append("")  # sentinel for iter(readline, "")
        stdout.readline.side_effect = lines
        stdout.channel.recv_exit_status.return_value = exit_code
        stderr.read.return_value = b"error output"
        ssh.exec_command.return_value = (MagicMock(), stdout, stderr)
        return ssh

    def test_uploads_and_executes_script(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash\necho hi")
        ssh = self._mock_ssh()
        execute_remote_script(ssh, str(script))
        ssh.open_sftp.assert_called_once()
        ssh.exec_command.assert_called_once()

    def test_sudo_prefix_when_requested(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh()
        execute_remote_script(ssh, str(script), use_sudo=True)
        cmd = ssh.exec_command.call_args[0][0]
        assert "sudo" in cmd

    def test_no_sudo_by_default(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh()
        execute_remote_script(ssh, str(script), use_sudo=False)
        cmd = ssh.exec_command.call_args[0][0]
        assert "sudo /tmp" not in cmd

    def test_args_appended_to_command(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh()
        execute_remote_script(ssh, str(script), args="alice 49000")
        cmd = ssh.exec_command.call_args[0][0]
        assert "alice 49000" in cmd

    def test_nonzero_exit_raises_runtime_error(self, tmp_path):
        script = tmp_path / "fail.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh(exit_code=1)
        with pytest.raises(RuntimeError, match="Script exited 1"):
            execute_remote_script(ssh, str(script))

    def test_exit_141_raises(self, tmp_path):
        """Exit 141 (SIGPIPE) must still be treated as an error."""
        script = tmp_path / "fail.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh(exit_code=141)
        with pytest.raises(RuntimeError, match="141"):
            execute_remote_script(ssh, str(script))

    def test_exit_minus_one_is_allowed(self, tmp_path):
        """Exit -1 means the channel closed (e.g. sshd restart) — not a failure."""
        script = tmp_path / "phase1.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh(exit_code=-1)
        execute_remote_script(ssh, str(script))  # must not raise

    def test_allow_nonzero_returns_exit_code(self, tmp_path):
        """allow_nonzero=True should return exit code without raising."""
        script = tmp_path / "verify.sh"
        script.write_text("#!/bin/bash")
        ssh = self._mock_ssh(exit_code=3)
        result = execute_remote_script(ssh, str(script), allow_nonzero=True)
        assert result == 3

    def test_sftp_retry_on_failure(self, tmp_path):
        script = tmp_path / "test.sh"
        script.write_text("#!/bin/bash")

        ssh = MagicMock()
        sftp = MagicMock()
        # Fail twice, succeed on third attempt
        ssh.open_sftp.side_effect = [Exception("not ready"), Exception("not ready"), sftp]

        stdout = MagicMock()
        stdout.readline.side_effect = [""]
        stdout.channel.recv_exit_status.return_value = 0
        stderr = MagicMock(); stderr.read.return_value = b""
        ssh.exec_command.return_value = (MagicMock(), stdout, stderr)

        with patch("provision.time.sleep"):
            execute_remote_script(ssh, str(script))
        assert ssh.open_sftp.call_count == 3


# ─────────────────────────────────────────────────────────────
# wait_for_ssh
# ─────────────────────────────────────────────────────────────

class TestWaitForSsh:
    def _make_mock_ssh_client(self, exit_code=0):
        mock_client = MagicMock()
        stdout = MagicMock()
        stdout.channel.recv_exit_status.return_value = exit_code
        mock_client.exec_command.return_value = (MagicMock(), stdout, MagicMock())
        return mock_client

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_returns_client_on_success(self, mock_sleep, mock_cls):
        mock_client = self._make_mock_ssh_client()
        mock_cls.return_value = mock_client

        result = wait_for_ssh("1.2.3.4", "root", key_filename="/tmp/key")

        assert result is mock_client
        mock_client.connect.assert_called_once()

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    @patch("provision.time.time")
    def test_retries_on_connection_error(self, mock_time, mock_sleep, mock_cls):
        # Extra values: time.time() is also called by the log formatter
        mock_time.side_effect = [0, 0, 0, 0, 0, 10, 10, 10]
        mock_client = self._make_mock_ssh_client()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = [Exception("refused"), None]

        result = wait_for_ssh("1.2.3.4", "root", key_filename="/tmp/key", timeout=300)

        assert result is mock_client
        assert mock_client.connect.call_count == 2

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    @patch("provision.time.time")
    def test_raises_timeout_error_when_deadline_exceeded(self, mock_time, mock_sleep, mock_cls):
        # Extra values: time.time() is also called by the log formatter
        # Flow: time.time() for deadline, logger.info, while-check, connect fails,
        # logger.info (retry msg with formatter), sleep, while-check (> deadline)
        mock_time.side_effect = [0, 0, 0, 0, 0, 0, 400]
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("refused")

        with pytest.raises(TimeoutError):
            wait_for_ssh("1.2.3.4", "root", key_filename="/tmp/key", timeout=300)

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_uses_custom_port(self, mock_sleep, mock_cls):
        mock_client = self._make_mock_ssh_client()
        mock_cls.return_value = mock_client

        wait_for_ssh("1.2.3.4", "alice", key_filename="/tmp/key", port=45000)

        assert mock_client.connect.call_args[1]["port"] == 45000

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_uses_password_when_no_key(self, mock_sleep, mock_cls):
        mock_client = self._make_mock_ssh_client()
        mock_cls.return_value = mock_client

        wait_for_ssh("1.2.3.4", "root", password="s3cret")

        kwargs = mock_client.connect.call_args[1]
        assert kwargs.get("password") == "s3cret"


# ─────────────────────────────────────────────────────────────
# lockdown_firewall
# ─────────────────────────────────────────────────────────────

class TestLockdownFirewall:
    def test_calls_set_rules_once(self):
        fw = MagicMock()
        lockdown_firewall(fw, 45116)
        fw.set_rules.assert_called_once()

    def test_single_rule_with_correct_port(self):
        fw = MagicMock()
        lockdown_firewall(fw, 45116)
        rules = fw.set_rules.call_args[0][0]
        assert len(rules) == 1
        assert rules[0].port == "45116"

    def test_rule_is_tcp_inbound(self):
        fw = MagicMock()
        lockdown_firewall(fw, 12345)
        rule = fw.set_rules.call_args[0][0][0]
        assert rule.protocol == "tcp"
        assert rule.direction == "in"

    def test_rule_allows_both_ipv4_and_ipv6(self):
        fw = MagicMock()
        lockdown_firewall(fw, 12345)
        source_ips = fw.set_rules.call_args[0][0][0].source_ips
        assert "0.0.0.0/0" in source_ips
        assert "::/0" in source_ips

    def test_ipv4_only_when_ipv6_disabled(self):
        fw = MagicMock()
        lockdown_firewall(fw, 12345, enable_ipv6=False)
        assert fw.set_rules.call_args[0][0][0].source_ips == ["0.0.0.0/0"]

    def test_different_ports_produce_different_rules(self):
        fw = MagicMock()
        lockdown_firewall(fw, 10000)
        r1 = fw.set_rules.call_args[0][0][0].port
        fw.reset_mock()
        lockdown_firewall(fw, 59999)
        r2 = fw.set_rules.call_args[0][0][0].port
        assert r1 != r2
