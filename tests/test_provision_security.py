"""
Tests for the security-sensitive helpers in provision.py:
private key file mode, smtp.env quoting, remote file mode and
host-key pinning between Phase 1 and Phase 2.
"""
import os
import stat
import subprocess
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from provision import build_smtp_env, upload_string, wait_for_ssh, write_private_key


# ─────────────────────────────────────────────────────────────
# write_private_key
# ─────────────────────────────────────────────────────────────

class TestWritePrivateKey:
    def test_file_is_0600(self, tmp_path):
        path = tmp_path / "id_rsa"
        write_private_key(str(path), "PRIVATE")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert path.read_text() == "PRIVATE"

    def test_replaces_existing_world_readable_file(self, tmp_path):
        path = tmp_path / "id_rsa"
        path.write_text("OLD")
        os.chmod(path, 0o644)
        write_private_key(str(path), "NEW")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert path.read_text() == "NEW"


# ─────────────────────────────────────────────────────────────
# build_smtp_env
# ─────────────────────────────────────────────────────────────

def _source_in_bash(content: str, tmp_path) -> dict[str, str]:
    env_file = tmp_path / "smtp.env"
    env_file.write_text(content)
    out = subprocess.run(
        ["bash", "-c", f'source "{env_file}"; printf "%s\\0" "$SMTP_HOST" "$SMTP_PORT" '
                       '"$SMTP_USER" "$SMTP_PASS" "$SMTP_FROM" "$ALERT_EMAIL"'],
        check=True, capture_output=True, text=True,
    ).stdout.split("\0")[:6]
    keys = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "ALERT_EMAIL"]
    return dict(zip(keys, out))


class TestBuildSmtpEnv:
    def test_none_without_host(self):
        assert build_smtp_env({"SMTP_USER": "u"}) is None

    def test_defaults(self, tmp_path):
        parsed = _source_in_bash(build_smtp_env({"SMTP_HOST": "smtp.example.com"}), tmp_path)
        assert parsed["SMTP_PORT"] == "587"
        assert parsed["ALERT_EMAIL"] == "root"

    @pytest.mark.parametrize("password", [
        "simple",
        "with space",
        "dollar$HOME",
        "back`tick`",
        "sub$(touch /tmp/pwned)",
        "quote'single",
        'quote"double',
        "semi;colon&amp",
    ])
    def test_values_survive_bash_source_unchanged(self, tmp_path, password):
        env = {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": password,
            "SMTP_FROM": "from@example.com",
            "ALERT_EMAIL": "alerts@example.com",
        }
        parsed = _source_in_bash(build_smtp_env(env), tmp_path)
        assert parsed["SMTP_PASS"] == password
        assert parsed["SMTP_USER"] == "user@example.com"


# ─────────────────────────────────────────────────────────────
# upload_string mode
# ─────────────────────────────────────────────────────────────

class TestUploadStringMode:
    def _mock_ssh(self, events):
        ssh = MagicMock()
        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp
        handle = MagicMock()
        handle.write.side_effect = lambda _c: events.append("write")
        sftp.chmod.side_effect = lambda *_a: events.append("chmod")
        sftp.file.return_value.__enter__ = lambda s: handle
        sftp.file.return_value.__exit__ = MagicMock(return_value=False)
        return ssh, sftp

    def test_chmod_happens_before_write(self):
        events = []
        ssh, sftp = self._mock_ssh(events)
        upload_string(ssh, "secret", "/home/u/smtp.env", mode=0o600)
        sftp.chmod.assert_called_once_with("/home/u/smtp.env", 0o600)
        assert events == ["chmod", "write"]

    def test_no_chmod_without_mode(self):
        events = []
        ssh, sftp = self._mock_ssh(events)
        upload_string(ssh, "public", "/tmp/x")
        sftp.chmod.assert_not_called()


# ─────────────────────────────────────────────────────────────
# wait_for_ssh host-key pinning
# ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


def _ok_client():
    client = MagicMock()
    stdout = MagicMock()
    stdout.channel.recv_exit_status.return_value = 0
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock())
    return client


class TestWaitForSshPinning:
    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_unpinned_uses_auto_add(self, _sleep, mock_cls):
        client = _ok_client()
        mock_cls.return_value = client
        wait_for_ssh("1.2.3.4", "root", key_filename="/k")
        policy = client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy, paramiko.AutoAddPolicy)

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_pinned_key_registered_for_port_and_rejects_unknown(self, _sleep, mock_cls, host_key):
        client = _ok_client()
        mock_cls.return_value = client
        wait_for_ssh("1.2.3.4", "svc", key_filename="/k", port=40000, host_key=host_key)
        client.get_host_keys.return_value.add.assert_called_once_with(
            "[1.2.3.4]:40000", host_key.get_name(), host_key,
        )
        policy = client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy, paramiko.RejectPolicy)

    @patch("provision.paramiko.SSHClient")
    @patch("provision.time.sleep")
    def test_host_key_mismatch_aborts_without_retry(self, mock_sleep, mock_cls, host_key):
        client = _ok_client()
        mock_cls.return_value = client
        other = paramiko.RSAKey.generate(2048)
        client.connect.side_effect = paramiko.BadHostKeyException("1.2.3.4", other, host_key)
        with pytest.raises(paramiko.BadHostKeyException):
            wait_for_ssh("1.2.3.4", "svc", key_filename="/k", port=40000, host_key=host_key)
        assert client.connect.call_count == 1
        mock_sleep.assert_not_called()
