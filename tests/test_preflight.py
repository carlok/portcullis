"""Unit tests for local preflight configuration validation."""

import pytest

from preflight import parse_bool, validate_config


def valid_env(**overrides):
    env = {
        "HCLOUD_TOKEN": "token-without-whitespace",
        "SERVER_NAME": "hardened-node",
        "SERVER_TYPE": "cx22",
        "LOCATION": "fsn1",
        "OS_IMAGE": "ubuntu-26.04",
        "SMTP_PORT": "587",
    }
    env.update(overrides)
    return env


class TestValidateConfig:
    def test_valid_minimal_config_has_no_errors(self):
        assert validate_config(valid_env()) == []

    def test_missing_token_is_error(self):
        errors = validate_config(valid_env(HCLOUD_TOKEN=""))
        assert "HCLOUD_TOKEN" in errors[0]

    def test_placeholder_token_is_error(self):
        errors = validate_config(valid_env(HCLOUD_TOKEN="your_hetzner_api_token_here"))
        assert "HCLOUD_TOKEN" in errors[0]

    def test_token_whitespace_is_error(self):
        errors = validate_config(valid_env(HCLOUD_TOKEN="abc def"))
        assert "whitespace" in errors[0]

    def test_invalid_server_name_is_error(self):
        errors = validate_config(valid_env(SERVER_NAME="-bad"))
        assert any("SERVER_NAME" in error for error in errors)

    def test_invalid_hetzner_slug_is_error(self):
        errors = validate_config(valid_env(SERVER_TYPE="CX 22"))
        assert any("SERVER_TYPE" in error for error in errors)

    def test_valid_new_user_is_allowed(self):
        assert validate_config(valid_env(NEW_USER_NAME="svc_admin-1")) == []

    def test_invalid_new_user_is_error(self):
        errors = validate_config(valid_env(NEW_USER_NAME="Admin"))
        assert any("NEW_USER_NAME" in error for error in errors)

    def test_invalid_smtp_port_is_error(self):
        errors = validate_config(valid_env(SMTP_PORT="99999"))
        assert any("SMTP_PORT" in error for error in errors)

    def test_partial_smtp_without_host_is_error(self):
        errors = validate_config(valid_env(ALERT_EMAIL="ops@example.com"))
        assert any("SMTP_HOST" in error for error in errors)

    def test_smtp_host_requires_sender_and_recipient(self):
        errors = validate_config(valid_env(SMTP_HOST="smtp.example.com"))
        assert any("SMTP_FROM" in error for error in errors)
        assert any("ALERT_EMAIL" in error for error in errors)

    def test_complete_smtp_config_is_allowed(self):
        errors = validate_config(valid_env(
            SMTP_HOST="smtp.example.com",
            SMTP_FROM="server@example.com",
            ALERT_EMAIL="ops@example.com",
        ))
        assert errors == []


class TestEnableIpv6:
    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on", " False ", "0", "no", "off"])
    def test_accepts_boolean_words(self, value):
        assert validate_config(valid_env(ENABLE_IPV6=value)) == []

    def test_unset_is_valid(self):
        assert validate_config(valid_env()) == []

    @pytest.mark.parametrize("value", ["maybe", "2", "enable", ""])
    def test_rejects_other_values_when_set(self, value):
        env = valid_env(ENABLE_IPV6=value)
        errors = validate_config(env)
        if value == "":
            assert errors == []  # blank falls back to the default (true)
        else:
            assert any("ENABLE_IPV6" in e for e in errors)

    @pytest.mark.parametrize("value,expected", [
        ("true", True), ("Yes", True), ("1", True), ("ON", True),
        ("false", False), ("No", False), ("0", False), ("off", False),
        ("nope", None), ("", None),
    ])
    def test_parse_bool(self, value, expected):
        assert parse_bool(value) is expected
