#!/usr/bin/env python3
"""
Hetzner VM Provisioner — Two-Phase Hardening
=============================================
Phase 1 (~30s): Immediate lockdown — custom user, key-only SSH, random port,
                UFW, sysctl hardening. Runs as root on port 22.
                Hetzner firewall is closed to port 22 as soon as Phase 1 finishes.

Phase 2 (mins):  Full CIS hardening — package updates, auditd, AIDE, fail2ban,
                 msmtp, logwatch, rkhunter, Podman. Runs as the new user via sudo.
"""

import io
import os
import shlex
import time
import uuid
import secrets
import string
import logging
from dotenv import load_dotenv
from hcloud import Client
from hcloud.server_types.domain import ServerType
from hcloud.images.domain import Image
from hcloud.locations.domain import Location
from hcloud.firewalls.domain import FirewallRule
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import paramiko

from preflight import validate_config


# ─────────────────────────────────────────────────────────────
# Colored logging
# ─────────────────────────────────────────────────────────────

class _ColorFormatter(logging.Formatter):
    _RESET  = "\033[0m"
    _BOLD   = "\033[1m"
    _LEVEL_STYLES = {
        logging.DEBUG:    "\033[38;5;244m",  # grey
        logging.INFO:     "\033[32m",         # green
        logging.WARNING:  "\033[33m",         # yellow
        logging.ERROR:    "\033[31m",         # red
        logging.CRITICAL: "\033[1;31m",       # bold red
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_STYLES.get(record.levelno, self._RESET)
        ts    = self.formatTime(record, "%H:%M:%S")
        level = f"{color}{record.levelname:<8}{self._RESET}"
        msg   = record.getMessage()
        return f"{ts} {level} {msg}"


def _setup_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter())
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    # Quiet noisy libraries
    logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
    logging.getLogger("hcloud").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    return logging.getLogger(__name__)


logger = _setup_logging()


# ─────────────────────────────────────────────────────────────
# SSH key helpers
# ─────────────────────────────────────────────────────────────

def generate_ssh_keypair() -> tuple[str, str]:
    """Return (private_key_pem, public_key_openssh) as strings."""
    logger.info("Generating RSA-4096 SSH keypair...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_openssh = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_pem, public_openssh


def write_private_key(path: str, private_pem: str) -> None:
    """Write the private key with mode 0600 from creation (no readable window)."""
    if os.path.exists(path):
        os.remove(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(private_pem)


def build_smtp_env(env) -> str | None:
    """Return smtp.env content for Phase 2, or None when SMTP is not configured.

    Phase 2 sources this file with bash, so every value is shell-quoted:
    passwords containing $, spaces, quotes or backticks survive unchanged.
    """
    smtp_host = env.get("SMTP_HOST", "")
    if not smtp_host:
        return None
    values = {
        "SMTP_HOST":   smtp_host,
        "SMTP_PORT":   env.get("SMTP_PORT", "587"),
        "SMTP_USER":   env.get("SMTP_USER", ""),
        "SMTP_PASS":   env.get("SMTP_PASS", ""),
        "SMTP_FROM":   env.get("SMTP_FROM", ""),
        "ALERT_EMAIL": env.get("ALERT_EMAIL", "root"),
    }
    return "\n".join(f"{k}={shlex.quote(v)}" for k, v in values.items()) + "\n"


def generate_random_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and sum(c.isdigit() for c in pwd) >= 3):
            return pwd


# ─────────────────────────────────────────────────────────────
# SSH / SFTP helpers
# ─────────────────────────────────────────────────────────────

class TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """Accept the host key of a VM we have just created, and log it.

    Phase 1 is the first contact with a machine created seconds earlier by
    this same process, so there is nothing to compare its key against: no
    prior connection, and Hetzner does not publish the fingerprint through
    the API. The key is accepted once, its fingerprint is logged, and
    Phase 2 then connects with that exact key pinned (see wait_for_ssh),
    so any later substitution is detected.
    """

    def missing_host_key(self, client, hostname, key) -> None:
        logger.info(
            f"Trusting host key of new VM {hostname}: "
            f"{key.get_name()} {key.fingerprint}"
        )


def wait_for_ssh(
    ip: str,
    username: str,
    *,
    key_filename: str | None = None,
    password: str | None = None,
    port: int = 22,
    timeout: int = 300,
    host_key: paramiko.PKey | None = None,
) -> paramiko.SSHClient:
    """Connect once SSH answers.

    Without *host_key* the first key seen is trusted and logged
    (TrustOnFirstUsePolicy — only valid for a VM created moments ago).
    With *host_key* only that exact key is accepted; a mismatch aborts
    immediately instead of retrying.
    """
    logger.info(f"Waiting for SSH at {username}@{ip}:{port} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client = paramiko.SSHClient()
            if host_key is None:
                client.set_missing_host_key_policy(TrustOnFirstUsePolicy())
            else:
                host_id = ip if port == 22 else f"[{ip}]:{port}"
                client.get_host_keys().add(host_id, host_key.get_name(), host_key)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                ip, port=port, username=username,
                key_filename=key_filename, password=password,
                timeout=10, banner_timeout=30, auth_timeout=30,
            )
            _, stdout, _ = client.exec_command("echo ready")
            if stdout.channel.recv_exit_status() == 0:
                logger.info(f"SSH connection established on port {port}.")
                return client
            client.close()
        except paramiko.BadHostKeyException:
            raise
        except Exception as exc:
            logger.info(f"SSH not ready yet on port {port} ({exc}); retrying in 5s...")
            time.sleep(5)
    raise TimeoutError(f"SSH at {ip}:{port} did not become available within {timeout}s.")


def upload_string(
    ssh_client: paramiko.SSHClient,
    content: str,
    remote_path: str,
    mode: int | None = None,
) -> None:
    """Upload a string as a file on the remote host.

    When *mode* is given it is applied before any content is written.
    """
    sftp = ssh_client.open_sftp()
    with sftp.file(remote_path, "w") as f:
        if mode is not None:
            sftp.chmod(remote_path, mode)
        f.write(content)
    sftp.close()
    logger.debug(f"Uploaded content to {remote_path}")


def execute_remote_script(
    ssh_client: paramiko.SSHClient,
    local_path: str,
    args: str = "",
    use_sudo: bool = False,
    max_sftp_retries: int = 8,
    allow_nonzero: bool = False,
) -> int:
    """Upload a local script via SFTP and execute it on the remote host.

    Returns the exit code.  Raises RuntimeError on non-zero exit unless
    *allow_nonzero* is True (useful for scripts like verify.sh that
    return the number of failed checks).
    """
    logger.info(f"Uploading {os.path.basename(local_path)}...")
    sftp = None
    for attempt in range(1, max_sftp_retries + 1):
        try:
            sftp = ssh_client.open_sftp()
            break
        except Exception as exc:
            logger.warning(f"SFTP attempt {attempt}/{max_sftp_retries} failed: {exc}")
            time.sleep(5)
    if sftp is None:
        raise RuntimeError("Could not open SFTP channel.")

    home_dir = sftp.normalize(".")
    remote_path = f"{home_dir}/{os.path.basename(local_path)}"
    sftp.put(local_path, remote_path)
    sftp.close()

    sudo = "sudo " if use_sudo else ""
    cmd  = f"chmod +x {remote_path} && {sudo}{remote_path} {args}".strip()
    logger.info(f"Executing: {cmd}")
    _, stdout, stderr = ssh_client.exec_command(cmd)

    # Non-blocking read with heartbeat — prints elapsed time when the
    # remote script produces no output for 15+ seconds (e.g. apt upgrade).
    channel = stdout.channel
    start = time.time()
    last_heartbeat = start
    buf = ""
    while not channel.closed:
        if channel.recv_ready():
            chunk = channel.recv(4096).decode(errors="replace")
            if not chunk:
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                logger.info(f"  [remote] {line.rstrip()}")
            last_heartbeat = time.time()
        elif channel.exit_status_ready():
            # Drain any remaining data
            while channel.recv_ready():
                buf += channel.recv(4096).decode(errors="replace")
            break
        else:
            now = time.time()
            if now - last_heartbeat >= 15:
                elapsed = int(now - start)
                mins, secs = divmod(elapsed, 60)
                logger.info(f"  ... {mins}m{secs:02d}s elapsed — still running")
                last_heartbeat = now
            time.sleep(1)
    if buf.strip():
        logger.info(f"  [remote] {buf.rstrip()}")

    exit_code = channel.recv_exit_status()
    if exit_code not in (0, -1) and not allow_nonzero:
        err = stderr.read().decode(errors="replace").strip()
        raise RuntimeError(f"Script exited {exit_code}: {err}")
    logger.info(f"{os.path.basename(local_path)} finished (exit {exit_code}).")
    return exit_code


# ─────────────────────────────────────────────────────────────
# Hetzner firewall helpers
# ─────────────────────────────────────────────────────────────

def lockdown_firewall(firewall, ssh_port: int) -> None:
    """Replace all inbound rules with: only the new SSH port."""
    logger.info(f"Locking down Hetzner firewall — closing port 22, opening {ssh_port}/tcp ...")
    actions = firewall.set_rules([
        FirewallRule(
            direction="in",
            protocol="tcp",
            port=str(ssh_port),
            source_ips=["0.0.0.0/0", "::/0"],
        )
    ])
    for action in actions:
        action.wait_until_finished()
    logger.info("Hetzner firewall locked down.")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    # Try explicit container path first, fall back to cwd search
    env_path = "/app/.env"
    if os.path.isfile(env_path):
        loaded = load_dotenv(env_path, override=True)
        logger.debug(f"Loaded .env from {env_path} (result={loaded})")
    else:
        loaded = load_dotenv(override=True)
        logger.debug(f"{env_path} not found — load_dotenv() cwd search, result={loaded}")

    raw_token = os.getenv("HCLOUD_TOKEN", "")
    token = raw_token.strip()

    if not token:
        logger.critical("HCLOUD_TOKEN is not set or is empty. Aborting.")
        return

    # Diagnostic — never logs the actual token value
    quotes = ('"', "'")
    has_quotes = token[0] in quotes or token[-1] in quotes
    has_ws = any(c.isspace() for c in token)
    logger.debug(
        f"Token diagnostics: len={len(token)} (raw_len={len(raw_token)}) "
        f"has_whitespace={has_ws} has_quotes={has_quotes}"
    )
    if len(raw_token) != len(token):
        logger.warning(f"Token had {len(raw_token) - len(token)} leading/trailing whitespace chars — stripped.")

    config_errors = validate_config(os.environ)
    if config_errors:
        for error in config_errors:
            logger.critical(f"Config: {error}")
        logger.critical("Invalid configuration (see ./run.sh preflight). Aborting.")
        return

    client = Client(token=token)

    # ── Configuration ──────────────────────────────────────────
    base_name   = os.getenv("SERVER_NAME", "hardened-node")
    server_name = f"{base_name}-{uuid.uuid4().hex[:6]}"
    server_type = os.getenv("SERVER_TYPE", "cx22")
    location    = os.getenv("LOCATION",    "fsn1")
    os_image    = os.getenv("OS_IMAGE",    "ubuntu-26.04")

    new_user = os.getenv("NEW_USER_NAME") or f"svc_{uuid.uuid4().hex[:8]}"
    ssh_port = secrets.choice(range(10_000, 60_000))

    # SMTP (optional) — forwarded to Phase 2 for msmtp setup
    smtp_env_content = build_smtp_env(os.environ)

    key_path = "/workspace/id_rsa"

    # Resources that need rollback on failure
    server       = None
    firewall     = None
    ssh_client   = None
    hcloud_key   = None

    t_start = time.time()

    try:
        # ── Generate keypair ───────────────────────────────────
        priv_key, pub_key = generate_ssh_keypair()
        write_private_key(key_path, priv_key)
        logger.info(f"Private key saved to {key_path}")

        # ── Upload key to Hetzner (for root access at VM boot) ─
        hcloud_key_name = f"prov-key-{uuid.uuid4().hex[:6]}"
        hcloud_key = client.ssh_keys.create(name=hcloud_key_name, public_key=pub_key)
        logger.info(f"Hetzner SSH key uploaded: {hcloud_key_name}")

        # ── Create Hetzner firewall (port 22 only, temporary) ──
        logger.info("Creating Hetzner firewall (port 22 — temporary, Phase 1 only)...")
        fw_resp = client.firewalls.create(
            name=f"fw-{server_name}",
            rules=[FirewallRule(
                direction="in", protocol="tcp", port="22",
                source_ips=["0.0.0.0/0", "::/0"],
            )],
        )
        firewall = fw_resp.firewall

        # ── Create VM ──────────────────────────────────────────
        logger.info(f"Creating VM '{server_name}' ({server_type}) in {location} ...")
        vm_resp = client.servers.create(
            name=server_name,
            server_type=ServerType(name=server_type),
            image=Image(name=os_image),
            location=Location(name=location),
            firewalls=[firewall],
            ssh_keys=[hcloud_key],
        )
        server = vm_resp.server
        vm_resp.action.wait_until_finished()
        server = client.servers.get_by_id(server.id)
        server_ip = server.public_net.ipv4.ip
        logger.info(f"VM ready. IP: {server_ip}")

        # ── Highlight key identifiers ─────────────────────────
        _HL = "\033[1;97;44m"  # bold white on blue background
        _RS = "\033[0m"
        logger.info(f"{_HL}  Server : {server_name:<30}  ({server_ip})  {_RS}")
        logger.info(f"{_HL}  User   : {new_user:<46}{_RS}")
        logger.info(f"{_HL}  SSH    : port {ssh_port:<40}{_RS}")

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Immediate lockdown (~30 seconds)
        # ══════════════════════════════════════════════════════
        logger.info("=" * 55)
        logger.info("PHASE 1 — Immediate lockdown")
        logger.info("=" * 55)
        t_phase1 = time.time()

        ssh_client = wait_for_ssh(server_ip, "root", key_filename=key_path)
        # Pin this host key: Phase 2 must reach the same machine.
        server_host_key = ssh_client.get_transport().get_remote_server_key()
        logger.info(
            f"Host key pinned: {server_host_key.get_name()} "
            f"{server_host_key.fingerprint}"
        )

        # Upload the public key so Phase 1 can install it for the new user
        upload_string(ssh_client, pub_key, "/tmp/provisioner_pub_key")
        logger.debug("Public key uploaded to /tmp/provisioner_pub_key")

        # Run Phase 1 — creates user, hardens SSH, UFW, sysctl
        execute_remote_script(
            ssh_client,
            "harden-phase1.sh",
            args=shlex.join([new_user, str(ssh_port), server_name]),
            use_sudo=False,
        )
        logger.info("Phase 1 script finished.")

        # Restart sshd through the SAME session.  Ubuntu cloud ssh.service
        # uses KillMode=process — the main listener is killed but our
        # session's child process survives, so this command completes normally.
        logger.info(f"Restarting sshd to apply new config (port {ssh_port})...")
        _, stdout, _ = ssh_client.exec_command("systemctl restart ssh")
        rc = stdout.channel.recv_exit_status()
        logger.info(f"sshd restarted (exit {rc}).")

        # Verify sshd is now listening on the new port
        _, stdout, _ = ssh_client.exec_command(f"ss -tlnp | grep :{ssh_port}")
        ss_out = stdout.read().decode().strip()
        if str(ssh_port) in ss_out:
            logger.info(f"Verified: sshd listening on port {ssh_port}")
        else:
            logger.warning(f"sshd NOT on port {ssh_port}. Collecting diagnostics...")
            diag_cmds = [
                "ss -tlnp | grep sshd || echo '(no sshd listeners found)'",
                "ls -la /etc/ssh/sshd_config.d/ 2>/dev/null || echo '(dir missing)'",
                "cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null || echo '(no drop-ins)'",
                "grep -n '^Port' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || echo '(no Port directives)'",
                "systemctl status ssh --no-pager -l 2>&1 | head -30",
                "journalctl -u ssh --no-pager -n 20 2>&1",
            ]
            for cmd in diag_cmds:
                _, out, _ = ssh_client.exec_command(cmd)
                for line in out.read().decode().splitlines():
                    logger.warning(f"  [diag] {line}")

        ssh_client.close()
        ssh_client = None

        p1_secs = int(time.time() - t_phase1)
        logger.info(f"Phase 1 completed in {p1_secs}s.")

        # ── Close port 22 at Hetzner level — VM is now locked down ──
        lockdown_firewall(firewall, ssh_port)

        # ── Clean up Hetzner SSH key (no longer needed) ───────
        logger.info("Removing temporary Hetzner provisioning key...")
        client.ssh_keys.delete(hcloud_key)
        hcloud_key = None
        logger.info("Hetzner provisioning key removed.")

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Full CIS hardening
        # ══════════════════════════════════════════════════════
        logger.info("=" * 55)
        logger.info("PHASE 2 — Full CIS hardening (this takes several minutes)")
        logger.info("=" * 55)
        t_phase2 = time.time()

        # Reconnect as the new user on the randomised port
        ssh_client = wait_for_ssh(
            server_ip, new_user,
            key_filename=key_path,
            port=ssh_port,
            host_key=server_host_key,
        )

        # Upload SMTP credentials if provided
        if smtp_env_content:
            upload_string(
                ssh_client, smtp_env_content, f"/home/{new_user}/smtp.env", mode=0o600,
            )
            logger.info("SMTP credentials uploaded for msmtp configuration.")

        execute_remote_script(
            ssh_client,
            "harden-phase2.sh",
            use_sudo=True,
        )
        p2_secs = int(time.time() - t_phase2)
        p2m, p2s = divmod(p2_secs, 60)
        logger.info(f"Phase 2 completed in {p2m}m{p2s:02d}s.")

        # ── Post-provisioning health check ────────────────────
        smtp_flag = "smtp" if smtp_env_content else ""
        verify_failures = execute_remote_script(
            ssh_client,
            "verify.sh",
            args=shlex.join([new_user, str(ssh_port), smtp_flag] if smtp_flag
                            else [new_user, str(ssh_port)]),
            use_sudo=True,
            allow_nonzero=True,
        )
        if verify_failures > 0:
            logger.warning(f"Health check reported {verify_failures} failed check(s).")
        else:
            logger.info("All health checks passed.")

        ssh_client.close()
        ssh_client = None

        # ── Timing summary ────────────────────────────────────
        total_elapsed = int(time.time() - t_start)
        m, s = divmod(total_elapsed, 60)
        logger.info(f"Total provisioning time: {m}m{s:02d}s")

        # ── Done ───────────────────────────────────────────────
        _OK = "\033[1;97;42m"  # bold white on green background
        _CMD = "\033[1;97;45m" # bold white on magenta background
        logger.info(f"{_OK}{'':55}{_RS}")
        logger.info(f"{_OK}  PROVISIONING COMPLETE{'':<33}{_RS}")
        logger.info(f"{_OK}{'':55}{_RS}")
        logger.info(f"{_HL}  Server : {server_name:<30}  ({server_ip})  {_RS}")
        logger.info(f"{_HL}  SSH    : port {ssh_port:<40}{_RS}")
        logger.info(f"{_HL}  User   : {new_user:<46}{_RS}")
        logger.info(f"{_HL}  Key    : ./keys/id_rsa{'':<32}{_RS}")
        logger.info("")
        logger.info(f"Connect with:")
        logger.info(f"{_CMD}  ssh -i ./keys/id_rsa -o IdentitiesOnly=yes -p {ssh_port} {new_user}@{server_ip}  {_RS}")

    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        logger.warning("Rolling back Hetzner resources...")

        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass

        if server:
            logger.warning(f"Deleting server {server.name} ...")
            try:
                action = client.servers.delete(server)
                logger.warning("Waiting for server deletion to complete...")
                action.wait_until_finished()
                logger.warning(f"Server {server.name} deleted.")
            except Exception as e:
                logger.error(f"Could not delete server: {e}")

        if hcloud_key:
            try:
                client.ssh_keys.delete(hcloud_key)
            except Exception:
                pass

        if firewall:
            logger.warning(f"Deleting firewall {firewall.name} ...")
            try:
                client.firewalls.delete(firewall)
            except Exception as e:
                logger.error(f"Could not delete firewall: {e}")

        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
