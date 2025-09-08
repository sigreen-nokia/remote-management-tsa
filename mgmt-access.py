#!/usr/bin/env python3
import argparse
import sys
import logging
import logging.handlers
import traceback
import os
import platform
import socket
import subprocess
import shlex
import tempfile
import textwrap
from shutil import which
import shutil
from pathlib import Path
import re
import datetime
import getpass
import pwd
import shlex

def setup_logger(level=logging.INFO):
    # Don’t let logging print handler tracebacks on emit errors
    logging.raiseExceptions = False

    logger = logging.getLogger("mgmt-access.py")  
    logger.setLevel(level)
    logger.propagate = False  # keep messages from bubbling to root

    # Clear existing handlers (avoid duplicates if re-initialized)
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()

    # Always have a console handler
    console = logging.StreamHandler(stream=sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(
        "%(asctime)s %(name)s [%(levelname)s]: %(message)s",
        datefmt="%b %d %H:%M:%S"
    ))
    logger.addHandler(console)

    # Try to add syslog, but don’t error if unavailable
    syslog_added = False
    syslog_address = None

    if platform.system() == "Darwin":
        candidate = "/var/run/syslog"
        if os.path.exists(candidate):
            syslog_address = candidate
    else:
        candidate = "/dev/log"
        if os.path.exists(candidate):
            syslog_address = candidate

    try:
        if syslog_address:
            # Use UDP datagrams (default); works for both macOS and Linux
            sh = logging.handlers.SysLogHandler(address=syslog_address, socktype=socket.SOCK_DGRAM)
            sh.setLevel(level)
            # Common syslog-ish format: "<prog>[pid]: message"
            sh.setFormatter(logging.Formatter("%(name)s[%(process)d]: %(message)s"))
            logger.addHandler(sh)
            syslog_added = True
        else:
            # Optionally, try network syslog if local socket missing:
            # sh = logging.handlers.SysLogHandler(address=("localhost", 514))
            # logger.addHandler(sh)
            pass
    except Exception:
        # Quietly skip syslog if it fails (socket missing, permission, etc.)
        syslog_added = False

    # Optional: let DEBUG go to console even if syslog drops it by facility config
    logger.debug(
        "Logger initialized (level=%s, syslog=%s)",
        logging.getLevelName(level),
        "yes" if syslog_added else "no"
    )
    return logger



def check_not_running_as_root(logger=None):
    """
    Check if this script is being run with root privileges (uid 0).
    Exits if not root.
    """
    if os.geteuid() == 0:
        msg = "This script must not be run as root (no sudo)."
        if logger:
            logger.critical(msg)
        else:
            print(msg)
        sys.exit(1)
    else:
        if logger:
            logger.debug("Confirmed not running as root (uid=0).")

def check_running_as_root(logger=None):
    """
    Check if this script is being run with root privileges (uid 0).
    Exits if not root.
    """
    if os.geteuid() != 0:
        msg = "This script must be run as root (use sudo)."
        if logger:
            logger.critical(msg)
        else:
            print(msg)
        sys.exit(1)
    else:
        if logger:
            logger.debug("Confirmed running as root (uid=0).")

#used in install_client and install_server in a slightly different way

_SHELL_METACHARS = ("|", "&", ";", "<", ">", "(", ")", "$", "`", "\\", '"', "'", "{", "}", "[", "]", "*", "?", "~", "||", "&&")

def _needs_shell(cmd_str: str) -> bool:
    return any(tok in cmd_str for tok in _SHELL_METACHARS)

def run(cmd, check=True, capture_output=False, logger=None):
    """
    Unified command runner.

    - Prefers run_cmd(logger, cmd, check, capture_output) if defined.
    - Falls back to subprocess.run with smart shell detection.
    - Accepts str or list for `cmd`.
    - ALWAYS returns an object whose .stdout/.stderr are strings (never None).
    """
    # Try custom run_cmd if available
    try:
        if "run_cmd" in globals():
            proc = run_cmd(logger, cmd, check=check, capture_output=capture_output)  # type: ignore[name-defined]
            # Normalize outputs to strings
            try:
                if getattr(proc, "stdout", None) is None:
                    proc.stdout = ""
                if getattr(proc, "stderr", None) is None:
                    proc.stderr = ""
            except Exception:
                pass
            return proc
    except Exception as e:
        if logger:
            logger.debug(f"run_cmd() failed, falling back to subprocess.run: {e}")

    # Logging
    if logger:
        # Use DEBUG if we're capturing; INFO otherwise
        (logger.debug if capture_output else logger.info)(f"RUN: {cmd}")

    # Decide shell vs. arg list
    use_shell = isinstance(cmd, str) and _needs_shell(cmd)
    if isinstance(cmd, list):
        args = cmd
    elif use_shell:
        args = cmd  # pass the raw string to the shell
    else:
        args = shlex.split(cmd)

    # Run
    proc = subprocess.run(
        args,
        shell=use_shell,
        check=check,
        text=True,
        capture_output=capture_output,
    )

    # Ensure stdout/stderr are always strings (never None)
    # Note: if capture_output=False, these will be empty strings.
    proc.stdout = proc.stdout or ""
    proc.stderr = proc.stderr or ""

    return proc







#def run(cmd, check=True, capture_output=False, logger=None):
#    """
#    Wrapper for running shell commands.
#
#    - Uses run_cmd(logger, cmd, check, capture_output) if defined in the module.
#    - Falls back to subprocess.run().
#    - Accepts str or list for cmd.
#    - Provides optional capture_output (stdout/stderr).
#    - Logs at DEBUG/INFO if logger is provided.
#    """
#    # Prefer custom run_cmd() if present
#    try:
#        if "run_cmd" in globals():
#            return run_cmd(logger, cmd, check=check, capture_output=capture_output)  # type: ignore[name-defined]
#    except Exception:
#        pass
#
#    # Fallback: subprocess.run
#    if logger:
#        level = logger.debug if capture_output else logger.info
#        level(f"RUN: {cmd}")
#
#    # Decide how to run command
#    if isinstance(cmd, str):
#        cmd_list = shlex.split(cmd)
#    else:
#        cmd_list = cmd
#
#    return subprocess.run(
#        cmd_list,
#        check=check,
#        capture_output=capture_output,
#        text=True,
#    )


def add_locked_down_sshd(logger, CLIENT_SSH_TUNNEL_PORT, ssh_user="ops"):
    """
    Create a locked-down secondary sshd instance bound to CLIENT_SSH_TUNNEL_PORT,
    restricted to `ssh_user` (default 'ops'), and managed by systemd as
    'sshd-remote-mgmt.service'.

    Writes:
      - /etc/ssh/sshd_config_remote_mgmt
      - /lib/systemd/system/sshd-remote-mgmt.service

    Then runs:
      systemctl stop/daemon-reload/enable/start/status on the new unit.
    """
    if os.geteuid() != 0:
        logger.error("add_locked_down_sshd() must be run as root (sudo).")
        raise PermissionError("Root privileges required")

    # Friendly warning if the user doesn't exist
    try:
        pwd.getpwnam(ssh_user)
    except KeyError:
        logger.warning(f"User '{ssh_user}' does not exist. AllowUsers will restrict access to a non-existent user.")

    cfg_path = Path("/etc/ssh/sshd_config_remote_mgmt")
    unit_path = Path("/lib/systemd/system/sshd-remote-mgmt.service")

    cfg_text = (
        "# remote-management-tsa locked down ssh daemon\n"
        f"AllowUsers {ssh_user}\n"
        "KbdInteractiveAuthentication no\n"
        "X11Forwarding yes\n"
        "PrintMotd no\n"
        "AcceptEnv LANG LC_*\n"
        "PasswordAuthentication no\n"
        "UsePAM no\n"
        "ChallengeResponseAuthentication no\n"
        "GatewayPorts yes\n"
        f"Port {CLIENT_SSH_TUNNEL_PORT}\n"
    )

    unit_text = (
        "[Unit]\n"
        "Description=OpenBSD Secure Shell server\n"
        "Documentation=man:sshd(8) man:sshd_config(5)\n"
        "After=network.target auditd.service\n"
        "ConditionPathExists=!/etc/ssh/sshd_not_to_be_run\n"
        "\n"
        "[Service]\n"
        "EnvironmentFile=-/etc/default/ssh\n"
        "ExecStartPre=/usr/sbin/sshd -t\n"
        "ExecStart=/usr/sbin/sshd -D $SSHD_OPTS -f /etc/ssh/sshd_config_remote_mgmt\n"
        "ExecReload=/usr/sbin/sshd -t\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "KillMode=process\n"
        "Restart=on-failure\n"
        "RestartPreventExitStatus=255\n"
        "Type=notify\n"
        "RuntimeDirectory=sshd\n"
        "RuntimeDirectoryMode=0755\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "Alias=sshd-remote-mgmt.service\n"
    )

    def _atomic_write(path: Path, text: str, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                if not text.endswith("\n"):
                    text += "\n"
                f.write(text)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    # 1) Write config
    logger.info(f"Writing {cfg_path} …")
    backup_file(cfg_path, logger)
    _atomic_write(cfg_path, cfg_text, mode=0o644)

    # 2) Write unit file
    logger.info(f"Writing {unit_path} …")
    backup_file(unit_path, logger)
    _atomic_write(unit_path, unit_text, mode=0o644)

    # Validate the custom config before touching the service
    logger.info("Validating sshd config …")
    try:
        # Validate explicitly against the new config
        run(f"/usr/sbin/sshd -t -f {cfg_path}", check=True, capture_output=True, logger=logger)
    except Exception as e:
        logger.error(f"sshd config validation failed for {cfg_path}: {e}")
        raise

    # 3) Setup and start the service
    logger.info("Configuring systemd unit sshd-remote-mgmt.service …")
    run("sudo systemctl stop sshd-remote-mgmt.service", check=False, logger=logger)
    run("sudo systemctl daemon-reload", check=True, logger=logger)
    run("sudo systemctl enable sshd-remote-mgmt.service", check=True, logger=logger)
    run("sudo systemctl start sshd-remote-mgmt.service", check=True, logger=logger)

    # Show status (no-pager), log output for visibility
    status = run("sudo systemctl status sshd-remote-mgmt.service --no-pager --full",
                 check=False, capture_output=True, logger=logger)
    if status.stdout:
        logger.debug(status.stdout.strip())

    logger.info("Locked-down sshd instance is deployed and started ✅")





def harden_sshd(logger, CLIENT_SSH_TUNNEL_PORT, ssh_login_user="ops"):
    """
    Prompt the operator, then switch sshd to key-only auth and set the tunnel port.
    Aborts unless the operator explicitly confirms.
    """
    sshd_main = "/etc/ssh/sshd_config"
    sshd_cloudinit = "/etc/ssh/sshd_config.d/50-cloud-init.conf"
    auth_keys = Path(f"/home/{ssh_login_user}/.ssh/authorized_keys")

    #setup ssh to work on port 22 and CLIENT_SSH_TUNNEL_PORT at the same time 
    logger.info(f"Setting sshd up to use two ports 22 and {CLIENT_SSH_TUNNEL_PORT}")
    replace_or_add_line(
        sshd_main,
        r"^\s*Port\s+",
        f"Port {CLIENT_SSH_TUNNEL_PORT}",
        logger=logger,
        extra_lines=["Port 22"],   # keep a fallback listener if you want
    )

    logger.warning("Next step I will DISABLE SSH password authentication (key-pairs only).")
    logger.warning(f"To avoid being locked out, Ensure you have ssh using key pairs working for this user before proceeding ")
    # Best-effort local sanity check
    if not auth_keys.exists() or auth_keys.stat().st_size == 0:
        logger.warning(f"No public keys found at {auth_keys}.")

    #loop untill the user confirms they have an ssh pub key installed, else they will lock themselfes out
    try:
        while True:
            confirm = input(
                "Type YES to proceed with disabling password logins (key-only). "
                "Ensure your SSH key pair is configured for this user. "
                "(Ctrl-C to abort): "
            ).strip()
            if confirm == "YES":
                break
            logger.info("waiting for you to confirm that your ssh key pairs have been configured for this user")
    except (KeyboardInterrupt, EOFError):
        logger.info("Remote management will not work untill you rerun the client-install and confirm this option")
        logger.info("Cancelled: leaving sshd password authentication unchanged.")
        return

    logger.info("Disabling password access in sshd; key pairs only.")
    logger.info("Additionaly enabling port forwarding in sshd")
    if Path(sshd_cloudinit).exists():
        replace_or_add_line(
            sshd_cloudinit,
            r"^\s*PasswordAuthentication\s+",
            "PasswordAuthentication no",
            logger=logger,
        )

    replace_or_add_line(sshd_main, r"^\s*PasswordAuthentication\s+", "PasswordAuthentication no", logger=logger)
    replace_or_add_line(sshd_main, r"^\s*UsePAM\s+", "UsePAM no", logger=logger)
    replace_or_add_line(sshd_main, r"^\s*ChallengeResponseAuthentication\s+", "ChallengeResponseAuthentication no", logger=logger)
    replace_or_add_line(sshd_main, r"^\s*GatewayPorts\s+", "GatewayPorts yes", logger=logger)

    try:
        run("sudo systemctl restart ssh", check=True, logger=logger)
        logger.info("sshd restarted successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restart ssh: {e.stderr.strip()}")
        raise



def backup_file(p, logger):
    """Backup config file p if it exists, to <p>.bak-YYYYmmdd-HHMMSS"""
    src = Path(p)
    if src.exists():
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = src.with_suffix(src.suffix + f".bak-{ts}")
        try:
            shutil.copy2(src, dst)
            logger.info(f"Note: I have Backed up file {src} before modifying to file {dst}")
        except Exception as e:
            logger.warning(f"Could not backup {src}: {e}")


def _as_port(logger, name, value, default_for_msg=None):
    """
    Coerce a string->int port, with friendly error if bad.
    Returns int in [1..65535].
    """
    s = str(value).strip()
    try:
        p = int(s)
    except ValueError:
        msg = f"Invalid port for {name!s}: {s!r}"
        if default_for_msg is not None:
            msg += f" (expected a number like {default_for_msg})"
        logger.error(msg)
        raise
    if not (1 <= p <= 65535):
        logger.error(f"Port out of range for {name}: {p} (must be 1..65535)")
        raise ValueError(f"bad port {p}")
    return p



def configure_ops_login_banner(logger):
    """
    Server-only: append an auto-status line to ~ops/.bash_profile.
    If /etc/systemd/system/reverse-ssh.service is absent (client), do nothing.
    """
    server_marker = Path("/etc/systemd/system/reverse-ssh.service")
    if not server_marker.exists():
        logger.info("No reverse-ssh.service marker detected → client mode; leaving /home/ops/.bash_profile unchanged.")
        return

    bash_profile = Path("/home/ops/.bash_profile")
    login_cmd = "sudo /usr/local/sbin/mgmt-access.py --status"
    header = "# Auto-run mgmt-access status on login"

    # Ensure file exists
    bash_profile.parent.mkdir(parents=True, exist_ok=True)
    if not bash_profile.exists():
        bash_profile.touch(mode=0o644, exist_ok=True)

    # Append only if not already present
    try:
        existing = bash_profile.read_text(encoding="utf-8")
    except Exception:
        existing = ""

    if login_cmd in existing:
        logger.debug(f"'{login_cmd}' already present in {bash_profile}; no change.")
    else:
        with open(bash_profile, "a", encoding="utf-8") as f:
            if not existing.endswith("\n"):
                f.write("\n")
            f.write(f"\n{header}\n{login_cmd}\n")
        logger.info(f"Configured {bash_profile} to run '{login_cmd}' on login.")

    # Best-effort ownership
    try:
        run(f"sudo chown ops:ops {bash_profile}", check=False, logger=logger)
    except subprocess.CalledProcessError as e:
        logger.warning(f"Could not chown {bash_profile} to ops:ops (non-fatal): {e}")




def replace_or_add_line(p, key_regex, replacement, *, logger, extra_lines=None):
    """                 
    Replace first line matching key_regex with replacement; if none matched, append replacement.
    Optionally also ensure extra_lines (list of lines) appear *after* replacement.
    """
    backup_file(p, logger)  # backup before modifying
    content = read_text(p)
    lines = content.splitlines()
    pat = re.compile(key_regex)
    replaced = False
    for i, line in enumerate(lines): 
        if pat.search(line): 
            if lines[i].strip() != replacement.strip():
                lines[i] = replacement
            replaced = True
            # insert extra lines right after
            if extra_lines:
                for extra in extra_lines:
                    if extra not in lines[i+1:i+2+len(extra_lines)]:  # avoid duplicates
                        lines.insert(i + 1, extra)
            break
    if not replaced:
        lines.append(replacement)
        if extra_lines:
            for extra in extra_lines:
                if extra not in lines:
                    lines.append(extra)
    new = "\n".join(lines) + "\n"
    if new != content:
        write_text(p, new)
        logger.info(f"Updated {p}: set `{replacement}` (+ extras)")
    else:
        logger.info(f"No change needed in {p} for `{replacement}`")

def read_text(p):
    try:
        return Path(p).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""

def write_text(p, content, mode=0o644):
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    Path(p).write_text(content, encoding="utf-8")
    os.chmod(p, mode)

def append_if_missing_line(p, line, logger):
    current = read_text(p)
    needle = line.strip()
    if needle and needle not in current:
        with open(p, "a", encoding="utf-8") as fh:
            if current and not current.endswith("\n"):
                fh.write("\n")
            fh.write(needle + "\n")
        logger.info(f"Appended to {p}")
    else:
        logger.info(f"Line already present in {p}")


def check_ops_user(logger):
    """
    Ensure the 'ops' user exists and has /home/ops present.
    Exit with error if not.
    """
    try:
        pwd.getpwnam("ops")  # raises KeyError if user doesn't exist
    except KeyError:
        logger.error("The user 'ops' does not exist on this system. Please run --add-ops-user first")
        sys.exit(1)

    home_dir = "/home/ops"
    if not os.path.isdir(home_dir):
        logger.error(f"Home directory {home_dir} does not exist for user 'ops'. Please run --add-ops-user first")
        sys.exit(1)

    logger.info("User 'ops' exists and /home/ops is present ✅")


def _looks_like_openssh_pubkey(line: str) -> bool:
    parts = line.strip().split()
    if len(parts) < 2:
        return False
    keytype = parts[0]
    allowed = {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
    return keytype in allowed


def _import_keys_from_file(auth_keys: Path, file_path: str, logger):
    """Read a file of public keys and append valid lines if missing."""
    p = Path(os.path.expanduser(file_path)).resolve()
    if not p.exists():
        logger.error(f"Key file not found: {p}")
        return
    if not p.is_file():
        logger.error(f"Not a file: {p}")
        return

    added = skipped = invalid = 0

    try:
        with p.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if not _looks_like_openssh_pubkey(line):
                    invalid += 1
                    logger.warning(f"Skipping non-OpenSSH-looking line from {p}: {line[:40]}...")
                    continue
                try:
                    before = auth_keys.read_text(encoding="utf-8") if auth_keys.exists() else ""
                    append_if_missing_line(auth_keys, line, logger)
                    after = auth_keys.read_text(encoding="utf-8")
                    if after != before:
                        added += 1
                    else:
                        skipped += 1
                except Exception as e:
                    logger.error(f"Failed to append key from {p}: {e}")
    except Exception as e:
        logger.error(f"Error reading {p}: {e}")
        return

    try:
        os.chmod(auth_keys, 0o600)
    except Exception as e:
        logger.warning(f"Could not chmod {auth_keys} to 600: {e}")

    logger.info(f"Imported from {p}: added={added}, skipped-duplicates={skipped}, invalid-format={invalid}")



def configure_ufw_ssh_from_private(logger):
    """
    Prompt for each RFC1918 subnet and, if confirmed, allow SSH (22/tcp) from it via UFW.
    Uses existing run() helper.
    """
    private_subnets = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    # Check if ufw exists
    try:
        result = run("ufw --version", check=False)
        if result.returncode != 0:
            logger.error("UFW does not appear to be installed. Install it with: sudo apt-get install ufw")
            return
    except Exception as e:
        logger.error(f"Failed to check UFW availability: {e}")
        return

    logger.info("Configuring UFW to allow SSH (tcp/22) from selected private IPv4 ranges.")

    for cidr in private_subnets:
        ans = input(f"Allow SSH (tcp/22) from {cidr}? [y/N]: ").strip().lower()
        if ans == "y":
            cmd = f"sudo ufw allow from {cidr} to any port 22 proto tcp"
            logger.info(f"Adding rule: {cmd}")
            run(cmd, check=True)
        else:
            logger.info(f"Skipped {cidr}")

    # Show current rules
    run("sudo ufw status numbered", check=False)

    # Check if ufw is active
    result = run("sudo ufw status", check=False)
    if "inactive" in result.stdout.lower():
        ans = input("UFW is inactive. Enable it now? [y/N]: ").strip().lower()
        if ans == "y":
            logger.info("Enabling UFW…")
            run("sudo ufw enable", check=True)
        else:
            logger.warning("UFW remains inactive. Rules will not take effect until UFW is enabled.")


def get_persistent_config(logger, varname, default, prompt=True, cast=None):
    """
    Get a persistent config value for `varname`.
    - Stores in a hidden file named .<varname>
    - If file exists, uses its value (with optional prompt to update).
    - If file does not exist, creates it with provided default (but can prompt first).
    """
    logger.debug(f"called get_persistent_config(): {varname}")
    filename = f".{varname}"
    value = str(default)
    caster = cast or (lambda x: type(default)(x))

    if os.path.exists(filename):
        logger.debug("os.path.exists true")
        with open(filename, "r") as f:
            saved_value = f.read().strip()
            if saved_value:
                value = saved_value
        logger.debug(f"Found existing {varname} in {filename}: using {value}")

        if prompt:
            new_value = input(
                f"Current {varname} is '{value}'. Enter new value or hit return for no change: "
            ).strip()
            if new_value:
                value = new_value
                with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
                    tmp.write(value)
                    tmp_path = tmp.name
                shutil.move(tmp_path, filename)
                logger.debug(f"Updated {filename} with new value {value}")
    else:
        logger.debug("os.path.exists false")
        if prompt:
            new_value = input(
                f"{varname} not set yet (default {default}). Enter value or hit return to use default: "
            ).strip()
            if new_value:
                value = new_value
        # write chosen or default value
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(str(value))
            tmp_path = tmp.name
        shutil.move(tmp_path, filename)
        logger.debug(f"Created {filename} with {varname}={value}")

    try:
        return caster(value)
    except Exception as e:
        logger.warning(f"Could not cast {varname}='{value}' ({e}), returning string")
        return value



def turn_on(logger, timer_override=None):
    """
    Enable and start reverse-ssh.service if present, then verify it's running.
    """
    service = "reverse-ssh.service"

    logger.info(f"Enabling the Remote Access Management Service...")
    logger.debug(f"timer_override is set to {timer_override}...")
    logger.debug(f"Checking for {service}...")

    try:
        # Check if service exists
        result = subprocess.run(
            ["systemctl", "list-unit-files", service],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        if service not in result.stdout:
            logger.error(f"{service} not found on this system. Aborting.")
            return

        logger.debug(f"{service} found. Enabling and starting...")

        subprocess.run(["sudo", "systemctl", "enable", service], check=True)
        subprocess.run(["sudo", "systemctl", "start", service], check=True)

        # Check if it's active
        status_check = subprocess.run(
            ["systemctl", "is-active", service],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        state = status_check.stdout.strip()

        if state == "active" and (timer_override is None or int(timer_override) != 0):
            logger.info(f"{service} is running ✅")
            logger.info(f"Remote Management Access will be disabled automatically in {timer_override} hours")
            disable_in_x_hours(logger, timer_override)
        elif state == "active" and (int(timer_override) == 0):
            logger.info(f"{service} is running ✅")
            logger.info(f"Remote Management will run untill it is disabled with with --off")
        else:
            logger.warning(f"{service} is NOT running or running without timer (state={state}, timer_override={timer_override})")


    except subprocess.CalledProcessError as e:
        logger.error(f"Error managing {service}: {e.stderr.strip()}")

def turn_off(logger):
    """
    Disable and stop reverse-ssh.service if present, then verify it's running.
    """
    logger.info(f"Disabling the Remote Access Management Service...")
    service = "reverse-ssh.service"

    logger.debug(f"Checking for {service}...")

    try:
        # Check if service exists
        result = subprocess.run(
            ["systemctl", "list-unit-files", service],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        if service not in result.stdout:
            logger.error(f"{service} not found on this system. Aborting.")
            return

        logger.debug(f"{service} found. Disabling and stopping...")

        subprocess.run(["sudo", "systemctl", "stop", service], check=True)
        subprocess.run(["sudo", "systemctl", "disable", service], check=True)

        # Check if it's inactive
        status_check = subprocess.run(
            ["systemctl", "is-active", service],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        state = status_check.stdout.strip()

        if state == "active":
            logger.warning(f"{service} is still running ")
        else:
            logger.info(f"{service} has been stopped ✅")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error managing {service}: {e.stderr.strip()}")

#def show_status(logger):
#    """
#    Show reverse-ssh.service status if present.
#    If log level is DEBUG, dump full `systemctl status` output.
#    """
#    logger.info("Checking the status of the Remote Access Management Service...")
#    service = "reverse-ssh.service"
#
#    logger.debug(f"Checking for {service}...")
#
#    try:
#        # Check if service exists
#        result = subprocess.run(
#            ["systemctl", "list-unit-files", service],
#            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
#        )
#        if service not in result.stdout:
#            logger.error(f"{service} not found on this system. Aborting.")
#            return
#
#        logger.debug(f"{service} found. Checking status...")
#
#        # If DEBUG → dump full status output
#        if logger.isEnabledFor(logging.DEBUG):
#            full_status = subprocess.run(
#                ["systemctl", "status", service],
#                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
#            )
#            logger.debug(f"Full systemctl status for {service}:\n{full_status.stdout.strip()}")
#        else:
#            # Only check active state
#            status_check = subprocess.run(
#                ["systemctl", "is-active", service],
#                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
#            )
#            state = status_check.stdout.strip()
#
#            if state == "active":
#                logger.info(f"{service} is running ✅")
#            else:
#                logger.warning(f"{service} is NOT running (state={state})")
#
#    except subprocess.CalledProcessError as e:
#        logger.error(f"Error managing {service}: {e.stderr.strip()}")


import logging
from pathlib import Path

def show_status(logger):
    """
    If /etc/systemd/system/reverse-ssh.service exists -> treat as server and check reverse-ssh.service.
    Otherwise -> treat as client and check sshd-remote-mgmt.service (with sudo).
    DEBUG level dumps full `systemctl status`; otherwise prints a brief active/inactive message.
    """
    server_marker = Path("/etc/systemd/system/reverse-ssh.service")
    if server_marker.exists():
        role = "server"
        service = "reverse-ssh.service"
        sudo = ""  # not needed
    else:
        role = "client"
        service = "sshd-remote-mgmt.service"
        sudo = "sudo "

    logger.info(f"Checking the status of the Remote Access Management Service ({role} mode)…")
    logger.debug(f"Service to check: {service}")

    try:
        # First, see if systemd knows about the unit
        listed = run(f"{sudo}systemctl list-unit-files {service}",
                     check=False, capture_output=True, logger=logger)
        if service not in listed.stdout:
            logger.error(f"{service} not found on this system.")
            # Still attempt a status call for any extra diagnostics
            diag = run(f"{sudo}systemctl status {service} --no-pager --full",
                       check=False, capture_output=True, logger=logger)
            if diag.stdout.strip():
                logger.debug(diag.stdout.strip())
            return

        logger.debug(f"{service} found. Checking status…")

        if logger.isEnabledFor(logging.DEBUG):
            # Dump full status when in DEBUG
            full = run(f"{sudo}systemctl status {service} --no-pager --full",
                       check=False, capture_output=True, logger=logger)
            logger.debug(f"Full systemctl status for {service}:\n{(full.stdout or '').strip()}")
        else:
            # Concise state only
            chk = run(f"{sudo}systemctl is-active {service}",
                      check=False, capture_output=True, logger=logger)
            state = (chk.stdout or "").strip()
            if state == "active":
                logger.info(f"{service} is running ✅")
            else:
                logger.warning(f"{service} is NOT running (state={state or 'unknown'})")

    except Exception as e:
        logger.error(f"Error checking {service}: {e}")




def install_sw(logger):
    """
    Install mgmt-access.py into /usr/local/sbin and make it executable.
    """
    src = Path("./mgmt-access.py").resolve()
    dst_dir = Path("/usr/local/sbin")
    dst = dst_dir / "mgmt-access.py"

    if not src.exists():
        logger.error(f"Source file not found: {src}")
        return

    try:
        # Ensure destination directory exists
        if not dst_dir.exists():
            logger.info(f"Creating directory {dst_dir}")
            dst_dir.mkdir(parents=True, exist_ok=True)

        # Copy file
        shutil.copy2(src, dst)
        logger.info(f"Copied {src} -> {dst}")

        # Make executable
        st = os.stat(dst)
        os.chmod(dst, st.st_mode | 0o111)  # add execute bits
        logger.info(f"Made {dst} executable")

    except Exception as e:
        logger.error(f"Failed to install {src} to {dst_dir}: {e}")

def ensure_pkg(pkg, logger):
    """
    Ensure a package is installed, prompt user if missing.
    Idempotent for apt packages.
    """
    try:
        subprocess.run(["dpkg", "-s", pkg], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Package already installed: {pkg}")
    except subprocess.CalledProcessError:
        logger.debug(f"The package '{pkg}' is required but not installed.")
        choice = input(f"'{pkg}' is not installed but is required. Do you want me to install it now? [y/N]: ").strip().lower()

        if choice == "y":
            logger.info(f"Installing package: {pkg}")
            subprocess.run("sudo apt-get update -y || true", shell=True, check=False)
            subprocess.run(f"export DEBIAN_FRONTEND=noninteractive; sudo apt-get install -y {pkg}", shell=True, check=True)
            logger.info(f"Package '{pkg}' installed successfully.")
        else:
            logger.error(f"Cannot continue without installing '{pkg}'.")
            raise RuntimeError(f"Required package '{pkg}' not installed.")

def backup_iptables(logger, backup_dir="/var/backups/iptables"):
    """
    Backup IPv4 and IPv6 iptables rules into timestamped files.
    
    :param logger: logging instance
    :param backup_dir: directory to store backup files
    """
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    files = {
        "ipv4": os.path.join(backup_dir, f"iptables-backup-{timestamp}.rules"),
        "ipv6": os.path.join(backup_dir, f"ip6tables-backup-{timestamp}.rules"),
    }

    try:
        logger.info(f"Backing up IPv4 iptables to {files['ipv4']}")
        with open(files["ipv4"], "w") as f:
            subprocess.run(["iptables-save"], stdout=f, stderr=subprocess.PIPE, check=True, text=True)

        logger.info(f"Backing up IPv6 iptables to {files['ipv6']}")
        with open(files["ipv6"], "w") as f:
            subprocess.run(["ip6tables-save"], stdout=f, stderr=subprocess.PIPE, check=True, text=True)

        logger.info("iptables backup completed successfully ✅")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to backup iptables: {e.stderr.strip()}")
    except Exception as e:
        logger.error(f"Unexpected error during iptables backup: {e}")

    return files


def disable_in_x_hours(logger, timer_override):
    """ 
    Schedule /usr/local/sbin/mgmt-access.py --off to run once after timer_override hours.
    Uses the 'at' command. If timer_override=0, do not schedule and log that it must be stopped manually.
    """     
    try:
        # Ensure timer_override is an integer
        hours = int(timer_override)

        if hours == 0:
            logger.info("Remote management will run until it is manually stopped --off (no auto-disable scheduled).")
            return
        elif hours < 0:
            logger.error(f"Invalid timer_override: {timer_override}. Must be >= 0.")
            return
        
        cmd = f"/usr/local/sbin/mgmt-access.py --off"
        at_cmd = f'echo "{cmd}" | at now + {hours} hours'
            
        logger.debug(f"Scheduling command: {cmd} to run in {hours} hour(s) using 'at'")
        result = subprocess.run(at_cmd, shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        logger.debug(f"'at' scheduled successfully: {result.stdout.strip()}")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to schedule with 'at': {e.stderr.strip()}")
    except ValueError:
        logger.error(f"timer_override must be an integer (got {timer_override})")


def timer_override(value):
    # Placeholder: logic to override timer
    print(f"Applying timer override: {value}")


def add_ops_user(logger):
    """
    Create a restricted user 'ops' who can only run:
        sudo /usr/local/sbin/mgmt-access.py

    Additions:
      - Prompts for and sets a password for 'ops'.
      - Configures login shell to run '/usr/local/sbin/mgmt-access.py --help'.
    """
    try:
        # 1. Check if user exists
        result = subprocess.run(
            ["id", "-u", "ops"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            logger.info("User 'ops' already exists.")
        else:
            # Create the user with /bin/bash shell
            subprocess.run(["sudo", "useradd", "-m", "-s", "/bin/bash", "ops"], check=True)
            logger.info("Created user 'ops'.")

        # 2. Prompt for password and set it
        password = getpass.getpass("Enter password for user 'ops': ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            logger.error("Passwords do not match. Aborting.")
            return

        # Use chpasswd to set password
        subprocess.run(
            ["sudo", "chpasswd"],
            input=f"ops:{password}",
            text=True,
            check=True
        )
        logger.info("Password set for user 'ops'.")

        # 3. Prepare sudoers file
        sudoers_file = "/etc/sudoers.d/ops"
        rule = "ops ALL=(ALL) NOPASSWD: /usr/local/sbin/mgmt-access.py\n"

        # Write rule atomically via visudo -cf check
        tmp_file = "/tmp/ops_sudoers"
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(rule)

        # Validate syntax with visudo
        check = subprocess.run(
            ["sudo", "visudo", "-cf", tmp_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if check.returncode != 0:
            logger.error(f"visudo check failed: {check.stderr}")
            return

        # Install file into /etc/sudoers.d/
        shutil.move(tmp_file, sudoers_file)
        subprocess.run(["sudo", "chmod", "440", sudoers_file], check=True)
        logger.info(f"Sudoers restriction applied in {sudoers_file}")

        # 4. Configure ops login banner 
        configure_ops_login_banner(logger)

        # All Done, ops user has been created
        logger.info("User 'ops' created and configured successfully.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")



def remove_ops_user(logger):
    """
    Remove the restricted 'ops' user and its sudoers configuration.
    Must be run with root privileges.
    """
    try:
        # 1. Check if user exists
        result = subprocess.run(
            ["id", "-u", "ops"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            logger.info("Removing user 'ops' and its home directory...")
            subprocess.run(["sudo", "userdel", "-r", "ops"], check=True)
            logger.info("User 'ops' removed.")
        else:
            logger.info("User 'ops' does not exist. Skipping user removal.")

        # 2. Remove sudoers file
        sudoers_file = "/etc/sudoers.d/ops"
        if os.path.exists(sudoers_file):
            subprocess.run(["sudo", "rm", "-f", sudoers_file], check=True)
            logger.info(f"Removed sudoers file {sudoers_file}")
        else:
            logger.info("No sudoers file for 'ops' found.")

        logger.info("remove_ops_user() completed successfully.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")


def ensure_ssh_key(logger, ssh_dir="/home/support/.ssh", key_name="id_rsa"):
    """
    Ensure SSH key pair exists for support user.
    If missing, prompt to generate one.
    Then display public key so user can copy it to client.
    """
    private_key = os.path.join(ssh_dir, key_name)
    public_key = private_key + ".pub"

    if not os.path.exists(public_key):
        logger.info(f"No SSH key found at {public_key}")
        response = input("No SSH key exists. Do you want to generate a new SSH key pair? [y/N]: ").strip().lower()
        if response == "y":
            try:
                os.makedirs(ssh_dir, exist_ok=True)
                subprocess.run(
                    ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", private_key, "-N", ""],
                    check=True
                )
                logger.info(f"SSH key pair generated at {private_key} and {public_key}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to generate SSH key pair: {e}")
                return False
        else:
            logger.warning("User declined to generate SSH key. Skipping.")
            return False

    # Show the public key
    if os.path.exists(public_key):
        with open(public_key, "r") as f:
            pubkey = f.read().strip()
        print("\n=== This is your public key ===")
        print(pubkey)
        print("\n==========================-=====")
        print("Note it down as you will need this when configuring the client-instance.\n")
        logger.info("Displayed public key to user.")
    else:
        logger.error("Public key still missing after attempted generation.")
        return False

    return True

def check_not_dcu(logger):
    """Abort if running on a DCU (detected by /pipedream marker)."""
    if Path("/pipedream").exists():
        logger.error("Detected /pipedream — this looks like a DCU. "
                     "Installing the client here will break things. Aborting.")
        sys.exit(1)

def check_supported_ubuntu(logger):
    """Abort unless running on Ubuntu 18.04, 20.04, 22.04, or 24.04, or 25.04."""
    dist = ("", "", "")
    if hasattr(platform, "linux_distribution"):  # deprecated after 3.7
        dist = platform.linux_distribution()
    if not dist[0]:
        try:
            with open("/etc/os-release") as f:
                os_release = f.read()
            if "Ubuntu" in os_release:
                ver = ""
                for line in os_release.splitlines():
                    if line.startswith("VERSION_ID="):
                        ver = line.split("=")[1].strip().strip('"')
                        break
                dist = ("Ubuntu", ver, "")
        except Exception:
            dist = ("", "", "")

    name, ver, _ = dist
    if name != "Ubuntu" or ver.split(".")[0] not in ("18", "20", "22", "24", "25"):
        logger.error(f"Unsupported OS detected: {name} {ver}. "
                     "install_client() only supports Ubuntu 18.04, 20.04, 22.04, or 24.04, or 25.04.")
        sys.exit(1)

    logger.info(f"Confirmed supported OS: {name} {ver}")


def install_server(logger):
    """
    Install and configure a reverse-SSH service using autossh.
    Mirrors the provided bash script. Requires sudo privileges.

    Steps:
      1) apt install autossh
      2) Write /etc/ssh/ssh_config.d/auto-ssh-systemd-hosts.conf
      3) Write /etc/systemd/system/reverse-ssh.service
      4) systemctl daemon-reload && enable && stop && status
    """
    logger.debug(f"install_server():")
    #prompt for each of the variables, and store localy as .file so th enext run has good default
    CLIENT_SSH_TUNNEL_PORT  = int(get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "9000"))
    CLIENT_SSH_PORT_FORWARD = CLIENT_SSH_TUNNEL_PORT + 1
    CLIENT_UI_PORT_FORWARD  = CLIENT_SSH_TUNNEL_PORT + 2
    logger.info(f"SSH forwarding will use the +1 port: {CLIENT_SSH_PORT_FORWARD}")
    logger.info(f"UI forwarding will use the +2 port: {CLIENT_UI_PORT_FORWARD}")
    CLIENT_FQDN_OR_IP             = get_persistent_config(logger, "CLIENT_FQDN_OR_IP", "10.20.30.40")

    # The host alias used by autossh (matches the Host entry we write below).
    AUTOSSH_HOST_ALIAS = CLIENT_FQDN_OR_IP  

    # Paths we write:
    ssh_cfg_path = "/etc/ssh/ssh_config.d/auto-ssh-systemd-hosts.conf"
    unit_path    = "/etc/systemd/system/reverse-ssh.service"

    # --- Helpers ---

    def write_file_with_sudo(dest_path, content):
        # Use a here-doc via tee to avoid worrying about root file perms.
        heredoc = content.replace("$", r"\$")  # prevent shell from expanding $ in content
        cmd = f"bash -lc 'cat > {shlex.quote(dest_path)} <<\"EOF\"\n{heredoc}\nEOF\nchmod 0644 {shlex.quote(dest_path)}'"
        logger.debug(f"Writing file with sudo tee: {dest_path}")
        run(["sudo", "bash", "-lc", cmd])

    # --- 0) Basic sanity checks ---
    if which("sudo") is None:
        logger.error("sudo not found on PATH. Aborting.")
        return False

    # --- 1) Ensure autossh is installed ---
    ensure_pkg("autossh", logger)

    # --- 2) Write ssh_config snippet ---
    ssh_cfg_content = textwrap.dedent(f"""\
        Host {CLIENT_FQDN_OR_IP}
            HostName {CLIENT_FQDN_OR_IP}
            IdentityFile /home/support/.ssh/id_rsa
            User ops 
            Port {CLIENT_SSH_TUNNEL_PORT}
            RemoteForward {CLIENT_SSH_PORT_FORWARD} 127.0.0.1:22
            RemoteForward {CLIENT_UI_PORT_FORWARD} 127.0.0.1:443
            GatewayPorts yes
            Compression yes
    """)
    try:
        logger.info(f"Writing SSH config: {ssh_cfg_path}")
        write_file_with_sudo(ssh_cfg_path, ssh_cfg_content)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to write {ssh_cfg_path}: {e}")
        return False

    # --- 3) Write systemd unit file ---
    unit_content = textwrap.dedent(f"""\
        [Unit]
        Description=Keeps an SSH tunnel to '{AUTOSSH_HOST_ALIAS}' open
        After=network-online.target

        [Service]
        User=support
        ExecStart=/usr/bin/autossh -M 0 -N -q -o "ServerAliveInterval=60" -o "ServerAliveCountMax=3" -o "StrictHostKeyChecking=no" {AUTOSSH_HOST_ALIAS}
        ExecStop=/usr/bin/killall -s KILL autossh
        Restart=always
        RestartSec=3

        [Install]
        WantedBy=multi-user.target
    """)
    try:
        logger.info(f"Writing systemd unit: {unit_path}")
        write_file_with_sudo(unit_path, unit_content)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to write {unit_path}: {e}")
        return False

    # --- 4) Enable service (dont start it yet) ---
    try:
        logger.info("Reloading systemd units...")
        run(["sudo", "systemctl", "daemon-reload"])

        #logger.info("Enabling reverse-ssh.service...")
        #run(["sudo", "systemctl", "enable", "reverse-ssh.service"])

        logger.info("Stopping reverse-ssh.service to ensure a clean state...")
        # Stop may fail if not running; do not check
        run(["sudo", "systemctl", "stop", "reverse-ssh.service"], check=False)

        logger.info("Disabling reverse-ssh.service to ensure a clean state...")
        # disable may fail; do not check
        run(["sudo", "systemctl", "disable", "reverse-ssh.service"], check=False)

    except subprocess.CalledProcessError as e:
        logger.error(f"systemd configuration failed: {e}")
        return False

    logger.info("Note: to test autossh")
    logger.info(f"ssh support@{CLIENT_FQDN_OR_IP} -p {CLIENT_SSH_TUNNEL_PORT}")
    logger.info(f"autossh {AUTOSSH_HOST_ALIAS}")
    logger.info("Service has been installed. Useful commands:")
    logger.info("  sudo systemctl start reverse-ssh.service")
    logger.info("  sudo systemctl stop reverse-ssh.service")
    logger.info("  sudo systemctl status reverse-ssh.service")
    
    #dump the public key or if its missing offer to create an ssh key pair
    ensure_ssh_key(logger)

    logger.info("installing mgmt-access.py into directory /usr/local/sbin/mgmt-access.py")
    install_sw(logger)

    #we use at to disable the daemon after xx hours, check its installed
    ensure_pkg("at", logger)

    logger.info("install_server() completed successfully.")

    return True


def install_client(logger):
    """
    Prepare a client host for secure reverse-SSH access.

      - Reads persisted config via get_persistent_config (which handles prompting/persistence)
      - Appends server's SSH public key to /home/support/.ssh/authorized_keys
      - Hardens sshd: disable password/PAM, disable challenge-response, enable GatewayPorts, set Port=<CLIENT_SSH_TUNNEL_PORT>
      - Restarts ssh service
      - Installs & configures UFW rules (22 from SSH_ALLOWED_IP; and 3 ports for access and forwarding)
      - Installs & configures fail2ban using jail.local (banaction=ufw, port=<CLIENT_SSH_TUNNEL_PORT>)
    """

    # --- safety checks ------------------------------------------------------
    check_supported_ubuntu(logger)
    check_not_dcu(logger)
    check_ops_user(logger)


    #prompt for each of the variables, and store localy as .file so th enext run has good default
    SERVER_IP = get_persistent_config(logger, "SERVER_IP", "10.20.30.40")  # type: ignore[name-defined]
    CLIENT_SSH_TUNNEL_PORT  = int(get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "9000"))
    CLIENT_SSH_PORT_FORWARD = CLIENT_SSH_TUNNEL_PORT + 1
    CLIENT_UI_PORT_FORWARD  = CLIENT_SSH_TUNNEL_PORT + 2
    logger.info(f"SSH forwarding will use the +1 port: {CLIENT_SSH_PORT_FORWARD}")
    logger.info(f"UI forwarding will use the +2 port: {CLIENT_UI_PORT_FORWARD}")
    SSH_ALLOWED_IP = get_persistent_config(logger, "SSH_ALLOWED_IP", "20.30.40.50")  # type: ignore[name-defined]
    SERVER_SSH_PUB_KEY = get_persistent_config(logger, "SERVER_SSH_PUB_KEY", "")  # type: ignore[name-defined]

    logger.info(f"SERVER_IP={SERVER_IP}, CLIENT_SSH_TUNNEL_PORT={CLIENT_SSH_TUNNEL_PORT}, SSH_ALLOWED_IP={SSH_ALLOWED_IP}")

    # -- Ask the user if they would like private address space added to ufw ----
    # -- If not we will lock it down so only the server and SSH_ALLOWED_IP can access it ----

    logger.info(f"By default, ssh will be locked down to only allow  ssh port 22 access from the following source addresses")
    logger.info(f"from the CLIENT_SSH_TUNNEL_PORT {CLIENT_SSH_TUNNEL_PORT} on port 22")
    logger.info(f"from the SERVER_IP {SERVER_IP} on port {CLIENT_SSH_TUNNEL_PORT}")
    logger.info(f"Would you like me to enable ssh from other private ipv4 subnets to help with your testing (these ufw rules should be removed once finished)")
    configure_ufw_ssh_from_private(logger)

    # --- 1) authorized_keys for ops user --------------------------------
    logger.info("adding ssh authorized_keys for the ops user.")
    ops_home = Path("/home/ops")
    ssh_dir = ops_home / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"
    
    ssh_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    
    # Ensure the file exists before appending
    auth_keys.touch(exist_ok=True)
    
    if SERVER_SSH_PUB_KEY.strip():
        append_if_missing_line(auth_keys, SERVER_SSH_PUB_KEY.strip(), logger)
        os.chmod(auth_keys, 0o600)
    else:
        logger.warning("SERVER_SSH_PUB_KEY is empty; skipping initial authorized_keys append.")

    # Optionally import ssh public keys from file(s)
    while True:
        ans = input("Import additional public keys for the ops user from a file? [y/N]: ").strip().lower()
        if ans != "y":
            break
        path_in = input("Enter the path to the file containing public keys: ").strip()
        if not path_in:
            logger.warning("No path entered; skipping.")
            continue
        _import_keys_from_file(auth_keys, path_in, logger)

    # Repeatedly prompt for any additional single keys
    while True:
        ans = input("Do you want to add another public SSH key for user 'ops'? [y/N]: ").strip().lower()
        if ans != "y":
            break
    
        key_line = input(
            "Paste the full OpenSSH public key line (e.g. 'ssh-ed25519 AAAAC3... comment'):\n"
        ).strip()
    
        if not key_line:
            logger.warning("Empty input; not adding a key.")
            continue
    
        if not _looks_like_openssh_pubkey(key_line):
            confirm = input("That doesn't look like a standard OpenSSH public key. Add anyway? [y/N]: ").strip().lower()
            if confirm != "y":
                logger.info("Skipped non-standard key format.")
                continue
        try:
            append_if_missing_line(auth_keys, key_line, logger)
            os.chmod(auth_keys, 0o600)
            logger.info("Key added (or already present).")
        except Exception as e:
            logger.error(f"Failed to append key: {e}")
    
    # best-effort ownership to ops:ops
    try:
        import pwd, grp
        uid = pwd.getpwnam("ops").pw_uid
        gid = grp.getgrnam("ops").gr_gid
        os.chown(ssh_dir, uid, gid)
        os.chown(auth_keys, uid, gid)
    except Exception as e:
        logger.warning(f"Could not chown ~/.ssh to ops:ops (non-fatal): {e}")

#    # --- 2) sshd hardening/config -------------------------------------------
#    harden_sshd(logger, CLIENT_SSH_TUNNEL_PORT, ssh_login_user="ops")

    # --- 2) create a second locked down sshd for use for remote-management---
    add_locked_down_sshd(logger, CLIENT_SSH_TUNNEL_PORT, ssh_user="ops") 

    # --- 3) UFW --------------------------------------------------------------
    #backup the existing iptables rules to /var/backups/iptables 
    backup_iptables(logger)
    ensure_pkg("ufw", logger)
    run(f"sudo ufw allow from {SSH_ALLOWED_IP} to any port 22 proto tcp")
    for p in (CLIENT_SSH_TUNNEL_PORT, CLIENT_SSH_PORT_FORWARD, CLIENT_UI_PORT_FORWARD):
        run(f"sudo ufw allow from {SERVER_IP} to any port {p} proto tcp")
    run("echo 'y' | sudo ufw enable", check=False)
    run("sudo ufw status", check=False)

    # --- 4) fail2ban via jail.local (safer than editing jail.conf) ----------
    ensure_pkg("fail2ban", logger)
    run("sudo systemctl enable fail2ban", check=False)
    run("sudo systemctl start fail2ban", check=False)

    jail_local = "/etc/fail2ban/jail.local"
    existing = read_text(jail_local).splitlines() if Path(jail_local).exists() else []

    def upsert_section(lines, section, kv):
        out, buf, in_sec, found = [], [], False, False
        def flush_buf():
            if buf:
                # ensure all kv exist
                keys_present = {re.split(r"\s*=", l, 1)[0].strip() for l in buf if "=" in l and not l.strip().startswith("#")}
                for k, v in kv.items():
                    if k not in keys_present:
                        buf.append(f"{k} = {v}")
                out.extend(buf)

        for line in lines or []:
            if re.match(r"^\s*\[[^\]]+\]\s*$", line):
                if in_sec:
                    flush_buf()
                in_sec = (line.strip() == f"[{section}]")
                found = found or in_sec
                buf = [line] if in_sec else []
                if not in_sec:
                    out.append(line)
            else:
                if in_sec:
                    buf.append(line)
                else:
                    out.append(line)
        if in_sec:
            flush_buf()
        if not found:
            out.append(f"[{section}]")
            for k, v in kv.items():
                out.append(f"{k} = {v}")
        return out

    #set the fail2ban ignore list, we never want to block the server or the SSH ip
    ignore_list = "127.0.0.1/8 ::1 192.168.1.0/24 " + SERVER_IP + "/32 " +  SSH_ALLOWED_IP + "/32"
    logger.debug(f"fail2ban ignore list: {ignore_list}")

    lines = upsert_section(existing, "DEFAULT", {
        "ignoreip": ignore_list,
        "banaction": "ufw",
    })
    lines = upsert_section(lines, "sshd", {
        "enabled": "true",
        "port": CLIENT_SSH_TUNNEL_PORT,         # monitor your listener port
        "filter": "sshd",
        "logpath": "/var/log/auth.log",
        "maxretry": "5",
        "findtime": "600",
        "bantime": "3600",
    })

    write_text(jail_local, "\n".join(lines) + "\n")

    run("sudo systemctl restart fail2ban")
    run("sudo fail2ban-client ping", check=False)
    run("sudo fail2ban-client status sshd", check=False)

    logger.info("Using fail2ban — useful commands:")
    logger.info("  sudo fail2ban-client status sshd")
    logger.info("  sudo fail2ban-client set sshd unbanip x.x.x.x")
    logger.info("  sudo fail2ban-client set sshd banip x.x.x.x")

    logger.info("installing mgmt-access.py into directory /usr/local/sbin/mgmt-access.py")
    install_sw(logger)

    logger.info("install_client() completed successfully.")



def main():

    parser = argparse.ArgumentParser(description="Management Access Control Tool")
    parser.add_argument( "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO)")
    parser.add_argument("--on", action="store_true", help="Turn management access ON")
    parser.add_argument("--off", action="store_true", help="Turn management access OFF")
    parser.add_argument("--status", action="store_true", help="Show current status")
    #parser.add_argument("--timer-override", type=str, metavar="VALUE", help="Override management access timer with specified VALUE")
    # 1) set the timer-override int if specified  
    #parser.add_argument( "--timer-override", default=24, type=int, metavar="HOURS", help="Override management access timer in hours (default=24)")
    parser.add_argument( "--timer-override", type=int, default=None, help="Override management access timer in hours (default=24, 0=leave_running, option requires --on)")
    parser.add_argument("--install-server", action="store_true", help="Install server components")
    parser.add_argument("--install-client", action="store_true", help="Install client components")
    parser.add_argument("--add-ops-user", action="store_true", help="create an ops user")
    parser.add_argument("--remove-ops-user", action="store_true", help="remove the ops user")
    # Parse arguments
    args = parser.parse_args()
    # If no arguments besides --log-level, show help and exit
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    # Convert string to logging level
    level = getattr(logging, args.log_level.upper(), logging.INFO)
    # Setup logger with chosen level (or INFO if not provided)
    logger = setup_logger(level=level)

    #this tool needs sudo permissions in order to write logs to syslog 
    check_running_as_root(logger)
    #setup argument parser
    parser = argparse.ArgumentParser( description="Management Access Control Tool")
    #--timer-override without --on, print help and exit 
    if args.timer_override is not None and not args.on:
        parser.error("--timer-override requires --on")
    #check args and run the functions to do the things
    if args.on:
        timer_value = args.timer_override if args.timer_override is not None else 24
        turn_on(logger, timer_override=timer_value)
    elif args.off:
        turn_off(logger)
    elif args.status:
        show_status(logger)
    elif args.timer_override:
        timer_override(args.timer_override)
    elif args.install_server:
        install_server(logger)
    elif args.install_client:
        install_client(logger)
    elif args.add_ops_user:
        add_ops_user(logger)
    elif args.remove_ops_user:
        remove_ops_user(logger)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
            print(f"mgmt-access.py Unhandled exception: {e}")
            traceback.print_exc()
