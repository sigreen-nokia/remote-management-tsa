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

def setup_logger(level=logging.INFO):
    # Don’t let logging print handler tracebacks on emit errors
    logging.raiseExceptions = False

    logger = logging.getLogger("tweedle.py")  # or "mgmt-access"
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
        "%(asctime)s %(name)s [%(levelname)s]: pid=%(process)d %(message)s",
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



def turn_on(timer_override=None):
    # Placeholder: logic to enable management access
    if timer_override is not None:
        print(f"Turning management access ON (timer override: {timer_override})")
    else:
        print("Turning management access ON")

def turn_off(logger):
    # Placeholder: logic to disable management access
    print("Turning management access OFF")

def show_status(logger):
    # Placeholder: logic to check current status
    print("Showing management access STATUS")

def timer_override(value):
    # Placeholder: logic to override timer
    print(f"Applying timer override: {value}")


import os
import subprocess

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
    """Abort unless running on Ubuntu 18.04, 20.04, 22.04, or 24.04."""
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
    if name != "Ubuntu" or ver.split(".")[0] not in ("18", "20", "22", "24"):
        logger.error(f"Unsupported OS detected: {name} {ver}. "
                     "install_client() only supports Ubuntu 18.04, 20.04, 22.04, or 24.04.")
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
    CLIENT_SSH_TUNNEL_PORT  = get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "8000")
    CLIENT_SSH_PORT_FORWARD = get_persistent_config(logger, "CLIENT_SSH_PORT_FORWARD", "8001")
    CLIENT_UI_PORT_FORWARD  = get_persistent_config(logger, "CLIENT_UI_PORT_FORWARD", "9001")
    CLIENT_FQDN             = get_persistent_config(logger, "CLIENT_FQDN", "86.146.112.89")

    # The host alias used by autossh (matches the Host entry we write below).
    AUTOSSH_HOST_ALIAS = CLIENT_FQDN  # in your bash you used "vm-in-deepfield-gcp"; align as needed

    # Paths we write:
    ssh_cfg_path = "/etc/ssh/ssh_config.d/auto-ssh-systemd-hosts.conf"
    unit_path    = "/etc/systemd/system/reverse-ssh.service"

    # --- Helpers ---
    def run(cmd, check=True, capture_output=False):
        logger.debug(f"Running: {cmd}")
        return subprocess.run(
            cmd if isinstance(cmd, list) else shlex.split(cmd),
            check=check,
            capture_output=capture_output,
            text=True,
        )

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
    try:
        if which("autossh"):
            logger.info("autossh is already installed. Skipping installation.")
        else:
            logger.info("Installing autossh (apt)...")
            if which("apt"):
                run(["sudo", "apt", "update"])
                run(["sudo", "apt", "install", "-y", "autossh"])
            else:
                logger.warning("apt not found; attempting to continue (autossh must already be installed).")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install autossh: {e}")
        return False

    # --- 2) Write ssh_config snippet ---
    ssh_cfg_content = textwrap.dedent(f"""\
        Host {CLIENT_FQDN}
            HostName {CLIENT_FQDN}
            IdentityFile /home/support/.ssh/id_rsa
            User support
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
        ExecStart=/usr/bin/autossh -M 0 -N -q -o "ServerAliveInterval=60" -o "ServerAliveCountMax=3" {AUTOSSH_HOST_ALIAS}
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

    # --- 4) Enable service (don’t start it yet) ---
    try:
        logger.info("Reloading systemd units...")
        run(["sudo", "systemctl", "daemon-reload"])

        logger.info("Enabling reverse-ssh.service...")
        run(["sudo", "systemctl", "enable", "reverse-ssh.service"])

        logger.info("Stopping reverse-ssh.service to ensure a clean state...")
        # Stop may fail if not running; do not check
        run(["sudo", "systemctl", "stop", "reverse-ssh.service"], check=False)

        logger.info("Querying status (this may show 'inactive/dead' until you start it)...")
        status = run(["sudo", "systemctl", "status", "reverse-ssh.service"], check=False, capture_output=True)
        logger.debug("\n" + status.stdout.strip())
    except subprocess.CalledProcessError as e:
        logger.error(f"systemd configuration failed: {e}")
        return False

    # --- Friendly notes (from your script) ---
    logger.info("Note: to test autossh")
    logger.info(f"ssh support@{CLIENT_FQDN} -p {CLIENT_SSH_TUNNEL_PORT}")
    logger.info(f"autossh {AUTOSSH_HOST_ALIAS}")
    logger.info("Service has been installed. Useful commands:")
    logger.info("  sudo systemctl start reverse-ssh.service")
    logger.info("  sudo systemctl stop reverse-ssh.service")
    logger.info("  sudo systemctl status reverse-ssh.service")
    
    #dump the public key or if its missing offer to create an ssh key pair
    ensure_ssh_key(logger)

    return True


def install_client(logger):
    """
    Prepare a client host for secure reverse-SSH access.

    Mirrors the original bash:
      - Reads persisted config via get_persistent_config (which handles prompting/persistence)
      - Appends server's SSH public key to /home/support/.ssh/authorized_keys
      - Hardens sshd: disable password/PAM, disable challenge-response, enable GatewayPorts, set Port=<CLIENT_SSH_TUNNEL_PORT>
      - Restarts ssh service
      - Installs & configures UFW rules (22 from SSH_ALLOWED_IP; 8000..8002 from SERVER_IP)
      - Installs & configures fail2ban using jail.local (banaction=ufw, port=<CLIENT_SSH_TUNNEL_PORT>)
    """

    # --- safety checks ------------------------------------------------------
    check_supported_ubuntu(logger)
    check_not_dcu(logger)


    # --- helpers--------------------------------
    def run(cmd, check=True):
        """Prefer your run_cmd() if present; else subprocess."""
        try:
            # If your module defines run_cmd(logger, cmd, check=True), use it
            return run_cmd(logger, cmd, check=check)  # type: ignore[name-defined]
        except Exception:
            logger.info(f"RUN: {cmd}")
            return subprocess.run(
                cmd, shell=True, check=check,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

    def ensure_pkg(pkg):
        # idempotent install for apt packages
        try:
            run(f"dpkg -s {pkg}")
            logger.info(f"Package already installed: {pkg}")
        except subprocess.CalledProcessError:
            run("sudo apt-get update -y || true", check=False)
            run(f"sudo apt-get install -y {pkg}")

    def read_text(p):
        try:
            return Path(p).read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def write_text(p, content, mode=0o644):
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        Path(p).write_text(content, encoding="utf-8")
        os.chmod(p, mode)

    def append_if_missing_line(p, line):
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

    def backup_file(p):
        """Backup config file p if it exists, to <p>.bak-YYYYmmdd-HHMMSS"""
        src = Path(p)
        if src.exists():
            ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            dst = src.with_suffix(src.suffix + f".bak-{ts}")
            try:
                shutil.copy2(src, dst)
                logger.info(f"Backed up {src} to {dst}")
            except Exception as e:
                logger.warning(f"Could not backup {src}: {e}")

    def replace_or_add_line(p, key_regex, replacement, extra_lines=None):
        """
        Replace first line matching key_regex with replacement; if none matched, append replacement.
        Optionally also ensure extra_lines (list of lines) appear *after* replacement.
        """
        backup_file(p)  # backup before modifying
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


    # --- gather config via your existing helper ------------------------------
    SERVER_IP = get_persistent_config(logger, "SERVER_IP", "10.20.30.40")  # type: ignore[name-defined]
    CLIENT_SSH_TUNNEL_PORT = str(get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "8000"))  # type: ignore[name-defined]
    SSH_ALLOWED_IP = get_persistent_config(logger, "SSH_ALLOWED_IP", "107.21.96.169")  # type: ignore[name-defined]
    SSH_PUB_KEY = get_persistent_config(logger, "SSH_PUB_KEY", "")  # type: ignore[name-defined]
    FAIL2BAN_EXCLUDE_IP = get_persistent_config(logger, "FAIL2BAN_EXCLUDE_IP", "")  # optional

    logger.info(f"SERVER_IP={SERVER_IP}, CLIENT_SSH_TUNNEL_PORT={CLIENT_SSH_TUNNEL_PORT}, SSH_ALLOWED_IP={SSH_ALLOWED_IP}")

    # --- 1) authorized_keys for support user --------------------------------
    support_home = Path("/home/support")
    ssh_dir = support_home / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"

    ssh_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(ssh_dir, 0o700)

    if SSH_PUB_KEY.strip():
        append_if_missing_line(auth_keys, SSH_PUB_KEY.strip())
        os.chmod(auth_keys, 0o600)
        # best-effort ownership to support:support
        try:
            import pwd, grp
            uid = pwd.getpwnam("support").pw_uid
            gid = grp.getgrnam("support").gr_gid
            os.chown(ssh_dir, uid, gid)
            os.chown(auth_keys, uid, gid)
        except Exception as e:
            logger.warning(f"Could not chown ~/.ssh to support:support (non-fatal): {e}")
    else:
        logger.warning("SSH_PUB_KEY is empty; skipping authorized_keys append.")

    # --- 2) sshd hardening/config -------------------------------------------
    sshd_main = "/etc/ssh/sshd_config"
    sshd_cloudinit = "/etc/ssh/sshd_config.d/50-cloud-init.conf"

    if Path(sshd_cloudinit).exists():
        replace_or_add_line(sshd_cloudinit, r"^\s*PasswordAuthentication\s+", "PasswordAuthentication no")

    replace_or_add_line(sshd_main, r"^\s*PasswordAuthentication\s+", "PasswordAuthentication no")
    replace_or_add_line(sshd_main, r"^\s*UsePAM\s+", "UsePAM no")
    replace_or_add_line(sshd_main, r"^\s*ChallengeResponseAuthentication\s+", "ChallengeResponseAuthentication no")
    replace_or_add_line(sshd_main, r"^\s*GatewayPorts\s+", "GatewayPorts yes")
    replace_or_add_line(sshd_main, r"^\s*Port\s+", f"Port {CLIENT_SSH_TUNNEL_PORT}", extra_lines=["Port 22"])

    try:
        run("sudo systemctl restart ssh")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restart ssh: {e.stderr.strip()}")
        raise

    # --- 3) UFW --------------------------------------------------------------
    ensure_pkg("ufw")
    run(f"sudo ufw allow from {SSH_ALLOWED_IP} to any port 22 proto tcp")
    for p in ("8000", "8001", "8002"):
        run(f"sudo ufw allow from {SERVER_IP} to any port {p} proto tcp")
    run("echo 'y' | sudo ufw enable", check=False)
    run("sudo ufw status", check=False)

    # --- 4) fail2ban via jail.local (safer than editing jail.conf) ----------
    ensure_pkg("fail2ban")
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

    ignore_list = "127.0.0.1/8 ::1 192.168.1.0/24"
    if FAIL2BAN_EXCLUDE_IP.strip():
        ignore_list += f" {FAIL2BAN_EXCLUDE_IP.strip()}"

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
    parser.add_argument( "--timer-override", type=int, default=None, help="Override management access timer in hours (default=24, requires --on)")
    parser.add_argument("--install-server", action="store_true", help="Install server components")
    parser.add_argument("--install-client", action="store_true", help="Install client components")
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
    #if args.timer_override is not None and not args.on:
    #    parser.error("--timer-override requires --on")
    if args.timer_override is not None and not args.on:
        parser.error("--timer-override requires --on")
    #check args and run the functions to do the things
    if args.on:
        timer_value = args.timer_override if args.timer_override is not None else 24
        turn_on(timer_override=timer_value)
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
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
            print(f"tweedle.py Unhandled exception: {e}")
            traceback.print_exc()
