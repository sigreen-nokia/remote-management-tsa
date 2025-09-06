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

import subprocess
import logging

def show_status(logger):
    """
    Show reverse-ssh.service status if present.
    If log level is DEBUG, dump full `systemctl status` output.
    """
    logger.info("Checking the status of the Remote Access Management Service...")
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

        logger.debug(f"{service} found. Checking status...")

        # If DEBUG → dump full status output
        if logger.isEnabledFor(logging.DEBUG):
            full_status = subprocess.run(
                ["systemctl", "status", service],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
            )
            logger.debug(f"Full systemctl status for {service}:\n{full_status.stdout.strip()}")
        else:
            # Only check active state
            status_check = subprocess.run(
                ["systemctl", "is-active", service],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
            )
            state = status_check.stdout.strip()

            if state == "active":
                logger.info(f"{service} is running ✅")
            else:
                logger.warning(f"{service} is NOT running (state={state})")

    except subprocess.CalledProcessError as e:
        logger.error(f"Error managing {service}: {e.stderr.strip()}")



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

        # 4. Configure login command
        bash_profile = Path("/home/ops/.bash_profile")
        login_cmd = "/usr/local/sbin/mgmt-access.py --help"
        with open(bash_profile, "a", encoding="utf-8") as f:
            f.write(f"\n# Auto-run mgmt-access help on login\n{login_cmd}\n")
        subprocess.run(["sudo", "chown", "ops:ops", str(bash_profile)], check=True)
        logger.info(f"Configured {bash_profile} to run '{login_cmd}' on login.")

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
    CLIENT_SSH_TUNNEL_PORT  = get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "9000")
    CLIENT_SSH_PORT_FORWARD = get_persistent_config(logger, "CLIENT_SSH_PORT_FORWARD", "9001")
    CLIENT_UI_PORT_FORWARD  = get_persistent_config(logger, "CLIENT_UI_PORT_FORWARD", "9002")
    CLIENT_FQDN_OR_IP             = get_persistent_config(logger, "CLIENT_FQDN_OR_IP", "10.20.30.40")

    # The host alias used by autossh (matches the Host entry we write below).
    AUTOSSH_HOST_ALIAS = CLIENT_FQDN_OR_IP  # in your bash you used "vm-in-deepfield-gcp"; align as needed

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
    ensure_pkg("autossh", logger)

    # --- 2) Write ssh_config snippet ---
    ssh_cfg_content = textwrap.dedent(f"""\
        Host {CLIENT_FQDN_OR_IP}
            HostName {CLIENT_FQDN_OR_IP}
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

    Mirrors the original bash:
      - Reads persisted config via get_persistent_config (which handles prompting/persistence)
      - Appends server's SSH public key to /home/support/.ssh/authorized_keys
      - Hardens sshd: disable password/PAM, disable challenge-response, enable GatewayPorts, set Port=<CLIENT_SSH_TUNNEL_PORT>
      - Restarts ssh service
      - Installs & configures UFW rules (22 from SSH_ALLOWED_IP; 9000..9002 from SERVER_IP)
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
                logger.info(f"Note: I have Backed up file {src} before modifying to file {dst}")
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
    CLIENT_SSH_TUNNEL_PORT = str(get_persistent_config(logger, "CLIENT_SSH_TUNNEL_PORT", "9000"))  # type: ignore[name-defined]
    SSH_ALLOWED_IP = get_persistent_config(logger, "SSH_ALLOWED_IP", "107.21.96.169")  # type: ignore[name-defined]
    SSH_PUB_KEY = get_persistent_config(logger, "SSH_PUB_KEY", "")  # type: ignore[name-defined]

    logger.info(f"SERVER_IP={SERVER_IP}, CLIENT_SSH_TUNNEL_PORT={CLIENT_SSH_TUNNEL_PORT}, SSH_ALLOWED_IP={SSH_ALLOWED_IP}")

    # -- let the user know we are about to lock down ssh ----
    logger.info(f"Warning: On completion ssh will be locked down in ufw to only allow the following source addresses")
    logger.info(f"from the CLIENT_SSH_TUNNEL_PORT {CLIENT_SSH_TUNNEL_PORT} on port 22")
    logger.info(f"from the SERVER_IP {SERVER_IP} on port {CLIENT_SSH_TUNNEL_PORT}")

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
    #backup the existing iptables rules to /var/backups/iptables 
    backup_iptables(logger)
    ensure_pkg("ufw", logger)
    run(f"sudo ufw allow from {SSH_ALLOWED_IP} to any port 22 proto tcp")
    for p in ("9000", "9001", "9002"):
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
