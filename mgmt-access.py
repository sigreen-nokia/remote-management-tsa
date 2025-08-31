#!/usr/bin/env python3
import argparse
import sys
import logging
import logging.handlers
import traceback
import os
import platform
import socket

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

def install_server(logger):
    # Placeholder: logic to install server components
    print("Installing SERVER components")

def install_client(logger):
    # Placeholder: logic to install client components
    print("Installing CLIENT components")

def main():

    parser = argparse.ArgumentParser(description="Management Access Control Tool")
    parser.add_argument( "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level (default: INFO)")
    parser.add_argument("--on", action="store_true", help="Turn management access ON")
    parser.add_argument("--off", action="store_true", help="Turn management access OFF")
    parser.add_argument("--status", action="store_true", help="Show current status")
    #parser.add_argument("--timer-override", type=str, metavar="VALUE", help="Override management access timer with specified VALUE")
    # 1) set the timer-override int if specified  
    parser.add_argument( "--timer-override", default=24, type=int, metavar="HOURS", help="Override management access timer in hours (default=24)")
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

    #this tool should not be ran as root user
    check_not_running_as_root(logger)
    #setup argument parser
    parser = argparse.ArgumentParser( description="Management Access Control Tool")
    #--timer-override without --on, print help and exit 
    if args.timer_override is not None and not args.on:
        parser.error("--timer-override requires --on")
    #check args and run the functions to do the things
    if args.on:
        turn_on(timer_override=args.timer_override)
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
