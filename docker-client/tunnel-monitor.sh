#!/usr/bin/env bash
set -Eeuo pipefail

SSH_FORWARD_PORT="${REMOTE_SSH_PORT:-9001}"
UI_FORWARD_PORT="${REMOTE_UI_PORT:-9002}"
CHECK_INTERVAL="${MONITOR_INTERVAL:-5}"

ssh_state="unknown"
ui_state="unknown"

is_listening() {
    local port="$1"
    ss -lntH "sport = :${port}" 2>/dev/null | grep -q .
}

while true; do
    if is_listening "${SSH_FORWARD_PORT}"; then
        if [[ "${ssh_state}" != "up" ]]; then
            echo "Reverse SSH tunnel is available on port ${SSH_FORWARD_PORT}"
            ssh_state="up"
        fi
    else
        if [[ "${ssh_state}" != "down" ]]; then
            echo "Waiting for reverse SSH tunnel on port ${SSH_FORWARD_PORT}"
            ssh_state="down"
        fi
    fi

    if is_listening "${UI_FORWARD_PORT}"; then
        if [[ "${ui_state}" != "up" ]]; then
            echo "Reverse UI tunnel is available on port ${UI_FORWARD_PORT}"
            ui_state="up"
        fi
    else
        if [[ "${ui_state}" != "down" ]]; then
            echo "Waiting for reverse UI tunnel on port ${UI_FORWARD_PORT}"
            ui_state="down"
        fi
    fi

    sleep "${CHECK_INTERVAL}"
done
