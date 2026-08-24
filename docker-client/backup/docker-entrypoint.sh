#!/usr/bin/env bash
set -Eeuo pipefail

OPS_USER="${OPS_USER:-ops}"
AUTHORIZED_KEYS_SOURCE="/config/authorized_keys"
HOST_KEY_DIR="/etc/ssh/host-keys"

if [[ ! "${OPS_USER}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo "ERROR: Invalid OPS_USER: ${OPS_USER}" >&2
    exit 1
fi

if [[ ! -s "${AUTHORIZED_KEYS_SOURCE}" ]]; then
    echo "ERROR: Client public key file is missing or empty: ${AUTHORIZED_KEYS_SOURCE}" >&2
    exit 1
fi

if ! id "${OPS_USER}" >/dev/null 2>&1; then
    useradd --create-home --shell /usr/sbin/nologin "${OPS_USER}"
fi

# Unlock the account for public-key authentication.
# Password login remains disabled in sshd_config.
passwd -d "${OPS_USER}" >/dev/null

OPS_HOME="$(getent passwd "${OPS_USER}" | cut -d: -f6)"
install -d -m 0700 -o "${OPS_USER}" -g "${OPS_USER}" "${OPS_HOME}/.ssh"
install -m 0600 -o "${OPS_USER}" -g "${OPS_USER}" \
    "${AUTHORIZED_KEYS_SOURCE}" "${OPS_HOME}/.ssh/authorized_keys"

mkdir -p "${HOST_KEY_DIR}" /run/sshd
chmod 0700 "${HOST_KEY_DIR}"

if [[ ! -f "${HOST_KEY_DIR}/ssh_host_ed25519_key" ]]; then
    ssh-keygen -q -t ed25519 -N "" \
        -f "${HOST_KEY_DIR}/ssh_host_ed25519_key"
fi

if [[ ! -f "${HOST_KEY_DIR}/ssh_host_rsa_key" ]]; then
    ssh-keygen -q -t rsa -b 3072 -N "" \
        -f "${HOST_KEY_DIR}/ssh_host_rsa_key"
fi

chmod 0600 "${HOST_KEY_DIR}"/ssh_host_*_key
chmod 0644 "${HOST_KEY_DIR}"/ssh_host_*.pub

/usr/sbin/sshd -t

ED25519_FINGERPRINT="$(
    ssh-keygen -lf "${HOST_KEY_DIR}/ssh_host_ed25519_key.pub" -E sha256 |
    awk '{print $2}'
)"

echo "--------------------------------------------------"
echo "Deepfield Remote Management Docker Client"
echo "SSH host key: ${ED25519_FINGERPRINT}"
echo
echo "Listening:"
echo "  Client SSH connection : 0.0.0.0:9000"
echo "  Reverse SSH forward   : 0.0.0.0:9001"
echo "  Reverse UI forward    : 0.0.0.0:9002"
echo "  Login user            : ${OPS_USER}"
echo "--------------------------------------------------"

REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-9001}" \
REMOTE_UI_PORT="${REMOTE_UI_PORT:-9002}" \
MONITOR_INTERVAL="${MONITOR_INTERVAL:-5}" \
    /usr/local/bin/tunnel-monitor.sh &

exec /usr/sbin/sshd -D -e
