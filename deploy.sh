#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CREDENTIAL_FILE="${DNSSH_CREDENTIAL_FILE:-$SCRIPT_DIR/.deploy/credentials.env}"

if [[ -f "$CREDENTIAL_FILE" ]]; then
    echo "[deploy] Loading credentials from $CREDENTIAL_FILE"
    set -a
    # Normalize CRLF to LF so Windows edits do not break shell sourcing.
    # shellcheck disable=SC1090
    . <(sed 's/\r$//' "$CREDENTIAL_FILE")
    set +a
fi

REMOTE_USER="${DNSSH_REMOTE_USER:-root}"
REMOTE_HOST="${DNSSH_REMOTE_HOST:-5.22.215.188}"
REMOTE_DIR="${DNSSH_REMOTE_DIR:-/root/dnssh}"
SERVER_PORT="${DNSSH_SERVER_PORT:-53}"
DOMAIN="${DNSSH_DOMAIN:-}"
KEY_HEX="${DNSSH_KEY_HEX:-}"
IDENTITY_FILE="${DNSSH_DEPLOY_KEY_FILE:-$SCRIPT_DIR/.deploy/id_ed25519}"
PRIVATE_KEY_TEXT="${DNSSH_DEPLOY_PRIVATE_KEY:-}"
KEY_PASSPHRASE="${DNSSH_DEPLOY_PASSPHRASE:-}"

show_usage() {
    cat <<'EOF'
Usage:
  ./deploy.sh --domain <dns_domain> --key-hex <64_hex_chars> [options]

Options:
  --host <ip_or_host>        Remote host (default: 5.22.215.188)
  --user <username>          SSH user (default: root)
  --remote-dir <path>        Remote install dir (default: /root/dnssh)
  --port <udp_port>          dnssh-server listen port (default: 53)
  --identity-file <path>     SSH private key file
  --help                     Show this help

Environment variables:
  DNSSH_CREDENTIAL_FILE      Credentials env file (default: .deploy/credentials.env)
  DNSSH_DOMAIN               Same as --domain
  DNSSH_KEY_HEX              Same as --key-hex
  DNSSH_REMOTE_HOST          Same as --host
  DNSSH_REMOTE_USER          Same as --user
  DNSSH_REMOTE_DIR           Same as --remote-dir
  DNSSH_SERVER_PORT          Same as --port
  DNSSH_DEPLOY_KEY_FILE      Same as --identity-file
  DNSSH_DEPLOY_PRIVATE_KEY   Raw private key text (kept in a temp file at runtime)
  DNSSH_DEPLOY_PASSPHRASE    Optional passphrase used to unlock the key via ssh-add

Notes:
  - The script auto-loads .deploy/credentials.env when present.
  - Default key path is .deploy/id_ed25519.
    - Deployment uploads source and compiles dnssh-server on the remote host.
  - Do not commit private keys/passphrases to git.
  - If DNSSH_DEPLOY_PASSPHRASE is set, the script tries to unlock the key via ssh-add.
  - Otherwise OpenSSH prompts for passphrase interactively.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --key-hex)
            KEY_HEX="$2"
            shift 2
            ;;
        --host)
            REMOTE_HOST="$2"
            shift 2
            ;;
        --user)
            REMOTE_USER="$2"
            shift 2
            ;;
        --remote-dir)
            REMOTE_DIR="$2"
            shift 2
            ;;
        --port)
            SERVER_PORT="$2"
            shift 2
            ;;
        --identity-file)
            IDENTITY_FILE="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "[deploy] Unknown option: $1" >&2
            show_usage
            exit 1
            ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo "[deploy] Missing --domain (or DNSSH_DOMAIN)." >&2
    exit 1
fi

if [[ -z "$KEY_HEX" || ! "$KEY_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "[deploy] --key-hex must be exactly 64 hex characters." >&2
    exit 1
fi

if [[ ! "$SERVER_PORT" =~ ^[0-9]+$ ]] || (( SERVER_PORT < 1 || SERVER_PORT > 65535 )); then
    echo "[deploy] --port must be in range 1..65535." >&2
    exit 1
fi

tmp_key_file=""
staged_key_file=""
askpass_file=""
started_agent=0
control_path="${TMPDIR:-/tmp}/dnssh-deploy-${REMOTE_USER}@${REMOTE_HOST}-${$}.sock"

cleanup() {
    if [[ -n "$tmp_key_file" && -f "$tmp_key_file" ]]; then
        rm -f "$tmp_key_file"
    fi
    if [[ -n "$staged_key_file" && -f "$staged_key_file" ]]; then
        rm -f "$staged_key_file"
    fi
    if [[ -n "$askpass_file" && -f "$askpass_file" ]]; then
        rm -f "$askpass_file"
    fi
    if (( started_agent == 1 )) && [[ -n "${SSH_AGENT_PID:-}" ]]; then
        ssh-agent -k >/dev/null 2>&1 || true
    fi
    rm -f "$control_path" 2>/dev/null || true
}
trap cleanup EXIT

if [[ -n "$PRIVATE_KEY_TEXT" ]]; then
    tmp_key_file="$(mktemp "${TMPDIR:-/tmp}/dnssh-deploy-key.XXXXXX")"
    chmod 600 "$tmp_key_file"
    printf '%s\n' "$PRIVATE_KEY_TEXT" > "$tmp_key_file"
    IDENTITY_FILE="$tmp_key_file"
fi

if [[ -z "$IDENTITY_FILE" ]]; then
    echo "[deploy] Provide --identity-file or DNSSH_DEPLOY_PRIVATE_KEY." >&2
    exit 1
fi

if [[ ! -f "$IDENTITY_FILE" ]]; then
    echo "[deploy] SSH key file not found: $IDENTITY_FILE" >&2
    exit 1
fi

# Always stage the key into a local 0600 temp file. This avoids OpenSSH
# permission checks failing on Windows-mounted filesystems (e.g. /mnt/c).
staged_key_file="$(mktemp "${TMPDIR:-/tmp}/dnssh-sshkey.XXXXXX")"
chmod 600 "$staged_key_file"
# Also normalize CRLF to LF because OpenSSH key parsing is strict.
sed 's/\r$//' "$IDENTITY_FILE" > "$staged_key_file"
chmod 600 "$staged_key_file"

EFFECTIVE_IDENTITY_FILE="$staged_key_file"

if [[ -n "$KEY_PASSPHRASE" ]]; then
    if ! command -v ssh-add >/dev/null 2>&1 || ! command -v ssh-agent >/dev/null 2>&1 || ! command -v setsid >/dev/null 2>&1; then
        echo "[deploy] Warning: passphrase was provided but ssh-add/ssh-agent/setsid is unavailable; using interactive prompt." >&2
    else
        if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
            eval "$(ssh-agent -s)" >/dev/null
            started_agent=1
        fi

        askpass_file="$(mktemp "${TMPDIR:-/tmp}/dnssh-askpass.XXXXXX")"
        cat > "$askpass_file" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${DNSSH_DEPLOY_PASSPHRASE:-}"
EOF
        chmod 700 "$askpass_file"

        if ! DISPLAY="${DISPLAY:-:0}" \
             SSH_ASKPASS="$askpass_file" \
             SSH_ASKPASS_REQUIRE=force \
             DNSSH_DEPLOY_PASSPHRASE="$KEY_PASSPHRASE" \
             setsid ssh-add "$EFFECTIVE_IDENTITY_FILE" < /dev/null >/dev/null 2>&1; then
            echo "[deploy] Warning: automatic key unlock failed; continuing with interactive SSH prompt." >&2
        fi
    fi
fi

target="${REMOTE_USER}@${REMOTE_HOST}"
ssh_opts=(
    -o StrictHostKeyChecking=accept-new
    -o IdentitiesOnly=yes
    -o ControlMaster=auto
    -o ControlPersist=120
    -o "ControlPath=${control_path}"
    -i "$EFFECTIVE_IDENTITY_FILE"
)

echo "[deploy] Connecting to ${target}..."
ssh "${ssh_opts[@]}" "$target" "true"

echo "[deploy] Uploading source files to ${target}:${REMOTE_DIR}"
ssh "${ssh_opts[@]}" "$target" "mkdir -p '$REMOTE_DIR' && chmod 700 '$REMOTE_DIR'"
scp "${ssh_opts[@]}" ./dnssh.c ./makefile ./dnssh-server.service "${target}:${REMOTE_DIR}/"

echo "[deploy] Building and restarting remote dnssh-server..."
ssh "${ssh_opts[@]}" "$target" "REMOTE_DIR='$REMOTE_DIR' SERVER_PORT='$SERVER_PORT' DOMAIN='$DOMAIN' KEY_HEX='$KEY_HEX' bash -s" <<'EOF'
set -euo pipefail

# Install dependencies if missing (Debian/Ubuntu)
if ! dpkg -s build-essential libsodium-dev zlib1g-dev >/dev/null 2>&1; then
    echo "[deploy] Installing missing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y build-essential libsodium-dev zlib1g-dev
fi

cd "$REMOTE_DIR"
make dnssh-server
chmod 700 "$REMOTE_DIR/dnssh-server"

echo "[deploy] Installing systemd service..."
sed -e "s|/root/dnssh|$REMOTE_DIR|g" \
    -e "s|DEPLOY_PORT|$SERVER_PORT|g" \
    -e "s|DEPLOY_DOMAIN|$DOMAIN|g" \
    -e "s|DEPLOY_KEY|$KEY_HEX|g" \
    "$REMOTE_DIR/dnssh-server.service" > /etc/systemd/system/dnssh-server.service

systemctl daemon-reload
systemctl enable dnssh-server
systemctl restart dnssh-server
sleep 1

if ! systemctl is-active --quiet dnssh-server; then
    echo "[deploy] dnssh-server failed to stay running" >&2
    journalctl -u dnssh-server -n 40 --no-pager >&2 || true
    exit 1
fi
EOF

echo "[deploy] Success."
echo "[deploy] Check logs: ssh -i '$IDENTITY_FILE' '$target' \"journalctl -u dnssh-server -f\""
