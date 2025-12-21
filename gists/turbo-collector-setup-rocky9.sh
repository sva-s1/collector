#!/usr/bin/env bash
#https://gist.github.com/sva-s1/63e5cf6b5eac44e481faf0bb0ec991f7
set -euo pipefail

# Scalyr Agent 2 (SentinelOne Collector) installer for Rocky Linux 9
# - Installs scalyr-agent-2 into /opt/scalyr-agent-2/venv
# - Writes config/state/logs under /etc/scalyr-agent-2/
# - Uses /opt/scalyr-agent-2/scalyr wrapper (loads /etc/scalyr-agent-2/scalyr.env)
# - Installs a symlink to /usr/bin/scalyr so `sudo scalyr ...` works on Rocky secure_path
#
# Usage:
#   sudo bash install_scalyr_agent2_rocky9_v9.sh
#
# Re-run behavior:
#   Safe to re-run. It will overwrite:
#     - /etc/scalyr-agent-2/agent.json
#     - /etc/scalyr-agent-2/scalyr.env  (unless you choose to keep existing)
#     - /opt/scalyr-agent-2/scalyr
#     - /etc/systemd/system/scalyr-agent-2.service
#
# Notes:
# - API key is stored in /etc/scalyr-agent-2/scalyr.env (chmod 600).
# - The agent reads SCALYR_API_KEY and SCALYR_SERVER from environment at start.

N_STEPS=9

GREEN=$'\033[32m'
RESET=$'\033[0m'
BOLD=$'\033[1m'

step() {
  local n="$1"; shift
  printf "\n%s[%s/%s]%s %s\n" "${GREEN}" "${n}" "${N_STEPS}" "${RESET}" "$*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root (use: sudo bash $0)"
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

need_root

# ---------- constants ----------
TAG="v2.2.19"

BASE_ETC="/etc/scalyr-agent-2"
CFG="${BASE_ETC}/agent.json"
ENVFILE="${BASE_ETC}/scalyr.env"
LOGDIR="${BASE_ETC}/log"
DATADIR="${BASE_ETC}/data"

BASE_OPT="/opt/scalyr-agent-2"
VENV="${BASE_OPT}/venv"
PY="${VENV}/bin/python"
PIP="${VENV}/bin/pip"
WRAPPER="${BASE_OPT}/scalyr"
SYMLINK="/usr/bin/scalyr"

# Suppress the noisy warning everywhere we invoke python from this script.
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'

# ---------- step 1: packages ----------
step 1 "Installing OS packages via dnf (git, python, build deps, nc, tcpdump)..."

dnf -y makecache >/dev/null

dnf -y install \
  python3 python3-pip git \
  gcc make python3-devel \
  openssl-devel libffi-devel \
  nmap-ncat tcpdump \
  >/dev/null

command_exists git || die "git missing (dnf install git failed?)"
command_exists nc  || die "nc missing (dnf install nmap-ncat failed?)"

# ---------- step 2: directories ----------
step 2 "Creating directories under ${BASE_ETC} and ${BASE_OPT}..."

mkdir -p "${BASE_ETC}/agent.d" "${DATADIR}" "${LOGDIR}"
chmod 755 "${BASE_ETC}"
chown -R root:root "${BASE_ETC}"

mkdir -p "${BASE_OPT}"
chmod 755 "${BASE_OPT}"
chown -R root:root "${BASE_OPT}"

# ---------- step 3: venv + install ----------
step 3 "Creating venv + installing scalyr-agent-2 from Git tag ${TAG}..."

if [[ ! -x "${PY}" ]]; then
  python3 -m venv "${VENV}"
fi

"${PIP}" install -q --upgrade pip setuptools wheel >/dev/null

# Installing from Git tag requires git on PATH (already installed above).
"${PIP}" install -q "git+https://github.com/scalyr/scalyr-agent-2.git@${TAG}" >/dev/null

# Quiet sanity check: validate import (no agent config needed).
step 4 "Sanity check: Python import (quiet)..."
"${PY}" -c "import scalyr_agent; import scalyr_agent.agent_main; print('ok')" >/dev/null

# ---------- step 5: region + API key (prompt) ----------
step 5 "Collecting region + API key (writes ${ENVFILE})..."

echo
echo "${BOLD}SentinelOne region endpoints:${RESET}"
cat <<'MENU'
  1) US1 (default)  https://xdr.us1.sentinelone.net
  2) US2            https://xdr.us2.sentinelone.net
  3) EU1            https://xdr.eu1.sentinelone.net
  4) AP1            https://xdr.ap1.sentinelone.net
  5) AP2            https://xdr.ap2.sentinelone.net
  6) Custom         (enter a full https://xdr.<region>.sentinelone.net URL)
MENU
echo

read -r -p "Region choice [1-6] (default 1): " REGION_CHOICE
REGION_CHOICE="${REGION_CHOICE:-1}"

SCALYR_SERVER=""
case "${REGION_CHOICE}" in
  1) SCALYR_SERVER="https://xdr.us1.sentinelone.net" ;;
  2) SCALYR_SERVER="https://xdr.us2.sentinelone.net" ;;
  3) SCALYR_SERVER="https://xdr.eu1.sentinelone.net" ;;
  4) SCALYR_SERVER="https://xdr.ap1.sentinelone.net" ;;
  5) SCALYR_SERVER="https://xdr.ap2.sentinelone.net" ;;
  6)
    read -r -p "Enter custom SCALYR_SERVER (https://...): " SCALYR_SERVER
    ;;
  *)
    echo "Invalid choice '${REGION_CHOICE}', using default US1." >&2
    SCALYR_SERVER="https://xdr.us1.sentinelone.net"
    ;;
esac

# Ask whether to keep existing env file (if present).
if [[ -f "${ENVFILE}" ]]; then
  echo
  read -r -p "Found existing ${ENVFILE}. Keep it as-is? [y/N]: " KEEP_ENV
  KEEP_ENV="${KEEP_ENV:-N}"
  if [[ "${KEEP_ENV}" =~ ^[Yy]$ ]]; then
    echo "Keeping existing ${ENVFILE}."
    # Still ensure permissions.
    chmod 600 "${ENVFILE}"
    chown root:root "${ENVFILE}"
  else
    rm -f "${ENVFILE}"
  fi
fi

SCALYR_API_KEY=""
if [[ ! -f "${ENVFILE}" ]]; then
  echo
  echo "Get your key from: https://community.sentinelone.com/s/article/000006763"
  echo "  1) Log into your Singularity Data Lake console"
  echo "  2) Navigate to Settings > API Keys"
  echo "  3) Generate a \"Log Access Write\" key"
  echo "  4) Paste it below (input is hidden)."
  echo

  # Hidden input (Enter to skip).
  read -r -s -p "Enter SCALYR_API_KEY (hidden input, press Enter to skip for now): " SCALYR_API_KEY
  echo

  if [[ -z "${SCALYR_API_KEY}" ]]; then
    SCALYR_API_KEY="REPLACE_ME"
  fi

  cat > "${ENVFILE}" <<EOF
# Scalyr Agent 2 env vars (root-only)
# Update this file any time (then restart the service).
#
# Required (this is your "Log Write Access" API key):
SCALYR_API_KEY="${SCALYR_API_KEY}"

# SentinelOne Regional Endpoint
# US1 is the default region. For other regions, see:
# https://community.sentinelone.com/s/article/000004961
#
# Common regions:
#   US1: https://xdr.us1.sentinelone.net
#   US2: https://xdr.us2.sentinelone.net
#   EU1: https://xdr.eu1.sentinelone.net
#   AP1: https://xdr.ap1.sentinelone.net
#   AP2: https://xdr.ap2.sentinelone.net
SCALYR_SERVER="${SCALYR_SERVER}"
EOF

  chmod 600 "${ENVFILE}"
  chown root:root "${ENVFILE}"

  # Never keep the API key in shell memory longer than needed.
  unset SCALYR_API_KEY
fi

# ---------- step 6: agent.json ----------
step 6 "Writing ${CFG} (API key is read from ${ENVFILE})..."

cat > "${CFG}" <<'JSON'
{
  "ca_cert_path": "/etc/ssl/certs/ca-bundle.crt",
  "agent_log_path": "/etc/scalyr-agent-2/log",
  "agent_data_path": "/etc/scalyr-agent-2/data",
  "implicit_metric_monitor": false,
  "implicit_agent_process_metrics_monitor": false,
  "server_attributes": {
    "serverHost": "localhost"
  },
  "monitors": [
    {
      "module": "scalyr_agent.builtin_monitors.syslog_monitor",
      "protocols": "tcp:514, udp:514",
      "accept_remote_connections": true,
      "message_log": "fortigate.log",
      "parser": "marketplace-fortinetfortigate-latest"
    }
  ]
}
JSON

chmod 600 "${CFG}"
chown root:root "${CFG}"

# ---------- step 7: wrapper + PATH ----------
step 7 "Writing wrapper ${WRAPPER} and enabling /usr/bin/scalyr (works with sudo secure_path)..."

cat > "${WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG="/etc/scalyr-agent-2/agent.json"
ENVFILE="/etc/scalyr-agent-2/scalyr.env"
PY="/opt/scalyr-agent-2/venv/bin/python"

# Load env (SCALYR_API_KEY, SCALYR_SERVER, etc.) so humans + systemd behave the same.
if [[ -f "$ENVFILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENVFILE"
  set +a
fi

# Suppress noisy warning:
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'

# Quiet "already running" noise on start.
if [[ "${1:-}" == "start" ]]; then
  set +e
  out="$("$PY" -m scalyr_agent.agent_main -c "$CONFIG" "$@" 2>&1)"
  rc=$?
  set -e
  if echo "$out" | grep -qi "already running"; then
    exit 0
  fi
  if [[ $rc -ne 0 ]]; then
    echo "$out" >&2
    exit $rc
  fi
  echo "$out"
  exit 0
fi

exec "$PY" -m scalyr_agent.agent_main -c "$CONFIG" "$@"
EOF

chmod 0755 "${WRAPPER}"
ln -sf "${WRAPPER}" "${SYMLINK}"
chmod 0755 "${SYMLINK}"

command -v scalyr >/dev/null 2>&1 || die "scalyr not on PATH after symlink (${SYMLINK})"

# ---------- step 8: systemd + firewall ----------
step 8 "Writing systemd unit + enabling service (and opening firewall ports if firewalld is active)..."

cat > /etc/systemd/system/scalyr-agent-2.service <<'INI'
[Unit]
Description=Scalyr Agent 2 (venv wrapper)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking

# Optional: load env file (wrapper also loads it; redundancy is fine)
EnvironmentFile=-/etc/scalyr-agent-2/scalyr.env

ExecStart=/opt/scalyr-agent-2/scalyr start
ExecStop=/opt/scalyr-agent-2/scalyr stop
ExecReload=/opt/scalyr-agent-2/scalyr stop && /opt/scalyr-agent-2/scalyr start

# Helpful: dump verbose status into journal right after starting
ExecStartPost=/opt/scalyr-agent-2/scalyr status -v

Restart=on-failure
RestartSec=5s

User=root
Group=root

[Install]
WantedBy=multi-user.target
INI

systemctl daemon-reload
systemctl enable --now scalyr-agent-2 >/dev/null

# Open ports 514/tcp+udp only if firewalld is running.
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port=514/tcp >/dev/null || true
  firewall-cmd --permanent --add-port=514/udp >/dev/null || true
  firewall-cmd --reload >/dev/null || true
fi

# ---------- step 9: tests ----------
step 9 "Running local syslog tests (UDP + TCP) using nc..."

echo "Note: You should see one event per protocol (UDP and TCP)."
echo

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

udp_msg="<189>1 ${ts} nc-local FortiGate-40F-SVA - - - msg=\"local udp test\""
tcp_msg="<189>1 ${ts} nc-local FortiGate-40F-SVA - - - msg=\"local tcp test\""

echo "Test 1/2: UDP -> 127.0.0.1:514"
echo "${udp_msg}"
printf "%s\n" "${udp_msg}" | nc -u -v 127.0.0.1 514 || true
echo

echo "Test 2/2: TCP -> 127.0.0.1:514"
echo "${tcp_msg}"
printf "%s\n" "${tcp_msg}" | nc -v 127.0.0.1 514 || true
echo

echo "Done ✅"
echo
echo "Key paths:"
echo "  Config:   ${CFG}"
echo "  Env file: ${ENVFILE}"
echo "  Wrapper:  ${WRAPPER}"
echo
echo "Common commands:"
echo "  sudo scalyr start"
echo "  sudo scalyr stop"
echo "  sudo scalyr status -v"
echo
echo "If you edited ${ENVFILE}, restart to apply:"
echo "  sudo systemctl restart scalyr-agent-2"
echo
echo "Find your test events in SDL:"
echo "  1) Give it 60+ seconds"
echo "  2) Go to Search"
echo "  3) Choose XDR view"
echo "  4) Search:"
echo "       logfile = '/etc/scalyr-agent-2/log/fortigate.log'"
echo "  5) Time range: Last 10 minutes"
echo "  6) If empty, switch view to All Data"
echo
