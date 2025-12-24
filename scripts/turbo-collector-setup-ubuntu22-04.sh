#!/usr/bin/env bash
# Ubuntu 22.04 installer for SentinelOne Collector (Scalyr Agent 2)
# Author: Steve VanAllen
# Last Updated: 12-24-25

set -euo pipefail

# Scalyr Agent 2 (SentinelOne Collector) installer for Ubuntu 22.04.x LTS (Jammy)
# - Installs scalyr-agent-2 into /opt/scalyr-agent-2/venv
# - Writes config/state/logs under /etc/scalyr-agent-2/
# - Uses /opt/scalyr-agent-2/scalyr wrapper (loads /etc/scalyr-agent-2/scalyr.env)
# - Installs a symlink to /usr/bin/scalyr so `sudo scalyr ...` works with sudo secure_path

N_STEPS=10

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

prompt_yn() {
  local prompt="$1"
  local def="${2:-N}"
  local ans=""
  read -r -p "${prompt} [y/N]: " ans
  ans="${ans:-$def}"
  [[ "${ans}" =~ ^[Yy]$ ]]
}

need_root

# ---------- OS guard (Ubuntu 22.04.x only) ----------
[[ -r /etc/os-release ]] || die "/etc/os-release not found"
# shellcheck disable=SC1091
. /etc/os-release

if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
  die "Unsupported OS: ID='${ID:-}' VERSION_ID='${VERSION_ID:-}' VERSION='${VERSION:-}' (expected Ubuntu 22.04.x)"
fi

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

UNIT_ETC="/etc/systemd/system/scalyr-agent-2.service"
UNIT_LIB="/lib/systemd/system/scalyr-agent-2.service"
LOGROTATE="/etc/logrotate.d/scalyr-agent-2"

CA_CERT_PATH="/etc/ssl/certs/ca-certificates.crt"

# Suppress pip "new release available" noise
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'
export DEBIAN_FRONTEND=noninteractive

PRUNE_FAILED=0

# ---------- jq mask for account.id (keep last 4) ----------
JQ_MASK_ACCOUNT_ID='
def m:
  tostring as $t
  | ($t|length) as $n
  | if $n <= 4 then $t else ("x"*($n-4)) + ($t[-4:]) end;
.sessions |= with_entries(
  .value |= (
    if has("account.id") then .["account.id"] = (.["account.id"] | m) else . end
  )
)
'

# ---------- helpers ----------
show_514_listeners() {
  if command_exists ss; then
    ss -luntp 2>/dev/null | grep -E ':(514)\b' || true
  elif command_exists netstat; then
    netstat -luntp 2>/dev/null | grep -E ':(514)\b' || true
  else
    return 0
  fi
}

preflight_check_514() {
  local out=""
  out="$(show_514_listeners || true)"
  if [[ -n "${out}" ]]; then
    echo
    echo "${BOLD}Preflight warning:${RESET} something is already using port 514 (UDP/TCP):"
    echo "${out}"
    echo
    echo "If another service owns :514, scalyr-agent-2 may fail to start/bind."
    echo
    if ! prompt_yn "Continue anyway?" "N"; then
      die "Aborting: port 514 is already in use."
    fi
  else
    echo "Preflight: port 514 looks free (no listeners detected)."
  fi
}

post_start_check_514() {
  local out=""
  sleep 1
  out="$(show_514_listeners || true)"
  if [[ -z "${out}" ]]; then
    echo
    echo "WARN: No listeners detected on :514 after starting scalyr-agent-2."
    echo "WARN: This usually means bind failed (port conflict, permissions, or service crash)."
    echo
    echo "Service status:"
    systemctl --no-pager -l status scalyr-agent-2 || true
    echo
    echo "Listeners:"
    show_514_listeners || true
    echo
    die "scalyr-agent-2 does not appear to be listening on :514."
  fi

  echo
  echo "Verified listeners on :514:"
  echo "${out}"
  echo
}

ensure_ufw_514() {
  if command_exists ufw; then
    if ufw status 2>/dev/null | grep -qi '^Status:\s*active'; then
      ufw allow 514/tcp >/dev/null || true
      ufw allow 514/udp >/dev/null || true

      echo
      echo "UFW is active. Ensured allow rules exist for 514/tcp and 514/udp."
      echo "UFW rules (filtered):"
      ufw status 2>/dev/null | grep -E '(^Status:|514/(tcp|udp))' || true
      echo
    else
      echo "UFW is installed but not active; no firewall rules applied."
    fi
  else
    echo "UFW not installed; no firewall rules applied (Ubuntu firewall is typically ufw; AppArmor is not a firewall)."
  fi
}

safe_rm() {
  local p="$1"
  [[ -n "$p" ]] || return 0
  [[ -e "$p" || -L "$p" ]] || return 0

  if command_exists mountpoint; then
    if mountpoint -q "$p" 2>/dev/null; then
      echo "WARN: '${p}' is a mountpoint. Unmount first (example): umount -l '${p}'" >&2
      PRUNE_FAILED=1
      return 0
    fi
  fi

  if command_exists lsattr; then
    if lsattr -d "$p" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      echo "WARN: '${p}' appears immutable (chattr +i). Clear it first: chattr -i '${p}'" >&2
      PRUNE_FAILED=1
      return 0
    fi
  fi

  local err=""
  err="$(rm -rf -- "$p" 2>&1)" || true

  if [[ -e "$p" || -L "$p" ]]; then
    echo "WARN: Failed to remove '${p}'" >&2
    [[ -n "${err}" ]] && echo "WARN: rm said: ${err}" >&2
    echo "WARN: perms: $(ls -ld "$p" 2>/dev/null || true)" >&2
    PRUNE_FAILED=1
  fi
}

detect_existing_install() {
  local found=0
  local notes=()

  if [[ -d "${BASE_ETC}" ]]; then found=1; notes+=("Found directory: ${BASE_ETC}"); fi
  if [[ -d "${BASE_OPT}" ]]; then found=1; notes+=("Found directory: ${BASE_OPT}"); fi
  if [[ -f "${UNIT_ETC}" ]]; then found=1; notes+=("Found systemd unit: ${UNIT_ETC}"); fi
  if [[ -f "${UNIT_LIB}" ]]; then found=1; notes+=("Found systemd unit: ${UNIT_LIB}"); fi

  if [[ -L "${SYMLINK}" ]]; then
    found=1
    notes+=("Found symlink: ${SYMLINK} -> $(readlink -f "${SYMLINK}" 2>/dev/null || readlink "${SYMLINK}" || echo '?')")
  elif [[ -e "${SYMLINK}" ]]; then
    found=1
    notes+=("Found file (not symlink): ${SYMLINK}")
  fi

  if command_exists systemctl; then
    if systemctl is-enabled scalyr-agent-2 >/dev/null 2>&1; then found=1; notes+=("systemd: scalyr-agent-2 is enabled"); fi
    if systemctl is-active scalyr-agent-2 >/dev/null 2>&1; then found=1; notes+=("systemd: scalyr-agent-2 is active (running)"); fi
  fi

  if pgrep -f 'scalyr_agent\.agent_main' >/dev/null 2>&1; then
    found=1
    notes+=("Process detected: scalyr_agent.agent_main")
  elif pgrep -f 'scalyr_agent' >/dev/null 2>&1; then
    found=1
    notes+=("Process detected: scalyr_agent (generic match)")
  fi

  if command_exists dpkg-query; then
    if dpkg-query -W -f='${Status}' scalyr-agent-2 2>/dev/null | grep -q "install ok installed"; then
      found=1
      notes+=("dpkg: scalyr-agent-2 package is installed")
    fi
  fi

  if (( found )); then
    printf "%s\n" "${notes[@]}"
    return 0
  fi
  return 1
}

prune_existing_install() {
  echo
  echo "${BOLD}Pruning existing scalyr-agent-2 install/remnants...${RESET}"

  set +e

  if command_exists systemctl; then
    systemctl stop scalyr-agent-2 >/dev/null 2>&1 || true
    systemctl disable scalyr-agent-2 >/dev/null 2>&1 || true
  fi

  pkill -f 'scalyr_agent\.agent_main' >/dev/null 2>&1 || true
  pkill -f 'scalyr_agent' >/dev/null 2>&1 || true

  safe_rm "${UNIT_ETC}"
  safe_rm "${UNIT_LIB}"

  if command_exists systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed scalyr-agent-2 >/dev/null 2>&1 || true
  fi

  safe_rm "${BASE_ETC}"
  safe_rm "${BASE_OPT}"
  safe_rm "${LOGROTATE}"

  if [[ -L "${SYMLINK}" ]]; then
    tgt="$(readlink -f "${SYMLINK}" 2>/dev/null || true)"
    if [[ "${tgt}" == "${WRAPPER}" || "${tgt}" == "${BASE_OPT}"/* ]]; then
      safe_rm "${SYMLINK}"
    fi
  fi

  if command_exists dpkg-query; then
    if dpkg-query -W -f='${Status}' scalyr-agent-2 2>/dev/null | grep -q "install ok installed"; then
      apt-get remove -y --purge scalyr-agent-2 >/dev/null 2>&1 || true
      apt-get autoremove -y >/dev/null 2>&1 || true
    fi
  fi

  set -e
  echo "Prune attempt complete."
}

print_query_sudo_example() {
  # Bright cyan box so users can clearly see where the copy/paste starts & ends.
  local CYAN=$'\033[96m'
  local YELLOW=$'\033[93m'
  local RESET=$'\033[0m'
  local BOLD=$'\033[1m'

  echo "${CYAN}${BOLD}==================== COPY/PASTE START ====================${RESET}"
  echo "${YELLOW}${BOLD}(Copy everything between START and END as one block)${RESET}"
  echo

  cat <<'EOF'
sudo bash -lc '
set -euo pipefail
source /etc/scalyr-agent-2/scalyr.env
srv="$(printf %s "$SCALYR_SERVER" | tr -d "\r")"
key="$(printf %s "${SCALYR_READ_API_KEY:-$SCALYR_API_KEY}" | tr -d "\r")"
jqf="$(mktemp)"
cat > "$jqf" <<'"'"'JQ'"'"'
def m:
  tostring as $t
  | ($t|length) as $n
  | if $n <= 4 then $t else ("x"*($n-4)) + ($t[-4:]) end;
.sessions |= with_entries(
  .value |= (
    if has("account.id") then .["account.id"] = (.["account.id"] | m) else . end
  )
)
JQ
cat <<JSON | curl -sS -X POST "${srv%/}/api/query" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${key}" \
  --data-binary @- | jq -f "$jqf"
{
  "queryType": "log",
  "filter": "logfile = \"/etc/scalyr-agent-2/log/fortigate.log\"",
  "startTime": "5M",
  "endTime": "0H",
  "maxCount": 5
}
JSON
rm -f "$jqf"
echo
'
EOF

  echo
  echo "${CYAN}${BOLD}===================== COPY/PASTE END =====================${RESET}"
  echo
}


poll_query_until_matches() {
  local server="${1:-}"
  local key="${2:-}"

  echo "${BOLD}Optional verification:${RESET} polling SDL query API until we see matches."
  echo "First wait: 30 seconds (pipeline warm-up). Then retry every 5 seconds."
  echo "Press Ctrl+C to stop polling at any time."
  echo

  sleep 30

  local srv key_clean out rc status mcount
  srv="$(printf %s "$server" | tr -d '\r')"
  key_clean="$(printf %s "$key" | tr -d '\r')"

  while true; do
    set +e
    out="$(
      cat <<JSON | curl -sS -X POST "${srv%/}/api/query" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "Authorization: Bearer ${key_clean}" \
        --data-binary @-
{
  "queryType": "log",
  "filter": "logfile = \"/etc/scalyr-agent-2/log/fortigate.log\"",
  "startTime": "5M",
  "endTime": "0H",
  "maxCount": 5
}
JSON
    )"
    rc=$?
    set -e

    if [[ $rc -ne 0 ]]; then
      echo "Query failed (curl rc=${rc}). Retrying in 5s..."
      sleep 5
      continue
    fi

    status="$(printf %s "$out" | jq -r '.status // empty' 2>/dev/null || true)"
    mcount="$(printf %s "$out" | jq -r '.matches | length' 2>/dev/null || echo 0)"

    if [[ "$status" == "error/client/badParam" || "$status" == "error" ]]; then
      echo "Query returned an error response:"
      printf %s "$out" | jq .
      echo
      echo "Tip: confirm SCALYR_SERVER and SCALYR_READ_API_KEY (or SCALYR_API_KEY) in ${ENVFILE}"
      echo
      break
    fi

    if [[ "$status" == "success" ]]; then
      if [[ "${mcount}" -gt 0 ]]; then
        echo "Query response (matches found):"
        printf %s "$out" | jq "${JQ_MASK_ACCOUNT_ID}"
        echo
        echo "Looks good ✅"
        echo
        break
      fi

      echo "API reachable + key valid, but no matches yet (matches: []). Retrying in 5s..."
      sleep 5
      continue
    fi

    echo "Unexpected response (retrying in 5s):"
    printf %s "$out" | jq "${JQ_MASK_ACCOUNT_ID}" 2>/dev/null || printf %s "$out"
    echo
    sleep 5
  done
}

# ---------- step 1: preflight + prerequisites ----------
step 1 "Preflight: installing tools needed for checks + checking for existing install..."

apt-get update -y >/dev/null
apt-get install -y \
  ca-certificates \
  iproute2 \
  util-linux \
  e2fsprogs \
  lsof \
  ufw \
  >/dev/null

command_exists ss || die "ss missing (apt install iproute2 failed?)"
command_exists mountpoint || die "mountpoint missing (apt install util-linux failed?)"
command_exists lsattr || die "lsattr missing (apt install e2fsprogs failed?)"
command_exists lsof || die "lsof missing (apt install lsof failed?)"

if detect_existing_install >/tmp/scalyr_agent_existing.$$ 2>/dev/null; then
  echo
  echo "${BOLD}Detected existing scalyr-agent-2 install/remnants:${RESET}"
  cat /tmp/scalyr_agent_existing.$$ || true
  rm -f /tmp/scalyr_agent_existing.$$ || true
  echo
  echo "Cleanup is recommended to avoid conflicts (service collisions, old files, broken venv, etc.)."
  echo

  if prompt_yn "Prune the existing install/remnants and continue with a fresh install?" "N"; then
    PRUNE_FAILED=0
    prune_existing_install

    if [[ "${PRUNE_FAILED}" -ne 0 || -d "${BASE_ETC}" || -d "${BASE_OPT}" ]]; then
      echo
      echo "Cleanup did not fully complete."
      [[ -d "${BASE_ETC}" ]] && echo "  Still exists: ${BASE_ETC}"
      [[ -d "${BASE_OPT}" ]] && echo "  Still exists: ${BASE_OPT}"
      echo
      echo "Common causes:"
      echo "  - Mountpoint:   mountpoint '${BASE_ETC}'  OR  mountpoint '${BASE_OPT}'"
      echo "  - Immutable:    lsattr -d '${BASE_ETC}' '${BASE_OPT}'"
      echo "  - Busy handles: lsof +D '${BASE_ETC}'  (or +D '${BASE_OPT}')"
      echo
      die "Fix the above and re-run. Refusing to continue into a half-clean state."
    fi

    echo
    echo "Cleanup OK. Continuing with install..."
  else
    echo
    echo "If we do not clean up remnants, this install might fail or behave unpredictably."
    if prompt_yn "Stop now so you can clean up manually?" "Y"; then
      die "Aborting per user choice."
    fi
    echo "Continuing without cleanup (at your risk)..."
  fi
else
  rm -f /tmp/scalyr_agent_existing.$$ >/dev/null 2>&1 || true
  echo "No existing install detected."
fi

preflight_check_514
ensure_ufw_514

# ---------- step 2: packages ----------
step 2 "Installing OS packages via apt (git, python, build deps, nc, tcpdump, jq)..."

apt-get install -y \
  python3 python3-pip python3-venv \
  git \
  build-essential python3-dev \
  libssl-dev libffi-dev \
  netcat-openbsd tcpdump \
  jq \
  >/dev/null

command_exists git || die "git missing (apt install git failed?)"
command_exists nc  || die "nc missing (apt install netcat-openbsd failed?)"
command_exists jq  || die "jq missing (apt install jq failed?)"

# ---------- step 3: directories ----------
step 3 "Creating directories under ${BASE_ETC} and ${BASE_OPT}..."

mkdir -p "${BASE_ETC}/agent.d" "${DATADIR}" "${LOGDIR}"
chmod 755 "${BASE_ETC}"
chown -R root:root "${BASE_ETC}"

mkdir -p "${BASE_OPT}"
chmod 755 "${BASE_OPT}"
chown -R root:root "${BASE_OPT}"

# ---------- step 4: venv + install ----------
step 4 "Creating venv + installing scalyr-agent-2 from Git tag ${TAG}..."

if [[ ! -x "${PY}" ]]; then
  python3 -m venv "${VENV}"
fi

"${PIP}" --disable-pip-version-check install -q --upgrade pip setuptools wheel >/dev/null 2>&1

# Installing from Git tag requires git on PATH (already installed above).
"${PIP}" --disable-pip-version-check install -q "git+https://github.com/scalyr/scalyr-agent-2.git@${TAG}" >/dev/null 2>&1

# Quiet sanity check: validate import (no agent config needed).
step 5 "Sanity check: Python import (quiet)..."
"${PY}" -c "import scalyr_agent; import scalyr_agent.agent_main; print('ok')" >/dev/null

# ---------- step 6: region + API keys (prompt) ----------
step 6 "Collecting region + API keys (writes ${ENVFILE})..."

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
  6) read -r -p "Enter custom SCALYR_SERVER (https://...): " SCALYR_SERVER ;;
  *) echo "Invalid choice '${REGION_CHOICE}', using default US1." >&2
     SCALYR_SERVER="https://xdr.us1.sentinelone.net" ;;
esac

if [[ -f "${ENVFILE}" ]]; then
  echo
  read -r -p "Found existing ${ENVFILE}. Keep it as-is? [y/N]: " KEEP_ENV
  KEEP_ENV="${KEEP_ENV:-N}"
  if [[ "${KEEP_ENV}" =~ ^[Yy]$ ]]; then
    echo "Keeping existing ${ENVFILE}."
    chmod 600 "${ENVFILE}"
    chown root:root "${ENVFILE}"
  else
    rm -f "${ENVFILE}"
  fi
fi

SCALYR_API_KEY=""
SCALYR_READ_API_KEY=""

if [[ ! -f "${ENVFILE}" ]]; then
  echo
  echo "Get your keys from: https://community.sentinelone.com/s/article/000006763"
  echo "  1) Log into your Singularity Data Lake console"
  echo "  2) Navigate to Settings > API Keys"
  echo "  3) Generate a \"Log Access Write\" key (required)"
  echo "  4) (Optional) Generate a \"Log Access Read\" key for automated verification at the end"
  echo

  read -r -s -p "Enter SCALYR_API_KEY (WRITE key, hidden input, press Enter to skip for now): " SCALYR_API_KEY
  echo
  if [[ -z "${SCALYR_API_KEY}" ]]; then
    SCALYR_API_KEY="REPLACE_ME"
  fi

  echo
  echo "Optional: provide a READ key to let this script poll the API at the end until test events appear."
  read -r -s -p "Enter SCALYR_READ_API_KEY (READ key, hidden input, press Enter to skip): " SCALYR_READ_API_KEY
  echo

  cat > "${ENVFILE}" <<EOF
SCALYR_API_KEY="${SCALYR_API_KEY}"
SCALYR_SERVER="${SCALYR_SERVER}"
EOF

  if [[ -n "${SCALYR_READ_API_KEY}" ]]; then
    cat >> "${ENVFILE}" <<EOF
SCALYR_READ_API_KEY="${SCALYR_READ_API_KEY}"
EOF
  fi

  chmod 600 "${ENVFILE}"
  chown root:root "${ENVFILE}"
  unset SCALYR_API_KEY
  unset SCALYR_READ_API_KEY
fi

if [[ -f "${ENVFILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENVFILE}"
  set +a
fi

# ---------- step 7: agent.json ----------
step 7 "Writing ${CFG} (API key is read from ${ENVFILE})..."

cat > "${CFG}" <<JSON
{
  "ca_cert_path": "${CA_CERT_PATH}",
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

# ---------- step 8: wrapper + PATH ----------
step 8 "Writing wrapper ${WRAPPER} and enabling /usr/bin/scalyr..."

cat > "${WRAPPER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CONFIG="/etc/scalyr-agent-2/agent.json"
ENVFILE="/etc/scalyr-agent-2/scalyr.env"
PY="/opt/scalyr-agent-2/venv/bin/python"
if [[ -f "$ENVFILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENVFILE"
  set +a
fi
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'
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

# ---------- step 9: systemd + firewall ----------
step 9 "Writing systemd unit + enabling service (and opening firewall ports if ufw is active)..."

cat > /etc/systemd/system/scalyr-agent-2.service <<'INI'
[Unit]
Description=Scalyr Agent 2 (venv wrapper)
After=network-online.target
Wants=network-online.target
[Service]
Type=forking
EnvironmentFile=-/etc/scalyr-agent-2/scalyr.env
ExecStart=/opt/scalyr-agent-2/scalyr start
ExecStop=/opt/scalyr-agent-2/scalyr stop
ExecReload=/opt/scalyr-agent-2/scalyr stop && /opt/scalyr-agent-2/scalyr start
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

ensure_ufw_514
post_start_check_514

# ---------- step 10: tests ----------
step 10 "Running local syslog tests (UDP + TCP) using nc..."

echo "Note: You should see one event per protocol (UDP and TCP)."
echo

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

udp_msg="<189>1 ${ts} nc-local FortiGate-40F-SVA - - - msg=\"local udp test\""
tcp_msg="<189>1 ${ts} nc-local FortiGate-40F-SVA - - - msg=\"local tcp test\""

echo "Test 1/2: UDP -> 127.0.0.1:514"
echo "${udp_msg}"
printf "%s\n" "${udp_msg}" | nc -u -v -w1 127.0.0.1 514 || true
echo

echo "Test 2/2: TCP -> 127.0.0.1:514"
echo "${tcp_msg}"
printf "%s\n" "${tcp_msg}" | nc -v -w1 127.0.0.1 514 || true
echo

if [[ -n "${SCALYR_READ_API_KEY:-}" ]]; then
  poll_query_until_matches "${SCALYR_SERVER:-}" "${SCALYR_READ_API_KEY:-}"
else
  echo "Skipping API verification (no SCALYR_READ_API_KEY provided)."
  echo
fi

echo "Done ✅"
echo

echo "If you would like to query SDL again yourself:"
echo
echo "${BOLD}Example (copy/paste):${RESET}"
print_query_sudo_example

echo "Or if you would like to locate these events in the UI:"
echo
echo "Find your test events in SDL UI:"
echo "  1) Go to Search"
echo "  2) Choose XDR view"
echo "  3) Search:"
echo "       logfile = '/etc/scalyr-agent-2/log/fortigate.log'"
echo "  4) Time range: Last 10 minutes"
echo "  5) If empty, switch view to All Data"
echo

echo "Summary"
echo
echo "This host's IPv4 address(es): $(hostname -I | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' || true)"
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

