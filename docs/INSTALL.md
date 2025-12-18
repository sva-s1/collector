# Scalyr Agent 2 (SentinelOne Collector) install from scratch (Rocky Linux 9)

Installs **scalyr-agent-2** into a Python **venv** under `/opt`, with config + state + logs under **`/etc/scalyr-agent-2/`** (matching your working layout).

This revision uses a **single `scalyr` control wrapper** that:

- always uses `-c /etc/scalyr-agent-2/agent.json`
- always suppresses the `pkg_resources` deprecation warning
- supports `scalyr start`, `scalyr stop`, `scalyr status -v`
- is used by **systemd** (full path) and humans (via `$PATH`)
- lets you keep the **API key out of `agent.json`** by reading it from an env file

> [!TIP]
> Want the TLDR? Run the **TURBO installer**:
>
> ```bash
> sudo dnf -y install curl ca-certificates >/dev/null && curl -fsSL -L "https://gist.githubusercontent.com/sva-s1/de9927ea3429fa800318860a0d32c4a9/raw/turbo-collector-setup.sh" -o /tmp/turbo-collector-setup.sh && sudo bash /tmp/turbo-collector-setup.sh
> ```

---

## 0) Prep (Rocky 9)

```bash
sudo dnf -y update

# Practical deps:
# - git: required because pip installs from a Git tag (pip shells out to git)
# - build tooling: compile wheels if needed on your platform
# - nmap-ncat: provides `nc` for the tests
sudo dnf -y install \
  python3 python3-pip git \
  gcc make python3-devel \
  openssl-devel libffi-devel \
  nmap-ncat tcpdump
```

Quick sanity (avoids the “Cannot find command 'git'” surprise):

```bash
command -v git
git --version

command -v nc
nc -h | head -n 1 || true
```

---

## 1) Create directories (match the agent.json paths)

This matches:

- `agent_log_path`: `/etc/scalyr-agent-2/log`
- `agent_data_path`: `/etc/scalyr-agent-2/data`

```bash
sudo mkdir -p /etc/scalyr-agent-2/{agent.d,data,log}
sudo chown -R root:root /etc/scalyr-agent-2
sudo chmod 755 /etc/scalyr-agent-2
```

Create the `/opt` home for the venv + wrapper:

```bash
sudo mkdir -p /opt/scalyr-agent-2
sudo chown -R root:root /opt/scalyr-agent-2
sudo chmod 755 /opt/scalyr-agent-2
```

---

## 2) Create a dedicated venv + install from the GitHub release tag

```bash
sudo python3 -m venv /opt/scalyr-agent-2/venv

sudo /opt/scalyr-agent-2/venv/bin/pip install --upgrade pip setuptools wheel

# Install from tag
sudo /opt/scalyr-agent-2/venv/bin/pip install \
  "git+https://github.com/scalyr/scalyr-agent-2.git@v2.2.19"
```

---

## 3) Sanity check (quiet, no warning)

The noisy `pkg_resources` deprecation warning shows up when running the agent CLI directly.
So at this stage we do a simple **import-only** sanity check.

```bash
sudo /opt/scalyr-agent-2/venv/bin/python -c "import scalyr_agent; print('scalyr_agent import: OK')"
```

We’ll run the real `scalyr status -v` check **after** the wrapper exists (the wrapper suppresses the warning).

---

## 4) Put secrets in an env file (recommended)

Create `/etc/scalyr-agent-2/scalyr.env` (root-only). This keeps the key out of `agent.json`.

```bash
sudo tee /etc/scalyr-agent-2/scalyr.env >/dev/null <<'ENV'
# Required (this is your "Log Access Write" API key)
#
# Get your key from: https://community.sentinelone.com/s/article/000006763
# 1) Log into your Singularity Data Lake console
# 2) Navigate to Settings > API Keys
# 3) Generate a "Log Access Write" key
# 4) Paste it below
SCALYR_API_KEY="REPLACE_ME"

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
#
# Optional: set server via env instead of JSON:
# SCALYR_SERVER="https://xdr.us1.sentinelone.net"
ENV

sudo chmod 600 /etc/scalyr-agent-2/scalyr.env
sudo chown root:root /etc/scalyr-agent-2/scalyr.env
```

Load it for your current shell (optional, for immediate testing):

```bash
set -a
source /etc/scalyr-agent-2/scalyr.env
set +a
```

---

## 5) Create your main config (`/etc/scalyr-agent-2/agent.json`)

Important: **omit** `api_key` here if you want the env var to be used.

```bash
sudo tee /etc/scalyr-agent-2/agent.json >/dev/null <<'JSON'
{
  "ca_cert_path": "/etc/ssl/certs/ca-bundle.crt",
  "scalyr_server": "https://xdr.us1.sentinelone.net",
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
```

Lock it down:

```bash
sudo chmod 600 /etc/scalyr-agent-2/agent.json
sudo chown root:root /etc/scalyr-agent-2/agent.json
```

---

## 6) Create the `scalyr` control wrapper (no `.sh`)

This wrapper bakes in:

- the config path (`-c /etc/scalyr-agent-2/agent.json`)
- warning suppression (`PYTHONWARNINGS=...`)
- loads `/etc/scalyr-agent-2/scalyr.env` so humans + systemd behave the same

```bash
sudo tee /opt/scalyr-agent-2/scalyr >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG="/etc/scalyr-agent-2/agent.json"
ENVFILE="/etc/scalyr-agent-2/scalyr.env"
PY="/opt/scalyr-agent-2/venv/bin/python"

# Load secrets if present (SCALYR_API_KEY, optionally SCALYR_SERVER, etc.)
if [[ -f "$ENVFILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENVFILE"
  set +a
fi

# Suppress the noisy warning:
# /.../repoze/__init__.py: UserWarning: pkg_resources is deprecated as an API...
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'

# Optional: quiet "already running" noise on `start`
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

sudo chmod 0755 /opt/scalyr-agent-2/scalyr
```

### Put it on PATH for humans (and make `sudo scalyr ...` work)

On Rocky, `sudo` often uses a restricted `secure_path` which may **not** include `/usr/local/bin`. The simplest fix is to symlink into `/usr/bin`.

```bash
sudo ln -sf /opt/scalyr-agent-2/scalyr /usr/bin/scalyr
sudo chmod 0755 /opt/scalyr-agent-2/scalyr /usr/bin/scalyr

command -v scalyr
sudo command -v scalyr
```

Now we can do the **real** sanity check without the warning:

```bash
sudo scalyr status -v || true
```

---

## 7) Open the syslog ports (if using firewalld)

If this host should accept remote syslog on 514:

```bash
sudo firewall-cmd --permanent --add-port=514/tcp
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --reload
```

---

## 8) systemd service (uses the wrapper)

Create:

`/etc/systemd/system/scalyr-agent-2.service`

```bash
sudo tee /etc/systemd/system/scalyr-agent-2.service >/dev/null <<'INI'
[Unit]
Description=Scalyr Agent 2 (venv wrapper)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking

# Wrapper already loads /etc/scalyr-agent-2/scalyr.env, but systemd can too (harmless redundancy)
EnvironmentFile=-/etc/scalyr-agent-2/scalyr.env

ExecStart=/opt/scalyr-agent-2/scalyr start
ExecStop=/opt/scalyr-agent-2/scalyr stop
ExecReload=/opt/scalyr-agent-2/scalyr stop && /opt/scalyr-agent-2/scalyr start

# Helpful: dump verbose agent status into the journal right after starting
ExecStartPost=/opt/scalyr-agent-2/scalyr status -v

Restart=on-failure
RestartSec=5s

User=root
Group=root

[Install]
WantedBy=multi-user.target
INI
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scalyr-agent-2
```

> Note: If you change values in `scalyr.env`, you must restart the service for them to take effect.

---

## 9) Validate it’s actually working (includes `nc` tests)

### A) Service state + verbose agent status

```bash
sudo systemctl status scalyr-agent-2 --no-pager -l
sudo scalyr status -v
```

### B) Confirm it is listening on 514 TCP/UDP

```bash
sudo ss -luntp | egrep ':(514)\b'
```

### C) Send test syslog messages with netcat (the “it just works” tests)

Running the test **on the agent host itself**, using `127.0.0.1`:

**UDP:**

```bash
printf '<189>1 2025-12-17T00:00:00Z nc-local FortiGate-40F-SVA - - - msg="local udp test"\n' \
  | nc -u -v 127.0.0.1 514
```

**TCP:**

```bash
printf '<189>1 2025-12-17T00:00:00Z nc-local FortiGate-40F-SVA - - - msg="local tcp test"\n' \
  | nc -v 127.0.0.1 514
```

### D) Watch logs while you send the tests

```bash
sudo tail -n 200 -f /etc/scalyr-agent-2/log/agent.log
sudo tail -n 200 -f /etc/scalyr-agent-2/log/fortigate.log
```

---

## Find your test events in SDL

1) Give it **60+ seconds**  
2) Go to **Search**  
3) Choose **XDR view**  
4) Search:

```text
logfile = '/etc/scalyr-agent-2/log/fortigate.log'
```

5) Time range: **Last 10 minutes**  
6) If empty, switch view to **All Data**

---

## Troubleshooting notes (common gotchas)

### “ERROR: Cannot find command 'git'”

You’re installing from a Git tag, so pip shells out to `git`. Fix:

```bash
sudo dnf -y install git
command -v git
git --version
```

### `sudo scalyr ...` says command not found

You likely symlinked only into `/usr/local/bin`. Rocky `sudo` can ignore that path. Fix:

```bash
sudo ln -sf /opt/scalyr-agent-2/scalyr /usr/bin/scalyr
sudo command -v scalyr
```

### Nothing arrives in `fortigate.log`

- Confirm firewall is open:
  ```bash
  sudo firewall-cmd --list-ports
  ```
- Confirm the process is listening:
  ```bash
  sudo ss -luntp | grep -E ':(514)\b'
  ```
- Confirm packets are arriving:
  ```bash
  sudo tcpdump -ni any port 514
  ```

### Env var changes not taking effect

Environment-aware variables apply only at startup. Restart:

```bash
sudo systemctl restart scalyr-agent-2
sudo scalyr status -v
```

---

## Handy one-liners

```bash
# Verbose agent status
sudo scalyr status -v

# Restart + immediately show recent logs
sudo systemctl restart scalyr-agent-2 && sudo journalctl -u scalyr-agent-2 -n 200 --no-pager
```
