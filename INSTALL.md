# Scalyr Agent 2 (SentinelOne DataSet) install from scratch (Rocky Linux 9)

Installs **scalyr-agent-2** into a Python **venv** under `/opt`, with config + state + logs under **`/etc/scalyr-agent-2/`** (matching your working layout).

This revision uses a **single `scalyr` control wrapper** that:

- always uses `-c /etc/scalyr-agent-2/agent.json`
- always suppresses the `pkg_resources` deprecation warning
- supports `scalyr start`, `scalyr stop`, `scalyr status -v`
- is used by **systemd** (full path) and humans (via `$PATH`)
- avoids the annoying “already started” style message by treating start/stop as idempotent

---

## 0) Prep (Rocky 9)

```bash
sudo dnf -y update

# Practical deps:
# - git: required because pip installs from a Git tag (pip shells out to git)
# - build tooling: compile wheels if needed on your platform
# - nmap-ncat: provides `nc` on Rocky/RHEL
sudo dnf -y install \
  python3 python3-pip git \
  gcc make python3-devel \
  openssl-devel libffi-devel \
  nmap-ncat tcpdump
```

Quick sanity (avoids “Cannot find command 'git'” surprises):

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

## 3) Sanity check the agent can run

```bash
sudo /opt/scalyr-agent-2/venv/bin/python -m scalyr_agent.agent_main --help
```

---

## 4) Create your main config (`/etc/scalyr-agent-2/agent.json`)

Put your real API key in `api_key`.

```bash
sudo tee /etc/scalyr-agent-2/agent.json >/dev/null <<'JSON'
{
  "api_key": "keytokensecret",
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

## 5) Create the `scalyr` control wrapper (no `.sh`)

This wrapper bakes in:

- config path (`-c /etc/scalyr-agent-2/agent.json`)
- warning suppression (`PYTHONWARNINGS=...`)
- idempotent `start` / `stop` (quiet when already started / already stopped)

```bash
sudo tee /opt/scalyr-agent-2/scalyr >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG="/etc/scalyr-agent-2/agent.json"
PY="/opt/scalyr-agent-2/venv/bin/python"
PIDFILE="/etc/scalyr-agent-2/log/agent.pid"

# Suppress the noisy warning:
# /.../repoze/__init__.py: UserWarning: pkg_resources is deprecated as an API...
export PYTHONWARNINGS='ignore:pkg_resources is deprecated as an API:UserWarning'

is_running() {
  [ -f "$PIDFILE" ] || return 1
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  [ -n "${pid:-}" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

cmd="${1:-}"
shift || true

case "$cmd" in
  start)
    if is_running; then exit 0; fi
    exec "$PY" -m scalyr_agent.agent_main -c "$CONFIG" start
    ;;
  stop)
    if ! is_running; then exit 0; fi
    exec "$PY" -m scalyr_agent.agent_main -c "$CONFIG" stop
    ;;
  status)
    exec "$PY" -m scalyr_agent.agent_main -c "$CONFIG" status "$@"
    ;;
  *)
    exec "$PY" -m scalyr_agent.agent_main -c "$CONFIG" "$cmd" "$@"
    ;;
esac
EOF
```

Set permissions:

```bash
sudo chmod 0755 /opt/scalyr-agent-2/scalyr
```

### Put it on PATH (works for `sudo` too)

On Rocky/RHEL, `sudo` often uses a restricted PATH (“secure*path”), which may **not** include `/usr/local/bin`.
So we symlink into `/usr/bin` so both humans \_and* `sudo` can always find it:

```bash
sudo ln -sf /opt/scalyr-agent-2/scalyr /usr/bin/scalyr
sudo chmod 0755 /opt/scalyr-agent-2/scalyr /usr/bin/scalyr

command -v scalyr
sudo command -v scalyr
```

Quick test:

```bash
sudo scalyr status -v || true
```

---

## 6) Open the syslog ports (if using firewalld)

If this host should accept remote syslog on 514:

```bash
sudo firewall-cmd --permanent --add-port=514/tcp
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --reload
```

---

## 7) systemd service (uses the wrapper)

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

ExecStart=/opt/scalyr-agent-2/scalyr start
ExecStop=/opt/scalyr-agent-2/scalyr stop

# Optional but handy: write the verbose status into the journal after start
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

---

## 8) Validate it’s actually working (includes `nc` tests)

### A) Service state + verbose agent status

```bash
sudo systemctl status scalyr-agent-2 --no-pager -l
sudo scalyr status -v
```

### B) Confirm it is listening on 514 TCP/UDP

```bash
sudo ss -luntp | egrep ':(514)\b'
```

### C) Send test syslog messages with netcat (`nc`)

Replace `localhost` with the IP/hostname running the agent as needed.

**TCP 514:**

```bash
printf '<189>1 2025-12-16T00:00:00Z nc-test FortiGate-40F-SVA - - - date=2025-12-16 time=00:00:00 logid=0000000000 type=event subtype=system level=information msg="nc tcp test"\n' \
  | nc -v localhost 514
```

**UDP 514:**

```bash
printf '<189>1 2025-12-16T00:00:00Z nc-test FortiGate-40F-SVA - - - date=2025-12-16 time=00:00:00 logid=0000000000 type=event subtype=system level=information msg="nc udp test"\n' \
  | nc -u -v localhost 514
```

### D) Watch logs while you send the tests

```bash
sudo tail -n 200 -f /etc/scalyr-agent-2/log/agent.log
sudo tail -n 200 -f /etc/scalyr-agent-2/log/fortigate.log
```

---

## Troubleshooting notes (common gotchas)

### “ERROR: Cannot find command 'git'”

You’re installing from a Git tag, so pip shells out to `git`. Fix:

```bash
sudo dnf -y install git
command -v git
git --version
```

### `sudo: scalyr: command not found`

That’s `sudo` secure_path. Fix by symlinking into `/usr/bin`:

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

### Config edits not taking effect

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

