# Scalyr Agent 2 (SentinelOne Collector) install from scratch (Ubuntu 24.04 LTS)

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
> sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup-ubuntu24-04.sh)"
> ```

---

## 0) Prep (Ubuntu 24.04)

```bash
sudo apt-get update -y

# Practical deps:
# - git: required because pip installs from a Git tag (pip shells out to git)
# - build tooling: compile wheels if needed on your platform
# - netcat-openbsd: provides `nc` for the tests
# - jq: optional but useful for API verification
sudo apt-get install -y \
  python3 python3-pip python3-venv \
  git \
  build-essential python3-dev \
  libssl-dev libffi-dev \
  netcat-openbsd tcpdump \
  jq
```

Quick sanity (avoids the "Cannot find command 'git'" surprise):

```bash
command -v git
git --version

command -v nc
nc -h | head -n 1 || true
```

**Note for Ubuntu 24.04**: This install process intentionally pins `pip==23.3.2` in the venv to address a known compatibility issue with `scalyr-agent-2` and the `six`/`six-moves` dependency. The script applies patches to `pyproject.toml` and `setup.py` to ensure a successful install.

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

**Important for Ubuntu 24.04**: Due to PEP517/six compatibility issues, we need to:

1. Pin pip to version 23.3.2
2. Clone the repo and apply patches to `pyproject.toml` and `setup.py`
3. Install with `--no-use-pep517`

```bash
sudo python3 -m venv /opt/scalyr-agent-2/venv

# Pin pip to avoid compatibility issues
sudo /opt/scalyr-agent-2/venv/bin/pip install --disable-pip-version-check --upgrade "pip==23.3.2" setuptools wheel

# Install six explicitly
sudo /opt/scalyr-agent-2/venv/bin/pip install --disable-pip-version-check six

# Clone, patch, and install
WORKDIR="$(mktemp -d)"
cd "${WORKDIR}"

git clone https://github.com/scalyr/scalyr-agent-2.git scalyr-agent-2
cd scalyr-agent-2
git checkout v2.2.19

# Patch pyproject.toml to include six in build-system requires
# (This is a simplified version; the full script does more robust patching)
if [[ -f "pyproject.toml" ]]; then
  # Add six to build-system requires if not present
  python3 <<'PY'
from pathlib import Path
p = Path("pyproject.toml")
txt = p.read_text(encoding="utf-8")
if "six" not in txt:
    # Simple patch: add six to requires if it's a single-line array
    import re
    txt2 = re.sub(
        r'(requires\s*=\s*\[)(.*?)(\]\s*$)',
        lambda m: m.group(1) + m.group(2).rstrip() + ', "six"' + m.group(3),
        txt,
        count=1,
        flags=re.MULTILINE
    )
    p.write_text(txt2, encoding="utf-8")
PY
fi

# Patch setup.py if needed (simplified)
if [[ -f "setup.py" ]]; then
  python3 <<'PY'
from pathlib import Path
import re
p = Path("setup.py")
txt = p.read_text(encoding="utf-8")
# Patch import line if it exists
pattern = r"^(\s*)from scalyr_agent.__scalyr__ import SCALYR_VERSION, get_install_root\s*$"
def repl(m):
    indent = m.group(1)
    return indent + "def _read_version():\n" + \
           indent + "    with open(path.join(path.dirname(__file__), \"VERSION\"), encoding=\"utf-8\") as f:\n" + \
           indent + "        return f.read().strip()\n" + \
           indent + "\n" + \
           indent + "SCALYR_VERSION = _read_version()\n" + \
           indent + "\n" + \
           indent + "def get_install_root():\n" + \
           indent + "    return path.dirname(path.abspath(__file__))\n"
txt, count = re.subn(pattern, repl, txt, flags=re.M)
if count > 0:
    p.write_text(txt, encoding="utf-8")
PY
fi

# Install with --no-use-pep517 to avoid PEP517 issues
sudo /opt/scalyr-agent-2/venv/bin/pip install --disable-pip-version-check --no-use-pep517 .

cd /
rm -rf "${WORKDIR}"
```

---

## 3) Sanity check (quiet, no warning)

The noisy `pkg_resources` deprecation warning shows up when running the agent CLI directly.
So at this stage we do a simple **import-only** sanity check.

```bash
sudo /opt/scalyr-agent-2/venv/bin/python -c "import scalyr_agent; import scalyr_agent.agent_main; print('scalyr_agent import: OK')"
```

We'll run the real `scalyr status -v` check **after** the wrapper exists (the wrapper suppresses the warning).

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

# Optional: READ key for API verification
# SCALYR_READ_API_KEY="your-read-key-here"
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
  "ca_cert_path": "/etc/ssl/certs/ca-certificates.crt",
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

sudo chmod 0755 /opt/scalyr-agent-2/scalyr
```

### Put it on PATH for humans (and make `sudo scalyr ...` work)

On Ubuntu, `sudo` often uses a restricted `secure_path` which may **not** include `/usr/local/bin`. The simplest fix is to symlink into `/usr/bin`.

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

## 7) Open the syslog ports (if using UFW)

If this host should accept remote syslog on 514 and UFW is active:

```bash
# Check if UFW is active
sudo ufw status | grep -q "^Status: active" && sudo ufw allow 514/tcp && sudo ufw allow 514/udp
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
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scalyr-agent-2
```

> Note: If you change values in `scalyr.env`, you must restart the service for them to take effect.

---

## 9) Validate it's actually working (includes `nc` tests)

### A) Service state + verbose agent status

```bash
sudo systemctl status scalyr-agent-2 --no-pager -l
sudo scalyr status -v
```

### B) Confirm it is listening on 514 TCP/UDP

```bash
sudo ss -luntp | egrep ':(514)\b'
```

### C) Send test syslog messages with netcat (the "it just works" tests)

Running the test **on the agent host itself**, using `127.0.0.1`:

**UDP:**

```bash
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '<189>1 %s nc-local FortiGate-40F-SVA - - - msg="local udp test"\n' "${ts}" \
  | nc -u -v -w1 127.0.0.1 514
```

**TCP:**

```bash
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '<189>1 %s nc-local FortiGate-40F-SVA - - - msg="local tcp test"\n' "${ts}" \
  | nc -v -w1 127.0.0.1 514
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

### "ERROR: Cannot find command 'git'"

You're installing from a Git tag, so pip shells out to `git`. Fix:

```bash
sudo apt-get install -y git
command -v git
git --version
```

### `sudo scalyr ...` says command not found

You likely symlinked only into `/usr/local/bin`. Ubuntu `sudo` can ignore that path. Fix:

```bash
sudo ln -sf /opt/scalyr-agent-2/scalyr /usr/bin/scalyr
sudo command -v scalyr
```

### Nothing arrives in `fortigate.log`

- Confirm firewall is open (if UFW is active):
  ```bash
  sudo ufw status | grep 514
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

### Installation fails with PEP517/six errors

If you encounter build errors related to `six` or PEP517, ensure you:

1. Pinned pip to 23.3.2
2. Applied the patches to `pyproject.toml` and `setup.py`
3. Used `--no-use-pep517` when installing

If issues persist, use the TURBO installer script which handles all of this automatically.

---

## Handy one-liners

```bash
# Verbose agent status
sudo scalyr status -v

# Restart + immediately show recent logs
sudo systemctl restart scalyr-agent-2 && sudo journalctl -u scalyr-agent-2 -n 200 --no-pager
```



