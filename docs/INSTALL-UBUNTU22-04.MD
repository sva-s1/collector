# Scalyr Agent 2 (SentinelOne Collector) install from scratch (Ubuntu 22.04 LTS)

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
> # Note: Requires 'curl' to be installed
> sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup-ubuntu22-04.sh)"
> ```
>
> The installer will automatically install any missing system dependencies (like `ca-certificates`) using `apt`.

---

## 0) Prep (Ubuntu 22.04)

### Prerequisites

- `curl` - Required to download the installer script
- `apt` - Package manager for installing dependencies

### Install Dependencies

```bash
sudo apt-get update -y

# Install required tools if not already present
if ! command -v curl >/dev/null 2>&1; then
    sudo apt-get install -y curl
fi

# Additional dependencies that will be installed automatically if missing:
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

# Install latest pip/setuptools
sudo /opt/scalyr-agent-2/venv/bin/pip install --disable-pip-version-check --upgrade pip setuptools wheel

# Install scalyr-agent-2 directly from GitHub
sudo /opt/scalyr-agent-2/venv/bin/pip install --disable-pip-version-check "git+https://github.com/scalyr/scalyr-agent-2.git@v2.2.19"
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
ENV

# Secure the env file (root only, no group/other access)
sudo chmod 600 /etc/scalyr-agent-2/scalyr.env
```

---

## 5) Create the agent.json config

Create the main config file. This includes the SentinelOne-specific settings.

```bash
sudo tee /etc/scalyr-agent-2/agent.json >/dev/null <<'CONFIG'
{
  // SentinelOne API token (from scalyr.env)
  "api_key": "${SCALYR_API_KEY}",
  
  // SentinelOne API server (from scalyr.env if set, otherwise US1)
  "scalyr_server": "${SCALYR_SERVER:-https://xdr.us1.sentinelone.net}",
  
  // Log and data paths
  "agent_log_path": "/etc/scalyr-agent-2/log",
  "agent_data_path": "/etc/scalyr-agent-2/data",
  
  // Log rotation settings
  "max_log_offset_size": 50*1024*1024,  // 50MB
  "max_log_rotations": 3,
  "max_log_size": "20M",
  "max_existing_log_offset_size": "100M",
  
  // SentinelOne API polling interval (seconds)
  "s1_poll_interval": 30,
  
  // Log level (debug, info, warning, error, critical)
  "log_level": "info",
  
  // Monitor configurations
  "monitors": [
    {
      "module": "sentinelone_activity_monitor",
      "s1_site_token": "YOUR_SITE_TOKEN",  // Optional: filter by site
      "s1_account_token": "YOUR_ACCOUNT_TOKEN"  // Required for account-level access
    },
    {
      "module": "sentinelone_threat_monitor",
      "s1_site_token": "YOUR_SITE_TOKEN",  // Optional: filter by site
      "s1_account_token": "YOUR_ACCOUNT_TOKEN"  // Required for account-level access
    }
  ]
}
CONFIG

# Set appropriate permissions
sudo chmod 644 /etc/scalyr-agent-2/agent.json
```

---

## 6) Create the scalyr wrapper script

Create a wrapper script at `/opt/scalyr-agent-2/scalyr` that will be used to control the agent:

```bash
sudo tee /opt/scalyr-agent-2/scalyr >/dev/null <<'WRAPPER'
#!/bin/bash
# Wrapper for scalyr-agent-2 that handles the config path and suppresses pkg_resources warnings

# Source environment variables if the file exists
if [[ -f "/etc/scalyr-agent-2/scalyr.env" ]]; then
  # shellcheck disable=SC1091
  . "/etc/scalyr-agent-2/scalyr.env"
fi

# Find the Python interpreter in the venv
PYTHON_BIN="/opt/scalyr-agent-2/venv/bin/python"
MAIN_SCRIPT="/opt/scalyr-agent-2/venv/bin/scalyr-agent-2"

# Check if the main script exists
if [[ ! -f "${MAIN_SCRIPT}" ]]; then
  echo "Error: ${MAIN_SCRIPT} not found. Is the Scalyr Agent installed?" >&2
  exit 1
fi

# Special handling for 'status -v' to show more detailed output
if [[ "$1" == "status" && "$2" == "-v" ]]; then
  exec "${PYTHON_BIN}" "${MAIN_SCRIPT}" "$@" -c /etc/scalyr-agent-2/agent.json 2> >(grep -v "pkg_resources\|setuptools" >&2)
else
  # For all other commands, just pass through
  exec "${PYTHON_BIN}" -W "ignore::pkg_resources.PEP440Warning" "${MAIN_SCRIPT}" "$@" -c /etc/scalyr-agent-2/agent.json 2> >(grep -v "pkg_resources\|setuptools" >&2)
fi
WRAPPER

# Make the wrapper executable
sudo chmod 755 /opt/scalyr-agent-2/scalyr

# Create a symlink in /usr/local/bin for easy access
sudo ln -sf /opt/scalyr-agent-2/scalyr /usr/local/bin/scalyr
```

---

## 7) Create systemd service

Create a systemd service file to manage the agent:

```bash
sudo tee /etc/systemd/system/scalyr-agent-2.service >/dev/null <<'SERVICE'
[Unit]
Description=Scalyr Agent 2 (SentinelOne Collector)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
EnvironmentFile=-/etc/scalyr-agent-2/scalyr.env
ExecStart=/opt/scalyr-agent-2/scalyr start
ExecStop=/opt/scalyr-agent-2/scalyr stop
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
KillMode=process

[Install]
WantedBy=multi-user.target
SERVICE

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable scalyr-agent-2
```

---

## 8) Start the service and verify

```bash
# Start the service
sudo systemctl start scalyr-agent-2

# Check status
scalyr status -v

# Follow logs (Ctrl+C to stop)
journalctl -u scalyr-agent-2 -f
```

---

## 9) Verify data is being sent

You can verify that data is being sent to SentinelOne by checking:

1. The agent logs: `journalctl -u scalyr-agent-2`
2. The SentinelOne Data Lake console for incoming logs
3. The agent's status: `scalyr status -v`

---

## 10) (Optional) Install the turbo-collector-setup script

For easier future updates, you can install the turbo-collector-setup script:

```bash
sudo curl -fsSL -L "https://raw.githubusercontent.com/sva-s1/collector/main/scripts/turbo-collector-setup.sh" -o /usr/local/bin/turbo-collector-setup
sudo chmod +x /usr/local/bin/turbo-collector-setup
```

Then you can run updates with:

```bash
sudo turbo-collector-setup
```

---

## Troubleshooting

### Common Issues

1. **Permission Denied** errors:
   - Ensure all directories in `/etc/scalyr-agent-2/` are owned by `root:root`
   - The `scalyr.env` file should be `600` and owned by `root:root`

2. **API Connection Issues**:
   - Verify your `SCALYR_API_KEY` is correct and has the right permissions
   - Check your network/firewall allows outbound HTTPS to the SentinelOne API

3. **Python/Pip Issues**:
   - Ensure you have Python 3.6+ installed
   - Try running with `--no-cache-dir` if you encounter pip cache issues

4. **Service Not Starting**:
   - Check systemd logs: `journalctl -u scalyr-agent-2 -n 50 --no-pager`
   - Run the agent manually in foreground: `sudo -E /opt/scalyr-agent-2/scalyr start --no-fork`

### Upgrading

To upgrade to a newer version of the agent:

```bash
# Stop the service
sudo systemctl stop scalyr-agent-2

# Update the package
sudo /opt/scalyr-agent-2/venv/bin/pip install --upgrade "git+https://github.com/scalyr/scalyr-agent-2.git@v2.2.19"

# Restart the service
sudo systemctl start scalyr-agent-2
```

### Uninstalling

To completely remove the agent:

```bash
# Stop and disable the service
sudo systemctl stop scalyr-agent-2
sudo systemctl disable scalyr-agent-2

# Remove the service file
sudo rm -f /etc/systemd/system/scalyr-agent-2.service
sudo systemctl daemon-reload

# Remove the installation
sudo rm -rf /opt/scalyr-agent-2
sudo rm -f /usr/local/bin/scalyr

# Optionally remove the config and logs
# WARNING: This will delete all configuration and logs
# sudo rm -rf /etc/scalyr-agent-2
```

---

## Support

For support with this installation, please refer to the [Scalyr Agent 2 documentation](https://www.scalyr.com/help/install-agent-linux) or the [SentinelOne Collector documentation](https://community.sentinelone.com/s/).
