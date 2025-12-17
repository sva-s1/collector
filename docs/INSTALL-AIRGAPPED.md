## Air‑gapped / no‑internet install prep for the SentinelOne Collector

This doc is for **targets without outbound internet** (no access to `github.com` / `pypi.org`).
You’ll stage the Scalyr Agent 2 (“Yvette” / `v2.2.19`) bits on an **online helper box**, then copy them to your **air‑gapped Rocky Linux 9 VM**.

> [!TIP]
> These steps assume a RHEL/Rocky‑style system. Adapt package commands if you’re using a different distro.

---

### 1) On an internet‑connected helper machine

- **Create a staging directory**:

```bash
mkdir -p ~/scalyr-agent-2-offline
cd ~/scalyr-agent-2-offline
```

- **Download the upstream Scalyr Agent 2 release** (`v2.2.19` “Yvette”) from the GitHub releases page  
  → open [`https://github.com/scalyr/scalyr-agent-2`](https://github.com/scalyr/scalyr-agent-2)  
  → click **Releases** → locate **2.2.19 "Yvette"**  
  → download the **wheel or source tarball** into `~/scalyr-agent-2-offline`, for example:
  - `scalyr_agent-2.2.19-py2.py3-none-any.whl`, or
  - `scalyr_agent-2.2.19.tar.gz`

- (Optional but recommended) **Download Python dependencies into the same folder**:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip

pip download "scalyr-agent-2==2.2.19" -d ./pkgs
```

You should now have:

- one or more **agent artifacts** (`.whl` / `.tar.gz`)
- a `pkgs/` directory of **offline wheels** for dependencies

---

### 2) Copy artifacts to the air‑gapped Rocky 9 VM

From your **online helper**:

```bash
cd ~/scalyr-agent-2-offline
tar czf scalyr-agent-2-offline-v2.2.19.tgz .

scp scalyr-agent-2-offline-v2.2.19.tgz \
  <user>@<airgapped-vm>:/tmp/
```

On the **air‑gapped Rocky 9 VM**:

```bash
cd /tmp
tar xzf scalyr-agent-2-offline-v2.2.19.tgz
cd scalyr-agent-2-offline
```

---

### 3) Create the venv on the air‑gapped VM and install from local files

```bash
sudo python3 -m venv /opt/scalyr-agent-2/venv

sudo /opt/scalyr-agent-2/venv/bin/pip install --upgrade pip setuptools wheel
```

If you have the `pkgs/` folder with all wheels:

```bash
sudo /opt/scalyr-agent-2/venv/bin/pip install --no-index \
  --find-links pkgs \
  scalyr-agent-2==2.2.19
```

If you only copied the agent wheel or tarball:

```bash
sudo /opt/scalyr-agent-2/venv/bin/pip install \
  ./scalyr_agent-2.2.19-py2.py3-none-any.whl
# or
sudo /opt/scalyr-agent-2/venv/bin/pip install \
  ./scalyr-agent-2.2.19.tar.gz
```

Once the venv install succeeds, **switch back to the main Rocky 9 install guide** and continue from the config step (creating `/etc/scalyr-agent-2/agent.json`, wrapper, systemd, etc.).

---

### 4) Where to go next

- Rocky Linux 9 **online / standard** install steps: see [`INSTALL.md`](../INSTALL.md)
- Upstream agent source, docs, and changelog: [`https://github.com/scalyr/scalyr-agent-2`](https://github.com/scalyr/scalyr-agent-2)


