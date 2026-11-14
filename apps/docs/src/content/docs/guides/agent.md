---
title: Standalone Client Agent (1-Click Script)
description: How to enroll an existing external server (Ubuntu, Debian) without deploying the full Aegis suite.
---

This mode is designed for clients who already maintain their own application servers (e.g., LAMP stacks, Node.js runtimes, existing containerized workloads) and want to benefit from **sovereign energy telemetry** and **outbound threat containment** without refactoring their infrastructure.

## ⚡ 15-Second Enrollment Procedure

### Step 1: Obtain your Enrollment Token
1. Open your Aegis Cockpit: `http://<AEGIS_HOST>:4321/app`.
2. Click the top button: **`⚡ + Connect a Server`**.
3. Provide an identifier for the remote host (e.g. `vps-client-prod`).
4. The Cockpit instantly generates a customized enrollment command containing your signed token.

### Step 2: Run the Script on the Target Server

In the SSH shell of the remote server, execute the command with root privileges:

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- \
  --profile agent \
  --token aegis_tok_live_your_token \
  --endpoint http://<AEGIS_HOST>:8080 \
  --server-id vps-client-prod
```

> [!NOTE]
> You can also pull the script directly from your internal Aegis control plane:
> `curl -sSL http://<AEGIS_HOST>:8080/install.sh | sudo bash -s -- --profile agent ...`

### Step 3: Instant Telemetry Validation

The installation script:
1. Detects host architecture (physical Intel/AMD RAPL registers or virtualized Cloud VM).
2. Generates `/etc/aegis/agent.env`.
3. Installs and starts the autonomous systemd service `aegis-agent.service` (&lt; 15 MB RAM, 0% idle CPU).
4. Sends an initial signed handshake to your Aegis Control Plane.

The enrollment modal in your browser will automatically turn green:
> **✅ Server successfully connected! (18.5 W • CPU 12.0%)**

---

## 🛠️ Remote Service Management

```bash
# Check telemetry daemon status
sudo systemctl status aegis-agent

# Stream live measurement logs
sudo journalctl -u aegis-agent -f

# Temporarily stop the agent
sudo systemctl stop aegis-agent
```
