---
title: Bare-Metal Dedicated Server Deployment
description: Deploy Aegis on physical hardware with direct access to Intel/AMD RAPL hardware energy counters.
---

This guide is designed for organizations and enterprises operating dedicated physical servers (OVH Rise/Kimsufi, Hetzner Dedicated, Scaleway Dedibox, Dell PowerEdge on-premise).

## ⚡ Why Deploy Aegis on Bare-Metal?

On a physical bare-metal server, Aegis accesses the raw **RAPL (Running Average Power Limit)** hardware registers of Intel and AMD processors located under `/sys/class/powercap/intel-rapl`.

* **Absolute Physical Accuracy** : Direct hardware microjoule sampling across processor packages and DRAM (&plusmn;1% silicon precision).
* **Zero Statistical Estimation** : No theoretical TDP approximations; genuine real-time electrical draw in Watts.
* **Audit-Proof CSRD / EFRAG Evidence** : Verifiable energy reporting compliant with the voluntary SME standard (VSME, E3 section).

---

## 🚀 Method 1: 1-Click Script Deployment (Recommended)

On your dedicated physical server (root access required):

```bash
curl -sSL https://aegis.aivo.fr/install.sh | sudo bash -s -- --profile baremetal
```

The script automatically detects RAPL availability, binds `/sys/class/powercap`, and starts the hardened container stack.

---

## 🛠️ Method 2: Manual Deployment with Docker Compose

If you are orchestrating manually from Git:

### 1. Verify kernel RAPL module availability

```bash
# Check if the powercap sysfs interface is present
ls -la /sys/class/powercap/intel-rapl/

# If the kernel module is not loaded:
sudo modprobe intel_rapl_msr
```

### 2. Launch with the Bare-Metal profile

```bash
git clone https://github.com/aivo-labs/aegis.git /opt/aegis
cd /opt/aegis

# Deploy with hardware register mount
docker compose -f deploy/docker-compose/docker-compose-baremetal.yml up -d --build
```

---

## 🔍 Verify Direct Hardware Sampling

Inspect the telemetry agent container logs:

```bash
docker compose -f deploy/docker-compose/docker-compose-baremetal.yml logs telemetry-agent
```

You should see log entries containing:
```log
✅ [Ingest OK] Total: 64.20W (RAPL_HARDWARE_DIRECT) | CPU: 18.5% | Delta Joules: 321.00J
```

The `RAPL_HARDWARE_DIRECT` tag confirms that measurements originate directly from the silicon energy sensors.

---

## 🧪 Test Load & Wattage Dynamics

To observe real-time power fluctuations during active threat mitigation, trigger the attack testbench:

```bash
cd /opt/aegis
./scripts/run-pentest-demo.sh
```

In your Cockpit ([`http://localhost:4321/app`](http://localhost:4321/app)), watch the instant correlation between offensive payload mitigation and real-time CPU wattage spikes.
