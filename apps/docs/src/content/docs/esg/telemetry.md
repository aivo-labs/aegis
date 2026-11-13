---
title: Physical Metering & VS Standard (EFRAG)
description: Hardware energy telemetry, processor RAPL registers, Kepler eBPF probes, RGESN frugal mode, and certified ESG report generation.
---

Aegis Green breaks definitively with theoretical spend-based carbon accounting by relying strictly on **the superiority of real physical measurements**: recording genuine Watts and Joules consumed at the processor hardware registers.

---

## ⚡ Energy Telemetry Architecture Diagram

```
    ┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────────┐
    │    BARE-METAL SERVER     │  │    KUBERNETES CLUSTER    │  │        CLOUD VPS         │
    │      (Physical Node)     │  │     (EKS, GKE, Bare)     │  │    (KVM, QEMU, Cloud)    │
    │                          │  │                          │  │                          │
    │ Physical MSR Registers   │  │ Kernel eBPF Kepler Probe │  │ CPU Cycles via /proc/stat│
    │ Intel/AMD RAPL (±1%)     │  │ Per-Pod/Namespace shares │  │ Thermodynamic Model      │
    └────────────┬─────────────┘  └────────────┬─────────────┘  └────────────┬─────────────┘
                 │                             │                             │
                 └───────────────────────┬─────┴─────────────────────────────┘
                                         ▼
                 ┌───────────────────────────────────────────────────────────┐
                 │             SOVEREIGN RUST TELEMETRY AGENT                │
                 │                 (apps/telemetry-agent)                    │
                 │                                                           │
                 │  • Compiled native binary with zero GC overhead           │
                 │  • Negligible CPU footprint (< 0.2%)                      │
                 │  • Host PID isolation & read-only /proc, /sys mounts      │
                 │  • Continuous high-resolution sampling every 5 seconds    │
                 └─────────────────────────────┬─────────────────────────────┘
                                               │
                                               ▼ JSON Ingestion (/api/v1/gate/telemetry/energy)
                 ┌───────────────────────────────────────────────────────────┐
                 │               GO BACKEND & TIMESCALEDB                    │
                 │                                                           │
                 │  • Compressed time-series hypertables (7-day chunks)      │
                 │  • Real-time RTE EcoWatt carbon intensity correlation     │
                 │  • Scope 2 calculation: Energy (kWh), CO₂eq (g), Water (L)│
                 └─────────────────────────────┬─────────────────────────────┘
                                               │
                                ┌──────────────┴──────────────┐
                                ▼                             ▼
                 [ AEGIS WEB COCKPIT ]        [ ESG EXPORTS & CERTIFICATES ]
                 • EFRAG compliance radar     • Official CSRD / ESG PDF
                 • Real-time power monitoring • Standardized JSON audit file
                 • Energy Saver frugal switch • Granular raw CSV export
```

---

## 🔬 3 Capture Modes Suited to Any Infrastructure

The Rust telemetry agent automatically selects the most accurate measurement method available on the host environment:

### 1. Dedicated Bare-Metal Servers: RAPL Registers
On bare-metal physical servers (OVHcloud, Hetzner, Scaleway Dedibox), the agent reads directly from the Linux kernel **Intel/AMD RAPL (Running Average Power Limit)** interface via `/sys/class/powercap/intel-rapl`:
* Captures hardware counters in microjoules for the CPU socket, DRAM memory, and processor cores (*Package Energy Status*).
* Certified accuracy within **±1%** against physical testbench power meters.

### 2. Containerized Clusters: Kepler eBPF Probe
In Kubernetes environments, Aegis integrates with **Kepler (Kubernetes Efficient Power Level Exporter)** kernel probes:
* Attributes physical power consumption proportionally based on CPU instruction cycles and context switches for each **Namespace**, **Deployment**, or **Pod**.
* Empowers engineering teams to attribute carbon footprints directly to individual business microservices.

### 3. Cloud Virtual Machines (KVM / QEMU): Thermodynamic Modeling
On virtualized instances where hardware MSR registers are hidden by the hypervisor:
* Samples raw CPU cycle counters directly from `/proc/stat` (`user`, `system`, `iowait`, `idle`).
* Applies a continuous thermodynamic formula calibrated to the VM hardware profile (baseline idle consumption from 12 W up to 48 W under full load per vCPU).

---

## 🎯 2026 European Regulatory Compliance

Aegis Green transforms raw electrical metrics into audit-ready indicators compliant with European non-financial reporting mandates:

### 1. Voluntary Standard VS (EFRAG / formerly VSME)
* Fully aligned with **Pillar E3 (Climate Change & Digital Sobriety)** under the European **CSRD** directive for SMEs and mid-caps.
* Automated computation of **Scope 2** emissions (*Market-based* and *Location-based* methodologies) alongside datacenter water cooling consumption.

### 2. RGESN 2024 Framework (Rule 4.15 & Frugal Mode)
* The Aegis Cockpit features an **Energy Saver (Frugal Mode)** toggle conforming to Rule 4.15 of the French General Digital Eco-Design Framework (RGESN).
* Activating Frugal Mode adjusts telemetry sampling intervals, offloads GPU animations, and optimizes database query frequencies to lower server CPU load by up to 25% during off-peak hours.

### 3. Real-Time RTE EcoWatt Grid Sync & "Green Window"
* Correlates electrical power consumption with live grid carbon intensity metrics (gCO₂eq/kWh).
* Highlights the **Green Window** (optimal off-peak solar/wind generation periods, typically 11:00 to 15:00) to schedule power-hungry batch workloads, backups, and AI model fine-tuning.

---

## 📑 Export Formats & Certified Attestation

The Aegis Cockpit provides three audit-ready export formats:

1. **Official ESG Certificate (PDF)**: An executive document branded with Aegis sovereign styling, detailing total energy consumption (kWh), avoided emissions, and European regulatory compliance. Ready for submission to auditors, investors, and enterprise clients.
2. **Standardized JSON Audit Report** (`AEGIS-VSME-EFRAG-AUDIT-2026.json`): Structured, timestamped data matching official EFRAG schemas for automated ingestion into corporate CSR platforms.
3. **Raw CSV Export**: Point-by-point time-series history for statistical analysis and custom business intelligence pipelines.

---

## 📚 Articles & Technical References

Explore empirical laboratory measurements and software efficiency research on AIVO:

* 📖 [**Anatomy of a VPS Under Continuous Attack: Scanners, Energy, and Active Responses**](https://aivo.fr/en/blog/anatomie-vps-sous-assaut-continu-scanners-energie) — Empirical power consumption benchmarks during volumetric attacks and energy savings achieved through frontline interception.
* 📖 [**Shannon Entropy & Zero-Trust Decisions: Frugal AI Powering the WAF**](https://aivo.fr/en/blog/entropie-shannon-decision-zero-trust-ia-frugale) — Why lightweight mathematical scoring consumes 1,000x less electrical energy than cloud LLM API calls.
* 🔬 [**Aegis Sovereign Gate Case Study on AIVO.fr**](https://aivo.fr/en/realisations/aegis-sovereign-gate) — Combining high-assurance cyberdefense with European climate compliance commitments.
