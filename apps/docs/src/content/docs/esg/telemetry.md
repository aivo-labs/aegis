---
title: Physical Metering & EFRAG VS Standard
description: Raw energy telemetry, RAPL hardware registers, RGESN frugal mode, and audit-proof ESG certificates.
---

Aegis Green breaks away from spend-based carbon estimates by relying strictly on **the superiority of direct physical measurement** (genuine Watts and Joules consumed at the silicon layer).

## ⚡ Hardware Metering by Infrastructure Topology

The ultra-frugal Rust telemetry daemon (`apps/telemetry-agent`) automatically selects the most accurate physical data source available:

1. **Bare-Metal Physical Server** : Direct reading of Intel/AMD **RAPL** hardware MSR registers under `/sys/class/powercap/intel-rapl` (&plusmn;1% hardware precision).
2. **Kubernetes Cluster** : Seamless integration with CNCF **Kepler** eBPF probes to attribute hardware energy proportionally across **Namespaces** and **Pods**.
3. **Cloud VPS Virtual Machine (KVM/QEMU)** : High-frequency host processor sampling via `/proc/stat` processed through a thermodynamic curve calibrated to the virtualized CPU package profile (from 12W idle to 48W peak).

---

## 🎯 2026 Regulatory Alignment

Captured telemetry continuously feeds the ESG compliance module in the Cockpit:

### 1. EFRAG Voluntary Standard (VS / ex-VSME)
* Fully aligned with **Section E3 (Climate Change & Digital Sobriety)** of European CSRD reporting guidelines for SMEs.
* 1-click export of structured, signed audit records (`AEGIS-VSME-EFRAG-AUDIT-2026.json`).

### 2. RGESN 2024 Framework (Software Eco-Design)
* Compliance with **RGESN Rule 4.15** : One-click **Energy Saver (Frugal Mode)** toggling lower polling frequencies, reduced processor wakeups, and GPU animation offloading during high-stress periods.

### 3. Grid Carbon Intensity Correlation
* Real-time tracking of regional electrical grid carbon intensity (gCO2e/kWh).
* Automated highlighting of the **Green Window** (optimal hours of high renewable generation, typically 10:00–14:00) to schedule power-intensive batch analytics.
