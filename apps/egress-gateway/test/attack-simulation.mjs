#!/usr/bin/env node

/**
 * Aegis Egress (DP-03) — Banc d'Essais & Simulation d'Attaques Network Outbound
 * Test de montée en charge et de détection probabiliste DGA / C2 sous System One (Nimble 9B)
 */

import { processEgressQuery, calculateShannonEntropy } from '../src/index.mjs';

const TEST_DOMAINS = [
  // 1. Attaques C2 & Phishing connues (Level 1 CTI)
  { domain: 'c2-beacon.random-domain.top', expectedAction: 'BLOCK', category: 'C2_KNOWN' },
  { domain: 'malware-exfil.badsite.xyz', expectedAction: 'BLOCK', category: 'C2_KNOWN' },
  
  // 2. Domaines DGA à fort niveau d'entropie (Level 2 System One Nimble 9B)
  { domain: 'x99b-c2-beacon.random-domain.top', expectedAction: 'BLOCK', category: 'DGA_HIGH_ENTROPY' },
  { domain: 'a88z-exfiltrate-key-rsa9912.random.xyz', expectedAction: 'BLOCK', category: 'DGA_HIGH_ENTROPY' },
  { domain: 'phishing-verify-bank-access.click', expectedAction: 'BLOCK', category: 'PHISHING_SUSPECTED' },

  // 3. Trafic légitime autorisé (Clean Traffic)
  { domain: 'google.com', expectedAction: 'ALLOW', category: 'LEGITIMATE' },
  { domain: 'github.com', expectedAction: 'ALLOW', category: 'LEGITIMATE' },
  { domain: 'aegis.aivo.fr', expectedAction: 'ALLOW', category: 'LEGITIMATE' },
  { domain: 'api.scaleway.com', expectedAction: 'ALLOW', category: 'LEGITIMATE' }
];

async function runBenchmarkSimulation() {
  console.log('🛡️ [Aegis Egress DP-03] Lancement de la Simulation d Attaques & Benchmark System One...\n');

  const startTime = performance.now();
  let totalTests = 0;
  let correctDecisions = 0;
  let totalLatency = 0;

  for (const testCase of TEST_DOMAINS) {
    totalTests++;
    const res = await processEgressQuery(testCase.domain);
    totalLatency += res.latency_ms;

    const isMatch = res.action === testCase.expectedAction || (testCase.expectedAction === 'BLOCK' && res.action === 'QUARANTINE');
    if (isMatch) correctDecisions++;

    console.log(`[${isMatch ? '✅ PASS' : '❌ FAIL'}] ${testCase.domain.padEnd(42)} -> Action: ${res.action.padEnd(10)} | Latence: ${res.latency_ms.toFixed(2)} ms | Moteur: ${res.engine}`);
  }

  const totalDuration = performance.now() - startTime;
  const avgLatency = (totalLatency / totalTests).toFixed(2);
  const accuracy = ((correctDecisions / totalTests) * 100).toFixed(1);

  console.log('\n📊 ─── RÉSULTATS DU BANC D ESSAI AEGIS EGRESS ───');
  console.log(`• Total Requêtes Évaluées : ${totalTests}`);
  console.log(`• Taux de Précision        : ${accuracy}% (${correctDecisions}/${totalTests} tests réussis)`);
  console.log(`• Latence Moyenne / Requête: ${avgLatency} ms`);
  console.log(`• Temps Total d Exécution  : ${totalDuration.toFixed(2)} ms`);
  console.log(`• Modèle IA                : Nimble 9B (Ollama / /v1/systemone)`);
  console.log('---------------------------------------------------\n');
}

runBenchmarkSimulation().catch(console.error);
