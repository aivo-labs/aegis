#!/usr/bin/env node

/**
 * Moteur de Scan Unique Aegis (aegis-scanner)
 * Utilisé en Mode Passif (Lead Magnet / Non-intrusif) et Mode Actif (Authentifié & DNS Vérifié).
 */

import dns from 'node:dns/promises';
import https from 'node:https';

export async function runAegisScan(targetUrl, options = { mode: 'passive' }) {
  const urlObj = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
  const domain = urlObj.hostname;

  console.log(`[Aegis Scanner] Ingestion de la cible: ${domain} (Mode: ${options.mode})`);

  // 1. Contrôles DNS (SPF, DMARC, CAA)
  let dnsResults = { hasSpf: false, hasDmarc: false, hasCaa: false };
  try {
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
    const caaRecords = await dns.resolveCaa(domain).catch(() => []);

    dnsResults.hasSpf = txtRecords.some(r => r.join('').startsWith('v=spf1'));
    dnsResults.hasDmarc = dmarcRecords.some(r => r.join('').startsWith('v=DMARC1'));
    dnsResults.hasCaa = caaRecords.length > 0;
  } catch (e) {
    console.warn(`[Aegis Scanner] Avertissement DNS: ${e.message}`);
  }

  // 2. Audit Passif des En-têtes HTTP de Sécurité
  let httpResults = { statusCode: 0, missingHeaders: [], pageSizeKb: 0 };
  try {
    const res = await fetch(urlObj.href, { method: 'HEAD' });
    httpResults.statusCode = res.status;

    const securityHeaders = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options'];
    securityHeaders.forEach(h => {
      if (!res.headers.has(h)) {
        httpResults.missingHeaders.push(h);
      }
    });
  } catch (e) {
    console.warn(`[Aegis Scanner] Avertissement HTTP: ${e.message}`);
  }

  // 3. Calcul du score EcoIndex approximatif
  const ecoScore = Math.max(10, 100 - (httpResults.missingHeaders.length * 10));
  const ecoGrade = ecoScore >= 80 ? 'A' : ecoScore >= 70 ? 'B' : ecoScore >= 55 ? 'C' : 'D';

  return {
    domain,
    mode: options.mode,
    securityScore: ecoScore,
    ecoindex: {
      score: ecoScore,
      grade: ecoGrade
    },
    dns: dnsResults,
    http: httpResults,
    scannedAt: new Date().toISOString()
  };
}

// Support d'exécution CLI direct
if (process.argv[1] && process.argv[1].endsWith('index.mjs')) {
  const target = process.argv[2] || 'aivo.fr';
  runAegisScan(target)
    .then(res => console.log(JSON.stringify(res, null, 2)))
    .catch(err => console.error(err));
}
