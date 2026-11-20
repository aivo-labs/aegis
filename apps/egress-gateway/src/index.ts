#!/usr/bin/env node

/**
 * Passerelle Aegis Egress (apps/egress-gateway)
 * Architecture SOLID modulaire & Typée (TypeScript)
 */

import { loadEgressConfigFromEnv } from './config.js';
import { CtiBlocklistManager } from './cti/blocklist.js';
import { SystemOneClient } from './engine/system-one.js';
import { HttpEgressTelemetryReporter } from './telemetry/reporter.js';
import { EgressEvaluator } from './engine/evaluator.js';
import { createDnsUdpServer } from './dns/udp-server.js';
import { createEgressHttpServer } from './http/tcp-server.js';
import { calculateShannonEntropy } from './engine/entropy.js';
import type { EgressStateVector, EgressTelemetryPayload } from './types.js';

// Ré-exports pour tests et interopérabilité
export * from './types.js';
export * from './config.js';
export * from './cti/blocklist.js';
export * from './engine/entropy.js';
export * from './engine/ip-allowlist.js';
export * from './engine/system-one.js';
export * from './engine/evaluator.js';
export * from './dns/packet.js';
export * from './dns/udp-server.js';
export * from './http/tcp-server.js';
export * from './telemetry/reporter.js';

// Initialisation des dépendances et services
const config = loadEgressConfigFromEnv();
const ctiManager = new CtiBlocklistManager();
const systemOneClient = new SystemOneClient(
  config.systemOneApiUrl,
  config.systemOneModelName,
  config.systemOneApiKey,
  ctiManager
);
const telemetryReporter = new HttpEgressTelemetryReporter(config.gateApiUrl);
export const egressEvaluator = new EgressEvaluator(
  systemOneClient,
  telemetryReporter,
  ctiManager,
  config.tenantId,
  config.defaultProtectionEnabled
);

// Fonctions de compatibilité ascendante avec les anciens scripts & bancs d'essais
export function processEgressQuery(fqdn: string, clientIp = '127.0.0.1', protocolContext = 'dns_query') {
  return egressEvaluator.processQuery(fqdn, clientIp, protocolContext);
}

export function evaluateSystemOneDecision(stateVector: EgressStateVector) {
  return systemOneClient.evaluate(stateVector);
}

export const evaluateJevAiDecision = evaluateSystemOneDecision;

export function sendEgressTelemetry(payload: EgressTelemetryPayload) {
  return telemetryReporter.send(payload);
}

// Démarrage du démon d'écoute UDP & TCP/HTTP ou exécution CLI unitaire
if (
  process.argv[1] &&
  (process.argv[1].endsWith('index.js') ||
    process.argv[1].endsWith('index.mjs') ||
    process.argv[1].endsWith('index.ts'))
) {
  if (process.argv[2]) {
    // Mode CLI one-shot
    const targetFqdn = process.argv[2];
    processEgressQuery(targetFqdn).then(res => {
      console.log(`\n📍 Évaluation FQDN : ${targetFqdn}`);
      console.log(JSON.stringify(res, null, 2));
      process.exit(0);
    });
  } else {
    // 1. Serveur UDP DNS Sinkhole (:5053/udp)
    const udpServer = createDnsUdpServer(egressEvaluator, config.listenPort);
    udpServer.bind(config.listenPort, '0.0.0.0', () => {
      console.log(`🛡️ [Aegis Egress] Passerelle DNS Sinkhole active sur UDP 0.0.0.0:${config.listenPort}`);
      console.log(`⚡ Moteur IA System One (${config.systemOneModelName}) & Level 1 CrowdSec Cache prêts.`);
      console.log(`🔗 Endpoint API : ${config.systemOneApiUrl}`);
    });

    // 2. Serveur HTTP/TCP d'interception & Healthcheck (:5053/tcp)
    const tcpServer = createEgressHttpServer(
      egressEvaluator,
      config.listenPort,
      config.systemOneModelName
    );
    tcpServer.listen(config.listenPort, '0.0.0.0', () => {
      console.log(`🔒 [Aegis Egress] Intercepteur Socket/HTTP actif sur TCP 0.0.0.0:${config.listenPort}`);
    });
  }
}
