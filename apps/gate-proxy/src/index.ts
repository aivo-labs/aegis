#!/usr/bin/env node

/**
 * Passerelle Ingress PEP & WAF Zero-Trust pour Aegis Gate (apps/gate-proxy)
 * Architecture SOLID modulaire & Typée (TypeScript)
 */

import { loadConfigFromEnv } from './config.js';
import { createDefaultRuleRegistry } from './rules/default-rules.js';
import { IpReputationManager } from './quarantine/ip-reputation.js';
import { WafInspector } from './engine/inspector.js';
import { HttpTelemetryReporter } from './telemetry/reporter.js';
import { HttpProxyForwarder } from './proxy/forwarder.js';
import { createGateServer, type GateServerState } from './server.js';
import { canonicalizeInput } from './engine/canonicalizer.js';
import { computeRequestEntropy } from './engine/entropy.js';
import type { IncomingMessage } from 'node:http';

// Ré-exports pour tests et interopérabilité
export * from './types.js';
export * from './config.js';
export * from './engine/canonicalizer.js';
export * from './engine/entropy.js';
export * from './engine/inspector.js';
export * from './quarantine/ip-reputation.js';
export * from './rules/registry.js';
export * from './rules/rule.interface.js';
export * from './rules/default-rules.js';
export * from './proxy/forwarder.js';
export * from './telemetry/reporter.js';
export * from './server.js';
export * from './bff/session.js';
export * from './bff/auth-handler.js';

import { BffAuthHandler } from './bff/auth-handler.js';

// Configuration et dépendances
const config = loadConfigFromEnv();
const ruleRegistry = createDefaultRuleRegistry();
const ipReputation = new IpReputationManager();
const serverState: GateServerState = {
  protectionEnabled: config.defaultProtectionEnabled,
  maxPayloadBytes: config.defaultMaxPayloadBytes
};

const inspector = new WafInspector(
  ruleRegistry,
  ipReputation,
  () => serverState.maxPayloadBytes
);
const telemetry = new HttpTelemetryReporter(config.telemetryUrl);
const forwarder = new HttpProxyForwarder();
const authHandler = new BffAuthHandler(config);

// Immunité garantie au démarrage pour l'IP du VPS / hôte administrateur
ipReputation.unban('92.157.163.164');
ipReputation.unban('127.0.0.1');

export const gateServer = createGateServer(
  config,
  inspector,
  ipReputation,
  telemetry,
  forwarder,
  serverState,
  authHandler
);

/**
 * Fonction inspectRequest pour compatibilité ascendante avec les anciens scripts
 */
export function inspectRequest(
  req: IncomingMessage,
  rawBody = '',
  byteLength = 0,
  clientIp = ''
) {
  return inspector.inspect(
    req.url || '/',
    req.method || 'GET',
    req.headers,
    rawBody,
    byteLength,
    clientIp
  );
}

// Démarrage du serveur si exécuté comme script principal
if (process.argv[1] && (process.argv[1].endsWith('index.js') || process.argv[1].endsWith('index.mjs') || process.argv[1].endsWith('index.ts'))) {
  gateServer.listen(config.port, '0.0.0.0', () => {
    console.log(`🛡️ [Aegis Gate PEP] Passerelle d'interception Ingress WAF & Virtual Patching active sur le port ${config.port}`);
    console.log(`🎯 Cibles Upstream -> Web: ${config.webUrl} | Backend: ${config.backendUrl}`);
    console.log(`📡 Ingestion Télémétrie -> ${config.telemetryUrl}`);
    console.log(`🔒 Protection active : Overflow 413 (${serverState.maxPayloadBytes}B max), Zero-Day Virtual Patching, OWASP Top 10 & Scanners`);
  });
}
