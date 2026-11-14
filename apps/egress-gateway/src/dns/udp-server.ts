import dgram from 'node:dgram';
import type { IEgressEvaluator } from '../engine/evaluator.js';
import { parseDnsQueryPacket, buildDnsResponsePacket } from './packet.js';

export function createDnsUdpServer(evaluator: IEgressEvaluator, port: number): dgram.Socket {
  const udpServer = dgram.createSocket('udp4');

  udpServer.on('error', err => {
    console.error(`❌ [Aegis Egress UDP] Erreur socket : ${err.message}`);
  });

  udpServer.on('message', async (msg, rinfo) => {
    const parsed = parseDnsQueryPacket(msg);
    if (!parsed) return;

    const clientIp = rinfo.address === '::1' ? '127.0.0.1' : rinfo.address || '127.0.0.1';
    const decision = await evaluator.processQuery(parsed.fqdn, clientIp, 'dns_udp');
    const isBlocked = decision.action === 'BLOCK' || decision.action === 'QUARANTINE';

    console.log(
      `${isBlocked ? '🛑 [EGRESS BLOCK]' : '⚠️ [EGRESS BYPASS/ALLOW]'} FQDN=${parsed.fqdn} | Client=${clientIp} | Verdict=${decision.action} (${decision.threat_type}) | ${decision.latency_ms}ms`
    );

    try {
      const responseBuf = buildDnsResponsePacket(msg, parsed.questionEnd, isBlocked);
      udpServer.send(responseBuf, rinfo.port, rinfo.address);
    } catch {
      // Ignorer erreur d'envoi UDP client fermé
    }
  });

  return udpServer;
}
