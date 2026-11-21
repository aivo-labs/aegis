import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sealSession,
  unsealSession,
  parseCookies,
  serializeSessionCookie,
  serializeLogoutCookie,
  extractSessionFromRequest,
  type BffUserSession,
} from '../src/bff/session.js';
import { BffAuthHandler } from '../src/bff/auth-handler.js';
import { IncomingMessage, ServerResponse } from 'node:http';
import { Socket } from 'node:net';

test('Pure BFF Session — Seal & Unseal with AES-256-GCM', () => {
  const secret = 'test_secret_for_sovereign_bff_key_32!';
  const sampleSession: BffUserSession = {
    id: 'usr_secops_42',
    name: 'SecOps Analyst',
    email: 'secops@enterprise.fr',
    role: 'secops',
    tenantId: '00000000-0000-0000-0000-000000000001',
    exp: Date.now() + 3600000,
    createdAt: Date.now(),
  };

  const sealed = sealSession(sampleSession, secret);
  assert.ok(sealed, 'Sealed string must not be empty');
  assert.equal(typeof sealed, 'string');

  const unsealed = unsealSession(sealed, secret);
  assert.ok(unsealed, 'Unsealed session must exist');
  assert.equal(unsealed?.id, 'usr_secops_42');
  assert.equal(unsealed?.email, 'secops@enterprise.fr');
  assert.equal(unsealed?.role, 'secops');
  assert.equal(unsealed?.tenantId, '00000000-0000-0000-0000-000000000001');
});

test('Pure BFF Session — Rejects tampered or expired sessions', () => {
  const secret = 'test_secret_for_sovereign_bff_key_32!';
  const expiredSession: BffUserSession = {
    id: 'usr_expired',
    name: 'Old User',
    email: 'old@enterprise.fr',
    role: 'viewer',
    tenantId: '00000000-0000-0000-0000-000000000001',
    exp: Date.now() - 5000, // Déjà expiré
    createdAt: Date.now() - 3600000,
  };

  const sealedExpired = sealSession(expiredSession, secret);
  const unsealedExpired = unsealSession(sealedExpired, secret);
  assert.equal(unsealedExpired, null, 'Expired session must return null');

  // Altération de la chaîne chiffrée
  const validSession: BffUserSession = {
    id: 'usr_valid',
    name: 'Valid User',
    email: 'valid@enterprise.fr',
    role: 'admin',
    tenantId: '00000000-0000-0000-0000-000000000001',
    exp: Date.now() + 60000,
    createdAt: Date.now(),
  };
  const sealedValid = sealSession(validSession, secret);
  const tampered = sealedValid.slice(0, -4) + 'AAAA';
  const unsealedTampered = unsealSession(tampered, secret);
  assert.equal(unsealedTampered, null, 'Tampered ciphertext must fail GCM auth tag check');
});

test('Pure BFF Session — Cookie serialization & parsing', () => {
  const cookieHeader = '__Host-aegis_session=my_encrypted_payload; other_pref=dark';
  const parsed = parseCookies(cookieHeader);
  assert.equal(parsed['__Host-aegis_session'], 'my_encrypted_payload');
  assert.equal(parsed['other_pref'], 'dark');

  const serializedSecure = serializeSessionCookie('cookie_data_123', true, 3600);
  assert.ok(serializedSecure.includes('__Host-aegis_session=cookie_data_123'));
  assert.ok(serializedSecure.includes('HttpOnly'));
  assert.ok(serializedSecure.includes('SameSite=Lax'));
  assert.ok(serializedSecure.includes('Secure'));

  const logoutCookie = serializeLogoutCookie(true);
  assert.ok(logoutCookie.includes('Max-Age=0'));
});

test('Pure BFF AuthHandler — Intercepts and processes /api/auth/me', () => {
  const config: any = {
    tenantId: '00000000-0000-0000-0000-000000000001',
    sessionSecret: 'secret_key_for_unit_tests_32_bytes!',
  };
  const authHandler = new BffAuthHandler(config);

  // Requête non authentifiée
  const unauthReq: any = {
    url: '/api/auth/me',
    method: 'GET',
    headers: {},
  };
  let statusCode = 0;
  let responseData = '';
  const mockRes: any = {
    setHeader: () => {},
    writeHead: (code: number) => { statusCode = code; },
    end: (data: string) => { responseData = data; },
  };

  const handledUnauth = authHandler.handleAuthRequest(unauthReq, mockRes);
  assert.equal(handledUnauth, true);
  assert.equal(statusCode, 401);
  const unauthJson = JSON.parse(responseData);
  assert.equal(unauthJson.authenticated, false);

  // Requête authentifiée
  const validSession: BffUserSession = {
    id: 'usr_admin_ok',
    name: 'Admin Test',
    email: 'admin@aegis.local',
    role: 'admin',
    tenantId: config.tenantId,
    exp: Date.now() + 3600000,
    createdAt: Date.now(),
  };
  const sealed = sealSession(validSession, config.sessionSecret);
  const authReq: any = {
    url: '/api/auth/me',
    method: 'GET',
    headers: {
      cookie: `aegis_session=${sealed}`,
    },
  };

  const handledAuth = authHandler.handleAuthRequest(authReq, mockRes);
  assert.equal(handledAuth, true);
  assert.equal(statusCode, 200);
  const authJson = JSON.parse(responseData);
  assert.equal(authJson.authenticated, true);
  assert.equal(authJson.user.id, 'usr_admin_ok');
  assert.equal(authJson.user.role, 'admin');
});

test('Pure BFF AuthHandler — Handles /api/auth/login in standalone demo mode (GET & POST)', () => {
  const config: any = {
    tenantId: '00000000-0000-0000-0000-000000000001',
    sessionSecret: 'secret_key_for_unit_tests_32_bytes!',
  };
  const authHandler = new BffAuthHandler(config);

  // 1. GET /api/auth/login -> 302 Redirect vers /app/ avec Set-Cookie
  let statusCode = 0;
  let headers: Record<string, string> = {};
  const mockResGet: any = {
    setHeader: (k: string, v: string) => { headers[k] = v; },
    writeHead: (code: number, hdrs?: Record<string, string>) => {
      statusCode = code;
      if (hdrs) headers = { ...headers, ...hdrs };
    },
    end: () => {},
  };

  const getReq: any = { url: '/api/auth/login', method: 'GET', headers: {} };
  const handledGet = authHandler.handleAuthRequest(getReq, mockResGet);
  assert.equal(handledGet, true);
  assert.equal(statusCode, 302);
  assert.equal(headers['Location'], '/app/');
  assert.ok(headers['Set-Cookie'].includes('aegis_session='));

  // 2. POST /api/auth/login avec JSON -> 200 JSON avec Set-Cookie et redirect
  let postStatusCode = 0;
  let postHeaders: Record<string, string> = {};
  let postPayload = '';
  const mockResPost: any = {
    setHeader: (k: string, v: string) => { postHeaders[k] = v; },
    writeHead: (code: number, hdrs?: Record<string, string>) => {
      postStatusCode = code;
      if (hdrs) postHeaders = { ...postHeaders, ...hdrs };
    },
    end: (data: string) => { postPayload = data; },
  };

  const postReq: any = {
    url: '/api/auth/login',
    method: 'POST',
    headers: { accept: 'application/json' },
  };
  const handledPost = authHandler.handleAuthRequest(postReq, mockResPost);
  assert.equal(handledPost, true);
  assert.equal(postStatusCode, 200);
  assert.ok(postHeaders['Set-Cookie'].includes('aegis_session='));
  const postJson = JSON.parse(postPayload);
  assert.equal(postJson.ok, true);
  assert.equal(postJson.redirect, '/app/');
});

test('Pure BFF AuthHandler — Handles /api/auth/config and Keycloak SLO /api/auth/logout', () => {
  const config: any = {
    tenantId: '00000000-0000-0000-0000-000000000001',
    sessionSecret: 'secret_key_for_unit_tests_32_bytes!',
  };
  const oidcConfig = {
    issuerUrl: 'https://auth.aivo.fr/realms/aegis',
    clientId: 'aegis-cockpit',
  };
  const authHandler = new BffAuthHandler(config, oidcConfig);

  // 1. GET /api/auth/config
  let configStatus = 0;
  let configData = '';
  const mockResConfig: any = {
    writeHead: (c: number) => { configStatus = c; },
    end: (d: string) => { configData = d; },
  };
  const configReq: any = { url: '/api/auth/config', method: 'GET', headers: {} };
  assert.equal(authHandler.handleAuthRequest(configReq, mockResConfig), true);
  assert.equal(configStatus, 200);
  const cfg = JSON.parse(configData);
  assert.equal(cfg.oidc_active, true);
  assert.equal(cfg.issuer_url, 'https://auth.aivo.fr/realms/aegis');

  // 2. POST /api/auth/logout with Keycloak SLO URL
  let logoutStatus = 0;
  let logoutData = '';
  let logoutHeaders: any = {};
  const mockResLogout: any = {
    writeHead: (c: number, hdrs?: any) => {
      logoutStatus = c;
      if (hdrs) logoutHeaders = hdrs;
    },
    end: (d: string) => { logoutData = d; },
  };
  const logoutReq: any = {
    url: '/api/auth/logout',
    method: 'POST',
    headers: { host: 'aegis.aivo.fr' },
  };
  assert.equal(authHandler.handleAuthRequest(logoutReq, mockResLogout), true);
  assert.equal(logoutStatus, 200);
  assert.ok(logoutHeaders['Set-Cookie'].includes('Max-Age=0'));
  const logoutJson = JSON.parse(logoutData);
  assert.equal(logoutJson.status, 'success');
  assert.ok(logoutJson.logout_url.includes('protocol/openid-connect/logout'));
  assert.ok(logoutJson.logout_url.includes('client_id=aegis-cockpit'));
});

test('Aegis Gate PEP — ForwardAuth Endpoint (/_aegis/verify)', async () => {
  const { createGateServer } = await import('../src/server.js');
  const { WafInspector } = await import('../src/engine/inspector.js');
  const { IpReputationManager } = await import('../src/quarantine/ip-reputation.js');
  const config = {
    port: 8000,
    backendUrl: 'http://backend:80',
    webUrl: 'http://web:80',
    telemetryUrl: 'http://backend:80/api/v1/gate/telemetry/ingress',
    tenantId: '00000000-0000-0000-0000-000000000001',
    sessionSecret: 'test_secret_for_sovereign_bff_key_32!',
    defaultMaxPayloadBytes: 32768,
    defaultProtectionEnabled: true,
    upstreamRouting: {},
  };
  const { createDefaultRuleRegistry } = await import('../src/rules/default-rules.js');
  const ipRep = new IpReputationManager();
  const ruleRegistry = createDefaultRuleRegistry();
  const state = { protectionEnabled: true, maxPayloadBytes: 32768 };
  const inspector = new WafInspector(ruleRegistry, ipRep, () => state.maxPayloadBytes);
  const mockTelemetry: any = { send: () => {} };
  const mockForwarder: any = { forward: () => {} };

  const server = createGateServer(config, inspector, ipRep, mockTelemetry, mockForwarder, state);

  // 1. Requête légitime vérifiée par Traefik ForwardAuth -> 200 OK
  let verifiedCode = 0;
  const mockResAuth: any = {
    setHeader: () => {},
    writeHead: (c: number) => { verifiedCode = c; },
    end: () => {},
  };
  const mockReqAuth: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/api/v1/workorders',
      'x-forwarded-host': 'api.aivo.fr',
      'x-forwarded-for': '1.2.3.4',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqAuth, mockResAuth);
  assert.equal(verifiedCode, 200, 'Legitimate request should return 200 via ForwardAuth');

  // 2. Requête d'attaque interceptée par Traefik ForwardAuth -> 403 Forbidden
  let blockedCode = 0;
  let blockedBody = '';
  const mockResBlock: any = {
    setHeader: () => {},
    writeHead: (c: number) => { blockedCode = c; },
    end: (d: string) => { blockedBody = d; },
  };
  const mockReqBlock: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/wp-login.php',
      'x-forwarded-host': 'app.aivo.fr',
      'x-forwarded-for': '185.220.101.5',
      'user-agent': 'sqlmap/1.5',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqBlock, mockResBlock);
  assert.equal(blockedCode, 403, 'Malicious probe should return 403 via ForwardAuth');
  const blockJson = JSON.parse(blockedBody);
  assert.equal(blockJson.verdict, 'BLOCKED');

  // 3. Test de non-régression : Requête d'attaque testée depuis l'IP admin SOC -> Doit être bloquée (403)
  let adminBlockedCode = 0;
  let adminBlockedBody = '';
  const mockResAdminBlock: any = {
    setHeader: () => {},
    writeHead: (c: number) => { adminBlockedCode = c; },
    end: (d: string) => { adminBlockedBody = d; },
  };
  const mockReqAdminBlock: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/.env',
      'x-forwarded-host': 'nicolas.baud.dev',
      'x-forwarded-for': '198.51.100.10',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqAdminBlock, mockResAdminBlock);
  assert.equal(adminBlockedCode, 403, 'Admin pentest probe must still be blocked by ForwardAuth');
  const adminBlockJson = JSON.parse(adminBlockedBody);
  assert.equal(adminBlockJson.verdict, 'BLOCKED');
  assert.equal(adminBlockJson.threat_detected, 'PATH_TRAVERSAL_LFI');

  // 4. Passerelle Docker interne (172.17.0.1) : Bloque 4 attaques consécutives sans auto-bannir la passerelle
  for (let i = 0; i < 4; i++) {
    let gwCode = 0;
    const mockResGw: any = {
      setHeader: () => {},
      writeHead: (c: number) => { gwCode = c; },
      end: () => {},
    };
    const mockReqGw: any = {
      url: '/_aegis/verify',
      method: 'GET',
      headers: {
        'x-forwarded-method': 'GET',
        'x-forwarded-uri': '/.env',
        'x-forwarded-host': 'aivo.fr',
        'x-forwarded-for': '172.17.0.1',
      },
      socket: { remoteAddress: '172.17.0.1' },
      on: () => {},
    };
    server.emit('request', mockReqGw, mockResGw);
    assert.equal(gwCode, 403, `Docker gateway attack #${i + 1} must be blocked`);
  }
  assert.equal(ipRep.isBanned('172.17.0.1'), false, 'Docker bridge gateway 172.17.0.1 must never be auto-jailed');

  // 5. Mode Stealth 403 Anti-LLM : Masque la règle interne au client externe tout en gardant le verdict BLOCKED
  let stealthCode = 0;
  let stealthBody = '';
  const mockResStealth: any = {
    setHeader: () => {},
    writeHead: (c: number) => { stealthCode = c; },
    end: (d: string) => { stealthBody = d; },
  };
  const mockReqStealth: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/swagger.json',
      'x-forwarded-host': 'api.aivo.fr',
      'x-forwarded-for': '198.51.100.91',
      'x-aegis-stealth': 'true',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqStealth, mockResStealth);
  assert.equal(stealthCode, 403);
  const stealthJson = JSON.parse(stealthBody);
  assert.equal(stealthJson.threat_detected, 'SECURITY_POLICY_VIOLATION');
  assert.equal(stealthJson.risk_score, undefined);

  // 6. Leurre Canary Honeypot (/.env.canary) suivi du rejeu Canary Tripwire -> Auto-Ban immédiat
  let canaryTrapCode = 0;
  let canaryTrapBody = '';
  const mockResCanary: any = {
    setHeader: () => {},
    writeHead: (c: number) => { canaryTrapCode = c; },
    end: (d: string) => { canaryTrapBody = d; },
  };
  const mockReqCanary: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/.env.canary',
      'x-forwarded-host': 'aivo.fr',
      'x-forwarded-for': '198.51.100.92',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqCanary, mockResCanary);
  assert.equal(canaryTrapCode, 200);
  assert.ok(canaryTrapBody.includes('ak_live_aegis_canary_9f8e7d6c5b4a3210'));

  // Rejeu du jeton Canary par l'agent ARTEX -> 403 + Bannissement immédiat de l'IP
  let tripwireCode = 0;
  const mockResTripwire: any = {
    setHeader: () => {},
    writeHead: (c: number) => { tripwireCode = c; },
    end: () => {},
  };
  const mockReqTripwire: any = {
    url: '/_aegis/verify',
    method: 'GET',
    headers: {
      'x-forwarded-method': 'GET',
      'x-forwarded-uri': '/api/v1/data',
      'x-forwarded-host': 'aivo.fr',
      'x-forwarded-for': '198.51.100.92',
      authorization: 'Bearer ak_live_aegis_canary_9f8e7d6c5b4a3210',
    },
    socket: { remoteAddress: '127.0.0.1' },
    on: () => {},
  };
  server.emit('request', mockReqTripwire, mockResTripwire);
  assert.equal(tripwireCode, 403);
  assert.equal(ipRep.isBanned('198.51.100.92'), true, 'Attacker replaying a Canary Token must be banned immediately');
  ipRep.unban('198.51.100.92');
});

test('Pure BFF Session — Cryptographic Context-Binding Anti-Token Replay (Verrou n°5-Bis v1.3)', async () => {
  const { computeClientContextHash, sealSession, extractSessionFromRequest } = await import('../src/bff/session.js');
  const secret = 'context_binding_sovereign_secret_32b!';
  const legUa = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0';
  const legIp = '82.64.12.45';

  const session: BffUserSession = {
    id: 'usr_ctx_bound',
    name: 'Admin Context Bound',
    email: 'admin@aivo.fr',
    role: 'admin',
    tenantId: '00000000-0000-0000-0000-000000000001',
    exp: Date.now() + 60000,
    createdAt: Date.now(),
    ctxHash: computeClientContextHash(legUa, legIp),
  };

  const sealed = sealSession(session, secret);
  const cookieHeader = `aegis_session=${sealed}`;

  // 1. Même User-Agent et même sous-réseau /24 (82.64.12.99) -> Autorisé
  const validExtract = extractSessionFromRequest(cookieHeader, secret, {
    userAgent: legUa,
    clientIp: '82.64.12.99',
  });
  assert.ok(validExtract !== null);
  assert.equal(validExtract?.id, 'usr_ctx_bound');

  // 2. Rejeu par un Worker ARTEX avec un autre User-Agent -> Rejeté (null)
  const hijackedUa = extractSessionFromRequest(cookieHeader, secret, {
    userAgent: 'Go-http-client/2.0',
    clientIp: legIp,
  });
  assert.equal(hijackedUa, null, 'Session replayed with different User-Agent must be rejected');

  // 3. Rejeu depuis un sous-réseau IP distant (185.220.101.5) -> Rejeté (null)
  const hijackedIp = extractSessionFromRequest(cookieHeader, secret, {
    userAgent: legUa,
    clientIp: '185.220.101.5',
  });
  assert.equal(hijackedIp, null, 'Session replayed from different /24 public subnet must be rejected');
});


