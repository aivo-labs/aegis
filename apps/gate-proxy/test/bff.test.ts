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

