import http from 'node:http';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GateConfig } from '../config.js';
import {
  computeClientContextHash,
  extractSessionFromRequest,
  sealSession,
  serializeSessionCookie,
  serializeLogoutCookie,
  type BffUserSession,
  type SessionClientContext
} from './session.js';

export interface BffOidcConfig {
  issuerUrl?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  endSessionEndpoint?: string;
}

export class BffAuthHandler {
  private config: GateConfig;
  private oidcConfig: BffOidcConfig;
  private pendingStates: Map<string, { codeVerifier: string; createdAt: number }> = new Map();

  private getRequestContext(req: IncomingMessage): SessionClientContext {
    const forwarded = req.headers['x-forwarded-for'];
    const clientIp = typeof forwarded === 'string'
      ? forwarded.split(',')[0].trim()
      : (req.socket?.remoteAddress || '127.0.0.1');
    return {
      userAgent: (req.headers['user-agent'] as string) || 'unknown',
      clientIp
    };
  }

  constructor(config: GateConfig, oidcConfig: BffOidcConfig = {}) {
    this.config = config;
    this.oidcConfig = {
      issuerUrl: oidcConfig.issuerUrl || process.env.OIDC_ISSUER_URL || '',
      clientId: oidcConfig.clientId || process.env.OIDC_CLIENT_ID || 'aegis-cockpit',
      clientSecret: oidcConfig.clientSecret || process.env.OIDC_CLIENT_SECRET || '',
      redirectUri: oidcConfig.redirectUri || process.env.OIDC_REDIRECT_URI || '',
      authorizationEndpoint: oidcConfig.authorizationEndpoint || process.env.OIDC_AUTHORIZATION_ENDPOINT || '',
      tokenEndpoint: oidcConfig.tokenEndpoint || process.env.OIDC_TOKEN_ENDPOINT || '',
      endSessionEndpoint: oidcConfig.endSessionEndpoint || process.env.OIDC_END_SESSION_ENDPOINT || ''
    };
  }

  /**
   * Résout dynamiquement l'endpoint d'autorisation OIDC selon le fournisseur (Keycloak, Okta, Authelia, Authentik, etc.)
   */
  public getAuthorizationEndpoint(): string {
    if (this.oidcConfig.authorizationEndpoint) {
      return this.oidcConfig.authorizationEndpoint;
    }
    const issuer = (this.oidcConfig.issuerUrl || '').replace(/\/$/, '');
    if (issuer.includes('/realms/')) {
      return `${issuer}/protocol/openid-connect/auth`;
    }
    if (issuer.includes('okta.com')) {
      return `${issuer}/v1/authorize`;
    }
    return `${issuer}/authorize`;
  }

  /**
   * Résout dynamiquement l'endpoint de fin de session / déconnexion (SLO) selon le fournisseur
   */
  public getEndSessionEndpoint(): string {
    if (this.oidcConfig.endSessionEndpoint) {
      return this.oidcConfig.endSessionEndpoint;
    }
    const issuer = (this.oidcConfig.issuerUrl || '').replace(/\/$/, '');
    if (issuer.includes('/realms/')) {
      return `${issuer}/protocol/openid-connect/logout`;
    }
    if (issuer.includes('okta.com')) {
      return `${issuer}/v1/logout`;
    }
    return `${issuer}/logout`;
  }

  /**
   * Vérifie si la requête est en HTTPS ou protégée derrière un reverse-proxy TLS.
   */
  private isSecure(req: IncomingMessage): boolean {
    const proto = req.headers['x-forwarded-proto'];
    if (typeof proto === 'string' && proto.includes('https')) return true;
    return Boolean((req.socket as any)?.encrypted);
  }

  /**
   * Résout l'origine publique du site (ex: https://aegis.aivo.fr)
   * Priorité : OIDC_REDIRECT_URI (configurée explicitement), puis X-Forwarded-Host, puis Host
   */
  public getPublicOrigin(req: IncomingMessage, isHttps: boolean): string {
    if (this.oidcConfig.redirectUri) {
      try {
        return new URL(this.oidcConfig.redirectUri).origin;
      } catch {}
    }
    const rawHost = (req.headers['x-forwarded-host'] as string) || req.headers.host || 'aegis.aivo.fr';
    const cleanHost = rawHost.split(',')[0].trim().split(':')[0]; // Exclure tout port interne
    const proto = isHttps ? 'https' : 'http';
    return `${proto}://${cleanHost}`;
  }

  /**
   * Intercepte et traite les routes d'authentification /api/auth/*
   * Retourne true si la requête a été consommée et terminée.
   */
  public handleAuthRequest(req: IncomingMessage, res: ServerResponse): boolean {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (!pathname.startsWith('/api/auth/')) {
      return false;
    }

    const sessionSecret = this.config.sessionSecret;
    const isHttps = this.isSecure(req);

    // 0. GET /api/auth/config : Informations OIDC & SSO actives
    if (pathname === '/api/auth/config' && req.method === 'GET') {
      const isOidcActive = Boolean(this.oidcConfig.issuerUrl && this.oidcConfig.clientId);
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      });
      res.end(
        JSON.stringify({
          oidc_active: isOidcActive,
          issuer_url: this.oidcConfig.issuerUrl || null,
          client_id: this.oidcConfig.clientId || null
        })
      );
      return true;
    }

    // 1. GET ou POST /api/auth/login : Démarrage du flux de connexion
    if (pathname === '/api/auth/login' && (req.method === 'GET' || req.method === 'POST' || req.method === 'HEAD')) {
      if (req.method === 'HEAD') {
        res.writeHead(200);
        res.end();
        return true;
      }

      const isOidcActive = Boolean(this.oidcConfig.issuerUrl && this.oidcConfig.clientId);

      if (!isOidcActive) {
        if (!this.config.allowDemoAuth) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: false,
              error: 'OIDC_NOT_CONFIGURED',
              message: 'Authentification OIDC requise (définir OIDC_ISSUER_URL ou AEGIS_ALLOW_DEMO_AUTH=true en environnement local uniquement).'
            })
          );
          return true;
        }
        // Mode Standalone Démo (explicitement activé via AEGIS_ALLOW_DEMO_AUTH=true hors mode CTF)
        const reqCtx = this.getRequestContext(req);
        const sessionData: BffUserSession = {
          id: 'usr_sovereign_admin',
          name: 'Administrateur SOC Souverain',
          email: 'admin@aegis.local',
          role: 'admin',
          tenantId: this.config.tenantId,
          exp: Date.now() + 86400000, // 24 heures
          createdAt: Date.now(),
          ctxHash: computeClientContextHash(reqCtx.userAgent, reqCtx.clientIp)
        };

        const sealedCookie = sealSession(sessionData, sessionSecret);
        const cookieHeader = serializeSessionCookie(sealedCookie, isHttps, 86400);

        const accept = req.headers.accept || '';
        if (accept.includes('application/json') && req.method === 'POST') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': cookieHeader
          });
          res.end(JSON.stringify({ ok: true, authenticated: true, redirect: '/app/' }));
          return true;
        }

        res.writeHead(302, {
          'Set-Cookie': cookieHeader,
          Location: '/app/'
        });
        res.end();
        return true;
      }

      // Mode OIDC PKCE Standard
      const state = crypto.randomBytes(16).toString('hex');
      const codeVerifier = crypto.randomBytes(32).toString('base64url');
      const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

      this.pendingStates.set(state, { codeVerifier, createdAt: Date.now() });

      // Nettoyer les vieux états de plus de 10 minutes
      const tenMinutesAgo = Date.now() - 600000;
      for (const [st, val] of this.pendingStates.entries()) {
        if (val.createdAt < tenMinutesAgo) this.pendingStates.delete(st);
      }

      const publicOrigin = this.getPublicOrigin(req, isHttps);
      const redirectUri = this.oidcConfig.redirectUri || `${publicOrigin}/api/auth/callback`;
      const authUrl = new URL(this.getAuthorizationEndpoint());
      authUrl.searchParams.append('client_id', this.oidcConfig.clientId || 'aegis-cockpit');
      authUrl.searchParams.append('redirect_uri', redirectUri);
      authUrl.searchParams.append('response_type', 'code');
      authUrl.searchParams.append('scope', 'openid email profile');
      authUrl.searchParams.append('state', state);
      authUrl.searchParams.append('code_challenge', codeChallenge);
      authUrl.searchParams.append('code_challenge_method', 'S256');

      const accept = req.headers.accept || '';
      if (accept.includes('application/json') && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, redirect: authUrl.toString() }));
        return true;
      }

      res.writeHead(302, { Location: authUrl.toString() });
      res.end();
      return true;
    }

    // 2. GET /api/auth/callback : Échange de jetons PKCE réel et scellement du Cookie
    if (pathname === '/api/auth/callback' && req.method === 'GET') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const reqCtx = this.getRequestContext(req);
      const ctxHash = computeClientContextHash(reqCtx.userAgent, reqCtx.clientIp);

      // Mode démo explicite uniquement (jamais actif par défaut ni en mode CTF)
      if (!this.oidcConfig.issuerUrl) {
        if (!this.config.allowDemoAuth) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'OIDC_NOT_CONFIGURED' }));
          return true;
        }
        const sessionData: BffUserSession = {
          id: 'usr_sovereign_admin',
          name: 'Administrateur SOC Souverain',
          email: 'admin@aegis.local',
          role: 'admin',
          tenantId: this.config.tenantId,
          exp: Date.now() + 86400000,
          createdAt: Date.now(),
          ctxHash
        };
        const sealedCookie = sealSession(sessionData, sessionSecret);
        const cookieHeader = serializeSessionCookie(sealedCookie, isHttps, 86400);
        res.writeHead(302, { 'Set-Cookie': cookieHeader, Location: '/app/' });
        res.end();
        return true;
      }

      // Validation obligatoire du state PKCE anti-CSRF / anti-forge
      const pending = state ? this.pendingStates.get(state) : undefined;
      if (!code || !state || !pending || Date.now() - pending.createdAt > 600000) {
        if (state) this.pendingStates.delete(state);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'INVALID_OIDC_STATE_OR_CODE' }));
        return true;
      }
      this.pendingStates.delete(state);

      // Échange réel du code d'autorisation PKCE auprès du fournisseur OIDC
      const tokenEndpoint =
        this.oidcConfig.tokenEndpoint ||
        (this.oidcConfig.issuerUrl.includes('/realms/')
          ? `${this.oidcConfig.issuerUrl.replace(/\/$/, '')}/protocol/openid-connect/token`
          : `${this.oidcConfig.issuerUrl.replace(/\/$/, '')}/token`);
      const publicOrigin = this.getPublicOrigin(req, isHttps);
      const redirectUri = this.oidcConfig.redirectUri || `${publicOrigin}/api/auth/callback`;

      const formBody = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: this.oidcConfig.clientId || 'aegis-cockpit',
        code_verifier: pending.codeVerifier
      });
      if (this.oidcConfig.clientSecret) {
        formBody.set('client_secret', this.oidcConfig.clientSecret);
      }

      fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formBody.toString()
      })
        .then(async tokenRes => {
          if (!tokenRes.ok) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'OIDC_TOKEN_EXCHANGE_FAILED' }));
            return;
          }
          const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string };
          if (!tokens.id_token && !tokens.access_token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'OIDC_MISSING_TOKEN' }));
            return;
          }
          let claims: Record<string, unknown> = {};
          if (tokens.id_token && tokens.id_token.split('.').length === 3) {
            try {
              claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64url').toString('utf8'));
            } catch {
              claims = {};
            }
          }
          const roles = Array.isArray(claims.roles)
            ? claims.roles.map(String)
            : Array.isArray((claims.realm_access as { roles?: unknown[] } | undefined)?.roles)
              ? ((claims.realm_access as { roles: unknown[] }).roles).map(String)
              : [];
          const resolvedRole: BffUserSession['role'] = roles.includes('admin')
            ? 'admin'
            : roles.includes('secops')
              ? 'secops'
              : 'viewer';

          const sessionData: BffUserSession = {
            id: String(claims.sub || `usr_${crypto.randomBytes(4).toString('hex')}`),
            name: String(claims.name || claims.preferred_username || 'Opérateur SOC'),
            email: String(claims.email || 'operator@aegis.local'),
            role: resolvedRole,
            tenantId: this.config.tenantId,
            exp: Date.now() + 86400000,
            createdAt: Date.now(),
            ctxHash
          };

          const sealedCookie = sealSession(sessionData, sessionSecret);
          const cookieHeader = serializeSessionCookie(sealedCookie, isHttps, 86400);
          res.writeHead(302, { 'Set-Cookie': cookieHeader, Location: '/app/' });
          res.end();
        })
        .catch(() => {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'OIDC_PROVIDER_UNREACHABLE' }));
        });
      return true;
    }

    // 3. GET /api/auth/me ou /api/auth/user : État de la session courante
    if ((pathname === '/api/auth/me' || pathname === '/api/auth/user') && req.method === 'GET') {
      const session = extractSessionFromRequest(req.headers.cookie, sessionSecret, this.getRequestContext(req));

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      if (!session) {
        res.writeHead(401);
        res.end(
          JSON.stringify({
            authenticated: false,
            message: 'Session non authentifiée, expirée ou empreinte Context-Binding invalide'
          })
        );
        return true;
      }

      res.writeHead(200);
      res.end(
        JSON.stringify({
          authenticated: true,
          user: {
            id: session.id,
            name: session.name,
            email: session.email,
            role: session.role,
            tenant_id: session.tenantId,
            expires_at: new Date(session.exp).toISOString()
          }
        })
      );
      return true;
    }

    // 4. POST ou GET /api/auth/logout : Révocation de session & Single Logout Keycloak (SLO)
    if (pathname === '/api/auth/logout' && (req.method === 'POST' || req.method === 'GET')) {
      const logoutCookie = serializeLogoutCookie(isHttps);
      const isOidcActive = Boolean(this.oidcConfig.issuerUrl && this.oidcConfig.clientId);

      const publicOrigin = this.getPublicOrigin(req, isHttps);
      const postLogoutRedirect = `${publicOrigin}/api/auth/login`;

      let logoutUrl = '/api/auth/login';
      if (isOidcActive) {
        const endSessionUrl = new URL(this.getEndSessionEndpoint());
        endSessionUrl.searchParams.append('post_logout_redirect_uri', postLogoutRedirect);
        endSessionUrl.searchParams.append('client_id', this.oidcConfig.clientId || 'aegis-cockpit');
        logoutUrl = endSessionUrl.toString();
      }

      if (req.method === 'GET') {
        res.writeHead(302, {
          'Set-Cookie': logoutCookie,
          Location: logoutUrl
        });
        res.end();
        return true;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': logoutCookie
      });
      res.end(
        JSON.stringify({
          status: 'success',
          message: 'Session révoquée avec succès',
          logout_url: logoutUrl
        })
      );
      return true;
    }

    // 5. POST /api/auth/refresh : Rafraîchissement de session
    if (pathname === '/api/auth/refresh' && req.method === 'POST') {
      const session = extractSessionFromRequest(req.headers.cookie, sessionSecret, this.getRequestContext(req));
      if (!session) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: 'Session invalide' }));
        return true;
      }

      session.exp = Date.now() + 86400000;
      const newSealed = sealSession(session, sessionSecret);
      const cookieHeader = serializeSessionCookie(newSealed, isHttps, 86400);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': cookieHeader
      });
      res.end(
        JSON.stringify({
          status: 'success',
          user: {
            id: session.id,
            role: session.role,
            tenant_id: session.tenantId,
            expires_at: new Date(session.exp).toISOString()
          }
        })
      );
      return true;
    }

    // Endpoint d'authentification non reconnu
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found', endpoint: pathname }));
    return true;
  }

  /**
   * Enrichit les en-têtes HTTP envoyés au backend applicatif Go
   * avec les revendications d'identité extraites du Cookie HttpOnly chiffré.
   */
  public enrichBackendHeaders(req: IncomingMessage, targetHeaders: http.OutgoingHttpHeaders): void {
    const session = extractSessionFromRequest(
      req.headers.cookie,
      this.config.sessionSecret,
      this.getRequestContext(req)
    );
    if (session) {
      targetHeaders['x-aegis-tenant-id'] = session.tenantId;
      targetHeaders['x-aegis-user-id'] = session.id;
      targetHeaders['x-aegis-user-role'] = session.role;
      targetHeaders['x-aegis-user-email'] = session.email;
      if (this.config.internalAdminToken) {
        targetHeaders['x-aegis-internal-token'] = this.config.internalAdminToken;
      }
      // Injection d'un jeton d'authentification interne pour le Core Go
      targetHeaders['authorization'] = `Bearer aegis_token_${session.tenantId}_${session.id}`;
    }
  }
}
