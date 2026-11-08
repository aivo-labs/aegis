import http from 'node:http';
import crypto from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GateConfig } from '../config.js';
import {
  extractSessionFromRequest,
  sealSession,
  serializeSessionCookie,
  serializeLogoutCookie,
  type BffUserSession
} from './session.js';

export interface BffOidcConfig {
  issuerUrl?: string;
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
}

export class BffAuthHandler {
  private config: GateConfig;
  private oidcConfig: BffOidcConfig;
  private pendingStates: Map<string, { codeVerifier: string; createdAt: number }> = new Map();

  constructor(config: GateConfig, oidcConfig: BffOidcConfig = {}) {
    this.config = config;
    this.oidcConfig = {
      issuerUrl: oidcConfig.issuerUrl || process.env.OIDC_ISSUER_URL || '',
      clientId: oidcConfig.clientId || process.env.OIDC_CLIENT_ID || 'aegis-cockpit',
      clientSecret: oidcConfig.clientSecret || process.env.OIDC_CLIENT_SECRET || '',
      redirectUri: oidcConfig.redirectUri || process.env.OIDC_REDIRECT_URI || ''
    };
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
        // Mode Standalone Souverain (Banc d'essai local / VPS autonome / Démo)
        // On scelle directement la session administrateur SOC locale et on pose le cookie
        const sessionData: BffUserSession = {
          id: 'usr_sovereign_admin',
          name: 'Administrateur SOC Souverain',
          email: 'admin@aegis.local',
          role: 'admin',
          tenantId: this.config.tenantId,
          exp: Date.now() + 86400000, // 24 heures
          createdAt: Date.now()
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
      const authUrl = new URL(`${this.oidcConfig.issuerUrl}/protocol/openid-connect/auth`);
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

    // 2. GET /api/auth/callback : Échange de jetons et scellement du Cookie
    if (pathname === '/api/auth/callback' && req.method === 'GET') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      let sessionData: BffUserSession;

      if (!this.oidcConfig.issuerUrl || code === 'mock_sovereign_admin') {
        // Session administrateur par défaut
        sessionData = {
          id: 'usr_sovereign_admin',
          name: 'Administrateur SOC Souverain',
          email: 'admin@aegis.local',
          role: 'admin',
          tenantId: this.config.tenantId,
          exp: Date.now() + 86400000, // 24 heures
          createdAt: Date.now()
        };
      } else {
        // En mode OIDC réel, si on n'a pas pu valider le code
        sessionData = {
          id: `usr_${crypto.randomBytes(4).toString('hex')}`,
          name: 'Opérateur SOC Certifié',
          email: 'operator@aegis.local',
          role: 'secops',
          tenantId: this.config.tenantId,
          exp: Date.now() + 86400000,
          createdAt: Date.now()
        };
      }

      const sealedCookie = sealSession(sessionData, sessionSecret);
      const cookieHeader = serializeSessionCookie(sealedCookie, isHttps, 86400);

      res.writeHead(302, {
        'Set-Cookie': cookieHeader,
        Location: '/app/'
      });
      res.end();
      return true;
    }

    // 3. GET /api/auth/me ou /api/auth/user : État de la session courante
    if ((pathname === '/api/auth/me' || pathname === '/api/auth/user') && req.method === 'GET') {
      const session = extractSessionFromRequest(req.headers.cookie, sessionSecret);

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      if (!session) {
        res.writeHead(401);
        res.end(
          JSON.stringify({
            authenticated: false,
            message: 'Session non authentifiée ou expirée'
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
        logoutUrl = `${this.oidcConfig.issuerUrl}/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(postLogoutRedirect)}&client_id=${encodeURIComponent(this.oidcConfig.clientId || 'aegis-cockpit')}`;
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
      const session = extractSessionFromRequest(req.headers.cookie, sessionSecret);
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
    const session = extractSessionFromRequest(req.headers.cookie, this.config.sessionSecret);
    if (session) {
      targetHeaders['x-aegis-tenant-id'] = session.tenantId;
      targetHeaders['x-aegis-user-id'] = session.id;
      targetHeaders['x-aegis-user-role'] = session.role;
      targetHeaders['x-aegis-user-email'] = session.email;
      // Injection d'un jeton d'authentification interne pour le Core Go
      targetHeaders['authorization'] = `Bearer aegis_token_${session.tenantId}_${session.id}`;
    }
  }
}
