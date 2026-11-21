import crypto from 'node:crypto';

export interface BffUserSession {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'secops' | 'auditor' | 'viewer';
  tenantId: string;
  exp: number; // Timestamp Unix en ms
  createdAt: number;
  ctxHash?: string; // Verrou n°5-Bis (v1.3 « Anti-Artex ») : Empreinte Context-Binding (UA + Sous-réseau IP)
}

export interface SessionClientContext {
  userAgent?: string;
  clientIp?: string;
}

export const SESSION_COOKIE_NAME = '__Host-aegis_session';
export const FALLBACK_COOKIE_NAME = 'aegis_session';

const PRIVATE_OR_LOCAL_IP_REGEX =
  /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1$|localhost$|fe80:|fc00:|fd00:)/i;

/**
 * Extrait un préfixe de sous-réseau stable (/24 pour IPv4 public, /64 pour IPv6 public, 'local' pour RFC1918/loopback)
 */
export function extractSubnetPrefix(ip?: string): string {
  const clean = (ip || '').replace(/^::ffff:/, '').trim();
  if (!clean || PRIVATE_OR_LOCAL_IP_REGEX.test(clean)) {
    return 'local-net';
  }
  if (clean.includes('.')) {
    const parts = clean.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  }
  if (clean.includes(':')) {
    const parts = clean.split(':').slice(0, 4);
    return `${parts.join(':')}::/64`;
  }
  return 'local-net';
}

/**
 * Verrou n°5-Bis (v1.3 « Anti-Artex ») : Calcule l'empreinte cryptographique du contexte client
 * (User-Agent normalisé + préfixe sous-réseau IP) pour empêcher le rejeu de cookies volés par un Agent Worker.
 */
export function computeClientContextHash(userAgent?: string, clientIp?: string): string {
  const normUa = (userAgent || 'unknown').trim().toLowerCase();
  const subnet = extractSubnetPrefix(clientIp);
  return crypto
    .createHash('sha256')
    .update(`aegis_ctx_v1|${normUa}|${subnet}`)
    .digest('hex')
    .substring(0, 16);
}

/**
 * Vérifie que la session déchiffrée correspond au contexte client courant (si un ctxHash y est scellé).
 */
export function verifySessionContext(
  session: BffUserSession,
  userAgent?: string,
  clientIp?: string
): boolean {
  if (!session.ctxHash) return true;
  const expected = computeClientContextHash(userAgent, clientIp);
  return session.ctxHash === expected;
}

/**
 * Dérive une clé cryptographique de 32 octets (AES-256) à partir du secret configuré.
 */
function deriveKey(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret || 'aegis_default_sovereign_secret_key_32b!').digest();
}

/**
 * Chiffre et scelle une session utilisateur avec AES-256-GCM (Chiffrement Authentifié avec données associées).
 */
export function sealSession(session: BffUserSession, secret: string): string {
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(12); // Standard 96 bits pour GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const plaintext = Buffer.from(JSON.stringify(session), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Assemblage binaire : IV (12) + AuthTag (16) + Ciphertext
  const combined = Buffer.concat([iv, authTag, ciphertext]);
  return combined.toString('base64url');
}

/**
 * Déchiffre et vérifie l'intégrité de la session utilisateur.
 * Retourne null si le cookie est falsifié, altéré ou expiré.
 */
export function unsealSession(sealed: string, secret: string): BffUserSession | null {
  if (!sealed || typeof sealed !== 'string') return null;

  try {
    const combined = Buffer.from(sealed, 'base64url');
    if (combined.length < 28) return null; // 12 (IV) + 16 (Tag) minimum

    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const ciphertext = combined.subarray(28);

    const key = deriveKey(secret);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const session: BffUserSession = JSON.parse(decrypted.toString('utf8'));

    // Vérification de la date d'expiration
    if (!session.exp || session.exp < Date.now()) {
      return null;
    }

    return session;
  } catch {
    // Échec d'authentification GCM (altération ou mauvaise clé)
    return null;
  }
}

/**
 * Parse l'en-tête Cookie HTTP.
 */
export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;

  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx !== -1) {
      const key = pair.substring(0, idx).trim();
      const val = pair.substring(idx + 1).trim();
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

/**
 * Extrait la session depuis les cookies de la requête (supporte __Host-aegis_session ou aegis_session en dev).
 * Si clientContext est fourni et que la session possède un ctxHash, vérifie la liaison cryptographique (Anti-Replay).
 */
export function extractSessionFromRequest(
  cookieHeader: string | undefined,
  secret: string,
  clientContext?: SessionClientContext
): BffUserSession | null {
  const cookies = parseCookies(cookieHeader);
  const rawCookie = cookies[SESSION_COOKIE_NAME] || cookies[FALLBACK_COOKIE_NAME];
  if (!rawCookie) return null;
  const session = unsealSession(rawCookie, secret);
  if (!session) return null;
  if (clientContext && session.ctxHash) {
    if (!verifySessionContext(session, clientContext.userAgent, clientContext.clientIp)) {
      return null;
    }
  }
  return session;
}

/**
 * Sérialise le cookie de session pour l'en-tête Set-Cookie.
 */
export function serializeSessionCookie(
  cookieValue: string,
  isSecure: boolean,
  maxAgeSeconds = 86400
): string {
  // Utiliser le préfixe sécurisé __Host- si HTTPS est activé, sinon fallback compatible HTTP/localhost
  const name = isSecure ? SESSION_COOKIE_NAME : FALLBACK_COOKIE_NAME;
  const parts = [
    `${name}=${encodeURIComponent(cookieValue)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`
  ];

  if (isSecure) {
    parts.push('Secure');
  }

  return parts.join('; ');
}

/**
 * Génère le header Set-Cookie pour expirer la session (Logout).
 */
export function serializeLogoutCookie(isSecure: boolean): string {
  const name = isSecure ? SESSION_COOKIE_NAME : FALLBACK_COOKIE_NAME;
  const parts = [
    `${name}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  ];
  if (isSecure) parts.push('Secure');
  return parts.join('; ');
}
