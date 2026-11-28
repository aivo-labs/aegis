/**
 * Canonisation multi-encodage (Verrou n°2 Roadmap P1) :
 * 1. Décodage URL récursif (3 passes)
 * 2. Décodage des entités HTML (nommées, décimales &#97;, hexadécimales &#x61;)
 * 3. Décodage des séquences Hex (\x41) et Unicode (\u0041, %u0041)
 * 4. Normalisation des séparateurs de chemin (/./, //, ..\) anti-Path Traversal
 * 5. Décodage automatique et ré-injection des blocs Base64 suspects (>= 16 chars)
 * 6. Suppression des octets nuls (\0) et commentaires SQL inline (/*...*\/)
 */

const NAMED_HTML_ENTITIES: Record<string, string> = {
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&apos;': "'",
  '&#39;': "'",
  '&amp;': '&',
  '&sol;': '/',
  '&bsol;': '\\',
  '&colon;': ':',
  '&semi;': ';',
  '&equals;': '=',
  '&lpar;': '(',
  '&rpar;': ')',
  '&lcub;': '{',
  '&rcub;': '}',
  '&dollar;': '$'
};

const SUSPICIOUS_DECODED_B64_CONTENT =
  /[\s;|&$`<>(){}[\]'"\\/]|(?:select|union|insert|update|delete|drop|sleep|benchmark|cat|whoami|curl|wget|bash|sh|python|perl|php|eval|system|exec|jndi|ldap|rmi|passwd|shadow|allow_url_include|auto_prepend_file)/i;

export function decodeHtmlEntities(input: string): string {
  if (!input || !input.includes('&')) return input;

  let out = input.replace(
    /&(?:lt|gt|quot|apos|amp|sol|bsol|colon|semi|equals|lpar|rpar|lcub|rcub|dollar|#39);/gi,
    match => NAMED_HTML_ENTITIES[match.toLowerCase()] || match
  );

  // Entités numériques hexadécimales : &#x41; ou &#x41
  out = out.replace(/&#x([0-9a-fA-F]{1,4});?/g, (full, hex) => {
    const code = parseInt(hex, 16);
    return code >= 32 && code <= 126 ? String.fromCharCode(code) : full;
  });

  // Entités numériques décimales : &#65; ou &#65
  out = out.replace(/&#(\d{1,5});?/g, (full, dec) => {
    const code = parseInt(dec, 10);
    return code >= 32 && code <= 126 ? String.fromCharCode(code) : full;
  });

  return out;
}

export function decodeHexAndUnicodeEscapes(input: string): string {
  if (!input || (!input.includes('\\') && !input.includes('%u') && !input.includes('%U'))) {
    return input;
  }

  let out = input.replace(/\\x([0-9a-fA-F]{2})/g, (full, hex) => {
    const code = parseInt(hex, 16);
    return code >= 32 && code <= 126 ? String.fromCharCode(code) : full;
  });

  out = out.replace(/(?:\\u|%u)([0-9a-fA-F]{4})/gi, (full, hex) => {
    const code = parseInt(hex, 16);
    return code >= 32 && code <= 126 ? String.fromCharCode(code) : full;
  });

  return out;
}

export function normalizePathTraversals(input: string): string {
  if (!input) return input;
  return input
    // Normaliser ..\ et ..\.. en ../
    .replace(/\.\.\\+/g, '../')
    // Supprimer les segments /./ répétitifs
    .replace(/\/(?:\.\/)+/g, '/')
    // Réduire les barres obliques multiples (hors schémas protocolaires ://)
    .replace(/([^:])\/\/+/g, '$1/');
}

export function extractDecodedBase64Payloads(input: string): string[] {
  if (!input || input.length < 16) return [];

  const decodedPayloads: string[] = [];
  const b64Regex = /(?:^|[\s=:"'&?/,])([A-Za-z0-9+/]{16,}={0,2})(?=$|[\s"&',])/g;
  let match: RegExpExecArray | null;

  while ((match = b64Regex.exec(input)) !== null) {
    const candidate = match[1];
    if (candidate.length % 4 !== 0) continue;
    try {
      const buf = Buffer.from(candidate, 'base64');
      if (buf.length < 8) continue;
      const str = buf.toString('utf8');
      // Vérifier que le résultat décodé est composé uniquement de caractères ASCII imprimables
      if (/^[\x09\x0a\x0d\x20-\x7e]{8,}$/.test(str) && SUSPICIOUS_DECODED_B64_CONTENT.test(str)) {
        decodedPayloads.push(str);
      }
    } catch {
      // Ignorer bloc non-Base64
    }
  }

  return decodedPayloads;
}

export function canonicalizeInput(raw: string): string {
  let out = raw || '';

  // 1. Décodage URL récursif (3 passes)
  for (let i = 0; i < 3; i++) {
    try {
      const dec = decodeURIComponent(out);
      if (dec === out) break;
      out = dec;
    } catch {
      break;
    }
  }

  // 2. Décodage des séquences Hex (\x..) & Unicode (\u...., %u....)
  out = decodeHexAndUnicodeEscapes(out);

  // 3. Décodage des entités HTML (&lt;, &#x3c;, &#60;)
  out = decodeHtmlEntities(out);

  // 4. Normalisation des séparateurs de chemin (/./, //, ..\)
  out = normalizePathTraversals(out);

  // 5. Extraction et décodage des charges Base64 suspectes (avant conversion des '+' en espaces)
  const b64Payloads = extractDecodedBase64Payloads(out);
  if (b64Payloads.length > 0) {
    out = `${out} ${b64Payloads.join(' ')}`;
  }

  // 5-bis. Décodage des espaces form-urlencoded ('+' -> ' ') dans les query strings & formulaires
  // On conserve aussi la forme brute afin de ne pas casser les signatures exigeant un '+' littéral (ex: PHP2Shell %ad-d+)
  if (out.includes('+')) {
    out = `${out} ${out.replace(/\+/g, ' ')}`;
  }

  // 6. Purge des octets nuls, commentaires SQL inline et normalisation des espaces
  return out
    .replace(/\0/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\s+/g, ' ');
}
