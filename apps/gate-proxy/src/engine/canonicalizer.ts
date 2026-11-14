/**
 * Canonisation multi-encodage (Verrou n°2 Roadmap : Décodage URL récursif + suppression commentaires SQL)
 */
export function canonicalizeInput(raw: string): string {
  let out = raw || '';
  for (let i = 0; i < 3; i++) {
    try {
      const dec = decodeURIComponent(out);
      if (dec === out) break;
      out = dec;
    } catch {
      break;
    }
  }
  return out
    .replace(/\0/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\s+/g, ' ');
}
