/**
 * Calcul d'Entropie de Shannon pour la détection de DGA (Domain Generation Algorithms)
 * et d'exfiltration DNS (tunneling hex/base64)
 */
export function calculateShannonEntropy(str: string): number {
  const parts = str.toLowerCase().split('.');
  const targetLabel = parts.length > 1 ? parts.slice(0, -1).join('') : str.toLowerCase();
  const cleanStr = targetLabel.replace(/[^a-z0-9]/g, '');
  if (!cleanStr.length) return 0;

  const len = cleanStr.length;
  const frequencies: Record<string, number> = {};
  for (const char of cleanStr) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(2));
}
