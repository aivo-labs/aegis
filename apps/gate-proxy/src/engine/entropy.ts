/**
 * Calcul rapide d'entropie de Shannon sur l'URI + Payload
 */
export function computeRequestEntropy(str: string): number {
  const sample = (str || '').slice(0, 512);
  if (!sample.length) return 2.1;
  const freq: Record<string, number> = {};
  for (const ch of sample) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = sample.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(2));
}
