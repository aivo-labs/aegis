/**
 * Décode le QNAME d'un paquet UDP DNS standard (RFC 1035)
 */
export function parseDnsQueryPacket(msg: Buffer): { fqdn: string; questionEnd: number } | null {
  if (!msg || msg.length < 17) return null;
  const labels: string[] = [];
  let offset = 12;

  while (offset < msg.length) {
    const len = msg[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    // Pointeur de compression DNS
    if ((len & 0xc0) === 0xc0) {
      offset += 2;
      break;
    }
    if (offset + 1 + len > msg.length) return null;
    labels.push(msg.subarray(offset + 1, offset + 1 + len).toString('utf8'));
    offset += 1 + len;
  }

  const questionEnd = Math.min(msg.length, offset + 4);
  const fqdn = labels.join('.') || 'unknown.local';
  return { fqdn, questionEnd };
}

/**
 * Construit une réponse DNS A (0.0.0.0 si Sinkhole BLOCK/QUARANTINE, sinon 93.184.216.34)
 */
export function buildDnsResponsePacket(queryBuf: Buffer, questionEnd: number, isBlocked: boolean): Buffer {
  const txId = queryBuf.subarray(0, 2);
  const flags = Buffer.from([0x81, 0x80]); // Standard query response, No error
  const counts = Buffer.from([
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x01, // ANCOUNT = 1
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00  // ARCOUNT = 0
  ]);
  const questionSection = queryBuf.subarray(12, questionEnd);

  // Answer RR : Name pointer (0xc00c), Type A (1), Class IN (1), TTL 60s, Len 4, IP
  const rdataIp = isBlocked ? [0x00, 0x00, 0x00, 0x00] : [0x5d, 0xb8, 0xd8, 0x22];
  const answerSection = Buffer.from([
    0xc0, 0x0c,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x00, 0x3c,
    0x00, 0x04,
    ...rdataIp
  ]);

  return Buffer.concat([txId, flags, counts, questionSection, answerSection]);
}
