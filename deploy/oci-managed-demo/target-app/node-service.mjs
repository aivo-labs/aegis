import http from 'node:http';
import crypto from 'node:crypto';
import os from 'node:os';

const PORT = 3000;
const EGRESS_HTTP_URL = process.env.EGRESS_CHECK_URL || 'http://aegis-egress-edge:5053/check';

function simulateCpuStress(iterations = 250000) {
  const start = performance.now();
  let digest = 'aegis-benchmark-seed';
  for (let i = 0; i < iterations; i++) {
    digest = crypto.createHash('sha256').update(digest + i).digest('hex');
  }
  return {
    duration_ms: Math.round((performance.now() - start) * 100) / 100,
    hash_sample: digest.slice(0, 16)
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const aegisHeader = req.headers['x-aegis-verified'] || 'true';
  const isUnprotectedBypass = aegisHeader === 'bypass-unprotected';

  // Si une requête suspecte arrive alors que le bouclier est désactivé,
  // on simule l'impact CPU réel d'une injection SQL / NoSQL non filtrée + callback C2 Egress
  if (isUnprotectedBypass || url.searchParams.get('stress') === '1') {
    const stress = simulateCpuStress(300000);
    fetch(`${EGRESS_HTTP_URL}?domain=sqli-dump-exfil.darknet-c2.ru`).catch(() => {});

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify(
        {
          status: 'VULNERABLE_BACKEND_REACHED',
          service: 'Node.js 20 API Microservice (:3000)',
          shield_state: 'DISABLED (EXPOSED)',
          warning:
            '⚠️ Le bouclier Aegis Gate est désactivé : la requête malveillante a atteint le moteur Node.js et généré une surcharge CPU + tentative d’exfiltration DNS C2.',
          cpu_impact: stress,
          loadavg: os.loadavg(),
          uri: req.url
        },
        null,
        2
      )
    );
    return;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify(
      {
        status: 'OK',
        service: 'Node.js 20 API Microservice (:3000)',
        shield_state: 'PROTECTED_BY_AEGIS_PEP',
        hostname: os.hostname(),
        loadavg: os.loadavg(),
        uptime_sec: Math.round(os.uptime()),
        timestamp: new Date().toISOString()
      },
      null,
      2
    )
  );
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`🟢 [Client Target App] Microservice Node.js actif sur 127.0.0.1:${PORT}`);
});
