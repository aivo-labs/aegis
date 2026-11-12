<?php
header('X-Powered-By: PHP/' . phpversion() . ' (Aegis Managed Client Demo)');

$aegisVerified = $_SERVER['HTTP_X_AEGIS_VERIFIED'] ?? 'true';
$isProtected = ($aegisVerified !== 'bypass-unprotected');
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$egressCheckUrl = getenv('EGRESS_CHECK_URL') ?: 'http://aegis-egress-edge:5053/check';

// Détection d'une charge d'attaque atteignant PHP-FPM lorsque le bouclier Aegis est désactivé
// ou lors d'un test de charge explicite (/benchmark-cpu.php)
$isExploitAttempt = (
    stripos($requestUri, 'allow_url_include') !== false ||
    stripos($requestUri, 'auto_prepend_file') !== false ||
    stripos($requestUri, 'UNION') !== false ||
    stripos($requestUri, 'wp-login.php') !== false ||
    stripos($requestUri, 'xmlrpc.php') !== false ||
    stripos($requestUri, '.env') !== false ||
    stripos($requestUri, 'benchmark-cpu.php') !== false ||
    isset($_GET['stress'])
);

$cpuBurnMs = 0.0;
$egressTriggered = false;

if ((!$isProtected && $isExploitAttempt) || isset($_GET['stress'])) {
    $start = microtime(true);
    $iterations = isset($_GET['iterations']) ? min(1200000, max(50000, intval($_GET['iterations']))) : 350000;
    $seed = 'php2shell-compromise-simulation';
    for ($i = 0; $i < $iterations; $i++) {
        $seed = hash('sha256', $seed . $i);
    }
    $cpuBurnMs = round((microtime(true) - $start) * 1000, 2);

    // Simulation sécurisée du callback post-exploitation (PHP2Shell -> C2 DNS Egress)
    $ctx = stream_context_create(['http' => ['timeout' => 1.0]]);
    @file_get_contents($egressCheckUrl . '?domain=c2-php2shell-beacon.evil-botnet.ru', false, $ctx);
    $egressTriggered = true;

    if (isset($_GET['format']) && $_GET['format'] === 'json' || stripos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'COMPROMISED_SIMULATION_EXECUTED',
            'shield_state' => $isProtected ? 'PROTECTED' : 'BYPASSED_EXPOSED',
            'engine' => 'PHP-FPM ' . phpversion(),
            'warning' => '⚠️ Bouclier Aegis désactivé : l’exploit a atteint PHP-FPM, généré une charge CPU réelle et déclenché un callback DNS C2 sortant !',
            'cpu_burn_ms' => $cpuBurnMs,
            'hash_iterations' => $iterations,
            'c2_egress_callback_triggered' => $egressTriggered,
            'request_uri' => $requestUri,
            'client_ip' => $clientIp,
            'loadavg' => sys_getloadavg(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
}

if (isset($_GET['format']) && $_GET['format'] === 'json') {
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'HEALTHY',
        'app' => 'Aegis Managed Reference Client (Oracle Cloud OCI)',
        'stack' => [
            'web_server' => 'Nginx',
            'php_fpm' => PHP_VERSION,
            'node_microservice' => 'Node.js 20 (:3000)',
        ],
        'shield_active' => $isProtected,
        'client_ip' => $clientIp,
        'loadavg' => sys_getloadavg(),
        'timestamp' => gmdate('c'),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

$load = sys_getloadavg();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Client Managed OCI — Stack PHP 8.3 + Nginx + Node.js | Protégé par Aegis</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #050914;
      --card: #0c1427;
      --border: #1e293b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --emerald: #10b981;
      --rose: #f43f5e;
      --cyan: #06b6d4;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top, #0f172a 0%, var(--bg) 70%);
      color: var(--text);
      min-height: 100vh;
      padding: 2.5rem 1.25rem;
    }
    .container { max-width: 980px; margin: 0 auto; }
    .header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 1.5rem;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      margin-bottom: 1.5rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.45rem 0.9rem;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-protected {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .badge-exposed {
      background: rgba(244, 63, 94, 0.18);
      color: #fb7185;
      border: 1px solid rgba(244, 63, 94, 0.5);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.25rem;
    }
    .card h3 {
      margin: 0 0 0.5rem 0;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }
    .metric {
      font-size: 1.5rem;
      font-weight: 800;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .sub { font-size: 0.8rem; color: var(--muted); margin-top: 0.35rem; }
    .demo-box {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.5rem;
    }
    code {
      display: block;
      background: #020617;
      border: 1px solid #1e293b;
      padding: 0.8rem 1rem;
      border-radius: 10px;
      color: #38bdf8;
      font-size: 0.82rem;
      overflow-x: auto;
      margin: 0.5rem 0 1rem 0;
    }
    a.btn {
      display: inline-block;
      padding: 0.55rem 1rem;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.85rem;
      margin-right: 0.5rem;
      margin-bottom: 0.5rem;
      border: 1px solid rgba(6, 182, 212, 0.4);
      background: rgba(6, 182, 212, 0.12);
      color: #67e8f9;
    }
    a.btn-danger {
      border-color: rgba(244, 63, 94, 0.45);
      background: rgba(244, 63, 94, 0.15);
      color: #fda4af;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div style="font-size: 0.75rem; color: var(--cyan); font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;">
          Aegis Sovereign Gate • Nœud Client Managed (Oracle Cloud OCI)
        </div>
        <h1 style="margin: 0.35rem 0 0 0; font-size: 1.45rem;">Portail E-Commerce & API Multi-Stack (PHP-FPM + Nginx + Node.js)</h1>
      </div>
      <?php if ($isProtected): ?>
        <span class="badge badge-protected">🛡️ Bouclier Aegis Gate PEP : ACTIF</span>
      <?php else: ?>
        <span class="badge badge-exposed">⚠️ Bouclier Aegis : DÉSACTIVÉ (Serveur Exposé)</span>
      <?php endif; ?>
    </div>

    <?php if ($cpuBurnMs > 0): ?>
      <div class="card" style="border-color: var(--rose); background: rgba(244, 63, 94, 0.1); margin-bottom: 1.5rem;">
        <h3 style="color: #fda4af;">⚠️ Simulation d'Exploitation Exécutée (Bouclier Désactivé)</h3>
        <div class="metric" style="color: #fb7185;">Surcharge CPU : +<?php echo htmlspecialchars((string)$cpuBurnMs); ?> ms • Callback C2 DNS Déclenché</div>
        <div class="sub" style="color: #fecdd3;">
          La requête d'attaque a traversé jusqu'au moteur PHP-FPM <?php echo PHP_VERSION; ?>, généré un pic CPU mesurable par RAPL et tenté de contacter <strong>c2-php2shell-beacon.evil-botnet.ru</strong>.
        </div>
      </div>
    <?php endif; ?>

    <div class="grid">
      <div class="card">
        <h3>Stack Applicative</h3>
        <div class="metric" style="color: #38bdf8;">PHP <?php echo PHP_VERSION; ?> + Node 20</div>
        <div class="sub">Nginx Reverse Proxy + PHP-FPM + Microservice Node.js</div>
      </div>
      <div class="card">
        <h3>Charge CPU Système (LoadAvg)</h3>
        <div class="metric" style="color: #34d399;"><?php echo number_format($load[0], 2) . ' / ' . number_format($load[1], 2); ?></div>
        <div class="sub">Télémétrie RAPL remontée en temps réel vers aegis.aivo.fr/app</div>
      </div>
      <div class="card">
        <h3>Votre IP Visiteur</h3>
        <div class="metric" style="font-size: 1.2rem;"><?php echo htmlspecialchars($clientIp); ?></div>
        <div class="sub">Inspectée en &lt; 1ms par Aegis Gate PEP</div>
      </div>
    </div>

    <div class="demo-box">
      <h2 style="margin-top: 0; font-size: 1.1rem;">🎯 Scénarios de Démonstration Live (Cockpit aegis.aivo.fr/app)</h2>
      <p style="color: var(--muted); font-size: 0.9rem; line-height: 1.5;">
        Cliquez sur un vecteur ci-dessous ou utilisez le script <strong>run-live-attack-demo.sh</strong>.
        Lorsque le bouclier est <strong>ACTIF</strong> dans <code>aegis.aivo.fr/app</code>, l'attaque est bloquée instantanément en bordure (HTTP 403, 0% CPU applicatif).
        Lorsque vous <strong>DÉSACTIVEZ</strong> le bouclier dans <code>aegis.aivo.fr/app</code>, l'attaque atteint PHP-FPM/Node.js, provoque un pic CPU/Watts réel et déclenche une alerte d'exfiltration C2 DNS !
      </p>

      <div>
        <a class="btn" href="/">✅ Requête Légitime (Portail PHP)</a>
        <a class="btn" href="/api/node/status">✅ Microservice Node.js (/api/node/status)</a>
        <a class="btn btn-danger" href="/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input">💥 Tester Exploit PHP2Shell (CVE-2024-4577)</a>
        <a class="btn btn-danger" href="/api/node/search?q=1+UNION+SELECT+username,password+FROM+users--">💥 Tester Injection SQL (UNION SELECT)</a>
        <a class="btn btn-danger" href="/.env">💥 Tester Sonde Fichier Sensible (/.env)</a>
      </div>
    </div>
  </div>
</body>
</html>
