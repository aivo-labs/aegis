/**
 * Page HTML5 sobre et technique de présentation du Défi Red Team Permanent (ctf.aegis.aivo.fr).
 * Zéro dépendance externe (aucun CDN), HTML sémantique, bilingue FR/EN.
 */
export function renderCtfLandingHtml(shieldActive: boolean, nodeHostname: string): string {
  const safeHost = (nodeHostname || 'ctf.aegis.aivo.fr').replace(/[^a-zA-Z0-9.-]/g, '');
  const statusLabel = shieldActive ? 'ACTIVE_ZERO_TRUST' : 'DISABLED_BYPASS_DEMO';
  const statusColor = shieldActive ? '#10b981' : '#f43f5e';

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aegis Shield v1.3 — Permanent Red Team &amp; AI CTF</title>
  <meta name="description" content="Isolated Red Team arena for testing autonomous AI pentest agents and L7 WAF evasion against Aegis Shield v1.3." />
  <style>
    :root {
      --bg: #020617;
      --surface: #0b1120;
      --surface-alt: #0f172a;
      --border: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #10b981;
      --accent-soft: rgba(16, 185, 129, 0.12);
      --danger: #fb7185;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    a { color: #6ee7b7; text-decoration: none; }
    a:hover { text-decoration: underline; }
    code, pre { font-family: var(--mono); }

    .wrap {
      max-width: 960px;
      margin: 0 auto;
      padding: 2rem 1.25rem 4rem;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-family: var(--mono);
      font-size: 0.9rem;
      font-weight: 700;
      letter-spacing: 0.04em;
    }
    .header-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.28rem 0.7rem;
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: 6px;
      font-family: var(--mono);
      font-size: 0.78rem;
      color: var(--text);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: ${statusColor};
    }
    .lang-switch {
      display: inline-flex;
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      background: var(--surface);
    }
    .lang-switch button {
      border: 0;
      background: transparent;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.3rem 0.65rem;
      cursor: pointer;
    }
    .lang-switch button.active {
      background: var(--accent-soft);
      color: #6ee7b7;
    }

    .hero {
      padding: 2.5rem 0 2rem;
      border-bottom: 1px solid var(--border);
    }
    .eyebrow {
      font-family: var(--mono);
      font-size: 0.8rem;
      color: #6ee7b7;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 0.65rem;
    }
    h1 {
      margin: 0 0 0.9rem;
      font-size: clamp(1.75rem, 3.4vw, 2.45rem);
      line-height: 1.2;
      font-weight: 750;
      letter-spacing: -0.02em;
      color: #f8fafc;
    }
    .lead {
      margin: 0;
      max-width: 68ch;
      color: var(--muted);
      font-size: 1.05rem;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 1.25rem;
      margin-top: 2rem;
    }
    .col-7 { grid-column: span 7; }
    .col-5 { grid-column: span 5; }
    .col-12 { grid-column: span 12; }
    @media (max-width: 780px) {
      .col-7, .col-5 { grid-column: span 12; }
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem 1.35rem;
    }
    .panel h2 {
      margin: 0 0 0.85rem;
      font-size: 0.92rem;
      font-family: var(--mono);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #cbd5e1;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.55rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }
    th, td {
      text-align: left;
      padding: 0.55rem 0.4rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    tr:last-child td { border-bottom: none; }
    th {
      font-family: var(--mono);
      font-size: 0.74rem;
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
    }
    td code {
      color: #6ee7b7;
      font-size: 0.84rem;
    }

    .roe-list {
      margin: 0;
      padding-left: 1.15rem;
      font-size: 0.92rem;
      color: #cbd5e1;
    }
    .roe-list li { margin-bottom: 0.55rem; }
    .tag-ok { color: #6ee7b7; font-family: var(--mono); font-size: 0.78rem; font-weight: 700; }
    .tag-no { color: var(--danger); font-family: var(--mono); font-size: 0.78rem; font-weight: 700; }

    .code-box {
      position: relative;
      background: #020617;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.9rem 1rem;
      overflow-x: auto;
      font-size: 0.84rem;
      color: #cbd5e1;
    }
    .copy-btn {
      position: absolute;
      top: 0.55rem;
      right: 0.55rem;
      background: var(--surface-alt);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: var(--mono);
      font-size: 0.74rem;
      padding: 0.25rem 0.55rem;
      border-radius: 4px;
      cursor: pointer;
    }
    .copy-btn:hover { border-color: var(--accent); color: #6ee7b7; }

    footer {
      margin-top: 2.5rem;
      padding-top: 1.25rem;
      border-top: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 0.75rem;
      font-size: 0.84rem;
      color: var(--muted);
      font-family: var(--mono);
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <svg width="24" height="24" viewBox="0 0 64 64" fill="none" aria-hidden="true">
          <path d="M32 4L10 13.5V29.5C10 44.2 19.4 55.6 32 60C44.6 55.6 54 44.2 54 29.5V13.5L32 4Z" fill="#032e27" stroke="#34d399" stroke-width="3" stroke-linejoin="round"/>
          <path d="M21.5 32.5L28.8 39.5L43 23.5" fill="none" stroke="#6ee7b7" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>AEGIS // ${safeHost}</span>
      </div>
      <div class="header-right">
        <div class="status-pill">
          <span class="status-dot" aria-hidden="true"></span>
          <span>SHIELD: ${statusLabel}</span>
        </div>
        <div class="lang-switch" role="group" aria-label="Language">
          <button type="button" id="btn-fr" class="active" onclick="setLang('fr')">FR</button>
          <button type="button" id="btn-en" onclick="setLang('en')">EN</button>
        </div>
      </div>
    </header>

    <main>
      <section class="hero">
        <div class="eyebrow" data-fr="Arène Red Team Permanente • Nœud Isolé Google Cloud" data-en="Permanent Red Team Arena • Isolated Google Cloud Node">
          Arène Red Team Permanente • Nœud Isolé Google Cloud
        </div>
        <h1 data-fr="Éprouvez Aegis Shield v1.3 face à vos agents pentest IA" data-en="Battle-test Aegis Shield v1.3 against your AI pentest agents">
          Éprouvez Aegis Shield v1.3 face à vos agents pentest IA
        </h1>
        <p class="lead" data-fr="Cette instance isolée expose les protections Anti-Artex d'Aegis (Gate PEP, piège Canary, Tarpit adaptatif, Egress Sinkhole DNS et sonde Rust). Vos tentatives remontent en direct dans notre Cockpit SOC pour durcir continuellement le bouclier Open Source." data-en="This isolated instance runs Aegis Anti-Artex defenses (Gate PEP, Canary Honeypot, Adaptive Tarpit, DNS Egress Sinkhole, and Rust OS probe). Attempts stream live to our SOC Cockpit to continuously harden the open-source shield.">
          Cette instance isolée expose les protections Anti-Artex d'Aegis (Gate PEP, piège Canary, Tarpit adaptatif, Egress Sinkhole DNS et sonde Rust). Vos tentatives remontent en direct dans notre Cockpit SOC pour durcir continuellement le bouclier Open Source.
        </p>
      </section>

      <div class="grid">
        <section class="panel col-7">
          <h2 data-fr="Surface cible &amp; Endpoints" data-en="Target Surface &amp; Endpoints">Surface cible &amp; Endpoints</h2>
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th data-fr="Rôle / Comportement" data-en="Role / Behavior">Rôle / Comportement</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>GET /ctf</code></td>
                <td data-fr="Briefing JSON lisible par les agents IA (surface API &amp; règles)." data-en="Machine-readable JSON briefing for AI agents (API surface &amp; rules).">Briefing JSON lisible par les agents IA (surface API &amp; règles).</td>
              </tr>
              <tr>
                <td><code>GET /api/v1/ctf/flag</code></td>
                <td data-fr="Coffre-fort cible contenant le flag à capturer." data-en="Target vault holding the flag to capture.">Coffre-fort cible contenant le flag à capturer.</td>
              </tr>
              <tr>
                <td><code>GET /api/v1/invoices/{id}</code></td>
                <td data-fr="Route surveillée par la détection BOLA / IDOR à fenêtre glissante." data-en="Monitored by sliding-window BOLA / IDOR enumeration detection.">Route surveillée par la détection BOLA / IDOR à fenêtre glissante.</td>
              </tr>
              <tr>
                <td><code>PATCH /api/v1/profile</code></td>
                <td data-fr="Filtre Mass Assignment &amp; Prototype Pollution." data-en="Mass Assignment &amp; Prototype Pollution filter.">Filtre Mass Assignment &amp; Prototype Pollution.</td>
              </tr>
              <tr>
                <td><code>GET /v3/api-docs · POST /graphql</code></td>
                <td data-fr="Verrouillage de découverte de schémas OpenAPI &amp; GraphQL." data-en="OpenAPI &amp; GraphQL schema discovery lockdown.">Verrouillage de découverte de schémas OpenAPI &amp; GraphQL.</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="panel col-5">
          <h2 data-fr="Règles d'engagement" data-en="Rules of Engagement">Règles d'engagement</h2>
          <ul class="roe-list">
            <li>
              <span class="tag-ok">[OK]</span>
              <span data-fr="Agents IA autonomes (ARTEX, PentestGPT, CyberStrikeAI, Hexstrike) &amp; évasion WAF L7." data-en="Autonomous AI pentest agents (ARTEX, PentestGPT, CyberStrikeAI, Hexstrike) &amp; L7 WAF evasion.">Agents IA autonomes (ARTEX, PentestGPT, CyberStrikeAI, Hexstrike) &amp; évasion WAF L7.</span>
            </li>
            <li>
              <span class="tag-ok">[OK]</span>
              <span data-fr="Tests de contournement OAST, injection, BOLA et rejeu de jetons." data-en="OAST callback, injection, BOLA, and token replay testing.">Tests de contournement OAST, injection, BOLA et rejeu de jetons.</span>
            </li>
            <li>
              <span class="tag-no">[NO]</span>
              <span data-fr="DDoS volumétrique L3/L4 contre l'infrastructure Google Cloud." data-en="Volumetric L3/L4 network DDoS against Google Cloud infrastructure.">DDoS volumétrique L3/L4 contre l'infrastructure Google Cloud.</span>
            </li>
          </ul>
          <p style="margin: 1rem 0 0; font-size: 0.84rem; color: var(--muted);" data-fr="Note : déclencher un piège Canary ou multiplier les infractions critiques entraîne un Tarpit adaptatif et un bannissement temporaire (15–60 min) de votre IP." data-en="Note: triggering a Canary trap or repeated critical alerts activates an adaptive Tarpit and a temporary IP ban (15–60 min).">
            Note : déclencher un piège Canary ou multiplier les infractions critiques entraîne un Tarpit adaptatif et un bannissement temporaire (15–60 min) de votre IP.
          </p>
        </section>

        <section class="panel col-12">
          <h2 data-fr="Démarrage rapide (curl / Agent IA)" data-en="Quickstart (curl / AI Agent)">Démarrage rapide (curl / Agent IA)</h2>
          <div class="code-box">
            <button type="button" class="copy-btn" onclick="copyCmd(this)">Copy</button>
            <pre style="margin:0;"><code># 1. Inspect the machine-readable CTF briefing
curl -s https://${safeHost}/ctf

# 2. Run the open-source ReAct AI offensive agent against this arena
git clone https://github.com/aivo-labs/aegis.git &amp;&amp; cd aegis
./scripts/run-artex-vs-aegis-battle.sh --ai https://${safeHost}</code></pre>
          </div>
        </section>
      </div>
    </main>

    <footer>
      <span>Aegis Shield v1.3 • Open Source AGPLv3</span>
      <span>
        <a href="https://github.com/aivo-labs/aegis" target="_blank" rel="noopener noreferrer">GitHub</a>
        &nbsp;·&nbsp;
        <a href="https://aivo.fr/blog/ia-offensives-artex-defense-aegis-anti-artex" id="blog-link" target="_blank" rel="noopener noreferrer">Technical Article</a>
        &nbsp;·&nbsp;
        <a href="https://aegis.aivo.fr" target="_blank" rel="noopener noreferrer">aegis.aivo.fr</a>
      </span>
    </footer>
  </div>

  <script>
    function setLang(lang) {
      document.documentElement.lang = lang;
      document.getElementById('btn-fr').classList.toggle('active', lang === 'fr');
      document.getElementById('btn-en').classList.toggle('active', lang === 'en');
      document.querySelectorAll('[data-fr][data-en]').forEach(function(el) {
        el.innerHTML = el.getAttribute('data-' + lang);
      });
      var blogLink = document.getElementById('blog-link');
      if (blogLink) {
        blogLink.href = lang === 'en'
          ? 'https://aivo.fr/en/blog/offensive-ai-artex-aegis-anti-artex-shield'
          : 'https://aivo.fr/blog/ia-offensives-artex-defense-aegis-anti-artex';
      }
    }
    function copyCmd(btn) {
      var code = btn.nextElementSibling.innerText;
      navigator.clipboard.writeText(code).then(function() {
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1800);
      });
    }
    if (navigator.language && !navigator.language.toLowerCase().startsWith('fr')) {
      setLang('en');
    }
  </script>
</body>
</html>`;
}
