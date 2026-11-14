#!/usr/bin/env node
/**
 * Capture des captures d'écran haute définition du vrai Cockpit Aegis local (Mode Sombre)
 * afin de les intégrer en incrustation (Picture-in-Picture) dans la vidéo studio.
 */

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('/home/andjurka/Work/aivo/Sites/agency/node_modules/.pnpm/playwright@1.59.1/node_modules/playwright');

const OUTPUT_DIR = '/home/andjurka/Work/aivo/Sites/Aegis/scripts/benchmark-video/output';
fs.mkdirSync(OUTPUT_DIR, { recursive: true });

async function main() {
  const baseUrl = process.argv[2] || 'http://localhost:8000';
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage']
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 860 },
    deviceScaleFactor: 2,
    colorScheme: 'dark'
  });

  const page = await context.newPage();

  console.log('🔐 Authentification Pure BFF sur le Cockpit local...');
  await page.goto(`${baseUrl}/api/auth/login`, { waitUntil: 'networkidle', timeout: 20000 });
  await page.waitForTimeout(1800);

  // Forcer mode sombre si jamais un localStorage traînait
  await page.evaluate(() => {
    localStorage.setItem('aegis_theme', 'dark');
    document.documentElement.classList.remove('light');
  });

  console.log('📸 Capture 1/3 : Cockpit Overview (/app/)...');
  await page.goto(`${baseUrl}/app/`, { waitUntil: 'networkidle', timeout: 20000 });
  await page.waitForTimeout(2200);
  await page.screenshot({ path: path.join(OUTPUT_DIR, 'cockpit-overview.png') });

  console.log('📸 Capture 2/3 : Triage Kanban SOC (/app/triage)...');
  await page.goto(`${baseUrl}/app/triage`, { waitUntil: 'networkidle', timeout: 20000 });
  await page.waitForTimeout(2200);
  await page.screenshot({ path: path.join(OUTPUT_DIR, 'cockpit-triage.png') });

  console.log('📸 Capture 3/3 : RAPL Telemetry 1h Direct (/app/actions/green)...');
  await page.goto(`${baseUrl}/app/actions/green`, { waitUntil: 'networkidle', timeout: 20000 });
  await page.waitForTimeout(1500);
  const directBtn = page.locator('button', { hasText: '1h' }).first();
  if (await directBtn.count()) {
    await directBtn.click();
  }
  await page.waitForTimeout(2500);
  await page.screenshot({ path: path.join(OUTPUT_DIR, 'cockpit-rapl.png') });

  await browser.close();
  console.log(`✅ Captures Cockpit sauvegardées dans ${OUTPUT_DIR}`);
}

main().catch(err => {
  console.error('❌ Erreur capture Cockpit:', err);
  process.exit(1);
});
