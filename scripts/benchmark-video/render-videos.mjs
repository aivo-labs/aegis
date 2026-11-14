#!/usr/bin/env node
/**
 * Studio Renderer Playwright -> FFmpeg
 * Génère les vidéos 1080p30 FR & EN à partir de output/benchmark-data.json et des captures Cockpit,
 * puis dérive les formats compacts optimisés GitHub (MP4 720p, WebP animé, GIF).
 *
 * Options :
 *   --qa-only    Génère uniquement 4 captures QA (FR + EN) pour validation visuelle rapide.
 *   --fr-only    Génère uniquement la version FR.
 *   --en-only    Génère uniquement la version EN.
 */

import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('/home/andjurka/Work/aivo/Sites/agency/node_modules/.pnpm/playwright@1.59.1/node_modules/playwright');

const BASE_DIR = '/home/andjurka/Work/aivo/Sites/Aegis/scripts/benchmark-video';
const OUT_DIR = path.join(BASE_DIR, 'output');
const QA_DIR = path.join(OUT_DIR, 'qa');
const TEMPLATE_PATH = path.join(BASE_DIR, 'studio', 'template.html');
const DATA_PATH = path.join(OUT_DIR, 'benchmark-data.json');

const FPS = 30;
const DURATION_SEC = 50.0;
const TOTAL_FRAMES = Math.round(FPS * DURATION_SEC);

function loadDataUri(filePath) {
  if (!fs.existsSync(filePath)) return '';
  const b64 = fs.readFileSync(filePath).toString('base64');
  return `data:image/png;base64,${b64}`;
}

function runFfmpeg(args, label) {
  return new Promise((resolve, reject) => {
    console.log(`🎞️  [${label}] ffmpeg ${args.join(' ')}`);
    const proc = spawn('/usr/bin/ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d.toString(); });
    proc.on('close', code => {
      if (code === 0) resolve();
      else reject(new Error(`FFmpeg (${label}) failed with code ${code}:\n${stderr.slice(-1500)}`));
    });
  });
}

async function renderLanguageMaster(browser, data, assets, lang) {
  const outMp4 = path.join(OUT_DIR, `aegis-php2shell-benchmark-${lang}-1080p.mp4`);
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
    colorScheme: 'dark'
  });
  const page = await context.newPage();
  await page.goto(`file://${TEMPLATE_PATH}`, { waitUntil: 'load' });
  await page.evaluate(({ d, l, a }) => {
    window.initStudio(d, l, a);
    window.renderAtTime(0);
  }, { d: data, l: lang, a: assets });
  await page.evaluate(() => document.fonts.ready);

  console.log(`\n🎬 Rendu master 1080p (${lang.toUpperCase()}) : ${TOTAL_FRAMES} images @ ${FPS} fps -> ${path.basename(outMp4)}`);

  const ff = spawn('/usr/bin/ffmpeg', [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'png',
    '-framerate', String(FPS),
    '-i', '-',
    '-c:v', 'libx264',
    '-preset', 'medium',
    '-crf', '17',
    '-pix_fmt', 'yuv420p',
    '-movflags', '+faststart',
    '-an',
    outMp4
  ], { stdio: ['pipe', 'ignore', 'pipe'] });

  let ffErr = '';
  ff.stderr.on('data', d => { ffErr += d.toString(); });

  const ffDone = new Promise((resolve, reject) => {
    ff.on('close', code => {
      if (code === 0) resolve();
      else reject(new Error(`FFmpeg master (${lang}) exit ${code}:\n${ffErr.slice(-1500)}`));
    });
  });

  const tStart = Date.now();
  for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
    const tSec = frame / FPS;
    await page.evaluate(t => window.renderAtTime(t), tSec);
    const png = await page.screenshot({ type: 'png', animations: 'disabled' });
    const ok = ff.stdin.write(png);
    if (!ok) {
      await new Promise(r => ff.stdin.once('drain', r));
    }
    if ((frame + 1) % 150 === 0 || frame === TOTAL_FRAMES - 1) {
      const elapsedS = ((Date.now() - tStart) / 1000).toFixed(1);
      const pct = (((frame + 1) / TOTAL_FRAMES) * 100).toFixed(0);
      console.log(`   [${lang.toUpperCase()}] ${frame + 1}/${TOTAL_FRAMES} frames (${pct}%) en ${elapsedS}s`);
    }
  }

  ff.stdin.end();
  await ffDone;
  await context.close();
  const mb = (fs.statSync(outMp4).size / 1048576).toFixed(2);
  console.log(`✅ Master ${lang.toUpperCase()} généré : ${outMp4} (${mb} Mo)`);
  return outMp4;
}

async function renderQaSnapshots(browser, data, assets, langs) {
  fs.mkdirSync(QA_DIR, { recursive: true });
  const timestamps = [
    { name: '01-intro', t: 1.5 },
    { name: '02-shield-on', t: 14.0 },
    { name: '03-toggle-off', t: 22.0 },
    { name: '04-shield-off-spike', t: 38.0 },
    { name: '05-outro', t: 46.0 }
  ];

  for (const lang of langs) {
    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      deviceScaleFactor: 1,
      colorScheme: 'dark'
    });
    const page = await context.newPage();
    await page.goto(`file://${TEMPLATE_PATH}`, { waitUntil: 'load' });
    await page.evaluate(({ d, l, a }) => window.initStudio(d, l, a), { d: data, l: lang, a: assets });
    await page.evaluate(() => document.fonts.ready);

    for (const snap of timestamps) {
      await page.evaluate(t => window.renderAtTime(t), snap.t);
      const outPng = path.join(QA_DIR, `qa-${lang}-${snap.name}.png`);
      await page.screenshot({ path: outPng, type: 'png' });
    }
    await context.close();
    console.log(`📸 Captures QA (${lang.toUpperCase()}) écrites dans ${QA_DIR}`);
  }
}

async function generateGithubDerivatives(enMasterMp4) {
  const githubMp4 = path.join(OUT_DIR, 'aegis-php2shell-benchmark-en-github.mp4');
  const githubWebp = path.join(OUT_DIR, 'aegis-php2shell-benchmark-en-github.webp');
  const githubGif = path.join(OUT_DIR, 'aegis-php2shell-benchmark-en-github.gif');

  // 1. Compact 720p MP4 (< 5 MB ideal for GitHub markdown/releases)
  await runFfmpeg([
    '-y', '-i', enMasterMp4,
    '-vf', 'scale=1280:720:flags=lanczos',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '24',
    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-an',
    githubMp4
  ], 'GitHub 720p MP4');

  // 2. Animated WebP (800px @ 8fps, infinite loop) — supported directly in Markdown ![](...)
  await runFfmpeg([
    '-y', '-i', enMasterMp4,
    '-vf', 'fps=8,scale=800:-1:flags=lanczos',
    '-vcodec', 'libwebp', '-lossless', '0', '-compression_level', '6',
    '-q:v', '35', '-loop', '0', '-an',
    githubWebp
  ], 'GitHub Animated WebP');

  // 3. High-palette GIF fallback (768px @ 10fps, 128 colors to stay under 10 MB for GitHub raw)
  await runFfmpeg([
    '-y', '-i', enMasterMp4,
    '-vf', 'fps=10,scale=768:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3',
    '-loop', '0',
    githubGif
  ], 'GitHub Palette GIF');

  for (const f of [githubMp4, githubWebp, githubGif]) {
    const mb = (fs.statSync(f).size / 1048576).toFixed(2);
    console.log(`📦 GitHub Asset : ${path.basename(f)} -> ${mb} Mo`);
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const qaOnly = args.has('--qa-only');
  const langs = args.has('--fr-only') ? ['fr'] : args.has('--en-only') ? ['en'] : ['fr', 'en'];

  if (!fs.existsSync(DATA_PATH)) {
    throw new Error(`Dataset introuvable : ${DATA_PATH}`);
  }
  const data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  const assets = {
    overview: loadDataUri(path.join(OUT_DIR, 'cockpit-overview.png')),
    rapl: loadDataUri(path.join(OUT_DIR, 'cockpit-rapl.png'))
  };

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage']
  });

  try {
    if (qaOnly) {
      await renderQaSnapshots(browser, data, assets, langs);
      return;
    }

    const generated = {};
    for (const lang of langs) {
      generated[lang] = await renderLanguageMaster(browser, data, assets, lang);
    }

    // Générer aussi les 4 snapshots QA sur la version finale pour audit visuel
    await renderQaSnapshots(browser, data, assets, ['fr', 'en'].filter(l => langs.includes(l)));

    if (generated.en) {
      await generateGithubDerivatives(generated.en);
    }
  } finally {
    await browser.close();
  }
}

main().catch(err => {
  console.error('❌ Erreur studio renderer:', err);
  process.exit(1);
});
