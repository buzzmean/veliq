// Рендер растровых материалов VELIQ из SVG/HTML исходников через Chromium (Playwright).
// Запуск из корня репозитория:  node design/tools/render-assets.mjs
// Нужен установленный пакет playwright (npm i -D playwright) или NODE_PATH на него.
// .ico собираются отдельно: python3 design/tools/make-ico.py
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const B = (p) => resolve(ROOT, 'brand', p);

const svgJobs = [
  // [исходник, размеры, шаблон имени]
  ['icons/app-icon.svg', [16, 20, 24, 32, 40, 48, 64, 128, 180, 192, 256, 512], 'icons/png/app-icon-{s}.png'],
  ...['off', 'connecting', 'on', 'error'].flatMap((st) => ['dark', 'light'].map((th) =>
    [`icons/tray-${st}-${th}.svg`, [16, 20, 24, 32, 48], `icons/png/tray-${st}-${th}-{s}.png`])),
];

const htmlJobs = [
  ['social/og-image.html', 1200, 630, 'social/og-image.png'],
  ['social/og-clubs.html', 1200, 630, 'social/og-clubs.png'],
  ['social/og-vpn.html', 1200, 630, 'social/og-vpn.png'],
  ['social/github-banner.html', 1280, 640, 'social/github-banner.png'],
  ['social/github-social.html', 1280, 640, 'social/github-social-preview.png'],
];

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const page = await browser.newPage();
for (const [src, sizes, out] of svgJobs) {
  const svg = readFileSync(B(src), 'utf8');
  for (const s of sizes) {
    await page.setViewportSize({ width: s, height: s });
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace('<svg ', `<svg width="${s}" height="${s}" `)}</body></html>`);
    const file = B(out.replace('{s}', s));
    mkdirSync(dirname(file), { recursive: true });
    await page.screenshot({ path: file, omitBackground: true, clip: { x: 0, y: 0, width: s, height: s } });
  }
  console.log('svg →', out);
}
for (const [src, w, h, out] of htmlJobs) {
  await page.setViewportSize({ width: w, height: h });
  await page.goto(pathToFileURL(B(src)).href);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: B(out) });
  console.log('html →', out);
}
await browser.close();
