#!/usr/bin/env node
/* Visual / reflow / a11y evidence for the 0.875rem typography floor (t_279ccf45).
 *
 * Not a pass/fail gate (check_typefloor_chrome.js is the gate) — this prints
 * measurements and saves screenshots for the completion evidence:
 *   - screenshots at 390/768/1280/1440, light + dark, home + a post
 *   - 200% and 400% zoom reflow: horizontal-overflow and clipped-text scan
 *   - text-only enlargement (:root font-size 200%) reflow scan
 *   - keyboard focus order + visible focus ring on interactive elements
 *
 * Usage: serve _site on :4002, then
 *   NODE_PATH=<dir-with-playwright> node tools/check_typefloor_visual.js [base_url] [outdir]
 */

const { chromium } = require('playwright');
const fs = require('fs');

const BASE = process.argv[2] || 'http://127.0.0.1:4002/';
const OUT = process.argv[3] || '/tmp/typefloor-shots';
const CHROME = '/home/hermesctl/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome';
const PAGES = ['/', '/writeups/', '/posts/Hack-The-Box-CodePartTwo/'];

fs.mkdirSync(OUT, { recursive: true });
const issues = [];

async function overflowScan(page, label) {
  const r = await page.evaluate(() => {
    const doc = document.documentElement;
    const docOverflow = doc.scrollWidth - doc.clientWidth;
    // elements extending past the viewport or self-clipped
    const clipped = [];
    for (const el of document.querySelectorAll(
      '.ps-kicker, .chip, .writeup-meta, .ps-record-meta, .ps-record-read, .ps-latest-list li time, .ps-section-title, .ps-footer, .ps-footer-credit, .post-tag, .ps-related-meta, .ps-related-number, article figcaption, #sidebar .site-subtitle, #related-posts > h2'
    )) {
      const cs = getComputedStyle(el);
      if (cs.display === 'none') continue;
      if (el.scrollWidth > el.clientWidth + 1 && cs.overflowX !== 'visible') {
        clipped.push(`${el.tagName.toLowerCase()}.${el.className.split(' ')[0]} self-clipped`);
      }
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.right > doc.clientWidth + 1) {
        clipped.push(`${el.tagName.toLowerCase()}.${el.className.split(' ')[0]} beyond viewport (right=${Math.round(rect.right)})`);
      }
    }
    return { docOverflow, clipped };
  });
  console.log(`${label}: doc horizontal overflow = ${r.docOverflow}px, element issues = ${r.clipped.length ? r.clipped.join('; ') : 'none'}`);
  if (r.docOverflow > 0 || r.clipped.length) issues.push(`${label}: overflow=${r.docOverflow} ${r.clipped.join('; ')}`);
}

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox', '--force-device-scale-factor=1'] });

  // ---- screenshots at the four acceptance viewports, both themes ----
  for (const theme of ['light', 'dark']) {
    for (const vp of [
      { n: '390', w: 390, h: 844 },
      { n: '768', w: 768, h: 1024 },
      { n: '1280', w: 1280, h: 800 },
      { n: '1440', w: 1440, h: 900 },
    ]) {
      const page = await browser.newPage({ viewport: { width: vp.w, height: vp.h } });
      for (const path of PAGES) {
        await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
        await page.evaluate((t) => document.documentElement.setAttribute('data-bs-theme', t), theme);
        const name = path === '/' ? 'home' : path.split('/')[1];
        const file = `${OUT}/${theme}-${name}-${vp.n}.png`;
        await page.screenshot({ path: file, fullPage: false });
        await overflowScan(page, `${theme} ${name} @${vp.n}`);
      }
      await page.close();
    }
  }
  console.log(`screenshots written to ${OUT}`);

  // ---- zoom reflow: 200% / 400% via device scale ----
  for (const zoom of [2, 4]) {
    const page = await browser.newPage({ viewport: { width: 1440 / zoom, height: 900 / zoom } });
    for (const path of PAGES) {
      await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
      await page.evaluate(() => document.documentElement.style.zoom = null);
      await page.evaluate((z) => { document.documentElement.style.zoom = z; }, zoom);
      await page.waitForTimeout(150);
      await overflowScan(page, `zoom${zoom * 100}% ${path}`);
    }
    await page.close();
  }

  // ---- text-only enlargement: double :root font-size (em-based reflow) ----
  for (const path of PAGES) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
    await page.evaluate(() => {
      const root = document.documentElement;
      const cs = getComputedStyle(root);
      root.style.fontSize = `${parseFloat(cs.fontSize) * 2}px`;
    });
    await page.waitForTimeout(150);
    await overflowScan(page, `text-200% ${path}`);
    await page.close();
  }

  // ---- keyboard: Tab order + visible focus ring ----
  for (const path of PAGES) {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
    const focusReport = await page.evaluate(() => {
      const seen = [];
      const first = document.querySelector('.skip-link, a, button, input');
      if (first) first.focus();
      let el = document.activeElement;
      for (let i = 0; i < 12 && el; i++) {
        const cs = getComputedStyle(el);
        const ring = parseFloat(cs.outlineWidth) > 0 || cs.boxShadow !== 'none' ||
          (cs.textDecorationLine || '').includes('underline');
        seen.push(`${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${el.className && typeof el.className === 'string' ? '.' + el.className.split(' ')[0] : ''} focus-visible:${ring}`);
        el = el.nextElementSibling || (el.parentElement && el.parentElement.nextElementSibling);
        if (el) el.focus();
        el = document.activeElement;
      }
      return seen;
    });
    console.log(`focus probe ${path}: ${focusReport.slice(0, 6).join(' | ')}`);
    // Real Tab-key walk: every focused interactive element must show a visible indicator.
    const ringFails = [];
    for (let i = 0; i < 15; i++) {
      await page.keyboard.press('Tab');
      const r = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el || el === document.body) return null;
        const cs = getComputedStyle(el);
        const visible =
          (parseFloat(cs.outlineWidth) > 0 && cs.outlineStyle !== 'none') ||
          cs.boxShadow !== 'none' ||
          parseFloat(cs.borderTopWidth) !== parseFloat(cs.borderBottomWidth); // border swap pattern
        return { tag: el.tagName.toLowerCase(), id: el.id || '', cls: (typeof el.className === 'string' ? el.className.split(' ')[0] : ''), visible };
      });
      if (!r) break;
      if (!r.visible) ringFails.push(`${r.tag}#${r.id}.${r.cls}`);
    }
    console.log(`tab walk ${path}: focus-ring issues = ${ringFails.length ? ringFails.join('; ') : 'none'}`);
    if (ringFails.length) issues.push(`focus ring ${path}: ${ringFails.join('; ')}`);
    await page.close();
  }

  await browser.close();
  console.log(issues.length === 0 ? 'VISUAL/REFLOW/A11Y SCAN CLEAN' : `ISSUES:\n${issues.join('\n')}`);
})().catch((e) => { console.error(e); process.exit(1); });
