#!/usr/bin/env node
/* Computed-size regression check for the 0.875rem secondary-text floor.
 *
 * Council 20 (card t_279ccf45): every authorized user-facing secondary/
 * metadata selector must compute to >= 0.875rem (14px @ 16px root) in the
 * RENDERED site, in light AND dark theme. Also verifies: no horizontal
 * overflow across viewports, no clipping (scrollWidth > clientWidth) of the
 * measured elements, and that the decorative notebook typography was left
 * untouched (still below the floor).
 *
 * Usage: serve the built site (e.g. `python3 -m http.server 4002` in _site/),
 * then: NODE_PATH=<dir-with-playwright> node tools/check_typefloor_chrome.js [base_url]
 * Requires playwright with the bundled Chromium path below.
 */

const { chromium } = require('playwright');

const BASE = process.argv[2] || 'http://127.0.0.1:4002/';
const CHROME = '/home/hermesctl/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome';
const FLOOR_PX = 14; // 0.875rem at the theme's 16px :root font-size
const HOME = '/';

const SELECTORS = [
  // [selector, page, label]
  ['#sidebar .site-subtitle', '/', 'sidebar subtitle'],
  ['.ps-kicker', '/', 'hero kicker'],
  ['.chip', '/writeups/', 'chip'],
  ['.writeup-meta', '/writeups/', 'writeup meta'],
  ['.ps-section-title', '/', 'section title'],
  ['.ps-record-meta', '/', 'record meta'],
  ['.ps-record-read', '/', 'record read line'],
  ['.ps-latest-list li time', '/', 'latest list time'],
  ['.post-tag', '/', 'post tag (home)'],
  ['.ps-footer', '/', 'footer'],
  ['.ps-footer-credit', '/', 'footer credit'],
  ['#related-posts > h2', '/posts/Hack-The-Box-CodePartTwo/', 'related posts h2'],
  ['.ps-related-number', '/posts/Hack-The-Box-CodePartTwo/', 'related number'],
  ['.ps-related-meta', '/posts/Hack-The-Box-CodePartTwo/', 'related meta'],
  ['article figcaption', '/posts/Hack-The-Box-CodePartTwo/', 'figcaption'],
  ['.post-tags .post-tag', '/posts/Hack-The-Box-CodePartTwo/', 'post tag (post)'],
];

// Decorative notebook typography — explicitly EXCLUDED from the floor.
const NOTEBOOK = [
  ['.ps-notebook-title', 0.8],
  ['.ps-step-label', 0.78],
  ['.ps-step-detail', 0.75],
  ['.ps-notebook-stamp', 0.6],
];

let failures = 0;
function assert(name, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
}

async function measure(page, sel) {
  return page.evaluate((s) => {
    const el = document.querySelector(s);
    if (!el) return null;
    const cs = getComputedStyle(el);
    return {
      px: parseFloat(cs.fontSize),
      clipped: el.scrollWidth > el.clientWidth + 1,
    };
  }, sel);
}

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'] });

  for (const theme of ['light', 'dark']) {
    for (const vp of [
      { n: 'mobile390', w: 390, h: 844 },
      { n: 'tablet768', w: 768, h: 1024 },
      { n: 'desktop1280', w: 1280, h: 800 },
      { n: 'desktop1440', w: 1440, h: 900 },
    ]) {
      const page = await browser.newPage({ viewport: { width: vp.w, height: vp.h } });
      let currentPath = null;
      for (const [sel, path, label] of SELECTORS) {
        if (currentPath !== path) {
          await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
          // Force the theme the same way the site's theme.min.js does.
          await page.evaluate((t) => {
            document.documentElement.setAttribute('data-bs-theme', t);
          }, theme);
          currentPath = path;
        }
        const m = await measure(page, sel);
        if (!m) {
          assert(`${theme}/${vp.n}: ${label} (${sel}) present`, false, 'element not found');
          continue;
        }
        assert(
          `${theme}/${vp.n}: ${label} (${sel}) >= ${FLOOR_PX}px`,
          m.px >= FLOOR_PX,
          `computed ${m.px}px`
        );
        assert(`${theme}/${vp.n}: ${label} (${sel}) not clipped`, !m.clipped);
      }
      // Document-level horizontal overflow per viewport.
      for (const path of ['/', '/writeups/', '/posts/Hack-The-Box-CodePartTwo/']) {
        await page.goto(BASE.replace(/\/$/, '') + path, { waitUntil: 'networkidle' });
        await page.evaluate((t) => {
          document.documentElement.setAttribute('data-bs-theme', t);
        }, theme);
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth
        );
        assert(`${theme}/${vp.n}: no horizontal overflow on ${path}`, overflow <= 0, `${overflow}px`);
      }
      await page.close();
    }

    // Notebook typography must remain BELOW the floor (out-of-scope check), once per theme.
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await page.goto(BASE.replace(/\/$/, '') + '/', { waitUntil: 'networkidle' });
    await page.evaluate((t) => {
      document.documentElement.setAttribute('data-bs-theme', t);
    }, theme);
    for (const [sel, rem] of NOTEBOOK) {
      const m = await measure(page, sel);
      if (!m) {
        assert(`${theme}: notebook ${sel} present`, false, 'element not found');
        continue;
      }
      assert(
        `${theme}: notebook ${sel} unchanged (< ${FLOOR_PX}px)`,
        m.px < FLOOR_PX,
        `computed ${m.px}px (expected ${rem}rem = ${rem * 16}px)`
      );
    }
    // aria-hidden on the hero-visual wrapper (which contains the decorative
    // notebook) still intact.
    const aria = await page.evaluate(() => {
      const el = document.querySelector('.ps-hero-visual');
      return el ? el.getAttribute('aria-hidden') : 'no hero-visual element';
    });
    assert(`${theme}: notebook aria-hidden intact`, aria === 'true', `aria-hidden=${aria}`);
    await page.close();
  }

  await browser.close();
  console.log(failures === 0 ? '\ncheck_typefloor: ALL CHECKS PASSED' : `\ncheck_typefloor: ${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
