#!/usr/bin/env node
/* Computed-style regression check for topbar search chrome.
 *
 * Guards against the 44px `#topbar .btn` rule (specificity 0,2,0) overriding
 * the Chirpy theme's closed-state `display:none` for #search-cancel (and, on
 * desktop, #search-trigger / #sidebar-trigger). Verifies the controls rest
 * hidden, show during active search, hide again after cancel, keep >=44px hit
 * areas, no horizontal overflow, and visible keyboard focus.
 *
 * Usage: serve the built site (e.g. `python3 -m http.server 4002` in _site/),
 * then: node tools/check_search_chrome.js [base_url]
 * Requires playwright with the bundled Chromium path below.
 */

const { chromium } = require('playwright');

const BASE = process.argv[2] || 'http://127.0.0.1:4002/';
const CHROME = '/home/hermesctl/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome';

let failures = 0;
function assert(name, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
}

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'] });

  for (const vp of [
    { n: 'desktop', w: 1440, h: 900 },
    { n: 'mobile', w: 375, h: 800 },
    { n: 'mobile320', w: 320, h: 720 },
  ]) {
    const page = await browser.newPage({ viewport: { width: vp.w, height: vp.h } });
    await page.goto(BASE, { waitUntil: 'networkidle' });

    // --- resting state ---
    const rest = await page.evaluate(() => {
      const cs = (sel) => {
        const el = document.querySelector(sel);
        return el ? getComputedStyle(el).display : 'MISSING';
      };
      return {
        cancel: cs('#search-cancel'),
        searchBox: cs('search#search'),
        searchTrigger: cs('#search-trigger'),
        sidebarTrigger: cs('#sidebar-trigger'),
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      };
    });
    assert(`${vp.n}: #search-cancel hidden at rest`, rest.cancel === 'none', `display:${rest.cancel}`);
    assert(`${vp.n}: no horizontal overflow at rest`, rest.overflow <= 0, `${rest.overflow}px`);

    if (vp.w >= 850) {
      assert(`${vp.n}: search box visible at rest`, rest.searchBox === 'flex', `display:${rest.searchBox}`);
      assert(`${vp.n}: #search-trigger hidden at rest`, rest.searchTrigger === 'none', `display:${rest.searchTrigger}`);
      assert(`${vp.n}: #sidebar-trigger hidden at rest`, rest.sidebarTrigger === 'none', `display:${rest.sidebarTrigger}`);
    } else {
      assert(`${vp.n}: search box hidden at rest`, rest.searchBox === 'none', `display:${rest.searchBox}`);
      assert(`${vp.n}: #search-trigger visible at rest`, rest.searchTrigger !== 'none', `display:${rest.searchTrigger}`);
      assert(`${vp.n}: #sidebar-trigger visible at rest`, rest.sidebarTrigger !== 'none', `display:${rest.sidebarTrigger}`);
      const trig = await page.evaluate(() => {
        const b = document.querySelector('#search-trigger').getBoundingClientRect();
        return { w: b.width, h: b.height };
      });
      assert(`${vp.n}: search trigger >=44px hit area`, trig.w >= 44 && trig.h >= 44, JSON.stringify(trig));
    }

    // --- open search ---
    if (vp.w < 850) {
      // mobile: search opens via the trigger, which also reveals Cancel
      await page.click('#search-trigger');
      await page.waitForTimeout(200);
      const open = await page.evaluate(() => ({
        cancel: getComputedStyle(document.querySelector('#search-cancel')).display,
        searchBox: getComputedStyle(document.querySelector('search#search')).display,
      }));
      assert(`${vp.n}: #search-cancel shown with active search`, open.cancel !== 'none', `display:${open.cancel}`);
      assert(`${vp.n}: search box shown with active search`, open.searchBox !== 'none', `display:${open.searchBox}`);

      const cancelSize = await page.evaluate(() => {
        const b = document.querySelector('#search-cancel').getBoundingClientRect();
        return { w: b.width, h: b.height };
      });
      assert(`${vp.n}: cancel button >=44px hit area`, cancelSize.w >= 44 && cancelSize.h >= 44, JSON.stringify(cancelSize));

      // --- cancel restores resting state ---
      await page.click('#search-cancel');
      await page.waitForTimeout(200);
      const after = await page.evaluate(() => ({
        cancel: getComputedStyle(document.querySelector('#search-cancel')).display,
        searchBox: getComputedStyle(document.querySelector('search#search')).display,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      }));
      assert(`${vp.n}: cancel hides #search-cancel again`, after.cancel === 'none', `display:${after.cancel}`);
      assert(`${vp.n}: cancel closes search box`, after.searchBox === 'none', `display:${after.searchBox}`);
      assert(`${vp.n}: no horizontal overflow after cancel`, after.overflow <= 0, `${after.overflow}px`);

      // --- visible keyboard focus on search-trigger ---
      // programmatic .focus() does not match :focus-visible in Chrome;
      // navigate by keyboard, which is the guarantee being checked
      await page.evaluate(() => { document.querySelector('.skip-link')?.focus(); });
      let kbFocused = false;
      for (let i = 0; i < 40; i++) {
        await page.keyboard.press('Tab');
        kbFocused = await page.evaluate(() => document.activeElement?.id === 'search-trigger');
        if (kbFocused) break;
      }
      const focus = await page.evaluate(() => {
        if (!document.activeElement || document.activeElement.id !== 'search-trigger') return null;
        const cs = getComputedStyle(document.activeElement);
        return { style: cs.outlineStyle, width: cs.outlineWidth };
      });
      assert(`${vp.n}: keyboard focus reaches #search-trigger`, kbFocused);
      assert(`${vp.n}: visible focus outline on #search-trigger`,
        focus !== null && focus.style !== 'none' && parseFloat(focus.width) > 0, JSON.stringify(focus));
    } else {
      // desktop: stock Chirpy keeps the search box always open and the
      // trigger (the only Cancel path) hidden; open/cancel is type → clear.
      await page.click('#search-input');
      await page.type('#search-input', 'hack');
      await page.waitForTimeout(600);
      const typed = await page.evaluate(() => ({
        focused: document.activeElement === document.querySelector('#search-input'),
        resultsShown: !document.querySelector('#search-result-wrapper').classList.contains('d-none'),
        resultCount: document.querySelectorAll('#search-results article').length,
      }));
      assert(`${vp.n}: search input takes typing`, typed.focused, JSON.stringify(typed));
      assert(`${vp.n}: typing shows search results`, typed.resultsShown && typed.resultCount > 0, JSON.stringify(typed));
      await page.fill('#search-input', '');
      await page.waitForTimeout(600);
      const cleared = await page.evaluate(() => ({
        resultsHidden: document.querySelector('#search-result-wrapper').classList.contains('d-none'),
        cancelStillHidden: getComputedStyle(document.querySelector('#search-cancel')).display === 'none',
      }));
      assert(`${vp.n}: clearing query hides results`, cleared.resultsHidden, JSON.stringify(cleared));
      assert(`${vp.n}: cancel stays hidden on desktop flow`, cleared.cancelStillHidden, JSON.stringify(cleared));
    }

    // --- selected-work record headline affordance (home) ---
    const record = await page.evaluate(() => {
      const a = document.querySelector('.ps-record-title a');
      if (!a) return null;
      const cs = getComputedStyle(a);
      return { deco: cs.textDecorationLine, color: cs.color };
    });
    assert(`${vp.n}: record headline underlined by default`, record !== null && record.deco.includes('underline'), JSON.stringify(record));

    await page.close();
  }

  // --- sidebar drawer on mobile: 44px trigger, opens, closes ---
  const page = await browser.newPage({ viewport: { width: 375, height: 800 } });
  await page.goto(BASE, { waitUntil: 'networkidle' });
  const drawerSize = await page.evaluate(() => {
    const b = document.querySelector('#sidebar-trigger').getBoundingClientRect();
    return { w: b.width, h: b.height };
  });
  assert('mobile: sidebar-trigger >=44px hit area', drawerSize.w >= 44 && drawerSize.h >= 44, JSON.stringify(drawerSize));
  await page.click('#sidebar-trigger');
  await page.waitForTimeout(400);
  const drawerOpen = await page.evaluate(() => {
    const sb = document.querySelector('#sidebar');
    return { width: sb.getBoundingClientRect().width, mask: !document.querySelector('#mask').classList.contains('d-none') };
  });
  assert('mobile: sidebar drawer opens', drawerOpen.width > 0 && drawerOpen.mask, JSON.stringify(drawerOpen));
  // click the mask at the far right, clear of the sidebar
  await page.mouse.click(370, 400);
  await page.waitForTimeout(400);
  const drawerClosed = await page.evaluate(() => ({
    mask: document.querySelector('#mask').classList.contains('d-none'),
    bodyAttr: !document.body.hasAttribute('sidebar-display'),
  }));
  assert('mobile: sidebar drawer closes via mask', drawerClosed.mask && drawerClosed.bodyAttr, JSON.stringify(drawerClosed));

  await page.close();
  await browser.close();

  console.log(failures ? `SEARCH-CHROME CHECK: ${failures} FAILURES` : 'SEARCH-CHROME CHECK: ALL PASS');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
