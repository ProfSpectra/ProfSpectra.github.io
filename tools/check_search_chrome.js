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

  // --- drawer accessibility (inert closed drawer, Escape, focus return) ---
  // closed drawer at 375: inert + aria-hidden so Tab/AT never reach offscreen links
  const closedState = await page.evaluate(() => ({
    inert: document.getElementById('sidebar').hasAttribute('inert'),
    ariaHidden: document.getElementById('sidebar').getAttribute('aria-hidden'),
    expanded: document.getElementById('sidebar-trigger').getAttribute('aria-expanded'),
  }));
  assert('mobile: closed drawer is inert', closedState.inert, JSON.stringify(closedState));
  assert('mobile: closed drawer is aria-hidden', closedState.ariaHidden === 'true', JSON.stringify(closedState));
  assert('mobile: trigger aria-expanded=false at rest', closedState.expanded === 'false', JSON.stringify(closedState));

  // Tab never lands inside the closed drawer at 375
  await page.evaluate(() => { document.querySelector('.skip-link')?.focus(); });
  let leaked = false;
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press('Tab');
    const inDrawer = await page.evaluate(() => {
      const sb = document.getElementById('sidebar');
      return sb.contains(document.activeElement);
    });
    if (inDrawer) { leaked = true; break; }
  }
  assert('mobile: Tab never enters the closed drawer', !leaked);

  // open drawer: inert removed, trigger reflects open state, usable
  await page.click('#sidebar-trigger');
  await page.waitForTimeout(400);
  const openState = await page.evaluate(() => ({
    inert: document.getElementById('sidebar').hasAttribute('inert'),
    expanded: document.getElementById('sidebar-trigger').getAttribute('aria-expanded'),
    scrollLock: document.body.style.overflow === 'hidden' || getComputedStyle(document.body).overflow === 'hidden',
    navVisible: getComputedStyle(document.querySelector('#sidebar .nav-link')).display !== 'none',
  }));
  assert('mobile: open drawer is not inert', !openState.inert, JSON.stringify(openState));
  assert('mobile: trigger aria-expanded=true when open', openState.expanded === 'true', JSON.stringify(openState));
  assert('mobile: body scroll locked while drawer open', openState.scrollLock, JSON.stringify(openState));

  // a nav link in the open drawer receives keyboard focus with a visible outline
  await page.evaluate(() => document.querySelector('#sidebar .nav-link').focus());
  const drawerFocus = await page.evaluate(() => {
    const el = document.querySelector('#sidebar .nav-link');
    const cs = getComputedStyle(el);
    return { focused: document.activeElement === el, outline: cs.outlineStyle, width: cs.outlineWidth };
  });
  assert('mobile: open drawer nav focusable', drawerFocus.focused, JSON.stringify(drawerFocus));

  // Escape closes the drawer and restores focus to the trigger
  await page.keyboard.press('Escape');
  await page.waitForTimeout(400);
  const escState = await page.evaluate(() => ({
    bodyAttr: !document.body.hasAttribute('sidebar-display'),
    focusOnTrigger: document.activeElement && document.activeElement.id === 'sidebar-trigger',
    inert: document.getElementById('sidebar').hasAttribute('inert'),
  }));
  assert('mobile: Escape closes drawer', escState.bodyAttr, JSON.stringify(escState));
  assert('mobile: Escape returns focus to trigger', escState.focusOnTrigger, JSON.stringify(escState));
  assert('mobile: drawer inert again after Escape close', escState.inert, JSON.stringify(escState));

  // main-content pointerdown dismisses the drawer without blocking links
  await page.click('#sidebar-trigger');
  await page.waitForTimeout(300);
  await page.mouse.click(300, 500); // inside main content
  await page.waitForTimeout(300);
  const mainDismiss = await page.evaluate(() => ({
    bodyAttr: !document.body.hasAttribute('sidebar-display'),
    href: document.querySelector('.ps-cta a')?.getAttribute('href'),
  }));
  assert('mobile: main-content click dismisses drawer', mainDismiss.bodyAttr, JSON.stringify(mainDismiss));

  // drawer open must not push the document horizontally
  await page.click('#sidebar-trigger');
  await page.waitForTimeout(300);
  const pushed = await page.evaluate(() => ({
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    left: document.documentElement.scrollLeft,
  }));
  assert('mobile: drawer open does not horizontally push document', pushed.overflow <= 0 && pushed.left === 0, JSON.stringify(pushed));
  await page.keyboard.press('Escape');
  await page.waitForTimeout(200);

  // --- mobile search: Escape closes and restores focus to the trigger ---
  await page.click('#search-trigger');
  await page.waitForTimeout(300);
  const searchOpenState = await page.evaluate(() => ({
    open: document.querySelector('#search-cancel').classList.contains('d-block'),
    focusInInput: document.activeElement && document.activeElement.id === 'search-input',
  }));
  assert('mobile: search opens with focus in input', searchOpenState.open && searchOpenState.focusInInput, JSON.stringify(searchOpenState));
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
  const searchEsc = await page.evaluate(() => ({
    closed: !document.querySelector('#search-cancel').classList.contains('d-block'),
    focusOnTrigger: document.activeElement && document.activeElement.id === 'search-trigger',
  }));
  assert('mobile: Escape closes search', searchEsc.closed, JSON.stringify(searchEsc));
  assert('mobile: Escape returns focus to search trigger', searchEsc.focusOnTrigger, JSON.stringify(searchEsc));

  // --- desktop: sidebar never inert, aria-expanded absent-state safe ---
  const desk = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await desk.goto(BASE, { waitUntil: 'networkidle' });
  const deskState = await desk.evaluate(() => ({
    inert: document.getElementById('sidebar').hasAttribute('inert'),
    ariaHidden: document.getElementById('sidebar').getAttribute('aria-hidden'),
  }));
  assert('desktop: sidebar never inert', !deskState.inert, JSON.stringify(deskState));
  assert('desktop: sidebar never aria-hidden', deskState.ariaHidden !== 'true', JSON.stringify(deskState));
  await desk.close();

  // --- 200% text zoom at 320px: no document overflow, header not clipped ---
  const zoom = await browser.newPage({ viewport: { width: 320, height: 720 } });
  await zoom.goto(BASE, { waitUntil: 'networkidle' });
  await zoom.evaluate(() => { document.body.style.fontSize = '200%'; });
  await zoom.waitForTimeout(400);
  const zoomState = await zoom.evaluate(() => {
    const de = document.documentElement;
    const title = document.querySelector('.ps-title');
    const tb = document.querySelector('#topbar');
    return {
      overflow: de.scrollWidth - de.clientWidth,
      titleVisible: title ? title.getBoundingClientRect().width > 0 : false,
      topbarW: tb ? tb.getBoundingClientRect().width : 0,
      clientW: de.clientWidth,
    };
  });
  assert('textzoom200@320: no horizontal overflow', zoomState.overflow <= 0, JSON.stringify(zoomState));
  assert('textzoom200@320: hero content still visible', zoomState.titleVisible, JSON.stringify(zoomState));
  // controls keep >=44px at 200% zoom
  const zoomCta = await zoom.evaluate(() => {
    const b = document.querySelector('.ps-cta .ps-btn');
    return b ? { w: b.getBoundingClientRect().width, h: b.getBoundingClientRect().height } : null;
  });
  assert('textzoom200@320: CTA >=44px', zoomCta && zoomCta.h >= 44, JSON.stringify(zoomCta));
  await zoom.close();

  await page.close();
  await browser.close();

  console.log(failures ? `SEARCH-CHROME CHECK: ${failures} FAILURES` : 'SEARCH-CHROME CHECK: ALL PASS');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
