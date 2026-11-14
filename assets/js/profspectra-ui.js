/* ProfSpectra UI enhancements (theme.min.js complement).
 *
 * Scope (kept deliberately small — the theme owns search, sidebar toggle
 * mechanics, back-to-top and mode switching; we only add what the theme
 * lacks):
 *  1. Mobile drawer (<850px): the closed sidebar is inert + aria-hidden so
 *     keyboard/AT never walk into offscreen links. State is derived from the
 *     same signals the theme's toggle uses (body[sidebar-display], #mask
 *     visibility), so it stays in sync with the theme's own open/close paths
 *     (trigger click, mask click). Desktop never applies inert.
 *  2. Escape closes the drawer and mobile search, restoring focus to the
 *     opener (WCAG 2.1.2, 2.4.3).
 *  3. #sidebar-trigger reflects aria-expanded/aria-controls.
 *  4. Body scroll lock while the drawer is open (mobile only).
 *  5. Main-content pointerdown closes the drawer (dismiss without blocking
 *     links — we only act when the drawer is actually open).
 *  6. Mobile search open/close returns focus to #search-trigger.
 *
 * No framework; initialized on DOMContentLoaded after theme.min.js has run.
 * Reduced-motion: no animations are introduced here.
 */
(() => {
  'use strict';

  const MOBILE = matchMedia('(max-width: 849.9px)');

  const els = {
    sidebar: document.getElementById('sidebar'),
    trigger: document.getElementById('sidebar-trigger'),
    mask: document.getElementById('mask'),
    searchTrigger: document.getElementById('search-trigger'),
    searchCancel: document.getElementById('search-cancel'),
    searchBox: document.getElementById('search'),
    searchInput: document.getElementById('search-input'),
    main: document.getElementById('main-wrapper'),
  };

  if (!els.sidebar || !els.trigger) return;

  // --- drawer state -------------------------------------------------------
  // The theme toggles body[sidebar-display] + #mask. We derive open state
  // from the body attribute so both the trigger and mask paths stay in sync.
  const drawerOpen = () => document.body.hasAttribute('sidebar-display');

  const syncDrawerA11y = () => {
    const open = drawerOpen();
    const mobile = MOBILE.matches;
    // aria-expanded on the hamburger trigger
    els.trigger.setAttribute('aria-expanded', String(open));
    // The sidebar nav is visible chrome on desktop; only gate it on mobile,
    // and only when closed (open = the user is looking at it).
    const gated = mobile && !open;
    if (gated) {
      els.sidebar.setAttribute('inert', '');
      els.sidebar.setAttribute('aria-hidden', 'true');
    } else {
      els.sidebar.removeAttribute('inert');
      els.sidebar.removeAttribute('aria-hidden');
    }
    // Scroll lock while the overlay drawer is open on mobile.
    document.body.style.overflow = mobile && open ? 'hidden' : '';
  };

  // Theme opens/closes via clicks on trigger and mask; observe both, plus
  // resize (breakpoint crossings), to re-sync attributes.
  const origToggle = () => {}; // theme binds its own onclick; we only observe
  const observer = new MutationObserver(syncDrawerA11y);
  observer.observe(document.body, { attributes: true, attributeFilter: ['sidebar-display'] });
  MOBILE.addEventListener('change', syncDrawerA11y);
  syncDrawerA11y();

  // --- Escape closes drawer / search, focus returns to opener -------------
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;

    if (drawerOpen()) {
      e.preventDefault();
      // The theme's toggle is an onclick assignment, so re-dispatch a click
      // to close it through the theme's own path (keeps mask/state in sync).
      els.trigger.click();
      els.trigger.focus();
      return;
    }

    // Mobile search: open when #search has d-flex (theme's open marker) and
    // the cancel button is showing (d-block).
    const searchOpen = els.searchCancel && els.searchCancel.classList.contains('d-block');
    if (searchOpen) {
      e.preventDefault();
      els.searchCancel.click();
      if (els.searchTrigger) els.searchTrigger.focus();
    }
  });

  // --- main-content dismiss (non-blocking) --------------------------------
  // pointerdown (not click) so following a link still wins: we only close
  // the drawer; the navigation proceeds normally.
  els.main && els.main.addEventListener('pointerdown', () => {
    if (drawerOpen() && MOBILE.matches) els.trigger.click();
  });

  // --- mobile search focus return ------------------------------------------
  // The theme reveals Cancel (d-block) when search opens. Watch that class
  // so focus returns to the trigger when search closes by any path.
  if (els.searchCancel && els.searchTrigger) {
    let wasOpen = els.searchCancel.classList.contains('d-block');
    const searchObserver = new MutationObserver(() => {
      const open = els.searchCancel.classList.contains('d-block');
      if (wasOpen && !open && document.activeElement === document.body) {
        els.searchTrigger.focus();
      }
      wasOpen = open;
    });
    searchObserver.observe(els.searchCancel, { attributes: true, attributeFilter: ['class'] });
  }
})();
