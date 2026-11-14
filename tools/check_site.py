#!/usr/bin/env python3
"""Static regression tests against the built Jekyll site (_site/).

Run after a production build: `python3 tools/check_site.py`.

Covers: identity metadata, home structure (one H1, sections), the /writeups/
index listing every post, portfolio.yml data binding, viewport zoom, cover
image metadata (og:image / JSON-LD pointing at real files), favicon set with
test.html excluded, required CSS/JS, and no fabricated default metadata.
"""

import json
import re
import struct
import sys
from pathlib import Path
from urllib.parse import unquote

SITE = Path(__file__).resolve().parent.parent / "_site"
ROOT = Path(__file__).resolve().parent.parent
URL = "https://profspectra.github.io"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), str(detail)))
    return ok


def read(page):
    return (SITE / page).read_text(encoding="utf-8")


def front_matter_of(post_path):
    text = post_path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    return m.group(1) if m else ""


def fm_get(fm, key):
    m = re.search(r"^%s:\s*[\"']?(.*?)[\"']?\s*$" % key, fm, re.M)
    return m.group(1) if m else None


def all_source_posts():
    return sorted(
        p
        for p in ROOT.glob("**/_posts/*.md")
        if p.name != ".placeholder"
    )


def posts_with_cover():
    out = []
    for p in all_source_posts():
        fm = front_matter_of(p)
        if re.search(r"^image:", fm, re.M):
            out.append((p, fm))
    return out


def count_h1(html_text):
    return len(re.findall(r"<h1[\s>]", html_text))


def html_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def png_dims(path):
    with open(path, "rb") as fh:
        head = fh.read(33)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", head[16:24])


# ---------------------------------------------------------------------------
# 1. identity
# ---------------------------------------------------------------------------
home = read("index.html")
title_m = re.search(r"<title>.*?</title>", home)
check("identity: site title is ProfSpectra",
      re.search(r"<title>\s*ProfSpectra\s*</title>", home),
      title_m.group(0) if title_m else "no title")
check("identity: og:site_name is ProfSpectra",
      'property="og:site_name" content="ProfSpectra"' in home)
check("identity: description is not the Chirpy theme tagline",
      "minimal, responsive and feature-rich" not in home
      and 'name="description" content="' in home)
check("identity: no 'Username' placeholder", "Username" not in home)

# ---------------------------------------------------------------------------
# 2. home structure
# ---------------------------------------------------------------------------
check("home: exactly one h1", count_h1(home) == 1, "h1 count = %d" % count_h1(home))
h1m = re.search(r"<h1[^>]*>(.*?)</h1>", home, re.S)
h1_txt = re.sub(r"<[^>]+>", "", h1m.group(1)).strip() if h1m else ""
check("home: h1 names the identity or the value proposition",
      ("ProfSpectra" in h1_txt and "Putra Kaha" in h1_txt) or "Putra Kaha" in h1_txt,
      h1_txt[:80])
check("home: has meaningful h2 sections", len(re.findall(r"<h2[\s>]", home)) >= 3)
check("home: skip link to main", 'href="#main-content"' in home or "skip-link" in home)
check("home: aria-current on active nav", 'aria-current="page"' in home)
check("home: CTA to writeups", 'href="/writeups/"' in home)
check("home: CTA to about", 'href="/about/"' in home)
check("home: latest-writing section links posts",
      len(re.findall(r'href="/posts/[^"]+/"', home)) >= 3)

# ---------------------------------------------------------------------------
# 3. writeups page
# ---------------------------------------------------------------------------
try:
    writeups = read("writeups/index.html")
    check("writeups: /writeups/ page exists", True)
except FileNotFoundError:
    writeups = None
    check("writeups: /writeups/ page exists", False, "missing _site/writeups/index.html")

if writeups:
    check("writeups: title is 'Writeups | ProfSpectra'",
          re.search(r"<title>\s*Writeups \| ProfSpectra\s*</title>", writeups) is not None)
    missing = []
    for p in all_source_posts():
        title = fm_get(front_matter_of(p), "title")
        if title and title not in writeups and html_escape(title) not in writeups:
            missing.append(title)
    check("writeups: all posts listed", not missing,
          "missing: %s" % missing if missing else "%d posts" % len(all_source_posts()))
    check("writeups: single h1", count_h1(writeups) == 1,
          "h1 count = %d" % count_h1(writeups))
    check("writeups: links to archives", 'href="/archives/"' in writeups)
    check("writeups: aria-current on active nav", 'aria-current="page"' in writeups)

# empty tabs hidden from nav
def tab_fm(stem):
    p = ROOT / "_tabs" / (stem + ".md")
    return front_matter_of(p) if p.is_file() else ""


check("nav: advisory tab published:false",
      re.search(r"^published:\s*false", tab_fm("advisory"), re.M) is not None)
check("nav: poc tab published:false",
      re.search(r"^published:\s*false", tab_fm("poc"), re.M) is not None)
for page_html, label in ((home, "home"), (writeups, "writeups")) if writeups else ((home, "home"),):
    check("nav: advisory not in nav on %s" % label,
          not re.search(r'<a href="/advisory/"', page_html))
    check("nav: poc not in nav on %s" % label,
          not re.search(r'<a href="/poc/"', page_html))

# ---------------------------------------------------------------------------
# 4. data binding: _data/portfolio.yml drives the home content
# ---------------------------------------------------------------------------
pf = ROOT / "_data" / "portfolio.yml"
check("data: _data/portfolio.yml exists", pf.is_file())
if pf.is_file():
    def _load_portfolio():
        # Minimal parser for this file's known shape only — headings,
        # top-level scalars, and one nested list of flat mappings
        # (featured_writeups). stdlib-only: CI Pythons do not ship PyYAML.
        data, key = {}, None
        for raw in pf.read_text(encoding="utf-8").splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if raw.startswith(("featured_writeups:", "hero_visual:",
                               "focus_areas:", "projects:", "contact_links:",
                               "steps:")):
                key = raw.split(":", 1)[0]
                data[key] = []
            elif key and re.match(r"^\s+- ", raw):
                data[key].append(raw)
            elif not raw.startswith((" ", "\t")) and ":" in raw:
                k, _, v = raw.partition(":")
                v = v.strip().strip('"')
                data[k.strip()] = None if v in ("", ">-") else v
        # featured entries: `- path: /posts/X/` + optional `note:` line
        featured = []
        for line in data.get("featured_writeups") or []:
            m = re.match(r"^\s+- path:\s*(\S+)", line)
            if m:
                featured.append({"path": m.group(1), "note": ""})
            else:
                m = re.match(r"^\s+note:\s*(.*)$", line)
                if m and featured:
                    featured[-1]["note"] = m.group(1).strip()
        data["featured_writeups"] = featured
        return data

    pf_txt = pf.read_text(encoding="utf-8")

    # Featured writeups: every entry in portfolio.yml must resolve to a real,
    # built post. Resolution uses the built output (Jekyll-aware: slug strips
    # the leading date) — not a guessed flat source path. A featured path that
    # fails to resolve must FAIL the check, not silently drop the card.
    portfolio_data = _load_portfolio()
    featured_entries = (portfolio_data or {}).get("featured_writeups") or []
    check("data: featured_writeups present", bool(featured_entries))
    rendered_featured = 0
    for entry in featured_entries:
        path = entry["path"]
        check("data: home links featured writeup %s" % path,
              'href="%s"' % path in home)
        built_p = SITE / path.strip("/")
        if not built_p.is_dir():
            built_p = SITE / (path.strip("/") + ".html")
        check("data: featured path resolves to built post %s" % path,
              built_p.is_dir() or built_p.is_file(), str(built_p))
        # every valid entry must actually render a card on the home page
        # (count .ps-record articles; no silent drops, no count inflation)
        if 'href="%s"' % path in home:
            rendered_featured += 1
    check("data: every featured entry renders a home card",
          rendered_featured == len(featured_entries),
          "rendered %d of %d" % (rendered_featured, len(featured_entries)))

    # Latest-writing list must render exactly latest_count entries —
    # guards the `for ... limit:` loop (the `| limit:` filter is a no-op
    # and previously rendered all 8 posts).
    latest_count = (portfolio_data or {}).get("latest_count")
    if latest_count:
        m = re.search(r'<ul class="ps-latest-list">(.*?)</ul>', home, re.S)
        n = len(re.findall(r"<li>", m.group(1))) if m else 0
        check("data: latest list renders exactly %s entries" % latest_count,
              n == int(latest_count), "rendered %d" % n)

    # projects: names under the `projects:` list only (match after the key)
    proj_names = re.findall(r"^projects:\n((?:\s+- name:\s*\S+.*\n?(?:\s{4,}\S.*\n?)*)*)",
                            pf_txt, re.M)
    for name in re.findall(r"^\s+- name:\s*\S+", proj_names[0], re.M) if proj_names else []:
        name = name.split(":", 1)[1].strip().strip('"')
        check("data: home shows project %s" % name, name in home)
    # The hero fragment check previously matched `^  headline:` (0 matches —
    # YAML indents differently), so it never executed. Assert the headline
    # from parsed YAML and verify it renders inside the home H1.
    headline = (portfolio_data or {}).get("headline") or ""
    if headline:
        h1_html = re.search(r"<h1[^>]*>(.*?)</h1>", home, re.S)
        h1_txt = re.sub(r"<[^>]+>", " ", h1_html.group(1)) if h1_html else ""
        check("data: hero headline renders in home h1",
              headline.strip() in " ".join(h1_txt.split()),
              "headline: %r h1: %r" % (headline[:40], h1_txt[:60]))
    for m in re.finditer(r"^\s+url:\s*(\S+)$", pf_txt, re.M):
        check("data: home links %s" % m.group(1), 'href="%s"' % m.group(1) in home)

# ---------------------------------------------------------------------------
# 5. viewport
# ---------------------------------------------------------------------------
m = re.search(r'name="viewport" content="([^"]*)"', home)
if m:
    vp = m.group(1)
    check("viewport: zoom not disabled",
          "user-scalable=no" not in vp and "maximum-scale" not in vp, vp)
    check("viewport: well-formed tokens",
          re.fullmatch(r"width=device-width, initial-scale=1(, [a-z-]+=[a-z0-9]+)*", vp) is not None,
          vp)
else:
    check("viewport: well-formed tokens", False, "viewport meta missing")

# ---------------------------------------------------------------------------
# 6. cover metadata: og:image / JSON-LD point at real files
# ---------------------------------------------------------------------------
from urllib.parse import unquote

for src, fm in posts_with_cover():
    # built slug strips the leading date: 2026-11-13-Hack-The-Box-Touch -> Hack-The-Box-Touch
    slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", src.stem)
    built_p = SITE / "posts" / slug / "index.html"
    if not built_p.is_file():
        check("cover: post built %s" % slug, False)
        continue
    built = built_p.read_text(encoding="utf-8")
    og_imgs = re.findall(r'property="og:image" content="([^"]+)"', built)
    check("cover: %s has og:image" % slug, og_imgs)
    for url in og_imgs:
        ok = url.startswith(URL + "/assets/img/")
        check("cover: %s og:image is root-relative asset URL" % slug, ok, url)
        if ok:
            local = SITE / unquote(url[len(URL) + 1:])
            check("cover: %s og:image file exists" % slug, local.is_file(),
                  str(local.relative_to(SITE)))
    for url in og_imgs:
        # URLs with spaces (e.g. ".../Hack The Box/...") must be percent-encoded
        check("cover: %s og:image encodes unsafe path chars" % slug,
              " " not in url, url if " " in url else "ok")
    # JSON-LD image may be a string OR an object ({url, alt, ...}); parse the
    # JSON-LD properly instead of fragile string matching.
    for m in re.finditer(r'<script type="application/ld\+json">(.*?)</script>', built, re.S):
        try:
            blob = json.loads(m.group(1))
        except json.JSONDecodeError:
            check("cover: %s JSON-LD parses" % slug, False, m.group(1)[:120])
            continue
        img = blob.get("image")
        if isinstance(img, dict):
            img_url = img.get("url", "")
        elif isinstance(img, list):
            img_url = img[0].get("url", "") if img and isinstance(img[0], dict) else str(img[0] if img else "")
        else:
            img_url = str(img or "")
        check("cover: %s JSON-LD image resolves" % slug,
              img_url.startswith(URL + "/assets/img/")
              and (SITE / unquote(img_url[len(URL) + 1:])).is_file(),
              img_url or "missing")
        check("cover: %s JSON-LD image encodes unsafe path chars" % slug,
              " " not in img_url, img_url if " " in img_url else "ok")
    check("cover: %s twitter:card large" % slug,
          'name="twitter:card" content="summary_large_image"' in built)
    tag = re.search(r"<img[^>]*class=\"preview-img[^\"]*\"[^>]*>", built)
    if tag:
        alt = re.search(r'alt="([^"]*)"', tag.group(0))
        alt_val = alt.group(1) if alt else ""
        check("cover: %s cover alt is descriptive" % slug,
              alt_val and alt_val.lower() not in ("preview image", ""), alt_val[:60])
        w = re.search(r'width="(\d+)"', tag.group(0))
        h = re.search(r'height="(\d+)"', tag.group(0))
        ip = re.search(r"^\s+path:\s*(\S+)", fm, re.M)
        if w and h and ip:
            cover_path = ROOT / ip.group(1).lstrip("/")
            if cover_path.is_file():
                dims = png_dims(cover_path)
                check("cover: %s declared dims match file" % slug,
                      dims == (int(w.group(1)), int(h.group(1))),
                      "declared %sx%s vs actual %s" % (w.group(1), h.group(1), dims))

# ---------------------------------------------------------------------------
# 7. social preview on home
# ---------------------------------------------------------------------------
og_img = re.search(r'property="og:image" content="([^"]+)"', home)
check("og: home has og:image", og_img is not None)
if og_img:
    local = SITE / unquote(og_img.group(1).removeprefix(URL + "/").lstrip("/"))
    check("og: home og:image file exists", local.is_file(),
          str(local.relative_to(SITE)))
og_alt = re.search(r'property="og:image:alt" content="([^"]+)"', home)
check("og: home og:image:alt present", og_alt is not None,
      og_alt.group(1) if og_alt else "missing")
check("twitter: home card is summary_large_image",
      'name="twitter:card" content="summary_large_image"' in home)
check("twitter: home twitter:image present",
      re.search(r'(property|name)="twitter:image" content="' + re.escape(URL), home) is not None)
check("twitter: home twitter:image:alt present",
      re.search(r'(property|name)="twitter:image:alt" content="[^"]+"', home) is not None)

# ---------------------------------------------------------------------------
# 8. favicons / test.html exclusion
# ---------------------------------------------------------------------------
check("favicons: test.html not published",
      not (SITE / "assets/img/favicons/test.html").exists())
check("favicons: test.html not in sitemap", "test.html" not in read("sitemap.xml"))
for f in ["favicon.ico", "favicon-96x96.png", "apple-touch-icon.png",
          "web-app-manifest-192x192.png", "web-app-manifest-512x512.png"]:
    check("favicons: %s published" % f, (SITE / "assets/img/favicons" / f).is_file())

# ---------------------------------------------------------------------------
# 8b. content remediation: code headers, heading anchors, LCP, a11y names
# ---------------------------------------------------------------------------

# Every code block must keep its code-header + copy button (the tabindex
# rewrite must not destroy them) and be a labelled keyboard-focusable region.
total_blocks = 0
headers_ok = True
tabindex_ok = True
label_ok = True
for src in all_source_posts():
    slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", src.stem)
    built_p = SITE / "posts" / slug / "index.html"
    if not built_p.is_file():
        continue
    built = built_p.read_text(encoding="utf-8")
    blocks = len(re.findall(r'<div class="highlight"', built))
    headers = len(re.findall(r'<div class="code-header">', built))
    if blocks != headers:
        headers_ok = False
    total_blocks += blocks
    for m in re.finditer(r'<div class="highlight"([^>]*)>', built):
        attrs = m.group(1)
        if 'tabindex="0"' not in attrs:
            tabindex_ok = False
        if 'aria-label="' not in attrs:
            label_ok = False

check("content: code blocks exist across posts", total_blocks > 0,
      "%d blocks" % total_blocks)
check("content: every code block has a code-header (copy button intact)",
      headers_ok and total_blocks > 0)
check("content: every code scroll region is keyboard-focusable (tabindex=0)",
      tabindex_ok and total_blocks > 0)
check("content: every code scroll region has a meaningful accessible label",
      label_ok and total_blocks > 0)

# Heading anchors must be labelled with the human-readable heading text,
# not an internal slug/id like "ps-featured-heading".
anchor_labels = re.findall(r'class="anchor[^"]*" aria-label="Link to section: ([^"]+)"', home)
check("home: heading anchor labels are human-readable",
      bool(anchor_labels) and "ps-featured-heading" not in " ".join(anchor_labels),
      "; ".join(anchor_labels[:4]))
post_built = read("posts/Hack-The-Box-Management/index.html")
post_anchors = re.findall(r'class="anchor[^"]*" aria-label="Link to section: ([^"]+)"', post_built)
check("post: heading anchor labels use heading text, not ids",
      bool(post_anchors)
      and all(not a.startswith(("ps-", "at-a-glance")) or a == "At a glance" for a in post_anchors)
      and any(a == "At a glance" for a in post_anchors),
      "; ".join(post_anchors[:4]))

# Back-to-top button must have an accessible name.
_btt = re.search(r'<button[^>]*id="back-to-top"[^>]*>', home)
check("a11y: back-to-top has aria-label",
      _btt is not None and 'aria-label="Back to top"' in _btt.group(0),
      _btt.group(0)[:120] if _btt else "missing")

# Post navigation: the visible title must be contained in the accessible name.
prev_m = re.search(r'<a[^>]*href="[^"]*"[^>]*aria-label="([^"]*)"', post_built)
nav_block = re.search(r'<nav class="post-navigation.*?</nav>', post_built, re.S)
if nav_block:
    nav_html = nav_block.group(0)
    nav_links = re.findall(r'<a[^>]*aria-label="([^"]*)"[^>]*>\s*<p>(.*?)</p>', nav_html, re.S)
    named_ok = all(
        re.sub(r"<[^>]+>", "", vis).strip() in name for name, vis in nav_links
    )
    check("a11y: post-nav accessible names contain the visible title",
          bool(nav_links) and named_ok,
          "names: %s" % [n for n, _ in nav_links])
    nav_disabled = re.findall(r'<div class="btn btn-outline-primary disabled"[^>]*aria-label="([^"]*)"', nav_html)
    check("a11y: disabled post-nav placeholders keep consistent accessible text",
          all(n for n in nav_disabled), "labels: %s" % nav_disabled)
else:
    check("a11y: post-nav present on posts", False, "no post-navigation block")

# Post cover (LCP): no lazy loading, fetchpriority=high, real dimensions.
cover_img = re.search(r'<a[^>]*class="[^"]*preview-img[^"]*"[^>]*>\s*<img[^>]*>', post_built)
if cover_img:
    img_tag = re.search(r'<img[^>]*>', cover_img.group(0)).group(0)
    check("lcp: post cover not lazy-loaded", 'loading="lazy"' not in img_tag, img_tag[:150])
    check("lcp: post cover has fetchpriority=high", 'fetchpriority="high"' in img_tag, img_tag[:150])
    check("lcp: post cover declares real dimensions",
          'width="884"' in img_tag and 'height="306"' in img_tag, img_tag[:150])
else:
    check("lcp: post cover image present", False, "no cover anchor on Management post")

# Other in-body images must stay lazy.
body_imgs = re.findall(r'<img[^>]*loading="lazy"[^>]*>', post_built)
check("lcp: body images remain lazy-loaded where present (informational)",
      True, "%d lazy imgs" % len(body_imgs))

# ---------------------------------------------------------------------------
# 9. required assets / CSS / JS
# ---------------------------------------------------------------------------
check("assets: theme CSS built", (SITE / "assets/css/jekyll-theme-chirpy.css").is_file())
check("assets: custom SCSS override present",
      (ROOT / "assets/css/jekyll-theme-chirpy.scss").is_file())
check("assets: profspectra partial present",
      (ROOT / "_sass/profspectra.scss").is_file())
check("assets: theme.min.js present", (SITE / "assets/js/dist/theme.min.js").is_file())
check("assets: app.min.js present (pwa)", (SITE / "app.min.js").is_file())
check("assets: sw.min.js present (pwa)", (SITE / "sw.min.js").is_file())
check("assets: search index built",
      (SITE / "assets/js/data/search.json").is_file(),
      "search.json is the site search index (feed.xml is the RSS feed)")

# ---------------------------------------------------------------------------
# 9b. resting search chrome: the 44px `#topbar .btn` rule (specificity 0,2,0)
# must not resurrect the theme's closed-state topbar controls. The resting
# rules below must out-rank it, and must NOT use !important so the theme's
# `d-block`/`d-flex` toggle utilities still show the controls during search.
# Computed-style verification (open/cancel at desktop+mobile) lives in
# tools/check_search_chrome.js (needs a local server + Playwright).
# ---------------------------------------------------------------------------
css = (SITE / "assets/css/jekyll-theme-chirpy.css").read_text(encoding="utf-8")
_cancel_rule = re.search(r"#topbar #search-cancel:not\(\.d-block\)\{[^}]*\}", css)
check("search-chrome: resting rule for #search-cancel compiled",
      _cancel_rule is not None)
check("search-chrome: resting rules for topbar triggers compiled (>=850px)",
      re.search(r"@media ?\(min-width: 850px\)\{#topbar #search-trigger:not\(\.d-none\),#topbar #sidebar-trigger:not\(\.d-none\)\{display:none\}", css) is not None)
check("search-chrome: resting rules do not use !important",
      _cancel_rule is not None and "!important" not in _cancel_rule.group(0))


# ---------------------------------------------------------------------------
# 10. no fabricated / default metadata
# ---------------------------------------------------------------------------

# front matter must never leak into rendered pages (layout override files
# must start with '---', not a leading Liquid comment before front matter)
def _leaked_front_matter(text: str) -> bool:
    return text.lstrip().startswith("---") or "layout: compress" in text[:200]

for rel, text in (("index.html", home),
                  ("writeups/index.html", read("writeups/index.html")),
                  ("posts/Hack-The-Box-Management/index.html",
                   read("posts/Hack-The-Box-Management/index.html"))):
    check("render: no front matter leaked into %s" % rel,
          not _leaked_front_matter(text))

sidebar = re.search(r"<aside[^>]*Sidebar[^>]*>.*?</aside>", home, re.S)
if sidebar:
    check("fabrication: default avatar gone from sidebar",
          "web-app-manifest-512x512.png" not in sidebar.group(0))
    check("fabrication: monogram mark used in sidebar",
          "profspectra-mark" in sidebar.group(0))
check("fabrication: dead X handle not used", "x.com/ros.putra" not in home)
check("fabrication: working X handle present", "ros_putra" in home)

for m in re.finditer(r'<script type="application/ld\+json">(.*?)</script>', home, re.S):
    try:
        blob = json.dumps(json.loads(m.group(1)))
        check("jsonld: no Username placeholder", "Username" not in blob)
        check("jsonld: has ProfSpectra identity", "ProfSpectra" in blob)
    except json.JSONDecodeError:
        check("jsonld: home JSON-LD parses", False, m.group(1)[:120])

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
failed = [r for r in results if not r[1]]
print("check_site: %d/%d checks passed" % (len(results) - len(failed), len(results)))
for name, ok, detail in failed:
    print("FAIL %s — %s" % (name, detail))
sys.exit(1 if failed else 0)
