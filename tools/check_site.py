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
    pf_txt = pf.read_text(encoding="utf-8")
    featured_paths = re.findall(r"^\s+path:\s*(/posts/\S+/)$", pf_txt, re.M)
    for path in featured_paths:
        check("data: home links featured writeup %s" % path,
              'href="%s"' % path in home)
        src = ROOT / (path.strip("/").rstrip("/") + ".md")
        check("data: featured path resolves to source %s" % path, src.is_file())
    # projects: names under the `projects:` list only (match after the key)
    proj_names = re.findall(r"^projects:\n((?:\s+- name:\s*\S+.*\n?(?:\s{4,}\S.*\n?)*)*)",
                            pf_txt, re.M)
    for name in re.findall(r"^\s+- name:\s*\S+", proj_names[0], re.M) if proj_names else []:
        name = name.split(":", 1)[1].strip().strip('"')
        check("data: home shows project %s" % name, name in home)
    for m in re.finditer(r"^  headline:\s*[\"']?(.+?)[\"']?\s*$", pf_txt, re.M):
        frag = m.group(1).split("{")[0].strip()
        if frag and len(frag) > 8:
            check("data: home shows hero fragment '%s'" % frag[:30], frag in home)
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
            local = SITE / url[len(URL) + 1:]
            check("cover: %s og:image file exists" % slug, local.is_file(),
                  str(local.relative_to(SITE)))
    for url in re.findall(r'"image"\s*:\s*"([^"]+)"', built):
        local = SITE / url.removeprefix(URL + "/").lstrip("/")
        check("cover: %s JSON-LD image resolves" % slug,
              url.startswith(URL + "/assets/img/") and local.is_file(), url)
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
    local = SITE / og_img.group(1).removeprefix(URL + "/").lstrip("/")
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
# 9. required assets / CSS / JS
# ---------------------------------------------------------------------------
check("assets: theme CSS built", (SITE / "assets/css/jekyll-theme-chirpy.css").is_file())
check("assets: custom SCSS override present",
      (ROOT / "assets/css/jekyll-theme-chirpy.scss").is_file())
check("assets: profspectra partial present",
      (ROOT / "_sass/profspectra.scss").is_file())
check("assets: theme.min.js present", (SITE / "assets/js/dist/theme.min.js").is_file())
check("assets: app.min.js present (pwa)", (SITE / "app.min.js").is_file())
check("assets: sw.min.js present", (SITE / "sw.min.js").is_file())
check("assets: search index built", (SITE / "feed.xml").is_file())

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
