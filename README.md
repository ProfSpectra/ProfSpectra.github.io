# ProfSpectra

Source for [profspectra.github.io](https://profspectra.github.io) — Putra Kaha's security
writeups and cheatsheets. Jekyll + the Chirpy theme (gem, not a fork), published as
plain Markdown. Published under the MIT License (see `LICENSE`).

## Editing the site

### The home page (no HTML required)

Everything on the landing page — hero copy, focus areas, featured writeups, project
links, contact links — lives in **one file: [`_data/portfolio.yml`](_data/portfolio.yml)**.
Edit the YAML, commit, and the home page rebuilds from it. Featured writeups are
referenced by their URL, so their title, date and description always stay in sync with
the post itself.

### Writing a post

Posts are plain Markdown under a category folder, e.g.:

```
Boot2Root/Hack The Box/_posts/2026-11-14-Hack-The-Box-Example.md
```

Required front matter:

```yaml
---
title: "Hack The Box - Example"
description: One-line summary shown on the home page and in search results.
tags: HackTheBox Linux Boot2Root Easy   # tags drive the chips on index pages
media_subpath: /assets/img/writeups/Example/   # for body images
image:
  path: /assets/img/writeups/Example/example_solved.png   # full root-relative path
  alt: What the cover screenshot actually shows
  width: 886
  height: 300   # must match the real PNG dimensions
---
```

Put screenshots under `assets/img/writeups/<machine>/`. Body images can use short
names (resolved against `media_subpath`); the **cover `image.path` must be the full
root-relative path** so `og:image` and JSON-LD point at the real file.

### Pages and navigation

`_tabs/*.md` are the pages in the sidebar (order = `order:`). To hide a section that
has no posts yet, set `published: false` in its tab file — the posts still build, only
the nav entry disappears. To restore `Advisory`/`PoC` later:

```bash
git checkout origin/main -- _tabs/advisory.md _tabs/poc.md
# then remove the `published: false` line
```

### Styles

The site's look is two files: [`_sass/profspectra.scss`](_sass/profspectra.scss)
(palette, type, components) and
[`assets/css/jekyll-theme-chirpy.scss`](assets/css/jekyll-theme-chirpy.scss) (the
theme's documented extension point that imports it). The theme itself is never
edited — upgrades stay clean.

Overridden theme files (kept intentionally minimal, each with a comment saying what
changed):

- `_layouts/home.html` — portfolio landing
- `_includes/head.html` — viewport/zoom fix, paper/ink theme colors
- `_includes/sidebar.html` — monogram, `aria-current="page"`, labelled nav

## Preview, build, test

Local Ruby is provided via `profspectra-ruby` (deps in `vendor/bundle`):

```bash
# build (production)
profspectra-ruby /home/hermesctl/.local/rubies/ruby-3.2/usr/bin/bundle3.2 exec jekyll build

# link/structure check
profspectra-ruby /home/hermesctl/.local/rubies/ruby-3.2/usr/bin/bundle3.2 exec htmlproofer _site \
  --disable-external --ignore-urls '/^http:\/\/127.0.0.1/,/^http:\/\/0.0.0.0/,/^http:\/\/localhost/'

# static regression checks (identity, one H1, covers, nav, viewport, ...)
python3 tools/check_site.py

# local preview (port 4001; 4000 is in use by the baseline checkout)
profspectra-ruby /home/hermesctl/.local/rubies/ruby-3.2/usr/bin/bundle3.2 exec jekyll serve \
  -H 127.0.0.1 -P 4001
```

CI (`.github/workflows/pages-deploy.yml`) runs the same production build, htmlproofer
and `tools/check_site.py` on every push to `main`.
