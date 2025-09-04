---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

Hi—I'm **Putra Kaha**. This site is my hub for security **writeups**, CTF solutions, pentest notes, and quick cheat‑sheets. If you’re here to learn, verify a technique, or cross‑reference a finding, you’re in the right place.

## What you'll find here

* **CTF writeups** — step‑by‑step paths, payloads, and lessons learned.
* **Pentest notes** — reproducible PoCs with impact, mitigation, and mapping to OWASP/CIS/RMiT where relevant.
* **Cheat‑sheets** — short, copy‑pasteable commands for web, AD, cloud, and mobile testing.
* **Talks & slides** — decks, labs, and training materials I’ve released.

---

## Latest writeups

{% assign writeups = site.posts | where\_exp: "p", "p.tags contains 'CTF' or p.categories contains 'writeup' or p.tags contains 'writeup'" %}
{% if writeups and writeups.size > 0 %}

<ul>
{% for post in writeups limit:10 %}
  <li>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    <span class="text-muted small">— {{ post.date | date: "%Y-%m-%d" }}</span><br/>
    <span class="small">{{ post.excerpt | strip_html | truncate: 140 }}</span>
  </li>
{% endfor %}
</ul>
<p class="small"><a href="/archive/">See all posts →</a></p>
{% else %}
<p>No writeups published yet. Check back soon.</p>
{% endif %}

---

## Featured

{% assign featured = site.posts | where\_exp: "p", "p.tags contains 'featured'" %}
{% if featured and featured.size > 0 %}

<div class="post-grid">
{% for post in featured limit:6 %}
  <div class="post-card">
    <h3 class="h5"><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
    <p class="small">{{ post.excerpt | strip_html | truncate: 120 }}</p>
  </div>
{% endfor %}
</div>
{% endif %}

---

## Browse by category

<ul>
{% for category in site.categories %}
  {% assign name = category[0] %}
  {% assign posts = category[1] %}
  <li><a href="/categories/{{ name | slugify }}/">{{ name }}</a> <span class="text-muted small">({{ posts | size }})</span></li>
{% endfor %}
</ul>

## Browse by tag

<ul>
{% for tag in site.tags %}
  {% assign name = tag[0] %}
  {% assign posts = tag[1] %}
  <li><a href="/tags/#{{ name | slugify }}">{{ name }}</a> <span class="text-muted small">({{ posts | size }})</span></li>
{% endfor %}
</ul>

---

## Methodology & disclosure

* **Reproducibility first:** each writeup aims to provide exact steps and environment notes.

## Tools & lab

Burp Suite Pro, nmap, Nessus, sqlmap, dirsearch, BloodHound/Impacket, kerbrute, responder, Wireshark, Docker, k6, and a rotating cast of custom scripts.

## Contact & links

* **Email:** [putraros1226@gmail.com](mailto:putraros1226@gmail.com)
* **GitHub:** [https://github.com/ProfSpectra](https://github.com/ProfSpectra)
* **LinkedIn:** [https://www.linkedin.com/in/putra-kaha](https://www.linkedin.com/in/putra-kaha)

