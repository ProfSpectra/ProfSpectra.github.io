---
icon: fas fa-book-open
order: 1
---

<!-- All writeups, newest first. Rows are generated from post front matter. -->

{% assign writeup_posts = site.posts %}

<div class="writeups-index">

  {% for post in writeup_posts %}
    {% assign tag_list = post.tags | join: ' · ' %}
    <article class="writeup-row">
      <div class="writeup-meta">
        <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%b %-d, %Y" }}</time>
        <span class="dot" aria-hidden="true">·</span>
        <span>{{ post.categories | join: ' / ' }}</span>
        {% if post.categories contains 'Boot2Root' or post.categories contains 'PwnTillDawn' %}
          {% if post.categories contains 'PwnTillDawn' %}
            <span class="dot" aria-hidden="true">·</span>
            <span class="chip chip-platform">PwnTillDawn</span>
          {% else %}
            <span class="dot" aria-hidden="true">·</span>
            <span class="chip chip-platform">HTB</span>
          {% endif %}
          {% for tag in post.tags %}
            {% if tag == 'Easy' or tag == 'Medium' or tag == 'Hard' or tag == 'Difficult' %}
              <span class="chip">{{ tag }}</span>
            {% endif %}
            {% if tag == 'Linux' or tag == 'Windows' %}
              <span class="chip">{{ tag }}</span>
            {% endif %}
          {% endfor %}
        {% endif %}
      </div>

      <h2 class="writeup-title"><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></h2>

      <p class="writeup-desc">{{ post.description | default: post.excerpt | strip_html | escape }}</p>
    </article>
  {% endfor %}

</div>

<p class="writeups-footnote">
  Browse by <a href="{{ '/categories/' | relative_url }}">category</a>,
  <a href="{{ '/tags/' | relative_url }}">tag</a>, or see the full
  <a href="{{ '/archives/' | relative_url }}">archive</a> — or use the search box above.
</p>
