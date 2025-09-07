---
icon: fas fa-book
order: 3
---

<div class="card categories">
  {% assign ROOT = 'Cheatsheet' %}
  {% assign all_cheat = site.categories[ROOT] %}

  {% if all_cheat and all_cheat.size > 0 %}
    {%- comment -%} Collect unique sub-categories under Cheatsheet {%- endcomment -%}
    {% assign subs = "" | split: "" %}
    {% for p in all_cheat %}
      {% for c in p.categories %}
        {% if c != ROOT %}
          {% unless subs contains c %}
            {% assign subs = subs | push: c %}
          {% endunless %}
        {% endif %}
      {% endfor %}
    {% endfor %}
    {% assign ordered = subs | sort %}

    {% for sub in ordered %}
      {% assign group_posts = all_cheat | where_exp: 'p', "p.categories contains sub" | sort: 'date' | reverse %}

      <!-- sub-category header -->
      <div id="h_{{ sub | slugify }}" class="card-header d-flex justify-content-between hide-border-bottom">
        <span class="ms-2">
          <i class="far fa-folder-open fa-fw"></i>
          <a href="/categories/{{ sub | slugify }}/" class="mx-2">{{ sub }}</a>
          <span class="text-muted small font-weight-light">
            {{ group_posts.size }} {% if group_posts.size == 1 %}post{% else %}posts{% endif %}
          </span>
        </span>

        <!-- arrow -->
        <a href="#l_{{ sub | slugify }}" data-bs-toggle="collapse"
           aria-expanded="{% if forloop.first %}true{% else %}false{% endif %}"
           aria-label="toggle-{{ sub | slugify }}"
           class="category-trigger hide-border-bottom">
          <i class="fas fa-fw fa-angle-down"></i>
        </a>
      </div>
      <!-- .card-header -->

      <!-- posts under this sub-category -->
      <div id="l_{{ sub | slugify }}" class="collapse {% if forloop.first %}show{% endif %}"
           aria-expanded="{% if forloop.first %}true{% else %}false{% endif %}">
        {% if group_posts.size > 0 %}
          <ul class="list-group">
            {% for post in group_posts %}
              {%- assign date_format = site.minima.date_format | default: "%b %-d, %Y" -%}
              <li class="list-group-item">
                <i class="fas fa-file-alt fa-fw"></i>
                <a href="{{ post.url | relative_url }}" class="mx-2">{{ post.title | escape }}</a>
                <span class="text-muted small font-weight-light">{{ post.date | date: date_format }}</span>
              </li>
            {% endfor %}
          </ul>
        {% else %}
          <div class="list-group-item text-muted small">No posts yet.</div>
        {% endif %}
      </div>
    {% endfor %}
  {% else %}
    <div class="card-header">
      <span class="ms-2">No cheatsheets yet.</span>
    </div>
  {% endif %}
</div>

