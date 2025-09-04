---
layout: categories
icon: fas fa-stream
order: 1
---

{%- comment -%}
  _includes/categories-cards.html
  Renders cards of categories with child categories (co-occurring categories).
  - If include.parent is set, renders a single card for that parent.
  - Otherwise, renders one card per top-level category (first element in post.categories).
  Requires: Bootstrap (collapse) + Font Awesome.
{%- endcomment -%}

<div class="content">
  {%- assign parent_list = "" -%}
  {%- if include.parent and include.parent != "" -%}
    {%- assign parent_list = include.parent | append: "|" -%}
  {%- else -%}
    {%- capture parent_csv %}|{% endcapture -%}
    {%- for p in site.posts -%}
      {%- if p.categories and p.categories.size > 0 -%}
        {%- assign first = p.categories[0] -%}
        {%- assign needle = "|" | append: first | append: "|" -%}
        {%- unless parent_csv contains needle -%}
          {%- capture parent_csv -%}{{ parent_csv }}{{ first }}|{%- endcapture -%}
        {%- endunless -%}
      {%- endif -%}
    {%- endfor -%}
    {%- assign parent_list = parent_csv -%}
  {%- endif -%}

  {%- assign parents = parent_list | split: "|" -%}
  {%- for parent in parents -%}
    {%- if parent == "" -%}{%- continue -%}{%- endif -%}

    {%- comment -%} Gather posts under this parent category {%- endcomment -%}
    {%- assign posts_in_parent = site.posts | where_exp: "p", "p.categories contains parent" -%}

    {%- comment -%} Collect unique child categories that co-occur with the parent {%- endcomment -%}
    {%- capture child_csv %}|{% endcapture -%}
    {%- for p in posts_in_parent -%}
      {%- for c in p.categories -%}
        {%- if c != parent -%}
          {%- assign child_needle = "|" | append: c | append: "|" -%}
          {%- unless child_csv contains child_needle -%}
            {%- capture child_csv -%}{{ child_csv }}{{ c }}|{%- endcapture -%}
          {%- endunless -%}
        {%- endif -%}
      {%- endfor -%}
    {%- endfor -%}
    {%- assign child_names = child_csv | split: "|" | sort -%}

    {%- comment -%} Count non-empty child names {%- endcomment -%}
    {%- assign cats_count = 0 -%}
    {%- for c in child_names -%}
      {%- if c != "" -%}
        {%- assign cats_count = cats_count | plus: 1 -%}
      {%- endif -%}
    {%- endfor -%}

    {%- assign posts_count = posts_in_parent | size -%}
    {%- assign cid = parent | slugify -%}

    <div class="card categories mb-3">
      <div id="h_{{ cid }}" class="card-header d-flex justify-content-between align-items-center hide-border-bottom">
        <span class="ms-2">
          <i class="far fa-folder-open fa-fw"></i>
          <a class="mx-2" href="/categories/{{ cid }}/">{{ parent }}</a>
          <span class="text-muted small font-weight-light">
            {{ cats_count }} categories , {{ posts_count }} posts
          </span>
        </span>
        <a
          class="category-trigger hide-border-bottom"
          data-bs-toggle="collapse"
          href="#l_{{ cid }}"
          role="button"
          aria-expanded="true"
          aria-controls="l_{{ cid }}"
          aria-label="toggle {{ parent }}"
        >
          <i class="fas fa-fw fa-angle-down"></i>
        </a>
      </div>

      <div id="l_{{ cid }}" class="collapse show" aria-labelledby="h_{{ cid }}">
        <ul class="list-group">
          {%- for c in child_names -%}
            {%- if c == "" -%}{%- continue -%}{%- endif -%}
            {%- comment -%} Count posts that have BOTH parent and child {%- endcomment -%}
            {%- assign both_count = 0 -%}
            {%- for p in posts_in_parent -%}
              {%- if p.categories contains c -%}
                {%- assign both_count = both_count | plus: 1 -%}
              {%- endif -%}
            {%- endfor -%}
            <li class="list-group-item d-flex justify-content-between align-items-center">
              <span>
                <i class="far fa-folder fa-fw"></i>
                <a class="mx-2" href="/categories/{{ c | slugify }}/">{{ c }}</a>
                <span class="text-muted small font-weight-light">{{ both_count }} post{% if both_count != 1 %}s{% endif %}</span>
              </span>
            </li>
          {%- endfor -%}
          {%- if cats_count == 0 -%}
            <li class="list-group-item text-muted small">No subcategories.</li>
          {%- endif -%}
        </ul>
      </div>
    </div>
  {%- endfor -%}
</div>
