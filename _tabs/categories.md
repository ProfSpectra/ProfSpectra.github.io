---
layout: categories
icon: fas fa-stream
order: 1
---

{% for categories in site.categories %}
  <h3>{{ categories[0] }}</h3>
  <ul>
    {% for post in categories[1] %}
      <li><a href="{{ post.url }}">{{ post.title }}</a></li>
    {% endfor %}
  </ul>
{% endfor %}
