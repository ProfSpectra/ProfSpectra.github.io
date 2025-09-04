---
layout: tags
icon: fas fa-tags
order: 2
---

{% assign tagdata = '' | split:'@' %}
{% for tag in site.tags %}
    {% if post.tags contains tag.name or tag.name == post.tags %}
        {% capture data %}
        	<a href="{{ site.url }}{{ site.baseurl }}{{ tag.url }}">{{ tag.name }}</a>
        {% endcapture %}
        {% assign tagdata = tagdata | push: data %}
    {% endif %}
{% endfor %}
<p>{{ tagdata | array_to_sentence_string }}</p>
