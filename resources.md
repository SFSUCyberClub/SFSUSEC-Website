---
layout: default
title: Resources
permalink: /resources/
---
Whats up guys

<h2>
{% for resource in site.resources %}
        <a href="{{ resource.url }}"> {{ resource.title }} </a>
{% endfor %}
</h2>

