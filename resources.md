---
layout: default
title: Resources
permalink: /resources/
---
To include individual projects, writeups for ctfs, and any other interesting research related to security

<h2>
{% for resource in site.resources %}
        <a href="{{ resource.url }}"> {{ resource.title }} </a>
{% endfor %}
</h2>

