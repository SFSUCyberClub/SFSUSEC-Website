---
layout: default
title: Blogs
permalink: /blog/
---


<h2>
{% for blog in site.blogs %}
       <a href="{{ blog.url }}"> {{ blog.title }} </a>
{% endfor %}
<h2>
