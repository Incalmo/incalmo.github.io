---
layout: default
title: Updates & Research
permalink: /blog/
description: Safely deploying autonomous cybersecurity systems.
---
<h1 class="page-title">{{ page.title }}</h1>
<p class="page-lead">{{ page.description }}</p>

{% if site.posts and site.posts.size > 0 %}
<ul class="post-list">
  {% for post in site.posts %}
  <li class="post-card">
    <a href="{{ post.url | relative_url }}">
      <h2 class="post-card-title">{{ post.title }}</h2>
      <p class="post-meta">{{ post.date | date: '%B %-d, %Y' }}{% if post.author %}. {{ post.author }}{% endif %}</p>
    </a>
  </li>
  {% endfor %}
</ul>
{% else %}
<p>No posts yet. Check back soon!</p>
{% endif %}
