---
layout: post
title: "Frontier Cyber Evaluations: Sonnet 4.5"
description: '&ldquo;Claude, please hack this network&rdquo;'
date: 2025-10-01
author: Brian Singer
---

![Alt text for accessibility]({{ "/assets/sonnet_blog/monet_mural.jpg" | relative_url }}){: .rounded-lg width="400" style="display: block; margin: 3rem auto;" }


At Incalmo, our number one priority is: How well can frontier models hack networks? We view this question as critical to safety, as it informs the risk of AI in relation to cybersecurity harm. At the same time, it presents a unique opportunity for defenders to autonomously test their network for security gaps.

We collaborated with Anthropic to evaluate the hacking capabilities of Sonnet 4.5, their latest model. For context, we have already shown that LLMs with special harnesses can autonomously hack small enterprises (A\ blog post, link to paper). However, what surprised us with Sonnet 4.5 is how well it can hack networks without any special harnesses and only access to a Kali host’s shell.


## How to evaluate AI at hacking networks

Frontier models are often evaluated on security Q&A questions or small security challenges (e.g., exploit a vulnerability, solve a cryptography problem). While these evaluations are important, it's unclear how they translate to LLMs hacking networks. We see this in practice: a great red teamer often hacks networks using completely different strategies than how they may solve a CTF challenge.

We believe the best way to test if an LLM can hack a network, is by seeing if an LLM can hack a network. In practice, creating realistic networks to hack, i.e., cyber ranges, at scale is a notoriously hard problem. We have been working hard on this problem and have several novel ways to generate cyber ranges at scale (we will talk about this in future blog posts!). As a result, we are able to evaluate Sonnet 4.5 on diverse cyber ranges with 20 to 50 hosts across multiple networks.

## Sonnet 4.5 can hack networks with a shell
Our baseline evaluation is to give Sonnet 4.5 access to a Kali host’s shell. Then we—politely—ask the LLMs to hack a network (one of our cyber ranges). Then, Sonnet 4.5 will begin to execute shell commands, interpret their outputs, and run more commands.

Prior LLM models struggled to hack networks with a shell. For example, Sonnet 4, was only able to hack two of our easiest cyber ranges. However, we found that Sonnet 4.5 was significantly better at using just shells to hack networks. Sonnet 4.5 was more capable and successfully hacked 2 additional cyber ranges than prior models (Figure XX). Additionally, Sonnet 4.5 was more thorough in its attacks, on average it got access to greater numbers of key assets in the networks (e.g., fake SSNs in a database).


## The future of autonomous cybersecurity
While Sonnet 4.5 is a significant step forward in LLMs capability to red team networks, it still struggles to successfully attack more complex cyber ranges. As networks grow in topology complexity, number of hosts, and types of vulnerabilities, LLMs with shells continue to struggle at executing attacks while LLMs with harnesses (such as Incalmo[]link) continue to have much higher efficacy.

We are continuing to build ever more realistic, larger, and diverse cyber ranges for: evaluating LLMs, generating large amounts of realistic attack data, and designing autonomous cybersecurity systems. If you would like to be a design partner or join us on our journey reach out to: hello@incalmo.ai
