---
layout: post
title: "Can Sonnet 4.5 hack a network?"
description: ''
date: 2025-10-01
author: Brian Singer
published: false
---

![Alt text for accessibility]({{ "/assets/sonnet_blog/monet_mural.jpg" | relative_url }}){: .rounded-lg style="width: 100%; max-width: 400px; height: auto; display: block; margin: 3rem auto; padding: 0 1rem;" }

How well can frontier models hack networks? This question is critical to safety, as it informs the risk of AI in relation to cybersecurity harm. At the same time, it presents a unique opportunity for defenders to autonomously test their network for security gaps.

Incalmo collaborated with Anthropic to develop its "most realistic" way to evaluate the cyber capabilities of frontier models to date: a suite of cyber ranges of 25-50 hosts each, which test a model’s ability to orchestrate long-horizon cyber attacks centered on infiltrating and navigating a network to gain access to and exfiltrate critical assets. (pg. 41, [Sonnet 4.5 System Card](https://assets.anthropic.com/m/12f214efcc2f457a/original/Claude-Sonnet-4-5-System-Card.pdf)) When used to evaluate Sonnet 4.5, the System Card found that Sonnet 4.5 is significantly better at hacking networks with shell harnesses than prior Claude models, but still struggles without domain-specific assistive tools ([Cyber-toolkits](https://red.anthropic.com/2025/cyber-toolkits/), [Paper](https://arxiv.org/abs/2501.16466)). For example, Sonnet 4.5 with a Kali shell is able to autonomously attack 2 additional cyber ranges than Opus 4.1 with a Kali shell. 
**In summary, the Incalmo cyber-ranges highlight how the capabilities of LLMs using just shells to hack networks is rapidly improving.**

## How to evaluate AI at hacking networks

Frontier models are often evaluated on security Q&A questions or small security challenges (e.g., exploit a vulnerability, solve a cryptography problem). While these evaluations are important, it's unclear how they translate to LLMs hacking networks. Incalmo has seen this in practice: a great red teamer often hacks networks using completely different strategies than how they may solve a CTF challenge.

The best way to test if an LLM can hack a network, is by seeing if an LLM can hack a network. In practice, creating realistic networks to hack, i.e., cyber ranges, at scale is a notoriously hard problem. Incalmo is working hard on this problem and have several novel ways to generate cyber ranges at scale (will be described in a future blog post!). As a result, Incalmo was able to evaluate Sonnet 4.5 on diverse cyber ranges with 25 to 50 hosts across multiple networks.

<blockquote style="margin: 2rem 3rem; padding: 1rem 1.5rem; font-style: italic;">
"Our most realistic evaluations of potential autonomous cyber operation risks are a suite of cyber ranges of 25–50 hosts each."
<br><br>
<span style="font-style: normal; font-size: 0.9rem; color: #64748b;">— Sonnet 4.5 System Card, pg. 41</span>
</blockquote>

<figure style="text-align: center; margin: 3rem auto; max-width: 700px; padding: 0 1rem;">
  <img src="{{ "/assets/sonnet_blog/risk_platform.png" | relative_url }}" alt="Alt text for accessibility" class="rounded-lg" style="width: 100%; max-width: 600px; height: auto; display: block; margin: 0 auto;" />
  <figcaption style="margin-top: 0.25rem; font-style: italic; color: #64748b; font-size: 0.9rem;">Figure 1. Frontier models can attack cyber-ranges with various types of harnesses such as: the domain-specific Incalmo harness or using a Kali host's shell. There is actively large amounts of research on creating new types of harnesses (e.g., XBOW, PentestGPT, etc).</figcaption>
</figure>

## Sonnet 4.5 can hack networks
Incalmo’s cyber risk platform equips an LLM with an attack harness (Fig. 1). Then we—politely—ask the LLMs to hack a network (one of our cyber ranges). In the past, Incalmo showed how introducing a domain-specific attack system enabled LLMs to hack 37 out of 40 of our cyber ranges ([See](https://arxiv.org/abs/2501.16466)). Incalmo also found that prior LLMs without Incalmo and only access to a Kali host’s shell struggled to make much progress.

**However, Sonnet 4.5 was significantly better at using just the Kali harness to hack networks than prior Claude models. Sonnet 4.5 was more capable and successfully hacked two additional cyber ranges than prior models (Figure 2).**
Additionally, Sonnet 4.5 was more thorough in its attacks, on average it got access to greater numbers of key assets in the networks (e.g., fake SSNs in a database).

<figure style="text-align: center; margin: 3rem auto; max-width: 700px; padding: 0 1rem;">
  <img src="{{ "/assets/sonnet_blog/system_card_result.png" | relative_url }}" alt="Alt text for accessibility" class="rounded-lg" style="width: 100%; max-width: 600px; height: auto; display: block; margin: 0 auto;" />
  <figcaption style="margin-top: 0.25rem; font-style: italic; color: #64748b; font-size: 0.9rem;">Figure 2. (From the Sonnet 4.5 system card) Fraction of critical assets obtained by Claude Sonnet 3.7, 4, 4.5 and Opus 4.1 with the Kali harness on four cyber-ranges. Claude Sonnet 4.5 is able to obtain critical assets in two 2 additional cyber-ranges.</figcaption>
</figure>

## The future of autonomous cybersecurity
While Sonnet 4.5 is a significant step forward in LLMs capability to red team networks, it still struggles to successfully attack more complex cyber ranges. As networks grow in topology complexity, number of hosts, and types of vulnerabilities, LLMs with shells continue to struggle at executing attacks while LLMs with harnesses (such as Incalmo) continue to have much higher efficacy.

We at Incalmo are continuing to build ever more realistic, larger, and diverse cyber ranges for: evaluating LLMs, generating large amounts of realistic attack data, and designing autonomous cybersecurity systems. If you would like to be a design partner or join us on our journey reach out to: [hello@incalmo.ai](mailto:hello@incalmo.ai)
