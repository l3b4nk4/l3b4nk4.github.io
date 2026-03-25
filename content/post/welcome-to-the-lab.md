---
title: Welcome to the Lab
description: What this blog is for, how I document work, and what kind of write-ups are coming next.
date: 2026-03-25T09:20:00+02:00
lastmod: 2026-03-25T09:20:00+02:00
tags:
  - intro
  - workflow
categories:
  - blog
cover: "covers/recon-grid.svg"
---

This site is where I keep the clean version of the mess: write-ups, CTF notes, small methodology posts, and the command history that was actually worth saving.

<!--more-->

I wanted a place that feels closer to a field notebook than a portfolio. The goal is simple: document enough context that I can come back weeks later and still understand the path from first recon to final proof.

## What to expect

- End-to-end lab and challenge write-ups
- Short notes on recon, web testing, and privilege escalation
- Commands that are ready to replay instead of screenshots without context
- Honest dead ends when they teach something useful

## Baseline workflow

Most write-ups here will follow the same shape:

1. Define the target and scope.
2. Capture recon that changes the attack surface.
3. Walk through the exploit chain with evidence.
4. Close with proof, cleanup notes, and lessons worth keeping.

## A tiny example

```bash
nmap -Pn -sCV -oA scans/initial 10.10.10.10
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

The blog is live, the structure is set, and the next step is filling it with real targets.
