---
title: A Write-up Template I Can Reuse
description: A practical structure for capturing recon, exploitation, privilege escalation, and proof without losing the thread.
date: 2026-03-25T09:30:00+02:00
lastmod: 2026-03-25T09:30:00+02:00
tags:
  - template
  - methodology
  - notes
categories:
  - writeup
cover: "covers/shell-access.svg"
---

When I skip structure, I lose details. When I over-structure, I stop writing. This is the middle ground I keep coming back to for HTB boxes, CTF challenges, and internal lab notes.

<!--more-->

## Front matter I care about

- Target name and difficulty
- Date completed
- Tags for the actual techniques used
- A short description that explains the core chain

## Sections that usually matter

### 1. Recon

Start with what changed your understanding of the target. Skip the noise and keep the evidence that mattered.

```text
Open ports
Interesting headers
Tech stack hints
Credentials, leaks, or trust boundaries
```

### 2. Initial Access

Document the exploit path in order. If a bug needs a specific precondition, say it clearly.

### 3. Privilege Escalation

Capture the checks you ran, the signal you noticed, and the one thing that made the jump possible.

### 4. Proof and Cleanup

Keep a short proof section with the final artifact, then add anything worth fixing or watching.

## Why this format works for me

It keeps the post readable for someone else, but it is also practical for me six months later when I need the same idea again and only remember half the command chain.
