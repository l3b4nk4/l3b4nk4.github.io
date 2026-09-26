---
title: "DexCode"
description: "CTF misc challenge"
summary: "A UTS #35 transliteration challenge: write rewriting rules that reverse an arbitrary binary string — solved with a two-rule regex-capture loop."
date: 2026-09-26T00:00:00+02:00
lastmod: 2026-09-26T00:00:00+02:00
tags:
  - CTF
  - walkthrough
  - misc
  - UTS35
  - transliteration
  - string-rewriting
categories:
  - writeup
draft: true
---

## Goal

Submit a ruleset that transforms framed binary samples into their reversed binary representations, leaving no marker characters behind.

* Input frame: `^<spatter>*` (e.g., `^1011*`)
* Target output: `<reversed_spatter>` (e.g., `1101`)

## Source Code Analysis

### 1. The Target Specification

The scoring logic wraps inputs and checks outputs with two core functions:

```python
def task_wrap(bits): 
    return "^" + bits + "*" 

def task_expected(bits): 
    return bits[::-1] 
```

The test runner iterates through fixed inputs (e.g., `""`, `"0"`, `"1011"`, `"1000000000000001"`) and 30 randomized binary strings up to 16 bits:

```python
def judge(rules_text): 
    rules = parse_rules(rules_text) 
    failures = [] 
    for bits in build_tests(): 
        want = task_expected(bits) 
        try: 
            got = rewrite(rules, task_wrap(bits)) 
        except ValueError as e: 
            got = "<%s>" % e 
        if got != want: 
            failures.append({"input": task_wrap(bits), "want": want or "(empty)", 
                             "got": got or "(empty)"}) 
            if len(failures) >= 5: 
                break 
    return {"ok": not failures, "failures": failures} 
```

If `failures` is empty, the server grants the flag:

```python
if r["ok"]:
    self.sendln("  🩸  Slide: %s" % FLAG)
```
