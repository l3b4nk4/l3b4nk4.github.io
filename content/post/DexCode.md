---
title: "DexCode"
description: "CTF misc challenge"
summary: "A UTS #35 transliteration challenge: write rewriting rules that reverse an arbitrary binary string — solved with a three-rule regex-capture loop."
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
draft: false
---

## Challenge Summary

**DexCode** is a miscellaneous/programming challenge themed around Dexter Morgan's "Code." You connect to a TCP service that implements a subset of [UTS #35 transliteration](https://seriot.ch/computation/uts35/) — a rule-based string rewriting system. The task: write a set of rewriting rules that **reverse any binary string**.

Input arrives framed as `^BITS*` (e.g. `^1011*`), and the rules must produce the reversed bits with both markers removed (e.g. `1101`).

The server tests your ruleset against fixed strings and 30 random binary strings up to 16 bits long. Pass them all and you get the flag.

## Understanding the Rewriting Engine

Each rule has the form:

```
LEFT { KEY } RIGHT > RESULT ;
```

- **KEY** is a regex-like pattern matched at the current cursor position.
- **LEFT** / **RIGHT** are optional lookbehind / lookahead contexts.
- If there are no braces, the entire left-hand side is the KEY.
- **Scanning** runs left-to-right. The first rule (in file order) whose KEY matches at the cursor fires. If no rule matches, the cursor advances one position.
- The **RESULT** replaces the matched KEY text. It supports `$1`–`$9` back-references and a single cursor marker `|`. After a rewrite, scanning resumes at `match_start + offset_of(|)`. Without `|`, the cursor advances past the replacement.
- Single-quoted text (e.g. `'*'`) in the KEY is matched literally.
- The engine has a step budget of 400,000.

## The Reversal Algorithm

The key insight: we can match from position 0 every time by anchoring our patterns on `^`, and use `|` at the start of the result to reset the cursor back to position 0 after each rewrite.

The algorithm repeatedly strips the first bit after `^` and appends it right after `*`. Since each bit is inserted at the front of the output section (between `*` and the previously moved bits), this naturally builds the reversed string:

```
^1011*          start
^011*1          move 1 → prepend to output
^11*01          move 0 → prepend to output
^1*101          move 1 → prepend to output
^*1101          move 1 → prepend to output
1101            clean up ^* → done
```

Each step uses a regex like `\^0(.*)\*` to capture everything between the first bit and the `*` marker, then reconstructs the string without that first bit, placing it after `*`.

## The Solution — 3 Rules

```
'^'0(.*)'*' > |^$1*0
'^'1(.*)'*' > |^$1*1
'^''*' >
```

### How each rule works

| Rule | Regex | Fires when | Effect |
|------|-------|-----------|--------|
| `'^'0(.*)'*' > \|^$1*0` | `\^0(.*)\*` | First bit after `^` is `0` | Removes leading `0`, appends it after `*` |
| `'^'1(.*)'*' > \|^$1*1` | `\^1(.*)\*` | First bit after `^` is `1` | Removes leading `1`, appends it after `*` |
| `'^''*' >` | `\^\*` | `^` is directly before `*` (no bits left) | Removes both markers, leaving the reversed output |

The `|` at the start of every result keeps the cursor at position 0, so the next iteration immediately picks up the next bit. The `(.*)` capture group grabs everything between the consumed bit and `*`, and `$1` puts it back in place.

### Complexity

For an n-bit input, the algorithm runs exactly n+1 rule applications (n bit-moves + 1 cleanup), plus a linear scan of the final output where no rules match. Total steps: O(n). A 16-bit input uses roughly 33 steps — well within the 400,000 step budget.

## Detailed Trace: `^1011*` → `1101`

```
Step 1: cursor=0, rule 2 fires on "^1011*"
        match: ^1(011)* → result: ^011*1
        string: "^011*1", cursor reset to 0

Step 2: cursor=0, rule 1 fires on "^011*1"
        match: ^0(11)* → result: ^11*0
        string: "^11*01", cursor reset to 0

Step 3: cursor=0, rule 2 fires on "^11*01"
        match: ^1(1)* → result: ^1*1
        string: "^1*101", cursor reset to 0

Step 4: cursor=0, rule 2 fires on "^1*101"
        match: ^1()* → result: ^*1
        string: "^*1101", cursor reset to 0

Step 5: cursor=0, rule 3 fires on "^*1101"
        match: ^* → result: (empty)
        string: "1101", cursor at 0

Step 6-9: cursor scans "1101" left to right, no rules match.
          Final output: "1101" ✓
```

## Solver Script

```python
#!/usr/bin/env python3
import socket, time

HOST, PORT = "169.58.140.254", 8110
RULES = [
    "'^'0(.*)'*' > |^$1*0",
    "'^'1(.*)'*' > |^$1*1",
    "'^''*' >",
    "",
]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect((HOST, PORT))

data = b""
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
        if b"> " in data: break
    except socket.timeout: break
print(data.decode("utf-8", "replace"))

for line in RULES:
    s.sendall((line + "\n").encode())
    time.sleep(0.1)

data = b""
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    except socket.timeout: break
print(data.decode("utf-8", "replace"))
s.close()
```

Or simply paste the three rules into a netcat session:

```bash
nc 169.58.140.254 8110
```

Then type:

```
'^'0(.*)'*' > |^$1*0
'^'1(.*)'*' > |^$1*1
'^''*' >

```

(blank line to submit)

## Flag

```
CATF{REDACTED}
```
