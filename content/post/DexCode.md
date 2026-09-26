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

- Input frame: `^<spatter>*` (e.g., `^1011*`)
- Target output: `<reversed_spatter>` (e.g., `1101`)

---

## Source Code Analysis

### The Target Specification

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

---

## Deep Dive: The Custom Regex Compiler

The most critical hurdle is understanding that standard regex assumptions do not apply. Rather than compiling rules directly with Python's `re.compile()`, the challenge routes all left-hand-side patterns through a custom parser called `_compile_fragment()`:

```python
def _compile_fragment(frag):
    out = []
    i, n = 0, len(frag)
    while i < n:
        c = frag[i]
        if c == "\\":
            out.append(re.escape(frag[i + 1]) if i + 1 < n else re.escape("\\"))
            i += 2 if i + 1 < n else 1
        elif c == "'":
            j = i + 1
            lit = []
            while j < n and frag[j] != "'":
                lit.append(frag[j])
                j += 1
            out.append(re.escape("".join(lit)))
            i = j + 1
        elif c == "[":
            # ... bracket class handling ...
            out.append(frag[i:j + 1])
            i = j + 1
        elif c in "()*+?.":
            out.append(c)
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)
```

Every character passes through one of five branches. Understanding each branch reveals the traps and the intended mechanics.

### The Strict Metacharacter Whitelist

Only six metacharacters retain standard regex behavior:

| Character | Behavior |
|-----------|----------|
| `(` `)` | Capture groups for back-references (`$1`, `$2`, ...) |
| `*` `+` `?` | Standard greedy quantifiers |
| `.` | Wildcard (matches any character) |

Notably **absent** from the whitelist:

- `^` — no start-of-string anchor
- `$` — no end-of-string anchor
- `|` — no alternation/OR operator

### The Caret (`^`) Trap

Because `^` is not in the whitelist `"()*+?."`, it falls through to the default branch:

```python
else:
    out.append(re.escape(c))
```

Every unescaped `^` is escaped into `\^` — a **literal character match**, not a positional anchor.

This initially appears problematic, until you inspect `task_wrap()`: the server frames every test case with an actual, literal `^` prefix. The author intentionally made `^` a literal matcher so it directly matches the challenge envelope's starting delimiter without requiring special escaping.

### The Dual Nature of `*`

The envelope's closing delimiter is a literal `*`. However, because `*` is in the whitelist, typing a bare `*` acts as a **quantifier** (zero or more repetitions), not a literal match.

To match the actual closing `*`, we must use one of two escape mechanisms:

- **Backslash escape** (`\*`): triggers the `c == "\\"` branch, which calls `re.escape("*")` producing `\*`
- **UTS #35 literal quotes** (`'*'`): triggers the `c == "'"` branch, extracting the character between quotes and passing it through `re.escape()`

Failing to escape the trailing asterisk causes catastrophic parse errors or greediness bugs, as the engine treats it as a repetition operator on the preceding capture group.

### Bracket Classes

The parser manually tracks bracket boundaries, accounting for the POSIX edge case where `]` immediately follows `[` or `[^` (treating it as a literal `]` rather than closing the class). Once parsed, bracket classes like `[01]` are appended **raw** without `re.escape()`, allowing standard character sets inside patterns.

---

## The Solution

```
^([01])([01]*)\* > |^$2*$1
^\* >
```

### The Core Algorithm

The rule pair implements a tape-shifting algorithm: peel bits off the front one at a time, push each one behind the `*` marker, and loop until the input is empty.

1. Strip the first bit from the left
2. Push it behind the asterisk `*`
3. Reset the cursor back to index 0 using the revisit operator `|`
4. Repeat until all bits have crossed over `*`
5. Clean up by erasing the remaining `^*`

### Rule 1 — Shift and Loop

```
^([01])([01]*)\* > |^$2*$1
```

**Left-hand side (pattern):**

| Token | Purpose |
|-------|---------|
| `^` | Matches the literal leading boundary marker |
| `([01])` | Captures the first binary bit into `$1` |
| `([01]*)` | Captures all remaining bits before `*` into `$2` |
| `\*` | Matches the literal trailing asterisk |

**Right-hand side (replacement):**

| Token | Purpose |
|-------|---------|
| `\|` | Revisit cursor — resets the engine's read position to index 0 |
| `^$2*$1` | Rewrites the string: remaining bits `$2` stay inside the markers, while the first bit `$1` moves behind the asterisk |

### Rule 2 — Cleanup and Termination

```
^\* >
```

The engine checks rules top to bottom. As long as at least one digit exists between `^` and `*`, Rule 1 always matches first.

Once every digit has crossed over `*`, the string begins with `^*` — adjacent markers with nothing between them. Rule 1 fails, so the engine falls through to Rule 2, which matches the bare delimiter pair and replaces it with **nothing**. Both boundary markers are erased, leaving only the clean, reversed binary string.

---

## Execution Trace: `^1011*` to `1101`

```
Input:  ^1011*

Step 1  ^1011*    Rule 1: $1=1, $2=011  -->  ^011*1    cursor -> 0
Step 2  ^011*1    Rule 1: $1=0, $2=11   -->  ^11*01    cursor -> 0
Step 3  ^11*01    Rule 1: $1=1, $2=1    -->  ^1*101    cursor -> 0
Step 4  ^1*101    Rule 1: $1=1, $2=     -->  ^*1101    cursor -> 0
Step 5  ^*1101    Rule 2: ^* matched    -->  1101      done

Output: 1101
```

Each iteration peels the leftmost bit and prepends it to the output section after `*`. Since prepending reverses insertion order, the final result is the reversed string.

---

## Solver

Paste the two rules into a netcat session, followed by a blank line to submit:

```bash
nc 169.58.140.254 8110
```

```
^([01])([01]*)\* > |^$2*$1
^\* >

```

Or use the Python solver:

```python
#!/usr/bin/env python3
import socket, time

HOST, PORT = "169.58.140.254", 8110
RULES = [
    "^([01])([01]*)\\* > |^$2*$1",
    "^\\* >",
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

## Flag

```
CATF{REDACTED}
```
