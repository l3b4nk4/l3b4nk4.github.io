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
cover: "covers/DexCode.webp"
draft: false
---

## Challenge Overview

**DexCode** is a misc challenge where you connect to a TCP service running a custom string-rewriting engine — a subset of [UTS #35 transliteration](https://seriot.ch/computation/uts35/) — and write rules that **reverse any binary string** up to 16 bits long. No variables, no loops, no conditionals: just ordered pattern-replacement rules applied left-to-right. As Seriot's research shows, this minimal system is Turing-complete.

---

## Goal

Submit a ruleset that transforms framed binary samples into their reversed binary representations, leaving no marker characters behind.

- Input frame: `^<bits>*` (e.g., `^1011*`)
- Target output: `<reversed_bits>` (e.g., `1101`)

---

## Source Code Analysis

### The Target Specification

The scoring logic wraps every test input in a frame and compares the rewriting engine's output against the Python-reversed string:

```python
def task_wrap(bits):
    return "^" + bits + "*"

def task_expected(bits):
    return bits[::-1]
```

So for the input `"1011"`, the engine receives the string `"^1011*"` and must produce `"1101"`.

### The Test Suite

The judge iterates through 13 fixed inputs (including edge cases like `""`, `"0"`, `"1"`, `"1000000000000001"`) plus 30 randomized binary strings of varying length (up to 16 bits). If any single test case fails, the submission is rejected. The server stops after 5 failures:

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

Only when every test passes does the server reveal the flag:

```python
if r["ok"]:
    self.sendln("  🩸  Slide: %s" % FLAG)
```

### The Rewriting Engine

Before diving into the solution, it is essential to understand how the engine actually processes rules. The `rewrite()` function maintains a **cursor** (an integer index `i`) that starts at position 0 and scans the string left to right:

```python
def rewrite(rules, s):
    i = steps = 0
    while i <= len(s):
        for rule in rules:
            m = rule.regex.match(s, i)
            if not m:
                continue
            text, cur = _expand(rule.result, m)
            s = s[:i] + text + s[m.end():]
            i += len(text) if cur is None else cur
            steps += 1
            if steps > STEP_BUDGET:
                raise ValueError("step budget exceeded (does it halt?)")
            break
        else:
            i += 1
    return s
```

At each cursor position, the engine tries every rule **in file order**. The first rule whose pattern matches at the current cursor position fires: the matched portion of the string is replaced with the rule's output, and the cursor is repositioned. If no rule matches, the cursor simply advances one position to the right.

Two critical details about cursor behavior:

1. **Without a `|` marker in the output**: the cursor advances past the entire replacement text (`i += len(text)`). The engine moves forward and never revisits what it just wrote.
2. **With a `|` marker in the output**: the cursor moves to `match_start + offset_of(|)`. This is the key to looping — placing `|` at the very beginning of the output resets the cursor back to the match start position.

The engine also enforces a hard step budget of **400,000** rule applications. Any ruleset that doesn't terminate within this budget is rejected.

---

## Deep Dive: The Custom Regex Compiler

The most critical hurdle in this challenge is understanding that **standard regex assumptions do not apply**. Rather than compiling rules directly with Python's `re.compile()`, the challenge routes all left-hand-side patterns through a custom sanitization parser called `_compile_fragment()`. This parser decides, character by character, what becomes a regex metacharacter and what becomes a literal match:

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
            # bracket class handling with POSIX edge cases
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

Every character passes through one of five branches. Understanding each branch is essential to crafting a working ruleset.

### Branch 1: Backslash Escape (`\\`)

When the parser encounters a backslash, it takes the **next** character and wraps it in `re.escape()`, forcing it to be treated as a literal. This is how you match characters that would otherwise be interpreted as regex metacharacters.

For example, writing `\*` in a rule causes the parser to produce `\*` in the compiled regex — matching a literal asterisk character, not the "zero or more" quantifier.

### Branch 2: Single-Quote Literals (`'...'`)

The UTS #35 standard defines a quoting mechanism: anything between single quotes is treated as literal text. The parser extracts everything between the quotes and passes it through `re.escape()`.

Writing `'*'` has the same effect as `\*` — it matches a literal `*`. This is particularly useful for multi-character sequences: `'^*'` would match the literal string `^*` without needing to escape each character individually.

### Branch 3: Bracket Character Classes (`[...]`)

The parser manually tracks bracket boundaries, correctly handling the POSIX edge case where `]` immediately follows `[` or `[^` (treating it as a literal `]` inside the class rather than closing it). Once the class boundaries are found, the entire bracket expression is passed through **raw** — no `re.escape()` — preserving standard character class semantics.

This is why `[01]` works as expected: it matches either `0` or `1`, giving us a way to match any binary digit in a single token.

### Branch 4: The Metacharacter Whitelist (`()*+?.`)

Only **six** characters retain their standard regex behavior:

| Character | Behavior |
|-----------|----------|
| `(` `)` | Create capture groups for back-references (`$1`, `$2`, ...) |
| `*` `+` `?` | Greedy quantifiers (zero-or-more, one-or-more, zero-or-one) |
| `.` | Wildcard — matches any single character |

Everything else falls through to Branch 5.

### Branch 5: The Default — Literal Escape

Any character not handled by the previous four branches is passed through `re.escape()`, turning it into a **literal match**. This is where several important "gotchas" hide:

**The Caret (`^`) Trap:**
In standard regex, `^` is a start-of-string anchor. But because `^` is absent from the metacharacter whitelist `"()*+?."`, it falls through to the default branch and gets escaped into `\^` — a literal character match. This seems like a problem until you realize the challenge intentionally uses a literal `^` character as the input frame's opening delimiter. The parser's behavior and the challenge design are aligned: writing `^` in your rule pattern matches the actual `^` character in the input.

**The Asterisk (`*`) Duality:**
The envelope's closing delimiter is a literal `*` character. But because `*` IS in the metacharacter whitelist, writing a bare `*` in your pattern acts as the "zero or more" quantifier — it does NOT match the literal asterisk. To match the actual `*` delimiter, you must escape it using either `\*` (Branch 1) or `'*'` (Branch 2). Forgetting to do this is the most common mistake: the engine will interpret `*` as a repetition operator on whatever precedes it, causing bizarre parse errors or infinite greediness bugs.

**Missing Operators:**
Standard regex features like `^` (anchor), `$` (end anchor), and `|` (alternation) are all absent from the whitelist. They get escaped into literals. The `|` character in the replacement side has a completely different meaning — it is the UTS #35 **revisit cursor**, not a regex OR operator.

---

## Understanding UTS #35 Transliteration

The challenge implements a subset of the [Unicode UTS #35 transliteration](https://seriot.ch/computation/uts35/) standard. In the full standard, transliteration rules are used to convert text between writing systems (e.g., Cyrillic to Latin). But as [Seriot's research](https://seriot.ch/computation/uts35/) proves, this rule system is **Turing-complete** — it can compute anything a general-purpose computer can.

The key features that make it computationally powerful are:

1. **Ordered rule application**: rules are tried top-to-bottom, and the first match wins. This creates implicit conditional logic — later rules act as "else" branches.
2. **The revisit cursor (`|`)**: this allows the engine to loop by sending the cursor back to a previous position, enabling unbounded iteration.
3. **Capture groups and back-references**: `$1`, `$2`, etc. allow rules to rearrange matched substrings, not just replace them.

Together, these three features give you the equivalent of a read/write head on a tape — a Turing machine. The string IS the tape, the cursor IS the head, and the rules ARE the transition table.

---

## The Solution

```
^([01])([01]*)\* > |^$2*$1
^\* >
```

That's it. Two rules. Let's break down exactly how and why they work.

### The Core Idea

Think of the input string as having two zones separated by the `*` marker:

```
^  1 0 1 1  *
   ^^^^^^^^
   work zone    output zone (initially empty)
```

The algorithm repeatedly takes the **first** bit from the work zone and moves it to the **front** of the output zone (right after `*`). Because each bit is inserted at the front rather than the back, the output accumulates in reversed order:

```
Work zone    Output zone    Bit moved
---------    -----------    ---------
1 0 1 1      (empty)        —
0 1 1        1              first bit "1" moved
1 1          0 1            "0" prepended before "1"
1            1 0 1          "1" prepended before "01"
(empty)      1 1 0 1        "1" prepended before "101"
```

When the work zone is empty, the cleanup rule erases the `^*` markers and the reversed string remains.

### Rule 1 — Shift and Loop

```
^([01])([01]*)\* > |^$2*$1
```

**Left-hand side (what it matches):**

| Token | Compiled Regex | What it does |
|-------|---------------|--------------|
| `^` | `\^` | Matches the literal `^` opening marker |
| `([01])` | `([01])` | Captures the **first** binary bit into group `$1` |
| `([01]*)` | `([01]*)` | Captures **all remaining** bits (zero or more) into group `$2` |
| `\*` | `\*` | Matches the literal `*` closing marker |

The full compiled regex is `\^([01])([01]*)\*`. It matches the entire frame from `^` through `*`, splitting the bits into "first bit" (`$1`) and "everything else" (`$2`).

Note that `\*` only matches the first literal `*` in the string (the boundary marker). Any bits that have already been moved past `*` into the output zone are left untouched — they sit beyond the match boundary.

**Right-hand side (what it produces):**

| Token | What it does |
|-------|--------------|
| `\|` | **Revisit cursor** — tells the engine to reset its reading position to the start of the match (index 0). Without this, the cursor would advance past the replacement and the engine would never loop back to process the next bit. |
| `^` | Writes the literal `^` marker back |
| `$2` | Writes back the remaining bits (everything except the first bit) |
| `*` | Writes the literal `*` marker back (in the replacement side, `*` is just a literal character — no escaping needed) |
| `$1` | Writes the captured first bit **after** the `*` marker, effectively prepending it to the output zone |

**Why `*` doesn't need escaping on the right side:**
The replacement string is processed by `_expand()`, which is a completely different function from `_compile_fragment()`. In `_expand()`, `*` has no special meaning — it is just a literal character. Only `|`, `$`, and `\` are treated specially in the replacement.

### Rule 2 — Cleanup and Termination

```
^\* >
```

This rule matches the literal string `^*` — the opening and closing markers sitting directly next to each other with no bits between them.

**When does it fire?** The engine always tries rules in file order. As long as there is at least one bit between `^` and `*`, Rule 1's pattern `\^([01])([01]*)\*` matches first (because `[01]` requires at least one digit). Rule 2 never gets a chance to fire.

Once every bit has been moved to the output zone, the string looks like `^*1101`. Now Rule 1 fails — there are no `[01]` characters between `^` and `*` for it to match. The engine falls through to Rule 2, which matches the bare `^*` and replaces it with **nothing** (empty right-hand side). The markers are deleted, leaving only `1101` — the clean, reversed string.

**Why doesn't the cursor loop forever?** Rule 2 has no `|` marker, so the cursor advances past the (zero-length) replacement. It then scans through `1101` one character at a time, finds no matching rules at any position, and exits the while loop. The rewriting is complete.

---

## Execution Trace

Let's walk through the complete execution of `^1011*` step by step, showing the string state, which rule fires, the capture groups, and the cursor position after each step.

### Input: `^1011*`

```
Step 1:
  String:  ^1011*          Cursor: 0
  Rule 1 matches: ^([01])([01]*)\*
    $1 = "1"    (first bit)
    $2 = "011"  (remaining bits)
  Replace with: |^$2*$1 = ^011*1
  String:  ^011*1          Cursor: 0 (reset by |)

Step 2:
  String:  ^011*1          Cursor: 0
  Rule 1 matches: ^([01])([01]*)\*
    $1 = "0"    (first bit)
    $2 = "11"   (remaining bits)
  Replace with: |^$2*$1 = ^11*0
  String:  ^11*01          Cursor: 0 (reset by |)

Step 3:
  String:  ^11*01          Cursor: 0
  Rule 1 matches: ^([01])([01]*)\*
    $1 = "1"    (first bit)
    $2 = "1"    (remaining bits)
  Replace with: |^$2*$1 = ^1*1
  String:  ^1*101          Cursor: 0 (reset by |)

Step 4:
  String:  ^1*101          Cursor: 0
  Rule 1 matches: ^([01])([01]*)\*
    $1 = "1"    (first bit)
    $2 = ""     (no remaining bits)
  Replace with: |^$2*$1 = ^*1
  String:  ^*1101          Cursor: 0 (reset by |)

Step 5:
  String:  ^*1101          Cursor: 0
  Rule 1 fails (no [01] between ^ and *)
  Rule 2 matches: ^\*
  Replace with: (empty)
  String:  1101            Cursor: 0

Steps 6-9:
  Cursor scans positions 0-3: "1", "1", "0", "1"
  No rules match at any position. Cursor exits.

Output: 1101
```

### Why Prepending Reverses

The reversal works because each bit is **prepended** to the output zone, not appended:

| Step | Bit moved | Output zone (after `*`) | Reading order |
|------|-----------|------------------------|---------------|
| 1 | `1` | `1` | `1` |
| 2 | `0` | `01` | `0, 1` |
| 3 | `1` | `101` | `1, 0, 1` |
| 4 | `1` | `1101` | `1, 1, 0, 1` |

The original string `1011` read left-to-right becomes `1101` — exactly the reverse.

### Edge Cases

**Empty string** (`^*`): Rule 1 fails immediately (no bits to capture). Rule 2 matches `^*` and deletes it. Output: empty string. Correct.

**Single bit** (`^0*`): Rule 1 fires once, moving `0` past `*`, giving `^*0`. Then Rule 2 deletes `^*`. Output: `0`. Correct (a single character reversed is itself).

### Step Complexity

For an n-bit input, the algorithm performs exactly **n + 1** rule applications (n shifts + 1 cleanup), followed by a linear scan of the n-character output. Total: **O(n)** steps. Even the largest test case (16 bits) uses only ~33 steps — well within the 400,000 step budget.

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

(the trailing blank line signals end of input)

Or use the automated Python solver:

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

---

## References

- [UTS #35: Turing-Completeness of Unicode Transliteration](https://seriot.ch/computation/uts35/) — Seriot's proof that this rule system can compute anything, including the theoretical foundation behind this challenge.
- [Unicode Technical Standard #35](https://unicode.org/reports/tr35/tr35-general.html#Transform_Rules_Syntax) — the official specification for transliteration transform rules.

## Flag

```
CATF{th3_c0d3_0f_h4rry_r3v3r535_bl00d}
```
