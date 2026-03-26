---
title: "A Very Small Locker"
description: "CTF web challenge"
summary: "A web challenge with two paths: an unintended NoSQL injection shortcut, and the intended chain of business logic, XSS, and IDOR."
date: 2025-11-16T10:45:12+02:00
lastmod: 2025-11-16T10:45:12+02:00
tags:
  - CTF
  - walkthrough
  - web
  - XSS
categories:
  - writeup
cover: "covers/a-very-small-locker.png"
draft: false
---

<!--more-->

I wanted to write up **A Very Small Locker**, a web challenge from Pwnsec CTF, because it had two very different solve paths.

The unintended solution is a quick NoSQL injection. The intended route is much nicer: a business logic bug, then XSS, then an IDOR-style privilege bypass to recover the leaked flag.

## Unintended solve

Starting from the source code, the first important clue was that the flag lived at `/master/confedential`.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*yTYBnmZjKFdGlMzRUQgSRA.png)

That page was supposed to be accessible only to masters. Since the backend used Mongoose, my first thought was **NoSQL injection**.

MongoDB supports operators like `$regex`, so if the login endpoint accepts unsanitized input, it is possible to match credentials without knowing the exact value.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*zpX07DRyIPNjjU4vaWJ4gw.png)

After logging in as the master account, visiting `/master/confedential` gives the flag immediately.

That solves the challenge, but it is not the intended path.

## Intended solve

The intended route was more interesting. The goal was to make the bot visit `/master/confedential` and leak the result somewhere I could later read.

The useful sink was `/transactions/search?searchTerm=...`, but before I could talk to the bot through `/master`, I needed more than `10000000000000` in my balance.

### Step 1: Infinite money with a negative transfer

Looking at the transfer logic, the application did not block negative values.

![captionless image](https://miro.medium.com/v2/resize:fit:1364/format:webp/1*0dK1JHb0RJyFJQpHrt68pg.png)

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*Eqt7Hui-oPOsFRKu92PV2Q.png)

So instead of losing money, I could transfer a negative amount and increase my own balance.

> What happens if we transfer a negative number?

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*TYJEm2Lahoe0A6IjDmTRqA.png)

That gave me effectively infinite money.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*B9kkbDU82wdKefNzQARc-w.png)

Now `/master` was available.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*zUre7fT9HEOUPCe_o1CwRA.png)

### Step 2: Turning the message feature into XSS

At this point I could send a message to the bot, but the page had CSP protections, so the obvious payloads failed.

![captionless image](https://miro.medium.com/v2/resize:fit:1272/format:webp/1*St5cSnIUN6s47U1TIFCBZw.png)

I ran the challenge locally to understand exactly how the input was rendered.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*jRBqKuLJ22ahNuKVhm5J1g.png)

The key detail was that `userMessage` ended up inside a JavaScript template expression like `${"test"}`.

So the problem became: how do we break out of that expression and append our own one? In other words, how do we turn it into something like `${"test"}${alert()}`?

After some trial and error, I got a working alert.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*qO37eLosEMhfP3wwjF-IIA.png)

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*h8Fng53QBLqHGCvd2RCN2w.png)

Once I had XSS, I used it to fetch `/master/confedential` and push the result into the transaction search flow with this payload:

```js
\"}${fetch(`/master/confedential`).then(function(r){return r.text()}).then(function(d){return fetch(`/transactions/search?searchTerm=${btoa(d)}`)})}
```

The idea is simple:

1. make the bot request `/master/confedential`
2. read the response body
3. base64-encode the content
4. send it to `/transactions/search?searchTerm=...`

### Step 3: Reaching the leaked data

I could access the search page here:

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*lljmWt0NqJfa9dAnIsIS7g.png)

In the transaction history, I found the master's id.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*HpgAbVH5q6Gn3bKnK8xdhg.png)

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*RsQmtqxxCwYThkVIUWAQpQ.png)

That led to the last part of the challenge.

### Step 4: Business logic bug to read the history

Taking a look at the history-checking function:

![captionless image](https://miro.medium.com/v2/resize:fit:1098/format:webp/1*mS9bUkDWA8duHrSxyuuWLQ.png)

The application decided whether someone was a bank master by checking the account holder's last name. If the last name matched the expected "Bank Master" pattern, the server treated that user as privileged.

My own bank master was named:

![captionless image](https://miro.medium.com/v2/resize:fit:462/format:webp/1*RIKgmNAwgDGbGt4gx5bnww.png)

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*HehzRX-eUNJztRDQV5jQtg.png)

`test's Bank Master`

So I changed my last name to:

`test's Bank Master's Bank Master`

That way, the application treated me as the bank master of my bank master, which let me access the privileged transaction history.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*57YPepQgGDcSsBikacxStg.png)

Inside the history was the base64-encoded data from the XSS step.

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*sqbRdNPyr6h89bPd1k5d6g.png)

After decoding it, I finally got the flag.


