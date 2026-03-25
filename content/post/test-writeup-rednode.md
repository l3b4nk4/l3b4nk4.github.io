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

`I Hate PHP` is a web challenge you need RCE to get the flag from the server .

<!--more-->

## the code we have 

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

## the 1st step

 I read the files `/proc/self/cmdline` that i confirmed  that `session.upload_progress.enabled=On` and the second file was `/proc/self/environ` that i confirmed `The built-in PHP server is using 4 workers via PHP_CLI_SERVER_WORKERS=4` that helps in race condition we gonna demonstatrate later 

