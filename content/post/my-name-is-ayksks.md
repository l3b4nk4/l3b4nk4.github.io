---
title: "My name is ayksks "
description: "CTF WEB challenge"
summary: "This is the challenge where I achieved second blood: XSS → SSRF → RCE."
date: 2025-12-09T15:22:45+02:00
lastmod: 2025-12-09T15:22:45+02:00
tags:
  - CTF
  - walkthrough
  - web
categories:
  - writeup
cover: "covers/react2shell.png"
draft: false
---



![captionless image](https://miro.medium.com/v2/format:webp/1*CGLTlcsRaGg97iBUpETMJw.png)

> _Note: the bot has no internet_
> 
> _Note: the flag is in a random file_
> 
> _meaning we need RCE_
## XSS
there is a bot we need XSS to get admin cookie and login as admin after trying injecting payloads in the Parameters and finally An alert popped up.

![captionless image](https://miro.medium.com/v2/format:webp/1*dq_wZegtfqWRD4LKOOZBtQ.png)

and it was in not expected parameter and there is the payload

![captionless image](https://miro.medium.com/v2/resize:fit:1086/format:webp/1*RZRZgxub5R2zxU6fhACrfA.png)

in /upload and when you upload anything becomes in your logs and u can report it to the admin

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*g48qlnV_XsJ1ygZyOwzc3Q.png)

we can get the token admin but the admin does not connect to network how can we get admin cookie??

> `1- Deliver payload to XSS for the bot`
> 
> `2-Execute document.cookie`
> 
> `3-make the admin upload his cookie with my cookie`
> 
> 4`–we got admin cookie in our logs`

with this payload we can get admin cookie
### get admin cookie
```
<script>var c=document.cookie;document.cookie='token=YOUR_COOKIE;path=/upload';var f=new FormData();f.append('description',c);fetch('/upload',{method:'POST',body:f});</script>
```

after inject the payload in the logs and report it we can get admin cookie

![captionless image](https://miro.medium.com/v2/format:webp/1*UHsMupRH5sqMJFX6Ji8PRA.png)

after get admin cookie we can use it and /admin now is available and there is a Check health for links

![captionless image](https://miro.medium.com/v2/format:webp/1*0rC6V8ayL9ObJFTLaCVMLQ.png)

now we need RCE to get the flag because it was random file how can we get RCE from SSRF ??
Now it is time for our New CVE React2shell ([CVE-2025–66478](https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp))and when you type [http://internal-service:1337](http://internal-service:1337/) and check Health It sends the request powered by next.js

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*4FfCG9wgj4Dt4kDXmEIcnw.png)
## React2shell

Now it is time to get RCE with react2shell and this the request sent to service

![captionless image](https://miro.medium.com/v2/format:webp/1*yVzORz4L3f5AAuWj3GNjXw.png)

and this is the request send two the service

```
GET / HTTP/1.1
User-Agent: DevPortal-AdminBot/1.0
Host: internal-service:1337
Connection: keep-alive
```

we need to make it like that

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*xDGSSB484Oko07KurijvKg.png)

after struggling a get the perfect payload to Get RCE

![captionless image](https://miro.medium.com/v2/resize:fit:1314/format:webp/1*gg3Wo8wPt-ky0I68jCCY1w.png)
### RCE 

we get the id

![captionless image](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*iQHEnfD7Deo5VSG0911uuQ.png)

and here is the flag

![captionless image](https://miro.medium.com/v2/format:webp/1*qyGIxCvN5jk-F9Fh7MHu3g.png)

## flag
> `_nullctf{br0_7h15_3xpl017_15_50_r3c3n7_why_d1d_y0u_m4k3_7h15_4_ch4ll3ng3}_`

woo-hoo, we got the flag

And that’s a wrap for this challenge — see you in the next hack!👾
