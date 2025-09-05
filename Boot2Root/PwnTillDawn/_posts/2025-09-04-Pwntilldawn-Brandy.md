---
layout: post
title:  "PwnTillDawn - Brandy (Difficult)"
tags: PwnTillDawn Linux Boot2Root Difficult
media_subpath: /assets/img/writeups/PwnTillDawn/Brandy/
image:
  path: Brandy.png
---

## At a glance

| Item                 | Details       |
| -------------------- | ------------- |
| **Type**             | Boot2Root     |
| **Difficulty**       | Difficult     |
| **IP Address**       | 10.150.150.27 |
| **Operating System** | Linux         |

## Recon

* **Passive**: tech stack, endpoints, robots, JS routes, third‑party assets
* **Active**: directory brute‑force, API discovery, parameter mining

```bash
# Check for any open port
nmap 10.150.150.27
```

![Nmap Result](nmap.png)

Shows SSH and HTTP port open.

```bash
# Check for any common directories
dirsearch -u http://10.150.150.27
```

![Dirsearch Result](dirsearch.png)

From this result there are two accesible path:

  - /cart/
  - /master/

1. /cart/

![/cart Result](cart.png)

From this result we retrive the first flag and domain for the IP.
<crm.pwntilldawn.com>

> FLAG61=2971f3459fe55db1237aad5e0f0a259a41633962

2. /master/

![/master Result](master.png)

For the second path, we know that the creator always use **rick** for everything. So we figure out that **rick** is common username and password for this challenge.
