---
layout: post
title:  "Cheatsheet - Stable Shell Linux"
description: Performing Stable Shell on Linux
tags: Cheatsheet Linux 
---

Guide to get **Stable Shell** in **Linux**

## TTY Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
/usr/bin/script -qc /bin/bash /dev/null
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
echo os.system('/bin/bash')
/bin/sh -i
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
```


## Stabilization Process

```bash
# Victim

python -c 'import pty; pty.spawn("/bin/bash")' # Any TTY Shell
export TERM=xterm
stty cols 132 rows 34
Ctrl+z

# Attacker

stty raw -echo; fg
```
