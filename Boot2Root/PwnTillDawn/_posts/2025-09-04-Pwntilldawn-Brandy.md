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

    ![Cart Path Result](cart.png)

    From this result we retrive the first flag and domain for the IP which is `crm.pwntilldawn.com`.

    > **FLAG61=2971f3459fe55db1237aad5e0f0a259a41633962**

2. /master/

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

## CVE 2017-9840

Actually, I think this is the intended vulnerability for this challenge but then, I figure there are other CVE that can be exploited by rick user to perform arbitrary code execution.

> Why this is the intended way?
> Unauthorized -> Authorized as Rick -> SQL Injection -> Authorized as Cliff -> Insecure File Upload -> Arbitrary Code Execution.
{: .prompt-info }
