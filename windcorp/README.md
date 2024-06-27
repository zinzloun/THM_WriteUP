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
Navigating the site we can see that the IM client used is [Spark](https://www.igniterealtime.org/projects/spark). Using searchspolit to find some exploits but I found nothing.

The search input does nothing since the form does not perform any action. Indeed the change password form return the following response. Inspecting the workflow in Burp:

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
ChangeMe#1234

  


    

  


  

    
