## Vulnversity
Find SUID files
  
    find / -user root -perm -4000 -exec ls -ldb {} \;
