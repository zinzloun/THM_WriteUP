## Include

### Identify services
	rustscan -a 10.10.163.112 -b 1000
	...
	PORT      STATE SERVICE        REASON
	22/tcp    open  ssh            syn-ack
	25/tcp    open  smtp           syn-ack
	110/tcp   open  pop3           syn-ack
	143/tcp   open  imap           syn-ack
	993/tcp   open  imaps          syn-ack
	995/tcp   open  pop3s          syn-ack
	4000/tcp  open  remoteanything syn-ack
	50000/tcp open  ibm-db2        syn-ack
	
	nmap -sVC -p 22,25,110,143,993,995,4000,50000 10.10.163.112
	...
	4000/tcp  open  http     Node.js (Express middleware)
	|_http-title: Sign In
	50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
	| http-cookie-flags: 
	|   /: 
	|     PHPSESSID: 
	|_      httponly flag not set
	|_http-server-header: Apache/2.4.41 (Ubuntu)
	|_http-title: System Monitoring Portal
	MAC Address: 02:EF:7E:91:F2:8B (Unknown)
	Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel

## Webservers
I concentrated my efforts on the 2 webserver. Visit both of them.
The one on port 4000 permits to access using guest\guest as credentials.
The other on port 50000 present a login page

## Escaling to the admin profile
After spending quite a lot of times try to get a path to be admin in the app running on port 4000, I just tried the most obvious thing:
in the friend profile 1(the logged in default profile) create a new Recommend an Activity to guest with the following values:
- isAdmin
- true

And you can access the API URL http://10.10.245.117:4000/admin/api

## Internal API
We need to find a way to access the internal API that runs on localhost: SSRF could be a way, but we need to find the vulnerability.
Playing again with the Recommend an Activity I noticed that I could change the image profile: profileImage:/etc/passwd
But actually we cannot get the content of the file, of course.

### Found SSRF+RFI
Visit http://10.10.245.117:4000/admin/settings and you can have the preview (B64 encoded) of the content of the remote image.

Try if it works with others, maybe an API response? :)

## Access SysMon App (port 50000)
<!-- credentials are administrator\S$9$qk6d#**LQU -->
Looking to the network tba FF Devtools I noticed an interesting entry:
http://10.10.80.218:50000/profile.php?img=profile.png

so it seems that another file inclusion vulnerability is in place. I tested for the remote FI but it didnt work, so it seems that only local FI is allowed.

I spent quite a lot of time trying payloads to access /etc/passwd, nothing worked, then I found a [list](./LFI-pay4passwd.txt) used in a previous engagment compiled for the same purpose.
You can find the list here. Since using Intruder in BurpCE is really a pain, I scripted, with the help of ChatGPT, a procedure to speed up the process. You can fine this
script [here](./find-passwd-LFI.py) as well


