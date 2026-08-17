---
title: "Metasploit Exploit Module Development"
description: "Hands-on notes for turning a working proof of concept into a Metasploit module that checks the target, handles failure properly and cleans up after itself."
category: exploit-development
order: 30
status: published
topics:
  - Metasploit
  - Exploit Engineering
  - Check Method
  - Reliability
relatedResearch:
  - slug: cve-2022-33891
    label: CVE-2022-33891 — Apache Spark Shell Command Injection
  - slug: zyxel-router-chained-rce
    label: Zyxel Router Chained RCE
  - slug: cve-2023-50445
    label: CVE-2023-50445 — GL.iNet Shell Injection
relatedArticles:
  - slug: from-vulnerability-analysis-to-exploit-development
    label: From Vulnerability Analysis to Exploit Development
---
## Getting a shell is the fun part

Once a proof of concept gives me command execution, the vulnerability is proven. But a Metasploit module needs a bit more love before I consider it finished.

I want it to answer things like:

- Am I talking to the right product?
- Is the target version actually vulnerable?
- Does a non-default feature need to be enabled?
- Which target and architecture should I use?
- Can I tell the difference between “not vulnerable” and “my request failed”?
- Am I dropping files or changing configuration?
- Can I clean those changes up?

That is the difference between a one-off PoC and a module I am happy to run again later.

## Running a local module while developing

I keep development modules under:

```text
~/.msf4/modules/
```

and mirror the normal Metasploit namespace.

For example:

```text
~/.msf4/modules/exploits/linux/http/
~/.msf4/modules/auxiliary/admin/http/
```

A typical test cycle is:

```shell
cp my_module.rb ~/.msf4/modules/exploits/linux/http/
msfconsole
```

and inside Metasploit:

```text
reload_all
search my_module
use exploit/linux/http/my_module
info
options
advanced
```

I use `reload_all` a lot while writing modules. It is faster than restarting `msfconsole` for every small change.

## Build `check` early

I like to get `check` working before the exploit is polished.

The flow is usually:

```text
identify the product
    ↓
identify the version or feature
    ↓
do a safe vulnerable-behavior check if possible
    ↓
return a useful CheckCode
```

A web server banner alone is rarely enough. I prefer something product-specific: a version endpoint, a known page, a response marker, or a harmless request that confirms the vulnerable code path.

This also makes development nicer because I can repeatedly test the target without firing the payload every time.

## Be explicit about the things the exploit needs

Some modules only work when one extra condition is true.

Apache Spark CVE-2022-33891 is a good example: the vulnerable path depends on ACL support being enabled. That kind of condition belongs in the module logic and the documentation, not hidden in a comment somewhere.

The same goes for:

- authentication;
- writable directories;
- optional services;
- a specific CPU architecture;
- a second vulnerability;
- a credential or secret recovered earlier in a chain.

For a chain I tend to think in steps:

```text
get information
        ↓
recover secret / credential
        ↓
create authenticated state
        ↓
reach command execution
        ↓
deliver payload
```

If step two fails, I want the module to say step two failed.

## Keep payload delivery as simple as possible

Once command execution works, I decide how to get a useful session.

Common options are:

- direct command payload;
- encoded command;
- command stager;
- write a file and execute it;
- use an interpreter already present;
- drop a native payload.

I normally start with the least complicated option and only move to a command stager or native dropper when the target needs it.

Complex payload delivery is harder to debug and gives you more things to clean up.

## Cleanup is part of the module

If I create a file, plugin, cron job, user or temporary directory, I try to register it for cleanup.

And when cleanup is impossible, I document the side effect.

A good module should leave the target in roughly the same state it found it, apart from the session you deliberately opened.

## Use the framework instead of reinventing it

Metasploit already has a lot of useful helpers. I try to use the HTTP, authentication and command-stager mixins instead of writing my own plumbing.

It gives you:

- consistent proxy handling;
- SSL support;
- payload staging;
- common error handling;
- easier review by the Metasploit team.

It also makes the module easier for somebody else to read.

## Keep the CVE story with the CVE

I have written quite a few modules over the years, and a big list of module descriptions quickly turns into a second vulnerability archive.

That is not what I want here.

The vulnerability-specific analysis, official module and contribution PR live on the related Research page. This page is for the bits I reuse while **building** a module.

For example:

- [Apache Spark Shell Command Injection](/research/cve-2022-33891/)
- [Zyxel Router Chained RCE](/research/zyxel-router-chained-rce/)
- [GL.iNet Shell Injection](/research/cve-2023-50445/)

## Official module versus my development copy

Once a module lands in the official Metasploit Framework, that is the version I want people to use.

My rule for the site is simple:

```text
official module exists
    → link the official module
    → link the contribution PR when I know it
    → no duplicate local .rb download

no official module exists
    → link my research implementation
    → add the contribution PR when applicable
```

The PR is still useful because it shows the discussion and review history. The official module is the maintained code.

## My quick pre-PR checklist

Before submitting a module I normally check:

- `rubocop` / formatting is clean;
- references and authors are correct;
- `check` works;
- required options are really required;
- targets and architectures are accurate;
- failure messages are useful;
- temporary files are cleaned;
- no lab IPs, passwords or debug prints are left behind;
- the description explains the vulnerability without requiring the advisory open next to it.

Then I test it again from a clean Metasploit checkout. That catches a surprising number of “works on my box” mistakes.
