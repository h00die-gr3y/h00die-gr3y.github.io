---
title: Router Firmware Analysis Workflow
description: My practical workflow for moving from a firmware image to the web interface, native helpers, emulation and targeted validation on embedded Linux routers.
category: iot-embedded
order: 40
status: published
topics:
  - Firmware
  - Embedded Linux
  - Routers
  - Reverse Engineering
  - Emulation
relatedResearch:
  - slug: cve-2023-50445
    label: CVE-2023-50445 — GL.iNet Shell Injection
  - slug: cve-2023-50919
    label: CVE-2023-50919 — GL.iNet Authentication Bypass
  - slug: cve-2024-48456
    label: CVE-2024-48456 — Netis Command Injection
  - slug: zyxel-router-chained-rce
    label: Zyxel Router Chained RCE
relatedArticles: []
---
## Do not start in Ghidra

It is tempting to throw the biggest binary into a disassembler immediately. I usually get more value by first treating the firmware as a complete little Linux system.

My first inventory looks something like this:

```text
CPU architecture
endianness
kernel and libc
filesystem layout
init system
web server
management daemons
CGI / Lua / PHP components
configuration storage
network services
privileged helper binaries
```

That already tells me where I want to look next.

## Keep the firmware image clean

I keep the downloaded firmware image untouched, record where it came from and calculate a checksum.

Everything else happens in a separate working directory.

On the first extraction pass I am looking for:

- filesystem type;
- nested vendor containers;
- plaintext configuration defaults;
- setuid or privileged binaries;
- startup scripts;
- web roots;
- CGI handlers;
- scripts that call shell commands;
- files that look like NVRAM or configuration databases.

I also keep the extraction commands in my notes. Being able to reproduce the exact filesystem later is worth the small effort.

## Follow the web interface into the system

Router web interfaces are often a chain of different technologies rather than one application.

A request may travel through:

```text
HTTP server
   ↓
CGI / Lua / proprietary dispatcher
   ↓
shell script or native helper
   ↓
configuration subsystem
   ↓
privileged daemon / system command
```

This is where things get interesting.

A parameter may look perfectly harmless in JavaScript or Lua and then end up unquoted in a shell command two layers deeper.

I follow the value all the way down.

## Search first, reverse second

Simple string searches save a lot of Ghidra time.

I look for:

- command strings;
- CGI route names;
- configuration keys;
- `system`;
- `popen`;
- `exec*`;
- vendor wrappers around those functions;
- password-generation routines;
- update scripts;
- diagnostic functions;
- log collection;
- telnet or SSH setup.

Those hits tell me which binaries deserve proper reverse engineering.

## Emulation is great when it works

I like emulation because it makes repeated testing much quicker, but I do not force it.

Depending on the device I may use:

```text
static analysis
    +
user-mode / partial emulation
    +
full-system emulation when it behaves
    +
real hardware when needed
```

FirmAE and similar tooling can get you surprisingly far, but routers love proprietary drivers, odd NVRAM behavior and hardware-specific startup logic.

Whenever the emulator behaves differently from the real device, I write it down. Otherwise it is very easy to debug the emulator instead of the router.

## Always check the execution user

One of the first commands I run after reaching command execution is usually:

```shell
id
```

A web vulnerability becomes a very different finding when the command crosses from the management interface into a daemon running as `root`.

I check:

- which process executes the action;
- its user and group;
- whether another daemon is involved;
- whether privilege separation exists;
- whether execution is immediate or delayed.

## Router chains are often more fun than single bugs

Embedded devices regularly give you several smaller weaknesses that fit together nicely.

For example:

```text
unauthenticated information disclosure
        ↓
recover credential or secret
        ↓
login / bypass authentication
        ↓
command injection
        ↓
root
```

I write the chain down exactly like that while testing. It makes it much easier to see what still needs proof and later turns directly into the exploit flow.

## A few things I keep in the notebook

Before I call the analysis done I normally have:

- firmware filename and hash;
- target architecture;
- important startup processes;
- web route → handler mapping;
- dangerous helper functions;
- execution user;
- exact vulnerable versions I tested;
- differences between emulation and hardware;
- any chained bugs needed to reach the final impact.

That is enough structure to pick the work up again months later without having to rediscover the whole router.
