---
title: PHP Deserialization and Object Injection
description: A practical guide to working out what attacker-controlled PHP deserialization actually gives you, which classes are reachable, and how that can grow into real impact.
category: web-applications
order: 20
status: published
topics:
  - PHP
  - Deserialization
  - Object Injection
  - Gadget Chains
relatedResearch:
  - slug: cve-2026-26978
    label: CVE-2026-26978 — FreePBX Backup & Restore PHP Object Injection to RCE
  - slug: cve-2023-41892
    label: CVE-2023-41892 — Craft CMS Remote Code Execution
relatedArticles:
  - slug: from-vulnerability-analysis-to-exploit-development
    label: From Vulnerability Analysis to Exploit Development
---
## `unserialize()` is interesting, but it is not automatically RCE

When I see attacker-controlled data reaching `unserialize()`, that immediately gets my attention.

The second reaction should be: **what can I actually do with it?**

I break the problem into a few steps:

```text
serialized data I can control
            ↓
      PHP deserialization
            ↓
 classes and magic methods I can reach
            ↓
 useful side effect
            ↓
       real security impact
```

The interesting part is not the word `unserialize()` itself. It is the code that becomes reachable after PHP creates the object.

## First find the trust boundary

I want to know exactly where the serialized data comes from.

Common places are:

- backup or restore archives;
- session or cache data;
- database records;
- HTTP parameters or cookies;
- import files;
- framework state objects.

Then I check whether the application really lets me control that data. Encryption, signatures, integrity checks or access-control checks can completely change the story.

## Look at what is loaded

PHP object injection becomes much more interesting when the application has a large class space.

Composer packages, framework classes and vendor libraries may already contain everything needed for a useful gadget chain.

My usual checklist is:

- application and framework version;
- Composer dependencies and versions;
- autoload behavior;
- `__wakeup()`, `__destruct()`, `__toString()`, `__invoke()` and friends;
- classes that write files, delete files, make network requests or execute processes.

A class does not need to look security-sensitive by itself. I care about what happens when attacker-controlled properties reach its methods.

## Follow the side effects

I search for useful behavior such as:

```text
file write
file delete
path manipulation
process execution
network request
dynamic callback
template evaluation
expression evaluation
```

Then I work backwards and ask whether object properties give me enough control to reach that behavior.

That is basically what a gadget chain is: a route from the object I can create to the side effect I actually want.

## Preconditions can make or break the exploit

A clean-looking chain on paper can still fail because the runtime is missing one small ingredient.

Things I check include:

- optional PHP extensions;
- writable directories;
- dependency versions;
- whether the class is autoloaded;
- whether authentication is required;
- whether a second request is needed;
- whether a generated file must be triggered separately.

I write these down while testing. It saves a lot of confusion later when the exploit works on one target and not on another.

## Keep the explanation simple

I prefer the vulnerability story to make sense before showing the final payload.

A format that works well is:

```text
Root cause
  attacker-controlled data is deserialized

What that gives me
  object and property control

Useful class behavior
  attacker-controlled side effect

Impact
  file write / command execution / other compromise
```

That structure is much easier to reuse when the gadget chain changes between versions.

## When I build the exploit

Once I have the chain working, I still test the boring bits:

- Can I detect the vulnerable version?
- Can I detect a missing dependency?
- Can I clean up generated files?
- Can I fail with a useful error instead of a dead session?
- Can I make the chain work without hard-coded paths from my lab?

Those details are what turn a working proof of concept into something I trust enough to use again.
