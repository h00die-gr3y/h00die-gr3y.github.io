---
title: Command Injection Analysis
description: A hands-on way to trace user-controlled input into operating-system commands, prove whether it is really exploitable, and capture the conditions that matter.
category: web-applications
order: 10
status: published
topics:
  - Command Injection
  - Data Flow
  - Shell Execution
  - Validation
relatedResearch:
  - slug: cve-2022-33891
    label: CVE-2022-33891 — Apache Spark Shell Command Injection
  - slug: cve-2025-5946
    label: CVE-2025-5946 — Centreon Poller Reload Command Injection
  - slug: cve-2025-5965
    label: CVE-2025-5965 — Centreon Backup Configuration Command Injection
relatedArticles:
  - slug: from-vulnerability-analysis-to-exploit-development
    label: From Vulnerability Analysis to Exploit Development
---
## Start with the path, not the scary function

Finding `system()`, `exec()`, `shell_exec()` or a process wrapper is always interesting, but it is only the start.

When I review command-injection code I want to answer four simple questions:

1. **Where can I control the input?** HTTP parameter, configuration value, database field, uploaded filename, API object, environment variable, and so on.
2. **What happens to it on the way down?** Concatenation, quoting, encoding, validation, normalization or some helper function that quietly changes the value.
3. **Where is the command really built?** I want to see both the executable and the point where a shell such as `sh -c`, `bash -c` or backticks comes into play.
4. **What do I need before I can reach it?** Authentication, a specific role, a feature flag, a scheduled job, a restart or another trigger.

I normally write the route down like this:

```text
input I control
    ↓
application parsing
    ↓
validation / transformation
    ↓
command construction
    ↓
shell or process API
    ↓
actual execution
```

That small exercise prevents a lot of false positives.

## Check whether a shell is involved

There is an important difference between handing arguments directly to a process and building one big string that a shell will interpret.

Conceptually:

```text
execve("program", ["program", user_input])
```

is very different from:

```text
/bin/sh -c "program " + user_input
```

The second version gives shell metacharacters a chance to do something useful for an attacker.

So I never stop at “this code launches a process.” I check **how** it launches that process.

## Prove it with the smallest useful test

Once the data flow looks exploitable, I start small. The goal is to prove command execution, not to win a payload beauty contest.

Useful lab checks are:

- a short delay;
- a harmless marker file;
- an outbound DNS or HTTP request to infrastructure I control;
- command output when the application already reflects it.

If `id` is enough to show the execution user, there is no reason to start with a complicated reverse shell.

## Do not forget the trigger

Some of the nicest command injections do not execute immediately.

I have run into cases where the value is stored first and only used later by:

- a cron job;
- a backup task;
- a service reload;
- a diagnostic action;
- an export job;
- a separate administrative workflow.

That delay matters. It changes both the exploit path and the risk rating.

I normally record the preconditions explicitly:

```text
Authentication : unauthenticated / authenticated
Required role  : none / user / administrator
Trigger        : immediate / restart / scheduled job / manual action
Execution user : www-data / application account / root / unknown
Exposure       : local / management network / Internet reachable
```

## A few mistakes that are easy to make

- Seeing `system()` and declaring victory without tracing the source.
- Missing sanitization between the input and the command.
- Assuming quotes make a shell command safe.
- Forgetting a delayed trigger.
- Proving execution but never checking the resulting OS user.
- Mixing one product-specific payload with the reusable root-cause explanation.

## How I like to write the finding

A short root-cause statement should tell the reader where the value comes from, what goes wrong, where it executes and what triggers it.

For example:

> User-controlled input from an administrative configuration value is concatenated into a shell command without sufficient neutralization. The command is executed later by the backup process, allowing the configured value to inject operating-system commands in the context of the backup service.

Then I put the real request, payload and product-specific details in the related Research entry. That keeps this page useful when I am looking at the next application.
