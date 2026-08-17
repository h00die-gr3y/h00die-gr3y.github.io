# Knowledge Base Migration — v2.13

This release performs the first substantive migration of the legacy Jekyll knowledge pages into the Astro Knowledge Base.

## Source review

The source export contained seven selected legacy files:

- `_pages/ad-domain-attack.md`
- `_pages/tips-and-tricks.md`
- `_pages/module-development.md`
- `_posts/2024-08-26-howto-uart-shell.md`
- `_pages/iot-uart-shell.md`
- `_pages/references.md`
- `_pages/log4shell.md`

The migration is editorial, not a verbatim copy.

## Decisions

| Legacy source | Decision | Result |
|---|---|---|
| Active Directory Domain Attacks | REWRITE | `active-directory-attack-techniques.md` |
| Metasploit Tips and Tricks | REWRITE | `metasploit-workflow-tips.md` |
| Metasploit Module Development | MERGE | expanded `metasploit-module-development.md` |
| How to spawn an UART shell? | MERGE | merged into `uart-shell-access.md` |
| IoT Hacking - Spawning UART shells | MERGE | merged into `uart-shell-access.md` |
| References | MERGE / RETIRE | useful references kept with relevant KB articles |
| Log4shell Attacks | ARCHIVE | no standalone article; legacy source contained only an under-construction placeholder |

## Editorial rules applied

- Remove legacy theme markup, inline color styling, Jekyll gallery tags and casual presentation.
- Preserve the technical concepts and lab-derived observations.
- Do not copy the old CVE-specific Metasploit module catalog into the Knowledge Base.
- Keep CVE-specific analysis and implementation provenance in Research.
- Remove language about hiding researcher identity from the Metasploit tunnel material.
- Do not republish the ngrok authentication token embedded in the legacy page.
- Treat the Active Directory examples as historical lab workflows and make disruptive state changes explicit.
- Consolidate duplicate UART material into one maintained article.
- Do not invent a Log4Shell article from an unfinished legacy placeholder.

## Knowledge Base after migration

The intended published set is:

1. Command Injection Analysis
2. PHP Deserialization and Object Injection
3. Metasploit Exploit Module Development
4. Metasploit Workflow Tips: Listeners, NAT and Tunnels
5. Router Firmware Analysis Workflow
6. UART Shell Access and Serial Debugging
7. Active Directory Attack Paths: AD CS Relay and Zerologon

## Assets

The UART article references four legacy images. Run:

```bash
node scripts/migrate-legacy-knowledge-assets.mjs
```

The script copies them from the sibling Jekyll repository into:

```text
public/images/knowledge-base/uart-shell-access/
```

It never modifies the legacy repository.

## Redirects

Compatibility pages are added for known legacy page permalinks and filename-based post aliases. They provide a visible fallback link and client-side redirect to the maintained content.
