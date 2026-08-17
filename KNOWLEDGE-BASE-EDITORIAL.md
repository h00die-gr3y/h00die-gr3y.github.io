# Knowledge Base Editorial Pass — v2.13.1

This pass changes the Knowledge Base from a migration-style reference set into standalone h00die-gr3y technical articles.

## Editorial rules

Published Knowledge Base content should:

- sound like one researcher explaining how the work is actually done;
- prefer direct, practical wording over academic terminology;
- keep useful lab commands, output and troubleshooting details;
- preserve screenshots and hardware/lab images when they add technical value;
- avoid migration-history wording inside the article body;
- avoid phrases such as "the original article", "the original lab", "legacy source", or "the old page";
- avoid the academic use of "primitive" where plainer terms such as capability, behavior, building block or vulnerable path are clearer;
- remain technically structured enough to work as a reusable reference.

## Content changes

### Active Directory

The AD article is substantially expanded again. It now includes the lab topology, PetitPotam / AD CS tooling setup, DNS preparation, `ntlmrelayx`, PetitPotam output, PFX/PKINIT steps, PKINIT troubleshooting, NT-hash recovery, ticket creation, directory-secret demonstration, Zerologon check/exploitation, machine-account recovery and restoration.

The `petitpotam.png` image is now migrated into the article assets.

### UART

The UART page reads as a direct hands-on lab and retains the Transpeed/PCB/connection/test-bed images, `minicom` setup, shell output and `dmesg -n 1` troubleshooting.

### Metasploit

Module-development and listener/tunnel pages use a more personal working-notes voice and retain practical commands instead of reducing everything to abstract models.

### Web and firmware notes

Command Injection, PHP Deserialization and Router Firmware Analysis also received the same tone pass so the Knowledge Base reads as one coherent section.

## Scope

Research records remain the canonical place for vulnerability-specific evidence, CVE details and exploit provenance. Knowledge Base pages focus on the reusable hands-on methods.
