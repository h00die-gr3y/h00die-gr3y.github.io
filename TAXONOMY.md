# Research taxonomy — v3.2.1

## Research origin

Each entry has one primary origin:

- `original-research`
- `technical-analysis`

## Research activity

`exploitDevelopment: true` is reserved for research where a **concrete, reusable exploit implementation is part of the h00die-gr3y work submission**.

Qualifying examples include a Metasploit module, standalone exploit script, PoC tool or another separately identifiable implementation produced as part of the research.

The following do **not** qualify by themselves:

- command-injection payloads or reverse-shell strings;
- manual reproduction steps;
- successful exploitation in a lab;
- an inline marker command or callback;
- a third-party exploit or module referenced for context;
- a source stub that merely points to an available public module.

A research article can therefore discuss exploitation in depth without being classified as **Exploit Development**.

## Editorial status

- `polished` — publication-quality website edit completed
- `normalized` — structurally normalized but intentionally not promoted to polished when the source itself is only a stub
- `archived` — reserved for untouched archive material

## Exploit artifacts

Implementation metadata and the Exploit Development category are related but not identical. `exploitArtifacts` may retain a relevant third-party implementation for context even when `exploitDevelopment` is `false`.

For entries classified as Exploit Development, at least one implementation must be attributable to the research work. Metasploit contribution pull requests and local h00die-gr3y research implementations provide direct provenance. A small audited set of older official modules is retained where the archived assessment explicitly states that h00die-gr3y created the implementation even though a contribution PR was not preserved in the metadata. CVE-2024-11320 is additionally retained as Exploit Development by explicit editorial decision because its research metadata contains the official Metasploit module artifact.
