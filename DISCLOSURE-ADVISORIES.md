# Disclosure and advisory model — v3.1

The h00die-gr3y website is the canonical technical research archive.

External records have separate roles:

- **CVE** — global vulnerability identity.
- **Vendor advisory** — remediation and vendor disclosure record.
- **GitHub Security Advisory** — disclosure record where applicable.
- **Researcher advisory** — historical GHSAs published in the h00die-gr3y repository before the current site workflow existed.
- **Exploit implementation** — Metasploit, Python, Nuclei or other implementation metadata.

## Historical researcher advisories

v3.1 records the three published GHSAs already associated with first-class Research entries:

- `GHSA-m4f8-9c8x-8f3f` → `CVE-2025-4653`
- `GHSA-wcqx-vw37-9pv8` → `CVE-2025-4678`
- `GHSA-g6r8-jjf7-w7gh` → `CVE-2025-5946`

These remain part of the permanent disclosure history. They are not duplicated as separate Research articles.

## Future workflow

1. Keep pre-disclosure research private.
2. Report through the vendor/CNA disclosure process.
3. Use a vendor/project advisory or GHSA when one exists.
4. Publish the detailed technical article under `/research/` at coordinated public disclosure.
5. Record CVE, vendor/GHSA disclosure records and exploit implementations as structured metadata.

The schema includes an optional `researchId` in the form `HGR-YYYY-NNN` for future work that needs a stable identifier before a CVE exists. Historical entries are not retroactively assigned HGR numbers in v3.1.
