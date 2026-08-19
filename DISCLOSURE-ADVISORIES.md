# Disclosure and advisory model — v3.2

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

The schema includes an optional `researchId` in the form `HGR-YYYY-NNN` for future work that needs a stable identifier before a CVE exists. Historical entries are not retroactively assigned HGR numbers in v3.1.1.

## Research publication provenance

Research content now has an explicit source provenance model:

- `attacker-kb-archive` — preserved research imported from the historical AttackerKB archive. This is the schema default so the existing 63 entries require no frontmatter rewrite.
- `site-native` — research first published directly by h00die-gr3y on this site.

A future site-native Research entry should use:

```yaml
source:
  provenance: site-native
  platform: h00die-gr3y
  url: https://h00die-gr3y.github.io/research/<slug>/
```

The Research layout uses that field to distinguish **Originally published on ...** archive provenance from **Published by h00die-gr3y** site-native provenance. Site-native entries are also excluded from the **Edited archive** label.

## Embargo boundary

An `embargoed` status is schema-valid because private drafts use the same content model, but embargoed Markdown must never be committed to this public repository. Release QA now fails if a public `src/content/research/*.md` file contains `disclosure.status: embargoed`.

Keep private drafts outside the repository (or with a non-`.md` extension in a private workspace) until coordinated public disclosure. At publication, change the source provenance to `site-native`, set the canonical site URL and resolve the final disclosure metadata before moving the article into `src/content/research/`.

## First-class Research without an advisory record

CVE-2026-53804 is published as a first-class, site-native **Original Research** article at `/research/cve-2026-53804/`. The Research page is the canonical technical publication.

Its structured `disclosure` object uses `status: published` and finder credit while leaving `advisories: []`. This intentionally keeps the publication out of the Published Advisories portfolio while preserving disclosure metadata on the Research detail page.

The Research, CVE and Exploit Development indexes derive their totals from the content collection and therefore include the new entry automatically. The preserved AttackerKB baseline remains 63 entries.
