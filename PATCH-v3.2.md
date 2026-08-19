# v3.2 — CVE-2026-53804 canonical Research publication

## Publication

- Adds `src/content/research/cve-2026-53804.md`.
- Publishes it as **Original Research** with `source.provenance: site-native`.
- Uses the Research page itself as the canonical technical source.
- Records the CVE, CWE-77, affected OTRS Community Edition / Znuny / OTOBO products, administrator prerequisite, PGP configuration path, exploitation flow, `Kernel/System/Crypt/PGP.pm` root cause, impact, mitigation status and finder credit.
- Does not create a researcher-advisory record for this CVE.

## Disclosure model

The entry uses:

```yaml
disclosure:
  status: published
  credit: h00die-gr3y — Finder
  reported: null
  advisories: []
```

`DisclosurePanel.astro` is adjusted so publication status, date and finder credit are still rendered when the advisory list is empty.

## Counts and indexes

No hard-coded public index count is changed because the current Astro pages derive Research, CVE and Exploit Development totals from the content collection.

The historical homepage statistic remains **63 AttackerKB entries**. v3.2 adds one site-native entry, bringing the Research corpus to at least **64** while preserving the archive baseline.

## QA

Release QA now additionally verifies that CVE-2026-53804:

- exists in the public Research collection;
- is `original-research`;
- uses `site-native` provenance and the canonical `/research/cve-2026-53804/` URL;
- is published with finder credit;
- has an empty advisory array;
- contains the PGP settings and `Kernel/System/Crypt/PGP.pm` root-cause path;
- contains no researcher-advisory URL.
