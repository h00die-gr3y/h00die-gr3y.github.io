# v3.1.1 — Native Research Provenance

## Purpose

v3.1 introduced structured disclosure/advisory metadata. v3.1.1 makes the Research model safe for the next phase: publishing new research directly on h00die-gr3y while retaining correct provenance for the 63-entry AttackerKB import.

## Changes

- Adds `source.provenance`:
  - `attacker-kb-archive` (default)
  - `site-native`
- Existing migrated content requires no frontmatter edits.
- Research detail pages show:
  - `Originally published on <platform>` for imported archive research.
  - `Published by h00die-gr3y` for site-native research.
- Site-native entries no longer receive the `Edited archive` list label.
- The Research and Exploits index copy no longer implies all future content is archived.
- The homepage fixed `63` statistic is explicitly labeled `AttackerKB entries`.
- QA now:
  - allows the Research collection to grow beyond 63 entries;
  - requires the preserved AttackerKB baseline to remain exactly 63;
  - rejects embargoed Markdown in the public Research collection;
  - validates canonical source metadata for site-native entries;
  - counts researcher advisories dynamically while retaining the three historical GHSA baseline checks.

## Not included

- No CVE-2026-53804 content.
- No draft GHSA content.
- No production deployment.
- No changes to the main navigation.
