# v3.2.1 — Exploit Development taxonomy audit

## Purpose

Correct the `exploitDevelopment` identifier so it means **a concrete exploit implementation is part of the research submission**, rather than merely indicating payload validation or successful exploitation.

## Changes

- Audits all 64 Research entries.
- Removes 8 false-positive Exploit Development classifications.
- Leaves 51 qualifying Exploit Development entries.
- Removes misleading `## Exploit development` sections from CVE-2024-12992 and CVE-2025-5965 while preserving their PoC/reproduction material.
- Retains CVE-2024-11320 as Exploit Development by explicit editorial decision.
- Corrects CVE-2026-53804 to `exploitDevelopment: false` because the canonical article contains validation commands but no exploit artifact.
- Retains useful third-party implementation references on technical-analysis pages without treating those pages as h00die-gr3y Exploit Development work.
- Updates taxonomy documentation, historical content summary and Exploits-index wording.
- Adds release QA that enforces artifact/provenance evidence for the category.

## Unchanged

- Research entries: 64
- Preserved AttackerKB entries: 63
- Site-native Research entries: 1
- Structured researcher advisories: 3
- CVE-2026-53804 remains the canonical site-native Original Research publication with no researcher-advisory record.
