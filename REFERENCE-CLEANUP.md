# v2.10 — Reference Cleanup

This release normalizes the research reference layer across all 63 migrated research entries.

## Reference ownership

Research pages now separate three concerns:

- **Article body** — contextual technical links and cross-references.
- **Implementation sidebar** — Metasploit modules, contribution PRs, local fallback implementations and other exploit artifacts.
- **References** — canonical CVE record, vendor advisories, original disclosures, documentation and relevant third-party research.

Implementation links are no longer duplicated in `## References`.

## Canonical CVE rule

Every CVE research page contains exactly one canonical primary CVE reference:

`https://www.cve.org/CVERecord?id=CVE-YYYY-NNNN`

The rule is applied both to the rendered Markdown References section and to structured `references:` frontmatter. Legacy MITRE CGI, NVD and Tenable CVE pages are not used as an additional primary CVE record.

## AttackerKB migration

AttackerKB remains only as historical provenance in the frontmatter `source:` field.

Article-body AttackerKB links were handled as follows:

- migrated h00die-gr3y research -> `/research/<slug>/`
- references inside captured module-info output -> absolute `https://h00die-gr3y.github.io/research/<slug>/`
- CVEs without a migrated h00die-gr3y page -> canonical CVE.org record or an existing independent analysis
- self-references -> removed or replaced with the local research page as context required

There are no remaining `attackerkb.com` URLs in research article bodies.

## Formatting cleanup

All `## References` sections now use Markdown bullet lists. Legacy malformed links such as `[label] (url)` were normalized to `[label](url)`.

## Validation

Post-migration validation confirms:

- 63 research entries
- 62 CVE entries + 1 non-CVE research article
- 63 References sections
- 62/62 CVE pages with exactly one canonical CVE.org reference in the article
- 62/62 CVE entries with exactly one `type: canonical` CVE.org reference in frontmatter
- 0 AttackerKB URLs in article bodies
- 0 implementation/sidebar URLs duplicated in References sections
- 0 implementation/sidebar URLs duplicated in structured `references:` metadata
- 0 malformed `[label] (url)` links
- all References sections use list formatting
- Markdown code fences remain balanced

Historical AttackerKB source provenance is intentionally retained and should not be removed from `source:`.
