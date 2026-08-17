# Articles — v2.11

Articles are long-form technical publications that are not centered on one vulnerability record.

## Separation from Research

- `Research` remains the record for individual vulnerability discoveries and technical analyses.
- `CVEs` remains the canonical CVE-indexed view of that research.
- `Exploits` remains the view over research with exploit-development activity.
- `Articles` connects methods, techniques and lessons across multiple research records or covers technical subjects that are not naturally represented by a single CVE.

## Content model

Articles live under `src/content/articles/` and use:

- title
- description
- published/revised dates
- draft/published status
- topics
- related research
- featured flag

Only `status: published` entries are emitted in the static article routes and index.

## First article

`from-vulnerability-analysis-to-exploit-development.md` is the first long-form article. It synthesizes the exploitation workflow using existing research examples rather than duplicating one CVE assessment.
