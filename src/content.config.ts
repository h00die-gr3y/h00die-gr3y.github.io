import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const research = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/research' }),
  schema: z.object({
    title: z.string(),
    topicName: z.string(),
    cve: z.string().nullable(),
    description: z.string(),
    published: z.string(),
    revised: z.string(),
    disclosureDate: z.string().nullable(),
    researchId: z.string().regex(/^HGR-\d{4}-\d{3}$/).nullable().optional(),
    disclosure: z.object({
      status: z.enum(['embargoed', 'coordinated', 'published']),
      credit: z.string().nullable().optional(),
      reported: z.string().nullable().optional(),
      advisories: z.array(z.object({
        type: z.enum(['researcher', 'vendor', 'github', 'other']),
        label: z.string(),
        id: z.string().nullable().optional(),
        url: z.string(),
        published: z.string().nullable().optional(),
      })).default([]),
    }).nullable().optional(),
    source: z.object({
      platform: z.string(),
      url: z.string(),
    }),
    researchType: z.enum(['original-research', 'technical-analysis']),
    exploitDevelopment: z.boolean(),
    editorialStatus: z.enum(['archived', 'normalized', 'polished']),
    vulnerabilityClasses: z.array(z.string()).optional(),
    authentication: z.enum(['unauthenticated', 'authenticated', 'mixed', 'unknown']).optional(),
    privilegesRequired: z.string().nullable().optional(),
    platforms: z.array(z.string()).optional(),
    vendor: z.string().nullable(),
    products: z.array(z.string()),
    weaknesses: z.array(z.string()),
    vulnerableVersions: z.array(z.string()),
    cvss: z.object({
      score: z.number(),
      severity: z.string(),
      vector: z.string(),
    }).nullable(),
    attackerValue: z.number().nullable(),
    exploitability: z.number().nullable(),
    mitreTactics: z.array(z.string()),
    tags: z.array(z.string()),
    exploitArtifacts: z.array(z.object({
      type: z.enum(['metasploit', 'python', 'nuclei', 'poc', 'script', 'other']),
      label: z.string(),
      url: z.string().optional(),
      officialUrl: z.string().optional(),
      pullRequestUrl: z.string().optional(),
      localUrl: z.string().optional(),
    })),
    references: z.array(z.object({
      label: z.string(),
      url: z.string(),
      type: z.string(),
    })),
  }),
});


const articles = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/articles' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    published: z.string(),
    revised: z.string(),
    status: z.enum(['draft', 'published']),
    featured: z.boolean().default(false),
    topics: z.array(z.string()),
    relatedResearch: z.array(z.object({
      slug: z.string(),
      label: z.string(),
    })).default([]),
  }),
});

const knowledgeBase = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/knowledge-base' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    category: z.enum(['web-applications', 'exploit-development', 'infrastructure', 'iot-embedded', 'tools-techniques']),
    order: z.number().default(100),
    status: z.enum(['draft', 'published']),
    topics: z.array(z.string()).default([]),
    relatedResearch: z.array(z.object({
      slug: z.string(),
      label: z.string(),
    })).default([]),
    relatedArticles: z.array(z.object({
      slug: z.string(),
      label: z.string(),
    })).default([]),
  }),
});

export const collections = { research, articles, knowledgeBase };
