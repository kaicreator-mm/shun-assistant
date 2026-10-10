// Evidence-backed growth attribution (L2 §14.3): explain WHERE the disk
// growth is, from recorded observation evidence. Size ranks *explanations*;
// it never reaches the deletion decision — a huge USER_CREATED_UNKNOWN
// directory is reported as unattributable disposable growth, never as a
// cleanup candidate (Product C-003: "deletion by size alone is forbidden").
import type { ResidueClassification } from '@shun/contracts';
import type { ClassificationPolicy, CleanupCategory } from './classify.ts';
import { classifyDirectory } from './classify.ts';
import { StorageVerticalError } from './errors.ts';
import type { ObservationEvidence } from './observe.ts';

export interface Attribution {
  growthSourcePath: string;
  /** Frozen residue-space label (C-002; no TEMP exists there — see classify.ts). */
  classifiedAs: ResidueClassification;
  evidenceRefs: string[];
  /** Human-readable explanation backing the attribution (drives the R2 preview). */
  explanation: string;
  measuredBytes: number;
}

/**
 * Attribute growth to the largest policy-eligible disposable directory among
 * the observed candidates. A candidate qualifies only if its classification
 * (path policy) is inside cleanupPolicy.eligibleCategories — size ordering
 * happens strictly WITHIN the eligible set. Directories with inaccessible
 * entries are skipped for attribution (honesty: unmeasured bytes cannot back
 * an evidence claim).
 */
export function attributeGrowth(input: {
  observation: ObservationEvidence;
  eligibleCategories: readonly CleanupCategory[];
  classificationPolicy: ClassificationPolicy;
  observationEvidenceRef: string;
}): Attribution {
  const { observation, eligibleCategories, classificationPolicy, observationEvidenceRef } = input;
  const eligible = new Set<string>(eligibleCategories);
  const candidates = observation.directories
    .filter((dir) => dir.inaccessibleEntries.length === 0)
    .map((dir) => ({ dir, classification: classifyDirectory(dir.path, classificationPolicy) }))
    .filter(
      (c) =>
        c.classification.cleanupCategory !== null && eligible.has(c.classification.cleanupCategory),
    )
    .filter((c) => c.dir.bytes > 0)
    .sort((a, b) => b.dir.bytes - a.dir.bytes);

  const best = candidates[0];
  if (!best) {
    throw new StorageVerticalError(
      'GROWTH_NOT_ATTRIBUTED',
      'no policy-eligible disposable directory with measured bytes exists in the scan scope',
    );
  }

  const largerIneligible = observation.directories
    .filter((d) => d.bytes > best.dir.bytes)
    .map((d) => classifyDirectory(d.path, classificationPolicy));
  const largerUnknown = largerIneligible.filter(
    (c) => c.cleanupCategory === null && c.residue !== 'PROTECTED',
  ).length;
  const largerProtected = largerIneligible.filter((c) => c.residue === 'PROTECTED').length;

  const category = best.classification.cleanupCategory as CleanupCategory;
  const parts = [
    `Observed ${observation.directories.length} director${observation.directories.length === 1 ? 'y' : 'ies'} across ${observation.roots.length} scope root(s).`,
    `${best.dir.path} holds ${best.dir.bytes} bytes in ${best.dir.files} files and matches disposable policy marker "${best.classification.matchedMarker}" (cleanup category ${category}; residue taxonomy ${best.classification.residue}).`,
  ];
  if (largerUnknown > 0 || largerProtected > 0) {
    parts.push(
      `Larger director${largerUnknown + largerProtected === 1 ? 'y exists' : 'ies exist'} in the scope (${largerUnknown} user/unknown, ${largerProtected} protected) but ${largerUnknown + largerProtected === 1 ? 'is' : 'are'} NOT policy-eligible disposable data and ${largerUnknown + largerProtected === 1 ? 'was' : 'were'} therefore neither attributed nor targeted — size alone never selects a cleanup target.`,
    );
  }

  return {
    growthSourcePath: best.dir.path,
    classifiedAs: best.classification.residue,
    evidenceRefs: [
      observationEvidenceRef,
      `evidence://observation/directory/${encodeURIComponent(best.dir.path)}`,
    ],
    explanation: parts.join(' '),
    measuredBytes: best.dir.bytes,
  };
}
