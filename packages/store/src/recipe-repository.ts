// v0.2 immutable Recipe revision repository (no execution or auto-promotion).
// Product #96 / L2 #101 / frozen DAG #102 T03.
// Receipts, approval and dispatch are owned by later ActionController/T04.
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import {
  canonicalJson,
  RecipeActionGraphSchema,
  RecipeRevisionIdentitySchema,
  type RecipeActionGraph,
  type RecipeRevisionIdentity,
  verifyRecipeRevision,
} from '@shun/contracts';
import type { ShunStore } from './shun-store.ts';

export type SavedRecipeRevision = Readonly<{
  identity: RecipeRevisionIdentity;
  sourceText: string;
  actionGraph: RecipeActionGraph;
  compiledArtifact: string;
  declaredEffects: readonly string[];
}>;

type RecipeRow = {
  recipe_id: string;
  revision_sha256: string;
  payload: string;
  payload_sha256: string;
};

export type RecipeStoreRefusal =
  | 'RECIPE_INVALID'
  | 'RECIPE_IDENTITY_MISMATCH'
  | 'RECIPE_REVISION_CONFLICT'
  | 'RECIPE_CORRUPT'
  | 'RECIPE_STORE_UNAVAILABLE';

export class RecipeStoreError extends Error {
  constructor(readonly code: RecipeStoreRefusal) {
    super(code); // fixed code only, never leak source/paths/compiled content
    this.name = 'RecipeStoreError';
  }
}

function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function validIdentity(value: unknown): value is RecipeRevisionIdentity {
  return RecipeRevisionIdentitySchema.safeParse(value).success;
}

/**
 * Read-only, immutable revision content. NEVER mark a revision enabled here.
 * Running/approving Recipe source belongs to the T04 typed ActionController.
 */
export class ImmutableRecipeRepository {
  private readonly db: DatabaseSync;

  constructor(store: ShunStore) {
    this.db = store.database;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS recipe_revisions_v02 (
        recipe_id TEXT NOT NULL,
        revision_sha256 TEXT NOT NULL,
        payload TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (recipe_id, revision_sha256)
      )
    `);
    // Prevent accidental INSERT OR REPLACE/UPDATE/DELETE mutating pinned source.
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS recipe_revisions_v02_no_update
      BEFORE UPDATE ON recipe_revisions_v02
      BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECIPE_REVISION'); END
    `);
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS recipe_revisions_v02_no_delete
      BEFORE DELETE ON recipe_revisions_v02
      BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECIPE_REVISION'); END
    `);
  }

  /** Fail-closed identity verification before any SQLite write. */
  private parseAndVerify(value: unknown): SavedRecipeRevision {
    if (!value || typeof value !== 'object') throw new RecipeStoreError('RECIPE_INVALID');
    let candidate: SavedRecipeRevision;
    try {
      candidate = value as SavedRecipeRevision;
      if (
        !validIdentity(candidate.identity) ||
        !verifyRecipeRevision(candidate.identity) ||
        typeof candidate.sourceText !== 'string' ||
        typeof candidate.compiledArtifact !== 'string' ||
        candidate.sourceText.length > 1024 * 1024 ||
        candidate.compiledArtifact.length > 1024 * 1024 ||
        !Array.isArray(candidate.declaredEffects) ||
        candidate.declaredEffects.length > 32
      ) throw new RecipeStoreError('RECIPE_INVALID');

      const graph = RecipeActionGraphSchema.safeParse(candidate.actionGraph);
      if (!graph.success || graph.data.nodes.length > 128 || graph.data.edges.length > 256) {
        throw new RecipeStoreError('RECIPE_INVALID');
      }
      const effects = [...new Set(graph.data.nodes.map((node) => node.op))].sort();
      if (
        candidate.declaredEffects.some((effect) => typeof effect !== 'string') ||
        canonicalJson(candidate.declaredEffects) !== canonicalJson(effects)
      ) throw new RecipeStoreError('RECIPE_IDENTITY_MISMATCH');
      const identity = candidate.identity;
      if (
        digest(candidate.sourceText) !== identity.sourceSha256 ||
        digest(canonicalJson(graph.data)) !== identity.actionGraphSha256 ||
        digest(candidate.compiledArtifact) !== identity.compiledSha256 ||
        digest(canonicalJson(effects)) !== identity.declaredEffectsSha256
      ) throw new RecipeStoreError('RECIPE_IDENTITY_MISMATCH');
      return {
        identity,
        sourceText: candidate.sourceText,
        actionGraph: graph.data,
        compiledArtifact: candidate.compiledArtifact,
        declaredEffects: effects,
      };
    } catch (error) {
      if (error instanceof RecipeStoreError) throw error;
      throw new RecipeStoreError('RECIPE_INVALID');
    }
  }

  append(value: unknown): { recipeId: string; revisionSha256: string; inserted: boolean } {
    const record = this.parseAndVerify(value);
    const payload = canonicalJson(record);
    const payloadSha256 = digest(payload);
    const { recipeId, revisionSha256 } = record.identity;
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const existing = this.db.prepare(
        'SELECT recipe_id, revision_sha256, payload, payload_sha256 FROM recipe_revisions_v02 WHERE recipe_id = ? AND revision_sha256 = ?',
      ).get(recipeId, revisionSha256) as RecipeRow | undefined;
      if (existing) {
        if (existing.payload_sha256 !== payloadSha256 || existing.payload !== payload) {
          throw new RecipeStoreError('RECIPE_REVISION_CONFLICT');
        }
        this.db.exec('COMMIT');
        return { recipeId, revisionSha256, inserted: false };
      }
      this.db.prepare(
        'INSERT INTO recipe_revisions_v02 (recipe_id, revision_sha256, payload, payload_sha256, created_at) VALUES (?, ?, ?, ?, ?)',
      ).run(recipeId, revisionSha256, payload, payloadSha256, new Date().toISOString());
      this.db.exec('COMMIT');
      return { recipeId, revisionSha256, inserted: true };
    } catch (error) {
      try { this.db.exec('ROLLBACK'); } catch { /* no transaction if unavailable */ }
      if (error instanceof RecipeStoreError) throw error;
      throw new RecipeStoreError('RECIPE_STORE_UNAVAILABLE');
    }
  }

  get(recipeId: string, revisionSha256: string): SavedRecipeRevision | null {
    if (!recipeId || !/^[a-f0-9]{64}$/.test(revisionSha256)) {
      throw new RecipeStoreError('RECIPE_INVALID');
    }
    let row: RecipeRow | undefined;
    try {
      row = this.db.prepare(
        'SELECT recipe_id, revision_sha256, payload, payload_sha256 FROM recipe_revisions_v02 WHERE recipe_id = ? AND revision_sha256 = ?',
      ).get(recipeId, revisionSha256) as RecipeRow | undefined;
    } catch {
      throw new RecipeStoreError('RECIPE_STORE_UNAVAILABLE');
    }
    if (!row) return null;
    try {
      if (digest(row.payload) !== row.payload_sha256) throw new RecipeStoreError('RECIPE_CORRUPT');
      const saved: unknown = JSON.parse(row.payload);
      const result = this.parseAndVerify(saved);
      if (
        result.identity.recipeId !== recipeId ||
        result.identity.revisionSha256 !== revisionSha256 ||
        canonicalJson(result) !== row.payload
      ) throw new RecipeStoreError('RECIPE_CORRUPT');
      return result;
    } catch {
      throw new RecipeStoreError('RECIPE_CORRUPT');
    }
  }
}
