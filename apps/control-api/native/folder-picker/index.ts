/**
 * Fail-closed loader for the dedicated Windows Shell folder-picker addon.
 * There is no browser, shell-script, PowerShell or JavaScript fallback.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FOLDER_PICKER_ADDON_SHA256 } from './artifacts.ts';

export type FolderIdentity = Readonly<{
  volumeSerial: string;
  fileId: string;
}>;

export type FolderDirectoryIdentity = FolderIdentity &
  Readonly<{
    isDirectory: boolean;
    isReparsePoint: boolean;
    isNetworkPath: boolean;
    isVolumeRoot: boolean;
  }>;

export type NativeFolderSelection =
  | Readonly<{ status: 'CANCELLED' }>
  | Readonly<{ status: 'REFUSED'; code: string }>
  | Readonly<{
      status: 'SELECTED';
      path: string;
      displayName: string;
      identity: FolderIdentity;
    }>;

/**
 * A live native directory lease: an opaque in-process token plus the
 * volume/file identity captured from a reparse-free handle chain. It is
 * defense-in-depth only. Downstream metadata APIs still walk by path, so
 * replacement during the path-based scan remains a documented residual risk.
 */
export type NativeDirectoryLease = Readonly<{
  leaseId: string;
  directory: FolderDirectoryIdentity;
}>;

export interface FolderPickerNativePort {
  /** Frozen contract: the modal Shell dialog runs on a dedicated COM STA
   * async worker; the Node main event loop is never blocked. */
  pickFolder(): Promise<NativeFolderSelection>;
  inspectFolder(path: string): FolderDirectoryIdentity;
  /** Pins the directory chain for `path` and returns the lease plus the
   * identity read from the pinned handle. Fails closed on any reparse
   * component, non-directory component or non-plain-drive path. */
  acquireDirectoryLease(path: string): NativeDirectoryLease;
  /** Re-reads the directory identity from the pinned handle of a live lease;
   * refuses with a typed drift code if the captured identity no longer
   * matches. */
  verifyDirectoryLease(lease: NativeDirectoryLease): FolderDirectoryIdentity;
  /** Releases the lease and every handle in its chain. */
  releaseDirectoryLease(lease: NativeDirectoryLease): void;
  /** The pinned object's own current DOS path (read from the held handle),
   * for path-based walks that must not consult a possibly-replaced recorded
   * location. */
  directoryLeasePath(lease: NativeDirectoryLease): string;
}

const nativeDirectory = dirname(fileURLToPath(import.meta.url));
export const folderPickerAddonPath = join(nativeDirectory, 'shun_folder_picker.node');

function artifactDigest(): string | null {
  if (!existsSync(folderPickerAddonPath)) return null;
  try {
    return createHash('sha256').update(readFileSync(folderPickerAddonPath)).digest('hex');
  } catch {
    return null;
  }
}

export function verifyFolderPickerArtifact(): Readonly<{
  ok: boolean;
  code?: string;
  sha256?: string;
}> {
  if (process.platform !== 'win32')
    return { ok: false, code: 'FOLDER_PICKER_PLATFORM_NOT_WINDOWS' };
  const actual = artifactDigest();
  if (actual === null) return { ok: false, code: 'FOLDER_PICKER_ADDON_MISSING' };
  if (!/^[a-f0-9]{64}$/.test(FOLDER_PICKER_ADDON_SHA256) || actual !== FOLDER_PICKER_ADDON_SHA256) {
    return { ok: false, code: 'FOLDER_PICKER_ADDON_SHA_MISMATCH', sha256: actual };
  }
  return { ok: true, sha256: actual };
}

type RawSelectionResult = {
  status: string;
  code?: string;
  path?: string;
  displayName?: string;
  identity?: {
    volumeSerial?: string;
    fileId?: string;
  };
};

type RawDirectoryIdentity = {
  volumeSerial?: string;
  fileId?: string;
  isDirectory?: boolean;
  isReparsePoint?: boolean;
  isNetworkPath?: boolean;
  isVolumeRoot?: boolean;
};

type RawAddon = {
  pickFolder(): Promise<RawSelectionResult>;
  inspectFolder(path: string): RawDirectoryIdentity;
  acquireDirectoryLease(path: string): {
    leaseId?: string;
    directory?: RawDirectoryIdentity;
  };
  verifyDirectoryLease(leaseId: string): RawDirectoryIdentity;
  releaseDirectoryLease(leaseId: string): void;
  directoryLeasePath(leaseId: string): string;
};

function mapIdentity(raw: NonNullable<RawSelectionResult['identity']>): FolderIdentity {
  if (typeof raw.volumeSerial !== 'string' || typeof raw.fileId !== 'string') {
    throw new Error('FOLDER_PICKER_IDENTITY_INVALID');
  }
  return { volumeSerial: raw.volumeSerial, fileId: raw.fileId };
}

function mapDirectoryIdentity(raw: RawDirectoryIdentity): FolderDirectoryIdentity {
  const identity = mapIdentity(raw);
  if (
    typeof raw.isDirectory !== 'boolean' ||
    typeof raw.isReparsePoint !== 'boolean' ||
    typeof raw.isNetworkPath !== 'boolean' ||
    typeof raw.isVolumeRoot !== 'boolean'
  ) {
    throw new Error('FOLDER_PICKER_DIRECTORY_IDENTITY_INVALID');
  }
  return {
    ...identity,
    isDirectory: raw.isDirectory,
    isReparsePoint: raw.isReparsePoint,
    isNetworkPath: raw.isNetworkPath,
    isVolumeRoot: raw.isVolumeRoot,
  };
}

export function loadFolderPicker(): FolderPickerNativePort {
  const check = verifyFolderPickerArtifact();
  if (!check.ok) throw new Error(check.code ?? 'FOLDER_PICKER_ARTIFACT_REFUSED');
  const require = createRequire(import.meta.url);
  const addon = require(folderPickerAddonPath) as RawAddon;
  if (
    !addon ||
    typeof addon.pickFolder !== 'function' ||
    typeof addon.inspectFolder !== 'function' ||
    typeof addon.acquireDirectoryLease !== 'function' ||
    typeof addon.verifyDirectoryLease !== 'function' ||
    typeof addon.releaseDirectoryLease !== 'function' ||
    typeof addon.directoryLeasePath !== 'function'
  ) {
    throw new Error('FOLDER_PICKER_ADDON_API_INVALID');
  }
  return Object.freeze({
    async pickFolder(): Promise<NativeFolderSelection> {
      let raw: RawSelectionResult;
      try {
        raw = await addon.pickFolder();
      } catch {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_ASYNC_TASK_FAILED' };
      }
      if (raw?.status === 'CANCELLED') return { status: 'CANCELLED' };
      if (raw?.status === 'REFUSED') {
        return {
          status: 'REFUSED',
          code: typeof raw.code === 'string' ? raw.code : 'FOLDER_PICKER_REFUSED',
        };
      }
      if (
        raw?.status !== 'SELECTED' ||
        typeof raw.path !== 'string' ||
        typeof raw.displayName !== 'string' ||
        !raw.identity
      ) {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_RESULT_INVALID' };
      }
      try {
        return {
          status: 'SELECTED',
          path: raw.path,
          displayName: raw.displayName,
          identity: mapIdentity(raw.identity),
        };
      } catch {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_IDENTITY_INVALID' };
      }
    },
    inspectFolder(path: string): FolderDirectoryIdentity {
      return mapDirectoryIdentity(addon.inspectFolder(path));
    },
    acquireDirectoryLease(path: string): NativeDirectoryLease {
      if (typeof path !== 'string' || path.length === 0) {
        throw new Error('FOLDER_PICKER_LEASE_PATH_REQUIRED');
      }
      const raw = addon.acquireDirectoryLease(path);
      if (!raw || typeof raw.leaseId !== 'string' || !/^[a-f0-9]{32}$/.test(raw.leaseId)) {
        throw new Error('FOLDER_PICKER_LEASE_ID_INVALID');
      }
      return {
        leaseId: raw.leaseId,
        directory: mapDirectoryIdentity(raw.directory ?? {}),
      };
    },
    verifyDirectoryLease(lease: NativeDirectoryLease): FolderDirectoryIdentity {
      if (!lease || typeof lease.leaseId !== 'string') {
        throw new Error('FOLDER_PICKER_LEASE_INVALID');
      }
      return mapDirectoryIdentity(addon.verifyDirectoryLease(lease.leaseId));
    },
    releaseDirectoryLease(lease: NativeDirectoryLease): void {
      if (!lease || typeof lease.leaseId !== 'string') {
        throw new Error('FOLDER_PICKER_LEASE_INVALID');
      }
      addon.releaseDirectoryLease(lease.leaseId);
    },
    directoryLeasePath(lease: NativeDirectoryLease): string {
      if (!lease || typeof lease.leaseId !== 'string') {
        throw new Error('FOLDER_PICKER_LEASE_INVALID');
      }
      const path = addon.directoryLeasePath(lease.leaseId);
      if (typeof path !== 'string' || path.length === 0) {
        throw new Error('FOLDER_PICKER_LEASE_PATH_UNAVAILABLE');
      }
      return path;
    },
  });
}
