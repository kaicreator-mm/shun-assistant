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

export type FolderUserIdentity = Readonly<{
  userSid: string;
  logonSid: string;
  sessionId: number;
}>;

export type FolderIdentity = FolderUserIdentity &
  Readonly<{
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

export interface FolderPickerNativePort {
  /** Frozen contract: the modal Shell dialog runs on a dedicated COM STA
   * async worker; the Node main event loop is never blocked. */
  pickFolder(): Promise<NativeFolderSelection>;
  currentIdentity(): FolderUserIdentity;
  inspectFolder(path: string): FolderDirectoryIdentity;
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
    userSid?: string;
    logonSid?: string;
    sessionId?: number;
    volumeSerial?: string;
    fileId?: string;
  };
};

type RawAddon = {
  pickFolder(): Promise<RawSelectionResult>;
  currentIdentity(): {
    userSid?: string;
    logonSid?: string;
    sessionId?: number;
  };
  inspectFolder(path: string): {
    userSid?: string;
    logonSid?: string;
    sessionId?: number;
    volumeSerial?: string;
    fileId?: string;
    isDirectory?: boolean;
    isReparsePoint?: boolean;
    isNetworkPath?: boolean;
    isVolumeRoot?: boolean;
  };
};

function mapIdentity(raw: NonNullable<RawSelectionResult['identity']>): FolderIdentity {
  if (
    typeof raw.userSid !== 'string' ||
    typeof raw.logonSid !== 'string' ||
    !Number.isSafeInteger(raw.sessionId) ||
    typeof raw.volumeSerial !== 'string' ||
    typeof raw.fileId !== 'string'
  )
    throw new Error('FOLDER_PICKER_IDENTITY_INVALID');
  return {
    userSid: raw.userSid,
    logonSid: raw.logonSid,
    sessionId: raw.sessionId as number,
    volumeSerial: raw.volumeSerial,
    fileId: raw.fileId,
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
    typeof addon.currentIdentity !== 'function' ||
    typeof addon.inspectFolder !== 'function'
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
    currentIdentity(): FolderUserIdentity {
      const raw = addon.currentIdentity();
      if (
        typeof raw.userSid !== 'string' ||
        typeof raw.logonSid !== 'string' ||
        !Number.isSafeInteger(raw.sessionId)
      )
        throw new Error('FOLDER_PICKER_USER_IDENTITY_UNAVAILABLE');
      return {
        userSid: raw.userSid,
        logonSid: raw.logonSid,
        sessionId: raw.sessionId as number,
      };
    },
    inspectFolder(path: string): FolderDirectoryIdentity {
      const raw = addon.inspectFolder(path);
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
    },
  });
}
