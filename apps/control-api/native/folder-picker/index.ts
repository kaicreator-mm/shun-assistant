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

export type FolderIdentity = FolderUserIdentity & Readonly<{
  volumeSerial: string;
  fileId: string;
}>;

export type FolderDirectoryIdentity = FolderIdentity & Readonly<{
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
  selectFolder(): NativeFolderSelection;
  currentIdentity(): FolderUserIdentity;
  inspectDirectory(path: string): FolderDirectoryIdentity;
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

export function verifyFolderPickerArtifact(): Readonly<{ ok: boolean; code?: string; sha256?: string }> {
  if (process.platform !== 'win32') return { ok: false, code: 'FOLDER_PICKER_PLATFORM_NOT_WINDOWS' };
  const actual = artifactDigest();
  if (actual === null) return { ok: false, code: 'FOLDER_PICKER_ADDON_MISSING' };
  if (!/^[a-f0-9]{64}$/.test(FOLDER_PICKER_ADDON_SHA256) ||
      actual !== FOLDER_PICKER_ADDON_SHA256) {
    return { ok: false, code: 'FOLDER_PICKER_ADDON_SHA_MISMATCH', sha256: actual };
  }
  return { ok: true, sha256: actual };
}

type RawAddon = {
  select_folder(): {
    status: string;
    code?: string;
    path?: string;
    display_name?: string;
    identity?: {
      user_sid?: string;
      logon_sid?: string;
      session_id?: number;
      volume_serial?: string;
      file_id?: string;
    };
  };
  current_identity(): {
    user_sid?: string;
    logon_sid?: string;
    session_id?: number;
  };
  inspect_directory(path: string): {
    user_sid?: string;
    logon_sid?: string;
    session_id?: number;
    volume_serial?: string;
    file_id?: string;
    is_directory?: boolean;
    is_reparse_point?: boolean;
    is_network_path?: boolean;
    is_volume_root?: boolean;
  };
};

function mapIdentity(raw: NonNullable<ReturnType<RawAddon['select_folder']>['identity']>): FolderIdentity {
  if (typeof raw.user_sid !== 'string' || typeof raw.logon_sid !== 'string' ||
      !Number.isSafeInteger(raw.session_id) || typeof raw.volume_serial !== 'string' ||
      typeof raw.file_id !== 'string') throw new Error('FOLDER_PICKER_IDENTITY_INVALID');
  return {
    userSid: raw.user_sid,
    logonSid: raw.logon_sid,
    sessionId: raw.session_id as number,
    volumeSerial: raw.volume_serial,
    fileId: raw.file_id,
  };
}

export function loadFolderPicker(): FolderPickerNativePort {
  const check = verifyFolderPickerArtifact();
  if (!check.ok) throw new Error(check.code ?? 'FOLDER_PICKER_ARTIFACT_REFUSED');
  const require = createRequire(import.meta.url);
  const addon = require(folderPickerAddonPath) as RawAddon;
  if (!addon || typeof addon.select_folder !== 'function' ||
      typeof addon.current_identity !== 'function' ||
      typeof addon.inspect_directory !== 'function') {
    throw new Error('FOLDER_PICKER_ADDON_API_INVALID');
  }
  return Object.freeze({
    selectFolder(): NativeFolderSelection {
      const raw = addon.select_folder();
      if (raw?.status === 'CANCELLED') return { status: 'CANCELLED' };
      if (raw?.status === 'REFUSED') {
        return { status: 'REFUSED', code: typeof raw.code === 'string' ? raw.code : 'FOLDER_PICKER_REFUSED' };
      }
      if (raw?.status !== 'SELECTED' || typeof raw.path !== 'string' ||
          typeof raw.display_name !== 'string' || !raw.identity) {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_RESULT_INVALID' };
      }
      try {
        return {
          status: 'SELECTED',
          path: raw.path,
          displayName: raw.display_name,
          identity: mapIdentity(raw.identity),
        };
      } catch {
        return { status: 'REFUSED', code: 'FOLDER_PICKER_IDENTITY_INVALID' };
      }
    },
    currentIdentity(): FolderUserIdentity {
      const raw = addon.current_identity();
      if (typeof raw.user_sid !== 'string' || typeof raw.logon_sid !== 'string' ||
          !Number.isSafeInteger(raw.session_id)) throw new Error('FOLDER_PICKER_USER_IDENTITY_UNAVAILABLE');
      return {
        userSid: raw.user_sid,
        logonSid: raw.logon_sid,
        sessionId: raw.session_id as number,
      };
    },
    inspectDirectory(path: string): FolderDirectoryIdentity {
      const raw = addon.inspect_directory(path);
      const identity = mapIdentity(raw);
      if (typeof raw.is_directory !== 'boolean' ||
          typeof raw.is_reparse_point !== 'boolean' ||
          typeof raw.is_network_path !== 'boolean' ||
          typeof raw.is_volume_root !== 'boolean') {
        throw new Error('FOLDER_PICKER_DIRECTORY_IDENTITY_INVALID');
      }
      return {
        ...identity,
        isDirectory: raw.is_directory,
        isReparsePoint: raw.is_reparse_point,
        isNetworkPath: raw.is_network_path,
        isVolumeRoot: raw.is_volume_root,
      };
    },
  });
}
