const SAFE_SELECTION_REF = /^host:folder:[a-f0-9]{64}$/;
const CONTROL_OR_BIDI = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;
const RESERVED_DOS = /^(con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/i;

function isRecord(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch { return false; }
}

function exactKeys(value, expected) {
  try {
    if (!isRecord(value)) return false;
    const keys = Reflect.ownKeys(value);
    return keys.length === expected.length &&
      keys.every((key) => typeof key === 'string' && expected.includes(key));
  } catch { return false; }
}

function safeDisplayName(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 160 &&
    value !== '.' && value !== '..' &&
    !value.startsWith(' ') && !value.endsWith(' ') &&
    !value.endsWith('.') && !/[\\/:*?"<>|]/u.test(value) &&
    !CONTROL_OR_BIDI.test(value) && !RESERVED_DOS.test(value);
}

/**
 * Validate the Host folder-picker receipt. The opaque selectionRef is kept
 * only in memory for the exact current Guided step and is never a display
 * value, persisted UI preference, or authority by itself.
 *
 * @param {number} httpStatus
 * @param {unknown} raw
 * @param {number} nowUnixMs
 */
export function projectFolderSelection(httpStatus, raw, nowUnixMs = Date.now()) {
  if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs <= 0 || !isRecord(raw)) {
    return { status: 'UNKNOWN', code: 'FOLDER_SELECTION_UNVERIFIED' };
  }
  if (httpStatus === 200 && exactKeys(raw, ['status']) && raw.status === 'CANCELLED') {
    return { status: 'CANCELLED' };
  }
  if (httpStatus === 200 && exactKeys(raw, ['status', 'selectionRef', 'displayName', 'expiresAtUnixMs']) &&
      raw.status === 'SELECTED' && SAFE_SELECTION_REF.test(raw.selectionRef) &&
      safeDisplayName(raw.displayName) &&
      Number.isSafeInteger(raw.expiresAtUnixMs) &&
      raw.expiresAtUnixMs > nowUnixMs &&
      raw.expiresAtUnixMs <= nowUnixMs + 5 * 60 * 1000) {
    return {
      status: 'SELECTED',
      selectionRef: raw.selectionRef,
      displayName: raw.displayName,
      expiresAtUnixMs: raw.expiresAtUnixMs,
    };
  }
  if (httpStatus === 409 && isRecord(raw) && raw.status === 'STALE') {
    return { status: 'STALE' };
  }
  if (httpStatus === 422 && isRecord(raw) && raw.status === 'REFUSED') {
    return { status: 'REFUSED' };
  }
  return { status: 'UNKNOWN', code: 'FOLDER_SELECTION_UNVERIFIED' };
}

/**
 * Classify the exact Host-guided receipt + HTTP status.
 * @param {number} httpStatus
 * @param {unknown} raw
 * @returns {'RECORDED'|'REFUSED'|'STALE'|'UNKNOWN'}
 */
export function guidedReceiptStatus(httpStatus, raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return 'UNKNOWN';
  const value = /** @type {Record<string, unknown>} */ (raw);
  if (httpStatus === 200 && value.status === 'RECORDED' &&
      value.humanGrantIssued === false && value.effectSent === false &&
      Array.isArray(value.history)) return 'RECORDED';
  if (httpStatus === 422 && value.status === 'REFUSED') return 'REFUSED';
  if (httpStatus === 409 && value.status === 'STALE') return 'STALE';
  return 'UNKNOWN';
}
