/**
 * Browser-only folder preview; NOT Host-selected scope.
 * File bytes/names are never inspected or sent to any backend.
 */

/**
 * @param {ArrayLike<{size: number, webkitRelativePath?: string}>|null} files
 * @returns {{status:'PREVIEW', folder:string, files:number, bytes:number} |
 *   {status:'REFUSED',code:string}}
 */
export function summarizeBrowserFolder(files) {
  if (!files || !Number.isSafeInteger(files.length) || files.length === 0 ||
      files.length > 4096) return {status:'REFUSED',code:'FOLDER_SELECTION_EMPTY_OR_TOO_LARGE'};
  let folder='';
  let bytes=0;
  for (let i=0;i<files.length;i++) {
    const file=files[i];
    if (!file || !Number.isSafeInteger(file.size) || file.size < 0 ||
        file.size > Number.MAX_SAFE_INTEGER - bytes) {
      return {status:'REFUSED',code:'FOLDER_ENTRY_INVALID'};
    }
    const relative=file.webkitRelativePath;
    // Chromium directory picker supplies a relative folder prefix; no
    // absolute path or traversal is accepted, even in a forged FileList.
    if (typeof relative!=='string' || relative.length>2048 ||
        relative.startsWith('/') || relative.includes('\\') ||
        relative.includes('\0') || /^[A-Za-z]:/.test(relative)) {
      return {status:'REFUSED',code:'FOLDER_PATH_INVALID'};
    }
    const parts=relative.split('/');
    if (parts.length<2 || parts.some(x=>x===''||x==='.'||x==='..')) {
      return {status:'REFUSED',code:'FOLDER_PATH_INVALID'};
    }
    const top=parts[0];
    if (!top || top.length>160 || /[\u0000-\u001f]/.test(top)) {
      return {status:'REFUSED',code:'FOLDER_NAME_INVALID'};
    }
    if (folder && top!==folder) return {status:'REFUSED',code:'FOLDER_MIXED_SELECTION'};
    folder=top;
    bytes+=file.size;
  }
  // This summary is display only. Never derive an absolute Windows path,
  // approval, currentness, CaseRef, or API request from it.
  return {status:'PREVIEW',folder,files:files.length,bytes};
}

/**
 * Classify the **exact** Host-guided receipt + HTTP status.
 * @param {number} httpStatus
 * @param {unknown} raw
 * @returns {'RECORDED'|'REFUSED'|'STALE'|'UNKNOWN'}
 */
export function guidedReceiptStatus(httpStatus,raw) {
  if(!raw || typeof raw!=='object' || Array.isArray(raw))return 'UNKNOWN';
  const value=/** @type {Record<string,unknown>} */(raw);
  if(httpStatus===200 && value.status==='RECORDED' &&
      value.humanGrantIssued===false && value.effectSent===false &&
      Array.isArray(value.history))return 'RECORDED';
  if(httpStatus===422 && value.status==='REFUSED')return 'REFUSED';
  if(httpStatus===409 && value.status==='STALE')return 'STALE';
  return 'UNKNOWN';
}
