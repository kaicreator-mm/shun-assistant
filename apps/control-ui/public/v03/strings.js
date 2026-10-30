// v03 Control UI string catalog (T10, Issue #238).
//
// CN/EN parity is a hard requirement of the bounded surface: every key exists
// in BOTH locales, and every authority-relevant entry carries the same
// polarity marker in both locales (see stringsAudit). Lookups fail closed:
// an unbound locale or a missing key is a refusal, never a silent fallback to
// the other language. Pure data + pure functions; no DOM, no fetch.

/**
 * @typedef {'en'|'zh'} Locale
 */

/**
 * @typedef {Object} StringEntry
 * @property {string} text
 * @property {boolean} authorityRelevant True when the sentence decides,
 *   describes or bounds authorization semantics (approve/refuse/unknown/
 *   paused/scope/consent) and must never drift between CN and EN.
 * @property {string} [polarity] Required when authorityRelevant; one of
 *   AUTHORITY_POLARITIES. Language-neutral semantic tag, identical in both
 *   locales.
 */

/** The two supported locales. Anything else is unbound and refused. */
export const LOCALES = Object.freeze(['en', 'zh']);

/** Closed polarity taxonomy for authority-relevant strings. */
export const AUTHORITY_POLARITIES = Object.freeze([
  'APPROVE',
  'REFUSE',
  'UNKNOWN',
  'PAUSED',
  'SCOPE',
  'CONSENT',
]);

/** @type {Record<string, Record<string, StringEntry>>} */
export const STRINGS = {
  en: {
    'app.title': {
      text: 'Shun — Bounded Control (v0.3)',
      authorityRelevant: false,
    },
    'app.subtitle': {
      text: 'One guided step at a time. Nothing takes effect without your explicit approval.',
      authorityRelevant: false,
    },
    'state.currentStep': {
      text: 'Current guided step',
      authorityRelevant: false,
    },
    'state.selectedScope': {
      text: 'Selected scope',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'state.progress': {
      text: 'Progress',
      authorityRelevant: false,
    },
    'state.history': {
      text: 'History',
      authorityRelevant: false,
    },
    'state.refused': {
      text: 'Refused',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'state.unknown': {
      text: 'Unknown',
      authorityRelevant: true,
      polarity: 'UNKNOWN',
    },
    'state.paused': {
      text: 'Paused',
      authorityRelevant: true,
      polarity: 'PAUSED',
    },
    'state.ok': {
      text: 'Completed',
      authorityRelevant: false,
    },
    'scope.selectedRoot': {
      text: 'Selected root folder',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.none': {
      text: 'No folder is selected yet.',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.unknown': {
      text: 'The selected scope is unknown. Nothing outside a confirmed scope is shown.',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.outsideRefused': {
      text: 'Refused to show content outside the selected scope.',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'consent.explicitRequired': {
      text: 'This step takes a real effect and needs your explicit approval (R2).',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'consent.humanRelay': {
      text: 'Your decision is relayed as-is to Shun over the local API; it never becomes an automatic grant.',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'consent.notGrant': {
      text: 'Approving here is not a grant: Shun re-checks everything on its own side.',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'step.approve': {
      text: 'Approve this step',
      authorityRelevant: true,
      polarity: 'APPROVE',
    },
    'step.refuse': {
      text: 'Refuse this step',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'step.relayPending': {
      text: 'Waiting to relay your decision…',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'outcome.accepted': {
      text: 'Step recorded.',
      authorityRelevant: false,
    },
    'outcome.rejected': {
      text: 'The step was refused.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'outcome.blocked': {
      text: 'The step was blocked.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'outcome.unknown': {
      text: 'The step result is unknown. Nothing is treated as done.',
      authorityRelevant: true,
      polarity: 'UNKNOWN',
    },
    'outcome.replay': {
      text: 'This exact step result was already submitted (possible replay). It was refused.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'advisory.title': {
      text: 'Suggestion (advisory only)',
      authorityRelevant: false,
    },
    'advisory.notAuthority': {
      text: 'Suggestions are never authority and never approve anything on their own.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.stepExpired': {
      text: 'This step has expired. Nothing can be approved on it anymore.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.stepInvalid': {
      text: 'This step could not be verified, so it is not shown as current. Nothing was approved.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.forgeryRefused': {
      text: 'This step result carried fields it must never carry (forged authority). It was refused.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.localeUnbound': {
      text: 'This scope or consent text is not bound to your language, so it is refused instead of guessed.',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'history.empty': {
      text: 'Nothing has happened yet.',
      authorityRelevant: false,
    },
    'paused.reason': {
      text: 'The journey is paused. Nothing runs until it is resumed.',
      authorityRelevant: true,
      polarity: 'PAUSED',
    },
  },
  zh: {
    'app.title': {
      text: 'Shun — 有界控制（v0.3）',
      authorityRelevant: false,
    },
    'app.subtitle': {
      text: '一次只显示一个引导步骤。没有您的明确批准，任何操作都不会生效。',
      authorityRelevant: false,
    },
    'state.currentStep': {
      text: '当前引导步骤',
      authorityRelevant: false,
    },
    'state.selectedScope': {
      text: '已选范围',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'state.progress': {
      text: '进度',
      authorityRelevant: false,
    },
    'state.history': {
      text: '历史',
      authorityRelevant: false,
    },
    'state.refused': {
      text: '已拒绝',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'state.unknown': {
      text: '未知',
      authorityRelevant: true,
      polarity: 'UNKNOWN',
    },
    'state.paused': {
      text: '已暂停',
      authorityRelevant: true,
      polarity: 'PAUSED',
    },
    'state.ok': {
      text: '已完成',
      authorityRelevant: false,
    },
    'scope.selectedRoot': {
      text: '所选根目录',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.none': {
      text: '尚未选择任何文件夹。',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.unknown': {
      text: '所选范围未知。未经确认的范围不显示任何内容。',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'scope.outsideRefused': {
      text: '已拒绝显示超出所选范围的内容。',
      authorityRelevant: true,
      polarity: 'SCOPE',
    },
    'consent.explicitRequired': {
      text: '此步骤会产生真实效果，需要您的明确批准（R2）。',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'consent.humanRelay': {
      text: '您的决定会通过本地 API 原样转发给 Shun；它绝不会变成自动授权。',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'consent.notGrant': {
      text: '在此批准并不等于授权：Shun 会在自己一侧重新核验一切。',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'step.approve': {
      text: '批准此步骤',
      authorityRelevant: true,
      polarity: 'APPROVE',
    },
    'step.refuse': {
      text: '拒绝此步骤',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'step.relayPending': {
      text: '正在转发您的决定……',
      authorityRelevant: true,
      polarity: 'CONSENT',
    },
    'outcome.accepted': {
      text: '步骤已记录。',
      authorityRelevant: false,
    },
    'outcome.rejected': {
      text: '该步骤已被拒绝。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'outcome.blocked': {
      text: '该步骤已被阻止。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'outcome.unknown': {
      text: '步骤结果未知。任何内容都不会被视为已完成。',
      authorityRelevant: true,
      polarity: 'UNKNOWN',
    },
    'outcome.replay': {
      text: '此步骤结果已提交过（可能的重放）。已被拒绝。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'advisory.title': {
      text: '建议（仅供参考）',
      authorityRelevant: false,
    },
    'advisory.notAuthority': {
      text: '建议绝不是授权，也绝不会自行批准任何操作。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.stepExpired': {
      text: '此步骤已过期。不能再对它做任何批准。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.stepInvalid': {
      text: '无法核验此步骤，因此不会将其显示为当前步骤。未批准任何内容。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.forgeryRefused': {
      text: '此步骤结果携带了绝不允许携带的字段（伪造授权）。已被拒绝。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'error.localeUnbound': {
      text: '此范围或同意文案未绑定到您的语言，因此拒绝显示而不是猜测。',
      authorityRelevant: true,
      polarity: 'REFUSE',
    },
    'history.empty': {
      text: '还没有发生任何事情。',
      authorityRelevant: false,
    },
    'paused.reason': {
      text: '旅程已暂停。在恢复之前不会有任何操作运行。',
      authorityRelevant: true,
      polarity: 'PAUSED',
    },
  },
};

/**
 * @typedef {Object} TextOk
 * @property {true} ok
 * @property {string} text
 * @property {undefined} [code]
 * @property {undefined} [reason]
 */
/**
 * @typedef {Object} TextRefused
 * @property {false} ok
 * @property {'LOCALE_UNBOUND'|'KEY_MISSING'} code
 * @property {string} reason
 * @property {undefined} [text]
 */
/** @typedef {TextOk|TextRefused} TextResult */

/**
 * Fail-closed lookup: an unbound locale or a key missing from THAT locale is
 * a refusal. There is deliberately no cross-locale fallback — scope and
 * consent sentences must be bound to the user's locale to render at all.
 *
 * @param {string} locale
 * @param {string} key
 * @returns {TextResult}
 */
export function t(locale, key) {
  if (typeof locale !== 'string' || !LOCALES.includes(locale)) {
    return {
      ok: false,
      code: 'LOCALE_UNBOUND',
      reason: `Locale "${String(locale)}" is not bound to this surface; refusing to guess text.`,
    };
  }
  const entry = /** @type {Record<string, StringEntry>} */ (STRINGS[locale])[key];
  if (!entry || typeof entry.text !== 'string' || entry.text.length === 0) {
    return {
      ok: false,
      code: 'KEY_MISSING',
      reason: `Key "${key}" is missing for locale "${locale}"; refusing to render a substitute.`,
    };
  }
  return { ok: true, text: entry.text };
}

/**
 * @typedef {Object} AuditProblem
 * @property {string} problem
 * @property {string} [key]
 * @property {string} [locale]
 */
/**
 * @typedef {Object} AuditOk
 * @property {true} ok
 * @property {undefined} [problems]
 */
/**
 * @typedef {Object} AuditRefused
 * @property {false} ok
 * @property {'STRINGS_AUDIT_REFUSED'} code
 * @property {AuditProblem[]} problems
 */
/** @typedef {AuditOk|AuditRefused} AuditResult */

/**
 * Structural CN/EN parity audit of a strings catalog:
 * - both locales present, key sets identical;
 * - every entry has non-empty text and a boolean authorityRelevant flag;
 * - authority-relevant entries carry a known polarity, plain entries none;
 * - authorityRelevant flag and polarity agree across locales.
 * Language-level wording checks (that EN and ZH really say the same thing)
 * live in the T10 tests, which pin anchor vocabulary per polarity.
 *
 * @param {unknown} catalog
 * @returns {AuditResult}
 */
export function stringsAudit(catalog) {
  /** @type {AuditProblem[]} */
  const problems = [];
  if (!catalog || typeof catalog !== 'object') {
    return {
      ok: false,
      code: 'STRINGS_AUDIT_REFUSED',
      problems: [{ problem: 'catalog is not an object' }],
    };
  }
  const record = /** @type {Record<string, unknown>} */ (catalog);
  for (const locale of LOCALES) {
    if (!record[locale] || typeof record[locale] !== 'object') {
      problems.push({ problem: `locale "${locale}" missing`, locale });
    }
  }
  if (problems.length > 0) {
    return { ok: false, code: 'STRINGS_AUDIT_REFUSED', problems };
  }
  const en = /** @type {Record<string, StringEntry>} */ (record.en);
  const zh = /** @type {Record<string, StringEntry>} */ (record.zh);
  const enKeys = Object.keys(en).sort();
  const zhKeys = Object.keys(zh).sort();
  if (enKeys.length !== zhKeys.length) {
    problems.push({ problem: `key count differs: en=${enKeys.length} zh=${zhKeys.length}` });
  }
  for (const key of enKeys) {
    if (!(key in zh)) problems.push({ problem: 'key missing in zh', key });
  }
  for (const key of zhKeys) {
    if (!(key in en)) problems.push({ problem: 'key missing in en', key });
  }
  for (const key of enKeys) {
    if (!(key in zh)) continue;
    const enEntry = en[key];
    const zhEntry = zh[key];
    if (!enEntry || !zhEntry) continue;
    for (const locale of LOCALES) {
      const entry = /** @type {Record<string, StringEntry>} */ (record[locale])[key];
      if (!entry || typeof entry !== 'object') {
        problems.push({ problem: 'entry is not an object', key, locale });
        continue;
      }
      if (typeof entry.text !== 'string' || entry.text.length === 0) {
        problems.push({ problem: 'text missing or empty', key, locale });
      }
      if (typeof entry.authorityRelevant !== 'boolean') {
        problems.push({ problem: 'authorityRelevant is not a boolean', key, locale });
      }
      if (entry.authorityRelevant === true) {
        if (typeof entry.polarity !== 'string' || !AUTHORITY_POLARITIES.includes(entry.polarity)) {
          problems.push({ problem: 'authority entry lacks a known polarity', key, locale });
        }
      } else if (entry.polarity !== undefined) {
        problems.push({ problem: 'non-authority entry carries a polarity', key, locale });
      }
    }
    if (enEntry.authorityRelevant !== zhEntry.authorityRelevant) {
      problems.push({ problem: 'authorityRelevant differs between en and zh', key });
    }
    if (enEntry.polarity !== zhEntry.polarity) {
      problems.push({ problem: 'polarity differs between en and zh', key });
    }
  }
  if (problems.length > 0) {
    return { ok: false, code: 'STRINGS_AUDIT_REFUSED', problems };
  }
  return { ok: true };
}
