//! Consent request validation, native approval minting and the single-use
//! assertion ledger. This is the broker's trusted decision core:
//!
//! - the EXACT disclosure projection is pinned: the request's `projectionJson`
//!   must be the frozen v0.2 T01 shape, and its recomputed BCrypt SHA-256 must
//!   equal `scope.approvedProjectionSha256` before any dialog is shown;
//! - provider facts are literals (deepseek / deepseek-flash / the pinned
//!   chat-completions destination / GOAL_TEXT only) — no arbitrary target;
//! - an approval is minted ONLY after the native dialog confirms (see
//!   dialog.rs); it carries a fresh single-use nonce and an HMAC proof under
//!   a per-process random key, so a restarted broker invalidates everything;
//! - `verify` consumes the assertion atomically: one approval authorizes at
//!   most one downstream `TrustedDeepSeekTransport.invoke`.

use crate::crypto;
use crate::timeutil;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub const BROKER_ID: &str = "shun-consent-broker-win32";
pub const BROKER_REVISION: &str = "v02-t08-c02-r1";
pub const PROOF_FORMAT: &str = "shun-broker-proof-v1";
pub const PROTOCOL: u32 = 1;
pub const DEEPSEEK_DESTINATION: &str = "https://api.deepseek.com/chat/completions";
/// Confirmation freshness cap minted by the broker itself.
pub const MAX_APPROVAL_TTL_MS: i64 = 5 * 60 * 1000;

/// All id/revision Ref fields are constrained to this unambiguous charset so
/// the MAC-covered canonical string needs no JSON escaping (the goal text is
/// never MAC input — only its digest is).
fn valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:@/-".contains(c))
}

pub struct ValidatedRequest {
    pub scope_json: Map<String, Value>,
    pub approved_projection_sha256: String,
    pub task_id: String,
    pub goal_preview: String,
    pub expires_at_ms: i64,
}

pub enum ValidateError {
    ScopeInvalid,
    ProjectionInvalid,
    DigestMismatch,
    ScopeExpired,
}

impl ValidateError {
    pub fn code(&self) -> &'static str {
        match self {
            ValidateError::ScopeInvalid => "REFUSED_SCOPE_INVALID",
            ValidateError::ProjectionInvalid => "REFUSED_PROJECTION_INVALID",
            ValidateError::DigestMismatch => "REFUSED_DIGEST_MISMATCH",
            ValidateError::ScopeExpired => "REFUSED_SCOPE_EXPIRED",
        }
    }
}

fn positive_int(scope: &Map<String, Value>, key: &str) -> Option<i64> {
    match scope.get(key) {
        Some(Value::Number(n)) if n.is_u64() && n.as_u64().unwrap_or(0) > 0 => {
            n.as_u64().map(|v| v as i64)
        }
        _ => None,
    }
}

/// Validate the full consent request against the frozen v0.2 shape.
pub fn validate_request(request: &Value) -> Result<ValidatedRequest, ValidateError> {
    // The wire request is FLAT: every CloudDisclosureScope field sits at the
    // request root next to projectionJson/dialogTimeoutMs. Only the
    // whitelisted scope keys are ever copied into a minted approval, so no
    // transport detail can leak into the consent record.
    let scope = request.as_object().ok_or(ValidateError::ScopeInvalid)?;

    let str_field = |key: &str| scope.get(key).and_then(Value::as_str).unwrap_or("");
    for key in [
        "taskId",
        "principalId",
        "sessionId",
        "scopeRevision",
        "registryRevision",
        "policyRevision",
        "pricingRevision",
        "approvedProjectionSha256",
        "issuedAt",
        "expiresAt",
    ] {
        if !valid_ref(str_field(key)) {
            return Err(ValidateError::ScopeInvalid);
        }
    }
    if str_field("providerId") != "deepseek"
        || str_field("modelId") != "deepseek-flash"
        || str_field("destination") != DEEPSEEK_DESTINATION
    {
        return Err(ValidateError::ScopeInvalid);
    }
    match scope.get("disclosureCategories") {
        Some(Value::Array(items)) if items.len() == 1 && items[0] == Value::String("GOAL_TEXT".into()) => {}
        _ => return Err(ValidateError::ScopeInvalid),
    }
    match scope.get("revocationEpoch") {
        Some(Value::Number(n)) if n.is_u64() => {}
        _ => return Err(ValidateError::ScopeInvalid),
    }
    for key in [
        "maxCalls",
        "maxInputTokens",
        "maxOutputTokens",
        "maxCostMicros",
    ] {
        positive_int(scope, key).ok_or(ValidateError::ScopeInvalid)?;
    }

    // Backend consent window must still be open and non-degenerate.
    let issued_ms = timeutil::parse_iso_utc(str_field("issuedAt"))
        .ok_or(ValidateError::ScopeInvalid)?;
    let expires_ms = timeutil::parse_iso_utc(str_field("expiresAt"))
        .ok_or(ValidateError::ScopeInvalid)?;
    if expires_ms <= issued_ms {
        return Err(ValidateError::ScopeInvalid);
    }
    let now = timeutil::now_ms();
    if now >= expires_ms {
        return Err(ValidateError::ScopeExpired);
    }

    // The EXACT projection: frozen T01 buildDeepSeekGoalDisclosure shape only.
    let projection = request
        .get("projectionJson")
        .and_then(Value::as_str)
        .ok_or(ValidateError::ProjectionInvalid)?;
    if projection.is_empty() || projection.len() > 32 * 1024 {
        return Err(ValidateError::ProjectionInvalid);
    }
    let parsed: Value = serde_json::from_str(projection).map_err(|_| ValidateError::ProjectionInvalid)?;
    let obj = parsed.as_object().ok_or(ValidateError::ProjectionInvalid)?;
    if obj.len() != 5 {
        return Err(ValidateError::ProjectionInvalid);
    }
    let p_str = |key: &str| obj.get(key).and_then(Value::as_str).unwrap_or("");
    if p_str("destination") != DEEPSEEK_DESTINATION
        || p_str("providerId") != "deepseek"
        || p_str("modelId") != "deepseek-flash"
    {
        return Err(ValidateError::ProjectionInvalid);
    }
    match obj.get("disclosureCategories") {
        Some(Value::Array(items)) if items.len() == 1 && items[0] == Value::String("GOAL_TEXT".into()) => {}
        _ => return Err(ValidateError::ProjectionInvalid),
    }
    let goal_text = p_str("goalText");
    if goal_text.is_empty()
        || goal_text.chars().count() > 8192
        || goal_text.contains('\0')
        || goal_text.trim().is_empty()
    {
        return Err(ValidateError::ProjectionInvalid);
    }

    // Digest exactness: recompute over the received bytes.
    let digest = crypto::hex(&crypto::sha256(&[projection.as_bytes()]));
    let claimed = str_field("approvedProjectionSha256");
    if digest != claimed {
        return Err(ValidateError::DigestMismatch);
    }

    let task_id = str_field("taskId").to_string();
    let goal_preview: String = goal_text.chars().take(96).collect();
    let mut scope_json = Map::new();
    for key in [
        "taskId",
        "principalId",
        "sessionId",
        "providerId",
        "modelId",
        "destination",
        "approvedProjectionSha256",
        "scopeRevision",
        "disclosureCategories",
        "registryRevision",
        "policyRevision",
        "pricingRevision",
        "revocationEpoch",
        "maxCalls",
        "maxInputTokens",
        "maxOutputTokens",
        "maxCostMicros",
        "issuedAt",
        "expiresAt",
    ] {
        if let Some(value) = scope.get(key) {
            scope_json.insert(key.to_string(), value.clone());
        }
    }
    Ok(ValidatedRequest {
        scope_json,
        approved_projection_sha256: digest,
        task_id,
        goal_preview,
        expires_at_ms: expires_ms,
    })
}

/// A consumed-or-live assertion record in the in-process ledger.
struct LedgerEntry {
    expires_ms: i64,
    consumed: bool,
}

pub struct ConsentCore {
    key: Vec<u8>,
    ledger: HashMap<String, LedgerEntry>,
}

pub struct MintedApproval {
    pub approval: Value,
}

impl ConsentCore {
    pub fn new() -> Self {
        ConsentCore {
            key: crypto::random_bytes(32),
            ledger: HashMap::new(),
        }
    }

    fn mac_covered(
        consent_id: &str,
        task_id: &str,
        digest: &str,
        nonce: &str,
        assertion_id: &str,
        expires_at: &str,
        scope_revision: &str,
        max_calls: &str,
        max_cost_micros: &str,
    ) -> Vec<u8> {
        let canonical = format!(
            "{PROOF_FORMAT}\n{consent_id}\n{task_id}\n{digest}\n{nonce}\n{assertion_id}\n{expires_at}\n{scope_revision}\n{max_calls}\n{max_cost_micros}"
        );
        canonical.into_bytes()
    }

    /// Mint the approval AFTER a real native-dialog confirmation. Single-use
    /// nonce + HMAC proof under the per-process key; expiry is clamped to the
    /// broker's own freshness cap.
    pub fn mint(&self, request: &ValidatedRequest, now_ms: i64) -> MintedApproval {
        let nonce = crypto::hex(&crypto::random_bytes(32));
        let consent_id = format!("shun-consent-{}", crypto::hex(&crypto::random_bytes(16)));
        let assertion_id = crypto::hex(&crypto::random_bytes(16));
        let issued_ms = now_ms;
        let expires_ms = i64::min(request.expires_at_ms, issued_ms + MAX_APPROVAL_TTL_MS);
        let issued_at = timeutil::format_iso_utc(issued_ms);
        let expires_at = timeutil::format_iso_utc(expires_ms);

        let mut scope = request.scope_json.clone();
        scope.insert("issuedAt".into(), Value::String(issued_at));
        scope.insert("expiresAt".into(), Value::String(expires_at.clone()));

        let get = |k: &str| {
            request
                .scope_json
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let max_calls = request
            .scope_json
            .get("maxCalls")
            .and_then(Value::as_number)
            .and_then(|n| n.as_u64())
            .unwrap_or(0);
        let max_cost = request
            .scope_json
            .get("maxCostMicros")
            .and_then(Value::as_number)
            .and_then(|n| n.as_u64())
            .unwrap_or(0);

        let covered = Self::mac_covered(
            &consent_id,
            &get("taskId"),
            &request.approved_projection_sha256,
            &nonce,
            &assertion_id,
            &expires_at,
            &get("scopeRevision"),
            &max_calls.to_string(),
            &max_cost.to_string(),
        );
        let mac = crypto::base64(&crypto::hmac_sha256(&self.key, &[&covered]));
        let proof = format!("{PROOF_FORMAT}.{assertion_id}.{expires_at}.{mac}");

        let approval = json!({
            "consentId": consent_id,
            "scope": Value::Object(scope),
            "confirmationNonce": nonce,
            "displayedProjectionSha256": request.approved_projection_sha256,
            "displayedDisclosureCategories": ["GOAL_TEXT"],
            "issuer": {
                "brokerId": BROKER_ID,
                "brokerRevision": BROKER_REVISION,
                "assertionId": assertion_id,
                "channel": "AUTHENTICATED_PRIVATE_IPC",
                "proof": proof,
            },
        });
        MintedApproval { approval }
    }

    /// Record a freshly minted assertion as live (single-use).
    pub fn register(&mut self, approval: &Value) {
        let nonce = approval
            .get("confirmationNonce")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let expires_ms = approval
            .pointer("/scope/expiresAt")
            .and_then(Value::as_str)
            .and_then(timeutil::parse_iso_utc)
            .unwrap_or(0);
        self.ledger.insert(
            nonce,
            LedgerEntry {
                expires_ms,
                consumed: false,
            },
        );
    }

    /// Verify + atomically CONSUME an approval's broker assertion. Valid only
    /// when the MAC matches under THIS process's key, the nonce is live, not
    /// yet consumed and not expired. Any failure consumes nothing further and
    /// reports a redacted reason.
    pub fn verify_consume(&mut self, approval: &Value, now_ms: i64) -> (bool, &'static str) {
        let s = |p: &str| approval.pointer(p).and_then(Value::as_str).unwrap_or("");
        let consent_id = s("/consentId");
        let task_id = s("/scope/taskId");
        let digest = s("/scope/approvedProjectionSha256");
        let nonce = s("/confirmationNonce");
        let proof = s("/issuer/proof");
        let expires_at = s("/scope/expiresAt");
        let scope_revision = s("/scope/scopeRevision");
        let assertion_id = s("/issuer/assertionId");
        let issuer_broker = s("/issuer/brokerId");
        let channel = s("/issuer/channel");
        let max_calls = approval
            .pointer("/scope/maxCalls")
            .and_then(Value::as_number)
            .and_then(|n| n.as_u64())
            .unwrap_or(0)
            .to_string();
        let max_cost = approval
            .pointer("/scope/maxCostMicros")
            .and_then(Value::as_number)
            .and_then(|n| n.as_u64())
            .unwrap_or(0)
            .to_string();

        if issuer_broker != BROKER_ID || channel != "AUTHENTICATED_PRIVATE_IPC" {
            return (false, "PROOF_INVALID");
        }
        let expected_prefix = format!("{PROOF_FORMAT}.{assertion_id}.{expires_at}.");
        let Some(mac) = proof.strip_prefix(&expected_prefix) else {
            return (false, "PROOF_INVALID");
        };
        let covered = Self::mac_covered(
            consent_id,
            task_id,
            digest,
            nonce,
            assertion_id,
            expires_at,
            scope_revision,
            &max_calls,
            &max_cost,
        );
        let expect = crypto::base64(&crypto::hmac_sha256(&self.key, &[&covered]));
        if !crypto::constant_time_eq(mac.as_bytes(), expect.as_bytes()) {
            return (false, "PROOF_INVALID");
        }
        let Some(entry) = self.ledger.get_mut(nonce) else {
            return (false, "ASSERTION_UNKNOWN");
        };
        if entry.consumed {
            return (false, "ASSERTION_CONSUMED");
        }
        if now_ms >= entry.expires_ms {
            return (false, "ASSERTION_EXPIRED");
        }
        entry.consumed = true;
        (true, "CONSUMED")
    }

    /// Non-consuming freshness probe backing CloudConsentCurrentness.nonceIsUnused.
    pub fn nonce_unused(&mut self, nonce: &str, now_ms: i64) -> bool {
        self.prune(now_ms);
        match self.ledger.get(nonce) {
            Some(entry) => !entry.consumed && now_ms < entry.expires_ms,
            None => false,
        }
    }

    fn prune(&mut self, now_ms: i64) {
        self.ledger.retain(|_, entry| now_ms < entry.expires_ms + 3_600_000);
    }
}
