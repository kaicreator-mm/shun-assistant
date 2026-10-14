# i85-U01 R2 — DeepSeek API inference inside an internetClient-only AppContainer (2026-10-14)

Scope adjustment (user instruction, this session): the R2 "real model" leg was
executed against the **remote DeepSeek API (model `deepseek-flash`)** using the
session-provided test key, instead of provisioning a local model. This is a
scope-adjusted research leg: "offline local inference" is **not** tested (an
API is online by definition) and `REAL_LOCAL_INFERENCE` / `OVERALL_U01` remain
**BLOCKED** per the issue definition. No production code touched.

## Final evidence run r2h (container `shunu01-r2h`, launcher exit 0)

- Child: staged `X:\node.exe` (v24.21.0, SHA256 `BA4E6D110E8C1592A1ECD390F6B05F3DA124B13871A5BE62B341A07A853C6C32`
  — byte-identical to the R1 rt1 binary) + `inference-child.js`
  (`A8C46C7D1700AE6CB02F808CD330338053D49BFF2B07E5A205048BDEC29EE883`).
- Token evidence (OS API, classes verified empirically — see bugs below):
  `TokenIsAppContainer=1`; `TokenAppContainerSid
  S-1-15-2-240989768-...-3027949543` == profile SID;
  `TokenCapabilities = ["S-1-15-3-1"]` — internetClient ONLY.
- Broker↔child channel: anonymous stdin/stdout(/stderr) pipes delivered via
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (no loopback, no named endpoints, no
  loopback exemption). 281-byte task payload in, JSONL results out.
- Two real inferences, both ok (HTTP 200, modelEcho `deepseek-flash`):
  seq1 "We live on Earth." (103 tokens, content SHA256 AF6184A4...553DC);
  seq2 "391" = 17*23 correct (69 tokens, content SHA256 A934C244...F38B9).
- Endpoint identity, captured from INSIDE the sandbox: remoteAddress
  3.173.21.63, TLS leaf `fingerprint256 0B:11:24:76:...:52:5B:47:5D`,
  subject `CN=*.deepseek.com`, issuer `CN=Amazon RSA 2048 M01`, validTo
  2026-12-25 — byte-identical to the broker-side `openssl s_client` capture
  (`r2g-tls-broker.txt`). Broker-side DNS: api.deepseek.com →
  d3bbv8sr76az5s.cloudfront.net → 3.173.21.63.
- Negative probes from the same sandboxed child: loopback 127.0.0.1:61645 →
  ERROR/ETIMEDOUT 314 ms; LAN 192.168.100.245:61647 → SynSent stuck for the
  full 6 s window (11 observer ticks), never Established; both sinks logged
  ZERO accepts during any sandbox window (last accepts were control-phase
  only).
- Independent observer (100 ms Get-NetTCPConnection poller keyed on the
  staged executable path `X:\node.exe`, sensitivity proven by an unsandboxed
  control that was caught Established on all three destinations): the
  sandboxed child's ONLY Established remote connection was
  192.168.100.245:58044 -> 3.173.21.63:443 during the inference window.
  Zero helper processes (`Win32_Process ParentProcessId` scan: 0).
- Unsandboxed positive controls (same host, same sinks): POSITIVE_CONNECTED
  to LAN + loopback, sinks logged accepted events.
- API key: present in the child environment (test key), value never logged.

## Verdicts (research legs; separate by design)

```ini
APPCONTAINER_LAUNCH_WITH_CAPABILITY=PASS
RESTRICTED_EGRESS_INTERNETCLIENT_ONLY=PASS
REAL_API_INFERENCE_X2=PASS
ENDPOINT_IDENTITY_TLS_PINNED=PASS
PROCESS_IDENTITY_AND_HELPERS=PASS
CLEANUP=PASS   # regLeftover=0 pkgLeftover=0, subst removed, sinks stopped, stages deleted
REAL_LOCAL_INFERENCE=BLOCKED   # scope-adjusted to remote API by user instruction
OVERALL_U01=BLOCKED            # unchanged: hypothesis is LOCAL zero-egress
```

## Bugs found and fixed on the way (all research-only; launcher hardening)

1. **CreateProcessW error 87 with a non-empty capabilities array** — two
   compounding causes: (a) `SECURITY_CAPABILITIES.Capabilities` must be an
   `SID_AND_ATTRIBUTES` array (16-byte entries), not a bare PSID pointer
   array (MS LaunchAppContainer sample + Chromium sandbox pass
   SID_AND_ATTRIBUTES); (b) `CreateAppContainerProfile` must itself be
   created with the same capability list — a capability-less profile plus a
   capability-bearing attribute is rejected. Capability SID derived via
   `ntdll!RtlDeriveCapabilitySidsFromName` (`DeriveCapabilitySidsByName`
   lives in an api-ms set the .NET Framework loader cannot bind); the name
   UNICODE_STRING length must be exact — one byte short derives an
   unregistered hash capability which also 87s.
2. **Pipe EOF deadlock** — the parent kept its own copies of the
   child-end pipe handles from `CreatePipe`; after the child exited the
   parent was still the last writer and `ReadFile` blocked forever. Child
   ends are now closed in the parent immediately after `CreateProcessW`.
3. **TOKEN_INFORMATION_CLASS off-by-one** — on this build 29=
   TokenIsAppContainer, 30=TokenCapabilities, 31=TokenAppContainerSid
   (verified by class scan + SID dump, `tokcaps-debug.ps1`). Classes 28/5
   are TokenLogonSid groups / TokenPrimaryGroup; using them "worked" only by
   coincidence (counts) and produced empty capability listings.
4. **Observer buffer loss** — `StreamWriter` AutoFlush=false lost the
   inference-window records when the observer was killed; now AutoFlush,
   and the observer is always left to finish its window naturally.
5. **Host TCP-stack quirk (documented limitation)** — ESTABLISHED loopback/
   same-host-IP connections do not appear in `Get-NetTCPConnection` on this
   build (only post-close TimeWait artifacts). Remote (true egress)
   connections DO appear with pid+path. Loopback/LAN denial is therefore
   proven by child probe outcomes + sink-side accept logs + SynSent
   visibility, not by Established-state absence in the poller.
6. **max_tokens reasoning race** — deepseek-flash spends tokens on reasoning
   first; max_tokens=64 once hit `finishReason=length` with empty visible
   content (r2g seq1). Payload raised to 256.

## Must-not-claim (restated)

This run does NOT demonstrate: a local model origin; offline inference;
absence of unobserved telemetry beyond the independently observed connection
set; Windows editions other than the tested build (26300.9457, UAC-filtered
admin-group unelevated token); that internetClient restricts egress to
DeepSeek only — it allows outbound to ANY public Internet host; the
restriction proven is "public-Internet-only, loopback/LAN denied, single
observed destination". No production source merged; no #86/#87 rerun.
