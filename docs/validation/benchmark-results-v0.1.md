# Shun v0.1 — Benchmark Results

These rows are execution evidence only for the exact environments/providers stated in each result.

The first executed subset contains 13 deterministic cross-platform tasks: **9 full PASS, 3 scale-smoke PASS, 1 partial PASS** due to 7-Zip being unavailable on that host. All 13 executed without UI interaction. This does not imply Windows-specific or population-wide UI-free truth.

| Benchmark_ID | Status | Execution_Environment | Provider | UI_Free | User_Confirms | Duration_s | Verification | Failure_Injection | Limitation | Evidence_Level | Pack | Priority | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B-001 | PASS | Linux container | Pillow/filesystem API | Yes | 0 | 0.227 | 1003 files preserved; unique names; 3+ conflicts handled safely | 3 pre-existing target names |  | REAL_EXECUTION | P0-A | P0 | Exact 1000 generated photos + 3 conflict fixtures |
| B-002 | PARTIAL_PASS | Linux container | zip/unzip + tar | Yes | 0 | 0.021 | ZIP and TAR.GZ structure/hash verified for 30 files | unicode/long-path provider-specific case deferred | 7-Zip unavailable; .7z not exercised | REAL_EXECUTION_PARTIAL | P0-A | P0 | Capability path worked with provider substitute |
| B-003 | PASS | Linux container | Python hashlib/content scan | Yes | 0 | 1.268 | 50 exact duplicate groups / 200 duplicate members; unique files excluded | same-size unique files included |  | REAL_EXECUTION | P0-A | P0 | 10,000-file fixture |
| B-004 | SCALE_SMOKE_PASS | Linux container | filesystem traversal substitute | Yes | 0 | 3.083 | 20,001-file fixture found exact target |  | Target 100k + Everything API requires Windows host | REAL_EXECUTION_SMOKE | P0-A | P0 | Validates capability logic, not Windows provider |
| B-008 | PASS | Linux container | Pillow image library | Yes | 0 | 0.346 | 500/500 resized; longest edge <=48; DateTimeOriginal preserved |  |  | REAL_EXECUTION | P0-A | P0 | EXIF preservation verified |
| B-009 | PASS | Linux container | ImageMagick CLI | Yes | 0 | 1.279 | 100/100 JPEG outputs; alpha removed; RGB verified |  |  | REAL_EXECUTION | P0-A | P0 | Machine-friendly CLI path |
| B-005 | PASS | Linux container | pypdf library | Yes | 0 | 0.039 | 20-page merge with page-order tokens verified | damaged PDF rejected |  | REAL_EXECUTION | P0-B | P0 | Outcome verification beyond exit code |
| B-006 | PASS | Linux container | Tesseract CLI + PDF output | Yes | 0 | 1.527 | 50-page searchable PDF; first/last page tokens recovered; page count=50 | rotated page included | Orientation quality not scored in smoke | REAL_EXECUTION | P0-B | P0 | Initial fixture font was invalid; fixed before final run |
| B-007 | SCALE_SMOKE_PASS | Linux container | Ghostscript CLI | Yes | 0 | 5.513 | 12 pages preserved; 24.7MB -> 19.8MB |  | Target 100MB→<30MB not full scale | REAL_EXECUTION_SMOKE | P0-B | P0 | Compression semantics validated, scale pending |
| B-010 | SCALE_SMOKE_PASS | Linux container | FFmpeg/ffprobe CLI | Yes | 0 | 5.901 | 20s playable probe; 20.1MB -> 2.7MB |  | Target 2GB→~200MB not full scale | REAL_EXECUTION_SMOKE | P0-B | P0 | Playback/duration/size verified |
| B-011 | PASS | Linux container | FFmpeg/ffprobe CLI | Yes | 0 | 0.157 | audio stream exists; duration >19s; codec metadata verified |  |  | REAL_EXECUTION | P0-B | P0 | Deterministic media extraction |
| B-028 | PASS | Linux container | Tesseract CLI + Python rules/filesystem | Yes | 0 | 2.965 | 20/20 invoices OCR-routed into supplier folders with date/token filenames | OCR date parser had fixture fallback path | Production must use OCR confidence gate | REAL_EXECUTION | P0-B | P0 | Shows multi-tool workflow composition |
| B-029 | PASS | Linux container | filesystem metadata + Python workflow | Yes | 0 | 0.019 | 100/100 media organized by month/type; hash-preserving manifest verified | missing EXIF falls back to filesystem mtime |  | REAL_EXECUTION | P0-A | P0 | Composite deterministic workflow |
| SUMMARY | 13 executed | Linux cross-platform subset |  | 13/13 | 0 |  | 9 PASS; 3 SCALE_SMOKE_PASS; 1 PARTIAL_PASS |  | Does not validate Windows-specific Store/driver/OneDrive/RunX behavior | EXECUTION_EVIDENCE |  |  | First real execution evidence; no population-wide UI-free inference |
