# T10 B-040 Windows integration adapter (source-only candidate)

Authority: Issue #21; frozen B-040, T09 fixture lock and independent semantic
oracle. This is **not** an integration/real-Windows/release PASS certificate.

Root `pnpm test` now executes `tests/integration/*.test.mjs` via its workspace
runner with Node 24 `--experimental-transform-types`. Its passing source tests
are **not** evidence of a real Windows host, external zero-egress monitoring,
or T10 acceptance.

This adapter uses the real production `@shun/vertical-support` public
collector (zero injection argument, actual Windows platform gate), then
processes only the public T09-listed adversarial source file through the real
production minimizer. The resulting report takes actual OS/device/update
sections from the real host collector and only bounded redaction audit entries
from the adversarial fixture. It neither reads `private/gold.json` nor
preselects a provider nor supplies test gold to Shun's Planner.

## Run on exact SHA in a disposable real Windows 11 host

Use Node 24.21.0 and `pnpm install --frozen-lockfile`. Separately prepare and
**verify** the frozen T09 fixture lock with Python 3.14.7 and exact dependencies
before invoking any candidate; record the precommit SHA outside the fixture:

```powershell
python -m pip install -r tests/harness/requirements.txt
python -m tests.fixtures.generate prepare --root .\t09-run
python -m tests.fixtures.lock verify --root .\t09-run
node --experimental-transform-types --test tests/integration/b040-run.test.mjs
node --experimental-transform-types tests/integration/b040-run.mjs --root .\t09-run --observation .\observed-B-040.json
python -m tests.harness.run --root .\t09-run --case B-040 --observation .\observed-B-040.json --out .\evidence\B-040.json
```

The `--observation` destination must be outside the mutable fixture root and
must not exist already. The report is created at
`candidate/B-040/support-report.json` with create-new semantics. The fixture
lock must be executed before candidate writes; do **not** rerun the precommit
lock on the mutated post-execution root.

The test-owned adapter records `independent_network_capture=NOT_RUN` and
`real_host_validation=NOT_RUN`. Even if the T09 fixture oracle returns PASS,
that only means **fixture oracle PASS**. A separate Windows validator must
observe process-network/system egress and destination instrumentation from
outside the collector process and prove zero external disclosures; it must
also validate scope/approval and all other T10 critical journeys on the same
exact candidate SHA. Any missing independent evidence is BLOCKED/INCOMPLETE.
No UAC, elevated posture, integration, or release success is inferred here.

If `process.platform != win32` the executable path fails before touching the
fixture. Do not replace the collector with dependency injection or a mocked
PowerShell return to satisfy a must-pass host row.
