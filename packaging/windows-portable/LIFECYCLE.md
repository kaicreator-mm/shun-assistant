# T09 P03 — Portable per-user lifecycle and qualification

This is a **Core-only user-profile lifecycle**, not an MSI/service installer,
Windows Authenticode substitute, or final release qualification.

## Distribution model

- An operator builds the Node24 Windows Core-only staging folder using
  `packaging/windows-portable/build.mjs`, then signs the **entire** stage using
  the accepted P01 `scripts/package-v02/manifest.mjs sign` with a private
  Ed25519 key **outside** the stage. Do not generate production signing keys
  from a browser, user request or Shun itself.
- The user receives the *signed stage* including its packaged `node.exe`.
  A **trusted installer/bootstrap** must authenticate the launcher/verifier
  (e.g. an OS-verifiable signed distributor). A manifest by itself cannot
  establish a trusted execution chain when the verifier script could be
  changed by the attacker before it runs.
- The operator's trusted public key path and SHA256 SPKI fingerprint are
  supplied out of band; neither is accepted from the package manifest.

The per-user paths are fixed:

```text
%LOCALAPPDATA%/ShunAssistant/
  core/       replaceable app bundle, node.exe, local UI and native binaries
  state/      user-owned data (ShunStore, operator-provisioned state, canaries)
```

The lifecycle script uses **only Node24 built-ins plus the reviewed P01
verifier**, keeps all data under the current user's profile, rejects UNC/mapped
network drives using the Windows OS-reported DriveType=3 check, and does not
request elevation, create users, install a service or generate signing secrets.
It stages verified bytes to an isolated sibling, verifies the copy, replaces
only `core/` and retains `state/`. A failed replacement attempts to roll
back the former Core. Executable handles may block Windows replacement;
stop the old app before upgrading.

## Test/build commands

On a controlled Windows x64 Node24 build host, run tests (no product
credentials or DeepSeek call required):

```powershell
node --test packaging/windows-portable/lifecycle.test.mjs
node packaging/windows-portable/build.mjs "$env:TEMP\shun-v02-stage"
node packaging/windows-portable/smoke.mjs "$env:TEMP\shun-v02-stage"
node scripts/package-v02/manifest.mjs sign "$env:TEMP\shun-v02-stage" "C:\operator\private-key.pem"
node scripts/package-v02/manifest.mjs verify "$env:TEMP\shun-v02-stage" "C:\operator\public-key.pem" "<OUT_OF_BAND_SPKI_SHA256>"
```

With a trusted launch chain, the staged `node.exe` can run the included
`packaging/windows-portable/lifecycle.mjs`, so a user does **not** need to
install Node/pnpm just to operate the distribution:

```powershell
& "$env:TEMP\shun-v02-stage\node.exe" "$env:TEMP\shun-v02-stage\packaging\windows-portable\lifecycle.mjs" install "$env:TEMP\shun-v02-stage" "C:\operator\public-key.pem" "<OUT_OF_BAND_SPKI_SHA256>"
& "$env:TEMP\shun-v02-stage\node.exe" "$env:TEMP\shun-v02-stage\packaging\windows-portable\lifecycle.mjs" uninstall
```

**No unconditional user-state removal command is provided.** Ordinary
uninstall removes only the replaceable Core directory; operator-owned SQLite
WAL, local credentials and saved tasks must remain intact. A future explicit
privacy/data-deletion action would need its own review and confirmation.

## Remaining acceptance before T09 closure

1. Independently review the P03 code and run actual Node24 targeted tests.
   The tests use temporary signed synthetic payloads to prove `install →
   upgrade → uninstall` state-canary invariants, not native Windows runtime.
2. A **genuine Standard User** (not a filtered admin token) on supported
   Windows Home **and** Pro must execute signed portable install/start,
   upgraded Core/retained canaries, uninstall and retained canaries. Capture
   exact version SHA, OS edition/token, exit and file/DB receipts.
3. Verify actual fixed **local** disk SQLite WAL and app-owned directories
   for real operator-provisioned ShunStore, no network/UNC state, no Node
   or pnpm requirement for the user, no unapproved provider/model download,
   no silent authority/grant bootstrap.
4. Verify real-storage startup and one bounded Recipe journey using the
   previously accepted T08 signed authority setup; a demo-only smoke is not a
   real launch test.
5. Separate T11 will still own physical human dialog consent, hidden
   negatives, all critical journeys and independent release qualification.

**This P03 source is not a T09 PASS or authorization to merge main.**
