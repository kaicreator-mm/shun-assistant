# T08 Independent Review Checklist

- [ ] Exact HEAD/base/tree, Task Pack and Execution Pack identities match.
- [ ] Only the three T08 allowed-write-set patterns changed.
- [ ] Provider is curated and signed by an existing verified trust root.
- [ ] Artifact digest is verified before staging/loading; cache identity is content-bound.
- [ ] Selected ABI and capability binding match exactly; unsupported npm graph rejects.
- [ ] Tampered/unsigned artifact and fake Host trust root reject.
- [ ] Existing provider-loader and vertical-jit sources remain untouched.
- [ ] No network download, real Windows install/activation or OS mutation occurred.
- [ ] T00/T11-owned package manifests, exports and lockfile remain untouched.
- [ ] Focused tests, provider-loader/vertical-jit/contracts regressions, exact-HEAD CI and independent Review pass.
- [ ] Task Learning disposition is explicit; no main/v0.2 merge or release claim.
