// T08 POSITIVE/NEGATIVE suite for the signed trusted Host adapter, driven by
// the controller-committed production trust material (Issue #236 option 1).

import { generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTrustedProviderHost } from "../../../../packages/domain-host/src/provider/trusted-provider-host.ts";
import { CuratedProviderStager } from "../../../../packages/provider-loader/src/staging.ts";
import { CuratedProviderVerifier } from "../../../../packages/vertical-jit/src/curated-provider.ts";
import {
	ARTIFACT_SHA256,
	ATTACKER_PEM,
	BINDING_ID,
	DESCRIPTOR,
	RG_BYTES,
	ROOT_KEY_ID,
	ROOT_PEM,
	SCOPE,
	sha256Hex,
	tamperedBytes,
} from "./material.ts";

function realRoots() {
	return [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }];
}

describe("T08 signed trusted Host adapter — production material", () => {
	it("admits the real signed descriptor and binds the real rg.exe bytes", () => {
		// The committed artifact is byte-identical to the signed digest.
		expect(sha256Hex(RG_BYTES)).toBe(ARTIFACT_SHA256);

		const host = createTrustedProviderHost({
			roots: realRoots(),
			scopes: [SCOPE],
		});
		const verified = host.verifyProviderDescriptor(DESCRIPTOR);
		expect(verified.ok).toBe(true);
		if (!verified.ok) return;
		expect(verified.artifact.bindingId).toBe(BINDING_ID);
		expect(verified.artifact.artifactSha256).toBe(ARTIFACT_SHA256);
		expect(Object.isFrozen(verified)).toBe(true);
		expect(host.verifyProviderBytes(verified, RG_BYTES)).toBe(true);
		expect(host.verifyProviderBytes(verified, tamperedBytes())).toBe(false);
		expect(host.verifyProviderBytes(verified, Buffer.from("tiny"))).toBe(false);
	});

	it("describeTrust leaks only keyIds/bindingIds, never PEM material", () => {
		const host = createTrustedProviderHost({
			roots: realRoots(),
			scopes: [SCOPE],
			now: () => new Date("2026-10-31T00:00:00.000Z"),
		});
		const trust = host.describeTrust();
		expect(trust.roots).toEqual([ROOT_KEY_ID]);
		expect(trust.bindings).toEqual([BINDING_ID]);
		expect(trust.anchoredAt).toBe("2026-10-31T00:00:00.000Z");
		expect(Object.isFrozen(trust)).toBe(true);
		const rendered = JSON.stringify(trust);
		expect(rendered).not.toContain("BEGIN");
		expect(rendered).not.toContain(ROOT_PEM.slice(40, 80));
	});

	it("offline trusted cache: seeded real bytes stage and read back with zero fetch", async () => {
		const verifier = new CuratedProviderVerifier(realRoots(), [SCOPE]);
		const dir = await mkdtemp(join(tmpdir(), "t08-cache-"));
		try {
			const cacheRoot = join(dir, "cache");
			await mkdir(join(cacheRoot, "artifacts"), { recursive: true });
			await writeFile(join(cacheRoot, "artifacts", ARTIFACT_SHA256), RG_BYTES);
			const stager = new CuratedProviderStager({
				cacheRoot,
				verifier,
				isOffline: () => true,
			});
			const staged = await stager.stage(DESCRIPTOR);
			expect(staged).toMatchObject({
				ok: true,
				state: "VERIFIED_BYTES_ONLY",
				digest: ARTIFACT_SHA256,
			});
			const readBack = await stager.readVerified(DESCRIPTOR);
			expect(readBack).not.toBeNull();
			expect(sha256Hex(readBack as Buffer)).toBe(ARTIFACT_SHA256);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("offline with an empty cache refuses to fetch (OFFLINE), never fabricates bytes", async () => {
		const verifier = new CuratedProviderVerifier(realRoots(), [SCOPE]);
		const dir = await mkdtemp(join(tmpdir(), "t08-offline-"));
		try {
			const stager = new CuratedProviderStager({
				cacheRoot: join(dir, "cache"),
				verifier,
				isOffline: () => true,
			});
			expect(await stager.stage(DESCRIPTOR)).toMatchObject({
				ok: false,
				code: "OFFLINE",
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("NEGATIVE ①: one flipped byte fails byte binding and cache admission", async () => {
		const host = createTrustedProviderHost({
			roots: realRoots(),
			scopes: [SCOPE],
		});
		const verified = host.verifyProviderDescriptor(DESCRIPTOR);
		expect(verified.ok).toBe(true);
		const tampered = tamperedBytes();
		expect(sha256Hex(tampered)).not.toBe(ARTIFACT_SHA256);
		expect(host.verifyProviderBytes(verified, tampered)).toBe(false);

		const verifier = new CuratedProviderVerifier(realRoots(), [SCOPE]);
		const dir = await mkdtemp(join(tmpdir(), "t08-tamper-"));
		try {
			const cacheRoot = join(dir, "cache");
			await mkdir(join(cacheRoot, "artifacts"), { recursive: true });
			await writeFile(join(cacheRoot, "artifacts", ARTIFACT_SHA256), tampered);
			const stager = new CuratedProviderStager({
				cacheRoot,
				verifier,
				isOffline: () => true,
			});
			expect(await stager.stage(DESCRIPTOR)).toMatchObject({
				ok: false,
				code: "CACHE_UNTRUSTED",
			});
			expect(await stager.readVerified(DESCRIPTOR)).toBeNull();
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("NEGATIVE ②: a fake ephemeral Host trust root cannot admit the real descriptor", () => {
		const fakeRoots = [{ keyId: ROOT_KEY_ID, publicKeyPem: ATTACKER_PEM }];
		const fakeHost = createTrustedProviderHost({
			roots: fakeRoots,
			scopes: [SCOPE],
		});
		expect(fakeHost.verifyProviderDescriptor(DESCRIPTOR)).toMatchObject({
			ok: false,
			code: "CATALOG_SIGNATURE_INVALID",
		});
		// Same fake key under an unknown keyId is not trusted at all.
		const unknownIdHost = createTrustedProviderHost({
			roots: [{ keyId: "attacker-root-1", publicKeyPem: ATTACKER_PEM }],
			scopes: [SCOPE],
		});
		expect(unknownIdHost.verifyProviderDescriptor(DESCRIPTOR)).toMatchObject({
			ok: false,
			code: "CATALOG_UNTRUSTED",
		});
	});

	it("NEGATIVE ③: an unpinned dependency graph is scope drift before the signature check", () => {
		const host = createTrustedProviderHost({
			roots: realRoots(),
			scopes: [SCOPE],
		});
		// Tampering dependencySha256 also invalidates the signature, but the
		// verifier resolves the host-curated name↔digest bijection BEFORE
		// verifying the signature — the production CLI scope pins no dependency
		// names, so the precise drift code is returned first.
		const npmGraph = { ...DESCRIPTOR, dependencySha256: ["ab".repeat(32)] };
		expect(host.verifyProviderDescriptor(npmGraph)).toMatchObject({
			ok: false,
			code: "CATALOG_SCOPE_DRIFT",
		});
	});

	it("NEGATIVE ④: hostile getters and malformed configuration are refused at construction", () => {
		const bomb = {
			keyId: ROOT_KEY_ID,
			get publicKeyPem(): string {
				throw new Error("getter bomb");
			},
		};
		expect(() =>
			createTrustedProviderHost({ roots: [bomb], scopes: [SCOPE] }),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		expect(() =>
			createTrustedProviderHost({
				roots: realRoots(),
				scopes: [SCOPE],
				now: () => {
					throw new Error("clock bomb");
				},
			}),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		expect(() =>
			createTrustedProviderHost({
				roots: realRoots(),
				scopes: [SCOPE],
				now: () => 123 as unknown as Date,
			}),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		expect(() =>
			createTrustedProviderHost({ roots: [], scopes: [SCOPE] }),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
		expect(() =>
			createTrustedProviderHost({
				roots: [
					{
						keyId: ROOT_KEY_ID,
						publicKeyPem: rsa.publicKey
							.export({ type: "spki", format: "pem" })
							.toString(),
					},
				],
				scopes: [SCOPE],
			}),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		expect(() =>
			createTrustedProviderHost({ roots: realRoots(), scopes: [SCOPE, SCOPE] }),
		).toThrow("TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED");
		expect(() => createTrustedProviderHost(undefined as never)).toThrow(
			"TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED",
		);
	});

	it("NEGATIVE ⑤: mutating the caller roots/scopes after construction cannot retarget trust", () => {
		const roots: Array<{ keyId: string; publicKeyPem: string }> = [
			{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM },
		];
		const scopes = [{ ...SCOPE }];
		const host = createTrustedProviderHost({ roots, scopes });
		const rootEntry = roots[0];
		const scopeEntry = scopes[0];
		if (!rootEntry || !scopeEntry) throw new Error("unreachable test setup");
		rootEntry.publicKeyPem = ATTACKER_PEM;
		roots.push({ keyId: "attacker-root-1", publicKeyPem: ATTACKER_PEM });
		scopeEntry.artifactSha256 = "f".repeat(64);
		const verified = host.verifyProviderDescriptor(DESCRIPTOR);
		expect(verified.ok).toBe(true);
		if (!verified.ok) return;
		expect(host.verifyProviderBytes(verified, RG_BYTES)).toBe(true);
	});

	it("a shifty getter is read exactly once into the frozen snapshot", () => {
		let reads = 0;
		const shifty = {
			keyId: ROOT_KEY_ID,
			get publicKeyPem(): string {
				reads += 1;
				return reads === 1 ? ROOT_PEM : ATTACKER_PEM;
			},
		};
		const host = createTrustedProviderHost({
			roots: [shifty],
			scopes: [SCOPE],
		});
		expect(reads).toBe(1);
		expect(host.verifyProviderDescriptor(DESCRIPTOR).ok).toBe(true);
		expect(reads).toBe(1);
	});
});
