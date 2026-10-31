// T08 suite for the Curated Provider JIT B (bounded acquisition-lifecycle
// proposal): real production descriptor in, frozen PROPOSAL_ONLY or typed
// refusal out — never execution, download or authorization.
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { TrustedProviderHostPort } from "../../../../packages/domain-computer/src/provider/provider-jit.ts";
import { createProviderJitBusinessAdapter } from "../../../../packages/domain-computer/src/provider/provider-jit.ts";
import type { TrustedProviderHost } from "../../../../packages/domain-host/src/provider/trusted-provider-host.ts";
import { createTrustedProviderHost } from "../../../../packages/domain-host/src/provider/trusted-provider-host.ts";
import {
	ARTIFACT_SHA256,
	ATTACKER_PEM,
	BINDING_ID,
	DESCRIPTOR,
	RG_BYTES,
	ROOT_KEY_ID,
	ROOT_PEM,
	SCOPE,
	tamperedBytes,
} from "./material.ts";

function realHost(): TrustedProviderHost {
	return createTrustedProviderHost({
		roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
		scopes: [SCOPE],
	});
}

function fakeRootHost(): TrustedProviderHost {
	return createTrustedProviderHost({
		roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ATTACKER_PEM }],
		scopes: [SCOPE],
	});
}

function port(
	host: TrustedProviderHost,
	policy: { cacheRoot: string; offline: boolean },
): TrustedProviderHostPort {
	return {
		verifyProviderDescriptor: (descriptor) =>
			host.verifyProviderDescriptor(descriptor),
		verifyProviderBytes: (verified, bytes) =>
			host.verifyProviderBytes(verified, bytes),
		cachePeek: (digest) =>
			existsSync(join(policy.cacheRoot, "artifacts", digest))
				? "SEEDED"
				: "MISS",
		isOffline: () => policy.offline,
	};
}

function assertNoAuthorityShape(result: {
	status: string;
	[key: string]: unknown;
}): void {
	const keys = Object.keys(result).sort();
	if (result.status === "PROPOSAL_ONLY") {
		expect(keys).toEqual([
			"artifactSha256",
			"bindingId",
			"cacheState",
			"deterministic",
			"effectRoute",
			"executionAuthorized",
			"modelCalls",
			"status",
		]);
		expect(result.executionAuthorized).toBe(false);
		expect(result.effectRoute).toBe("T11_WIRING_ONLY");
		expect(result.modelCalls).toBe(0);
		expect(result.deterministic).toBe(true);
		// No nested object can smuggle an execution capability.
		for (const value of Object.values(result)) {
			expect(typeof value === "object" && value !== null).toBe(false);
		}
	} else {
		expect(keys).toEqual(["code", "modelCalls", "status"]);
		expect(result.modelCalls).toBe(0);
	}
	expect(Object.isFrozen(result)).toBe(true);
}

describe("T08 Curated Provider JIT B — proposal lifecycle", () => {
	it("POSITIVE: offline with a seeded trusted cache proposes SEEDED acquisition", () => {
		const dir = mkdtempSync(join(tmpdir(), "t08-jit-"));
		try {
			const cacheRoot = join(dir, "cache");
			mkdirSync(join(cacheRoot, "artifacts"), { recursive: true });
			writeFileSync(join(cacheRoot, "artifacts", ARTIFACT_SHA256), RG_BYTES);
			const jit = createProviderJitBusinessAdapter(
				port(realHost(), { cacheRoot, offline: true }),
				{ capabilityId: "file.search" },
			);
			const proposal = jit.proposeProviderAcquisition(DESCRIPTOR);
			assertNoAuthorityShape(proposal);
			expect(proposal).toMatchObject({
				status: "PROPOSAL_ONLY",
				bindingId: BINDING_ID,
				artifactSha256: ARTIFACT_SHA256,
				cacheState: "SEEDED",
			});
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("POSITIVE: caller-supplied exact rg.exe bytes bind and propose without cache", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
		);
		const proposal = jit.proposeProviderAcquisition(DESCRIPTOR, RG_BYTES);
		assertNoAuthorityShape(proposal);
		expect(proposal).toMatchObject({
			status: "PROPOSAL_ONLY",
			cacheState: "MISS",
		});
		// Model-supplied bytes never substitute for the trusted cache: the same
		// correct bytes under an offline policy still refuse (acquisition must be
		// re-routed through T11's stager, never accepted from request input).
		const offlineJit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: true,
			}),
		);
		expect(
			offlineJit.proposeProviderAcquisition(DESCRIPTOR, RG_BYTES),
		).toMatchObject({
			status: "REFUSED",
			code: "OFFLINE_CACHE_MISS",
		});
	});

	it("POSITIVE: online with an empty cache still proposes (acquisition route exists)", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
		);
		const proposal = jit.proposeProviderAcquisition(DESCRIPTOR);
		assertNoAuthorityShape(proposal);
		expect(proposal).toMatchObject({
			status: "PROPOSAL_ONLY",
			cacheState: "MISS",
		});
	});

	it("NEGATIVE ⑥a: offline + cache MISS refuses OFFLINE_CACHE_MISS", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: true,
			}),
		);
		const refused = jit.proposeProviderAcquisition(DESCRIPTOR);
		assertNoAuthorityShape(refused);
		expect(refused).toMatchObject({
			status: "REFUSED",
			code: "OFFLINE_CACHE_MISS",
		});
	});

	it("NEGATIVE ⑥b: caller-supplied wrong bytes refuse ARTIFACT_HASH_MISMATCH", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: true,
			}),
		);
		for (const bytes of [
			tamperedBytes(),
			Buffer.from("tiny"),
			"not-bytes" as unknown as Uint8Array,
		]) {
			const refused = jit.proposeProviderAcquisition(DESCRIPTOR, bytes);
			assertNoAuthorityShape(refused);
			expect(refused).toMatchObject({
				status: "REFUSED",
				code: "ARTIFACT_HASH_MISMATCH",
			});
		}
	});

	it("NEGATIVE ⑥c: forged/invalid descriptors refuse DESCRIPTOR_INVALID at JIT level", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
		);
		for (const bad of [
			{ ...DESCRIPTOR, artifactSha256: "zz-not-a-hash" },
			{ ...DESCRIPTOR, extraField: "strict schema rejects unknown keys" },
			{ ...DESCRIPTOR, curatorSignature: undefined },
			null,
			42,
		]) {
			const refused = jit.proposeProviderAcquisition(bad);
			assertNoAuthorityShape(refused);
			expect(refused).toMatchObject({
				status: "REFUSED",
				code: "DESCRIPTOR_INVALID",
			});
		}
		// The same wire-invalid descriptor surfaces as CATALOG_UNTRUSTED at the
		// Host boundary: the four-class vocabulary stays Host-owned.
		expect(
			realHost().verifyProviderDescriptor({
				...DESCRIPTOR,
				artifactSha256: "zz",
			}),
		).toMatchObject({
			ok: false,
			code: "CATALOG_UNTRUSTED",
		});
	});

	it("NEGATIVE ②: a fake Host trust root flows through as CATALOG_SIGNATURE_INVALID", () => {
		const jit = createProviderJitBusinessAdapter(
			port(fakeRootHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
		);
		const refused = jit.proposeProviderAcquisition(DESCRIPTOR);
		assertNoAuthorityShape(refused);
		expect(refused).toMatchObject({
			status: "REFUSED",
			code: "CATALOG_SIGNATURE_INVALID",
		});
	});

	it("NEGATIVE ③: unpinned npm dependency graph refuses CATALOG_SCOPE_DRIFT", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
		);
		const refused = jit.proposeProviderAcquisition({
			...DESCRIPTOR,
			dependencySha256: ["ab".repeat(32)],
		});
		assertNoAuthorityShape(refused);
		expect(refused).toMatchObject({
			status: "REFUSED",
			code: "CATALOG_SCOPE_DRIFT",
		});
	});

	it("a capability pin outside the verified scope refuses CATALOG_SCOPE_DRIFT", () => {
		const jit = createProviderJitBusinessAdapter(
			port(realHost(), {
				cacheRoot: "T:/nonexistent-t08-cache",
				offline: false,
			}),
			{ capabilityId: "other.capability" },
		);
		expect(jit.proposeProviderAcquisition(DESCRIPTOR)).toMatchObject({
			status: "REFUSED",
			code: "CATALOG_SCOPE_DRIFT",
		});
	});

	it("refuses a broken or hostile trust port at construction", () => {
		for (const broken of [
			null,
			{},
			{ verifyProviderDescriptor: () => {}, isOffline: () => false },
		] as unknown[]) {
			expect(() =>
				createProviderJitBusinessAdapter(broken as never, {}),
			).toThrow("PROVIDER_JIT_CONFIGURATION_REFUSED");
		}
		expect(() =>
			createProviderJitBusinessAdapter(
				realHost() as unknown as TrustedProviderHostPort,
				{
					capabilityId: "",
				},
			),
		).toThrow("PROVIDER_JIT_CONFIGURATION_REFUSED");
	});

	it("a throwing cache peek or offline policy fails closed, never to a proposal", () => {
		const host = realHost();
		const hostilePort: TrustedProviderHostPort = {
			verifyProviderDescriptor: (descriptor) =>
				host.verifyProviderDescriptor(descriptor),
			verifyProviderBytes: (verified, bytes) =>
				host.verifyProviderBytes(verified, bytes),
			cachePeek: () => {
				throw new Error("peek bomb");
			},
			isOffline: () => {
				throw new Error("policy bomb");
			},
		};
		const jit = createProviderJitBusinessAdapter(hostilePort);
		expect(jit.proposeProviderAcquisition(DESCRIPTOR)).toMatchObject({
			status: "REFUSED",
			code: "OFFLINE_CACHE_MISS",
		});
		// Online policy fail-closed path: unknown peek still means MISS.
		const onlineHostile = createProviderJitBusinessAdapter({
			...hostilePort,
			isOffline: () => false,
		});
		const proposal = onlineHostile.proposeProviderAcquisition(DESCRIPTOR);
		expect(proposal).toMatchObject({
			status: "PROPOSAL_ONLY",
			cacheState: "MISS",
		});
		assertNoAuthorityShape(proposal);
	});
});
