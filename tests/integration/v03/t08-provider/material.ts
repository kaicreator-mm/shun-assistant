// T08 test material loader. Reads the controller-committed production
// fixtures (never modified by this task) and derives the trusted scope that
// exactly matches the signed descriptor. The artifact bytes are re-hashed on
// load so fixture drift fails loudly instead of silently passing.
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { TrustedProviderScope } from "../../../../packages/vertical-jit/src/curated-provider.ts";

const FIXTURE_DIR = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"fixtures",
);

export const DESCRIPTOR: Record<string, unknown> = Object.freeze(
	JSON.parse(
		readFileSync(
			join(FIXTURE_DIR, "provider-catalog-artifact.rg-14.1.1.canonical.json"),
			"utf8",
		),
	) as Record<string, unknown>,
) as Record<string, unknown>;

export const ROOT_PEM = readFileSync(
	join(FIXTURE_DIR, "curator-trust-root.prod.public.pem"),
	"utf8",
);
export const RG_BYTES: Buffer = readFileSync(
	join(FIXTURE_DIR, "artifacts", "rg.exe"),
);

export const ROOT_KEY_ID = DESCRIPTOR.signerKeyId as string;
export const ARTIFACT_SHA256 = DESCRIPTOR.artifactSha256 as string;
export const BINDING_ID = DESCRIPTOR.bindingId as string;

/** The attacker key used by every negative test (never trusted by the real root). */
export const ATTACKER = generateKeyPairSync("ed25519");
export const ATTACKER_PEM = ATTACKER.publicKey
	.export({ type: "spki", format: "pem" })
	.toString();

export function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

if (sha256Hex(RG_BYTES) !== ARTIFACT_SHA256) {
	throw new Error(
		"fixture drift: committed rg.exe bytes do not match the signed descriptor",
	);
}

/** Trusted scope derived 1:1 from the signed production descriptor fields. */
export const SCOPE: TrustedProviderScope = Object.freeze({
	providerId: DESCRIPTOR.providerId as string,
	capabilityId: DESCRIPTOR.capabilityId as string,
	version: DESCRIPTOR.version as string,
	catalogRevision: DESCRIPTOR.catalogRevision as string,
	bindingId: BINDING_ID,
	scopedVerifierId: DESCRIPTOR.scopedVerifierId as string,
	catalogManifestSha256: DESCRIPTOR.catalogManifestSha256 as string,
	bindingEvidenceSha256: DESCRIPTOR.bindingEvidenceSha256 as string,
	artifactSha256: ARTIFACT_SHA256,
	origin: DESCRIPTOR.origin as string,
	platform: "windows-x64",
	artifactKind: "CLI",
});

export function tamperedBytes(): Buffer {
	const copy = Buffer.from(RG_BYTES);
	const offset = 4096;
	copy[offset] = (copy[offset] ?? 0) ^ 0xff;
	return copy;
}
