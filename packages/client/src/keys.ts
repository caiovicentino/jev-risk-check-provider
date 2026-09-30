// x402check's attestation keys, pinned by the signing guard by default.

/**
 * RFC 7638 SHA-256 thumbprints (base64url) of the keys did:web:x402check.xyz signs attestations
 * with: the current key first, then any next key published ahead of a rotation. A rotation ships
 * the next key's thumbprint in a client release before the provider switches to it.
 */
export const X402CHECK_KEY_THUMBPRINTS: readonly string[] = ["J8BVKKyWmMP2WVzlxa4gi_1D0znFMZLcxs-BDlYeS8c"];
