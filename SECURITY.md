# Security Policy

## Hardened host integration

See [docs/hardening.md](docs/hardening.md) for resource limits, transactional
storage, host-supplied authorization, authenticated imports, and remaining trust
boundaries. Optional Ed25519 verification requires the `signing` installation
extra and an independently pinned public key. Never derive authorization or key
trust from imported record fields alone.

## Private keys

Do **not** commit private keys, seed phrases, recovery material, Keybase private-directory contents, hardware-token secrets, or decrypted keystore exports.

The identity record may contain:

- public signing keys;
- key fingerprints / KIDs;
- an external keystore provider name;
- an external keystore URI or opaque key handle when publication of that locator is acceptable.

A keystore URI is not proof of control of the corresponding private key. Cryptographic continuity should be marked verified only after a challenge/signature has been validated against the recorded public key.

## Public repositories

Before publishing, review the PDF and configuration examples for private path names, usernames, device names, account identifiers, or other metadata you do not want public.

## State signing

Recommended flow:

1. Use `IdentityRecord.canonical_bytes()` with the declared v1 encoding. It sets `integrity.state_hash`, `integrity.signature`, and `integrity.signed_at` to null before hashing to avoid self-reference.
2. Compute SHA-256 over the canonical UTF-8 JSON representation.
3. Sign the hash (or canonical representation) using the externally protected Ed25519 private key.
4. Store the public key, fingerprint, signature, signing time, and canonicalization/version metadata in the identity record.
5. Verify before accepting migrations, recoveries, or imported autobiographical state as cryptographically continuous.

The 0.2.0 verifier supports an explicit domain-separated `ed25519-v1:` signature
encoding over `signature_payload(record)`. Use that payload for new signatures;
the older generic recommendation to sign a hash or canonical bytes does not
identify a compatible signature format. `signed_at` is not authenticated by the
legacy canonical encoding. Keep private keys external.
