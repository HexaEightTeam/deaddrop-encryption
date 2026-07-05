# Security Model

Threat model and trust boundaries for the HexaEight **client-side** 2-party message encryption in
this repository. This describes what the client code (`AliceBobDemo.vb`) provides and what it
relies on. It makes no claim of a specific quantum security level, no claim of formal proof, and
no claim of FIPS-140 module validation.

## Primitives

| Purpose | Primitive | Standard |
|--------|-----------|----------|
| Key derivation (extract-then-expand) | KMAC256 | SP 800-185 |
| `.EM1` keystream | SHAKE-256 (XOF) | FIPS 202 |
| `.EM1` integrity tag | KMAC256 | SP 800-185 |
| `pk0`, digests | SHA-512 | FIPS 180-4 |
| `.FM1` AEAD | AES-256-GCM | FIPS 197 / SP 800-38D |
| `.CM1` AEAD | ChaCha20-Poly1305 | RFC 8439 |
| `.SM1` AEAD (misuse-resistant) | AES-256-GCM-SIV | RFC 8452 |
| Nonce | CSPRNG (`RandomNumberGenerator`) | — |

Keys are derived by a **KMAC256 extract-then-expand** KDF (`PRK = KMAC256(salt, CS)`;
`key_c = KMAC256(PRK, label_c)`), with CS serialized canonically as unsigned big-endian. The
**key-agreement** (channel-secret pairing) is a custom construction built on these primitives, not
a NIST-standardized key establishment (SP 800-56A/B/C).

**Crypto-agility.** Ciphers are pluggable behind a domain-separated KDF label
(`key_c = KMAC256(PRK, label_c)`) and a wire marker, so primitives can be migrated without changing
the architecture. A new standardized AEAD slots in as an additional 2-party marker (AEADs are not
peelable), and the KDF/keystream primitives can be swapped for the 2-party and peelable multi-hop
paths alike. The channel-secret derivation and envelope are unaffected.

## Channel secret

Two parties derive the same secret CS without transmitting it:

```
pk0        = SHA512(Resource) * BigInteger(TokenSecret),  TokenSecret = SHAKE256(password)
pkpf/pkpd  = iterated SHAKE-256 over the password (asymmetric iteration counts)
CS(encrypt) = pk0*(pkpf^2 + pkpf*pkpd + tk0_new) + (pkpf2^2 + pkpf2*pkpd2 + tk1_new) + sky
CS(decrypt) = pk0*(pkpd^2 + pkpd*pkpf + tk0_rem) + (pkpd2^2 + pkpd2*pkpf2 + tk1_rem) + sky
              -> both forms evaluate to the same value
```

`TokenSecret`, `pkpf`, `pkpd` are derived locally from the password and are never transmitted.
`tk0_*/tk1_*/sky` are per-peer pairing fields obtained from the platform.

### Channel-secret space (why two channels effectively never share a CS)

In the reference deployment CS is an integer of at most **1269 bits** (its minimal-length
canonical encoding is at most 159 bytes). That bit-length *upper-bounds* the entropy of CS but
does not by itself establish it — the quantity that governs channel uniqueness is the min-entropy
**k** that the (out-of-scope) derivation actually endows on CS. Each (identity-pair, epoch)
channel derives its own CS. The figures below are therefore **conditional on the derivation
supplying pairwise-independent channel secrets of min-entropy k** — itself a property of the
derivation, since channels for overlapping identity pairs draw on related inputs.

- **Birthday bound:** conditioned on min-entropy k, two independent channels collide with
  probability at most 2⁻ᵏ, so a collision becomes even *possible* only on the order of 2^(k/2)
  channels.
- **Realistic worst case:** even 1 trillion identities (~2⁴⁰) give ~2⁷⁹ identity-pairs; times
  millions of ~15-minute epochs (~2²²) is ~2¹⁰¹ total channels ever created (N ≈ 2¹⁰¹). If the
  derivation supplies min-entropy at the transport's own 256-bit key scale, the collision
  probability is ≤ N²/2^(k+1) = 2^(2·101 − 257) = **2⁻⁵⁵** — negligible — and larger available
  width only widens the margin.

So distinct channels sharing a CS is not a realistic event **provided the derivation delivers
min-entropy comfortably above 2·log₂N**; a collision would otherwise reflect an implementation
bug in the pairing-material issuance rather than a natural event. Whether the derivation supplies
that entropy is out of scope here (see the accompanying preprint, Remark 2).

## Trust boundaries

| Entity | Trust | Rationale |
|--------|-------|-----------|
| User device | Trusted | Holds the password; derives keys locally |
| Network | Untrusted | Sees only ciphertext + nonce + tag + marker |
| Other identities | Untrusted | Cannot derive another identity's CS without its password material |
| Platform / key broker | Out of scope | Supplies per-peer pairing material; the broker internals are a proprietary boundary and are not covered by this document |

**Client-verifiable property.** CS depends on `TokenSecret`, which is derived on the device from
the password and never leaves it (trace `ChannelSecretBytes` ← `GenerateSenderKeys` ← the
password). It follows directly from this client that the transport **never transmits CS and does
not leak it through ciphertexts** to the network or other identities (up to the IND-CCA argument);
whether such a party can *compute* CS is governed by the out-of-scope derivation.

**Platform boundary — semi-trusted broker, not in the data path.** The platform operates as a
semi-trusted key broker: it is **not in the data path**. Message encryption and decryption happen entirely on the
client from the locally-derived channel secret; the encrypt/decrypt code paths make **no call to
the platform** and never hand it plaintext or the decryption operation — the platform is contacted
only at setup to obtain the per-peer key material, never during message exchange. This "not in the
data path" property is evident by reading the client (the encrypt/decrypt functions have no
platform round-trip). The enrollment / key-brokering internals are a proprietary boundary and
are out of scope here; this document describes only the client-side properties above.

## Message security

Per message, with a fresh CSPRNG nonce:

- **Confidentiality.** `.EM1` XORs a `SHAKE256(key_enc ‖ nonce)` keystream over the JSON envelope;
  `.FM1`/`.CM1` encrypt it under a standard AEAD. Per-cipher keys are domain-separated by label.
- **Integrity.** `.FM1`/`.CM1` use the AEAD tag. `.EM1` uses **Encrypt-then-MAC**: KMAC256
  over `nonce ‖ ciphertext`, keyed from CS, verified **constant-time before decryption**. The
  authenticated data is the whole ciphertext, so any modification is rejected before the
  plaintext is used. `.FM1`/`.CM1` are the recommended default; `.EM1` exists for the peelable
  multi-hop case.
- **Nonce.** Random per message (16 bytes for `.EM1`, 12 for the AEADs); security depends on
  non-reuse under a given CS. Callers should bound the number of messages per CS (or use a
  misuse-resistant AEAD such as AES-GCM-SIV) — see Areas for review.
- **Replay.** The envelope carries a timestamp but the demo does not enforce freshness; callers
  must add an anti-replay window appropriate to their transport.

## What breaking confidentiality requires

An attacker with the ciphertext must obtain CS, which requires the peer's client-held
`TokenSecret` / password material (never transmitted). There is no public-key exchange in the
message path, so there is no Shor-vulnerable key exchange to attack.

## Post-quantum posture

The message layer uses **only symmetric cryptography** — SHAKE-256 / KMAC-256, AES-256-GCM,
ChaCha20-Poly1305, AES-256-GCM-SIV — and contains **no RSA, Diffie-Hellman, or elliptic-curve
key exchange**. Consequences:

- **Shor's algorithm** (which breaks RSA/ECC/DH) has nothing to attack in the data path — there
  is no public-key exchange to factor or solve a discrete log against. Unlike TLS/PKI systems,
  there is no quantum-vulnerable key exchange to migrate.
- **Grover's algorithm** gives only a quadratic speedup on brute force, halving symmetric
  strength. At 256-bit primitives that leaves **~128-bit post-quantum security** — NIST's
  Category-5 bar for quantum-safe symmetric cryptography.

**Scope of the claim:** this is a statement about the *message layer*. The post-quantum property
comes from the absence of public-key exchange (not from any single hash function), and rests on
standard symmetric primitives rather than NIST PQC algorithms (ML-KEM / ML-DSA). We describe the
strength in structural terms — symmetric, Grover-only.

**Signatures** are a separate capability from the message MACs used here. Per-identity
post-quantum signatures (ML-DSA / SPHINCS+, name-resolved, no PKI) are being added.

**Caveat (entropy-bound).** Effective post-quantum strength is bounded by the entropy of the
identity secret fed into derivation. Machine identities use high-entropy machine-generated secrets
(full ~128-bit PQ); human identities rely on a password layered with mobile-identity material to
>=128 bits.

## Areas for review

The parts we most want a cryptographer to scrutinize (see `AI-REVIEW.md` §4):

- The KMAC256 extract-then-expand KDF (`PRK = KMAC256(salt, CS)`; `key_c = KMAC256(PRK, label_c)`)
  and the canonical unsigned big-endian CS encoding — is the extract step adequate if CS is only
  high-entropy rather than perfectly uniform?
- Random-nonce birthday bound and practical message-count limits under a fixed CS.
- The `.EM1` Encrypt-then-MAC composition (keystream + KMAC256 over `marker ‖ nonce ‖ ciphertext`)
  as a 2-party AE, and whether `.FM1`/`.CM1` should remain the recommended default.

## Explicit non-goals

- No specific quantum "security level in bits" is claimed.
- Not a NIST-standardized key-establishment scheme.
- Not FIPS-140 module-validated (a BC-FIPS build is available for regulated deployments).
- No formal (machine-checked or reduction) proof of the custom construction yet.
