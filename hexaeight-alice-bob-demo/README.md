# HexaEight Client Cipher — Alice ↔ Bob Demo

A small, self-contained VB.NET reference for HexaEight's **client-side 2-party message
encryption**, published for independent cryptographic review. Two identities (Alice, Bob) derive
the **same channel secret** without transmitting it, then exchange messages under **four
interchangeable ciphers** over that secret. Per-cipher keys come from a **KMAC256
extract-then-expand** KDF over a canonical (unsigned big-endian) channel secret.

| Marker | Cipher | Notes |
|--------|--------|-------|
| `.FM1` | AES-256-GCM (FIPS 197 / SP 800-38D) | standard AEAD, 2-party (default) |
| `.CM1` | ChaCha20-Poly1305 (RFC 8439) | standard AEAD, 2-party |
| `.SM1` | AES-256-GCM-SIV (RFC 8452) | nonce-misuse-resistant AEAD, 2-party |
| `.EM1` | SHAKE-256 keystream + Encrypt-then-MAC (KMAC256) | keystream design; layerable for multi-hop |

## What's here

- **`AliceBobDemo.vb`** — the entire implementation: channel-secret derivation, the four
  ciphers, the JSON envelope, integrity tag, and nonce handling. The file header documents the
  construction, trust model, and scope.
- **`AI-REVIEW.md`** — the review request: what we claim, the construction stated plainly, the
  questions we want a cryptographer to answer, and a findings-first response format.
- **`LOGINTOKEN-SAMPLE-FOR-REVIEW.md`** — a live identity credential published on purpose so the
  authentication/trust model can be inspected against real material.
- **`SECURITY-MODEL.md`** — threat model, trust boundaries, and what breaking the scheme requires.
- **`AliceBobDemo.vbproj`** — .NET 8.0 project (BouncyCastle.Cryptography 2.4.0, Newtonsoft.Json).

## Build & run

Requires the .NET 8.0 SDK.

```bash
dotnet restore
dotnet build -c Release
dotnet run  -c Release
```

The program runs each cipher end-to-end and prints a round-trip plus a tamper-rejection check:

```
--- FM1 (AES-256-GCM, FIPS) ---                  [PASS] round-trip  [PASS] tamper rejected
--- CM1 (ChaCha20-Poly1305) ---                  [PASS] round-trip  [PASS] tamper rejected
--- SM1 (AES-256-GCM-SIV, misuse-resistant) ---  [PASS] round-trip  [PASS] tamper rejected
--- EM1 (SHAKE-256 keystream + Encrypt-then-MAC) [PASS] round-trip  [PASS] tamper rejected
```

For each cipher the demo encrypts a message from Alice to Bob over the shared channel secret,
decrypts it back, and then flips a ciphertext byte to confirm decryption rejects tampering.

Deterministic **test vectors** for cross-language reproducibility are in `TEST-VECTORS.md`; they
are regenerated with `dotnet run -- vectors` (pass `vectors` after `--` exactly — extra `dotnet`
flags before `--` are not forwarded and will run the demo instead).

## Dead Drop Encryption

The Alice → Bob exchange above is a **dead drop**: Alice encrypts using only Bob's identity and
the shared channel secret — **no interactive handshake, and Bob does not need to be online**. The
ciphertext can sit anywhere (queue, file, object store, USB) until Bob later decrypts it. There
are no certificates, no public keys to exchange, and no session negotiation.

In production this extends further: because a sender only needs a destination's **identity name**
(the platform brokers the per-peer pairing material), a client can encrypt to a destination that
is offline, spawned later, or not yet provisioned — the message waits to be picked up. This
standalone demo shows the offline, handshake-free part; the platform provides the name-based key
brokering for destinations that do not exist yet.

Learn more or try it on your own identities at **[www.hexaeight.com](https://www.hexaeight.com)**.

## Scope (read before reviewing)

Evaluate this as a **symmetric channel-secret transport** with standard AEAD options. The
cryptographic primitives are FIPS-approved (SHAKE-256, AES-256-GCM, SHA-512) or standardized
(ChaCha20-Poly1305, RFC 8439). The key-agreement — how two parties arrive at the same channel
secret — is a **custom construction**; it is not a NIST-standardized key-establishment scheme,
and this is not a FIPS-140 validated module. There is no public-key exchange in the message path.

Start with **`AI-REVIEW.md`**. The platform is a **semi-trusted broker — it is not in the data
path**: message encryption/decryption happen entirely on the client from the locally-derived
channel secret, and the encrypt/decrypt code makes no call to the platform (it is contacted only
at setup to obtain key material). This is evident by reading the client. CS also depends on
client-held material (`TokenSecret`) that never leaves the device, so the transport never
transmits CS and does not leak it through ciphertexts (up to the IND-CCA argument); whether the
network or another identity can *compute* CS is governed by the out-of-scope derivation, not the
transport. The platform's enrollment internals are a proprietary boundary and are out of scope
here.

## Note

In this standalone demo the passwords and per-peer shared keys are hardcoded constants so it
runs offline. In production they come from the enrollment + LoginToken + key-fetch flow described
in the `AliceBobDemo.vb` header.
