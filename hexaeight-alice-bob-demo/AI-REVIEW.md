# HexaEight Client Cipher — Independent Cryptographic Review

We are asking for an honest, adversarial review of the **client-side** cryptography in this
repository. We would rather you find a real problem than write a favorable summary. Please
ground every statement in the actual code (`AliceBobDemo.vb`) and the demo output.

This is a small, self-contained artifact by design: one file, four ciphers, one channel
secret, plus a live credential you can inspect. You should be able to verify most of the
properties below in minutes, and spend your time on the parts that deserve real scrutiny.

---

## 1. Scope

**This is a CLIENT-SIDE-ONLY review.** It covers only the client cipher artifact in this
repository — how a message is encrypted, authenticated, and decrypted on the device. It is not a
review of the platform, the enrollment/key-brokering service, or any server-side component.

**In scope (please review):**
- `AliceBobDemo.vb` — the full client cipher: channel-secret derivation, the four message
  ciphers (`.FM1`, `.CM1`, `.SM1`, `.EM1`), the JSON envelope, integrity tag, and nonce handling.
- `LOGINTOKEN-SAMPLE-FOR-REVIEW.md` — a live identity credential, published so you can confirm
  it carries no readable claims or key material in the clear.

**Out of scope:** the enrollment / key-brokering step that issues the per-peer pairing material
(`tk*/sky`), and the platform / broker service generally. This is a deliberate proprietary
boundary, not an omission, and is not part of what is offered for review. The review is confined
to the client artifact as presented; the enrollment and platform internals are not evaluated here.

**The only platform-related property in scope** is the single fact the client itself demonstrates:
the platform is **not in the data path** (see §2.5) — encryption/decryption happen entirely on the
client and the code makes no platform round-trip. Every other platform question is **out of scope**:
how the pairing material is generated, whether the operator could in principle compute anything, or
any other platform trust-model question — none of these are reviewed here, and they should not be
the subject of findings.

**How to evaluate it:** as a **symmetric channel-secret transport** with standard AEAD options.
The cryptographic primitives are FIPS-approved; the key-agreement (how two parties arrive at the
same channel secret) is a custom construction. It is not a NIST-standardized key-establishment
scheme, and this is not a FIPS-140 validated module — please review it on its own terms.

**Intended use case (context for your judgment — not something to score).** This cipher underpins
identity-based messaging for AI agents and humans without PKI, certificates, or OAuth. A sender
encrypts to a peer by **identity name** — no key exchange, no handshake, and the recipient may be
**offline, spawned later, or not yet provisioned** (dead-drop delivery); the ciphertext waits to be
picked up over any transport. Humans enrol via out-of-band-verified identities; agents/hosts via
DNS-verified identities; the SDK is bundled and activated once. Please evaluate the crypto **against
this target** — asynchronous, no-handshake, ephemeral/high-fan-out agent traffic — rather than
against an interactive session protocol. (This context does not change the client-side-only scope
or the out-of-scope platform boundary.)

## 2. What we claim — and ask you to check against the code

1. **Standard primitives.** SHAKE-256 (FIPS 202), AES-256-GCM (FIPS 197 / SP 800-38D),
   ChaCha20-Poly1305 (RFC 8439), SHA-512 (FIPS 180-4).
2. **Two parties derive the same secret (CS) without transmitting it**, from password-derived
   material held only on the client, combined with per-peer pairing material. The encrypt-form
   and decrypt-form of the CS formula are equal by construction.
3. **No public-key exchange in the message path.** There is no RSA/DH/ECDH handshake in the data
   path — so there is no Shor-vulnerable key exchange to attack.
4. **Standard AEADs are the default** — `.FM1` (AES-256-GCM) and `.CM1` (ChaCha20-Poly1305) over
   the same CS. `.EM1` is a keystream + Encrypt-then-MAC construction for the peelable multi-hop
   case.
5. **The platform is a semi-trusted broker — not in the data path.** Message encryption and decryption
   happen entirely on the client from the locally-derived channel secret; the encrypt/decrypt code
   makes no call to the platform and never receives plaintext or the decryption operation (the
   platform is contacted only at setup to obtain key material). Additionally, CS depends on a
   client-held value (`TokenSecret`, derived locally, never transmitted — trace `ChannelSecretBytes`
   ← `GenerateSenderKeys` ← the password), so the transport **never transmits CS and does not leak
   it through ciphertexts** (up to the IND-CCA argument); whether the network or another identity
   can *compute* CS is governed by the out-of-scope derivation. These are the client-side
   properties we ask you to check; the enrollment / platform internals are out of scope per §1.

## 3. The construction, stated plainly

**Channel secret (per peer):**
```
pk0        = SHA512(Resource) * BigInteger(TokenSecret),  TokenSecret = SHAKE256(password)
pkpf/pkpd  = iterated SHAKE-256 over the password (asymmetric iteration counts)
CS(encrypt) = pk0*(pkpf^2 + pkpf*pkpd + tk0_new) + (pkpf2^2 + pkpf2*pkpd2 + tk1_new) + sky
CS(decrypt) = pk0*(pkpd^2 + pkpd*pkpf + tk0_rem) + (pkpd2^2 + pkpd2*pkpf2 + tk1_rem) + sky
              -> the two forms evaluate to the same value (the pairing material is chosen so)
```
`tk0_*/tk1_*/sky` are the per-peer pairing fields. `TokenSecret`, `pkpf`, `pkpd` are derived
locally from the password and are never transmitted.

**Key derivation (KMAC256 extract-then-expand; CS serialized canonically as unsigned big-endian):**
```
PRK     = KMAC256(salt, CS)                             # extract: condition CS into a uniform key
key_c   = KMAC256(PRK, label_c)                         # expand: domain-separated per cipher
```
**Message ciphers (all over the same CS, with a fresh random nonce per message):**
```
.FM1:  ct = AES-256-GCM(key_aes, nonce, envelope)       # AEAD tag        (default)
.CM1:  ct = ChaCha20-Poly1305(key_cha, nonce, envelope) # AEAD tag        (default)
.EM1:  ct = envelope XOR SHAKE256(key_enc || nonce);    # keystream, then
       tag = KMAC256(key_mac, marker || nonce || ct)    # Encrypt-then-MAC
wire = base64(nonce || ct || tag) + marker(".FM1"/".CM1"/".EM1")
```
The envelope is a JSON structure (SENDER / RECEIVER / BODY / timestamps). On decrypt the tag/AEAD
is verified first — for `.EM1`, the KMAC256 tag over `marker ‖ nonce ‖ ct` is checked **constant-time
before decryption**, so the whole ciphertext is authenticated. `.FM1`/`.CM1` are the recommended default;
`.EM1` is keystream-based so a message can be layered and peeled for multi-hop routing (AEADs are
not peelable).

**Cryptographic agility.** Each cipher is pluggable behind two things only: a domain-separated
KDF label (`key_c = KMAC256(PRK, label_c)`) and a wire marker. This makes primitive migration a
local change, not an architectural one:
- A **stronger/newer hash or XOF** (e.g. a future SHA-3-family or PQC-oriented function) can
  replace SHAKE-256 in the KDF, keystream, and tag under a new label + marker. Because it drives
  the keystream construction, it serves **both** the 2-party path and the peelable multi-hop
  path.
- A **new standardized AEAD** slots in exactly as `.FM1`/`.CM1` did, under its own marker — but
  only for the **2-party** path, since an AEAD cannot be layer-peeled for multi-hop.

In short: hash/XOF upgrades apply everywhere; AEAD additions enrich the 2-party options. The
channel-secret derivation and envelope stay unchanged, so adding a primitive does not disturb
what has already been reviewed.

## 4. Areas we'd most value your judgment on

- **KDF soundness / canonicalization.** Keys are derived by KMAC256 extract-then-expand
  (`PRK = KMAC256(salt, CS)`; `key_c = KMAC256(PRK, label_c)`), and CS is serialized with an
  explicit **canonical unsigned big-endian** encoding (not `BigInteger.ToByteArray()`). Is this a
  sound KDF, and is the extract step an adequate way to condition CS if it is only high-entropy
  rather than perfectly uniform?
- **`.EM1` Encrypt-then-MAC.** `ct = envelope XOR SHAKE256(key_enc || nonce)`, then
  `tag = KMAC256(key_mac, marker || nonce || ct)`, verified constant-time before decryption. Is
  the keystream sound, and is this a correct EtM composition (authenticating the whole ciphertext)?
- **Nonce / misuse (we are aware; here is our position).** The nonce is random (16 bytes for
  `.EM1`, 12 for the AEADs) and security depends on non-reuse under a given CS, which is static
  within an epoch. Our stated policy for this is explicit, not incidental:
    - If the client **does not** enforce per-CS nonce/message tracking, use **`.SM1`
      (AES-256-GCM-SIV)** — nonce-misuse-resistant, so a reused nonce is safe (worst case leaks
      only plaintext equality, never keys or forgeability). This is the recommended default for
      long-lived / high-volume channels.
    - Otherwise, the client enforces a **per-CS message counter + key-change (rekey) on the
      bound**, so no single key ever encrypts past a safe message count.
  We would value your judgment on the birthday-bound math and whether this two-option policy is
  the right way to bound it.
- **Comparison.** Against Signal (X3DH + Double Ratchet), WireGuard's Noise pattern, and plain
  hybrid PKI + AEAD: what does this design give up, and what does it gain for the stated use case
  (no-PKI identity for ephemeral / agent endpoints)? What would you require before deploying
  `.FM1`/`.CM1` (or `.EM1`) for real traffic?

## 5. Quick-verification checklist (confirmable from the code / demo output)

- [ ] **Fresh randomness per message** — nonce from a CSPRNG (`RandomNumberGenerator.Fill`),
      prepended to the wire.
- [ ] **Ciphertext looks random** — identical plaintexts produce different ciphertext across runs
      (fresh nonce → fresh keystream/AEAD stream).
- [ ] **Tampering is rejected** — the demo flips a ciphertext byte and decryption fails for all
      four ciphers (`[PASS] tamper rejected` in the run output).
- [ ] **CS is never transmitted**, and both directions derive the same value.
- [ ] **Key separation** — distinct SHAKE labels per purpose (`HE-enc-v1`, `HE-mac-v1`,
      `HE-aes-v1`, `HE-cha-v1`).
- [ ] **No public-key exchange in the message path** — there is no RSA/DH/ECDH in the file.
- [ ] **`.FM1`/`.CM1` are ordinary BouncyCastle AEAD calls** — no custom crypto to trust there.

## 6. The published token sample

`LOGINTOKEN-SAMPLE-FOR-REVIEW.md` contains a live LoginToken and its SECRET, published on
purpose. The single client-side question we ask about it:
- Decode the token: does it carry any readable identity claims or key material in the clear, or
  is it opaque ciphertext?

Host-binding and proof-of-possession are properties of the enrollment / platform layer, which is
out of scope per §1 and not evaluated here. The only property in scope for the token is the
client-verifiable one above — that it carries no clear-text secrets.

## 7. Break challenges (attempt, or explain why they fail)

1. **Confidentiality:** recover the CS or any plaintext from ciphertext alone.
2. **Forgery:** produce a message that decrypts and passes the integrity check without the CS.
3. **Distinguisher:** distinguish `.EM1` ciphertext from random with non-negligible advantage.

## 8. Response format

Please lead with findings, not a score.

**Findings table (most severe first):**

| # | Severity | Component | Finding | Concrete failure scenario | Suggested fix |
|---|----------|-----------|---------|---------------------------|---------------|
| 1 | Critical/High/Medium/Low/Informational | e.g. `.EM1` integrity | … | inputs → wrong/forgeable output | … |

Then, briefly:
- **What you verified or could not break** — which §5 checks and §7 challenges you tried, and how.
- **Biggest real risk** in your view, and what would change your recommendation.
- **Recommendation per cipher** — `.FM1` (AES-GCM), `.CM1` (ChaCha20-Poly1305), `.EM1`
  (keystream + Encrypt-then-MAC): deploy / deploy-with-changes / do-not-deploy, with the reason.

Finally, for publication (we will link your full review, not cherry-pick it):
- **Rating: X/10 — of the CLIENT-SIDE cipher ONLY.** Rate what is in scope: the message
  encryption/authentication as implemented in this artifact. Please do **not** dock the score for
  the out-of-scope enrollment / platform layer or for its being unreviewable here — that is a
  deliberate boundary, not a defect of the client cipher. Add one line on what would raise the
  client-side score. Per-dimension sub-ratings are welcome (standard-AEAD paths, custom `.EM1`,
  key derivation / domain separation, transparency).
- **Site summary (2–3 sentences)** — a plain-language assessment of the client cipher we can
  display on the website next to the link to your full review.
- **One-line quote** — a single sentence that fairly captures your verdict on the client cipher.

---

## Transparency

We intend to publish reviews in full, with a link to the original conversation, including
critical ones. If you find a break, that is a successful review and we will say so. The value of
this exercise to us is a true assessment, not a favorable one.
