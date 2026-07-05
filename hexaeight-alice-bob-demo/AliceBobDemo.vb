Imports System
Imports System.Numerics
Imports System.Linq
Imports System.Text
Imports System.Security.Cryptography
Imports System.IO
Imports System.Threading.Tasks
Imports System.Diagnostics
Imports Microsoft.VisualBasic
Imports Newtonsoft.Json
Imports Org.BouncyCastle.Crypto.Digests

'************************************************************************************************
' HexaEight - 2-party message encryption (standalone reference for security review)
'************************************************************************************************
'
' WHAT THIS IS
'   A self-contained demo of HexaEight's CLIENT-SIDE 2-party message encryption between two
'   identities (Alice, Bob). It shows FOUR interchangeable ciphers over the SAME channel
'   secret, so a reviewer can compare the custom construction against standard AEADs:
'
'     .FM1  AES-256-GCM                              (FIPS 197 / SP 800-38D)   [default]
'     .CM1  ChaCha20-Poly1305                        (RFC 8439)
'     .SM1  AES-256-GCM-SIV                          (RFC 8452, nonce-misuse-resistant)
'     .EM1  SHAKE-256 keystream + Encrypt-then-MAC   (custom; peelable -> multi-hop capable)
'
' THE CHANNEL SECRET (CS)
'   Both parties independently derive the SAME secret CS without ever transmitting it. CS mixes:
'     - password-derived material (client-only, never leaves the device):
'         pkpf/pkpd = iterated SHAKE-256 of the party's password;
'         pk0 = SHA512(Resource) * BigInteger(TokenSecret), TokenSecret = SHAKE-256(password)
'     - platform-brokered pairing material carried in the shared key
'         (tk0_new/tk0_rem/tk1_new/tk1_rem/sky)
'   ChannelSecretBytes() computes CS: the encrypt-form (pkpf/tk*_new) and the decrypt-form
'   (pkpd/tk*_rem) yield the IDENTICAL value by construction. The platform brokers the pairing
'   but cannot compute CS itself (it lacks the client-only TokenSecret) - a property verifiable
'   directly from this client code.
'
' PER-MESSAGE FLOW
'   1. Derive CS from (this party's password) + (the peer's shared key); serialize it canonically
'      (unsigned big-endian magnitude — portable across languages).
'   2. Derive per-cipher keys with a KMAC256 extract-then-expand KDF:
'        PRK   = KMAC256(salt, CS)        (extract: condition CS into a uniform key)
'        key_c = KMAC256(PRK, label_c)    (expand: independent per-cipher key)
'   3. Wrap the message in a JSON envelope (SENDER/RECEIVER/BODY/timestamps + a tag field).
'   4. Encrypt under a FRESH random nonce:
'        FM1/CM1 -> a standard AEAD; integrity via the built-in AEAD tag. (Recommended default.)
'        EM1     -> XOR a SHAKE-256(key_enc||nonce) keystream, then MAC marker||nonce||ciphertext
'                   (Encrypt-then-MAC, KMAC256 keyed from a CS-derived key). Built for peelable multi-hop.
'   5. Wire = Base64(nonce || ciphertext || tag) + marker (".FM1" / ".CM1" / ".EM1").
'   On decrypt the tag/AEAD is verified FIRST (EM1: constant-time) and any tampered message is
'   rejected before the plaintext is used.
'
' PRIMITIVES & SCOPE
'   - Primitives are FIPS-approved: SHAKE-256 (FIPS 202), AES-256-GCM (FIPS 197 / SP 800-38D),
'     SHA-512 (FIPS 180-4). ChaCha20-Poly1305 is RFC 8439. EM1 authenticates with
'     Encrypt-then-MAC (KMAC256 over nonce||ciphertext, keyed from CS).
'   - The KEY-AGREEMENT (the CS pairing) is a CUSTOM construction, NOT a NIST-standardized
'     scheme, and this is NOT a FIPS-140 validated module. No quantum "security-level" numbers
'     are claimed: the relevant property is that the DATA PATH contains no Shor-vulnerable
'     public-key exchange (there is no RSA/ECDH handshake to break).
'   - The algorithm is public (Kerckhoffs). Security rests on the secret password, not on
'     keeping the code secret.
'   - Keccak/sponge primitives are used throughout: a KMAC256 extract-then-expand KDF derives the
'     per-cipher keys from CS, and SHAKE256(key_enc||nonce) is the .EM1 keystream. KMAC is a keyed
'     MAC/KDF (SP 800-185) and SHAKE is not length-extension-vulnerable, so these keyed
'     constructions are safe.
'
' POST-QUANTUM POSTURE
'   The message layer is ALL symmetric (SHAKE-256/KMAC-256, AES-256-GCM, ChaCha20-Poly1305,
'   AES-256-GCM-SIV) with NO RSA/DH/ECDH key exchange. So Shor's algorithm has nothing in the
'   data path to break (unlike TLS/PKI, there is no quantum-vulnerable key exchange to migrate);
'   the only quantum threat is Grover, which merely halves symmetric strength - ~128-bit
'   post-quantum at 256-bit keys. Effective strength is bounded by the identity secret's entropy.
'   Post-quantum SIGNATURES (ML-DSA / SPHINCS+, name-resolved, no PKI) are being added - a
'   separate capability from the symmetric message MACs here.
'
' SECURITY PROPERTIES & LIMITS
'   - Secret entropy: the value fed into key derivation is >=128-bit. Machine identities use
'     machine-generated secrets; a human-chosen password is layered with mobile-identity
'     material to reach >=128 bits before derivation. The SHAKE iteration is domain stretching,
'     NOT a memory-hard password hash - it relies on that >=128-bit input assumption.
'   - Forward secrecy: CS is static within a key-generation epoch, but the platform rotates the
'     pairing material every ~15 minutes (per KGT epoch), so CS rotates per epoch. A previous
'     KGT can only be fetched for up to ~1 hour; after that the old-epoch pairing material is
'     unrecoverable, so traffic older than that window cannot be re-derived even by the parties.
'     A CS compromise therefore exposes only the current epoch's traffic on that channel, not all
'     past/future traffic. This is a bounded exposure window (coarse forward secrecy), NOT a
'     per-message ratchet (no post-compromise security within an epoch).
'   - Nonce budget: keys are fixed per CS, nonces are random (12 B AEAD / 16 B EM1). Keep well
'     under the birthday bound per CS (<= ~2^32 messages); epoch rotation already caps this in
'     practice. AES-GCM-SIV is the misuse-resistant option if a channel is very high-volume.
'
' MULTI-HOP / MULTI-PARTY (".EM1" is the N=1 case of this; full onion is in the platform library)
'   A message can traverse an ordered chain of identities h1 -> h2 -> ... -> hN so that no relay
'   can read or alter it - only the designated recipient recovers it. The sender:
'     - derives one channel secret per hop (CS_h1 ... CS_hN),
'     - XORs one keystream layer per hop over the plaintext P (an onion):
'         C = P XOR KS(CS_h1) XOR KS(CS_h2) XOR ... XOR KS(CS_hN),   KS(x) = SHAKE256(kEnc(x)||nonce)
'     - appends ONE open tag = KMAC256(CS_hN, nonce || SHAKE256(P)) keyed by the LAST hop.
'   Each intermediate hop "peels" exactly its own layer with its own CS (in-transit marker
'   ".EMM"); the nonce and tag ride through untouched. After the final peel (marker ".EM1") the
'   recipient recovers P and verifies the tag. Because every layer needs that hop's CS - which
'   needs that hop's client-held secret - no relay can decrypt or tamper. If the actual reader is
'   not the designated last hop, it peels to get P and asks the last hop to recompute the tag
'   (delegated peer-to-peer verification). This 2-party demo is the same construction with N=1.
'
' SIGNING (FORTHCOMING - per-identity post-quantum signatures, no PKI)
'   Each identity holds ONE PQ signing keypair (e.g. ML-DSA or SPHINCS+, SHAKE variant). The
'   PRIVATE seed is client-generated and stored as public-safe ciphertext Enc(seed, K), where K
'   is an epoch-stable CS-derived key the platform cannot recover - so any device of the identity
'   reconstructs the same signing key (password-change / multi-device safe). The PUBLIC key is
'   published to a name registry and resolves from the IDENTITY NAME (no certificates, no CA
'   chain, no key passing): a verifier looks up "agent-name" -> public key and checks the
'   signature OFFLINE. This gives attributable, offline "who signed this" for agent
'   requests/responses/audit entries. Unlike a symmetric tag, a signature is verifiable by anyone
'   without giving them the ability to forge - which a shared-secret MAC cannot provide.
'
' REGISTRATION & TRUST MODEL (where the password and the shared keys come from)
'   - IDENTITY is established OUT OF BAND, not via a simple web form. HexaEight verifies the
'     authenticity of a user's email through multiple out-of-band techniques, and agents/hosts
'     prove their identity via DNS records. This out-of-band verification is what prevents
'     identity spoofing at enrollment.
'   - During enrollment the identity's key material is established and the platform issues a
'     LoginToken. The platform keeps only one-way properties needed to pair identities - not
'     the password, and not the password-derived keys used to compute CS.
'   - The LoginToken is NOT a bearer credential, and presenting it alone is NOT sufficient (a
'     stolen token is useless on its own). Every authenticated request also requires PROOF OF
'     POSSESSION: the client must encrypt the request with its password-derived keys, which the
'     platform verifies. Those keys stay on the device and are re-derived locally each session,
'     so a token cannot be replayed without them. Only after this proof does the platform
'     broker the per-peer SHARED KEYS (the tk*/sky fields below).
'   - BLIND BROKER - THE PLATFORM IS NOT IN THE DATA PATH. This is the core property, and it is
'     evident by reading the client: message encryption and decryption happen entirely on the
'     client from the locally-derived channel secret; the encrypt/decrypt functions make NO call
'     to the platform and never hand it plaintext or the decryption operation. The platform is
'     contacted only at setup to obtain the per-peer key material, never during message exchange.
'   - What THIS client also proves on its own: CS requires the on-device TokenSecret (derived from
'     the password, never transmitted), so the NETWORK and OTHER IDENTITIES cannot compute CS or
'     read content. The enrollment / key-brokering internals are a proprietary boundary and are out
'     of scope for this artifact; only the client-side properties above are in scope here.
'   - In this standalone demo the password and shared keys are HARDCODED constants so it runs
'     offline; in production they come from the out-of-band-verified enrollment + LoginToken +
'     proof-of-possession + key-fetch flow.
'   - A REAL, live LoginToken + SECRET for one identity is published for scrutiny in
'     LOGINTOKEN-SAMPLE-FOR-REVIEW.md - deliberately, to let reviewers test the host-binding /
'     proof-of-possession claims against actual credentials.
'************************************************************************************************

Module HexaEight6KeyStandalone

    ' Alice's credentials
    Private aliceResource As String = "alice-user-agent.tryhexaeight.com"
    Private alicePassword As String = "Zh-KyfbXqP-jbYxMIzKZAh9k2WgpUBWyQz2kaxwoU"

    ' Bob's credentials
    Private bobResource As String = "bob-user-agent.tryhexaeight.com"
    Private bobPassword As String = "1JdldryK9YQzyBNDnf!37JCYTpb.DohLvZw17SoRNX0ALOuXF7#Wn"

    ' Shared keys (8-field format from alice-bob-communication140-v3.csx with SHAKE-256)
    Private bobSharedKey As String = "DGVsbDA=:DGVsbDA=:i5r56OSZLCK0x3hKjf1Ojf0NiPQOSqnBADL9X9Tia4MPIDE7jLi3bxxK4nfX3DDk8koYniGX4VtsLB4s/QvEPcX/8KYkXj2bWZp+wDgJk+cW/nnucj/FwqrOMm8Xcg3V+nSook/CtoWE/nMFMrA2hyziM4Akl+u86J4eT7K0PkEIxffbsrr61EYzR/oFS//k0LxEWj38u0BaUvi2Vkon4zNHad/jQCs+uCxlQd4G3m9pceIifTALtQIETgXp/u2Qc38JcEYd+CuZPb4A/d6679RrQ3ZaEEotPWTWmaMcYMHkRUJsoao4GhUmheVNHPULsiDKKHA1lMnGzv5TmnzUz5JOWUhjrZMbweG7+Eap9vztVpgYw7qvZkXJEBKZRUm7yHv2nj2CiaLhKlE1xRpsde5U2qrwWgpDEHQ6ymG18UZcqh2ZoVEv6nUyA5AcmLxx1F9qIJayTDQzziLd4C13yQ3WQVfYrm+wdH6/9oj8LAg5sBvkffWv+Gqppz8m5KfJK80md+BQg6XoNvAnEG1wyLIXfRn7F+RkhFz/z8JIphzvG5RPCcDkeWNIxFyKgAID6xRKvcBMtfC/chtU1IgYzfemQ83lgQ1jL2ih3/gXVzDaK1tfNvxA6VothBTA/8Y=:8mzpPXnLWDiu4fGjSgOOhgWFSIhphh7UcGYag7Juesdi5S2a1NAZfcJq9ADv6ixOxOE/2UooFTtkT0B9zHAxUP95J9qJKgS5YmH0CdPnOTOIBWD8cUSToHMhpPSnTHoPF0x9yDHz6YjgyId2NGxbwaF01216Gz0nDEwcfAM4IosAYIhiPAHdSWnXF/L3w6kELc/l/B5zMWIhXPpe8oDMcoZkuStq27JGsbylDouENv8tDDhzoLJ/E2QMpu02i0dqXubPlx5brOfBqA8Rfpjjmu97Dc1FMSUnAYQHi/kq9j3dwPFUhJTaZDBWxggaSLVlZGEYOIgSyKtYlfdMlo4wIFR4gbh1W4EPjtXUYGB8DERxwAyxxjfgDoFG6t9Uy9mjKh1DAr1q9yolnJY4IcKSSDs04xqDrse/gqbKHzr9gFdIVfGQ8ypS1ALL1tBLud2+EoAaXBrfB1Y/nJRAprxeGINfhaDU1p4KvPS94pykAvwjwzaSAINkg5BzYcVE3RgNI3ifuGf2xBeBoIZeppvR9X3bKsivYzXu5yzL8kPoVuVXZrKUKTzb/Na0nPkmXDMHJfFpfxjpLw7Tp/1zY4aANhovHGutLEFF3D1cUP98Xqzx6PbNZibO8Q1ySpY/7i6GGsUWZPQEllfvM8TJd3579BASIqa6FWWOdMT4JUOCwQM=:x9ASKlhgjeznZKBpdJUHG5WAh4ms5e2E15hkK0Mxv2L8EtCbWoCIUm1NGCZb5JB2ti1b81sWhVY4vIX4mt3WS2wQWTBEcw8QYBYDt+uz60pqSGXMipUN8RKy6awkg0g6NDIbjqI8eZld0mKCXM+84BYKlkEFcY2XH4730BlkSfcOMjyOSmNdANjpcMjr3Tdfb958LWfWFGVg4OtdzbEJpFfOQPsyZhMPBEKCvjBaAl9zO/XXStkf2nzGS0IiFDSeMhAroGjWSW5UsohpicPprSbUWKh3AmyggcEaTduc4is1hFibto2FXtV5Xukh+s7gcmtfPi+afs95NP/e4aL/F9EliNsrVpDb7xsK+L/PIlUmM0EG6kXShV7CMxAmdhBdksDGpmGs4K6GaeHhQQbXPTE1TkyZTcG/KSgSqr6DOSspy9ZxIekG3SS6cDCnlmHxfNLjQ31klKUi2A7CX9ysHXhzz77eT3ZpjDgNgLT2YB5nO+Zrq8X6xOJ5tYpFusm4gra3b2dJ39fLxc+IIzgxzQxoaB0iTNbgvzO75+XfXwFF905fE7aDxinLquy0EdNHDak/b0uDfvn0rE2aKug90a9CAr2huYrOlMcs/3hu9BeYhO0awV0A1lDcBMnhnucR3qoc4KNGL5npwKJq9V5QdBk4ectBNDZnjzTQHcecSfs=:0HCLnY+RJ3rtsW/LP3x0b6mCSPkbNCvSqT8CnLQ9/FC75kA+0r/MQs7QeJ+asOaqOwX22IIeyKayuvfeFlwdl5nbKNoSizxAvBKEcuEJexjss/A5ISQP37a2MO7EnQNeXo/YPxgVJUdxJ2lW1QiqPd190YHzyv6/fkz+FRQuBry4q3VteQPB3seYwAxifcjoMHagpKW4uRkG+jvlBKbSagl3nRzG4BCK3jYdBB9ZV5//T2d3fsR2JHMHSsPse0v5PXPq3M/Yp8K3BFBtrR7ZqFpVlYbWBXmhg84ts/ncA6nw3QNZyRd92bqQVRpCYsoos2eAg4gv+J2eXtK6Lcm+yfU/Aey4RsxiROY2a3I2BkAE8tp/VYnHNzIR7lj+2VUzAM8XZU2nUu07Wna1giMTan5qZ4OaDR+jSZKK/EwOnQYt0Ju9bpF3RLPizOqWodaAD7FNAVTFXQkaOO7baudBCD1BZAuXm/zLqypNgEKS44lbwj9XXbCSRM9boRdAC/O8NEQpyaNwDF462+DJEISWlTVYTYbLxwljhg7Q/otSxdkUaGpqooEEKMKEQfRVcRsBvfOpzeXK/yo91dpHhHT2i9SDUiFfzxPYtESDDiJKX8N/ukzatKTKP6a0D0/W6S3whTcjymCPlRpZyV/d7bp3ZFad+vPG2W8zlSenj8e0n/o=:wIZlndx9EZIx8T9a+6xJIgaeRBDnWjh5X19yjGCgSwoHi6wT6DWnYjUDE2ndj3AbVbtdnScUKwlLBkCLuHWzAE+ep3BJNlEHNnSzemGMVl6YYSADKA1tWHPvb3oe+OtEFdwbRkMep0P+Fy/iEwpuBwPMZVMgq+/hBJilmJcYj7Q6aLkQJ3BlFSWHUh978jRxeBoFXp1AjifhVhLLBjQJyTumkn9OMytL0SkReqpcEPws5MNQ7Cn5wHjB6++Cb1GilDDcblAYHM0rh71KPJ1hlfgn1Z+YiY3kjuYhtFWk0MVTYGXerQNwhICiYGfgV78q/5TgmPHE0NI01rFDI7lIr2jneb9DGIbsIQtY5Z3o8sE4yD7KlcLKrP1pHjV8XZDRBQ+x6jy5HnlRp3qtBV3P9RTKRB0mzHiaY/TSkRdjeGZbM7U2e+RN6Bl7HWJWBx0U1yutq3EvQu8VaQqMTc5mBJ5lLetqurW7U2jZekUwc21nhnGYxfn8KMp+W0JAS/9CBcsr9rcuWPrV3leABX5CyrNJ7Fv5phKQQ9bgp8L7YZ+zuBgVDUcilJbuEG58JxQi/vx6d8yheiiKPwh5SgAv9ccTsvA6FMdBCok96LRx01Y5zUNgZZb9MfxSFsIEPOh9iZq8S5RdQBa6vQTeM+6gF9ILNs9/0zuFgHxwGyJulP0=:i5r56OSZLCK0x3hKjf1Ojf0NiPQOSqnBADL9X9Tia4MPIDE7jLi3bxxK4nfX3DDk8koYniGX4VtsLB4s/QvEPcX/8KYkXj2bWZp+wDgJk+cW/nnucj/FwqrOMm8Xcg3V+nSook/CtoWE/nMFMrA2hyziM4Akl+u86J4eT7K0PkEIxffbsrr61EYzR/oFS//k0LxEWj38u0BaUvi2Vkon4zNHad/jQCs+uCxlQd4G3m9pceIifTALtQIETgXp/u2Qc38JcEYd+CuZPb4A/d6679RrQ3ZaEEotPWTWmaMcYMHkRUJsoao4GhUmheVNHPULsiDKKHA1lMnGzv5TmnzUz5JOWUhjrZMbweG7+Eap9vztVpgYw7qvZkXJEBKZRUm7yHv2nj2CiaLhKlE1xRpsde5U2qrwWgpDEHQ6ymG18UZcqh2ZoVEv6nUyA5AcmLxx1F9qIJayTDQzziLd4C13yQ3WQVfYrm+wdH6/9oj8LAg5sBvkffWv+Gqppz8m5KfJK80md+BQg6XoNvAnEG1wyLIXfRn7F+RkhFz/z8JIphzvG5RPCcDkeWNIxFyKgAID6xRKvcBMtfC/chtU1IgYzfemQ83lgQ1jL2ih3/gXVzDaK1tfNvxA6VothBTA/8Y="

    Private aliceSharedKey As String = "DGVsbDA=:DGVsbDA=:zr6acEzNWuSrE9h9ucJMNNvNHG9vWAyTeJtKeGiXom/2i4xvpMG62lleuBrl6GzSF44khn6RL/IsTWfiH2wtlcAGQr4x+8NMUJdJJnQ7h9vSXijm4EBJW2GMdF34rjkhKD2MYZJb/EnZbGGnz3G86hgV3pDSR28Bm9s6FiHfVQBS24MD7BiHLpPh7ktvB1CtNG0ssGYCefP7f+nMgGjuuOSj83ap6lPq4zyeBt5eU2gccPPBj7dn+qZk3dNd+862ubu9DnJRWcisxYp93vtHiFbVC+XgmxsKNFU1XjyD4FAiZH3pcTCHQbVZuRx/iwrZSP4402N3LfyN3Qp1kchFm0oLR3JV5og+XuV2yX4ifaZ6F35H9XZYj6If2rwymmI6ZB7AT8oZvU5Ulox5ZXFi0ytCJ7h08Iosj+NMGZNK6Ozw2cuSFyxDOVOKVxuIz0jPGhphqoN622It31NUmGJjt/72tLnz+8r23tw0gxEWbIM+M1gtRxamMpy4XPAuKVFTlnBu7sRP1BhY1UjlEXpUpa42sMRH98gMEzeBwe0UIf+Ku/ATpAHGWUSK2IddtpE0HUAc2ydY8qJXBBrbenn7TQZCiAs2WussALLykapjxoFvVIdCCKD7B9ES8AjhUwo=:tTK344UsURA9LxkHgAvIRYInswH8W/vfn4tnqVBW9nKsm6QP0vQy1zr+tzlcZcMz5TfwiSrcQQJ+QyEzf/QLJnWwgzXq7b9AdNEoOzyeae+ngtQHJ6g7dOS5Swhkwn2er9GEw/+gPbobeE6pKPyz/s+z31vXH2JYD/XJRSsFTAAUJb+Low+HEXC2dSpfFNtFsL3oFmf25VzWlyMVhmJALRWHOS3zkJbcS05MfIrY8kt5MRt07GWQ0ObX76vk5pqckIMp8PCuDB1TB7YSxxdLYXuiRlZpj44YmLxel7EfQZKoKMS5ebHVj8SJSrIOqLNUR594Gb34n/FwK1xqWn0ykoBHKFE6pJcmrQ97gJ1PQfjAUoK5A8QjGnNCcLazgPz461/5+RqxwcZEoZ9vp4c4ODs+GzYnjNEmG8/cILTOFB+I1LyM9qI2pf0sMLFfVn0McqEndk9CdsaOhfTDf+zGLnUiaeP8bavEYPkoqj8AsTbIYmRdTX26Kp6miS82WSxqTvb0JdvI3o+ldACgQ0UKrB600Mj9X5R7oCc7lsEGZaFXdBW0E776NiJ+HfSbPHnsEFYciE6LV6P4z7/fI0wroEbFel4lJEfYgHRZyefv1q2+dC6Ee9Orf+dg79xEQq30KdKYUP3rRV7UHT6KftLrYMcK9tTn68l4pN8P2NTlOQQ=:mr4eCn7X95saljmZ0coZV6VCi4kOnfLsV9LtPpixV/tR5M5XWg+1laAwDxsl/tZ4yrpMtrmIdlPzlHAaqEOpUY8NZEdTdX3QM9wHYRfv05On3m7yztGlHy5aiuX7yydKupSIh2102fVLzjYgf3JZF54Lsk76lpeYMSBwYgZn5vpAdYQAY8vNlLHRiHHZ9xxr2d1kHm0wi+e+2teRo0+mxnXxkOoPxsSkGaGUYFS1I5XRPSEdjsNiAnPhPYGqSdL99IkXa5cOTtflERI43Q7dZmldK54ZRADPiHFzVvaLY2pOh1ffY2O/0siE4la0m2zbHJS9kheDybPP0+AbOBe3qvmwqLkb3poFDNZNJ4l3w75koVa01KEWu0s4uZykFx3wlvw2ACnhWCbENpIDhgNPQ2Q2rVS1ZcD/6Xg2e7s9RXJGJnebF/q+fewrRh3smaQUPqx40bZduBN07qVqXALP8SRGES8BfxiTr4yyrm5G9b6ltLb47/JYF/sRLnVeMWMxwUtwzPKvHn9xS30jy9BgmEasU52TRQIB86gVvrLdFn//IKaNBGkIvhUDt72gGVIkz//UZHQY1PeVrh+pGO2HA4UbxoSDHzCLOqDyPjn4T/RVsUKZZWlvK1RlA/qMwQdmGSscRLNmX98pGapM4cuRlVaXaV3UIKo509Msm/uh6fc=:r3RMXTAy3E3/zi7UtvBLZh0/zw+V8q9Sh2RcwxpylUTPqLuWnpTEhMmwZy8u/mPU658405o4KwNms+9iFFTzMADj8LYZePtWUgGcDPjGD4/sz14mKjB9iRTUUiwX9QTLnDLhCUNKUlhi8Z9XNME3nS1R41bAfiDkzGf4UBIGCqAHzgzUwV8io4Gv2qG0Dp+Jnw3cKfvBwJJ8skzpGI+jvv7wAywABh5FPZ7XjvbWTfCSLLpT9LdYTACJDhS1FogSmyLKUlisrOStWl5gW5cyXaSKCKtwOKUOedpr6El0wSpkGzPK1WJu85en08QfTJ3348gF7oaVu1u+L8W320uStZqR93nO1WgHz4rGOW+uMHvF6zfMMkxyh+OFXVv9rIFrLXwhHf3ru+CnanIxAbTT5WHhqpzQUuD9rX/VSLjxoNqUfveemH3LeMzijnn32X5r3wnfpl3WLaL4qx8KW3joJhYRCtvpY0R8oiM1q5Hwr1I8yciqMv6WdmriFl1EWpA7QxafkQeTcVzuMQJ/THo6Nvxkt9SlsQM1hDFElsu8042v8KeNZcxZr2sN78mytKA7RdY0b1eM6R9lcSdgWDI6zbXl4xhey7BkV1ZHI+xIyJttQH+swpNJYFEiiawPuYskYwRSOxQNJ5OSVHTX1/YXTxMY0vA/xJwUpM5U5JmVxf0=:t0U4i5cBsJnmFAkNXlMFpHxmOXQEoUV+IzpMW/7Cx2aZJmuRlKJkhWQq7KLoPdEFSx1nw94rz6QwDXfYwefZ6hDuiBd3QWgAMCIaqHZvtxV10X+ujZxSyFABhkajCKXmmJrlJxfpKYp8o6fdAwrUbofSvvJ7fibvzjHx+MC/qliDO5Gt5UQ2EC4AU7jo4PXS+XKtwq0YFyre+bJ2MrDYIh0Ajn2uXs7eV5I9NQq6ac+X8UQgaDJEQ4dwBQxVFs6TIvA3eC38TAYo4MlH0QWQXKToCjB9nsZmUAx9cMOFX8/UhNpOFYem0WI8mg6LH2LaSlY7DhO+AlnPnUoF8Ct5+nW5Mqm1AVMgmSpO11by+CAyNL3vnNkvh4PtRg4Y/70BAcClEBSyJWJhM4sSxATFtcPKbP0zXrKhq77Nuj44i+QEQEzLRrQrGlZSRlBXimlnxtZNNZgHoa/sSlgVqwgVELbmVUVED0eoeIs8cktvQHlP8DmJ1NJIAyPyO1ahsIrcoT5mxDJiGKaVH3rSEuDigCkRZcE2U8Ujh/JKPxq9DHZJfDGAR3w3dZ8szrACY4pUMowW6iQh6e0Q7v2mHkX01t3AGhUR6y4PRiDqfusxOtYlVeduXmSeT9iZPR/OoLcvu9COKQDJCkmDmWj7ta8gRsFljC2cd9oe8tSj9KBBeQ==:zr6acEzNWuSrE9h9ucJMNNvNHG9vWAyTeJtKeGiXom/2i4xvpMG62lleuBrl6GzSF44khn6RL/IsTWfiH2wtlcAGQr4x+8NMUJdJJnQ7h9vSXijm4EBJW2GMdF34rjkhKD2MYZJb/EnZbGGnz3G86hgV3pDSR28Bm9s6FiHfVQBS24MD7BiHLpPh7ktvB1CtNG0ssGYCefP7f+nMgGjuuOSj83ap6lPq4zyeBt5eU2gccPPBj7dn+qZk3dNd+862ubu9DnJRWcisxYp93vtHiFbVC+XgmxsKNFU1XjyD4FAiZH3pcTCHQbVZuRx/iwrZSP4402N3LfyN3Qp1kchFm0oLR3JV5og+XuV2yX4ifaZ6F35H9XZYj6If2rwymmI6ZB7AT8oZvU5Ulox5ZXFi0ytCJ7h08Iosj+NMGZNK6Ozw2cuSFyxDOVOKVxuIz0jPGhphqoN622It31NUmGJjt/72tLnz+8r23tw0gxEWbIM+M1gtRxamMpy4XPAuKVFTlnBu7sRP1BhY1UjlEXpUpa42sMRH98gMEzeBwe0UIf+Ku/ATpAHGWUSK2IddtpE0HUAc2ydY8qJXBBrbenn7TQZCiAs2WussALLykapjxoFvVIdCCKD7B9ES8AjhUwo="

    Private pkpf As BigInteger
    Private pkpf2 As BigInteger
    Private pkpd As BigInteger  ' decrypt-side password-derived key
    Private pkpd2 As BigInteger ' decrypt-side password-derived key
    Private tk0_new As BigInteger
    Private tk0_rem As BigInteger
    Private tk1_new As BigInteger
    Private tk1_rem As BigInteger
    Private sharedkey_new As BigInteger


    ' Encryption strength setting
    Private encryptionStrength As String = "default"

    '************************************************************************************************
    ' CRYPTOGRAPHIC HELPER FUNCTIONS
    '************************************************************************************************

    ' ComputeSHA512: Standard SHA-512 cryptographic hash
    ' Purpose: Derives keys from passwords and resource identifiers
    ' Input: UTF-8 string
    ' Output: 64-byte (512-bit) hash
    Private Function ComputeSHA512(input As String) As Byte()
        Using sha512 As SHA512 = SHA512.Create()
            Return sha512.ComputeHash(Encoding.UTF8.GetBytes(input))
        End Using
    End Function

    ' ComputeSHA512Bytes: SHA-512 hash on byte array
    ' Purpose: Used in iterative key derivation (PKPF generation)
    ' Input: Raw bytes
    ' Output: 64-byte hash
    Private Function ComputeSHA512Bytes(input As Byte()) As Byte()
        Using sha512 As SHA512 = SHA512.Create()
            Return sha512.ComputeHash(input)
        End Using
    End Function

    ' ComputeSHAKE512Byte: SHAKE-256 XOF (FIPS 202) over a string, 256 bytes of output.
    '   Used for password-derived key material. SHAKE-256 is a SHA-3 (Keccak) sponge XOF;
    '   as a symmetric primitive it offers 256-bit classical strength (~128-bit under Grover).
    '   The 256-byte output length is a design choice for the downstream BigInteger key math,
    '   not a security-level claim.
    ' Input:  UTF-8 string (password or intermediate value). Output: 256 bytes.
    Private Function ComputeSHAKE512Byte(input As String) As Byte()
        Try
            Dim shake256 As New ShakeDigest(256)
            Dim bytes As Byte() = Encoding.UTF8.GetBytes(input)
            shake256.BlockUpdate(bytes, 0, bytes.Length)
            Dim hash(255) As Byte  ' 256 bytes = 2048 bits
            shake256.OutputFinal(hash, 0, 256)
            Return hash
        Catch ex As Exception
            Return Nothing
        End Try
    End Function

    ' ComputeSHAKE512Byte2: SHAKE-256 XOF over a byte array, 256 bytes out. Used to iterate
    '   the password-derived keys: PKPF (8 iters), PKPF2 (to 16), PKPD (9), PKPD2 (to 17).
    '   Iterating stretches the derivation (slows brute force); it is not a quantum-level claim.
    ' Input: bytes from the previous iteration. Output: 256 bytes.
    Private Function ComputeSHAKE512Byte2(input As Byte()) As Byte()
        Try
            Dim shake256 As New ShakeDigest(256)
            shake256.BlockUpdate(input, 0, input.Length)
            Dim hash(255) As Byte  ' 256 bytes
            shake256.OutputFinal(hash, 0, 256)
            Return hash
        Catch ex As Exception
            Return Nothing
        End Try
    End Function

    ' ReverseString: Reverses character order
    ' Purpose: Non-linear transformation in PKPF key derivation
    ' Example: "ABC123" → "321CBA"
    ' This prevents rainbow table attacks on password hashes
    Private Function ReverseString(input As String) As String
        Dim chars() As Char = input.ToCharArray()
        Array.Reverse(chars)
        Return New String(chars)
    End Function

    ' ParseSharedKey: extract the platform shared-key fields
    ' Format: "f0:f1:f2:tk0_new:tk0_rem:tk1_new:tk1_rem:sky_new" (8 fields, colon-separated)
    ' Fields 0-2: legacy markers (unused)
    ' Fields 3-7: tk0_new/tk0_rem/tk1_new/tk1_rem/sky (platform pairing material)
    ' Sets module-level variables for use in encryption/decryption
    Private Sub ParseSharedKey(sharedKey As String)
        Dim fields = sharedKey.Split(":"c)
        tk0_new = New BigInteger(Convert.FromBase64String(fields(3)))       ' First part of token 0
        tk0_rem = New BigInteger(Convert.FromBase64String(fields(4)))       ' Remainder of token 0
        tk1_new = New BigInteger(Convert.FromBase64String(fields(5)))       ' First part of token 1
        tk1_rem = New BigInteger(Convert.FromBase64String(fields(6)))       ' Remainder of token 1
        sharedkey_new = New BigInteger(Convert.FromBase64String(fields(7))) ' Shared key component
    End Sub

    '************************************************************************************************
    ' KEY DERIVATION FUNCTIONS
    '************************************************************************************************

    ' GeneratePKPF: Password Key Prime Factor
    ' Purpose: Derives a large cryptographic key from password using 8 iterations
    ' Algorithm:
    '   1. Hash password with SHAKE-256 (256 bytes output)
    '   2. Reverse the Base64 string
    '   3. Repeat hash 7 more times (8 total iterations)
    '   4. Convert final 256-byte hash to BigInteger
    Private Function GeneratePKPF(password As String) As BigInteger
        Try
            ' STEP 1: Hash the password with SHAKE-256 FIRST
            Dim passwordHash As Byte() = ComputeSHAKE512Byte(password)
            Dim passwordHashBase64 As String = Convert.ToBase64String(passwordHash)

            ' STEP 2: Reverse the password hash
            Dim reversed As String = ReverseString(passwordHashBase64)

            ' First iteration: SHAKE-256 of reversed password hash
            Dim temp As Byte() = ComputeSHAKE512Byte(reversed)

            ' Iterations 2-8: Hash the hash 7 more times
            For i As Integer = 2 To 8
                temp = ComputeSHAKE512Byte2(temp)
            Next

            ' Return full 256 bytes as BigInteger (no reduction)
            Return New BigInteger(temp)
        Catch ex As Exception
            Return BigInteger.Zero
        End Try
    End Function

    ' GeneratePKPF2: Second Password Key Prime Factor
    ' Purpose: Extends PKPF with 8 additional hash iterations
    ' Algorithm:
    '   1. Start with PKPF bytes (output of first 8 iterations)
    '   2. Hash 8 more times with SHAKE-256 (iterations 9-16)
    '   3. Return full 256 bytes as BigInteger
    ' Total: 16 iterations of SHAKE-256 from original password
    Private Function GeneratePKPF2(pkpf As BigInteger) As BigInteger
        Try
            ' Convert PKPF to bytes (iteration 8 output)
            Dim temp As Byte() = pkpf.ToByteArray()

            ' Perform iterations 9-16: 8 more SHAKE-256 hashes
            For i As Integer = 9 To 16
                temp = ComputeSHAKE512Byte2(temp)
            Next

            ' Return full 256 bytes as BigInteger (no reduction)
            Return New BigInteger(temp)
        Catch ex As Exception
            Return BigInteger.Zero
        End Try
    End Function

    ' GeneratePKPD: Password Key Prime Derivation (decrypt-side)
    ' Purpose: Creates separate decryption keys using 9 iterations (one more than PKPF's 8)
    ' decrypt-side key; encryption and decryption use different SHAKE-256 iteration counts
    ' Algorithm:
    '   1. Hash password with SHAKE-256 (256 bytes output)
    '   2. Reverse the Base64 string
    '   3. Hash the reversed string
    '   4. Repeat hash 8 more times (9 total iterations, vs PKPF's 8)
    '   5. Return full 256 bytes as BigInteger
    Private Function GeneratePKPD(password As String) As BigInteger
        Try
            ' STEP 1: Hash the password with SHAKE-256 FIRST
            Dim passwordHash As Byte() = ComputeSHAKE512Byte(password)
            Dim passwordHashBase64 As String = Convert.ToBase64String(passwordHash)

            ' STEP 2: Reverse the password hash
            Dim reversed As String = ReverseString(passwordHashBase64)

            ' First iteration: SHAKE-256 of reversed password hash
            Dim temp As Byte() = ComputeSHAKE512Byte(reversed)

            ' Iterations 2-9: Hash the hash 8 more times (one more than PKPF)
            For i As Integer = 2 To 9
                temp = ComputeSHAKE512Byte2(temp)
            Next

            ' Return full 256 bytes as BigInteger (no reduction)
            Return New BigInteger(temp)
        Catch ex As Exception
            Return BigInteger.Zero
        End Try
    End Function

    ' GeneratePKPD2: Second Password Key Prime Derivation (decrypt-side)
    ' Purpose: Extends PKPD with 8 additional hash iterations (iterations 10-17)
    ' decrypt-side counterpart of PKPF2
    ' Algorithm:
    '   1. Start with PKPD bytes (output of 9 iterations)
    '   2. Hash 8 more times with SHAKE-256 (iterations 10-17)
    '   3. Return full 256 bytes as BigInteger
    ' Total: 17 iterations from original password (vs PKPF2's 16)
    Private Function GeneratePKPD2(pkpd As BigInteger) As BigInteger
        Try
            ' Convert PKPD to bytes (iteration 9 output)
            Dim temp As Byte() = pkpd.ToByteArray()

            ' Iterations 10-17: Hash 8 more times with SHAKE-256
            For i As Integer = 10 To 17
                temp = ComputeSHAKE512Byte2(temp)
            Next

            ' Return full 256 bytes as BigInteger (no reduction)
            Return New BigInteger(temp)
        Catch ex As Exception
            Return BigInteger.Zero
        End Try
    End Function

    ' GenerateSenderKeys: Derives all sender keys from resource and password
    '
    ' PASSWORD-DERIVED KEY MATERIAL
    ' ────────────────────────────────────────────────────────────────────
    '
    ' Inputs:
    '   - resource: Unique identifier (e.g., "alice-user-agent.tryhexaeight.com")
    '   - password: Secret password (user's secret credential)
    '
    ' Outputs:
    '   - Returns: PK0 (Primary Key 0 = Combined authentication key)
    '   - Sets module variables: pkpf, pkpf2 (encryption), pkpd, pkpd2 (decryption)
    '
    ' Key Derivation Process:
    '   Step 1: TokenSecret = Base64(SHAKE-256(Password))    // 256 bytes
    '   Step 2: Token1 = BigInteger(SHA512(Resource))        // 64 bytes, protocol compatibility
    '   Step 3: Token2 = BigInteger(TokenSecret)             // From SHAKE-256 password hash
    '   Step 4: PK0 = Token1 × Token2                        // Combined authentication key
    '   Step 5: PKPF  = GeneratePKPF(Password)               // 8 iterations
    '   Step 6: PKPF2 = GeneratePKPF2(PKPF)                  // 16 iterations total
    '   Step 7: PKPD  = GeneratePKPD(Password)               // 9 iterations
    '   Step 8: PKPD2 = GeneratePKPD2(PKPD)                  // 17 iterations total
    '
    ' WHY DIFFERENT HASH FUNCTIONS?
    ' ──────────────────────────────────────────────────────────────────
    ' • Password → SHAKE-256: the critical secret; all cryptographic strength derives from it
    ' • Resource → SHA-512: Public identifier, used for protocol compatibility
    ' • The security depends on the PASSWORD, not the resource name
    ' • Resource is like an email address (public), password is the secret
    '
    ' PRIMITIVE NOTE:
    ' ──────────────────────────────────────────────────────────────────
    ' • All password-derived keys (TokenSecret, PKPF, PKPF2, PKPD, PKPD2) use SHAKE-256
    ' • As a symmetric primitive SHAKE-256 is quantum-safe; this is NOT a scheme-level post-quantum claim.
    '
    Private Function GenerateSenderKeys(resource As String, password As String) As BigInteger
        ' Step 1: Create TokenSecret from password (Base64 of SHAKE-256)
        Dim TokenSecret As String = Convert.ToBase64String(ComputeSHAKE512Byte(password))

        ' Step 2: Generate Token1 from resource identifier (still SHA-512)
        Dim token1Bytes = ComputeSHA512(resource)
        Dim GeneratedToken1 = New BigInteger(token1Bytes)

        ' Step 3: Generate Token2 from TokenSecret
        Dim GeneratedToken2 = New BigInteger(Convert.FromBase64String(TokenSecret))

        ' Step 4: Calculate PK0 = Token1 × Token2
        Dim pk0 = BigInteger.Multiply(GeneratedToken1, GeneratedToken2)

        ' Step 5: Generate PKPF from raw password (8 iterations) - FOR ENCRYPTION
        ' IMPORTANT: Uses raw password, NOT TokenSecret!
        pkpf = GeneratePKPF(password)

        ' Step 6: Generate PKPF2 from PKPF (16 iterations total) - FOR ENCRYPTION
        pkpf2 = GeneratePKPF2(pkpf)

        ' Step 7: Generate PKPD from raw password (9 iterations) - decrypt-side
        pkpd = GeneratePKPD(password)

        ' Step 8: Generate PKPD2 from PKPD (17 iterations total) - decrypt-side
        pkpd2 = GeneratePKPD2(pkpd)

        Return pk0
    End Function

    '************************************************************************************************
    ' LOOKUP TABLE INITIALIZATION (Performance Optimization)
    '************************************************************************************************

    ' InitLookupTable: Pre-computes modular remainders for all possible keycounter values
    ' Purpose: Avoid expensive BigInteger modulo operations during encryption/decryption
    ' Input: BigInteger key (any of the 8 keys)
    ' Output: Lookup table with 32769 entries (one for each keycounter 32768-65536)
    ' Algorithm:
    '   For each keycounter kc from 32768 to 65536:
    '     lookup[kc-32768] = key mod kc
    ' Performance: Pre-computation takes ~10-20ms, saves 29 mod ops per 64-byte chunk

    '************************************************************************************************
    ' JSON PADDING (Anti-Known-Plaintext Attack Protection)
    '************************************************************************************************

    ' BuildJsonData: Wraps message in JSON with random GUID padding
    ' Purpose: Prevents known-plaintext attacks by adding random data
    ' Input:
    '   - request: Message type (e.g., "DATAMESSAGE")
    '   - sender: Sender identifier
    '   - receiver: Receiver identifier
    '   - body: Actual message content
    ' Output: JSON string with random padding at start and end
    ' Format: {"rnd1":"rnd2",...,"REQUEST":"...","SENDER":"...","BODY":"...","rnd3":"rnd4",...}
    ' Security: Each encryption has different random GUIDs, making pattern analysis impossible
    Private Function BuildJsonData(request As String, sender As String, receiver As String, body As String, Optional macKey As String = Nothing) As String
        Dim sb As New StringBuilder()
        Dim randomcnt As Integer = RandomNumberGenerator.GetInt32(2, 4)   ' CSPRNG (padding count)
        Dim unixTime As Long = CLng((DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds)

        ' NOTE: no inner "HMAC" field is emitted. Integrity is provided by the outer authentication
        ' tag (AEAD tag for .FM1/.CM1; Encrypt-then-MAC over nonce||ciphertext for .EM1), not by
        ' anything inside the envelope. (macKey is retained for signature compatibility, unused.)

        sb.Append("{")

        ' Random padding at start (2-3 random GUID pairs)
        For i = 0 To randomcnt - 1
            If i > 0 Then sb.Append(",")
            sb.Append("""").Append(Guid.NewGuid().ToString().Substring(0, 2)).Append(""":""")
            sb.Append(Guid.NewGuid().ToString().Substring(0, 2)).Append("""")
        Next

        ' Actual data fields — JSON-encode every value (JsonConvert.ToString adds quotes + escapes),
        ' never raw string concatenation, so a body containing " or \ cannot inject envelope fields.
        sb.Append(",""REQUEST"":").Append(JsonConvert.ToString(request))
        sb.Append(",""SENDER"":").Append(JsonConvert.ToString(sender))
        sb.Append(",""RECEIVER"":").Append(JsonConvert.ToString(receiver))
        sb.Append(",""CURRENTTIME"":").Append(JsonConvert.ToString(unixTime.ToString()))
        sb.Append(",""BODY"":").Append(JsonConvert.ToString(body))

        ' Random padding at end (2-3 random GUID pairs)
        randomcnt = RandomNumberGenerator.GetInt32(2, 4)   ' CSPRNG (padding count)
        For i = 0 To randomcnt - 1
            sb.Append(",""").Append(Guid.NewGuid().ToString().Substring(0, 2)).Append(""":""")
            sb.Append(Guid.NewGuid().ToString().Substring(0, 2)).Append("""")
        Next

        sb.Append("}  ") ' Note: adds 2 spaces at end!
        Return sb.ToString()
    End Function

    ' BuildUserJsonData: Reconstructs JSON message with updated receive time
    ' Used by DecryptMessageUsingSharedKey after JSON deserialization
    Private Function BuildUserJsonData(ByVal request As String, ByVal sender As String, ByVal receiver As String, body As String, messagesenttime As String) As String
        Try
            Dim jsonstringreq As New StringBuilder()
            Dim randomcnt As Integer
            randomcnt = New Random().Next(2, 4)
            Dim cnt As Integer = 0
            Dim uTime As Int64
            uTime = (DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds
            Dim jw As New IO.StringWriter(jsonstringreq)
            Using writer As JsonWriter = New JsonTextWriter(jw)
                writer.WriteStartObject()
                writer.WritePropertyName("REQUEST")
                writer.WriteValue(request)
                writer.WritePropertyName("SENDER")
                writer.WriteValue(sender)
                writer.WritePropertyName("RECEIVER")
                writer.WriteValue(receiver)
                writer.WritePropertyName("STIME")
                writer.WriteValue(messagesenttime)
                writer.WritePropertyName("RTIME")
                writer.WriteValue(uTime.ToString)
                writer.WritePropertyName("BODY")
                writer.WriteValue(body)
                writer.WriteEndObject()
            End Using
            Return jsonstringreq.ToString()
        Catch ex As Exception
            Return ""
        End Try
    End Function

    Private Sub SetEncryptionStrength(strength As String)
        encryptionStrength = strength.ToLower().Trim()
    End Sub

    ' ===== EM1 helpers: SHAKE-256 keystream + channel secret + constants =====
    Private Const EM_MARKER As String = ".EM1"
    Private Const NonceLen As Integer = 16
    Private ReadOnly ENC_LABEL As Byte() = Encoding.ASCII.GetBytes("HE-enc-v1")
    Private ReadOnly MAC_LABEL As Byte() = Encoding.ASCII.GetBytes("HE-mac-v1")

    Private Function Shake256(outLen As Integer, ParamArray parts As Byte()()) As Byte()
        Dim xof As New ShakeDigest(256)
        For Each p In parts : xof.BlockUpdate(p, 0, p.Length) : Next
        Dim o(outLen - 1) As Byte : xof.OutputFinal(o, 0, outLen) : Return o
    End Function

    ' NIST KMAC256 keyed MAC (BouncyCastle, SP 800-185) over an unambiguous byte string, for
    ' Encrypt-then-MAC. Sponge-based (Keccak) — same primitive family as the SHAKE keystream/KDF.
    Private Function Kmac256(key As Byte(), outLen As Integer, ParamArray parts As Byte()()) As Byte()
        Dim mac As New Org.BouncyCastle.Crypto.Macs.KMac(256, MAC_LABEL)
        mac.Init(New Org.BouncyCastle.Crypto.Parameters.KeyParameter(key))
        For Each p In parts : mac.BlockUpdate(p, 0, p.Length) : Next
        Dim sz As Integer = mac.GetMacSize()
        Dim full(sz - 1) As Byte : mac.DoFinal(full, 0)
        If outLen >= sz Then Return full
        Dim o(outLen - 1) As Byte : Array.Copy(full, 0, o, 0, outLen) : Return o
    End Function

    Private ReadOnly KDF_CUSTOM As Byte() = Encoding.ASCII.GetBytes("HE-kdf-v1")
    Private ReadOnly KDF_SALT As Byte() = Encoding.ASCII.GetBytes("HE-cs-extract-v1")

    ' KMAC256(key, message) -> 32 bytes, under a fixed KDF customization string (domain-separated
    ' from the message-integrity KMAC, which uses MAC_LABEL).
    Private Function KmacKdf(key As Byte(), ParamArray message As Byte()()) As Byte()
        Dim mac As New Org.BouncyCastle.Crypto.Macs.KMac(256, KDF_CUSTOM)
        mac.Init(New Org.BouncyCastle.Crypto.Parameters.KeyParameter(key))
        For Each m In message : mac.BlockUpdate(m, 0, m.Length) : Next
        Dim sz As Integer = mac.GetMacSize()
        Dim full(sz - 1) As Byte : mac.DoFinal(full, 0)
        Dim o(31) As Byte : Array.Copy(full, 0, o, 0, 32) : Return o
    End Function

    ' Per-cipher key derivation: extract-then-expand (KMAC256, SP 800-185 / 800-108 pattern).
    '   PRK = KMAC(salt, CS)     -- EXTRACT: condition CS into a uniform pseudorandom key, so the
    '                               keys don't rest solely on CS already being uniform.
    '   key = KMAC(PRK, label)   -- EXPAND: an independent per-cipher key from PRK + its label.
    Private Function DeriveKey(label As Byte(), csB As Byte()) As Byte()
        Dim prk As Byte() = KmacKdf(KDF_SALT, csB)
        Return KmacKdf(prk, label)
    End Function

    ' Canonical CS encoding: UNSIGNED BIG-ENDIAN magnitude — an explicit, portable byte format
    ' (no sign byte, documented endianness). Do NOT use BigInteger.ToByteArray() directly: its
    ' little-endian / two's-complement / variable sign-byte behaviour is a .NET quirk that other
    ' languages (Node/Python/Go/Java) do not reproduce, which would silently break cross-language
    ' key derivation. Every language's default big-int serialization is unsigned big-endian.
    Private Function CanonicalCS(cs As BigInteger) As Byte()
        Return BigInteger.Abs(cs).ToByteArray(isUnsigned:=True, isBigEndian:=True)
    End Function

    ' Channel secret (BIG) as canonical bytes.
    Private Function ChannelSecretBytes(pk0 As BigInteger, encryptSide As Boolean) As Byte()
        Dim cs As BigInteger
        If encryptSide Then
            cs = pk0 * (pkpf * pkpf + pkpf * pkpd + tk0_new) + (pkpf2 * pkpf2 + pkpf2 * pkpd2 + tk1_new) + sharedkey_new
        Else
            cs = pk0 * (pkpd * pkpd + pkpd * pkpf + tk0_rem) + (pkpd2 * pkpd2 + pkpd2 * pkpf2 + tk1_rem) + sharedkey_new
        End If
        Return CanonicalCS(cs)
    End Function

    ' ===== 2-party AEAD alternatives: ".FM1" AES-256-GCM (FIPS), ".CM1" ChaCha20-Poly1305,
    '       ".SM1" AES-256-GCM-SIV (RFC 8452, nonce-misuse-resistant) =====
    Private Const FM_MARKER As String = ".FM1"
    Private Const CM_MARKER As String = ".CM1"
    Private Const SM_MARKER As String = ".SM1"
    Private Const AeadNonceLen As Integer = 12
    Private ReadOnly AES_LABEL As Byte() = Encoding.ASCII.GetBytes("HE-aes-v1")
    Private ReadOnly CHA_LABEL As Byte() = Encoding.ASCII.GetBytes("HE-cha-v1")
    Private ReadOnly SIV_LABEL As Byte() = Encoding.ASCII.GetBytes("HE-siv-v1")

    ' aad binds the cipher marker into the AEAD tag, so swapping the wire marker is a first-class
    ' integrity failure (not merely caught incidentally by per-cipher key separation).
    Private Function AeadRun(cipher As Org.BouncyCastle.Crypto.Modes.IAeadCipher, forEncrypt As Boolean, key As Byte(), nonce As Byte(), aad As Byte(), data As Byte()) As Byte()
        cipher.Init(forEncrypt, New Org.BouncyCastle.Crypto.Parameters.AeadParameters(New Org.BouncyCastle.Crypto.Parameters.KeyParameter(key), 128, nonce, aad))
        Dim outBuf(cipher.GetOutputSize(data.Length) - 1) As Byte
        Dim n As Integer = cipher.ProcessBytes(data, 0, data.Length, outBuf, 0)
        n += cipher.DoFinal(outBuf, n)
        If n = outBuf.Length Then Return outBuf
        Dim o(n - 1) As Byte : Array.Copy(outBuf, o, n) : Return o
    End Function

    Private Function AeadEncrypt(message As String, senderResource As String, senderPassword As String, recipientResource As String, recipientSharedKey As String, label As Byte(), makeCipher As Func(Of Org.BouncyCastle.Crypto.Modes.IAeadCipher), marker As String) As String
        Try
            ParseSharedKey(recipientSharedKey)
            Dim pk0 = GenerateSenderKeys(senderResource, senderPassword)
            Dim csB = ChannelSecretBytes(pk0, True)
            Dim key = DeriveKey(label, csB)
            Dim nonce(AeadNonceLen - 1) As Byte : RandomNumberGenerator.Fill(nonce)
            ' Integrity on the AEAD paths comes from the AEAD tag; the envelope carries no
            ' security-bearing inner HMAC (BuildJsonData's default field is inert here).
            Dim json = BuildJsonData("DATAMESSAGE", senderResource, recipientResource, message)
            Dim ct = AeadRun(makeCipher(), True, key, nonce, Encoding.ASCII.GetBytes(marker), Encoding.UTF8.GetBytes(json))
            Dim wire(AeadNonceLen + ct.Length - 1) As Byte
            Array.Copy(nonce, 0, wire, 0, AeadNonceLen)
            Array.Copy(ct, 0, wire, AeadNonceLen, ct.Length)
            Return Convert.ToBase64String(wire) & marker
        Catch ex As Exception
            Console.WriteLine("AEAD encrypt error: " & ex.Message) : Return Nothing
        End Try
    End Function

    Private Function AeadDecrypt(encryptedB64 As String, recipientResource As String, recipientPassword As String, senderSharedKey As String, label As Byte(), makeCipher As Func(Of Org.BouncyCastle.Crypto.Modes.IAeadCipher), marker As String) As String
        Try
            If encryptedB64.EndsWith(marker) Then encryptedB64 = encryptedB64.Substring(0, encryptedB64.Length - marker.Length)
            ParseSharedKey(senderSharedKey)
            Dim pk0 = GenerateSenderKeys(recipientResource, recipientPassword)
            Dim csB = ChannelSecretBytes(pk0, False)
            Dim key = DeriveKey(label, csB)
            Dim bytes = Convert.FromBase64String(encryptedB64)
            Dim nonce(AeadNonceLen - 1) As Byte : Array.Copy(bytes, 0, nonce, 0, AeadNonceLen)
            Dim ct(bytes.Length - AeadNonceLen - 1) As Byte : Array.Copy(bytes, AeadNonceLen, ct, 0, ct.Length)
            Dim pt = AeadRun(makeCipher(), False, key, nonce, Encoding.ASCII.GetBytes(marker), ct)   ' throws on tamper / marker mismatch
            Dim json = Encoding.UTF8.GetString(pt)
            Dim m = System.Text.RegularExpressions.Regex.Match(json, "\{.*\}", System.Text.RegularExpressions.RegexOptions.Singleline)
            Return If(m.Success, m.Value, Nothing)
        Catch ex As Exception
            Return Nothing   ' AEAD tag failure = tamper -> reject
        End Try
    End Function

    ' AES-256-GCM (FIPS) — ".FM1"
    Private Function EncryptFM1(message As String, sr As String, sp As String, rr As String, rk As String) As String
        Return AeadEncrypt(message, sr, sp, rr, rk, AES_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), FM_MARKER)
    End Function
    Private Function DecryptFM1(ct As String, rr As String, rp As String, sk As String) As String
        Return AeadDecrypt(ct, rr, rp, sk, AES_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), FM_MARKER)
    End Function

    ' ChaCha20-Poly1305 (RFC 8439) — ".CM1"
    Private Function EncryptCM1(message As String, sr As String, sp As String, rr As String, rk As String) As String
        Return AeadEncrypt(message, sr, sp, rr, rk, CHA_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(), CM_MARKER)
    End Function
    Private Function DecryptCM1(ct As String, rr As String, rp As String, sk As String) As String
        Return AeadDecrypt(ct, rr, rp, sk, CHA_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(), CM_MARKER)
    End Function

    ' AES-256-GCM-SIV (RFC 8452, nonce-misuse-resistant) — ".SM1"
    Private Function EncryptSM1(message As String, sr As String, sp As String, rr As String, rk As String) As String
        Return AeadEncrypt(message, sr, sp, rr, rk, SIV_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.GcmSivBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), SM_MARKER)
    End Function
    Private Function DecryptSM1(ct As String, rr As String, rp As String, sk As String) As String
        Return AeadDecrypt(ct, rr, rp, sk, SIV_LABEL, Function() New Org.BouncyCastle.Crypto.Modes.GcmSivBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), SM_MARKER)
    End Function

    ' EM1 encrypt: SHAKE-256 keystream, then Encrypt-then-MAC over nonce‖ciphertext.
    ' Integrity authenticates the ENTIRE ciphertext (every field the decryptor returns).
    Private Function EncryptMessageUsingSharedKey(message As String, senderResource As String, senderPassword As String, recipientResource As String, recipientSharedKey As String) As String
        Try
            ParseSharedKey(recipientSharedKey)                          ' tk0_new/tk0_rem/tk1_new/tk1_rem/sky_new
            Dim pk0 = GenerateSenderKeys(senderResource, senderPassword) ' pk0, pkpf, pkpd from SHAKE(password)
            Dim csB As Byte() = ChannelSecretBytes(pk0, True)           ' channel secret (encrypt-form)
            Dim kEnc As Byte() = DeriveKey(ENC_LABEL, csB)
            Dim kMac As Byte() = DeriveKey(MAC_LABEL, csB)

            Dim jsonMessage As String = BuildJsonData("DATAMESSAGE", senderResource, recipientResource, message)
            Dim pt = Encoding.UTF8.GetBytes(jsonMessage)

            ' keystream XOR
            Dim nonce(NonceLen - 1) As Byte : RandomNumberGenerator.Fill(nonce)
            Dim ks = Shake256(pt.Length, kEnc, nonce)
            Dim ct(pt.Length - 1) As Byte
            For i = 0 To pt.Length - 1 : ct(i) = CByte(pt(i) Xor ks(i)) : Next

            ' tag = KMAC256(kMac, marker ‖ nonce ‖ ct)  (Encrypt-then-MAC; marker bound in)
            Dim maced(NonceLen + ct.Length - 1) As Byte
            Array.Copy(nonce, 0, maced, 0, NonceLen)
            Array.Copy(ct, 0, maced, NonceLen, ct.Length)
            Dim tag = Kmac256(kMac, 32, Encoding.ASCII.GetBytes(EM_MARKER), maced)

            ' wire = nonce(16) ‖ ct ‖ tag(32) , marker ".EM1"
            Dim wire(NonceLen + ct.Length + tag.Length - 1) As Byte
            Array.Copy(nonce, 0, wire, 0, NonceLen)
            Array.Copy(ct, 0, wire, NonceLen, ct.Length)
            Array.Copy(tag, 0, wire, NonceLen + ct.Length, tag.Length)
            Return Convert.ToBase64String(wire) & EM_MARKER
        Catch ex As Exception
            Console.WriteLine("Encrypt error: " & ex.Message)
            Return Nothing
        End Try
    End Function

    ' EM1 decrypt: verify the tag over nonce‖ct (constant-time) BEFORE decrypting; then XOR back.
    Private Function DecryptMessageUsingSharedKey(encryptedB64 As String, recipientResource As String, recipientPassword As String, senderSharedKey As String) As String
        Try
            ParseSharedKey(senderSharedKey)
            Dim pk0 = GenerateSenderKeys(recipientResource, recipientPassword)
            Dim csB As Byte() = ChannelSecretBytes(pk0, False)          ' channel secret (decrypt-form)
            Dim kEnc As Byte() = DeriveKey(ENC_LABEL, csB)
            Dim kMac As Byte() = DeriveKey(MAC_LABEL, csB)

            If encryptedB64.EndsWith(EM_MARKER) Then encryptedB64 = encryptedB64.Substring(0, encryptedB64.Length - EM_MARKER.Length)
            Dim bytes = Convert.FromBase64String(encryptedB64)
            If bytes.Length < NonceLen + 32 Then Return Nothing

            ' split: nonce ‖ ct ‖ tag(32)
            Dim ctLen = bytes.Length - NonceLen - 32
            Dim nonce(NonceLen - 1) As Byte : Array.Copy(bytes, 0, nonce, 0, NonceLen)
            Dim tag(31) As Byte : Array.Copy(bytes, NonceLen + ctLen, tag, 0, 32)

            ' verify tag over marker‖nonce‖ct (the whole ciphertext) — constant-time — BEFORE decrypting
            Dim maced(NonceLen + ctLen - 1) As Byte
            Array.Copy(bytes, 0, maced, 0, NonceLen + ctLen)
            Dim expected = Kmac256(kMac, 32, Encoding.ASCII.GetBytes(EM_MARKER), maced)
            If Not Org.BouncyCastle.Utilities.Arrays.ConstantTimeAreEqual(tag, expected) Then Return Nothing   ' tamper -> reject

            ' authenticated: XOR keystream back
            Dim ct(ctLen - 1) As Byte : Array.Copy(bytes, NonceLen, ct, 0, ctLen)
            Dim ks = Shake256(ctLen, kEnc, nonce)
            For i = 0 To ctLen - 1 : ct(i) = CByte(ct(i) Xor ks(i)) : Next
            Dim decrypted As String = Encoding.UTF8.GetString(ct)

            Dim jsonMatch = System.Text.RegularExpressions.Regex.Match(decrypted, "\{.*\}", System.Text.RegularExpressions.RegexOptions.Singleline)
            If Not jsonMatch.Success Then Return Nothing
            Dim resptemplate = New With {Key .REQUEST = "", .SENDER = "", .RECEIVER = "", .CURRENTTIME = "", .BODY = "", .HMAC = ""}
            Dim datamessage = JsonConvert.DeserializeAnonymousType(jsonMatch.Value, resptemplate)
            Return BuildUserJsonData(datamessage.REQUEST.ToString(), datamessage.SENDER.ToString(), datamessage.RECEIVER.ToString(), datamessage.BODY.ToString(), datamessage.CURRENTTIME.ToString())
        Catch ex As Exception
            Return Nothing
        End Try
    End Function

    ' Parse the decrypted JSON with the deserializer (not a regex) so a body containing quotes or
    ' backslashes round-trips intact.
    Private Function ExtractBody(json As String) As String
        If String.IsNullOrEmpty(json) Then Return ""
        Try
            Dim d = JsonConvert.DeserializeAnonymousType(json, New With {Key .BODY = ""})
            Return If(d IsNot Nothing AndAlso d.BODY IsNot Nothing, d.BODY.ToString(), json)
        Catch
            Return json
        End Try
    End Function

    ' Run one cipher and print checkable evidence: round-trip, semantic security, tamper-rejection.
    Private Sub RunCipher(name As String, msg As String, encFn As Func(Of String, String), decFn As Func(Of String, String))
        Const markerLen As Integer = 4
        Console.WriteLine("--- " & name & " ---")

        Dim ct = encFn(msg)
        If String.IsNullOrEmpty(ct) Then Console.WriteLine("  [FAIL] encrypt returned empty") : Console.WriteLine() : Return
        Dim wireBytes = Convert.FromBase64String(ct.Substring(0, ct.Length - markerLen))
        Console.WriteLine("  wire: " & wireBytes.Length & " bytes (" & Encoding.UTF8.GetByteCount(msg) & "-byte message) ; " & ct.Substring(0, Math.Min(48, ct.Length)) & "...")

        ' 1) round-trip
        Dim body = ExtractBody(decFn(ct))
        Console.WriteLine("  decrypt: " & body)
        Console.WriteLine(If(body = msg, "  [PASS] round-trip", "  [FAIL] round-trip"))

        ' 2) semantic security: same plaintext, encrypted again -> different ciphertext (fresh nonce)
        Dim ct2 = encFn(msg)
        Console.WriteLine(If(ct2 <> ct, "  [PASS] same plaintext -> different ciphertext (fresh nonce)", "  [FAIL] ciphertext repeats"))

        ' 3) tamper: flip one byte mid-ciphertext (marker kept). Rejection must come from the
        '    integrity check, not from JSON breaking.
        Dim tb = Convert.FromBase64String(ct.Substring(0, ct.Length - markerLen))
        Dim idx = tb.Length \ 2                         ' mid-ciphertext, past the nonce
        tb(idx) = CByte(tb(idx) Xor 1)
        Dim tampered = Convert.ToBase64String(tb) & ct.Substring(ct.Length - markerLen)
        Dim bodyT = ExtractBody(decFn(tampered))
        Console.WriteLine(If(bodyT <> msg, "  [PASS] tamper rejected", "  [FAIL] tamper accepted"))
        Console.WriteLine()
    End Sub

    Private Function Hex(b As Byte()) As String
        Return BitConverter.ToString(b).Replace("-", "").ToLowerInvariant()
    End Function

    ' Deterministic test vectors (Alice -> Bob, encrypt-side) with a fixed nonce and fixed raw
    ' plaintext, so a cross-language port can check the key schedule and each cipher byte-for-byte.
    ' Run: dotnet run -c Release -- vectors
    Private Sub GenerateTestVectors()
        ParseSharedKey(bobSharedKey)
        Dim pk0 = GenerateSenderKeys(aliceResource, alicePassword)
        Dim csB = ChannelSecretBytes(pk0, True)
        Dim prk = KmacKdf(KDF_SALT, csB)
        Dim kEnc = DeriveKey(ENC_LABEL, csB)
        Dim kMac = DeriveKey(MAC_LABEL, csB)
        Dim kAes = DeriveKey(AES_LABEL, csB)
        Dim kCha = DeriveKey(CHA_LABEL, csB)
        Dim kSiv = DeriveKey(SIV_LABEL, csB)

        Dim pt = Encoding.UTF8.GetBytes("HexaEight DDE test vector 0001")
        Dim n16(15) As Byte : For i = 0 To 15 : n16(i) = CByte(i) : Next
        Dim n12(11) As Byte : For i = 0 To 11 : n12(i) = CByte(i) : Next

        ' EM1: keystream + Encrypt-then-MAC over marker||nonce||ct
        Dim ks = Shake256(pt.Length, kEnc, n16)
        Dim emCt(pt.Length - 1) As Byte : For i = 0 To pt.Length - 1 : emCt(i) = CByte(pt(i) Xor ks(i)) : Next
        Dim maced(16 + emCt.Length - 1) As Byte
        Array.Copy(n16, 0, maced, 0, 16) : Array.Copy(emCt, 0, maced, 16, emCt.Length)
        Dim emTag = Kmac256(kMac, 32, Encoding.ASCII.GetBytes(EM_MARKER), maced)

        ' AEADs: fixed 12-byte nonce, marker bound as AAD
        Dim fm = AeadRun(New Org.BouncyCastle.Crypto.Modes.GcmBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), True, kAes, n12, Encoding.ASCII.GetBytes(FM_MARKER), pt)
        Dim cm = AeadRun(New Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305(), True, kCha, n12, Encoding.ASCII.GetBytes(CM_MARKER), pt)
        Dim sm = AeadRun(New Org.BouncyCastle.Crypto.Modes.GcmSivBlockCipher(New Org.BouncyCastle.Crypto.Engines.AesEngine()), True, kSiv, n12, Encoding.ASCII.GetBytes(SM_MARKER), pt)

        Console.WriteLine("# HexaEight Dead Drop Encryption — Test Vectors")
        Console.WriteLine("")
        Console.WriteLine("Deterministic vectors for cross-language reproducibility of the client transport.")
        Console.WriteLine("Encrypt-side (Alice -> Bob), fixed nonce, fixed raw plaintext (the JSON envelope's")
        Console.WriteLine("random GUID padding is a separate non-deterministic step and is omitted here so the")
        Console.WriteLine("cipher core is exactly reproducible). All values are lowercase hex.")
        Console.WriteLine("")
        Console.WriteLine("## Key schedule")
        Console.WriteLine("| value | hex |")
        Console.WriteLine("|-------|-----|")
        Console.WriteLine("| canonical CS  be(CS)          | " & Hex(csB) & " |")
        Console.WriteLine("| PRK = KMAC(salt, be(CS))      | " & Hex(prk) & " |")
        Console.WriteLine("| k_enc = KMAC(PRK, HE-enc-v1)   | " & Hex(kEnc) & " |")
        Console.WriteLine("| k_mac = KMAC(PRK, HE-mac-v1)   | " & Hex(kMac) & " |")
        Console.WriteLine("| k_aes = KMAC(PRK, HE-aes-v1)   | " & Hex(kAes) & " |")
        Console.WriteLine("| k_cha = KMAC(PRK, HE-cha-v1)   | " & Hex(kCha) & " |")
        Console.WriteLine("| k_siv = KMAC(PRK, HE-siv-v1)   | " & Hex(kSiv) & " |")
        Console.WriteLine("")
        Console.WriteLine("## Message inputs")
        Console.WriteLine("| value | hex |")
        Console.WriteLine("|-------|-----|")
        Console.WriteLine("| plaintext (utf-8)             | " & Hex(pt) & " |")
        Console.WriteLine("| nonce (16-byte, .EM1)         | " & Hex(n16) & " |")
        Console.WriteLine("| nonce (12-byte, AEADs)        | " & Hex(n12) & " |")
        Console.WriteLine("")
        Console.WriteLine("## Cipher outputs")
        Console.WriteLine("| cipher | ciphertext (hex) | tag (hex) |")
        Console.WriteLine("|--------|------------------|-----------|")
        Console.WriteLine("| .EM1 (SHAKE keystream + KMAC EtM) | " & Hex(emCt) & " | " & Hex(emTag) & " |")
        Console.WriteLine("| .FM1 (AES-256-GCM)               | " & Hex(fm.Take(pt.Length).ToArray()) & " | " & Hex(fm.Skip(pt.Length).ToArray()) & " |")
        Console.WriteLine("| .CM1 (ChaCha20-Poly1305)         | " & Hex(cm.Take(pt.Length).ToArray()) & " | " & Hex(cm.Skip(pt.Length).ToArray()) & " |")
        Console.WriteLine("| .SM1 (AES-256-GCM-SIV)           | " & Hex(sm.Take(pt.Length).ToArray()) & " | " & Hex(sm.Skip(pt.Length).ToArray()) & " |")
        Console.WriteLine("")
        Console.WriteLine("Notes: AEAD output = ciphertext(||)tag with a 16-byte (128-bit) tag; the marker string")
        Console.WriteLine("(e.g. `.FM1`) is bound as associated data. The .EM1 tag is KMAC256(k_mac, marker||nonce||ct).")
    End Sub

    Sub Main()
        Try : Console.OutputEncoding = System.Text.Encoding.UTF8 : Catch : End Try
        Dim __args = Environment.GetCommandLineArgs()
        If __args.Length > 1 AndAlso __args(1) = "vectors" Then GenerateTestVectors() : Return
        SetEncryptionStrength("default")
        Console.WriteLine("=====================================================================")
        Console.WriteLine(" HexaEight 2-party ciphers over the same channel secret (Alice -> Bob)")
        Console.WriteLine(" Dead drop: no handshake, recipient need not be online.")
        Console.WriteLine("   .FM1 = AES-256-GCM       (FIPS 197 / SP 800-38D)   [default]")
        Console.WriteLine("   .CM1 = ChaCha20-Poly1305 (RFC 8439)")
        Console.WriteLine("   .SM1 = AES-256-GCM-SIV   (RFC 8452, nonce-misuse-resistant)")
        Console.WriteLine("   .EM1 = SHAKE-256 keystream + Encrypt-then-MAC       (peelable multi-hop)")
        Console.WriteLine("=====================================================================")
        Console.WriteLine()

        Dim msg As String = "Hello Bob! Alice here - one channel secret, four cipher options."

        ' Standard AEADs are the recommended default for 2-party confidential messaging.
        RunCipher("FM1 (AES-256-GCM, FIPS)", msg,
                  Function(m) EncryptFM1(m, aliceResource, alicePassword, bobResource, bobSharedKey),
                  Function(c) DecryptFM1(c, bobResource, bobPassword, aliceSharedKey))

        RunCipher("CM1 (ChaCha20-Poly1305)", msg,
                  Function(m) EncryptCM1(m, aliceResource, alicePassword, bobResource, bobSharedKey),
                  Function(c) DecryptCM1(c, bobResource, bobPassword, aliceSharedKey))

        ' SM1: AES-256-GCM-SIV — nonce-misuse-resistant option for very high-volume channels.
        RunCipher("SM1 (AES-256-GCM-SIV, misuse-resistant)", msg,
                  Function(m) EncryptSM1(m, aliceResource, alicePassword, bobResource, bobSharedKey),
                  Function(c) DecryptSM1(c, bobResource, bobPassword, aliceSharedKey))

        ' EM1: keystream + Encrypt-then-MAC — built for the peelable multi-hop case.
        RunCipher("EM1 (SHAKE-256 keystream + Encrypt-then-MAC)", msg,
                  Function(m) EncryptMessageUsingSharedKey(m, aliceResource, alicePassword, bobResource, bobSharedKey),
                  Function(c) DecryptMessageUsingSharedKey(c, bobResource, bobPassword, aliceSharedKey))

        Console.WriteLine("=====================================================================")
        Console.WriteLine(" Demo complete: same CS, four ciphers, all round-trip + tamper-reject.")
        Console.WriteLine("=====================================================================")
    End Sub

End Module
