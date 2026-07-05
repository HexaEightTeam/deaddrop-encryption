# HexaEight Dead Drop Encryption — Test Vectors

Deterministic vectors for cross-language reproducibility of the client transport.
Encrypt-side (Alice -> Bob), fixed nonce, fixed raw plaintext (the JSON envelope's
random GUID padding is a separate non-deterministic step and is omitted here so the
cipher core is exactly reproducible). All values are lowercase hex.

## Key schedule
| value | hex |
|-------|-----|
| canonical CS  be(CS)          | 1d6fcd3e5cc5d5eb9e5fbb7d4f3cb9c0fd7820f2532d6b40d1114fd4f03821fecb0ec609eca3ed3bdce8914a57235ea45827ebde831c1805d1daf5c640f03082860c6f5bf899ecc70f7d90fcb34c4d8a2ed8364c515b0e1e62a708571aa68358fef3df58f0e2ab50588ff191bcfd3dab703519a5cb8b1c41015a33eef1a1d547e8f852e3b4b5eaf8914913269701a1df926f01043f0eb3325f102d7b24f0b3 |
| PRK = KMAC(salt, be(CS))      | e371b19109dddf15178b0de512f4acd8f6cc8a590800e1a02d75fa877fa4336f |
| k_enc = KMAC(PRK, HE-enc-v1)   | 7af3d7c72c0c094dd68dc7514a76e0d6dbff590210d44e3d4e7f90948f54e8b5 |
| k_mac = KMAC(PRK, HE-mac-v1)   | 371e84b24ab54a3ad8f260b683da2d05cbad51e83f6d8455b578da920327297c |
| k_aes = KMAC(PRK, HE-aes-v1)   | 159ae0542980a18200a95bc6946100a347b1694c90b1c5ed72639f14d20d3acb |
| k_cha = KMAC(PRK, HE-cha-v1)   | 0fee75aed11012a38d00ba17da69de3418a019556ba76cac29a110a57606a837 |
| k_siv = KMAC(PRK, HE-siv-v1)   | 7de7fda0e707033a948cdb4121b6359b30439d1b89809e8a0aaf7d6069bd7334 |

## Message inputs
| value | hex |
|-------|-----|
| plaintext (utf-8)             | 48657861456967687420444445207465737420766563746f722030303031 |
| nonce (16-byte, .EM1)         | 000102030405060708090a0b0c0d0e0f |
| nonce (12-byte, AEADs)        | 000102030405060708090a0b |

## Cipher outputs
| cipher | ciphertext (hex) | tag (hex) |
|--------|------------------|-----------|
| .EM1 (SHAKE keystream + KMAC EtM) | 1ed41754a5ad0b7c9cec365e40d7a4f8a88c37c6ac9226f47876558099e9 | f91a5d2307b062815552c508940d1071849d312a113924dba8fe66d9d0c14364 |
| .FM1 (AES-256-GCM)               | 3a63644ab68289b8d772ad34242809b41b07ee169d875dd39b526194cd87 | d437ccfe72e2573ead6e405c845bd267 |
| .CM1 (ChaCha20-Poly1305)         | 3f9af1afc4cfa2184a06b7f4e00ff2adfac4ffa70c8388bfcedaf72ec96f | aa29531379fe2b4ae8dc552620d261ab |
| .SM1 (AES-256-GCM-SIV)           | b3c285036f94372ce0d0d15423f958b3f6d2e192efbd962f5ee92c12fa0a | 3f2ddaf40b2bdf2dddbf10661a9139fe |

Notes: AEAD output = ciphertext(||)tag with a 16-byte (128-bit) tag; the marker string
(e.g. `.FM1`) is bound as associated data. The .EM1 tag is KMAC256(k_mac, marker||nonce||ct).
