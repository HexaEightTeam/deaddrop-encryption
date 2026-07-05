# Live LoginToken Sample — Deliberately Published for Review

This file contains a **real, live** HexaEight identity credential set, published on purpose so
reviewers can scrutinize the authentication model directly rather than take our word for it.

> **This is an invitation, not a leak.** We are handing you a production LoginToken and its
> SECRET for one identity. If the model is what we claim, having these does not let you
> impersonate this identity from your machine, read its traffic, or mint its keys. If we are
> wrong, this is exactly the material you need to prove it. Please try.

---

## The credential set (identity: `web0-bliss-cyan-radar84`)

```
HEXAEIGHT_RESOURCENAME = web0-bliss-cyan-radar84            (public identity name)

HEXAEIGHT_MACHINETOKEN = <the LoginToken>                   (see below — opaque ciphertext)

HEXAEIGHT_SECRET       = pwZJvhAdf0@VhIJEc5wz02GqqAXEXcmjzmebVKUsY2Z0sTazmIIfzvx

HEXAEIGHT_LICENSECODE  = dmNS.5

hexaeight.mac          = 472E44A2-F3EE-4763-AA71-9E8A5E023A1B   (device-binding GUID)
```

**LoginToken (`HEXAEIGHT_MACHINETOKEN`):**

```
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.egZNQ59lCM2CFupVYMBT+CQCd7c+Jw6OHTvdCOVyLW8xXuiPZ/jG0DdN/Agk3BhGXmywLPasbdjUJZ78eepsxAqkPFoMIvbeaibY+LJ70IyLgkIYQJev36J0sQVQ9iGy+60EBj5kASO6HoLFlfDv9J/Mw/pVowHBP/We9leMTWygP03xPW6q+b7Zrk6fAL5OF1gC9tPHpUQgH1bulkFfEnXQj0F4li08tXg4+VN8Burz67dQje6wo54tv8baJCm0+KxSLbGeYiVkFJxD7g7tk+HYSt52Fn+zF6EhJ0O2JWffTnCMDr+6OITL62NZoJaXvASkVMJAfhY7EP4dhHCIrkTdMDXBEmQPuQ1G9TvSjj+cp5MuYRAoXgi17aRyfe4uGNNijArefJkWUmzkdn861/vOso0Fj7YTXJVOeXBglFHGQQ5ovcQ4Ya29P8GkjxF/5ZwDOo5LieJubjNnaDSe8Fsikzz4y/frTRlmadRiuXRt3PU50DKeq+JWO2RIPkE3E+VCjbdqb5Faw4labvjV80ttQPFUUBWk8sxA+PI0msCiOEDdv/v1pFq/NALa2ZjvtwQrN7mse4USrqS6V7hSAg==:EWaggPhmaIkXyNAfoSwkkSyp4NqWx3s2qBPIZn88D8Ya7wfST5itg3rvtQ3R38Pr4wHAGWR7H7HB61qmwX3i3Gx1yFqxa2B4oqKiGakROfJTPsnoRpq1uen1tU8cpDaY6b/4pLqSydpG61ARNyy5QDZRpnZLJBNH66jFsgIqJIUKmdWIfeZP1m4QOuRftVEmWEvYXyRXNUWw2J5eMo5PqFwrwcIFGL8gu6uHzOFGw6qL7e9IGaqVLYnDjhjkPXl/pp5clJ8bBkXjpNZrJ2131JOZ8LZAELZISz1AS2TLUwhzACWY4/iEpHbnGu0bxsZyEzu1asjGEE2vdvvHmTJmHvUal9bOG/+D1dmmKPdWpDCUT9uy/M27pREcn91riNXcf1pjGOuTdweQWwYu5C88UkxexVDrky8t6LKzDdUT9PzVMBIzCg/TjT4177A6AYdlMwTb5+x5bPu8ZaJTbFl2O0REQzfl/Mo60D1K3S/5rD0koGWDh/rS+rQJq7nypxs2E+VCjbdqb5Faw4labvjV80ttQPFUUBWk8sxA+PI0msCiOEDdv/v1pFq/NALa2ZjvtwQrN7mse4USrqS6V7hSAg==
```

---

## Structural scrutiny (what the token actually is)

Decoded, the LoginToken is **opaque, high-entropy ciphertext** — not a readable bearer token:

| Property | Finding |
|---|---|
| Format | `BLOB_A . BLOB_B : BLOB_C` (colon + dot delimited) |
| Sizes | `BLOB_A` = 1632 bytes · `BLOB_B` = 448 bytes · `BLOB_C` = 448 bytes |
| Content | ~40% printable bytes → indistinguishable from random; **no cleartext JSON, no readable claims** |
| Key material | **None in the clear.** There is no password-derived key, no channel secret, nothing to lift out by decoding |

Contrast with an OAuth/JWT bearer token, whose payload is Base64URL cleartext you can read and
often replay. This token carries no readable authorization payload to extract.

---

## Why this is safe to publish — and exactly what to attack

Three independent properties should stop a holder of this token+SECRET:

1. **Device + license binding.** The credential is bound to this host via `hexaeight.mac`
   (device GUID `472E44A2-…`) and `LICENSECODE`. The licensed client only issues usable key
   material on the machine it is bound to. Copy the token + SECRET to a different host and the
   binding no longer matches.

2. **Proof of possession, not bearer auth.** Presenting the LoginToken is **not sufficient** to
   authenticate. Every authenticated request must be **encrypted with the identity's
   password-derived keys**, which are re-derived locally and never transmitted. A stolen token
   with no on-device key material cannot produce a valid request — so it cannot be replayed.

3. **The platform is a semi-trusted broker — not in the data path.** Message encryption/decryption happen
   entirely on the client from the locally-derived channel secret; the encrypt/decrypt code makes
   no call to the platform (it is contacted only at setup for key material). Data flows
   peer-to-peer as ciphertext. CS also requires client-held material (`TokenSecret`) that never
   leaves the device, so the transport never transmits CS and does not leak it through ciphertexts;
   whether the network or another identity can *compute* CS is governed by the out-of-scope
   derivation (verifiable from `AliceBobDemo.vb`, `ChannelSecretBytes`). The enrollment internals
   are a proprietary boundary and out of scope for this token sample.

### What to scrutinize

We are not asking anyone to attack our infrastructure — just to examine the token itself:

- **[Decode]** Decode the LoginToken. Does it expose any readable identity claims, or any
  password-derived key or channel-secret material in the clear?
- **[Extraction]** By analysis of the token + SECRET alone, can you recover any key material or
  the channel secret for this identity?
- **[Model]** Given the structure, assess the design: the credential is host-bound and an
  authenticated request additionally requires proving possession of on-device key material, so
  it is not a bearer token. Does anything about the token reduce to a bearer credential?

---

## Notes for the reviewer

- These are **live** values for a real identity we control, published intentionally for this
  review. They are not sanitized or fabricated.
- This complements the open cipher demo (`AliceBobDemo.vb`) and its *Registration & Trust
  Model* header: that explains the model; this lets you test it against a real credential.
- The password-derived keys and the channel secret are **not** in this file — by design they
  never leave the device. But security does not rely on hiding them here: the token and SECRET
  are public precisely because that alone should not be enough to break anything.
