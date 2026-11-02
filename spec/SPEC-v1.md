# ps-manager password derivation: algorithm version 1

**Status: DRAFT.** This document may still change until it is marked *Frozen*.
Once frozen, nothing in it changes: any change to inputs, normalization,
cryptographic operations or output encoding requires a new algorithm version
(v2) with its own specification and test vectors, and v1 stays available
indefinitely.

## 1. Purpose

Given a memorized master secret and a few facts the user already knows about an
account, reproduce the same password on any device, with no stored state. This
document defines the computation precisely enough that an independent
implementation produces byte-identical output.

## 2. Notation

| Notation | Meaning |
|---|---|
| `\|\|` | Byte-string concatenation |
| `u32be(n)` | `n` as a 4-byte unsigned big-endian integer |
| `lp(s)` | `u32be(len(s)) \|\| s`, where `s` is a byte string (text is UTF-8 encoded first) and `len` counts bytes |
| `SHA-256(m)` | SHA-256 (FIPS 180-4) |
| `HMAC(k, m)` | HMAC-SHA-256 (RFC 2104) with key `k` and message `m`; 32-byte output |
| `"..."` | An ASCII string literal, encoded as its bytes |

All text is processed as sequences of Unicode code points and encoded as UTF-8
(without BOM) when converted to bytes.

## 3. Inputs

| Input | Description | Normalization | Constraint |
|---|---|---|---|
| `identity` | A fixed personal string, e.g. the user's full name. Acts as the Argon2 salt so that guessing work cannot be shared across users. | `NormalizeText` | non-empty after normalization |
| `secret` | The master secret (passphrase). | `NormalizeSecret` | non-empty after normalization |
| `site` | The website or service, e.g. `github.com`. URLs are accepted. | `NormalizeSite` | non-empty after normalization |
| `account` | Distinguishes several accounts on one site, e.g. a login name. Optional. | `NormalizeText` | may be empty (the default) |
| `generation` | Rotation counter; increment to change one password. | - | integer, `1 <= generation <= 4294967295`, default `1` |
| `profile` | Password policy name (section 9). | - | one of the v1 profile names, default `standard` |
| `length` | Password length in characters. | - | within the profile's range, default is the profile's default |

Each normalized field must be shorter than 2^32 bytes.

## 4. Normalization

### 4.1 White space

`WS` is the following fixed set of code points (the Unicode `White_Space`
property as of Unicode 16.0, frozen here so that later Unicode versions cannot
change v1):

```
U+0009..U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000..U+200A,
U+2028, U+2029, U+202F, U+205F, U+3000
```

### 4.2 NormalizeText(x)

1. `x := NFKC(x)`
2. Replace every code point `c` of `x` by its Unicode **full lowercase mapping**,
   applied to each code point independently: unconditional mappings from
   `UnicodeData.txt` and `SpecialCasing.txt`; no language-specific rules; no
   context-sensitive rules (in particular, no Final_Sigma: U+03A3 always
   becomes U+03C3). Example: U+0130 becomes U+0069 U+0307.
3. `x := NFKC(x)`
4. Remove all leading and trailing code points that are in `WS`.
5. Replace every maximal run of `WS` code points inside `x` by a single U+0020.

### 4.3 NormalizeSite(x)

1. `x := NormalizeText(x)`
2. If `x` contains `://`, remove everything up to and including the **first** `://`.
3. If `x` contains any of `/`, `?`, `#`, remove everything from the **first** such character to the end.
4. If `x` contains `@`, remove everything up to and including the **last** `@`.
5. If `x` contains `:` and every code point after the **last** `:` is an ASCII digit `0` to `9` (or there are none), remove everything from that last `:` to the end.
6. Remove all leading and trailing code points that are in `WS`.
7. Remove all trailing `.` characters.
8. If `x` starts with `www.` and has more than 4 code points, remove the first 4 code points.

Examples: `https://user@www.GitHub.com:443/login?next=/` -> `github.com`;
`example.com` written in fullwidth characters (U+FF45 U+FF58 ... with U+FF0E
as the dot) -> `example.com`; `www.` -> `www`.

NormalizeSite deliberately does **not** reduce host names to a registrable domain
(no Public Suffix List, which changes over time) and does **not** convert between
Unicode and Punycode (`xn--...`) forms. `accounts.example.com` and `example.com`
are different sites.

### 4.4 NormalizeSecret(x)

`x := NFC(x)`. Nothing else: case and white space are significant, and
compatibility characters are preserved.

### 4.5 Unicode versions

NFC, NFKC and case mappings are stable under the Unicode Stability Policy for
assigned characters. Implementations must support Unicode 16.0 or later. The
result for code points that are unassigned in the implementation's Unicode
version is not specified.

## 5. Root key

```
salt   = SHA-256( lp("ps-manager/v1/salt") || lp(NormalizeText(identity)) )
K_root = Argon2id( password = UTF-8(NormalizeSecret(secret)), salt = salt )
```

Argon2id (RFC 9106) with the following fixed parameters, the second
recommended option of RFC 9106 section 4:

| Parameter | Value |
|---|---|
| Variant | Argon2id (type 2) |
| Version | 0x13 |
| Memory `m` | 65536 KiB (64 MiB) |
| Passes `t` | 3 |
| Parallelism `p` | 4 |
| Tag length `T` | 32 bytes |
| Secret `K`, associated data `X` | empty |

The result does not depend on how many threads an implementation uses.

## 6. Fingerprint

A short, non-secret check value that lets the user notice a mistyped identity
or master secret (the system stores nothing to check against).

```
F           = HMAC( K_root, lp("ps-manager/v1/fingerprint") )
A           = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   (32 characters)
fingerprint = A[F[0] mod 32] || A[F[1] mod 32] || A[F[2] mod 32] || A[F[3] mod 32]
```

`F[i]` is the i-th byte of `F` (0-based); `A[j]` is the j-th character of `A`.
The fingerprint carries 20 bits about `K_root`.

## 7. Site key

```
K_site = HMAC( K_root,
               lp("ps-manager/v1/site")
             || lp(NormalizeSite(site))
             || lp(NormalizeText(account))
             || u32be(generation)
             || lp(profile)
             || u32be(length) )
```

`profile` is the profile name exactly as listed in section 9 (lowercase ASCII).
`length` is the actual length used, even when it equals the profile default.

## 8. Byte stream and uniform selection

The byte stream `R` is the infinite concatenation `B_0 || B_1 || B_2 || ...` where

```
B_i = HMAC( K_site, lp("ps-manager/v1/stream") || u32be(i) )
```

Bytes are consumed from `R` strictly in order, and no byte is used twice.

**Uniform(n)**, for `1 <= n <= 256`, returns an integer in `[0, n)` without bias:

```
limit = 256 - (256 mod n)
repeat:
    b = next byte of R
    if b < limit: return b mod n
```

## 9. Policy profiles

Character classes (each listed in its exact order):

| Class | Characters | Count |
|---|---|---|
| `LOWER` | `abcdefghijklmnopqrstuvwxyz` | 26 |
| `UPPER` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 26 |
| `DIGIT` | `0123456789` | 10 |
| `SYMBOL` | `!#$%&*+-=?@^_` | 13 |
| `SYMBOL_BASIC` | `!@#$%^&*` | 8 |

Profiles:

| Profile | Classes, in order | Alphabet size | Default length | Allowed lengths |
|---|---|---|---|---|
| `standard` | LOWER, UPPER, DIGIT, SYMBOL | 75 | 24 | 8-64 |
| `alphanumeric` | LOWER, UPPER, DIGIT | 62 | 24 | 8-64 |
| `legacy` | LOWER, UPPER, DIGIT, SYMBOL_BASIC | 70 | 16 | 8-64 |
| `pin` | DIGIT | 10 | 6 | 4-64 |

The profile's **alphabet** is the concatenation of its classes in the order given.

## 10. Password generation

```
alphabet = the profile's alphabet
repeat:
    P = empty
    repeat length times:
        P := P || alphabet[Uniform(len(alphabet))]
    if P contains at least one character from every class of the profile:
        return P
```

Every attempt continues consuming the same stream `R`; a rejected attempt is
discarded entirely. The output is uniformly distributed over all passwords of
the given length and alphabet that contain every class. The loop ends with
probability 1; for all v1 profiles the expected number of attempts is below 3.

The password is ASCII; its UTF-8 bytes equal its characters.

## 11. Versioning

- The identifier of this algorithm is `ps-manager/v1`. All domain-separation
  labels above contain it.
- An implementation must never switch algorithm versions implicitly. A future
  version is selected only by an explicit user choice.
- Adding a new profile in a later revision of v1 is allowed only if it leaves
  every existing profile's output unchanged; because the profile name is part
  of `K_site`, a new name does not affect existing ones.

## 12. Test vectors

`spec/vectors-v1.json` contains normalization cases, root keys, fingerprints,
site keys and passwords. A conforming implementation reproduces all of them.
`reference/psm_ref.py` is an independent implementation (Python standard
library plus the `cryptography` package for Argon2id) that checks the file.

## 13. Security notes (non-normative)

- `K_root` is as sensitive as the master secret. `K_site` and passwords reveal
  only their own account.
- Any derived password or the fingerprint allows offline guessing of the master
  secret; Argon2id makes each guess cost 64 MiB and three passes. The master
  secret must be strong enough on its own: assume an attacker knows the
  identity and this specification.
- A compromised device that sees the master secret compromises every derived
  password. Enter it only on trusted devices.
- Changing the master secret or identity changes every password. Migrate
  accounts individually while the old inputs still work.
