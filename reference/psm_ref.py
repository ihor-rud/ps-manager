#!/usr/bin/env python3
"""Independent reference implementation of ps-manager/v1 (spec/SPEC-v1.md).

Written from the specification, not from the Rust code, so that the two can
check each other. Requires only the Python standard library plus the
`cryptography` package (for Argon2id, which uses OpenSSL's implementation).

    python3 reference/psm_ref.py verify spec/vectors-v1.json
    python3 reference/psm_ref.py generate github.com [--account A] [--generation N]
                                 [--profile P] [--length L] [--identity I]
"""

import argparse
import getpass
import hashlib
import hmac
import json
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Section 4.1: U+0009..U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000..U+200A,
# U+2028, U+2029, U+202F, U+205F, U+3000.
WS = frozenset(
    "\t\n\x0b\x0c\r \x85\xa0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)

# Section 9
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT = "0123456789"
SYMBOL = "!#$%&*+-=?@^_"
SYMBOL_BASIC = "!@#$%^&*"


class Profile(NamedTuple):
    classes: tuple[str, ...]
    default_length: int
    min_length: int
    max_length: int


PROFILES: dict[str, Profile] = {
    "standard": Profile((LOWER, UPPER, DIGIT, SYMBOL), 24, 8, 64),
    "alphanumeric": Profile((LOWER, UPPER, DIGIT), 24, 8, 64),
    "legacy": Profile((LOWER, UPPER, DIGIT, SYMBOL_BASIC), 16, 8, 64),
    "pin": Profile((DIGIT,), 6, 4, 64),
}

FINGERPRINT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
MAX_GENERATION = 0xFFFFFFFF


def u32be(n: int) -> bytes:
    return struct.pack(">I", n)


def lp(data: str | bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return u32be(len(data)) + data


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


# Section 4.2
def normalize_text(x: str) -> str:
    x = unicodedata.normalize("NFKC", x)
    # Lowercase each code point on its own: no Final_Sigma context.
    x = "".join(c.lower() for c in x)
    x = unicodedata.normalize("NFKC", x)
    out: list[str] = []
    pending_space = False
    for c in x:
        if c in WS:
            pending_space = bool(out)
        else:
            if pending_space:
                out.append(" ")
                pending_space = False
            out.append(c)
    return "".join(out)


def strip_ws(x: str) -> str:
    start, end = 0, len(x)
    while start < end and x[start] in WS:
        start += 1
    while end > start and x[end - 1] in WS:
        end -= 1
    return x[start:end]


# Section 4.3
def normalize_site(x: str) -> str:
    x = normalize_text(x)
    i = x.find("://")
    if i >= 0:
        x = x[i + 3 :]
    cuts = [i for i in (x.find("/"), x.find("?"), x.find("#")) if i >= 0]
    if cuts:
        x = x[: min(cuts)]
    i = x.rfind("@")
    if i >= 0:
        x = x[i + 1 :]
    i = x.rfind(":")
    if i >= 0 and all(c in DIGIT for c in x[i + 1 :]):
        x = x[:i]
    x = strip_ws(x)
    x = x.rstrip(".")
    if x.startswith("www.") and len(x) > len("www."):
        x = x[len("www.") :]
    return x


# Section 4.4
def normalize_secret(x: str) -> str:
    return unicodedata.normalize("NFC", x)


# Section 5
def salt(identity: str) -> bytes:
    identity = normalize_text(identity)
    if not identity:
        msg = "identity is empty"
        raise ValueError(msg)
    return hashlib.sha256(lp("ps-manager/v1/salt") + lp(identity)).digest()


def root_key(identity: str, secret: str) -> bytes:
    secret = normalize_secret(secret)
    if not secret:
        msg = "master secret is empty"
        raise ValueError(msg)
    kdf = Argon2id(
        salt=salt(identity),
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536,
        ad=None,
        secret=None,
    )
    return kdf.derive(secret.encode("utf-8"))


# Section 6
def fingerprint(k_root: bytes) -> str:
    f = hmac_sha256(k_root, lp("ps-manager/v1/fingerprint"))
    return "".join(FINGERPRINT_ALPHABET[b % 32] for b in f[:4])


def resolve_length(profile: str, length: int | None) -> int:
    p = PROFILES[profile]
    length = p.default_length if length is None else length
    if not p.min_length <= length <= p.max_length:
        msg = (
            f"length {length} is outside {p.min_length}..{p.max_length} "
            f"for profile {profile}"
        )
        raise ValueError(msg)
    return length


# Section 7
def site_key(
    k_root: bytes,
    site: str,
    account: str,
    generation: int,
    profile: str,
    length: int,
) -> bytes:
    site = normalize_site(site)
    if not site:
        msg = "site is empty after normalization"
        raise ValueError(msg)
    if not 1 <= generation <= MAX_GENERATION:
        msg = f"generation must be in 1..{MAX_GENERATION}"
        raise ValueError(msg)
    message = (
        lp("ps-manager/v1/site")
        + lp(site)
        + lp(normalize_text(account))
        + u32be(generation)
        + lp(profile)
        + u32be(length)
    )
    return hmac_sha256(k_root, message)


# Section 8
class Stream:
    def __init__(self, k_site: bytes) -> None:
        self.k_site = k_site
        self.block = b""
        self.pos = 0
        self.i = 0
        self.rejected_bytes = 0

    def byte(self) -> int:
        if self.pos == len(self.block):
            message = lp("ps-manager/v1/stream") + u32be(self.i)
            self.block = hmac_sha256(self.k_site, message)
            self.i += 1
            self.pos = 0
        b = self.block[self.pos]
        self.pos += 1
        return b

    def uniform(self, n: int) -> int:
        limit = 256 - (256 % n)
        while True:
            b = self.byte()
            if b < limit:
                return b % n
            self.rejected_bytes += 1


class Password(NamedTuple):
    value: str
    attempts: int
    rejected_bytes: int


# Section 10
def password(
    k_root: bytes,
    site: str,
    account: str = "",
    generation: int = 1,
    profile: str = "standard",
    length: int | None = None,
) -> Password:
    length = resolve_length(profile, length)
    classes = PROFILES[profile].classes
    alphabet = "".join(classes)
    stream = Stream(site_key(k_root, site, account, generation, profile, length))
    attempts = 0
    while True:
        attempts += 1
        p = "".join(alphabet[stream.uniform(len(alphabet))] for _ in range(length))
        if all(any(c in cls for c in p) for cls in classes):
            return Password(p, attempts, stream.rejected_bytes)


def verify(path: str) -> None:
    v: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    failures = 0

    def check(label: str, actual: object, expected: object) -> None:
        nonlocal failures
        if actual != expected:
            failures += 1
            print(f"FAIL {label}: expected {expected!r}, got {actual!r}")

    if v["algorithm"] != "ps-manager/v1":
        sys.exit(f"unexpected algorithm {v['algorithm']!r}")
    functions = {
        "text": normalize_text,
        "site": normalize_site,
        "secret": normalize_secret,
    }
    for case in v["normalization"]:
        f = functions[case["function"]]
        label = f"{case['function']}({case['input']!r})"
        check(label, f(case["input"]), case["output"])

    passwords = retried = byte_rejections = 0
    for root in v["roots"]:
        identity: str = root["identity"]
        label = repr(identity)
        check(
            f"identity {label}", normalize_text(identity), root["normalized_identity"]
        )
        check(f"salt {label}", salt(identity).hex(), root["salt"])
        k_root = root_key(identity, root["secret"])
        check(f"root key {label}", k_root.hex(), root["root_key"])
        check(f"fingerprint {label}", fingerprint(k_root), root["fingerprint"])
        for case in root["passwords"]:
            site: str = case["site"]
            account: str = case["account"]
            generation: int = case["generation"]
            profile: str = case["profile"]
            length: int = case["length"]
            label = f"{identity!r} {(site, account, generation, profile, length)}"
            check(f"site {label}", normalize_site(site), case["normalized_site"])
            check(
                f"account {label}",
                normalize_text(account),
                case["normalized_account"],
            )
            key = site_key(k_root, site, account, generation, profile, length)
            check(f"site key {label}", key.hex(), case["site_key"])
            p = password(k_root, site, account, generation, profile, length)
            check(f"password {label}", p.value, case["password"])
            passwords += 1
            retried += p.attempts > 1
            byte_rejections += p.rejected_bytes > 0

    print(
        f"{len(v['normalization'])} normalization cases, {len(v['roots'])} root keys, "
        f"{passwords} passwords ({retried} needed a second attempt, "
        f"{byte_rejections} rejected a stream byte)",
    )
    if failures:
        sys.exit(f"{failures} mismatches")
    print("all vectors match")


def generate(args: argparse.Namespace) -> None:
    identity: str = args.identity if args.identity is not None else input("Identity: ")
    secret = getpass.getpass("Master secret: ")
    k_root = root_key(identity, secret)
    print(f"fingerprint {fingerprint(k_root)}", file=sys.stderr)
    p = password(
        k_root,
        args.site,
        args.account,
        args.generation,
        args.profile,
        args.length,
    )
    print(p.value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reference implementation of ps-manager/v1",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="check a test-vector file")
    v.add_argument("path")
    g = sub.add_parser("generate", help="derive a password")
    g.add_argument("site")
    g.add_argument("--account", default="")
    g.add_argument("--generation", type=int, default=1)
    g.add_argument("--profile", default="standard", choices=PROFILES)
    g.add_argument("--length", type=int)
    g.add_argument("--identity")
    args = parser.parse_args()
    if args.command == "verify":
        verify(args.path)
    else:
        generate(args)


if __name__ == "__main__":
    main()
