#!/usr/bin/env python3
"""CyberShield Toolkit - a small defensive cybersecurity CLI.

Features:
  1. password-check : strength analysis (entropy, common passwords, patterns)
  2. password-gen   : cryptographically secure password generator
  3. hash           : SHA-256 / SHA-512 / MD5 checksum of a file
  4. integrity-init / integrity-verify : file integrity monitoring (FIM)
  5. log-analyze    : detect SSH brute-force attempts in auth logs
"""
import argparse
import hashlib
import json
import math
import os
import re
import secrets
import string
import sys
from collections import Counter, defaultdict

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "dragon", "111111", "123123", "password1",
    "qwerty123", "football", "login", "passw0rd", "master", "sunshine",
}

# ---------------------------------------------------------------- passwords
def analyze_password(pw: str) -> dict:
    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw): pool += 10
    if re.search(r"[^\w\s]", pw): pool += 32
    entropy = len(pw) * math.log2(pool) if pool else 0.0

    issues = []
    if len(pw) < 12: issues.append("Use at least 12 characters")
    if not re.search(r"[a-z]", pw): issues.append("Add lowercase letters")
    if not re.search(r"[A-Z]", pw): issues.append("Add uppercase letters")
    if not re.search(r"\d", pw): issues.append("Add digits")
    if not re.search(r"[^\w\s]", pw): issues.append("Add symbols (!@#$...)")
    if pw.lower() in COMMON_PASSWORDS:
        issues.append("This is a very common password"); entropy = min(entropy, 10)
    if re.search(r"(.)\1{2,}", pw): issues.append("Avoid repeated characters (aaa)")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", pw.lower()):
        issues.append("Avoid sequences like 1234 / abcd / qwer")

    if entropy < 28: label = "VERY WEAK"
    elif entropy < 36: label = "WEAK"
    elif entropy < 60: label = "MEDIUM"
    elif entropy < 80: label = "STRONG"
    else: label = "VERY STRONG"
    return {"length": len(pw), "entropy_bits": round(entropy, 1),
            "strength": label, "suggestions": issues}


def generate_password(length=16, symbols=True) -> str:
    alphabet = string.ascii_letters + string.digits + (string.punctuation if symbols else "")
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)
                and (not symbols or any(c in string.punctuation for c in pw))):
            return pw

# ------------------------------------------------------------------ hashing
def hash_file(path: str, algo="sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------- integrity
def build_baseline(directory: str) -> dict:
    baseline = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            if os.path.abspath(full) == os.path.abspath(os.path.join(directory, "baseline.json")):
                continue
            try:
                baseline[os.path.relpath(full, directory)] = hash_file(full)
            except OSError:
                pass
    return baseline


def compare_baseline(old: dict, new: dict) -> dict:
    return {
        "modified": sorted(k for k in old if k in new and old[k] != new[k]),
        "deleted": sorted(k for k in old if k not in new),
        "added": sorted(k for k in new if k not in old),
    }

# ------------------------------------------------------------- log analysis
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


def analyze_log(path: str, threshold: int = 5) -> dict:
    per_ip, users = Counter(), defaultdict(set)
    with open(path, errors="ignore") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                per_ip[m["ip"]] += 1
                users[m["ip"]].add(m["user"])
    suspicious = [{"ip": ip, "failed_attempts": n, "usernames_tried": sorted(users[ip])}
                  for ip, n in per_ip.most_common() if n >= threshold]
    return {"total_failed": sum(per_ip.values()), "unique_ips": len(per_ip),
            "threshold": threshold, "suspicious": suspicious}

# --------------------------------------------------------------------- CLI
def main(argv=None):
    p = argparse.ArgumentParser(prog="cybershield", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("password-check", help="check password strength")
    s.add_argument("password")
    s = sub.add_parser("password-gen", help="generate a secure password")
    s.add_argument("-l", "--length", type=int, default=16)
    s.add_argument("--no-symbols", action="store_true")
    s = sub.add_parser("hash", help="hash a file")
    s.add_argument("file"); s.add_argument("-a", "--algo", default="sha256",
                                           choices=["md5", "sha256", "sha512"])
    s = sub.add_parser("integrity-init", help="create baseline of a directory")
    s.add_argument("directory")
    s = sub.add_parser("integrity-verify", help="verify directory against baseline")
    s.add_argument("directory")
    s = sub.add_parser("log-analyze", help="detect SSH brute-force in auth log")
    s.add_argument("logfile"); s.add_argument("-t", "--threshold", type=int, default=5)

    a = p.parse_args(argv)

    if a.cmd == "password-check":
        r = analyze_password(a.password)
        print(f"Length   : {r['length']}\nEntropy  : {r['entropy_bits']} bits\nStrength : {r['strength']}")
        for t in r["suggestions"]: print(f"  - {t}")
    elif a.cmd == "password-gen":
        print(generate_password(a.length, not a.no_symbols))
    elif a.cmd == "hash":
        print(f"{a.algo}: {hash_file(a.file, a.algo)}")
    elif a.cmd == "integrity-init":
        b = build_baseline(a.directory)
        with open(os.path.join(a.directory, "baseline.json"), "w") as f:
            json.dump(b, f, indent=2)
        print(f"Baseline saved for {len(b)} files.")
    elif a.cmd == "integrity-verify":
        with open(os.path.join(a.directory, "baseline.json")) as f:
            old = json.load(f)
        r = compare_baseline(old, build_baseline(a.directory))
        for k in ("modified", "deleted", "added"):
            for item in r[k]: print(f"[{k.upper()}] {item}")
        if not any(r.values()): print("OK: no changes detected.")
        else: sys.exit(1)
    elif a.cmd == "log-analyze":
        r = analyze_log(a.logfile, a.threshold)
        print(f"Failed logins: {r['total_failed']} from {r['unique_ips']} IPs")
        if not r["suspicious"]: print("No suspicious IPs.")
        for s in r["suspicious"]:
            print(f"[ALERT] {s['ip']} -> {s['failed_attempts']} attempts, users: {', '.join(s['usernames_tried'])}")


if __name__ == "__main__":
    main()
