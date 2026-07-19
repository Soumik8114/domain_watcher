#!/usr/bin/env python3
"""
domain_watch.py — CLI tool to detect fake/lookalike domains impersonating
a real organization's domain.

Usage:
    python domain_watch.py acme.com
    python domain_watch.py acme.com acmecorp.io          # multiple domains
    python domain_watch.py acme.com --min-score 30       # only show riskier hits
    python domain_watch.py acme.com --json out.json      # also save raw JSON

What it does:
    1. Generates typosquat/lookalike permutations of the domain(s) you give it
       (character swaps, omissions, homoglyphs, TLD swaps, hyphenation, etc.)
    2. Checks which of those permutations actually resolve on the internet
    3. For each one that resolves: looks up WHOIS registration info
    4. Scores each candidate by how suspicious it looks
    5. Prints a ranked table to your terminal

Setup:
    pip install dnstwist python-whois python-Levenshtein tabulate

Requires the `dnstwist` CLI to be on PATH (installed automatically via pip).
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta

try:
    import whois
except ImportError:
    print("Missing dependency. Run: pip install dnstwist python-whois python-Levenshtein tabulate")
    sys.exit(1)

try:
    import Levenshtein
except ImportError:
    Levenshtein = None

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None


def generate_candidates(domain: str) -> list[dict]:
    """Run dnstwist CLI and return only candidates that actually resolve."""
    try:
        command = ["dnstwist", "--registered", "--format", "json", domain]
        print("[*] Generating candidate domains with dnstwist...", flush=True)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        start_time = time.monotonic()
        last_progress = start_time
        stdout, stderr = "", ""

        while True:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                break

            now = time.monotonic()
            if now - last_progress >= 5:
                elapsed = int(now - start_time)
                print(f"[*] dnstwist still working... {elapsed}s elapsed", flush=True)
                last_progress = now

            time.sleep(0.2)
    except FileNotFoundError:
        print("dnstwist not found on PATH. Install with: pip install dnstwist")
        sys.exit(1)

    if process.returncode != 0:
        print(f"dnstwist failed for {domain}:\n{stderr}")
        return []

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        print(f"Could not parse dnstwist output for {domain}")
        return []


def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return {"registrar": w.registrar, "creation_date": creation_date}
    except Exception:
        return {"registrar": None, "creation_date": None}


def is_recently_registered(creation_date, days: int = 90) -> bool:
    if not creation_date:
        return False
    try:
        return datetime.utcnow() - creation_date < timedelta(days=days)
    except TypeError:
        return False


def score_candidate(*, registered_recently: bool, edit_distance: int, fuzzer: str) -> int:
    """Simple 0-100 heuristic score. Tune weights as you see real results."""
    score = 15  # baseline: it resolves at all

    if registered_recently:
        score += 30  # brand-new domain mimicking an established brand = strong signal

    if edit_distance <= 2:
        score += 25  # very close typo of the real domain
    elif edit_distance <= 4:
        score += 12

    if fuzzer in ("homoglyph", "bitsquatting", "subdomain"):
        score += 10  # these fuzzers tend to produce more deliberate-looking fakes

    return min(score, 100)


def scan_domain(domain: str, min_score: int) -> list[dict]:
    print(f"\n[*] Scanning for lookalikes of: {domain}", flush=True)
    candidates = generate_candidates(domain)
    print(f"[*] {len(candidates)} registered/resolving candidate(s) found.", flush=True)

    if candidates:
        print("[*] Generated candidate domains:", flush=True)
        for index, candidate in enumerate(candidates, start=1):
            candidate_domain = candidate.get("domain", "unknown")
            fuzzer = candidate.get("fuzzer", "unknown")
            print(f"    {index:>3}. {candidate_domain} ({fuzzer})", flush=True)

    print("[*] Checking WHOIS and scoring candidates...", flush=True)

    rows = []
    total_candidates = len(candidates)
    for index, c in enumerate(candidates, start=1):
        candidate_domain = c.get("domain")
        if not candidate_domain or candidate_domain == domain:
            continue

        print(
            f"    -> [{index}/{total_candidates}] Checking {candidate_domain} ({c.get('fuzzer', 'unknown')})",
            flush=True,
        )

        whois_info = get_whois_info(candidate_domain)
        recently_registered = is_recently_registered(whois_info["creation_date"])
        edit_distance = Levenshtein.distance(domain, candidate_domain) if Levenshtein else -1

        score = score_candidate(
            registered_recently=recently_registered,
            edit_distance=edit_distance,
            fuzzer=c.get("fuzzer", ""),
        )

        if score < min_score:
            print(f"       skipped: score {score} below threshold {min_score}", flush=True)
            continue

        print(f"       matched: score {score}", flush=True)

        rows.append({
            "original_domain": domain,
            "fake_domain": candidate_domain,
            "risk_score": score,
            "fuzzer": c.get("fuzzer"),
            "dns_a": c.get("dns_a"),
            "registrar": whois_info["registrar"],
            "registered": str(whois_info["creation_date"]) if whois_info["creation_date"] else "unknown",
            "recently_registered": recently_registered,
        })

    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows


def print_results(all_rows: list[dict]):
    if not all_rows:
        print("\nNo suspicious domains found above the score threshold.")
        return

    print(f"\n=== {len(all_rows)} suspicious domain(s) found ===\n")
    table_data = [
        [r["risk_score"], r["original_domain"], r["fake_domain"], r["fuzzer"],
         r["registrar"] or "-", "yes" if r["recently_registered"] else "-"]
        for r in all_rows
    ]
    headers = ["Score", "Real Domain", "Fake Domain", "Technique", "Registrar", "New Reg?"]

    if tabulate:
        print(tabulate(table_data, headers=headers, tablefmt="simple"))
    else:
        print("\t".join(headers))
        for row in table_data:
            print("\t".join(str(x) for x in row))


def main():
    parser = argparse.ArgumentParser(description="Detect fake/lookalike domains impersonating your real domain(s).")
    parser.add_argument("domains", nargs="+", help="One or more real domains to protect, e.g. acme.com")
    parser.add_argument("--min-score", type=int, default=0, help="Only show candidates scoring at least this (0-100)")
    parser.add_argument("--json", metavar="FILE", help="Also save full results as JSON to this file")
    args = parser.parse_args()

    all_rows = []
    for domain in args.domains:
        all_rows.extend(scan_domain(domain, args.min_score))

    print_results(all_rows)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_rows, f, indent=2, default=str)
        print(f"\nFull results saved to {args.json}")


if __name__ == "__main__":
    main()
