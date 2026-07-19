#!/usr/bin/env python3
"""Recall / precision benchmark for the secret scanner.

`secretscan.scan_text` is a classifier: every rule is a bet about what a real
leaked credential looks like. The only honest way to say one version is better
than another is to measure it against a labeled corpus — so this is that
corpus, plus a scorer that reports:

  * RECALL     — of the planted, realistic (fake) secrets, how many were found
  * PRECISION  — of the decoys (secret-SHAPED strings that are NOT credentials),
                 how many were correctly left alone

Every value here is fake: AWS's own documented example key, obviously-synthetic
`aaaa…` fills, and public test vectors. Nothing real is committed.

Run it directly for a human-readable report:  python3 tests/secret_bench.py
Import CORPUS_POSITIVE / CORPUS_DECOY / score() for the CI floor in unit.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from consoles.redcell import secretscan


# --------------------------------------------------------------------------
# Positives — a realistic (fake) credential in a realistic delivery context.
# `expect` is the substring a correct rule name should contain (case-insensitive),
# or None for "any rule firing on this is a hit" (the generic/entropy path).
# `ctx` documents the shape so a miss tells you WHICH real-world packaging beat
# the scanner, not just that something was missed.
# --------------------------------------------------------------------------
class P:
    __slots__ = ("cid", "text", "expect", "ctx")

    def __init__(self, cid, text, expect, ctx):
        self.cid, self.text, self.expect, self.ctx = cid, text, expect, ctx


A = "a" * 36
CORPUS_POSITIVE: list[P] = [
    # ---- cloud ----
    P("aws-akia", 'const k="AKIAIOSFODNN7EXAMPLE";', "aws access key", "js assignment"),
    P("aws-secret-ctx",
      'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', "aws secret", "named assignment"),
    P("gcp-sa", '{"type":"service_account","project_id":"x"}', "service-account", "inline json blob"),
    # ---- payments ----
    P("stripe-live", 'stripe="sk_live_' + "a" * 24 + '"', "stripe secret", "js assignment"),
    P("stripe-rk", 'k="rk_live_' + "b" * 24 + '"', "stripe restricted", "js assignment"),
    P("square", 'tok="sq0atp-' + "a" * 22 + '"', "square", "js assignment"),
    # ---- source control ----
    P("gh-classic", 'token: "ghp_' + A + '"', "github token", "json-ish"),
    P("gh-fpat", 'x="github_pat_' + "A" * 82 + '"', "fine-grained", "js assignment"),
    P("gitlab", 'x = "glpat-' + "a" * 20 + '"', "gitlab", "js assignment"),
    P("npm", 'x="npm_' + "A" * 36 + '"', "npm", "js assignment"),
    # ---- comms / email ----
    P("slack-tok", 'x="xoxb-123456789012-abcdefghijkl"', "slack token", "js assignment"),
    P("slack-hook",
      'url:"https://hooks.slack.com/services/T00000000/B00000000/' + "a" * 24 + '"', "slack webhook", "config url"),
    P("sendgrid", 'SG.' + "a" * 22 + '.' + "b" * 43, "sendgrid", "bare token"),
    # ---- AI ----
    P("openai", 'k="sk-' + "A" * 40 + '"', "openai", "js assignment"),
    P("anthropic", 'k="sk-ant-' + "x" * 30 + '"', "anthropic", "js assignment"),
    # ---- generic / structural ----
    P("privkey", '-----BEGIN RSA PRIVATE KEY-----', "private key", "pem header"),
    P("basic-auth", 'fetch("https://user:s3cretpass@api.example.com/x")', "basic-auth", "url creds"),
    P("bearer", 'headers:{Authorization:"Bearer ' + "A" * 32 + '"}', "bearer", "auth header"),
    P("generic-entropy", 'apiKey: "a8Fk2Lp9Qz3Xr7Vn1Bm4Cw6"', None, "named high-entropy assignment"),

    # ---- packaging the current scanner is known to struggle with (the gaps
    # this benchmark exists to close). These SHOULD eventually be recalled. ----
    P("json-apikey", '{"apiKey":"Ab3Xy9Kd7Qm2Wp5Rt8Zc1Nv4Bh6Jl0"}', None, "json key:value, no space"),
    P("bare-entropy-var",
      'const t="Zx9Kd7Qm2Wp5Rt8Zc1Nv4Bh6Jl0Ab3Xy";', None, "high-entropy value, innocuous var name"),
    P("query-param",
      'fetch("/v1/data?api_key=Ab3Xy9Kd7Qm2Wp5Rt8Zc1Nv4Bh6Jl0")', None, "secret in url query param"),
]


# --------------------------------------------------------------------------
# Decoys — secret-SHAPED strings that must NOT be reported (or must land as
# low/public), because crying wolf is what makes a scan report unusable.
# --------------------------------------------------------------------------
class D:
    __slots__ = ("cid", "text", "ctx")

    def __init__(self, cid, text, ctx):
        self.cid, self.text, self.ctx = cid, text, ctx


CORPUS_DECOY: list[D] = [
    D("webpack-hash", 'src="/static/js/main.9f8c2 a1b4e7d0.chunk.js"'.replace(" ", ""), "webpack content hash"),
    D("git-sha", 'const COMMIT="e3b0c44298fc1c149afbf4c8996fb92427ae41e4";', "git/sha1 hash"),
    D("uuid", 'id:"550e8400-e29b-41d4-a716-446655440000"', "uuid v4"),
    D("sri", 'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQ"', "subresource integrity"),
    D("md5-ish", 'etag:"d41d8cd98f00b204e9800998ecf8427e"', "md5 etag"),
    D("placeholder-1", 'apiKey: "your_api_key_here"', "placeholder"),
    D("placeholder-2", 'secret = "changeme12345678"', "placeholder"),
    D("placeholder-3", 'token: "xxxxxxxxxxxxxxxx"', "placeholder"),
    D("base64-word", 'data:"SGVsbG8gV29ybGQgdGhpcyBpcyBqdXN0IHRleHQ="', "base64 of plain text"),
    D("css-path", 'd="M12.5 3.8c-1.2 0.4-2.1 1.5-2.1 2.8v134.2l8.4-3.1z"', "svg path data"),
    D("lorem", 'text:"the quick brown fox jumps over the lazy dog again"', "prose"),
    D("version", 'version:"4.17.21-beta.3+build.1928"', "semver"),
    # non-credential strings that used to raise a medium+ alarm and shouldn't:
    # a generic key- token that isn't hex, and an eyJ..eyJ.. that doesn't decode
    # as a real JWT. (SK+32hex and 32hex-usN are deliberately NOT here — those
    # ARE the Twilio/Mailchimp key shapes, so surfacing them is correct, not a
    # false alarm; the report tiers them by confidence for the analyst.)
    D("mailgun-generic", 'data-key="key-abcdefghij0123456789ABCDEFGHIJ01";', "key- token, not hex → not a Mailgun key"),
    D("jwt-lookalike", 'x="eyJhbGciOiJub25lICBz.eyJzdWIiOjEyMzQ1Njc4OTB9.abcdefghij1234567890";', "eyJ..eyJ.. that doesn't decode"),
]


def score(scan=secretscan.scan_text):
    """Run `scan` over every corpus item and return a metrics dict."""
    hits, misses = [], []
    for p in CORPUS_POSITIVE:
        findings = scan(p.text, "bench")
        if p.expect is None:
            ok = bool(findings)
        else:
            ok = any(p.expect.lower() in f["rule"].lower() for f in findings)
        (hits if ok else misses).append(p)

    clean, false_pos = [], []
    for d in CORPUS_DECOY:
        # A decoy "fails" only if something fires that is NOT public_ok/info —
        # a low/info note is acceptable; a medium+ real-leak finding is a false alarm.
        findings = [f for f in scan(d.text, "bench")
                    if not f.get("public_ok") and f.get("severity") not in ("low", "info")]
        (false_pos if findings else clean).append((d, findings))

    return {
        "recall": len(hits) / len(CORPUS_POSITIVE),
        "precision": len(clean) / len(CORPUS_DECOY),
        "hits": hits, "misses": misses,
        "clean": clean, "false_pos": false_pos,
        "n_pos": len(CORPUS_POSITIVE), "n_decoy": len(CORPUS_DECOY),
    }


def main() -> int:
    m = score()
    print(f"\n  Secret-scanner benchmark  ({m['n_pos']} planted secrets, {m['n_decoy']} decoys)\n")
    print(f"  RECALL     {m['recall'] * 100:5.1f}%   ({len(m['hits'])}/{m['n_pos']} planted secrets found)")
    print(f"  PRECISION  {m['precision'] * 100:5.1f}%   ({len(m['clean'])}/{m['n_decoy']} decoys correctly ignored)\n")
    if m["misses"]:
        print("  MISSED (false negatives):")
        for p in m["misses"]:
            print(f"    - {p.cid:20s} {p.ctx}")
        print()
    if m["false_pos"]:
        print("  FALSE ALARMS (fired on a decoy):")
        for d, fs in m["false_pos"]:
            rules = ", ".join(sorted({f["rule"] for f in fs}))
            print(f"    - {d.cid:20s} {d.ctx}  ->  {rules}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
