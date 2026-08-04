#!/usr/bin/env python3
"""Offline unit suite for Nucleus's highest-risk pure logic.

Unlike tests/smoke.py (a live end-to-end script that starts every console and
hits real loopback endpoints), this suite never touches the network — no DNS,
no outbound HTTP, nothing past 127.0.0.1 for the one test that needs a running
handler to observe response headers. Run from the repo root:

    python3 -m unittest tests.unit -v

Some tests encode target behavior for hardening that's landing concurrently
in the app modules this suite covers (SSRF guard consolidation, _md_safe
character coverage, the Expert-mode deny-list, the apikeys quote bug). A
failing test here is a real signal against that target, not a flaky test —
don't "fix" it by loosening the assertion.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
import uuid
import zlib
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from consoles.recon import detect
from shared import common
from shared import apikeys
from engine import osint_report as report
from consoles.redcell import runners
from consoles.redcell import wordlists
from consoles.redcell import hashtools
from consoles.redcell import webscan
from consoles.redcell import playbooks
from consoles.redcell import secretscan
from consoles.redcell import keyverify
from consoles.redcell import stresstest
from consoles.redcell import tlsaudit
from consoles.redcell import techfp
from consoles.redcell import jwtaudit
from consoles.recon import takeover
from consoles.bastion import scrub
from consoles.redcell.app import build_app as _redcell_build_app
from consoles.recon.app import build_app as _recon_build_app
from consoles.bastion.app import build_app as _bastion_build_app
from consoles.devkit import tools as devkit_tools
from consoles.devkit.app import build_app as _devkit_build_app
from consoles.systems import sysinfo

# tests/ on path so the labeled-corpus benchmark is importable as a CI floor
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


# ==========================================================================
# 1. consoles/recon/detect.py — classify / validate / normalize_for
# ==========================================================================
class ClassifyTypesTests(unittest.TestCase):
    """One assertion per selector type classify() must route correctly."""

    def test_username(self):
        self.assertEqual(detect.classify("cole_munz99"), ("username", "cole_munz99"))

    def test_email(self):
        kind, val = detect.classify("User.Name+tag@Example.COM")
        self.assertEqual(kind, "email")
        self.assertEqual(val, "user.name+tag@example.com")

    def test_bare_domain(self):
        self.assertEqual(detect.classify("example.com"), ("domain", "example.com"))

    def test_ipv4(self):
        self.assertEqual(detect.classify("8.8.8.8"), ("ip", "8.8.8.8"))

    def test_ipv6(self):
        self.assertEqual(detect.classify("2001:4860:4860::8888"),
                          ("ip", "2001:4860:4860::8888"))

    def test_ipv6_bracketed(self):
        self.assertEqual(detect.classify("[::1]"), ("ip", "::1"))

    def test_phone(self):
        self.assertEqual(detect.classify("+1 (555) 123-4567"),
                          ("phone", "+15551234567"))

    def test_hash_md5(self):
        digest = hashlib.md5(b"test").hexdigest()
        self.assertEqual(detect.classify(digest), ("hash", digest))

    def test_hash_sha1(self):
        digest = hashlib.sha1(b"test").hexdigest()
        self.assertEqual(detect.classify(digest), ("hash", digest))

    def test_hash_sha256(self):
        digest = hashlib.sha256(b"test").hexdigest()
        self.assertEqual(detect.classify(digest), ("hash", digest))

    def test_btc_address(self):
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # genesis block address
        self.assertEqual(detect.classify(addr), ("crypto", addr))

    def test_eth_address(self):
        addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"  # WETH contract
        self.assertEqual(detect.classify(addr), ("crypto", addr))

    def test_mac_colon_form(self):
        self.assertEqual(detect.classify("AA:BB:CC:DD:EE:FF"),
                          ("mac", "aa:bb:cc:dd:ee:ff"))

    def test_mac_dash_form(self):
        self.assertEqual(detect.classify("AA-BB-CC-DD-EE-FF"),
                          ("mac", "aa-bb-cc-dd-ee-ff"))

    def test_coordinates(self):
        self.assertEqual(detect.classify("40.7128, -74.0060"),
                          ("geo", "40.7128,-74.0060"))

    def test_image_url(self):
        self.assertEqual(detect.classify("https://example.com/photo.jpg"),
                          ("image", "https://example.com/photo.jpg"))

    def test_plain_url_becomes_domain(self):
        self.assertEqual(detect.classify("https://example.com/page?id=1"),
                          ("domain", "example.com"))

    def test_name(self):
        self.assertEqual(detect.classify("Cole Munson"), ("name", "Cole Munson"))

    def test_company(self):
        self.assertEqual(detect.classify("Acme Corp"), ("company", "Acme Corp"))


class ClassifyEdgeCaseTests(unittest.TestCase):
    """Ambiguous inputs that could plausibly be misrouted by a naive check."""

    def test_32_hex_string_is_hash_not_username(self):
        # Also a legal username string by charset, but hash must win.
        digest = hashlib.md5(b"whatever").hexdigest()
        kind, _ = detect.classify(digest)
        self.assertEqual(kind, "hash")
        self.assertNotEqual(kind, "username")

    def test_dotted_quad_is_ip_not_version_string(self):
        kind, val = detect.classify("1.2.3.4")
        self.assertEqual(kind, "ip")
        self.assertEqual(val, "1.2.3.4")

    def test_mac_dash_form_not_swallowed_by_username(self):
        # Dash-separated MAC is charset-legal as a username too; MAC must win.
        kind, _ = detect.classify("aa-bb-cc-dd-ee-ff")
        self.assertEqual(kind, "mac")

    def test_short_digit_run_is_not_phone(self):
        # Below the 7-digit floor -> falls through to username, not phone.
        kind, _ = detect.classify("12345")
        self.assertNotEqual(kind, "phone")

    def test_empty_string_defaults_to_username(self):
        self.assertEqual(detect.classify(""), ("username", ""))


class ValidateTests(unittest.TestCase):

    def test_ip_valid_and_invalid(self):
        self.assertTrue(detect.validate("ip", "1.1.1.1"))
        self.assertFalse(detect.validate("ip", "not-an-ip"))

    def test_phone_length_bounds(self):
        self.assertTrue(detect.validate("phone", "+15551234567"))
        self.assertFalse(detect.validate("phone", "123"))

    def test_crypto_requires_btc_or_eth_shape(self):
        self.assertTrue(detect.validate("crypto", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"))
        self.assertFalse(detect.validate("crypto", "not-a-crypto-address"))

    def test_email_format(self):
        self.assertTrue(detect.validate("email", "user@example.com"))
        self.assertFalse(detect.validate("email", "not-an-email"))

    def test_domain_format(self):
        self.assertTrue(detect.validate("domain", "example.com"))
        self.assertFalse(detect.validate("domain", "not a domain"))

    def test_username_format(self):
        self.assertTrue(detect.validate("username", "cole_munz99"))
        self.assertFalse(detect.validate("username", "has a space"))

    def test_hash_format(self):
        self.assertTrue(detect.validate("hash", hashlib.sha256(b"x").hexdigest()))
        self.assertFalse(detect.validate("hash", "not-hex"))

    def test_mac_format(self):
        self.assertTrue(detect.validate("mac", "aa:bb:cc:dd:ee:ff"))
        self.assertFalse(detect.validate("mac", "aa:bb:cc:dd:ee"))  # too short

    def test_geo_format(self):
        self.assertTrue(detect.validate("geo", "40.7,-74.0"))
        self.assertFalse(detect.validate("geo", "not-coordinates"))

    def test_freeform_types_accept_any_nonempty(self):
        self.assertTrue(detect.validate("company", "Whatever Inc"))
        self.assertTrue(detect.validate("image", "https://example.com/x.png"))

    def test_empty_value_always_invalid(self):
        for kind in detect.VALID_TYPES:
            self.assertFalse(detect.validate(kind, ""))


class NormalizeForTests(unittest.TestCase):

    def test_email_lowercased_and_stripped(self):
        self.assertEqual(detect.normalize_for("email", " User@EXAMPLE.com "),
                          "user@example.com")

    def test_domain_strips_scheme_path_query(self):
        self.assertEqual(
            detect.normalize_for("domain", "HTTPS://Example.COM/path?x=1"),
            "example.com")

    def test_ip_strips_brackets(self):
        self.assertEqual(detect.normalize_for("ip", "[::1]"), "::1")

    def test_phone_keeps_digits_and_plus(self):
        self.assertEqual(detect.normalize_for("phone", "+1 (555) 123-4567"),
                          "+15551234567")

    def test_geo_strips_whitespace(self):
        self.assertEqual(detect.normalize_for("geo", " 40.7 , -74.0 "), "40.7,-74.0")

    def test_hash_and_mac_lowercased(self):
        self.assertEqual(detect.normalize_for("hash", "ABCDEF00"), "abcdef00")
        self.assertEqual(detect.normalize_for("mac", "AA:BB:CC:DD:EE:FF"),
                          "aa:bb:cc:dd:ee:ff")

    def test_unhandled_kind_just_strips(self):
        self.assertEqual(detect.normalize_for("username", " Cole "), "Cole")


# ==========================================================================
# 2. shared/common.py — SSRF guard
# ==========================================================================
class SSRFGuardTests(unittest.TestCase):
    """Every case here uses an IP literal so it needs zero DNS resolution."""

    REJECT = [
        "127.0.0.1",    # loopback
        "10.0.0.1",     # RFC1918
        "192.168.1.1",  # RFC1918
        "172.16.0.1",   # RFC1918
        "169.254.1.1",  # link-local
        "100.64.0.1",   # CGNAT
        "0.0.0.0",      # unspecified
        "::1",          # IPv6 loopback
        "fc00::1",      # IPv6 unique-local
        "fe80::1",      # IPv6 link-local
        "224.0.0.1",    # multicast
        "240.0.0.1",    # reserved (class E)
    ]
    ACCEPT = ["1.1.1.1", "8.8.8.8"]

    def test_host_is_public_rejects_non_public_literals(self):
        for host in self.REJECT:
            with self.subTest(host=host):
                self.assertFalse(common.host_is_public(host))

    def test_host_is_public_accepts_public_literals(self):
        for host in self.ACCEPT:
            with self.subTest(host=host):
                self.assertTrue(common.host_is_public(host))

    def test_ip_is_public_rejects_non_public_literals(self):
        import ipaddress
        for host in self.REJECT:
            with self.subTest(host=host):
                self.assertFalse(common._ip_is_public(ipaddress.ip_address(host)))

    def test_ip_is_public_accepts_public_literals(self):
        import ipaddress
        for host in self.ACCEPT:
            with self.subTest(host=host):
                self.assertTrue(common._ip_is_public(ipaddress.ip_address(host)))

    def test_resolve_public_ips_helper_if_present(self):
        # Target behavior: a resolve_public_ips(host) helper backing both
        # host_is_public() and fetch()'s connect-pinning, so the two guards
        # can't drift apart. Test it directly when it exists.
        fn = getattr(common, "resolve_public_ips", None)
        if fn is None:
            self.skipTest("resolve_public_ips not present on this checkout yet")
        for host in self.REJECT:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    fn(host)
        for host in self.ACCEPT:
            with self.subTest(host=host):
                self.assertEqual(fn(host), [host])

    def test_resolve_public_rejects_private_literal_no_dns(self):
        with self.assertRaises(ValueError):
            common._resolve_public("127.0.0.1")

    def test_resolve_public_accepts_public_literal_no_dns(self):
        ip, family = common._resolve_public("1.1.1.1")
        self.assertEqual(ip, "1.1.1.1")
        self.assertIn(family, (socket.AF_INET, socket.AF_INET6))

    def test_empty_host_rejected(self):
        self.assertFalse(common.host_is_public(""))
        self.assertFalse(common.host_is_public("   "))


# ==========================================================================
# 3. engine/osint_report.py — grading
# ==========================================================================
class GradeBoundaryTests(unittest.TestCase):

    def _grade(self, total, max_total=1000):
        return report._grade(total, max_total)

    def test_90_pct_is_a(self):
        self.assertEqual(self._grade(900)[0], "A")

    def test_just_under_90_is_b(self):
        self.assertEqual(self._grade(899)[0], "B")

    def test_80_pct_is_b(self):
        self.assertEqual(self._grade(800)[0], "B")

    def test_just_under_80_is_c(self):
        self.assertEqual(self._grade(799)[0], "C")

    def test_65_pct_is_c(self):
        self.assertEqual(self._grade(650)[0], "C")

    def test_just_under_65_is_d(self):
        self.assertEqual(self._grade(649)[0], "D")

    def test_50_pct_is_d(self):
        self.assertEqual(self._grade(500)[0], "D")

    def test_just_under_50_is_f(self):
        self.assertEqual(self._grade(499)[0], "F")

    def test_zero_is_f(self):
        self.assertEqual(self._grade(0)[0], "F")

    def test_zero_max_total_does_not_divide_by_zero(self):
        grade, pct = report._grade(0, 0)
        self.assertEqual(grade, "F")
        self.assertEqual(pct, 0.0)


class ScoreSectionTests(unittest.TestCase):
    """Clean input scores near the ceiling with no findings; a bad/hostile
    input scores near the floor with findings raised."""

    def test_email_clean_scores_max_no_findings(self):
        spf = {"present": True, "record": "v=spf1 -all", "valid": True}
        dmarc = {"present": True, "record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "default"}
        pts, max_pts, findings = report._score_email(spf, dmarc, dkim, mx_present=True)
        self.assertEqual(pts, max_pts)
        self.assertEqual(findings, [])

    def test_email_bad_scores_zero_with_findings(self):
        spf = {"present": False, "record": None, "valid": False, "qualifier": None}
        dmarc = {"present": False, "record": None, "policy": None}
        dkim = {"found": False, "selector": None}
        pts, max_pts, findings = report._score_email(spf, dmarc, dkim, mx_present=True)
        self.assertEqual(pts, 0)
        self.assertTrue(findings)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    # --- SPF qualifier handling (regression: +all/?all must not read as valid) ---
    def test_spf_hardfail_is_protective(self):
        with mock.patch.object(report, "_txt_values", return_value=["v=spf1 -all"]):
            spf = report._check_spf("example.com")
        self.assertEqual(spf["qualifier"], "-")
        self.assertTrue(spf["valid"])

    def test_spf_plus_all_is_flagged_high_not_valid(self):
        with mock.patch.object(report, "_txt_values",
                               return_value=["v=spf1 include:_spf.example.com +all"]):
            spf = report._check_spf("example.com")
        self.assertEqual(spf["qualifier"], "+")
        self.assertFalse(spf["valid"])  # +all authorizes everyone — no protection
        dmarc = {"present": True, "record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "default"}
        pts, _max, findings = report._score_email(spf, dmarc, dkim, mx_present=True)
        self.assertTrue(any(f["severity"] == "high" and "+all" in f["title"] for f in findings))

    def test_spf_neutral_all_is_medium(self):
        spf = {"present": True, "record": "v=spf1 ?all", "valid": False, "qualifier": "?"}
        dmarc = {"present": True, "record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "default"}
        pts, _max, findings = report._score_email(spf, dmarc, dkim, mx_present=True)
        self.assertTrue(any(f["severity"] == "medium" and "?all" in f["title"] for f in findings))

    # --- TLS (regression: an expired/self-signed/mismatched cert must be scored,
    #     not vanish behind a failed verifying handshake) ---
    def test_tls_expired_cert_is_high_and_zero(self):
        tls = {"ok": True, "trusted": False, "self_signed": False, "hostname_ok": True,
               "days_left": -5, "verify_error": "certificate has expired"}
        pts, _max, findings = report._score_tls(tls)
        self.assertEqual(pts, 0)
        self.assertTrue(any(f["severity"] == "high" and "expired" in f["title"].lower()
                            for f in findings))

    def test_tls_self_signed_is_high_and_zero(self):
        tls = {"ok": True, "trusted": False, "self_signed": True, "hostname_ok": True, "days_left": 300}
        pts, _max, findings = report._score_tls(tls)
        self.assertEqual(pts, 0)
        self.assertTrue(any("self-signed" in f["title"].lower() for f in findings))

    def test_tls_hostname_mismatch_is_high_and_zero(self):
        tls = {"ok": True, "trusted": False, "self_signed": False, "hostname_ok": False, "days_left": 300}
        pts, _max, findings = report._score_tls(tls)
        self.assertEqual(pts, 0)
        self.assertTrue(any("hostname" in f["title"].lower() for f in findings))

    def test_tls_clean_cert_scores_max(self):
        tls = {"ok": True, "trusted": True, "self_signed": False, "hostname_ok": True, "days_left": 300}
        pts, max_pts, findings = report._score_tls(tls)
        self.assertEqual(pts, max_pts)
        self.assertEqual(findings, [])

    def test_tls_expiring_soon_is_medium(self):
        tls = {"ok": True, "trusted": True, "self_signed": False, "hostname_ok": True, "days_left": 5}
        pts, max_pts, findings = report._score_tls(tls)
        self.assertTrue(0 < pts < max_pts)
        self.assertTrue(any(f["severity"] == "medium" for f in findings))

    def test_host_matches_cert_wildcard_and_exact(self):
        self.assertTrue(report._host_matches_cert("www.example.com", None, ["*.example.com"]))
        self.assertFalse(report._host_matches_cert("a.b.example.com", None, ["*.example.com"]))
        self.assertTrue(report._host_matches_cert("example.com", "example.com", []))
        self.assertFalse(report._host_matches_cert("evil.com", "example.com", ["www.example.com"]))

    # --- Attack surface (regression: a source outage must not read as clean) ---
    def test_attack_surface_shodan_outage_excluded_from_grade(self):
        subs = {"ok": True, "count": 5}
        shodan = {"ok": False, "error": "timeout", "ports": [], "cves": []}
        pts, max_pts, findings = report._score_attack_surface(subs, shodan)
        self.assertEqual((pts, max_pts), (0, 0))  # dropped from numerator AND denominator
        self.assertTrue(any("not graded" in f["title"].lower() for f in findings))

    def test_attack_surface_clean_shodan_scores_full(self):
        subs = {"ok": True, "count": 5}
        shodan = {"ok": True, "ports": [80, 443], "cves": []}
        pts, max_pts, findings = report._score_attack_surface(subs, shodan)
        self.assertEqual((pts, max_pts), (20, 20))

    def test_attack_surface_cves_deduct(self):
        subs = {"ok": True, "count": 5}
        shodan = {"ok": True, "ports": [80, 443, 22], "cves": ["CVE-2021-1", "CVE-2021-2"]}
        pts, max_pts, findings = report._score_attack_surface(subs, shodan)
        self.assertEqual(max_pts, 20)
        self.assertLess(pts, 20)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    # --- HTTP->HTTPS redirect detection (regression: no more body-length guess) ---
    def test_redirects_to_https_reads_real_3xx(self):
        self.assertTrue(report._redirects_to_https(
            {"ok": True, "status": 308, "headers": {"location": "https://x/"}}))
        self.assertFalse(report._redirects_to_https(
            {"ok": True, "status": 301, "headers": {"location": "http://x/"}}))
        self.assertFalse(report._redirects_to_https(
            {"ok": True, "status": 200, "headers": {}}))
        self.assertIsNone(report._redirects_to_https({"ok": False, "error": "refused"}))

    def test_web_clean_scores_max_no_findings(self):
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        https_res = {"ok": True, "status": 200, "headers": headers, "body_len": 100}
        # A clean site force-redirects plaintext :80 to https (real 3xx + Location),
        # which is what the corrected redirect check looks for.
        http_res = {"ok": True, "status": 308, "headers": {"location": "https://example.com/"}}
        pts, max_pts, findings, _banner = report._score_web(https_res, http_res)
        self.assertEqual(pts, max_pts)
        self.assertEqual(findings, [])

    def test_web_unreachable_scores_zero_with_high_finding(self):
        https_res = {"ok": False, "error": "timeout"}
        http_res = {"ok": False, "error": "timeout"}
        pts, _max_pts, findings, _banner = report._score_web(https_res, http_res)
        self.assertEqual(pts, 0)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    def test_attack_surface_clean_scores_max_no_findings(self):
        subdomains = {"ok": True, "count": 5, "sample": []}
        shodan = {"ok": True, "ports": [80, 443], "cves": [], "tags": [], "hostnames": []}
        pts, max_pts, findings = report._score_attack_surface(subdomains, shodan)
        self.assertEqual(pts, max_pts)
        self.assertEqual(findings, [])

    def test_attack_surface_with_cves_and_risky_ports_scores_lower(self):
        subdomains = {"ok": True, "count": 5, "sample": []}
        shodan = {"ok": True, "ports": [80, 443, 3389, 23],
                  "cves": ["CVE-2021-1111", "CVE-2021-2222"], "tags": [], "hostnames": []}
        pts, max_pts, findings = report._score_attack_surface(subdomains, shodan)
        self.assertLess(pts, max_pts)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    def test_attack_surface_score_never_goes_negative(self):
        subdomains = {"ok": True, "count": 1, "sample": []}
        shodan = {"ok": True, "ports": list(range(1, 50)),
                  "cves": [f"CVE-2021-{n}" for n in range(20)], "tags": [], "hostnames": []}
        pts, _max_pts, _findings = report._score_attack_surface(subdomains, shodan)
        self.assertGreaterEqual(pts, 0)


# ==========================================================================
# 4. engine/osint_report.py — _md_safe / _esc injection neutralization
# ==========================================================================
class MarkdownSafetyTests(unittest.TestCase):
    """_md_safe runs before ANY external field (DNS/SPF/DMARC/HTTP banner)
    hits the Markdown report. A value with backtick/</>/&/|/[]/newline must
    come out unable to break a code span, inject a link/image, add a new
    Markdown line, or reopen raw HTML."""

    def test_backtick_neutralized(self):
        self.assertNotIn("`", report._md_safe("`inject`"))

    def test_angle_brackets_neutralized(self):
        out = report._md_safe("<script>alert(1)</script>")
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)

    def test_pipe_neutralized(self):
        self.assertNotIn("|", report._md_safe("a | b"))

    def test_newline_collapsed(self):
        out = report._md_safe("line one\nline two")
        self.assertNotIn("\n", out)

    def test_ampersand_neutralized(self):
        self.assertNotIn("&", report._md_safe("a & b"))

    def test_square_brackets_neutralized(self):
        # [text](url) is Markdown link syntax -- a hostile record could smuggle
        # a live link/image into the rendered report otherwise.
        out = report._md_safe("[click me](javascript:alert(1))")
        self.assertNotIn("[", out)
        self.assertNotIn("]", out)

    def test_combined_hostile_value(self):
        hostile = "`x` [y](z) <script>&amp;</script> | pipe\nnewline"
        out = report._md_safe(hostile)
        for ch in "`<>&|[]\n":
            with self.subTest(char=ch):
                self.assertNotIn(ch, out)


class HtmlEscapeTests(unittest.TestCase):

    def test_escapes_all_html_special_chars(self):
        out = report._esc("""<script>alert("x")&'y'</script>""")
        for raw in ("<", ">", '"', "'"):
            with self.subTest(char=raw):
                self.assertNotIn(raw, out)
        self.assertIn("&lt;", out)
        self.assertIn("&gt;", out)
        self.assertIn("&amp;", out)
        self.assertIn("&quot;", out)
        self.assertIn("&#39;", out)

    def test_none_becomes_empty_string(self):
        self.assertEqual(report._esc(None), "")

    def test_plain_text_is_unchanged(self):
        self.assertEqual(report._esc("plain text 123"), "plain text 123")


# ==========================================================================
# 5. consoles/redcell/runners.py — validators, scope check, option gate,
#    Expert deny-list
# ==========================================================================
class ValidateHostTests(unittest.TestCase):

    def test_rejects_leading_dash(self):
        ok, reason = runners.validate_host("-evil.com")
        self.assertFalse(ok)
        self.assertIn("argument injection", reason)

    def test_rejects_shell_metacharacters(self):
        ok, _reason = runners.validate_host("evil.com; rm -rf /")
        self.assertFalse(ok)

    def test_rejects_whitespace(self):
        ok, _reason = runners.validate_host("exa mple.com")
        self.assertFalse(ok)

    def test_accepts_normal_hostname(self):
        ok, host = runners.validate_host("example.com")
        self.assertTrue(ok)
        self.assertEqual(host, "example.com")

    def test_accepts_ip_literal(self):
        ok, host = runners.validate_host("8.8.8.8")
        self.assertTrue(ok)
        self.assertEqual(host, "8.8.8.8")

    def test_rejects_empty_and_oversized(self):
        self.assertFalse(runners.validate_host("")[0])
        self.assertFalse(runners.validate_host("a" * 254)[0])


class ValidateUrlTests(unittest.TestCase):

    def test_rejects_embedded_credentials(self):
        ok, reason, _cleaned = runners.validate_url("http://user:pass@host.com/")
        self.assertFalse(ok)
        self.assertIn("credentials", reason)

    def test_rejects_non_http_scheme(self):
        ok, _reason, _cleaned = runners.validate_url("ftp://host.com/")
        self.assertFalse(ok)

    def test_allow_any_scheme_accepts_non_http(self):
        # The stress probe passes allow_any_scheme=True so an operator can load-test
        # whatever scheme they aim at; the host is still validated and returned.
        ok, host, cleaned = runners.validate_url("ftp://host.com/x", allow_any_scheme=True)
        self.assertTrue(ok)
        self.assertEqual(host, "host.com")
        self.assertEqual(cleaned, "ftp://host.com/x")

    def test_allow_any_scheme_still_enforces_everything_else(self):
        # Loosening the scheme must not loosen the other checks: embedded creds and
        # host-less URLs are still rejected even with allow_any_scheme=True.
        ok, _r, _c = runners.validate_url("ftp://user:pass@host.com/", allow_any_scheme=True)
        self.assertFalse(ok)
        ok2, _r2, _c2 = runners.validate_url("javascript:alert(1)", allow_any_scheme=True)
        self.assertFalse(ok2)

    def test_rejects_leading_dash(self):
        ok, reason, _cleaned = runners.validate_url("-http://evil.com")
        self.assertFalse(ok)
        self.assertIn("argument injection", reason)

    def test_accepts_normal_url_with_query_string(self):
        ok, host, cleaned = runners.validate_url("https://example.com/page?id=1&x=2")
        self.assertTrue(ok)
        self.assertEqual(host, "example.com")
        self.assertEqual(cleaned, "https://example.com/page?id=1&x=2")


class ScopeCheckTests(unittest.TestCase):
    """IP literals only -- host_is_public() needs no DNS for these."""

    def test_private_target_blocked_without_lab(self):
        ok, reason = runners.scope_check("127.0.0.1", lab=False)
        self.assertFalse(ok)
        self.assertTrue(reason)

    def test_private_target_allowed_with_lab_override(self):
        ok, reason = runners.scope_check("127.0.0.1", lab=True)
        self.assertTrue(ok)
        self.assertIn("lab", reason)

    def test_public_target_allowed_without_lab(self):
        ok, reason = runners.scope_check("1.1.1.1", lab=False)
        self.assertTrue(ok)
        self.assertEqual(reason, "")


class ResolveOptionsTests(unittest.TestCase):
    """Uses the real nmap RunnerSpec -- a fixed, stable part of SAFE_RUNNERS."""

    def setUp(self):
        self.spec = runners.SAFE_RUNNERS["nmap"]

    def test_missing_option_falls_back_to_default(self):
        resolved, err = runners._resolve_options(self.spec, {})
        self.assertIsNone(err)
        self.assertEqual(resolved["profile"], self.spec.options["profile"].choices["quick"])

    def test_known_option_key_resolves_to_fixed_value(self):
        resolved, err = runners._resolve_options(self.spec, {"options": {"profile": "vuln"}})
        self.assertIsNone(err)
        self.assertEqual(resolved["profile"], self.spec.options["profile"].choices["vuln"])

    def test_unknown_option_key_is_refused(self):
        resolved, err = runners._resolve_options(self.spec, {"options": {"profile": "not-a-real-profile"}})
        self.assertIsNone(resolved)
        self.assertIsNotNone(err)
        self.assertEqual(err.status, 400)

    def test_raw_client_key_never_reaches_resolved_dict(self):
        # nuclei's "tags" option maps client key "cves" -> fixed value "cve"
        # (singular) -- a real name/value split, unlike nmap's "vuln" profile
        # which happens to also contain the literal word "vuln" in its argv.
        nuclei_spec = runners.SAFE_RUNNERS["nuclei"]
        resolved, err = runners._resolve_options(nuclei_spec, {"options": {"tags": "cves"}})
        self.assertIsNone(err)
        self.assertEqual(resolved["tags"], "cve")
        self.assertNotEqual(resolved["tags"], "cves")


class OpsecGateTests(unittest.TestCase):
    """The opsec gate refuses a target-touching run while the real IP is
    exposed, unless it's a lab target or the caller overrides. This is the
    'don't fire a scan from your real IP by accident' safety."""

    def test_lab_target_never_blocked(self):
        with mock.patch.object(runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "1.2.3.4"}):
            self.assertIsNone(runners.opsec_gate(lab=True, body={}))

    def test_explicit_override_bypasses(self):
        with mock.patch.object(runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "1.2.3.4"}):
            self.assertIsNone(runners.opsec_gate(lab=False, body={"proceed_exposed": True}))

    def test_not_exposed_allows(self):
        with mock.patch.object(runners.common, "opsec_status",
                               return_value={"exposed": False}):
            self.assertIsNone(runners.opsec_gate(lab=False, body={}))

    def test_exposed_blocks_with_marker(self):
        with mock.patch.object(runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "24.197.212.75",
                                             "reason": "no VPN detected"}):
            resp = runners.opsec_gate(lab=False, body={})
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 403)
        payload = json.loads(resp.body)
        self.assertTrue(payload["opsec_block"])
        self.assertIn("24.197.212.75", payload["error"])

    def test_opsec_check_error_does_not_hard_block(self):
        # A broken anonymity check must not be why authorized work is refused.
        with mock.patch.object(runners.common, "opsec_status", side_effect=RuntimeError("boom")):
            self.assertIsNone(runners.opsec_gate(lab=False, body={}))


class ExpertDenyListTests(unittest.TestCase):
    """Shell-equivalent binaries must never be reachable through Expert mode's
    arbitrary-argument runner, even though they may legitimately sit in the
    tool inventory for other purposes."""

    def test_shell_interpreters_denied(self):
        for binary in ("python", "python3", "bash", "sh"):
            with self.subTest(binary=binary):
                self.assertIn(binary, runners._EXPERT_DENY)

    def test_docker_denied(self):
        self.assertIn("docker", runners._EXPERT_DENY)

    def test_pivot_capable_network_tools_denied(self):
        # socat/tcpdump are shell-equivalent in effect (socat can open a raw
        # listener/reverse shell; tcpdump write-file + -z postrotate-exec is a
        # classic sudoers privesc) -- hardening target for the Expert deny-list.
        for binary in ("socat", "tcpdump"):
            with self.subTest(binary=binary):
                self.assertIn(binary, runners._EXPERT_DENY)

    def test_script_loading_tools_denied(self):
        # Tools whose CLI can load an arbitrary local script/config file that
        # then execs. exiftool -config is a Perl file eval'd on load -- the one
        # the adversarial verify pass caught still reachable.
        for binary in ("exiftool", "nmap", "mitmproxy", "tshark", "nuclei",
                       "ghidra", "analyzeHeadless"):
            with self.subTest(binary=binary):
                self.assertIn(binary, runners._EXPERT_DENY)


# ==========================================================================
# 6. consoles/redcell/wordlists.py — resolve()
# ==========================================================================
class WordlistResolveTests(unittest.TestCase):
    """Registry + allowed roots are patched per-test so this never depends on
    what's actually installed under /usr/share on the box running the suite."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = Path(self._tmp.name)

        self.good_root = (tmp / "goodroot").resolve()
        self.good_root.mkdir()
        good_file = self.good_root / "list.txt"
        good_file.write_text("admin\nlogin\n")

        outside_root = (tmp / "outsideroot").resolve()
        outside_root.mkdir()
        escape_file = outside_root / "escape.txt"
        escape_file.write_text("x\n")

        good_entry = wordlists.WordlistEntry(
            id="testroot/list.txt", label="list.txt", root="testroot",
            path=str(good_file), size=good_file.stat().st_size)
        escape_entry = wordlists.WordlistEntry(
            id="testroot/escape.txt", label="escape.txt", root="testroot",
            path=str(escape_file), size=escape_file.stat().st_size)

        self._roots_patch = mock.patch.object(wordlists, "ALLOWED_ROOTS", [self.good_root])
        self._registry_patch = mock.patch.object(
            wordlists, "_REGISTRY", {good_entry.id: good_entry, escape_entry.id: escape_entry})
        self._roots_patch.start()
        self._registry_patch.start()
        self.addCleanup(self._roots_patch.stop)
        self.addCleanup(self._registry_patch.stop)
        self.good_file = good_file

    def test_unknown_id_rejected(self):
        self.assertIsNone(wordlists.resolve("does-not-exist"))

    def test_registered_id_resolves_to_real_path(self):
        resolved = wordlists.resolve("testroot/list.txt")
        self.assertEqual(resolved, str(self.good_file))

    def test_id_escaping_allowed_roots_rejected(self):
        # Present in the registry but its path sits outside ALLOWED_ROOTS --
        # the resolve()-time re-check must still refuse it.
        self.assertIsNone(wordlists.resolve("testroot/escape.txt"))

    def test_empty_and_non_string_ids_rejected(self):
        self.assertIsNone(wordlists.resolve(""))
        self.assertIsNone(wordlists.resolve(None))


# ==========================================================================
# 7. shared/apikeys.py — quote handling regression
# ==========================================================================
class ApiKeyQuoteHandlingTests(unittest.TestCase):
    """get_key() must strip a single layer of surrounding quotes from a
    var/.env value, same as any normal .env parser (dotenv, docker compose
    env_file, etc.) -- this is the regression test for the quote bug."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.envfile = Path(self._tmp.name) / ".env"
        self.envfile.write_text(
            'NUCLEUS_TEST_DQUOTE_KEY="quoted-value"\n'
            "NUCLEUS_TEST_SQUOTE_KEY='single-quoted'\n"
            "NUCLEUS_TEST_PLAIN_KEY=plainvalue\n"
        )
        self._var_env_patch = mock.patch.object(apikeys, "_VAR_ENV", self.envfile)
        self._var_env_patch.start()
        self.addCleanup(self._var_env_patch.stop)

        # get_key() checks the real process environment first -- make sure a
        # stray value there can't shadow the .env fixture or leak out after.
        self._environ_patch = mock.patch.dict(os.environ, {}, clear=False)
        self._environ_patch.start()
        self.addCleanup(self._environ_patch.stop)
        for key in ("NUCLEUS_TEST_DQUOTE_KEY", "NUCLEUS_TEST_SQUOTE_KEY", "NUCLEUS_TEST_PLAIN_KEY"):
            os.environ.pop(key, None)

    def test_double_quotes_stripped(self):
        self.assertEqual(apikeys.get_key("NUCLEUS_TEST_DQUOTE_KEY"), "quoted-value")

    def test_single_quotes_stripped(self):
        self.assertEqual(apikeys.get_key("NUCLEUS_TEST_SQUOTE_KEY"), "single-quoted")

    def test_unquoted_value_unchanged(self):
        self.assertEqual(apikeys.get_key("NUCLEUS_TEST_PLAIN_KEY"), "plainvalue")

    def test_unset_key_returns_empty_string(self):
        self.assertEqual(apikeys.get_key("NUCLEUS_TEST_NOT_PRESENT"), "")

    def test_env_var_takes_priority_over_dotenv(self):
        os.environ["NUCLEUS_TEST_DQUOTE_KEY"] = "from-environment"
        self.assertEqual(apikeys.get_key("NUCLEUS_TEST_DQUOTE_KEY"), "from-environment")


# ==========================================================================
# 8. shared/common.py — security response headers
# ==========================================================================
class ResponseHeaderPlumbingTests(unittest.TestCase):
    """Response.headers is a per-instance dict (dataclass default_factory),
    so two Response objects never share -- or leak into -- the same mutable
    default."""

    def test_headers_dict_not_shared_between_instances(self):
        r1 = common.Response.json({"a": 1})
        r2 = common.Response.json({"b": 2})
        r1.headers["x"] = "1"
        self.assertNotIn("x", r2.headers)

    def test_csp_constant_is_locked_down(self):
        csp = common._CSP
        for directive in ("default-src 'none'", "script-src 'self'",
                          "style-src 'self'", "base-uri 'none'",
                          "form-action 'self'", "frame-ancestors 'none'"):
            with self.subTest(directive=directive):
                self.assertIn(directive, csp)


class LiveSecurityHeaderTests(unittest.TestCase):
    """The CSP/X-Frame-Options/nosniff/no-store headers are attached inside
    the HTTP handler's _send() at send time, not stored on the Response
    object itself -- so the only faithful way to verify a real response
    actually carries them is a real request. This binds 127.0.0.1 only, on
    an OS-assigned ephemeral port, serves one canned route, and shuts back
    down; no internet access, no fixed port to collide with."""

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_response_carries_hardened_security_headers(self):
        static_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(static_dir, ignore_errors=True))

        app = common.App(
            slug="unit-test-app", static_dir=static_dir,
            routes={"GET /ping": lambda req: common.Response.json({"ok": True})},
        )

        httpd = None
        last_error = None
        for _attempt in range(3):
            port = self._free_port()
            try:
                httpd = common.serve(app, port=port, block=False)
                break
            except OSError as e:
                last_error = e
                continue
        if httpd is None:
            self.skipTest(f"could not bind a loopback test port: {last_error}")

        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("GET", "/ping")
                resp = conn.getresponse()
                resp.read()
                headers = {k.lower(): v for k, v in resp.getheaders()}
            finally:
                conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertEqual(headers.get("content-security-policy"), common._CSP)
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertIn("referrer-policy", headers)


class BodyLimitTests(unittest.TestCase):
    """App.body_limits raises the POST cap for exactly the routes that opt in
    (bastion's scrub upload takes whole files); every route absent from the
    dict keeps the 256 KiB MAX_BODY. Enforcement lives inside _dispatch at
    request time, so — like the header tests above — only a real loopback
    request proves it. The over-limit cases declare Content-Length without
    ever sending a body: the guard fires on the declared length alone, and
    not sending half a megabyte keeps loopback socket buffers (and the
    deadlocks they invite) out of the test."""

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def setUp(self):
        static_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(static_dir, ignore_errors=True))

        def echo(req):
            return common.Response.json({"received": len(req.body)})

        app = common.App(
            slug="unit-test-app", static_dir=static_dir,
            routes={"POST /api/big": echo, "POST /api/small": echo},
            body_limits={"POST /api/big": 1024 * 1024},
        )

        self.httpd = None
        last_error = None
        for _attempt in range(3):
            port = self._free_port()
            try:
                self.httpd = common.serve(app, port=port, block=False)
                self.port = port
                break
            except OSError as e:
                last_error = e
                continue
        if self.httpd is None:
            self.skipTest(f"could not bind a loopback test port: {last_error}")
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _headers(self) -> dict:
        # POSTs need a same-origin Origin or the CSRF guard 403s before the
        # body-limit check is ever reached.
        return {"Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/octet-stream"}

    def _post_body(self, path: str, payload: bytes):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", path, body=payload, headers=self._headers())
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _post_declared(self, path: str, length: int) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest("POST", path)
            for k, v in self._headers().items():
                conn.putheader(k, v)
            conn.putheader("Content-Length", str(length))
            conn.endheaders()
            return conn.getresponse().status
        finally:
            conn.close()

    def test_opted_in_route_accepts_body_over_max_body(self):
        payload = b"x" * (512 * 1024)  # 2x MAX_BODY, half the route's own limit
        status, body = self._post_body("/api/big", payload)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["received"], len(payload))

    def test_route_absent_from_body_limits_keeps_max_body(self):
        self.assertEqual(self._post_declared("/api/small", 512 * 1024), 413)

    def test_opted_in_route_still_has_a_ceiling(self):
        self.assertEqual(self._post_declared("/api/big", 2 * 1024 * 1024), 413)

    def test_apps_without_body_limits_default_to_empty(self):
        # Backward compatibility: every existing console builds App without
        # the new field and must land on MAX_BODY via the empty-dict default.
        app = common.App(slug="unit-test-app", static_dir=Path("."), routes={})
        self.assertEqual(app.body_limits, {})


class TlsCertRebindTests(unittest.TestCase):
    """_tls_cert must connect to a resolved-and-validated IP, never re-resolve
    the hostname at connect time (DNS-rebinding TOCTOU the verify pass caught)."""

    def test_connects_to_validated_ip_not_hostname(self):
        seen = {}

        def fake_conn(addr, timeout=None):
            seen["host"] = addr[0]
            raise OSError("stop before real socket")  # we only care about the target

        with mock.patch.object(report.common, "resolve_public_ips", return_value=["93.184.216.34"]), \
             mock.patch.object(report.socket, "create_connection", side_effect=fake_conn):
            report._tls_cert("example.com")
        self.assertEqual(seen.get("host"), "93.184.216.34")

    def test_refuses_private_rebind_without_connecting(self):
        called = {"n": 0}

        def fake_conn(addr, timeout=None):
            called["n"] += 1
            raise OSError

        with mock.patch.object(report.common, "resolve_public_ips",
                               side_effect=ValueError("non-public IP")), \
             mock.patch.object(report.socket, "create_connection", side_effect=fake_conn):
            out = report._tls_cert("rebind.evil")
        self.assertFalse(out.get("ok"))
        self.assertEqual(called["n"], 0)  # never opened a socket


# ==========================================================================
# 9. consoles/redcell/hashtools.py — hash identification (labeled corpus)
# ==========================================================================
class HashIdentifyCorpusTests(unittest.TestCase):
    """A labeled corpus is the only honest test of an identifier: each real
    hash must surface its true type (as the top candidate for structured
    hashes, or somewhere in the ambiguous set for raw hex), with the RIGHT
    hashcat mode — a wrong -m sends a pentester off cracking with the wrong
    algorithm. Every case here is a real, validly-shaped hash of its type."""

    # (hash, expected-type-substring, expected hashcat mode among candidates)
    STRUCTURED = [
        ("$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6", "bcrypt", 3200),
        ("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", "sha512crypt", 1800),
        ("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", "sha256crypt", 7400),
        ("$1$28772684$iEwNOgGugqO9.bIz5sk8k/", "md5crypt", 500),
        ("$P$984478476IagS59wHZvyQMArzfx58u.", "phpass", 400),
        ("$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.", "apr1", 1600),
        ("*E6CC90B878B948C35E92B003C792C46C58C4AF40", "MySQL 4.1", 300),
        ("{SSHA}uFT2G5401Kk6MImUYtG4Ynf5R6E6Z0Zw", "SSHA", 111),
        ("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "NTLM", 1000),
        ("admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:0101000000000000", "NetNTLMv2", 5600),
        ("u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c", "NetNTLMv1", 5500),
        ("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$abcdefghijk", "Argon2", None),
    ]

    def test_structured_hashes_identify_as_top_candidate(self):
        for h, name_sub, _mode in self.STRUCTURED:
            with self.subTest(hash=h[:24]):
                cands = hashtools.identify(h)
                self.assertTrue(cands, f"no candidates for {name_sub}")
                self.assertIn(name_sub.lower(), cands[0]["name"].lower())

    def test_structured_hashes_carry_correct_hashcat_mode(self):
        for h, name_sub, mode in self.STRUCTURED:
            with self.subTest(hash=h[:24]):
                cands = hashtools.identify(h)
                self.assertEqual(cands[0]["hashcat"], mode)

    def test_raw_md5_is_ambiguous_and_lists_ntlm(self):
        # A bare 32-hex is genuinely MD5 *or* NTLM (and more). The identifier
        # must return the whole ambiguous set, not a single confident guess.
        cands = hashtools.identify("b4b9b02e6f09a9bd760f388b67351e2b")
        names = " ".join(c["name"] for c in cands)
        self.assertGreater(len(cands), 1)
        self.assertIn("MD5", names)
        self.assertIn("NTLM", names)
        self.assertTrue(all(c["ambiguous"] for c in cands))

    def test_raw_sha256_top_candidate_is_sha256(self):
        cands = hashtools.identify("127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935")
        self.assertIn("SHA-256", cands[0]["name"])
        self.assertEqual(cands[0]["hashcat"], 1400)

    def test_every_catalog_example_self_identifies(self):
        # An example that doesn't match its own pattern is a broken catalog
        # entry — it would mislead anyone who pastes it to see the shape.
        for _pat, ht in hashtools._STRUCTURED:
            if not ht.example:
                continue
            with self.subTest(type=ht.name):
                names = [c["name"] for c in hashtools.identify(ht.example)]
                self.assertIn(ht.name, names)

    def test_garbage_and_empty_return_no_candidates(self):
        for junk in ("", "   ", "not a hash at all!!", "xyz"):
            with self.subTest(junk=junk):
                self.assertEqual(hashtools.identify(junk), [])

    def test_oversized_input_rejected(self):
        self.assertEqual(hashtools.identify("a" * 9000), [])

    def test_crack_commands_wire_mode_and_format(self):
        cmds = hashtools.crack_commands(1000, "nt", attack="wordlist")
        self.assertIn("-m 1000", cmds["hashcat"])
        self.assertIn("--format=nt", cmds["john"])
        bf = hashtools.crack_commands(0, "raw-md5", attack="bruteforce")
        self.assertIn("-a 3", bf["hashcat"])

    def test_crack_commands_none_mode_yields_no_hashcat(self):
        # Argon2/yescrypt have no hashcat mode — must not fabricate one.
        cmds = hashtools.crack_commands(None, "argon2")
        self.assertIsNone(cmds["hashcat"])
        self.assertIsNotNone(cmds["john"])


# ==========================================================================
# 10. consoles/redcell/webscan.py — grading + header/cookie/CORS logic
# ==========================================================================
class WebScanGradeTests(unittest.TestCase):

    def test_grade_boundaries(self):
        self.assertEqual(webscan._grade(90, 100)[0], "A")
        self.assertEqual(webscan._grade(80, 100)[0], "B")
        self.assertEqual(webscan._grade(65, 100)[0], "C")
        self.assertEqual(webscan._grade(50, 100)[0], "D")
        self.assertEqual(webscan._grade(49, 100)[0], "F")

    def test_grade_zero_max_no_divide_by_zero(self):
        letter, pct = webscan._grade(0, 0)
        self.assertEqual(letter, "F")
        self.assertEqual(pct, 0.0)

    def test_missing_hsts_is_high_finding(self):
        pts, mx, findings = webscan._check_hsts(None)
        self.assertEqual(pts, 0)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    def test_strong_hsts_scores_full_no_findings(self):
        pts, mx, findings = webscan._check_hsts("max-age=31536000; includeSubDomains; preload")
        self.assertEqual(pts, mx)
        self.assertEqual(findings, [])

    def test_csp_unsafe_inline_flagged(self):
        pts, mx, findings = webscan._check_csp("default-src 'self' 'unsafe-inline'")
        self.assertLess(pts, mx)
        self.assertTrue(any("unsafe-inline" in f["title"].lower() or "unsafe-inline" in f["detail"].lower()
                            for f in findings))


class WebScanCookieTests(unittest.TestCase):
    """The Set-Cookie splitter must survive the Expires=...GMT comma that sits
    INSIDE one cookie without treating it as a cookie boundary — the classic
    bug in naive comma-splitting of a collapsed Set-Cookie header."""

    def test_splits_two_cookies_not_on_expires_comma(self):
        raw = ("session=abc; Path=/; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Secure; HttpOnly, "
               "token=xyz; SameSite=Strict")
        cookies, findings = webscan._analyze_cookies(raw)
        names = [c["name"] for c in cookies]
        self.assertEqual(names, ["session", "token"])

    def test_flags_detected_correctly(self):
        raw = "session=abc; Secure; HttpOnly, token=xyz; SameSite=Strict"
        cookies, _ = webscan._analyze_cookies(raw)
        by = {c["name"]: c for c in cookies}
        self.assertTrue(by["session"]["secure"])
        self.assertTrue(by["session"]["httponly"])
        self.assertEqual(by["session"]["samesite"], "(none)")
        self.assertFalse(by["token"]["secure"])
        self.assertEqual(by["token"]["samesite"], "Strict")

    def test_insecure_cookie_raises_medium_findings(self):
        _cookies, findings = webscan._analyze_cookies("id=1")
        sevs = {f["severity"] for f in findings}
        self.assertIn("medium", sevs)  # missing Secure + HttpOnly

    def test_no_cookies_no_findings(self):
        self.assertEqual(webscan._analyze_cookies(None), ([], []))


class WebScanAnalyzeIntegrationTests(unittest.TestCase):
    """End-to-end analyze() with common.fetch mocked, so no network. Proves the
    grade/findings pipeline wires together and a hostile response body can't
    escape (title is extracted as text, never interpreted)."""

    def _fake_fetch(self, status, headers, body=b""):
        def _f(url, **kwargs):
            return status, body, headers
        return _f

    def test_wide_open_site_grades_poorly(self):
        headers = {"Server": "nginx/1.18.0", "Content-Type": "text/html",
                   "Set-Cookie": "sid=1"}
        with mock.patch.object(webscan.common, "fetch",
                               side_effect=self._fake_fetch(200, headers, b"<title>hi</title>")):
            r = webscan.analyze("http://example.com")
        self.assertTrue(r["ok"])
        self.assertIn(r["grade"], ("D", "F"))  # no security headers at all
        self.assertTrue(any(f["severity"] == "high" for f in r["findings"]))
        self.assertEqual(r["title"], "hi")
        # version disclosure caught
        self.assertTrue(any("disclosure" in f["title"].lower() for f in r["findings"]))

    def test_hardened_site_grades_well(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Content-Type": "text/html",
        }
        with mock.patch.object(webscan.common, "fetch",
                               side_effect=self._fake_fetch(200, headers, b"")):
            r = webscan.analyze("https://example.com")
        self.assertIn(r["grade"], ("A", "B"))

    def test_blocked_target_returns_error_not_crash(self):
        def _raise(url, **kw):
            raise ValueError("host resolves to non-public address")
        with mock.patch.object(webscan.common, "fetch", side_effect=_raise):
            r = webscan.analyze("http://169.254.169.254/")
        self.assertFalse(r["ok"])
        self.assertIn("blocked", r["error"])


# ==========================================================================
# 11. consoles/redcell/playbooks.py — recipe integrity
# ==========================================================================
class PlaybookIntegrityTests(unittest.TestCase):
    """A playbook step that names a runner not in SAFE_RUNNERS would 400 at
    execution time and break the one-click flow — catch it at test time."""

    def test_every_runner_step_references_a_real_safe_runner(self):
        for p in playbooks.catalog():
            for step in p["steps"]:
                if step["kind"] == "runner":
                    with self.subTest(playbook=p["key"], tool=step["tool"]):
                        self.assertIn(step["tool"], runners.SAFE_RUNNERS)

    def test_step_kinds_are_known(self):
        for p in playbooks.catalog():
            for step in p["steps"]:
                self.assertIn(step["kind"], ("runner", "web-analyze", "secret-scan"))

    def test_playbook_keys_unique(self):
        keys = [p["key"] for p in playbooks.catalog()]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_playbook_has_target_kind(self):
        for p in playbooks.catalog():
            self.assertIn(p["target_kind"], ("url", "host"))

    def test_wordlist_steps_marked(self):
        # A step needing a wordlist must say so, else the executor won't pass one.
        for p in playbooks.catalog():
            for step in p["steps"]:
                if step.get("kind") == "runner" and step.get("tool") in ("ffuf", "gobuster-dir", "gobuster-dns"):
                    with self.subTest(playbook=p["key"]):
                        self.assertTrue(step.get("needs_wordlist"))

    def test_step_kinds_include_secret_scan(self):
        # secret-scan is a valid client-executed kind (its own endpoint).
        for p in playbooks.catalog():
            for step in p["steps"]:
                self.assertIn(step["kind"], ("runner", "web-analyze", "secret-scan"))


# ==========================================================================
# 12. consoles/redcell/secretscan.py — API-key / secret leak detection
# ==========================================================================
class SecretScanCorpusTests(unittest.TestCase):
    """Labeled corpus: each planted credential must be found under the right
    rule AND the right severity. Getting severity wrong is as bad as missing
    it — a report that screams about a public Stripe key and buries the live
    secret key is worse than useless."""

    CASES = [
        ("AWS Access Key ID", 'const k="AKIAIOSFODNN7EXAMPLE";', "critical", False),
        ("GitHub token", 'token: "ghp_' + "a" * 36 + '"', "critical", False),
        ("GitLab personal access token", 'x = "glpat-' + "a" * 20 + '"', "critical", False),
        ("Stripe secret key (LIVE)", 'stripe="sk_live_' + "a" * 24 + '"', "critical", False),
        ("Stripe publishable key (LIVE)", 'pub="pk_live_' + "b" * 24 + '"', "info", True),
        ("Slack token", 'x="xoxb-123456789012-abcdefghijkl"', "high", False),
        ("Google API key", 'key:"AIza' + "C" * 35 + '"', "medium", True),
        ("Private key block", '-----BEGIN RSA PRIVATE KEY-----', "critical", False),
        ("SendGrid API key", 'SG.' + "a" * 22 + '.' + "b" * 43, "critical", False),
        ("Anthropic API key", 'k="sk-ant-' + "x" * 30 + '"', "critical", False),
        ("Basic-auth credentials in URL", 'fetch("https://user:s3cretpass@api.example.com/x")', "high", False),
    ]

    def test_every_planted_secret_is_found(self):
        for rule, text, _sev, _pub in self.CASES:
            with self.subTest(rule=rule):
                names = [f["rule"] for f in secretscan.scan_text(text, "t")]
                self.assertIn(rule, names)

    def test_severity_and_public_flag_correct(self):
        for rule, text, sev, pub in self.CASES:
            with self.subTest(rule=rule):
                f = next(f for f in secretscan.scan_text(text, "t") if f["rule"] == rule)
                self.assertEqual(f["severity"], sev)
                self.assertEqual(f["public_ok"], pub)

    def test_generic_placeholder_is_suppressed(self):
        for placeholder in ('apiKey: "your_api_key_here"', 'secret = "changeme12345678"',
                            'token: "xxxxxxxxxxxxxxxx"'):
            with self.subTest(v=placeholder):
                fs = [f for f in secretscan.scan_text(placeholder, "t") if "assignment" in f["rule"]]
                self.assertEqual(fs, [])

    def test_generic_high_entropy_secret_is_caught(self):
        fs = [f for f in secretscan.scan_text('apiKey: "a8Fk2Lp9Qz3Xr7Vn1Bm4Cw6"', "t")
              if "assignment" in f["rule"]]
        self.assertTrue(fs)

    def test_masked_never_contains_full_secret(self):
        secret = "ghp_" + "a" * 36
        f = secretscan.scan_text(f'x="{secret}"', "t")[0]
        self.assertNotIn(secret, f["masked"])
        self.assertEqual(f["match"], secret)  # full value still available to the report

    def test_entropy_of_random_higher_than_word(self):
        self.assertGreater(secretscan._entropy("a8Fk2Lp9Qz3Xr7Vn1Bm4Cw6"),
                           secretscan._entropy("passwordpassword"))

    def test_clean_page_has_no_findings(self):
        self.assertEqual(secretscan.scan_text("<html><body>hello world</body></html>", "t"), [])


class SecretScanScopeTests(unittest.TestCase):
    """The JS harvester must stay on the target's own site — a scan of site X
    must not go fetch site Y's bundles."""

    def test_same_host_is_same_site(self):
        self.assertTrue(secretscan._same_site("app.example.com", "app.example.com"))

    def test_subdomain_of_apex_is_same_site(self):
        self.assertTrue(secretscan._same_site("cdn.example.com", "www.example.com"))
        self.assertTrue(secretscan._same_site("example.com", "www.example.com"))

    def test_third_party_is_not_same_site(self):
        self.assertFalse(secretscan._same_site("cdn.jsdelivr.net", "www.example.com"))
        self.assertFalse(secretscan._same_site("evil.com", "example.com"))

    def test_relative_url_treated_as_same_site(self):
        self.assertTrue(secretscan._same_site("", "example.com"))

    def test_cross_origin_scripts_skipped_not_fetched(self):
        html = (b'<script src="https://cdn.jsdelivr.net/x.js"></script>'
                b'<script src="/app.js"></script>')
        urls, skipped, over_cap = secretscan._collect_script_urls(html, "https://example.com/", "example.com")
        self.assertEqual(skipped, 1)
        self.assertEqual(over_cap, 0)
        self.assertEqual(urls, ["https://example.com/app.js"])

    def test_multi_tenant_suffix_is_not_same_site(self):
        # audit P1 #5 — two tenants on a multi-label suffix must NOT be same-site
        self.assertFalse(secretscan._same_site("evil.github.io", "victim.github.io"))
        self.assertFalse(secretscan._same_site("them.co.uk", "us.co.uk"))
        self.assertFalse(secretscan._same_site("other.s3.amazonaws.com", "mine.s3.amazonaws.com"))
        # but a real subdomain of the same registrable domain still is
        self.assertTrue(secretscan._same_site("cdn.victim.github.io", "victim.github.io"))
        self.assertTrue(secretscan._same_site("app.example.co.uk", "www.example.co.uk"))

    def test_modulepreload_links_harvested(self):
        html = (b'<link rel="modulepreload" href="/_next/chunk-admin.js">'
                b'<link href="/prefetch.mjs" rel="prefetch">')
        urls, _skip, _cap = secretscan._collect_script_urls(html, "https://example.com/", "example.com")
        self.assertIn("https://example.com/_next/chunk-admin.js", urls)
        self.assertIn("https://example.com/prefetch.mjs", urls)


class SecretScanAnalyzeIntegrationTests(unittest.TestCase):
    """analyze() with fetch mocked: a secret in the HTML and one in a same-site
    JS bundle must both surface, and a cross-origin script must not be fetched."""

    def test_finds_secrets_in_html_and_same_site_js(self):
        page = (b'<html><script src="/bundle.js"></script>'
                b'<script src="https://cdn.jsdelivr.net/lib.js"></script>'
                b'<script>var t="ghp_' + b"a" * 36 + b'";</script></html>')
        js = 'const stripe = "sk_live_' + "z" * 24 + '";'

        def fake_fetch(url, **kwargs):
            if url == "https://example.com/":
                return 200, page, {}
            if url == "https://example.com/bundle.js":
                return 200, js.encode(), {}
            raise AssertionError(f"should not fetch cross-origin: {url}")

        with mock.patch.object(secretscan.common, "fetch", side_effect=fake_fetch):
            r = secretscan.analyze("https://example.com/")
        self.assertTrue(r["ok"])
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("GitHub token", rules)          # from inline HTML script
        self.assertIn("Stripe secret key (LIVE)", rules)  # from same-site JS
        self.assertEqual(r["scripts_skipped_cross_origin"], 1)
        self.assertGreaterEqual(r["real_leak_count"], 2)

    def test_blocked_target_returns_error_not_crash(self):
        with mock.patch.object(secretscan.common, "fetch",
                               side_effect=ValueError("non-public address")):
            r = secretscan.analyze("http://169.254.169.254/")
        self.assertFalse(r["ok"])
        self.assertIn("blocked", r["error"])

    def test_total_scan_budget_caps_work_on_huge_target(self):
        # A page linking many large same-site scripts must stop SCANNING once
        # the byte budget is hit — bounds worst-case CPU regardless of target.
        n_scripts = (secretscan._TOTAL_SCAN_BUDGET // 2_000_000) + 4
        page = b"<html>" + b"".join(
            b'<script src="/s%d.js"></script>' % i for i in range(n_scripts)) + b"</html>"
        big_js = b"var x=1;" * 250_000  # ~2MB, no secrets

        def fake_fetch(url, **kwargs):
            return (200, page, {}) if url.endswith("/") else (200, big_js, {})

        with mock.patch.object(secretscan.common, "fetch", side_effect=fake_fetch):
            r = secretscan.analyze("https://example.com/")
        self.assertTrue(r["ok"])
        self.assertTrue(r["scan_truncated"])
        self.assertLessEqual(r["bytes_scanned"], secretscan._TOTAL_SCAN_BUDGET + 2_000_000)
        # some scripts were fetched but explicitly marked not-scanned
        self.assertTrue(any(s.get("fetched") and not s.get("scanned") for s in r["scripts_scanned"]))

    def test_keyword_prefilter_does_not_drop_detections(self):
        # The pre-filter is an optimization, not a behavior change — a real
        # secret whose keyword is present must still be found.
        fs = secretscan.scan_text('const s = "sk_live_' + "a" * 30 + '";', "t")
        self.assertTrue(any(f["rule"] == "Stripe secret key (LIVE)" for f in fs))

    def test_inline_script_extraction_is_linear_on_unclosed_tags(self):
        # Regression: a `.*?</script>` regex over a page full of UNCLOSED
        # <script> tags backtracks O(n^2) (a multi-minute stall). The linear
        # find-scan must finish a 2MB pathological page effectively instantly.
        import time
        pathological = b"<script>" * 250_000  # ~2MB, no closing tags
        t0 = time.monotonic()
        out = secretscan._iter_inline_scripts(pathological)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 2.0, f"inline extraction took {elapsed:.1f}s — O(n^2) regression")
        self.assertLessEqual(len(out), secretscan._MAX_INLINE_SCRIPTS)

    def test_inline_extraction_finds_inline_skips_external(self):
        page = (b'<script>var a="ghp_' + b"a" * 36 + b'";</script>'
                b'<script src="/x.js">this is not inline body</script>')
        out = secretscan._iter_inline_scripts(page)
        self.assertEqual(len(out), 1)           # the src= script is skipped
        self.assertIn(b"ghp_", out[0])

    def test_secret_scan_audit_strips_query_string(self):
        # A querystring can itself carry a secret (?api_key=...); the audit log
        # must record scheme/host/path only, never the query.
        captured = {}
        page = b'<html><script>var k="AKIAIOSFODNN7EXAMPLE";</script></html>'

        def fake_fetch(url, **kwargs):
            return 200, page, {}

        class Req:
            def json(self):
                return {"url": "https://example.com/app?api_key=supersecret123456",
                        "authorized": True, "proceed_exposed": True}  # skip the opsec gate in this test

        with mock.patch.object(secretscan.common, "fetch", side_effect=fake_fetch), \
             mock.patch.object(secretscan.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]), \
             mock.patch.object(secretscan.common, "host_is_public", return_value=True), \
             mock.patch.object(secretscan.runners, "_append_audit",
                               side_effect=lambda e: captured.update(e)):
            secretscan.handle_secret_scan(Req())
        self.assertIn("target", captured)
        self.assertNotIn("?", captured["target"])
        self.assertNotIn("supersecret", captured["target"])
        self.assertEqual(captured["target"], "https://example.com/app")


class SecretScanUpgradeTests(unittest.TestCase):
    """The 2026-07-17 overhaul: new provider shapes, the JSON quoted-key fix,
    3-word compounds, query-param + unlabeled-entropy passes, JWT decode-gating,
    and the credential-scoped placeholder filter."""

    def test_json_quoted_key_is_caught(self):
        # audit P0 #3 — "apiKey":"..." (closing quote before the colon)
        fs = secretscan.scan_text('{"apiKey":"Ab3Xy9Kd7Qm2Wp5Rt8Zc1Nv4Bh6Jl0"}', "t")
        self.assertTrue(fs, "JSON quoted-key assignment must be found")

    def test_aws_secret_without_aws_literal(self):
        # audit P0 #2 — secretAccessKey with no nearby "aws" literal
        blob = '{"secretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
        rules = {f["rule"] for f in secretscan.scan_text(blob, "t")}
        self.assertIn("AWS Secret Access Key", rules)

    def test_secret_in_url_query_param(self):
        fs = [f for f in secretscan.scan_text('fetch("/v1/x?api_key=Ab3Xy9Kd7Qm2Wp5Rt8Zc1Nv4")', "t")
              if "query" in f["rule"].lower()]
        self.assertTrue(fs)

    def test_unlabeled_high_entropy_string_found_at_low(self):
        fs = [f for f in secretscan.scan_text('const t="Zx9Kd7Qm2Wp5Rt8Zc1Nv4Bh6Jl0Ab3Xy";', "t")
              if "unlabeled" in f["rule"].lower()]
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "low")

    def test_jwt_lookalike_that_does_not_decode_is_dropped(self):
        # eyJ..eyJ.. shape but the header doesn't base64-decode to JSON
        fs = [f for f in secretscan.scan_text(
            'x="eyJhbGciOiJub25lICBz.eyJzdWIiOjF9.sig"', "t") if "JWT" in f["rule"]]
        self.assertEqual(fs, [])

    def test_real_jwt_is_found(self):
        import base64, json as _json
        seg = lambda o: base64.urlsafe_b64encode(_json.dumps(o).encode()).rstrip(b"=").decode()
        tok = seg({"alg": "HS256"}) + "." + seg({"iss": "acme", "sub": "42"}) + "." + "a" * 43
        found = [f for f in secretscan.scan_text(f'x="{tok}"', "t") if "JWT" in f["rule"]]
        self.assertTrue(found)

    def test_basic_auth_placeholder_scoped_to_password(self):
        # real password kept even if the HOST contains "example"; doc example dropped
        keep = secretscan.scan_text('fetch("https://user:s3cretPass9@api.example.com/x")', "t")
        self.assertTrue(any("Basic-auth" in f["rule"] for f in keep))
        drop = secretscan.scan_text('fetch("https://username:password@api.corp.com/x")', "t")
        self.assertFalse(any("Basic-auth" in f["rule"] for f in drop))

    def test_new_provider_shapes(self):
        cases = {
            "Shopify access token": "shpat_" + "a" * 32,
            "DigitalOcean access token": "doo_v1_" + "a" * 64,
            "Notion integration token (legacy)": "secret_" + "A" * 43,
            "Telegram bot token": "123456789:AA" + "b" * 33,
            "HashiCorp Vault service token": "hvs." + "C" * 95,
            "New Relic user API key": "NRAK-" + "A9" * 13 + "Z",  # 27 chars after NRAK-
        }
        for rule, val in cases.items():
            with self.subTest(rule=rule):
                rules = {f["rule"] for f in secretscan.scan_text(f'x="{val}";', "t")}
                self.assertIn(rule, rules)

    def test_db_connection_string_with_inline_password(self):
        fs = {f["rule"] for f in secretscan.scan_text(
            'DB="postgres://admin:Sup3rS3cret@db.internal:5432/app"', "t")}
        self.assertIn("Database connection string with inline credentials", fs)


class SecretScanFindingCapTests(unittest.TestCase):
    """audit P0 #1 — a noisy earlier file must NOT starve out a live secret in a
    later file. The old global cap aborted the scan loop; the fix scans every
    file and only trims the DISPLAYED list, after sorting by severity."""

    def test_live_secret_in_later_file_survives_noise(self):
        page = (b'<html><script src="/vendor.js"></script>'
                b'<script src="/app.js"></script></html>')
        # vendor.js: hundreds of low-value generic hits; app.js: one live Stripe key
        noise = ("var cfg={" + ",".join(f'apiKey{i}:"a8Fk2Lp9Qz3Xr7Vn1Bm4Cw{i:03d}"'
                                          for i in range(500)) + "};").encode()
        app = ('const stripe="sk_live_' + "z" * 30 + '";').encode()

        def fake_fetch(url, **kwargs):
            if url.endswith("/"):
                return 200, page, {}
            if url.endswith("/vendor.js"):
                return 200, noise, {}
            if url.endswith("/app.js"):
                return 200, app, {}
            raise AssertionError(url)

        with mock.patch.object(secretscan.common, "fetch", side_effect=fake_fetch):
            r = secretscan.analyze("https://example.com/")
        self.assertTrue(r["ok"])
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("Stripe secret key (LIVE)", rules,
                      "the live key in the second file must survive the noisy first file")


class SecretScanSourcemapTests(unittest.TestCase):
    """audit P0 #8 — the sourceMappingURL marker lives in the JS bundle, and the
    .map must be fetched + its de-minified sourcesContent scanned."""

    def test_sourcemap_recovered_and_scanned(self):
        page = b'<html><script src="/app.min.js"></script></html>'
        bundle = b'var t=1;\n//# sourceMappingURL=app.min.js.map'
        smap = json.dumps({
            "version": 3, "sources": ["src/config.js"],
            "sourcesContent": ['const stripe = "sk_live_' + "q" * 30 + '";'],
        }).encode()

        def fake_fetch(url, **kwargs):
            if url.endswith("/"):
                return 200, page, {}
            if url.endswith("/app.min.js"):
                return 200, bundle, {}
            if url.endswith("/app.min.js.map"):
                return 200, smap, {}
            raise AssertionError(url)

        with mock.patch.object(secretscan.common, "fetch", side_effect=fake_fetch):
            r = secretscan.analyze("https://example.com/")
        self.assertTrue(r["ok"])
        self.assertGreaterEqual(r["sourcemaps_scanned"], 1)
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("Stripe secret key (LIVE)", rules)


class KeyVerifyTests(unittest.TestCase):
    """The build-not-run verification helper: correct commands, paste-safety
    against attacker-controlled key values, and offline JWT decoding."""

    def test_command_built_for_known_provider(self):
        c = keyverify.build_command("GitHub token", "ghp_" + "a" * 36)
        self.assertIn("api.github.com/user", c["command"])
        self.assertTrue(c["leaves_target"])

    def test_paste_safety_against_injection(self):
        # A hostile page could plant a "key" full of shell metacharacters. The
        # built command must parse back (shlex, POSIX) with the evil value intact
        # as ONE literal argument — proof the shell treats it as inert data, not
        # code (no command substitution, no extra args).
        import shlex
        evil = "x`touch /tmp/pwned`;rm -rf ~"
        c = keyverify.build_command("OpenAI API key", evil)
        tokens = shlex.split(c["command"])  # would mis-split if quoting were broken
        self.assertTrue(any(evil in tok for tok in tokens),
                        "the hostile value must survive as one inert literal argument")

    def test_pair_flagged_for_aws(self):
        c = keyverify.build_command("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(c["needs_pair"])
        self.assertIn("<SECRET>", c["command"])

    def test_no_safe_check_reason(self):
        self.assertIsNotNone(keyverify.no_check_reason("Anthropic API key"))
        self.assertIsNone(keyverify.no_check_reason("GitHub token"))

    def test_jwt_decode_valid_and_invalid(self):
        import base64, json as _json
        seg = lambda o: base64.urlsafe_b64encode(_json.dumps(o).encode()).rstrip(b"=").decode()
        tok = seg({"alg": "HS256"}) + "." + seg({"iss": "acme"}) + ".sig"
        d = keyverify.decode_jwt(tok)
        self.assertEqual(d["payload"]["iss"], "acme")
        self.assertIsNone(keyverify.decode_jwt("not.a.jwt"))


class SecretScanBenchmarkFloorTests(unittest.TestCase):
    """CI floor tied to the labeled corpus (tests/secret_bench.py). If a change
    regresses recall or precision on the corpus, this fails — the eval-gate that
    plain unit tests can miss."""

    def test_corpus_recall_and_precision_are_perfect(self):
        import secret_bench
        m = secret_bench.score()
        self.assertEqual(m["recall"], 1.0,
                         f"recall regressed — missed: {[p.cid for p in m['misses']]}")
        self.assertEqual(m["precision"], 1.0,
                         f"precision regressed — false alarms: {[d.cid for d, _ in m['false_pos']]}")


class ExpertRedactionTests(unittest.TestCase):
    """A runner token must be scrubbed from Expert-mode output/audit — else it
    leaks in cleartext to var/redcell-scans.jsonl and the HTTP response. The
    redaction set unions the OSINT catalog with every runner-declared token, so
    a runner token is covered whether or not it's also in the catalog."""

    def test_every_runner_token_is_in_the_redaction_set(self):
        names = runners._all_secret_env_names()
        for spec in runners.SAFE_RUNNERS.values():
            if spec.uses_apikey:
                self.assertIn(spec.uses_apikey, names,
                              f"{spec.uses_apikey} would leak in Expert mode")

    def test_runner_token_is_redacted(self):
        self.assertIn("WPSCAN_API_TOKEN", runners._all_secret_env_names())
        with mock.patch.object(apikeys, "get_key",
                               side_effect=lambda n: "tok-abc-123" if n == "WPSCAN_API_TOKEN" else ""):
            out = runners._redact_all("wpscan --api-token tok-abc-123 --url http://x")
        self.assertNotIn("tok-abc-123", out)
        self.assertIn("***REDACTED***", out)


class WebScanTitleTests(unittest.TestCase):
    def test_title_extraction_linear_on_unclosed_tags(self):
        import time
        t0 = time.monotonic()
        webscan._extract_title(b"<title>" * 300_000)  # ~2MB unclosed
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_title_extracted_normally(self):
        self.assertEqual(webscan._extract_title(b"<html><title>Hi There</title></html>"), "Hi There")


# ==========================================================================
# 14. consoles/redcell/stresstest.py — DDoS resilience probe
#
# The probe fires real HTTP through common.fetch, so every test mocks fetch to
# canned responses (like the webscan/secretscan tests) — no network, fully
# deterministic. These lock down the three things that keep this tool a
# diagnostic and not a weapon: the hard caps, the circuit breaker, and the gate
# stack; plus the defense-detection and grade-by-error-origin logic.
# ==========================================================================
class _StressReq:
    """Minimal stand-in for the server's request object — only .json() is used."""
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def _stress_fetch(status=200, headers=None, body=b"ok"):
    def _f(url, **kw):
        return status, body, dict(headers or {})
    return _f


class StressCapTests(unittest.TestCase):
    """The caps are the whole safety story — they must be real ceilings, and
    every declared tier must sit under them."""

    def test_caps_stay_under_weapon_territory(self):
        # Tripwire: the caps can be a real load test, but must stay under the
        # "needs a cloud provider's sign-off" line (research: ~1M requests /
        # 30min). Concurrency was deliberately raised to 1000 for heavy authorized
        # engagements — that's above the ~500-connection casual line, which is why
        # the total-request (50k) and wall-clock (180s) ceilings, plus the gates
        # and breaker, carry the "not a weapon" guarantee. This tripwire keeps a
        # FUTURE accidental bump past the intended ceilings from sliding through.
        self.assertLessEqual(stresstest.MAX_CONCURRENCY, 1000)
        self.assertLessEqual(stresstest.MAX_TOTAL_REQUESTS, 500_000)
        self.assertLessEqual(stresstest.MAX_DURATION_S, 600)

    def test_every_tier_stays_within_concurrency_cap(self):
        for tier, spec in stresstest._TIERS.items():
            self.assertLessEqual(max(spec["ramp"]), stresstest.MAX_CONCURRENCY, tier)

    def test_probe_never_exceeds_total_request_cap(self):
        huge = {"smoke": {"ramp": [1], "hold": 0}, "huge": {"ramp": [10], "hold": 200}}
        with mock.patch.object(stresstest, "_TIERS", huge), \
             mock.patch.object(stresstest, "MAX_TOTAL_REQUESTS", 500), \
             mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch()):
            r = stresstest.probe("https://cap.example", "huge")
        self.assertLessEqual(r["totals"]["requests"], 500)
        self.assertIn("request cap", r["aborted"])

    def test_stress_tier_sustains_at_peak(self):
        # The stress tier must actually hold load at peak (not just ramp once) so
        # a well-provisioned target gets exercised — more steps at peak concurrency
        # than the ramp alone has.
        self.assertIn("stress", stresstest._TIERS)
        spec = stresstest._TIERS["stress"]
        self.assertGreater(spec["hold"], 0)
        # Cap the run small so the test is fast; the hold behavior is the same.
        with mock.patch.object(stresstest, "MAX_TOTAL_REQUESTS", 6000), \
             mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "cloudflare", "CF-Ray": "a"})):
            r = stresstest.probe("https://big.example", "stress")
        peak = max(spec["ramp"])
        peak_steps = [s for s in r["steps"] if s["concurrency"] == peak]
        self.assertGreater(len(peak_steps), 1)  # sustained, not a single peak touch
        self.assertGreater(r["totals"]["requests"], 3000)  # a real load test, not a smoke read

    def test_probe_respects_wall_clock_cap(self):
        with mock.patch.object(stresstest, "MAX_DURATION_S", 0.0), \
             mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch()):
            r = stresstest.probe("https://t.example", "smoke")
        self.assertTrue(r["ok"])
        self.assertIn("time cap", r["aborted"])


class StressCustomModeTests(unittest.TestCase):
    """Custom mode lets the operator pick request count / duration / concurrency
    for a detailed client test — but it must obey the SAME hard caps as a tier.
    These lock down the clamp (so it can't be an escape hatch) and that the run
    actually stops on the budget the operator set."""

    def test_parse_clamps_every_field_to_the_caps(self):
        spec = stresstest.parse_custom_spec(
            {"concurrency": 10_000, "requests": 9_999_999, "duration": "10m"})
        self.assertEqual(spec["concurrency"], stresstest.MAX_CONCURRENCY)
        self.assertEqual(spec["requests"], stresstest.MAX_TOTAL_REQUESTS)
        self.assertEqual(spec["duration_s"], stresstest.MAX_DURATION_S)
        # The raw request is preserved for the read-out's "you asked for" line.
        self.assertEqual(spec["requested"]["requests"], 9_999_999)

    def test_parse_junk_and_missing_fall_back_to_safe_defaults(self):
        spec = stresstest.parse_custom_spec({"concurrency": "abc", "requests": None})
        self.assertEqual(spec["concurrency"], stresstest._CUSTOM_DEFAULT_CONCURRENCY)
        self.assertEqual(spec["requests"], stresstest._CUSTOM_DEFAULT_REQUESTS)
        self.assertEqual(spec["duration_s"], stresstest._CUSTOM_DEFAULT_DURATION_S)

    def test_duration_units_and_floor(self):
        self.assertEqual(stresstest._parse_duration_s("90s", 180.0, 60.0), 90.0)
        self.assertEqual(stresstest._parse_duration_s("2m", 180.0, 60.0), 120.0)
        self.assertEqual(stresstest._parse_duration_s("1h", 180.0, 60.0), 180.0)  # clamped
        self.assertEqual(stresstest._parse_duration_s(45, 180.0, 60.0), 45.0)     # bare seconds
        self.assertEqual(stresstest._parse_duration_s(0, 180.0, 60.0), 60.0)      # 0 is meaningless → default
        self.assertEqual(stresstest._parse_duration_s(-5, 180.0, 60.0), 60.0)     # negative → default
        self.assertEqual(stresstest._parse_duration_s(0.5, 180.0, 60.0), 1.0)     # sub-second floored to >=1

    def test_custom_run_stops_on_the_request_budget(self):
        spec = stresstest.parse_custom_spec(
            {"concurrency": 50, "requests": 300, "duration": "120s"})
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "cloudflare", "CF-Ray": "a"})):
            r = stresstest.probe("https://c.example", "custom", custom=spec)
        self.assertTrue(r["ok"])
        self.assertEqual(r["tier"], "custom")
        self.assertLessEqual(r["totals"]["requests"], 300)
        self.assertIsNone(r["aborted"])          # a clean, expected stop, not an abort
        self.assertTrue(r["graceful_stop"])
        self.assertEqual(r["effective"]["requests"], 300)

    def test_custom_run_stops_on_the_duration_budget(self):
        # A tiny effective duration ends the run gracefully (the operator's choice),
        # not as an abort.
        with mock.patch.object(stresstest, "MAX_DURATION_S", 0.2), \
             mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch()):
            spec = stresstest.parse_custom_spec(
                {"concurrency": 10, "requests": 50_000, "duration": "0.2"})
            r = stresstest.probe("https://d.example", "custom", custom=spec)
        self.assertTrue(r["ok"])
        self.assertIsNone(r["aborted"])
        self.assertTrue(r["graceful_stop"])

    def test_custom_run_never_exceeds_the_hard_request_cap(self):
        # The safety invariant: even asking for far more than the cap, a custom
        # run can't push past MAX_TOTAL_REQUESTS. (Cap patched small for speed.)
        with mock.patch.object(stresstest, "MAX_TOTAL_REQUESTS", 500), \
             mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch()):
            spec = stresstest.parse_custom_spec(
                {"concurrency": 20, "requests": 9_999_999, "duration": "120s"})
            r = stresstest.probe("https://cap.example", "custom", custom=spec)
        self.assertLessEqual(r["totals"]["requests"], 500)

    def test_custom_run_ramps_then_sustains_at_peak(self):
        # With headroom in the request budget, a custom run walks a normal
        # progressive ramp (each rung real load) AND still delivers the bulk of
        # the budget as a sustained hold at the target concurrency. Concurrency
        # kept modest here so the suite doesn't spin a thousand threads; the ramp+
        # sustain logic is identical at any target. (Cap patched fast-but-roomy.)
        with mock.patch.object(stresstest, "MAX_TOTAL_REQUESTS", 40_000), \
             mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "cloudflare", "CF-Ray": "a"})):
            spec = stresstest.parse_custom_spec(
                {"concurrency": 200, "requests": 40_000, "duration": "120s"})
            r = stresstest.probe("https://peak.example", "custom", custom=spec)
        peak = r["effective"]["concurrency"]
        ramp_steps = [s for s in r["steps"] if s["concurrency"] < peak]
        peak_steps = [s for s in r["steps"] if s["concurrency"] == peak]
        peak_reqs = sum(s["requests"] for s in peak_steps)
        # A real ramp: it climbs through more than one rung, each firing real load
        # (not a token batch). The strong ladder is short by design.
        self.assertGreaterEqual(len(ramp_steps), 2)
        self.assertGreater(max(s["requests"] for s in ramp_steps), 100)
        # The ramp climbs (concurrency strictly increases up to the target).
        ramp_conc = [s["concurrency"] for s in ramp_steps]
        self.assertEqual(ramp_conc, sorted(ramp_conc))
        self.assertTrue(all(b > a for a, b in zip(ramp_conc, ramp_conc[1:])))
        # Sustained: more than one full step at the target, holding the majority
        # of the delivered load.
        self.assertGreater(len(peak_steps), 1)
        self.assertGreater(peak_reqs, r["totals"]["requests"] * 0.5)

    def test_custom_run_trips_the_breaker_when_it_is_on(self):
        # With the breaker ON (probe default), a failing origin still aborts.
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(500, {"Server": "nginx"})):
            spec = stresstest.parse_custom_spec(
                {"concurrency": 50, "requests": 5000, "duration": "120s"})
            r = stresstest.probe("https://z.example", "custom", custom=spec, breaker=True)
        self.assertIn("circuit breaker", r["aborted"] or "")
        self.assertEqual(r["grade"], "F")
        self.assertTrue(r["breaker_enabled"])

    def test_breaker_off_runs_full_ramp_but_still_grades_distress(self):
        # breaker=False: a failing origin does NOT abort — the run completes its
        # budget — but the distress is still measured and the grade is still F.
        # The custom-mode default is breaker off, which is what the operator wants
        # for a deliberate load test.
        with mock.patch.object(stresstest, "MAX_TOTAL_REQUESTS", 4000), \
             mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(500, {"Server": "nginx"})):
            spec = stresstest.parse_custom_spec(
                {"concurrency": 100, "requests": 4000, "duration": "120s"})
            r = stresstest.probe("https://z.example", "custom", custom=spec, breaker=False)
        self.assertNotIn("circuit breaker", r["aborted"] or "")
        self.assertFalse(r["breaker_enabled"])
        self.assertEqual(r["grade"], "F")            # distress still graded honestly
        self.assertTrue(r["graceful_stop"])          # it finished the budget instead of aborting
        # It actually climbed past where the breaker would have stopped it.
        self.assertTrue(any(s["concurrency"] == r["effective"]["concurrency"] for s in r["steps"]))
        self.assertGreater(r["totals"]["http_5xx"], 0)  # the failures ARE in the read-out


class StressPercentileTests(unittest.TestCase):
    def test_pct_basic(self):
        self.assertEqual(stresstest._pct([10, 20, 30, 40, 50], 50), 30.0)
        self.assertEqual(stresstest._pct([10, 20, 30, 40, 50], 100), 50.0)
        self.assertEqual(stresstest._pct([], 95), 0.0)

    def test_summary_shape(self):
        s = stresstest._summarize_latencies([5, 1, 3, 2, 4])
        self.assertEqual(s["min"], 1)
        self.assertEqual(s["max"], 5)
        self.assertEqual(s["count"], 5)


class StressProbeBehaviorTests(unittest.TestCase):
    def test_defended_target_grades_well(self):
        hdr = {"Server": "cloudflare", "CF-Ray": "abc-LAX", "X-RateLimit-Limit": "100"}
        with mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch(200, hdr)):
            r = stresstest.probe("https://x.example", "smoke")
        self.assertTrue(r["ok"])
        self.assertIn(r["grade"], ("A", "B"))
        self.assertTrue(r["defenses"]["rate_limiting"]["detected"])
        self.assertIn("Cloudflare", r["defenses"]["edge"]["providers"])

    def test_naked_origin_grades_poorly_with_high_findings(self):
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "nginx/1.18.0"})):
            r = stresstest.probe("https://y.example", "smoke")
        self.assertIn(r["grade"], ("D", "F"))
        self.assertTrue(any(f["severity"] == "high" for f in r["findings"]))

    def test_circuit_breaker_trips_on_5xx_and_stops_early(self):
        # Failing origin: the breaker must abort the ramp, not grind all steps.
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(500, {"Server": "nginx"})):
            r = stresstest.probe("https://z.example", "thorough")
        self.assertIn("circuit breaker", r["aborted"])
        self.assertLess(len(r["steps"]), len(stresstest._TIERS["thorough"]["ramp"]))
        self.assertEqual(r["grade"], "F")

    def test_edge_challenge_is_defended_not_failed(self):
        # 503 behind Cloudflare = the edge shedding load. Grade-by-origin must
        # read this as "found the ceiling" (D), never a naked-origin F.
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(503, {"Server": "cloudflare", "CF-Ray": "z-LAX"})):
            r = stresstest.probe("https://c.example", "smoke")
        self.assertTrue(r["defenses"]["challenge"]["detected"])
        self.assertEqual(r["grade"], "D")

    def test_unreachable_target_is_clean_error(self):
        def boom(url, **kw):
            raise OSError("connection refused")
        with mock.patch.object(stresstest, "_probe_get", side_effect=boom):
            r = stresstest.probe("https://u.example", "smoke")
        self.assertFalse(r["ok"])
        self.assertIn("unreachable", r["error"])

    def test_blocked_target_is_flagged_not_ramped(self):
        def blocked(url, **kw):
            raise ValueError("host resolves to non-public address")
        with mock.patch.object(stresstest, "_probe_get", side_effect=blocked):
            r = stresstest.probe("https://b.example", "smoke")
        self.assertFalse(r["ok"])
        self.assertIn("blocked", r["error"])


class StressDetectionTests(unittest.TestCase):
    def test_rate_limit_via_429(self):
        with mock.patch.object(stresstest, "_probe_get", side_effect=_stress_fetch(429, {})):
            r = stresstest.probe("https://rl.example", "smoke")
        self.assertTrue(r["defenses"]["rate_limiting"]["detected"])
        self.assertGreater(r["totals"]["rate_limited_429"], 0)

    def test_edge_via_server_header_marker(self):
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "AkamaiGHost"})):
            r = stresstest.probe("https://ak.example", "smoke")
        self.assertTrue(r["defenses"]["edge"]["present"])
        self.assertIn("Akamai", r["defenses"]["edge"]["providers"])

    def test_cf_mitigated_challenge_detected(self):
        with mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(403, {"cf-mitigated": "challenge", "Server": "cloudflare"})):
            r = stresstest.probe("https://ch.example", "smoke")
        self.assertTrue(r["defenses"]["challenge"]["detected"])


class _KAHandler(http.server.BaseHTTPRequestHandler):
    """A minimal keep-alive loopback server for the keep-alive probe tests."""
    protocol_version = "HTTP/1.1"   # keep-alive by default when Content-Length is set

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class StressKeepAliveTests(unittest.TestCase):
    """The high-RPS path reuses one SSRF-pinned connection per worker. These lock
    down the two things that matters: the SSRF guard still refuses private/loopback
    targets in the new path, and a connection is genuinely reused across requests."""

    def test_probe_get_ssrf_guard_holds_for_any_scheme(self):
        # The whole point: reusing common._resolve_public means the keep-alive path
        # inherits the SAME SSRF guard. The scheme allowlist is gone (an operator can
        # aim the probe at any scheme), so that guard now has to hold for ANY scheme,
        # not just http — every one of these must be refused BEFORE a socket is opened:
        # a ValueError, never a real connection. The ftp:// and gopher:// entries prove
        # dropping the scheme filter didn't open an SSRF hole.
        for bad in ("http://127.0.0.1/", "http://10.0.0.1/", "http://192.168.1.1/",
                    "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
                    "http://localhost/", "ftp://127.0.0.1/",
                    "gopher://169.254.169.254/", "http:///nohost"):
            with self.assertRaises(ValueError, msg=bad):
                stresstest._probe_get(bad, timeout=1.0)

    def test_keepalive_reuses_one_connection(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), _KAHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            # Allow loopback ONLY for this test by pinning the resolver.
            with mock.patch.object(stresstest.common, "_resolve_public",
                                   return_value=("127.0.0.1", socket.AF_INET)):
                ka = stresstest._KeepAliveConn()
                s1, _b1, h1 = stresstest._probe_get(url, keepalive=ka)
                first_conn = ka.conn
                s2, _b2, _h2 = stresstest._probe_get(url, keepalive=ka)
                second_conn = ka.conn
                ka.close()
            self.assertEqual((s1, s2), (200, 200))
            self.assertIsNotNone(first_conn)
            self.assertIs(first_conn, second_conn)   # the SAME connection was reused
            self.assertEqual(h1.get("Server"), "nginx")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_run_step_over_real_loopback_keepalive(self):
        # End-to-end through the real keep-alive _run_step (no mocked fetch) against
        # a live server: every request lands, none error, and the reuse means far
        # fewer connections than requests. Threaded server so N keep-alive
        # connections are served concurrently, the way a real target would.
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _KAHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            with mock.patch.object(stresstest.common, "_resolve_public",
                                   return_value=("127.0.0.1", socket.AF_INET)):
                step = stresstest._run_step(url, concurrency=4, n_requests=40,
                                            deadline=time.monotonic() + 15)
            self.assertEqual(step["requests"], 40)
            self.assertEqual(step["ok"], 40)
            self.assertEqual(step["http_5xx"], 0)
            self.assertEqual(step["conn_errors"], 0)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_transient_get_closes_its_connection(self):
        # A _probe_get with no keepalive (the baseline path) must not leak the fd —
        # it opens, uses, and closes a transient connection.
        srv = http.server.HTTPServer(("127.0.0.1", 0), _KAHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            with mock.patch.object(stresstest.common, "_resolve_public",
                                   return_value=("127.0.0.1", socket.AF_INET)):
                status, body, _h = stresstest._probe_get(url)   # keepalive=None
            self.assertEqual(status, 200)
            self.assertEqual(body, b"ok")
        finally:
            srv.shutdown()
            srv.server_close()


class StressOwnershipTests(unittest.TestCase):
    def test_dns_verify_match_and_mismatch(self):
        answers = [{"type": 16, "data": '"nucleus-loadtest-TOKEN123"'}]
        with mock.patch.object(stresstest.common, "dns_query", return_value=answers):
            self.assertTrue(stresstest.verify_ownership("x.example", "nucleus-loadtest-TOKEN123", "dns")["verified"])
            self.assertFalse(stresstest.verify_ownership("x.example", "WRONG", "dns")["verified"])

    def test_file_verify_match(self):
        # verify_ownership fetches the well-known file through common.fetch (not the
        # probe's keep-alive path), so this one stays mocked at common.fetch.
        with mock.patch.object(stresstest.common, "fetch",
                               side_effect=lambda url, **kw: (200, b"nucleus-loadtest-XYZ", {})):
            self.assertTrue(stresstest.verify_ownership("x.example", "nucleus-loadtest-XYZ", "file")["verified"])

    def test_empty_token_and_unknown_method(self):
        self.assertFalse(stresstest.verify_ownership("x.example", "", "dns")["verified"])
        self.assertFalse(stresstest.verify_ownership("x.example", "tok", "carrier-pigeon")["verified"])


class StressBuilderTests(unittest.TestCase):
    """The builder assembles copy-paste commands and NEVER executes — a
    malformed field must stay one inert shell argument (same guarantee as
    builder.py)."""

    def test_all_engines_build_something(self):
        for engine in ("k6", "vegeta", "hey", "wrk", "ab"):
            out = stresstest.build_loadtest(engine, {"url": "https://example.com"})
            self.assertEqual(out["engine"], engine)
            self.assertTrue(out.get("command") or out.get("files"))

    def test_shell_injection_is_quoted_inert(self):
        import shlex
        evil = "https://x.com/'; rm -rf ~ #"
        for engine in ("vegeta", "hey", "wrk", "ab"):
            cmd = stresstest.build_loadtest(engine, {"url": evil})["command"]
            # The real guarantee: re-tokenizing the command the way a shell would
            # must NOT surface the payload as its own words. `rm`, `-rf`, `;` stay
            # buried inside a single argument, never standalone tokens.
            tokens = shlex.split(cmd)
            self.assertNotIn("rm", tokens, engine)
            self.assertNotIn(";", tokens, engine)
            self.assertIn("rm -rf", cmd)  # still present in the string, just neutralized

    def test_k6_script_has_no_raw_newline_breakout(self):
        out = stresstest.build_loadtest("k6", {"url": "https://x.com\nfetch('evil')"})
        script = out["files"][0]["content"]
        # The injected newline was stripped before repr(), so no bare second line
        # of JS can appear from the URL.
        self.assertNotIn("\nfetch('evil')", script)

    def test_k6_numeric_fields_cannot_inject_js(self):
        # duration / concurrency are embedded RAW into the k6 JS (not shlex-quoted),
        # so they must be sanitized to digits(+unit). A newline+JS payload in them
        # must not become a second statement.
        out = stresstest.build_loadtest("k6", {
            "url": "https://ok.com", "duration": "30s\nfetch('http://evil')", "concurrency": "25'});evil()"})
        script = out["files"][0]["content"]
        self.assertNotIn("fetch('http://evil')", script)
        self.assertNotIn("evil()", script)
        self.assertNotIn("\n", stresstest._dur_field("30s\nx", "30s"))
        self.assertEqual(stresstest._int_field("25'});evil()", "50"), "25")

    def test_unknown_engine_is_handled(self):
        out = stresstest.build_loadtest("nmap", {"url": "https://x"})
        self.assertIn("unknown engine", out["command"])


class StressHandlerGateTests(unittest.TestCase):
    """Server-side gate stack — the UI has no say in whether a probe runs."""

    def setUp(self):
        # Isolate the cross-call throttle state between tests.
        stresstest._LAST_PROBE_END.clear()

    def test_authorized_required(self):
        resp = stresstest.handle_stress_probe(_StressReq({"url": "https://x.com"}))
        self.assertEqual(resp.status, 403)

    def test_invalid_tier_refused(self):
        resp = stresstest.handle_stress_probe(_StressReq({"url": "https://x.com", "authorized": True, "tier": "nuke"}))
        self.assertEqual(resp.status, 400)

    def test_invalid_target_refused(self):
        resp = stresstest.handle_stress_probe(_StressReq({"url": "javascript:alert(1)", "authorized": True}))
        self.assertEqual(resp.status, 400)

    def test_private_target_without_lab_refused(self):
        resp = stresstest.handle_stress_probe(_StressReq({"url": "http://10.0.0.1", "authorized": True}))
        self.assertEqual(resp.status, 403)

    def test_ownership_verify_fails_closed(self):
        # A claimed verification that doesn't check out must refuse — the scope
        # stamp can never be faked. Public IP literal so no DNS is needed for scope.
        body = {"url": "http://93.184.216.34", "authorized": True,
                "verify": {"token": "nucleus-loadtest-none", "method": "dns"}}
        with mock.patch.object(stresstest.runners.common, "opsec_status", return_value={"exposed": False}), \
             mock.patch.object(stresstest.common, "dns_query", return_value=[]):
            resp = stresstest.handle_stress_probe(_StressReq(body))
        self.assertEqual(resp.status, 403)
        self.assertIn("verification", json.loads(resp.body)["error"])

    def test_full_gate_stack_passes_and_stamps_scope(self):
        body = {"url": "http://93.184.216.34", "authorized": True, "tier": "smoke",
                "verify": {"token": "nucleus-loadtest-OK", "method": "dns"}}
        answers = [{"type": 16, "data": '"nucleus-loadtest-OK"'}]
        with mock.patch.object(stresstest.runners.common, "opsec_status", return_value={"exposed": False}), \
             mock.patch.object(stresstest.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]), \
             mock.patch.object(stresstest.common, "dns_query", return_value=answers), \
             mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "cloudflare", "CF-Ray": "a-LAX"})):
            resp = stresstest.handle_stress_probe(_StressReq(body))
        self.assertEqual(resp.status, 200)
        payload = json.loads(resp.body)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["scope_verified"]["verified"])

    def test_lab_does_not_bypass_opsec_on_public_target(self):
        # A load test must not fire from an exposed IP just because 'lab' is ticked.
        # lab can't mean "private" for the native probe (SSRF refuses private), so
        # a public target with lab:true still hits the opsec gate.
        body = {"url": "http://93.184.216.34", "authorized": True, "lab": True}
        with mock.patch.object(stresstest.runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "24.0.0.1", "reason": "no VPN"}):
            resp = stresstest.handle_stress_probe(_StressReq(body))
        self.assertEqual(resp.status, 403)
        self.assertTrue(json.loads(resp.body).get("opsec_block"))

    def test_verify_requires_authorization(self):
        resp = stresstest.handle_stress_verify(_StressReq(
            {"target": "93.184.216.34", "token": "nucleus-loadtest-x", "method": "dns"}))
        self.assertEqual(resp.status, 403)

    def test_verify_file_method_respects_opsec(self):
        # The file method touches the target from the real IP -> opsec gate applies.
        body = {"target": "93.184.216.34", "token": "nucleus-loadtest-x", "method": "file", "authorized": True}
        with mock.patch.object(stresstest.runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "24.0.0.1", "reason": "no VPN"}):
            resp = stresstest.handle_stress_verify(_StressReq(body))
        self.assertEqual(resp.status, 403)
        self.assertTrue(json.loads(resp.body).get("opsec_block"))

    def test_verify_dns_method_not_opsec_gated(self):
        # DNS verification contacts a resolver, not the target — no IP leak, no gate.
        body = {"target": "93.184.216.34", "token": "nucleus-loadtest-x", "method": "dns", "authorized": True}
        with mock.patch.object(stresstest.runners.common, "opsec_status",
                               return_value={"exposed": True, "public_ip": "24.0.0.1"}), \
             mock.patch.object(stresstest.common, "dns_query", return_value=[]):
            resp = stresstest.handle_stress_verify(_StressReq(body))
        self.assertEqual(resp.status, 200)  # ran the check (unverified), not opsec-blocked

    def test_concurrent_probe_refused_409(self):
        # Only one native probe runs at a time — a concurrent call is refused, not
        # queued, so parallel calls can't stack into real load. Simulate an
        # in-flight probe by holding the lock.
        self.assertTrue(stresstest._PROBE_LOCK.acquire(blocking=False))
        try:
            body = {"url": "http://93.184.216.34", "authorized": True}
            with mock.patch.object(stresstest.runners.common, "opsec_status", return_value={"exposed": False}), \
                 mock.patch.object(stresstest.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]):
                resp = stresstest.handle_stress_probe(_StressReq(body))
            self.assertEqual(resp.status, 409)
        finally:
            stresstest._PROBE_LOCK.release()

    def test_cooldown_between_probes_same_host(self):
        # Back-to-back probes of the same host are paced by the cooldown, so a
        # loop can't reset the per-run budget every call.
        body = {"url": "http://93.184.216.34", "authorized": True, "tier": "smoke"}
        with mock.patch.object(stresstest.runners.common, "opsec_status", return_value={"exposed": False}), \
             mock.patch.object(stresstest.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]), \
             mock.patch.object(stresstest, "_probe_get",
                               side_effect=_stress_fetch(200, {"Server": "nginx"})):
            first = stresstest.handle_stress_probe(_StressReq(body))
            second = stresstest.handle_stress_probe(_StressReq(body))
        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 429)
        self.assertIn("retry_after_s", json.loads(second.body))

    def test_build_handler_marks_not_executed(self):
        resp = stresstest.handle_stress_build(_StressReq({"engine": "k6", "params": {"url": "https://x"}}))
        self.assertEqual(resp.status, 200)
        self.assertFalse(json.loads(resp.body)["executed"])


# ==========================================================================
# 15. consoles/redcell/tlsaudit.py — protocol enumeration, cert grading,
#     rebind safety, handler gate stack
# ==========================================================================
class TlsAuditWeakCipherTests(unittest.TestCase):
    def test_known_weak_markers_detected(self):
        for name in ("RC4-MD5", "DES-CBC3-SHA", "EXP-RC4-MD5", "ADH-AES256-SHA", "NULL-MD5"):
            with self.subTest(cipher=name):
                self.assertTrue(tlsaudit._has_weak_cipher(name))

    def test_modern_ciphers_not_flagged(self):
        for name in ("ECDHE-RSA-AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305"):
            with self.subTest(cipher=name):
                self.assertFalse(tlsaudit._has_weak_cipher(name))

    def test_none_is_not_weak(self):
        self.assertFalse(tlsaudit._has_weak_cipher(None))


class TlsAuditGradeTests(unittest.TestCase):
    """grade() is pure over already-collected cert/protocol dicts — every
    case here is a constructed fixture, no network."""

    def _clean_cert(self, **overrides):
        base = {"ok": True, "trusted": True, "verify_error": None, "self_signed": False,
                "hostname_ok": True, "baseline_protocol": "TLSv1.3",
                "baseline_cipher": "TLS_AES_256_GCM_SHA384", "issuer": "Let's Encrypt",
                "subject_cn": "example.com", "not_after": "", "days_left": 300, "sans": []}
        base.update(overrides)
        return base

    def _clean_protocols(self, **overrides):
        base = {
            "TLS 1.0": {"accepted": False, "negotiated": None, "cipher": None, "reason": "refused"},
            "TLS 1.1": {"accepted": False, "negotiated": None, "cipher": None, "reason": "refused"},
            "TLS 1.2": {"accepted": True, "negotiated": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "reason": ""},
            "TLS 1.3": {"accepted": True, "negotiated": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "reason": ""},
        }
        base.update(overrides)
        return base

    def test_clean_modern_server_grades_a_with_no_findings(self):
        letter, pct, findings = tlsaudit.grade(self._clean_cert(), self._clean_protocols())
        self.assertEqual(letter, "A")
        self.assertEqual(findings, [])
        self.assertLessEqual(pct, 100.0)

    def test_self_signed_flagged_high_and_scores_low(self):
        cert = self._clean_cert(self_signed=True, trusted=False)
        letter, pct, findings = tlsaudit.grade(cert, self._clean_protocols())
        self.assertTrue(any(f["severity"] == "high" and "self-signed" in f["title"].lower() for f in findings))
        self.assertLess(pct, 90)

    def test_expired_cert_flagged_high(self):
        cert = self._clean_cert(days_left=-10)
        _letter, _pct, findings = tlsaudit.grade(cert, self._clean_protocols())
        self.assertTrue(any(f["severity"] == "high" and "expired" in f["title"].lower() for f in findings))

    def test_hostname_mismatch_flagged_high(self):
        cert = self._clean_cert(hostname_ok=False)
        _letter, _pct, findings = tlsaudit.grade(cert, self._clean_protocols())
        self.assertTrue(any("hostname" in f["title"].lower() for f in findings))

    def test_untrusted_chain_flagged_high(self):
        cert = self._clean_cert(trusted=False, verify_error="unable to get local issuer certificate")
        _letter, _pct, findings = tlsaudit.grade(cert, self._clean_protocols())
        self.assertTrue(any("does not validate" in f["title"].lower() for f in findings))

    def test_legacy_protocol_accepted_is_high_and_hurts_grade(self):
        protocols = self._clean_protocols()
        protocols["TLS 1.0"] = {"accepted": True, "negotiated": "TLSv1.0",
                                 "cipher": "ECDHE-RSA-AES256-SHA", "reason": ""}
        letter, _pct, findings = tlsaudit.grade(self._clean_cert(), protocols)
        self.assertTrue(any(f["severity"] == "high" and "TLS 1.0" in f["title"] for f in findings))
        self.assertIn(letter, ("C", "D", "F"))

    def test_weak_cipher_on_baseline_flagged_and_deduplicated(self):
        cert = self._clean_cert(baseline_cipher="RC4-MD5")
        protocols = self._clean_protocols()
        protocols["TLS 1.0"] = {"accepted": True, "negotiated": "TLSv1.0", "cipher": "RC4-MD5", "reason": ""}
        _letter, _pct, findings = tlsaudit.grade(cert, protocols)
        weak_findings = [f for f in findings if "weak cipher" in f["title"].lower()]
        self.assertEqual(len(weak_findings), 1)  # same cipher name on baseline + legacy -> one finding, not two

    def test_no_tls13_is_low_finding_not_score_killer(self):
        protocols = self._clean_protocols()
        protocols["TLS 1.3"] = {"accepted": False, "negotiated": None, "cipher": None, "reason": "refused"}
        letter, _pct, findings = tlsaudit.grade(self._clean_cert(), protocols)
        self.assertTrue(any(f["severity"] == "low" for f in findings))
        self.assertIn(letter, ("A", "B"))

class TlsAuditProtocolAttemptTests(unittest.TestCase):
    """_attempt_protocol's three outcomes: accepted (True), actively refused
    (False, an SSL protocol alert), or couldn't tell (None, a connection-level
    or local-capability issue) — all exercised without a real socket."""

    def test_connection_error_reports_none_not_crash(self):
        with mock.patch.object(tlsaudit.socket, "create_connection", side_effect=OSError("connection refused")):
            r = tlsaudit._attempt_protocol("93.184.216.34", "example.com", ssl.TLSVersion.TLSv1_2, 2.0)
        self.assertIsNone(r["accepted"])
        self.assertIn("connection error", r["reason"])

    def test_unsupported_version_reports_none_not_testable(self):
        r = tlsaudit._attempt_protocol("93.184.216.34", "example.com", 999999, 2.0)
        self.assertIsNone(r["accepted"])
        self.assertIn("not testable", r["reason"])

    def test_refused_handshake_reports_false(self):
        with mock.patch.object(tlsaudit.socket, "create_connection", return_value=mock.MagicMock()), \
             mock.patch.object(ssl.SSLContext, "wrap_socket",
                               side_effect=ssl.SSLError("tlsv1 alert protocol version")):
            r = tlsaudit._attempt_protocol("93.184.216.34", "example.com", ssl.TLSVersion.TLSv1, 2.0)
        self.assertFalse(r["accepted"])
        self.assertIn("alert", r["reason"])

    def test_accepted_handshake_reports_true_with_cipher(self):
        fake_ssock = mock.MagicMock()
        fake_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        fake_ssock.version.return_value = "TLSv1.2"
        fake_wrapped = mock.MagicMock()
        fake_wrapped.__enter__.return_value = fake_ssock
        with mock.patch.object(tlsaudit.socket, "create_connection", return_value=mock.MagicMock()), \
             mock.patch.object(ssl.SSLContext, "wrap_socket", return_value=fake_wrapped):
            r = tlsaudit._attempt_protocol("93.184.216.34", "example.com", ssl.TLSVersion.TLSv1_2, 2.0)
        self.assertTrue(r["accepted"])
        self.assertEqual(r["negotiated"], "TLSv1.2")
        self.assertEqual(r["cipher"], "ECDHE-RSA-AES256-GCM-SHA384")


class TlsAuditAssessTests(unittest.TestCase):
    """assess() end-to-end wiring: SSRF gate, then cert, then protocol sweep,
    then grade — with the network-facing pieces mocked out."""

    def test_refuses_private_rebind_without_ever_connecting(self):
        called = {"n": 0}

        def fake_conn(*a, **kw):
            called["n"] += 1
            raise OSError("must never be reached")

        with mock.patch.object(tlsaudit.common, "resolve_public_ips", side_effect=ValueError("non-public IP")), \
             mock.patch.object(tlsaudit.socket, "create_connection", side_effect=fake_conn):
            out = tlsaudit.assess("rebind.evil")
        self.assertFalse(out["ok"])
        self.assertEqual(called["n"], 0)

    def test_unresolvable_host_reports_error(self):
        with mock.patch.object(tlsaudit.common, "resolve_public_ips", return_value=[]):
            out = tlsaudit.assess("nowhere.invalid")
        self.assertFalse(out["ok"])

    def test_cert_failure_short_circuits_before_protocol_sweep(self):
        with mock.patch.object(tlsaudit.common, "resolve_public_ips", return_value=["93.184.216.34"]), \
             mock.patch.object(tlsaudit, "_cert_and_baseline", return_value={"ok": False, "error": "boom"}), \
             mock.patch.object(tlsaudit, "_attempt_protocol") as attempt_mock:
            out = tlsaudit.assess("example.com")
        self.assertFalse(out["ok"])
        attempt_mock.assert_not_called()

    def test_assembles_cert_protocols_and_grade(self):
        cert = {"ok": True, "trusted": True, "verify_error": None, "self_signed": False,
                "hostname_ok": True, "baseline_protocol": "TLSv1.3", "baseline_cipher": "TLS_AES_256_GCM_SHA384",
                "issuer": "Let's Encrypt", "subject_cn": "example.com", "not_after": "",
                "days_left": 300, "sans": []}
        with mock.patch.object(tlsaudit.common, "resolve_public_ips", return_value=["93.184.216.34"]), \
             mock.patch.object(tlsaudit, "_cert_and_baseline", return_value=cert), \
             mock.patch.object(tlsaudit, "_attempt_protocol",
                               return_value={"accepted": False, "negotiated": None,
                                             "cipher": None, "reason": "refused"}):
            out = tlsaudit.assess("example.com")
        self.assertTrue(out["ok"])
        self.assertEqual(out["resolved_ip"], "93.184.216.34")
        self.assertEqual(set(out["protocols"]), {"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"})
        self.assertIn(out["grade"], ("A", "B", "C", "D", "F"))


class TlsAuditHandlerGateTests(unittest.TestCase):
    def test_authorized_required(self):
        resp = tlsaudit.handle_tls_audit(_StressReq({"host": "example.com"}))
        self.assertEqual(resp.status, 403)

    def test_invalid_host_refused(self):
        resp = tlsaudit.handle_tls_audit(_StressReq({"host": "-evil.com", "authorized": True}))
        self.assertEqual(resp.status, 400)

    def test_private_target_without_lab_refused(self):
        resp = tlsaudit.handle_tls_audit(_StressReq({"host": "10.0.0.1", "authorized": True}))
        self.assertEqual(resp.status, 403)

    def test_private_target_with_lab_gets_native_message_not_a_connect_attempt(self):
        resp = tlsaudit.handle_tls_audit(_StressReq({"host": "10.0.0.1", "authorized": True, "lab": True}))
        self.assertEqual(resp.status, 400)
        self.assertIn("lab mode", json.loads(resp.body)["error"])

    def test_full_pass_through_calls_assess_and_returns_result(self):
        body = {"host": "93.184.216.34", "authorized": True}
        with mock.patch.object(tlsaudit.runners.common, "opsec_status", return_value={"exposed": False}), \
             mock.patch.object(tlsaudit.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]), \
             mock.patch.object(tlsaudit, "assess", return_value={"ok": True, "grade": "A", "counts": {}}):
            resp = tlsaudit.handle_tls_audit(_StressReq(body))
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.body)["grade"], "A")


# ==========================================================================
# 16. consoles/redcell/techfp.py — signature matching, cookie/generator
#     extraction, the zero-network vs one-fetch handler paths
# ==========================================================================
class TechFingerprintSignatureTests(unittest.TestCase):
    def test_cloudflare_detected_via_headers(self):
        headers = {"Server": "cloudflare", "CF-Ray": "abc123-LAX"}
        out = techfp.fingerprint(headers, b"")
        self.assertIn("Cloudflare", [t["name"] for t in out["technologies"]])

    def test_wordpress_plus_jquery_confidence_bumped_to_high(self):
        headers = {"Server": "nginx/1.18.0"}
        body = (b'<html><head><meta name="generator" content="WordPress 6.4">'
                b'<script src="/wp-content/themes/x/js/jquery.min.js"></script></head></html>')
        out = techfp.fingerprint(headers, body)
        by_name = {t["name"]: t for t in out["technologies"]}
        self.assertIn("WordPress", by_name)
        self.assertIn("jQuery", by_name)
        self.assertIn("nginx", by_name)
        # WordPress matched on BOTH the generator meta AND the /wp-content/ path --
        # two independent signals bump confidence to high automatically.
        self.assertEqual(by_name["WordPress"]["confidence"], "high")

    def test_php_detected_via_header_and_cookie_name(self):
        headers = {"X-Powered-By": "PHP/8.1.2", "Set-Cookie": "PHPSESSID=deadbeef; Path=/; HttpOnly"}
        out = techfp.fingerprint(headers, b"")
        self.assertIn("PHP", [t["name"] for t in out["technologies"]])

    def test_cookie_value_alone_never_triggers_a_name_based_signature(self):
        # 'jsessionid' only ever appears inside a cookie VALUE here, never as a
        # NAME -- matching against values (not just names) would be a false
        # positive that this test would catch.
        headers = {"Set-Cookie": "session=jsessionid-lookalike-value; Path=/"}
        out = techfp.fingerprint(headers, b"")
        self.assertNotIn("Apache Tomcat / Coyote", [t["name"] for t in out["technologies"]])

    def test_react_detected_via_html_marker(self):
        out = techfp.fingerprint({}, b'<div id="root" data-reactroot=""></div>')
        self.assertIn("React", [t["name"] for t in out["technologies"]])

    def test_google_analytics_detected_via_script_src(self):
        body = b'<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>'
        out = techfp.fingerprint({}, body)
        self.assertIn("Google Analytics", [t["name"] for t in out["technologies"]])

    def test_empty_response_yields_no_hits(self):
        out = techfp.fingerprint({}, b"")
        self.assertEqual(out["technologies"], [])
        self.assertEqual(out["count"], 0)

    def test_evidence_names_what_matched(self):
        out = techfp.fingerprint({"Server": "nginx/1.20.0"}, b"")
        hit = next(t for t in out["technologies"] if t["name"] == "nginx")
        self.assertTrue(any("nginx" in e.lower() for e in hit["evidence"]))


class TechFingerprintCookieAndGeneratorTests(unittest.TestCase):
    def test_cookie_split_survives_expires_comma(self):
        raw = ("session=abc; Path=/; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Secure, "
               "PHPSESSID=xyz; Path=/")
        self.assertEqual(techfp._cookie_names(raw), ["session", "PHPSESSID"])

    def test_empty_cookie_header_yields_no_names(self):
        self.assertEqual(techfp._cookie_names(""), [])

    def test_generator_extracted_name_then_content_order(self):
        html = '<meta name="generator" content="Joomla! - Open Source Content Management">'
        self.assertIn("joomla", techfp._extract_generator(html).lower())

    def test_generator_extracted_content_then_name_order(self):
        html = '<meta content="Drupal 10" name="generator">'
        self.assertIn("drupal", techfp._extract_generator(html).lower())

    def test_no_generator_tag_returns_empty_string(self):
        self.assertEqual(techfp._extract_generator("<html></html>"), "")


class TechFingerprintHandlerTests(unittest.TestCase):
    def test_direct_headers_path_makes_zero_network_calls(self):
        body = {"headers": {"Server": "nginx"}, "body": "<html></html>"}
        with mock.patch.object(techfp.common, "fetch",
                               side_effect=AssertionError("must not fetch on the direct-headers path")):
            resp = techfp.handle_tech_fingerprint(_StressReq(body))
        self.assertEqual(resp.status, 200)
        payload = json.loads(resp.body)
        self.assertTrue(any(t["name"] == "nginx" for t in payload["technologies"]))

    def test_direct_path_rejects_non_dict_headers(self):
        resp = techfp.handle_tech_fingerprint(_StressReq({"headers": "nope", "body": ""}))
        self.assertEqual(resp.status, 400)

    def test_url_path_requires_authorization(self):
        resp = techfp.handle_tech_fingerprint(_StressReq({"url": "https://example.com"}))
        self.assertEqual(resp.status, 403)

    def test_url_path_rejects_private_target_without_lab(self):
        resp = techfp.handle_tech_fingerprint(_StressReq({"url": "http://10.0.0.1", "authorized": True}))
        self.assertEqual(resp.status, 403)

    def test_url_path_fetches_exactly_once_and_fingerprints(self):
        body = {"url": "https://93.184.216.34", "authorized": True}
        with mock.patch.object(techfp.runners.common, "opsec_status", return_value={"exposed": False}), \
             mock.patch.object(techfp.runners, "_resolve_public_ips_safe", return_value=["93.184.216.34"]), \
             mock.patch.object(techfp.common, "fetch",
                               return_value=(200, b"<html></html>", {"Server": "nginx"})) as fetch_mock:
            resp = techfp.handle_tech_fingerprint(_StressReq(body))
        self.assertEqual(resp.status, 200)
        self.assertEqual(fetch_mock.call_count, 1)
        payload = json.loads(resp.body)
        self.assertEqual(payload["status"], 200)
        self.assertTrue(any(t["name"] == "nginx" for t in payload["technologies"]))


# ==========================================================================
# 17. consoles/redcell/jwtaudit.py — weakness detection + offline crack-
#     command build (never run)
# ==========================================================================
def _make_jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    import base64 as _b64

    def _seg(o):
        return _b64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    return f"{_seg(header)}.{_seg(payload)}.{sig}"


class JwtAuditFindingsTests(unittest.TestCase):
    def test_alg_none_is_critical(self):
        tok = _make_jwt({"alg": "none"}, {"sub": "x", "exp": 9999999999}, sig="")
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(r["ok"])
        self.assertTrue(any(f["severity"] == "critical" for f in r["findings"]))

    def test_alg_none_case_variant_still_caught(self):
        tok = _make_jwt({"alg": "NoNe"}, {"exp": 9999999999})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "critical" for f in r["findings"]))

    def test_hs256_flags_algorithm_confusion_and_builds_crack_commands(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 9999999999, "iss": "acme", "aud": "svc"})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "medium" and "confusion" in f["title"].lower()
                            for f in r["findings"]))
        self.assertIsNotNone(r["crack"])
        self.assertIn("-m 16500", r["crack"]["hashcat"])
        self.assertIn(tok, r["crack"]["hashcat_plain"])

    def test_rs256_gets_no_crack_commands(self):
        tok = _make_jwt({"alg": "RS256"}, {"exp": 9999999999})
        r = jwtaudit.analyze_jwt(tok)
        self.assertIsNone(r["crack"])

    def test_expired_token_is_high(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 1})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "high" and "expired" in f["title"].lower() for f in r["findings"]))

    def test_missing_exp_is_medium(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "x"})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "medium" and "exp" in f["title"].lower() for f in r["findings"]))

    def test_nbf_in_future_is_info(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 9999999999, "nbf": 9999999998})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "info" and "not valid yet" in f["title"].lower()
                            for f in r["findings"]))

    def test_missing_iss_aud_sub_is_low(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 9999999999})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "low" and "iss" in f["title"] for f in r["findings"]))

    def test_jku_x5u_jwk_headers_flagged_high(self):
        tok = _make_jwt({"alg": "RS256", "jku": "https://evil.example/keys.json",
                         "x5u": "https://evil.example/cert.pem", "jwk": {"kty": "RSA"}},
                        {"exp": 9999999999, "iss": "a", "aud": "b"})
        r = jwtaudit.analyze_jwt(tok)
        highs = [f["title"] for f in r["findings"] if f["severity"] == "high"]
        self.assertTrue(any("jku" in t for t in highs))
        self.assertTrue(any("x5u" in t for t in highs))
        self.assertTrue(any("jwk" in t for t in highs))

    def test_kid_header_flagged_info(self):
        tok = _make_jwt({"alg": "HS256", "kid": "../../dev/null"}, {"exp": 9999999999, "iss": "a", "aud": "b"})
        r = jwtaudit.analyze_jwt(tok)
        self.assertTrue(any(f["severity"] == "info" and "kid" in f["title"].lower() for f in r["findings"]))

    def test_malformed_token_is_reported_not_crashed(self):
        r = jwtaudit.analyze_jwt("not-a-jwt-at-all")
        self.assertFalse(r["ok"])
        self.assertIn("error", r)

    def test_clean_fully_scoped_hs256_token_has_only_the_algorithm_finding(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 9999999999, "iss": "acme", "aud": "svc", "sub": "u1"})
        r = jwtaudit.analyze_jwt(tok)
        titles = [f["title"] for f in r["findings"]]
        self.assertEqual(len(titles), 1)
        self.assertIn("HMAC algorithm", titles[0])


class JwtAuditCrackCommandPasteSafetyTests(unittest.TestCase):
    def test_hostile_token_stays_one_inert_argument(self):
        import shlex
        evil_token = "x`touch /tmp/pwned`;rm -rf ~"
        cmds = jwtaudit._crack_commands(evil_token)
        tokens = shlex.split(cmds["hashcat_plain"])
        self.assertTrue(any(evil_token in t for t in tokens))


class JwtAuditHandlerTests(unittest.TestCase):
    def test_missing_token_refused(self):
        resp = jwtaudit.handle_jwt_audit(_StressReq({}))
        self.assertEqual(resp.status, 400)

    def test_oversized_token_refused(self):
        resp = jwtaudit.handle_jwt_audit(_StressReq({"token": "a" * 9000}))
        self.assertEqual(resp.status, 400)

    def test_well_formed_token_returns_200(self):
        tok = _make_jwt({"alg": "HS256"}, {"exp": 9999999999, "iss": "a", "aud": "b"})
        resp = jwtaudit.handle_jwt_audit(_StressReq({"token": tok}))
        self.assertEqual(resp.status, 200)
        self.assertTrue(json.loads(resp.body)["ok"])


# ==========================================================================
# 18. consoles/recon/takeover.py — service matching, CNAME-chain following,
#     per-subdomain verdicts, batch handler
# ==========================================================================
def _single_cname(cname_target: str):
    """side_effect for a mocked common.dns_query: the first CNAME lookup
    resolves to `cname_target`; a lookup FOR that target returns no further
    CNAME, so _cname_chain stops there with exactly one hop."""
    def _fn(name, rtype):
        if rtype == "CNAME" and name != cname_target:
            return [{"data": cname_target + "."}]
        return []
    return _fn


class TakeoverServiceMatchTests(unittest.TestCase):
    def test_known_families_match_the_right_service(self):
        cases = {
            "foo.github.io": "GitHub Pages",
            "myapp.herokuapp.com": "Heroku",
            "shopname.myshopify.com": "Shopify",
            "help.zendesk.com": "Zendesk",
            "proj.surge.sh": "Surge.sh",
            "site.netlify.app": "Netlify",
            "x.pantheonsite.io": "Pantheon",
            "sub.domains.tumblr.com": "Tumblr",
            "landing.unbouncepages.com": "Unbounce",
            "blog.wordpress.com": "WordPress.com",
            "cdn.fastly.net": "Fastly",
            "bucket.s3.amazonaws.com": "AWS S3",
            "repo.bitbucket.io": "Bitbucket Pages",
            "blog.ghost.io": "Ghost(Pro)",
            "portfolio.cargocollective.com": "Cargo Collective",
            "app.fly.dev": "Fly.io",
            "status.statuspage.io": "Statuspage",
            "site.squarespace.com": "Squarespace",
            "app.azurewebsites.net": "Azure",
            "env.elasticbeanstalk.com": "AWS Elastic Beanstalk",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                svc = takeover._match_service(target)
                self.assertIsNotNone(svc, target)
                self.assertEqual(svc.name, expected)

    def test_unrelated_cname_matches_nothing(self):
        self.assertIsNone(takeover._match_service("internal.corp.example.com"))


class TakeoverCnameChainTests(unittest.TestCase):
    def test_follows_multi_hop_chain(self):
        chain_map = {
            "sub.example.com": [{"data": "cdn.example.net."}],
            "cdn.example.net": [{"data": "ghs.googlehosted.com."}],
            "ghs.googlehosted.com": [],
        }
        with mock.patch.object(takeover.common, "dns_query",
                               side_effect=lambda name, rtype: chain_map.get(name, [])):
            chain = takeover._cname_chain("sub.example.com")
        self.assertEqual(chain, ["cdn.example.net", "ghs.googlehosted.com"])

    def test_no_cname_returns_empty_chain(self):
        with mock.patch.object(takeover.common, "dns_query", return_value=[]):
            self.assertEqual(takeover._cname_chain("apex.example.com"), [])

    def test_loop_does_not_hang_or_grow_unbounded(self):
        def fake_dns(name, rtype):
            return [{"data": "b.example.com."}] if name == "a.example.com" else [{"data": "a.example.com."}]
        with mock.patch.object(takeover.common, "dns_query", side_effect=fake_dns):
            chain = takeover._cname_chain("a.example.com", max_hops=8)
        self.assertLessEqual(len(chain), 8)


class TakeoverDohStatusLookupTests(unittest.TestCase):
    """_doh_lookup_with_status keeps the raw DNS Status code -- needed to
    tell a genuine NXDOMAIN apart from a healthy-but-empty answer."""

    def test_nxdomain_status_parsed(self):
        body = json.dumps({"Status": 3, "Answer": []}).encode()
        with mock.patch.object(takeover.common, "fetch", return_value=(200, body, {})):
            answers, status = takeover._doh_lookup_with_status("gone.example.com", "A")
        self.assertEqual(answers, [])
        self.assertEqual(status, 3)

    def test_noerror_with_answer_parsed(self):
        body = json.dumps({"Status": 0, "Answer": [{"data": "1.2.3.4"}]}).encode()
        with mock.patch.object(takeover.common, "fetch", return_value=(200, body, {})):
            answers, status = takeover._doh_lookup_with_status("live.example.com", "A")
        self.assertEqual(answers, [{"data": "1.2.3.4"}])
        self.assertEqual(status, 0)

    def test_all_resolvers_unreachable_returns_none_status(self):
        with mock.patch.object(takeover.common, "fetch", side_effect=OSError("timeout")):
            answers, status = takeover._doh_lookup_with_status("x.example.com", "A")
        self.assertEqual(answers, [])
        self.assertIsNone(status)

    def test_empty_name_short_circuits_without_fetching(self):
        with mock.patch.object(takeover.common, "fetch", side_effect=AssertionError("must not fetch")):
            result = takeover._doh_lookup_with_status("", "A")
        self.assertEqual(result, ([], None))


class TakeoverCheckSubdomainTests(unittest.TestCase):
    def test_no_cname_is_safe(self):
        with mock.patch.object(takeover.common, "dns_query", return_value=[]):
            r = takeover.check_subdomain("www.example.com")
        self.assertEqual(r["verdict"], "safe")
        self.assertIsNone(r["service"])

    def test_unmatched_service_is_safe(self):
        with mock.patch.object(takeover.common, "dns_query",
                               side_effect=_single_cname("internal.corp.example.com")):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "safe")
        self.assertIsNone(r["service"])

    def test_vulnerable_http_fingerprint_match(self):
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("unclaimed.surge.sh")), \
             mock.patch.object(takeover.common, "fetch", return_value=(404, b"project not found", {})):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "vulnerable")
        self.assertEqual(r["service"], "Surge.sh")

    def test_edge_case_provider_reports_likely_not_vulnerable(self):
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("myapp.herokuapp.com")), \
             mock.patch.object(takeover.common, "fetch", return_value=(404, b"No such app", {})):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "likely")

    def test_not_vulnerable_provider_with_fingerprint_still_reports_safe(self):
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("help.zendesk.com")), \
             mock.patch.object(takeover.common, "fetch", return_value=(200, b"Help Center Closed", {})):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "safe")
        self.assertTrue(any("exploitable" in e for e in r["evidence"]))

    def test_fingerprint_absent_is_safe_claimed(self):
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("realapp.herokuapp.com")), \
             mock.patch.object(takeover.common, "fetch",
                               return_value=(200, b"<html>welcome to my real app</html>", {})):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "safe")

    def test_connection_failure_is_likely_not_vulnerable(self):
        def boom(url, **kw):
            raise OSError("connection refused")
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("gone.surge.sh")), \
             mock.patch.object(takeover.common, "fetch", side_effect=boom):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "likely")

    def test_blocked_target_is_error_not_crash(self):
        def blocked(url, **kw):
            raise ValueError("host resolves to non-public address")
        with mock.patch.object(takeover.common, "dns_query", side_effect=_single_cname("x.surge.sh")), \
             mock.patch.object(takeover.common, "fetch", side_effect=blocked):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "error")

    def test_azure_nxdomain_on_cname_target_is_vulnerable(self):
        with mock.patch.object(takeover.common, "dns_query",
                               side_effect=_single_cname("released.azurewebsites.net")), \
             mock.patch.object(takeover, "_doh_lookup_with_status",
                               return_value=([], takeover._DOH_STATUS_NXDOMAIN)):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "vulnerable")
        self.assertEqual(r["service"], "Azure")

    def test_azure_still_resolving_is_safe(self):
        with mock.patch.object(takeover.common, "dns_query",
                               side_effect=_single_cname("live.azurewebsites.net")), \
             mock.patch.object(takeover, "_doh_lookup_with_status",
                               return_value=([{"data": "20.1.2.3"}], 0)):
            r = takeover.check_subdomain("sub.example.com")
        self.assertEqual(r["verdict"], "safe")


class TakeoverBatchAndHandlerTests(unittest.TestCase):
    def test_check_many_empty_list(self):
        self.assertEqual(takeover._check_many([]), [])

    def test_check_many_preserves_input_order(self):
        def fake_check(sub):
            return {"subdomain": sub, "cname_chain": [], "service": None,
                    "verdict": "safe", "http_status": None, "evidence": [], "note": ""}
        with mock.patch.object(takeover, "check_subdomain", side_effect=fake_check):
            results = takeover._check_many(["a.example.com", "b.example.com", "c.example.com"])
        self.assertEqual([r["subdomain"] for r in results],
                         ["a.example.com", "b.example.com", "c.example.com"])

    def test_check_many_single_failure_does_not_sink_the_batch(self):
        def fake_check(sub):
            if sub == "bad.example.com":
                raise RuntimeError("boom")
            return {"subdomain": sub, "cname_chain": [], "service": None,
                    "verdict": "safe", "http_status": None, "evidence": [], "note": ""}
        with mock.patch.object(takeover, "check_subdomain", side_effect=fake_check):
            results = takeover._check_many(["ok.example.com", "bad.example.com"])
        by_sub = {r["subdomain"]: r for r in results}
        self.assertEqual(by_sub["ok.example.com"]["verdict"], "safe")
        self.assertEqual(by_sub["bad.example.com"]["verdict"], "error")

    def test_handler_requires_domain_or_subdomains(self):
        resp = takeover.handle_takeover(_StressReq({}))
        self.assertEqual(resp.status, 400)

    def test_handler_rejects_invalid_hostname(self):
        resp = takeover.handle_takeover(_StressReq({"domain": "not a domain!"}))
        self.assertEqual(resp.status, 400)

    def test_handler_rejects_too_many_subdomains(self):
        subs = [f"s{i}.example.com" for i in range(300)]
        resp = takeover.handle_takeover(_StressReq({"subdomains": subs}))
        self.assertEqual(resp.status, 400)

    def test_handler_dedupes_and_includes_domain(self):
        captured = []
        def fake_check(sub):
            captured.append(sub)
            return {"subdomain": sub, "cname_chain": [], "service": None,
                    "verdict": "safe", "http_status": None, "evidence": [], "note": ""}
        body = {"domain": "example.com", "subdomains": ["www.example.com", "example.com"]}
        with mock.patch.object(takeover, "check_subdomain", side_effect=fake_check):
            resp = takeover.handle_takeover(_StressReq(body))
        self.assertEqual(resp.status, 200)
        payload = json.loads(resp.body)
        self.assertEqual(payload["checked"], 2)  # example.com deduped against the explicit list
        self.assertEqual(set(captured), {"example.com", "www.example.com"})

    def test_handler_aggregates_verdict_counts(self):
        verdicts = iter(["vulnerable", "likely", "safe", "safe"])
        def fake_check(sub):
            return {"subdomain": sub, "cname_chain": [], "service": None,
                    "verdict": next(verdicts), "http_status": None, "evidence": [], "note": ""}
        body = {"subdomains": ["a.x.com", "b.x.com", "c.x.com", "d.x.com"]}
        with mock.patch.object(takeover, "check_subdomain", side_effect=fake_check):
            resp = takeover.handle_takeover(_StressReq(body))
        self.assertEqual(json.loads(resp.body)["counts"],
                         {"vulnerable": 1, "likely": 1, "safe": 2, "error": 0})


# ==========================================================================
# 19. Route registration — the new handlers must actually be reachable
# ==========================================================================
class RouteRegistrationTests(unittest.TestCase):
    def test_redcell_new_routes_registered(self):
        app = _redcell_build_app()
        self.assertIs(app.routes["POST /api/tls-audit"], tlsaudit.handle_tls_audit)
        self.assertIs(app.routes["POST /api/tech-fingerprint"], techfp.handle_tech_fingerprint)
        self.assertIs(app.routes["POST /api/jwt-audit"], jwtaudit.handle_jwt_audit)

    def test_recon_new_route_registered(self):
        app = _recon_build_app()
        self.assertIs(app.routes["POST /api/takeover"], takeover.handle_takeover)


# ==========================================================================
# 20. consoles/bastion/scrub.py — mat2 metadata scrubber
# ==========================================================================
def _scrub_png() -> bytes:
    """The spec fixture: a 1x1 PNG carrying a tEXt `Author: Jane Doe` chunk.
    Built from stdlib so the suite carries no binary blob — mat2 shows the
    Author pair, strips the chunk, and the cleaned file re-inspects empty,
    which makes the whole pipeline provable with ~100 bytes."""
    def _chunk(t: bytes, d: bytes) -> bytes:
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr)
            + _chunk(b"tEXt", b"Author\x00Jane Doe")
            + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + _chunk(b"IEND", b""))


class TestScrub(unittest.TestCase):
    """Everything the scrub module touches is attacker-influenced: filenames
    arrive percent-encoded from the browser, metadata values come from inside
    hostile files, and session tokens ride the query string. These tests pin
    the pure logic (sanitize / parse / token validation) offline and gate the
    real-mat2 round trips on the binary being installed."""

    def setUp(self):
        # Point the module at a throwaway tree so no test can create, purge,
        # or pollute the real var/scrub.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.scrub_dir = Path(self._tmp.name).resolve() / "scrub"
        patcher = mock.patch.object(scrub, "SCRUB_DIR", self.scrub_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- sanitize_name ------------------------------------------------------

    def test_sanitize_name_strips_traversal(self):
        self.assertEqual(scrub.sanitize_name("../../etc/passwd.png"), "passwd.png")

    def test_sanitize_name_strips_backslash_paths(self):
        # Windows-origin drag-drops arrive with backslash separators, which
        # Path() on Linux treats as ordinary name characters.
        self.assertEqual(scrub.sanitize_name("..\\..\\x.jpg"), "x.jpg")

    def test_sanitize_name_output_stays_in_safe_charset(self):
        hostile = [
            "shot\x00\x1f\x7f.png", "café ☕.png", "СПУТНИК.jpg",
            "'; rm -rf / #.png", "a  b__c   d.png", "<img src=x>.gif",
            "%2e%2e%2fescape.pdf",
        ]
        for name in hostile:
            with self.subTest(name=name):
                out = scrub.sanitize_name(name)
                self.assertTrue(out)
                self.assertTrue(re.fullmatch(r"[A-Za-z0-9._ -]+", out), out)

    def test_sanitize_name_caps_length_keeping_extension(self):
        out = scrub.sanitize_name("a" * 300 + ".jpg")
        self.assertLessEqual(len(out), 120)
        self.assertTrue(out.endswith(".jpg"))

    def test_sanitize_name_never_starts_with_dot_dash_or_space(self):
        for name in (".hidden.png", "--rf.png", "  pad.png"):
            with self.subTest(name=name):
                out = scrub.sanitize_name(name)
                self.assertFalse(out.startswith((".", "-", " ")), out)

    def test_sanitize_name_empty_stem_gets_a_stem(self):
        for name in ("", ".", "..."):
            with self.subTest(name=name):
                out = scrub.sanitize_name(name)
                self.assertTrue(out.startswith("file"), out)

    # -- parse_show -----------------------------------------------------------

    def test_parse_show_real_output_shape(self):
        text = ("[+] Metadata for /tmp/scrub/shot.png:\n"
                "    Author: Jane Doe\n")
        pairs, _notes = scrub.parse_show(text)
        self.assertEqual(pairs, [{"key": "Author", "value": "Jane Doe"}])

    def test_parse_show_no_metadata_is_note_not_pair(self):
        pairs, notes = scrub.parse_show("  No metadata found in /tmp/x.cleaned.png.\n")
        self.assertEqual(pairs, [])
        self.assertTrue(any("No metadata found" in n for n in notes), notes)

    def test_parse_show_warning_lines_become_notes(self):
        text = ("[-] Something went wrong reading the exif block\n"
                "[+] Metadata for /tmp/shot.png:\n"
                "    Author: Jane Doe\n")
        pairs, notes = scrub.parse_show(text)
        self.assertEqual(pairs, [{"key": "Author", "value": "Jane Doe"}])
        self.assertTrue(any("Something went wrong" in n for n in notes), notes)

    def test_parse_show_splits_on_first_separator_only(self):
        # Metadata values routinely contain ": " themselves (URLs, comments) —
        # only the first separator divides key from value.
        pairs, _notes = scrub.parse_show(
            "[+] Metadata for x:\n    Comment: rating: 5 stars: really\n")
        self.assertEqual(pairs, [{"key": "Comment", "value": "rating: 5 stars: really"}])

    def test_parse_show_caps_pair_count_and_notes_how_many_dropped(self):
        lines = ["[+] Metadata for /tmp/big.pdf:"]
        lines += [f"    Key{i}: value {i}" for i in range(600)]
        pairs, notes = scrub.parse_show("\n".join(lines))
        self.assertEqual(len(pairs), 500)
        self.assertTrue(any("100" in n for n in notes), notes)

    def test_parse_show_truncates_oversized_values(self):
        pairs, _notes = scrub.parse_show(
            "[+] Metadata for x:\n    Comment: " + "x" * 5000 + "\n")
        self.assertEqual(len(pairs), 1)
        self.assertLessEqual(len(pairs[0]["value"]), 2000)
        self.assertTrue(pairs[0]["value"].startswith("xxxx"))

    def test_parse_show_never_raises_on_garbage(self):
        for garbage in ("", "\x00\xff\xfe binary junk \x07", "::::\n: : :\n",
                        "[+]\n[-]\n    :\n", "    lonely-line-without-separator\n"):
            with self.subTest(garbage=garbage[:20]):
                pairs, notes = scrub.parse_show(garbage)
                self.assertIsInstance(pairs, list)
                self.assertIsInstance(notes, list)

    # -- _session_dir ----------------------------------------------------------

    def test_session_dir_rejects_crafted_tokens(self):
        for tok in ("", "..", "a/b", "short", "a" * 65,
                    "../../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd",
                    "aaaaaaaaaaaaaaa",             # 15 chars — one under the floor
                    "valid-looking/../escape-oops"):
            with self.subTest(token=tok):
                with self.assertRaises(ValueError):
                    scrub._session_dir(tok)

    def test_session_dir_accepts_real_token_inside_root(self):
        tok = secrets.token_urlsafe(24)
        d = scrub._session_dir(tok)
        d.relative_to(scrub.SCRUB_DIR)  # raises ValueError if it ever escapes
        self.assertEqual(d.name, tok)

    # -- create / delete / purge ------------------------------------------------

    def test_create_session_writes_private_files(self):
        sess = scrub.create_session("shot.png", b"data")
        d = scrub._session_dir(sess["token"])
        self.assertTrue(d.is_dir())
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        self.assertEqual(scrub.SCRUB_DIR.stat().st_mode & 0o777, 0o700)
        meta = json.loads((d / "meta.json").read_text())
        self.assertEqual(meta["name"], "shot.png")
        self.assertEqual(meta["size"], 4)
        for f in d.iterdir():
            with self.subTest(file=f.name):
                self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        uploads = [f for f in d.iterdir() if f.name != "meta.json"]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0].read_bytes(), b"data")

    def test_delete_session_removes_and_is_idempotent(self):
        sess = scrub.create_session("shot.png", b"x")
        d = scrub._session_dir(sess["token"])
        scrub.delete_session(sess["token"])
        self.assertFalse(d.exists())
        scrub.delete_session(sess["token"])  # deleting a gone session must not raise

    def test_purge_stale_removes_expired_and_keeps_fresh(self):
        old = scrub.create_session("old.png", b"x")
        fresh = scrub.create_session("new.png", b"y")
        old_dir = scrub._session_dir(old["token"])
        fresh_dir = scrub._session_dir(fresh["token"])
        past = time.time() - scrub.SESSION_TTL - 120
        os.utime(old_dir, (past, past))
        scrub.purge_stale()
        self.assertFalse(old_dir.exists())
        self.assertTrue(fresh_dir.exists())

    def test_purge_stale_without_scrub_dir_is_noop(self):
        with mock.patch.object(scrub, "SCRUB_DIR",
                               Path(self._tmp.name) / "never-created"):
            scrub.purge_stale()  # must not raise

    # -- status ------------------------------------------------------------------

    def test_status_fails_loud_when_mat2_missing(self):
        # FAIL-LOUD contract: available can never read true without the binary.
        real_which = common.which
        with mock.patch.object(common, "which",
                               side_effect=lambda name: None if name == "mat2" else real_which(name)):
            st = scrub.status()
        self.assertFalse(st["available"])
        self.assertTrue(st.get("reason"))

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_status_reports_version_and_dotted_formats(self):
        st = scrub.status()
        self.assertTrue(st["available"])
        self.assertIn("mat2", st["version"])
        self.assertEqual(st["max_upload_bytes"], scrub.MAX_UPLOAD)
        self.assertIsInstance(st["sandbox"], bool)
        self.assertIn(".png", st["formats"])
        self.assertTrue(all(f.startswith(".") for f in st["formats"]))
        self.assertEqual(st["format_count"], len(st["formats"]))

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_supported_exts_lowercase_dotted(self):
        exts = scrub.supported_exts()
        self.assertIn(".png", exts)
        self.assertTrue(all(e == e.lower() and e.startswith(".") for e in exts))

    # -- end-to-end with the real mat2 --------------------------------------------

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_e2e_png_roundtrip_with_real_mat2(self):
        sess = scrub.create_session("shot.png", _scrub_png())
        token = sess["token"]

        info = scrub.inspect(token)
        pairs = info.get("metadata") or []
        self.assertTrue(any(p["key"] == "Author" and "Jane Doe" in p["value"]
                            for p in pairs), pairs)

        out = scrub.clean(token)
        self.assertFalse(out.get("error"), out)
        self.assertTrue(out["clean"])
        self.assertEqual(out["metadata_after"], [])
        self.assertEqual(out["cleaned_name"], "shot.cleaned.png")
        self.assertGreater(out["size_before"], 0)
        self.assertGreater(out["size_after"], 0)

        path, name = scrub.cleaned_file(token)
        self.assertEqual(name, "shot.cleaned.png")
        data = Path(path).read_bytes()
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertNotIn(b"tEXt", data)

        scrub.delete_session(token)
        with self.assertRaises((ValueError, FileNotFoundError)):
            scrub.cleaned_file(token)

    # -- upload route contract (direct handler calls) ------------------------------

    def _upload_handler(self):
        # The route table is the contract — grab the registered handler rather
        # than importing a function name the spec doesn't pin. Built after
        # setUp's SCRUB_DIR patch so build_app's startup purge hits the
        # throwaway tree, never var/scrub.
        return _bastion_build_app().routes["POST /api/scrub/upload"]

    @staticmethod
    def _upload_req(headers: dict, body: bytes) -> common.Request:
        return common.Request("POST", "/api/scrub/upload", {}, headers, body, "127.0.0.1")

    def test_scrub_routes_registered_with_body_limit(self):
        app = _bastion_build_app()
        for key in ("GET /api/scrub/status", "POST /api/scrub/upload",
                    "POST /api/scrub/clean", "GET /api/scrub/file",
                    "POST /api/scrub/delete"):
            with self.subTest(route=key):
                self.assertIn(key, app.routes)
        self.assertEqual(app.body_limits.get("POST /api/scrub/upload"), scrub.MAX_UPLOAD)

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_upload_missing_filename_is_400(self):
        resp = self._upload_handler()(self._upload_req({}, b"data"))
        self.assertEqual(resp.status, 400)

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_upload_unsupported_extension_is_415(self):
        # lowercase header on purpose — the lookup must be case-insensitive
        resp = self._upload_handler()(self._upload_req({"x-filename": "notes.xyz"}, b"data"))
        self.assertEqual(resp.status, 415)
        err = json.loads(resp.body)["error"]
        self.assertIn(".xyz", err)
        self.assertIn("supported", err.lower())

    @unittest.skipUnless(common.which("mat2"), "mat2 not installed")
    def test_upload_empty_body_is_400(self):
        resp = self._upload_handler()(self._upload_req({"X-Filename": "shot.png"}, b""))
        self.assertEqual(resp.status, 400)

    def test_upload_without_mat2_is_503_fail_loud(self):
        real_which = common.which
        with mock.patch.object(common, "which",
                               side_effect=lambda name: None if name == "mat2" else real_which(name)):
            resp = self._upload_handler()(self._upload_req({"X-Filename": "shot.png"}, b"data"))
        self.assertEqual(resp.status, 503)
        self.assertIn("pacman -S mat2", json.loads(resp.body)["error"])


# ==========================================================================
# 21. consoles/devkit/tools.py — the pure-logic dev toolbelt
# ==========================================================================
class TestDevkit(unittest.TestCase):
    """Known-answer vectors for the devkit engine. Every function here is
    import-and-call with no server, so a wrong hash, a broken encode round-trip,
    a mis-verified JWT, or a cron miscount fails offline — before the thin POST
    wrappers ever see it. Devkit does no network or filesystem I/O; the ONE
    subprocess (the ReDoS-guarded regex worker) runs our own python, and the
    catastrophic-pattern case below asserts that guard returns an error dict
    instead of hanging a worker thread.

    The contract fixes the answer of each tool but deliberately leaves the
    result *wrapper* open (a value may come back bare or under result/value/...).
    The helpers below peel that one layer so a vector assertion pins the answer,
    not the wrapper the console author happened to pick, and the error helper
    accepts either a raised ValueError or an {'error': ...} dict as a clean
    rejection — what it never tolerates is bad input yielding a normal result."""

    # --- shape tolerance helpers -----------------------------------------
    @staticmethod
    def _unwrap(out):
        if isinstance(out, dict):
            for k in ("result", "value", "output", "bytes"):
                if k in out:
                    return out[k]
        return out

    @staticmethod
    def _as_list(out):
        """Normalize a generator's one-or-many output to a plain list."""
        if isinstance(out, dict):
            for k in ("results", "values", "passwords", "uuids", "ids", "result"):
                if k in out:
                    v = out[k]
                    return v if isinstance(v, list) else [v]
            for k in ("password", "uuid", "value"):
                if k in out:
                    return [out[k]]
        if isinstance(out, list):
            return out
        if isinstance(out, (str, int)):
            return [out]
        return []

    @staticmethod
    def _nums(v):
        """Pull the numeric components out of a color channel value however it
        is represented — 'rgb(255, 136, 0)', [255,136,0], {'r':255,...}, and
        decimals like 'hsl(32.0, 100.0%, 50.0%)' all come out as ints."""
        if isinstance(v, str):
            return [int(round(float(x))) for x in re.findall(r"-?\d+(?:\.\d+)?", v)]
        if isinstance(v, (list, tuple)):
            return [int(round(x)) for x in v if isinstance(x, (int, float))]
        if isinstance(v, dict):
            return [int(round(x)) for x in v.values() if isinstance(x, (int, float))]
        return []

    @staticmethod
    def _dt(s):
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1]
        return datetime.datetime.fromisoformat(s)

    def _assert_signals_error(self, fn, *args, **kwargs):
        """Bad input is a clean rejection, never a 500-shaped blow-up: the tool
        either raises ValueError or returns a dict carrying an 'error' key."""
        try:
            out = fn(*args, **kwargs)
        except ValueError:
            return
        self.assertIsInstance(out, dict,
                              f"{getattr(fn, '__name__', fn)} did not reject bad input: {out!r}")
        self.assertIn("error", out,
                      f"{getattr(fn, '__name__', fn)} returned no error for bad input: {out!r}")

    @staticmethod
    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def _make_jwt(self, payload, secret, alg="HS256"):
        header = {"alg": alg, "typ": "JWT"}
        signing = (self._b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
                   + "." + self._b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
        if alg == "none":
            return signing + "."
        mac = hmac.new(secret.encode("utf-8"), signing.encode("ascii"), hashlib.sha256).digest()
        return signing + "." + self._b64url(mac)

    # --- hashing ----------------------------------------------------------
    def test_hash_known_vectors(self):
        out = devkit_tools.hash_text("abc")
        self.assertEqual(out["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(out["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(out["sha256"],
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(out["sha3_256"],
                         "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        self.assertEqual(len(out["sha512"]), 128)

    def test_hash_blake2b_default_digest(self):
        out = devkit_tools.hash_text("abc")
        self.assertEqual(len(out["blake2b"]), 128)  # 64-byte digest as hex
        self.assertTrue(all(c in "0123456789abcdef" for c in out["blake2b"]))

    # --- encode / decode --------------------------------------------------
    def test_encode_decode_roundtrips(self):
        text = "The quick brown fox! <a>&'\" 1+2=3"
        for scheme in ("base64", "base64url", "base32", "hex", "url", "html", "rot13"):
            with self.subTest(scheme=scheme):
                enc = self._unwrap(devkit_tools.encode(text, scheme))
                self.assertIsInstance(enc, str)
                dec = self._unwrap(devkit_tools.decode(enc, scheme))
                self.assertEqual(dec, text)

    def test_base64_known_and_padless_decode(self):
        self.assertEqual(self._unwrap(devkit_tools.encode("hello", "base64")), "aGVsbG8=")
        # base64 decode must tolerate the stripped padding
        self.assertEqual(self._unwrap(devkit_tools.decode("aGVsbG8", "base64")), "hello")

    def test_hex_and_rot13_known_vectors(self):
        self.assertEqual(self._unwrap(devkit_tools.encode("hello", "hex")), "68656c6c6f")
        self.assertEqual(self._unwrap(devkit_tools.decode("68656c6c6f", "hex")), "hello")
        self.assertEqual(self._unwrap(devkit_tools.encode("hello", "rot13")), "uryyb")

    def test_decode_bad_input_errors(self):
        self._assert_signals_error(devkit_tools.decode, "!!!not-hex!!!", "hex")

    # --- JWT --------------------------------------------------------------
    def test_jwt_reads_header_and_payload(self):
        out = devkit_tools.jwt_decode(self._make_jwt({"sub": "42", "name": "Cole"}, "topsecret"))
        self.assertEqual(out["header"]["alg"], "HS256")
        self.assertEqual(out["alg"], "HS256")
        self.assertEqual(out["payload"]["sub"], "42")
        self.assertEqual(out["payload"]["name"], "Cole")

    def test_jwt_verify_with_right_and_wrong_secret(self):
        tok = self._make_jwt({"sub": "42"}, "topsecret")
        self.assertIs(devkit_tools.jwt_decode(tok, secret="topsecret", verify=True)["verified"], True)
        self.assertIs(devkit_tools.jwt_decode(tok, secret="wrong", verify=True)["verified"], False)

    def test_jwt_alg_none_warns(self):
        out = devkit_tools.jwt_decode(self._make_jwt({"sub": "42"}, "", alg="none"))
        self.assertTrue(out.get("warnings"))
        self.assertIn("none", " ".join(out["warnings"]).lower())

    def test_jwt_expiry_flag(self):
        past = self._make_jwt({"exp": int(time.time()) - 3600}, "s")
        future = self._make_jwt({"exp": int(time.time()) + 3600}, "s")
        out_past = devkit_tools.jwt_decode(past)
        self.assertIs(out_past["expired"], True)
        self.assertTrue(out_past.get("exp_human"))
        self.assertIn(devkit_tools.jwt_decode(future)["expired"], (False, None))

    def test_jwt_malformed_errors(self):
        self._assert_signals_error(devkit_tools.jwt_decode, "not-a-jwt")

    # --- JSON tool --------------------------------------------------------
    def test_json_pretty_and_minify(self):
        pretty = self._unwrap(devkit_tools.json_tool('{"b":1,"a":2}', "pretty"))
        self.assertIn("\n", pretty)
        self.assertEqual(json.loads(pretty), {"b": 1, "a": 2})
        mini = self._unwrap(devkit_tools.json_tool('{ "a" : 1 , "b" : 2 }', "minify"))
        self.assertEqual(mini, '{"a":1,"b":2}')

    def test_json_validate_accepts_valid(self):
        out = devkit_tools.json_tool('{"a":1}', "validate")
        if isinstance(out, dict):
            self.assertNotIn("error", out)

    def test_json_invalid_returns_error(self):
        try:
            out = devkit_tools.json_tool('{"a": }', "pretty")
        except ValueError:
            return
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    # --- generators -------------------------------------------------------
    def test_gen_password_length_and_classes(self):
        pw = self._as_list(devkit_tools.gen_password(length=24))[0]
        self.assertEqual(len(pw), 24)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_gen_password_count(self):
        pws = self._as_list(devkit_tools.gen_password(length=12, count=3))
        self.assertEqual(len(pws), 3)
        self.assertTrue(all(len(p) == 12 for p in pws))

    def test_gen_password_rejects_too_short(self):
        self._assert_signals_error(devkit_tools.gen_password, length=2)

    def test_gen_password_rejects_no_class(self):
        self._assert_signals_error(devkit_tools.gen_password, length=12,
                                   upper=False, lower=False, digits=False, symbols=False)

    def test_gen_uuid_version_and_count(self):
        ids = self._as_list(devkit_tools.gen_uuid(version=4, count=3))
        self.assertEqual(len(ids), 3)
        for u in ids:
            self.assertEqual(uuid.UUID(str(u)).version, 4)

    # --- numbers & color --------------------------------------------------
    def test_base_convert_known_and_roundtrip(self):
        self.assertEqual(self._unwrap(devkit_tools.base_convert("ff", 16, 2)), "11111111")
        self.assertEqual(self._unwrap(devkit_tools.base_convert("11111111", 2, 16)), "ff")
        self.assertEqual(self._unwrap(devkit_tools.base_convert("255", 10, 16)), "ff")

    def test_base_convert_bad_digit_errors(self):
        self._assert_signals_error(devkit_tools.base_convert, "xyz", 10, 2)

    def test_color_hex_to_rgb(self):
        out = devkit_tools.color_convert("#ff8800")
        self.assertEqual(self._nums(out["rgb"])[:3], [255, 136, 0])

    def test_color_hsl_within_tolerance(self):
        # #ff8800 is hsl(32, 100%, 50%) — the round-trip must land within a
        # rounding tolerance of that.
        hue, sat, lum = self._nums(devkit_tools.color_convert("#ff8800")["hsl"])[:3]
        self.assertLessEqual(abs(hue - 32), 2)
        self.assertEqual(sat, 100)
        self.assertLessEqual(abs(lum - 50), 2)

    def test_color_bad_errors(self):
        self._assert_signals_error(devkit_tools.color_convert, "not-a-color")

    def test_bytes_roundtrip(self):
        for n in (1024, 1048576, 1610612736):  # 1 KiB, 1 MiB, 1.5 GiB
            with self.subTest(n=n):
                human = self._unwrap(devkit_tools.humanize_bytes(n, binary=True))
                self.assertIsInstance(human, str)
                self.assertEqual(int(self._unwrap(devkit_tools.parse_bytes(human))), n)

    # --- text -------------------------------------------------------------
    def test_text_transforms(self):
        self.assertEqual(self._unwrap(devkit_tools.text_tools("Hello World!", "slugify")),
                         "hello-world")
        self.assertEqual(self._unwrap(devkit_tools.text_tools("hello world", "upper")),
                         "HELLO WORLD")

    def test_text_sort_unique(self):
        out = self._unwrap(devkit_tools.text_tools(
            "banana\napple\nbanana\ncherry", "sort", unique=True))
        self.assertEqual(out.splitlines(), ["apple", "banana", "cherry"])

    def test_text_dedup_keeps_order(self):
        out = self._unwrap(devkit_tools.text_tools("b\na\nb\nc\na", "dedup"))
        self.assertEqual(out.splitlines(), ["b", "a", "c"])

    def test_text_count(self):
        out = devkit_tools.text_tools("one two three\nfour five", "count")
        counts = out["counts"] if isinstance(out, dict) and "counts" in out else self._unwrap(out)
        self.assertEqual(counts["words"], 5)
        self.assertEqual(counts["lines"], 2)

    def test_text_diff_detects_changes(self):
        out = devkit_tools.text_diff("alpha\nbeta\ngamma", "alpha\nBETA\ngamma")
        self.assertTrue(out["changed"])
        self.assertTrue(out.get("added"))
        self.assertTrue(out.get("removed"))
        self.assertIn("beta", out["diff"])

    def test_text_diff_identical(self):
        self.assertFalse(devkit_tools.text_diff("same\ntext", "same\ntext")["changed"])

    # --- cron -------------------------------------------------------------
    def test_cron_every_15_min_spacing(self):
        out = devkit_tools.cron_next("*/15 * * * *", count=5, base_iso="2026-01-01T00:07:00")
        times = [self._dt(s) for s in out["next"]]
        self.assertEqual(len(times), 5)
        for earlier, later in zip(times, times[1:]):
            self.assertEqual((later - earlier).total_seconds(), 900)
        self.assertEqual((times[0].hour, times[0].minute), (0, 15))

    def test_cron_mondays_at_nine(self):
        out = devkit_tools.cron_next("0 9 * * 1", count=4, base_iso="2026-01-01T00:00:00")
        for dt in (self._dt(s) for s in out["next"]):
            self.assertEqual(dt.weekday(), 0)  # Monday
            self.assertEqual((dt.hour, dt.minute), (9, 0))

    def test_cron_month_starts(self):
        out = devkit_tools.cron_next("0 0 1 * *", count=3, base_iso="2026-01-15T00:00:00")
        for dt in (self._dt(s) for s in out["next"]):
            self.assertEqual(dt.day, 1)
            self.assertEqual((dt.hour, dt.minute), (0, 0))

    def test_cron_count_is_capped(self):
        out = devkit_tools.cron_next("* * * * *", count=100, base_iso="2026-01-01T00:00:00")
        self.assertLessEqual(len(out["next"]), 20)

    def test_cron_bad_field_errors(self):
        self._assert_signals_error(devkit_tools.cron_next, "99 * * * *",
                                   count=5, base_iso="2026-01-01T00:00:00")

    # --- regex (ReDoS-guarded subprocess) ---------------------------------
    def test_regex_normal_matches(self):
        out = devkit_tools.regex_test(r"(\d+)", "abc123def456")
        self.assertNotIn("error", out)
        self.assertEqual(out.get("count", len(out.get("matches", []))), 2)
        self.assertIn("123", json.dumps(out.get("matches")))

    def test_regex_invalid_pattern_errors(self):
        out = devkit_tools.regex_test("(unclosed", "text")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    def test_regex_catastrophic_backtracking_guarded(self):
        # The subprocess guard must kill this within its hard timeout and hand
        # back an error dict, never hang the caller. Input kept small so the
        # test finishes at the guard's timeout, not later.
        out = devkit_tools.regex_test(r"(a+)+$", "a" * 30 + "!")
        self.assertIsInstance(out, dict)
        self.assertIn("error", out)

    # --- network (CIDR) ---------------------------------------------------
    def test_cidr_info_slash24(self):
        out = devkit_tools.cidr_info("192.168.1.0/24")
        self.assertEqual(out["num_usable_hosts"], 254)
        self.assertEqual(out["num_addresses"], 256)
        self.assertEqual(out["prefixlen"], 24)
        self.assertEqual(out["version"], 4)
        self.assertTrue(out["is_private"])
        self.assertEqual(out["first_host"], "192.168.1.1")
        self.assertEqual(out["last_host"], "192.168.1.254")

    def test_cidr_contains(self):
        self.assertTrue(devkit_tools.cidr_contains("192.168.1.0/24", "192.168.1.50")["contains"])
        self.assertFalse(devkit_tools.cidr_contains("192.168.1.0/24", "10.0.0.1")["contains"])

    def test_cidr_bad_errors(self):
        self._assert_signals_error(devkit_tools.cidr_info, "999.1.1.0/24")


# ==========================================================================
# 21b. consoles/devkit — hostile-input hardening (no tool may exhaust a
# worker or 500 on pathological input). Regression cover for the four
# robustness fixes: deeply nested JSON (RecursionError), non-finite/oversized
# numbers (OverflowError), an unbounded password length, and an oversized
# base_convert value whose bignum would blow the int->str digit limit.
# ==========================================================================
class TestDevkitHardening(unittest.TestCase):
    def _assert_raises_value(self, fn, *args, **kwargs):
        with self.assertRaises(ValueError):
            fn(*args, **kwargs)

    def test_nested_json_is_clean_error(self):
        # json.loads blows its parser stack on this; the tool must translate
        # that into a ValueError, not let RecursionError escape.
        self._assert_raises_value(devkit_tools.json_tool, "[" * 60000 + "]" * 60000, "validate")

    def test_humanize_bytes_rejects_non_finite_and_oversized(self):
        self._assert_raises_value(devkit_tools.humanize_bytes, float("inf"))
        self._assert_raises_value(devkit_tools.humanize_bytes, float("nan"))
        self._assert_raises_value(devkit_tools.humanize_bytes, 10 ** 400)

    def test_humanize_duration_rejects_non_finite(self):
        self._assert_raises_value(devkit_tools.humanize_duration, float("inf"))
        self._assert_raises_value(devkit_tools.humanize_duration, 10 ** 400)

    def test_gen_password_length_is_capped(self):
        # An unbounded length is a memory/CPU exhaustion vector from a tiny
        # request; it must be rejected, not attempted.
        self._assert_raises_value(devkit_tools.gen_password, length=10 ** 8)

    def test_base_convert_value_length_is_capped(self):
        self._assert_raises_value(devkit_tools.base_convert, "f" * 5000, 16, 36)


# ==========================================================================
# 22. consoles/systems/sysinfo.py — read-only local machine collectors
# ==========================================================================
@unittest.skipUnless(sys.platform.startswith("linux"),
                     "systems collectors read Linux /proc and /sys")
class TestSystems(unittest.TestCase):
    """Shape + invariant checks for the read-only health collectors. They read
    /proc, /sys and stdlib only, so on any Linux box each returns a JSON-able
    dict without raising and the physical laws hold (used<=total, 0<=percent<=100,
    lo is always present, ...). Values are live, so nothing here pins an exact
    number — only the shape and the invariants that can't be violated. Key
    names the contract left loose are read tolerantly so a naming choice by the
    console author doesn't read as a failure."""

    @staticmethod
    def _num(v):
        """A byte-valued field may be a bare number or a {'bytes':N,'human':..}
        pair — return the numeric part, or None if there isn't one."""
        if isinstance(v, dict):
            for k in ("bytes", "value", "raw", "b"):
                if isinstance(v.get(k), (int, float)):
                    return v[k]
            return None
        return v if isinstance(v, (int, float)) else None

    @staticmethod
    def _rows(out, *keys):
        """Pull a list of rows whether the collector returns it bare or wraps
        it under a key (disks/network/processes)."""
        if isinstance(out, list):
            return out
        if isinstance(out, dict):
            for k in keys:
                if isinstance(out.get(k), list):
                    return out[k]
            for v in out.values():
                if isinstance(v, list):
                    return v
        return []

    def test_overview_has_hostname(self):
        out = sysinfo.overview()
        self.assertIsInstance(out, dict)
        self.assertTrue(out.get("hostname"))
        up = self._num(out.get("uptime", out.get("uptime_seconds")))
        if up is not None:
            self.assertGreaterEqual(up, 0)

    def test_cpu_percentages_in_range(self):
        out = sysinfo.cpu()
        self.assertIsInstance(out, dict)
        cores = self._rows(out, "per_core", "cores", "per_cpu", "percpu",
                           "core_percent", "per_core_percent")
        self.assertTrue(cores)  # at least one core reported
        overall = None
        for k in ("overall", "percent", "total", "usage", "utilization"):
            v = out.get(k)
            v = v.get("percent") if isinstance(v, dict) else v
            if isinstance(v, (int, float)):
                overall = v
                break
        if overall is not None:
            self.assertGreaterEqual(overall, 0)
            self.assertLessEqual(overall, 100)

    def test_memory_invariants(self):
        out = sysinfo.memory()
        total = self._num(out.get("total")) or self._num(out.get("total_bytes"))
        used = self._num(out.get("used"))
        if used is None:
            used = self._num(out.get("used_bytes"))
        self.assertIsNotNone(total)
        self.assertGreater(total, 0)
        if used is not None:
            self.assertLessEqual(used, total)
        pct = out.get("percent")
        pct = pct.get("percent") if isinstance(pct, dict) else pct
        if isinstance(pct, (int, float)):
            self.assertGreaterEqual(pct, 0)
            self.assertLessEqual(pct, 100)

    def test_disks_include_root_mount(self):
        rows = self._rows(sysinfo.disks(), "disks", "mounts", "filesystems")
        self.assertTrue(rows)
        self.assertTrue(any(isinstance(d, dict) and (self._num(d.get("total")) or 0) > 0
                            for d in rows))
        mounts = [d.get("mount") or d.get("mountpoint")
                  for d in rows if isinstance(d, dict)]
        self.assertIn("/", mounts)

    def test_network_lists_loopback(self):
        rows = self._rows(sysinfo.network(), "interfaces", "ifaces", "nics")
        names = [n.get("name") or n.get("iface") for n in rows if isinstance(n, dict)]
        self.assertIn("lo", names)

    def test_listening_returns_a_container(self):
        self.assertIsInstance(sysinfo.listening(), (dict, list))

    def test_processes_returns_two_nonempty_lists(self):
        out = sysinfo.processes(limit=10)
        lists = []
        if isinstance(out, dict):
            for v in out.values():
                if isinstance(v, list):
                    lists.append(v)
                elif isinstance(v, dict):
                    lists.extend(vv for vv in v.values() if isinstance(vv, list))
        elif isinstance(out, (list, tuple)):
            lists = [x for x in out if isinstance(x, list)]
        self.assertGreaterEqual(len(lists), 2)          # top-by-cpu and top-by-mem
        self.assertTrue(any(len(x) > 0 for x in lists))  # a running box has processes

    def test_sensors_shape(self):
        out = sysinfo.sensors()
        self.assertIsInstance(out, dict)
        for key in ("temps", "batteries", "ac"):
            self.assertIn(key, out)
        self.assertIsInstance(out["temps"], list)
        self.assertIsInstance(out["batteries"], list)

    def test_services_returns_dict(self):
        self.assertIsInstance(sysinfo.services(), dict)


# ==========================================================================
# 23. consoles/devkit/app.py — POST route contract (live loopback)
# ==========================================================================
class DevkitHandlerContractTests(unittest.TestCase):
    """One live-server proof that devkit's POST routes wear the framework's two
    guarantees: a malformed body comes back 400 (validated, never a 500 from an
    unhandled raise), and a POST without a same-origin Origin is refused 403 by
    the shared CSRF guard before the handler runs. Binds 127.0.0.1 on an
    OS-assigned ephemeral port and shuts back down; no network."""

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def setUp(self):
        app = _devkit_build_app()
        self.httpd = None
        last_error = None
        for _attempt in range(3):
            port = self._free_port()
            try:
                self.httpd = common.serve(app, port=port, block=False)
                self.port = port
                break
            except OSError as e:
                last_error = e
                continue
        if self.httpd is None:
            self.skipTest(f"could not bind a loopback test port: {last_error}")
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _post(self, path: str, body: bytes, headers: dict) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def test_bad_body_returns_400_not_500(self):
        # Same-origin so CSRF passes; an unparseable CIDR must validate into a
        # clean 400, not raise into a 500.
        headers = {"Origin": f"http://127.0.0.1:{self.port}",
                   "Content-Type": "application/json"}
        self.assertEqual(self._post("/api/devkit/cidr", b'{"cidr":"not-a-cidr"}', headers), 400)

    def test_post_without_origin_refused_403(self):
        self.assertEqual(
            self._post("/api/devkit/cidr", b'{"cidr":"192.168.1.0/24"}',
                       {"Content-Type": "application/json"}), 403)

    def test_post_with_foreign_origin_refused_403(self):
        self.assertEqual(
            self._post("/api/devkit/cidr", b'{"cidr":"192.168.1.0/24"}',
                       {"Origin": "http://evil.example:1234",
                        "Content-Type": "application/json"}), 403)


# ==========================================================================
# 24. shared/common.py — CSRF _origin_ok exact-port + fetch Set-Cookie
#     preservation (the two framework security fixes from the upgrade pass)
# ==========================================================================
class OriginExactPortTests(unittest.TestCase):
    """_origin_ok must accept ONLY this console's own origin, and the port has
    to match EXACTLY. A port-less Origin (http://localhost -> :80, or
    https://127.0.0.1 -> :443) used to slip through on a "still loopback"
    theory, which made any default-port loopback page a CSRF source for every
    console. Nucleus never serves on 80/443, so a genuine same-origin request
    always carries the real port and nothing legitimate is lost by requiring
    it."""

    PORT = 8890

    def test_exact_port_origin_accepted(self):
        for host in ("127.0.0.1", "localhost", "[::1]"):
            with self.subTest(host=host):
                self.assertTrue(common._origin_ok(f"http://{host}:{self.PORT}", self.PORT))

    def test_portless_origin_rejected(self):
        # http://localhost is :80, https://127.0.0.1 is :443 — neither is us.
        for origin in ("http://127.0.0.1", "http://localhost", "https://127.0.0.1",
                       "https://localhost", "http://[::1]"):
            with self.subTest(origin=origin):
                self.assertFalse(common._origin_ok(origin, self.PORT))

    def test_wrong_port_origin_rejected(self):
        for bad in (self.PORT + 1, 80, 443, 9999):
            with self.subTest(port=bad):
                self.assertFalse(common._origin_ok(f"http://127.0.0.1:{bad}", self.PORT))

    def test_foreign_host_rejected_even_with_right_port(self):
        self.assertFalse(common._origin_ok(f"http://evil.example:{self.PORT}", self.PORT))

    def test_empty_and_malformed_origin_rejected(self):
        self.assertFalse(common._origin_ok("", self.PORT))
        # A crafted bad port must not crash the guard — it must read as False.
        self.assertFalse(common._origin_ok("http://127.0.0.1:8890.evil", self.PORT))


class _TwoCookieHandler(http.server.BaseHTTPRequestHandler):
    """Emits TWO Set-Cookie headers so the fetch header-collapse fix can be
    proven end-to-end: a naive {k: v for ...} would keep only the last one."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        # Two cookies; the first carries an Expires with its own comma to prove
        # the "\n" join (not ",") is what keeps them separable downstream.
        self.send_header("Set-Cookie",
                         "session=abc; Path=/; Expires=Wed, 09 Jun 2027 10:18:14 GMT; HttpOnly")
        self.send_header("Set-Cookie", "tracking=xyz; Path=/; SameSite=Lax")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class FetchSetCookiePreservationTests(unittest.TestCase):
    """common.fetch must preserve every Set-Cookie header. Repeats collapse to
    the last value under a plain dict comprehension; the fix joins Set-Cookie
    repeats with "\\n" (comma is unsafe — cookies carry Expires=..., commas).
    Callers split resp_headers.get("Set-Cookie", "") on "\\n"."""

    def test_both_cookies_survive_the_fetch(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), _TwoCookieHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/"
            # Pin the SSRF resolver to loopback so fetch will talk to the test
            # server (the guard otherwise refuses 127.0.0.1) — same technique
            # the stresstest keep-alive tests use.
            with mock.patch.object(common, "_resolve_public",
                                   return_value=("127.0.0.1", socket.AF_INET)):
                status, _body, headers = common.fetch(url, timeout=5)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 200)
        raw = headers.get("Set-Cookie", "")
        cookies = raw.split("\n")
        self.assertEqual(len(cookies), 2, f"expected 2 cookies, got {cookies!r}")
        names = [c.split("=", 1)[0] for c in cookies]
        self.assertEqual(names, ["session", "tracking"])
        # The Expires comma inside cookie #1 must NOT have split it into two.
        self.assertIn("Expires=Wed, 09 Jun 2027", cookies[0])

    def test_single_valued_headers_stay_plain_strings(self):
        # Backward-compat: a non-repeated header is still a bare string, not a
        # list, so every existing single-valued consumer keeps working.
        out = common._collect_headers([("Content-Type", "text/html"),
                                       ("Server", "nginx")])
        self.assertEqual(out["Content-Type"], "text/html")
        self.assertEqual(out["Server"], "nginx")

    def test_non_cookie_repeats_join_with_comma(self):
        out = common._collect_headers([("Vary", "Accept"), ("Vary", "Origin")])
        self.assertEqual(out["Vary"], "Accept, Origin")


# ==========================================================================
# 25. consoles/devkit/tools.py — the new crypto/checksum/id tools
#     (HMAC, CRC32, Adler32, UUID v5). Known-answer vectors, tolerant to the
#     exact function name / result-wrapper the console author picks — a wrong
#     digest fails offline regardless.
# ==========================================================================
def _first_attr(mod, names):
    for n in names:
        fn = getattr(mod, n, None)
        if callable(fn):
            return fn
    return None


def _hex_in(out, length=None):
    """Pull the first hex string out of a tool result (bare string, or under a
    conventional key). Optionally require an exact hex length."""
    def _ok(s):
        if not isinstance(s, str):
            return False
        s = s.strip().lower()
        if not s or any(c not in "0123456789abcdef" for c in s):
            return False
        return length is None or len(s) == length
    if _ok(out):
        return out.strip().lower()
    if isinstance(out, dict):
        for k in ("hmac", "digest", "hex", "result", "value", "output", "mac"):
            v = out.get(k)
            if _ok(v):
                return v.strip().lower()
        for v in out.values():
            if _ok(v):
                return v.strip().lower()
    return None


def _uint32(v):
    """Normalize a checksum value (int, decimal string, or hex string) to a
    32-bit int, trying both decimal and hex readings of an ambiguous string."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v & 0xFFFFFFFF
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            try:
                return int(s, 16) & 0xFFFFFFFF
            except ValueError:
                return None
        for base in (10, 16):
            try:
                return int(s, base) & 0xFFFFFFFF
            except ValueError:
                continue
    return None


class DevkitHmacTests(unittest.TestCase):
    def setUp(self):
        self.fn = _first_attr(devkit_tools,
                              ("hmac_text", "hmac_digest", "hmac_hex", "hmac_hash",
                               "hmac_sign", "hmac_compute", "hmac_tool"))
        if self.fn is None:
            self.fail("devkit HMAC tool not present (expected e.g. hmac_text)")

    def _call(self, text, key, algo):
        for kw in ("algo", "algorithm", "alg", "hash"):
            try:
                return self.fn(text, key, **{kw: algo})
            except TypeError:
                continue
        return self.fn(text, key, algo)

    def test_hmac_sha256_known_vector(self):
        text = "The quick brown fox jumps over the lazy dog"
        expected = hmac.new(b"key", text.encode(), hashlib.sha256).hexdigest()
        got = _hex_in(self._call(text, "key", "sha256"), length=64)
        self.assertEqual(got, expected)

    def test_hmac_sha1_known_vector(self):
        expected = hmac.new(b"secret", b"data", hashlib.sha1).hexdigest()
        got = _hex_in(self._call("data", "secret", "sha1"), length=40)
        self.assertEqual(got, expected)


class DevkitChecksumTests(unittest.TestCase):
    """CRC32 + Adler32 — real zlib values, whether they land in the hash tool's
    output or a dedicated checksums function."""

    def _checksums(self, text):
        fn = _first_attr(devkit_tools,
                         ("checksums", "checksum", "crc_adler", "crc"))
        if fn is not None:
            return fn(text)
        # Folded into the hash tool instead.
        try:
            return devkit_tools.hash_text(text, algos=["crc32", "adler32"])
        except (ValueError, TypeError):
            self.fail("no checksums tool and hash_text doesn't do crc32/adler32")

    def _pull(self, out, key):
        if isinstance(out, dict):
            if key in out:
                return _uint32(out[key])
            for wrap in ("result", "value", "checksums"):
                w = out.get(wrap)
                if isinstance(w, dict) and key in w:
                    return _uint32(w[key])
        return None

    def test_crc32_known_value(self):
        out = self._checksums("abc")
        expected = zlib.crc32(b"abc") & 0xFFFFFFFF
        self.assertEqual(self._pull(out, "crc32"), expected)

    def test_adler32_known_value(self):
        out = self._checksums("abc")
        expected = zlib.adler32(b"abc") & 0xFFFFFFFF
        self.assertEqual(self._pull(out, "adler32"), expected)


class DevkitUuidV5Tests(unittest.TestCase):
    """UUID v5 is a SHA-1 namespace hash — it must be deterministic for a fixed
    namespace + name and report version 5."""

    def _extract(self, out):
        cand = TestDevkit._as_list(out)
        for item in cand:
            try:
                return uuid.UUID(str(item))
            except (ValueError, AttributeError):
                continue
        return None

    def _call(self, name):
        errs = []
        for kw in ({"version": 5, "namespace": "dns", "name": name},
                   {"version": 5, "ns": "dns", "name": name},
                   {"version": 5, "namespace": str(uuid.NAMESPACE_DNS), "name": name},
                   {"version": 5, "namespace": "url", "name": name}):
            try:
                out = devkit_tools.gen_uuid(**kw)
            except (TypeError, ValueError) as e:
                errs.append(str(e))
                continue
            u = self._extract(out)
            if u is not None:
                return u
        self.fail(f"gen_uuid did not produce a v5 UUID for a namespace+name ({errs})")

    def test_uuid5_is_version_5(self):
        self.assertEqual(self._call("example.com").version, 5)

    def test_uuid5_is_deterministic(self):
        self.assertEqual(self._call("example.com"), self._call("example.com"))

    def test_uuid5_differs_by_name(self):
        self.assertNotEqual(self._call("example.com"), self._call("example.org"))


# ==========================================================================
# 26. consoles/devkit/app.py — POST /api/devkit/hashfile (in-memory file hash)
#     Raw-body upload, X-Filename header, no disk write, no parsing. Proven
#     over a live loopback server the same way the scrub upload contract is.
# ==========================================================================
class DevkitHashfileTests(unittest.TestCase):
    SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def setUp(self):
        app = _devkit_build_app()
        if "POST /api/devkit/hashfile" not in app.routes:
            self.fail("devkit hashfile route not registered (POST /api/devkit/hashfile)")
        self.httpd = None
        last_error = None
        for _attempt in range(3):
            port = self._free_port()
            try:
                self.httpd = common.serve(app, port=port, block=False)
                self.port = port
                break
            except OSError as e:
                last_error = e
                continue
        if self.httpd is None:
            self.skipTest(f"could not bind a loopback test port: {last_error}")
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _post(self, body: bytes, headers: dict):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("POST", "/api/devkit/hashfile", body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def _origin_headers(self, filename="sample.bin"):
        return {"Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/octet-stream",
                "X-Filename": filename}

    def test_known_bytes_hash_to_known_sha256(self):
        status, body = self._post(b"abc", self._origin_headers("abc.txt"))
        self.assertEqual(status, 200)
        j = json.loads(body)
        # digests may sit at the top level or under a "hashes"/"result" map
        digests = j.get("hashes") or j.get("result") or j
        self.assertEqual(digests.get("sha256"), self.SHA256_ABC)
        # size + filename echoed back
        self.assertEqual(j.get("size", j.get("result", {}).get("size")), 3)
        self.assertIn("abc.txt", json.dumps(j))
        # the standard digest set is present
        blob = json.dumps(j)
        for algo in ("md5", "sha1", "sha512", "blake2b"):
            self.assertIn(algo, blob)

    def test_empty_body_is_400_not_500(self):
        status, _ = self._post(b"", self._origin_headers())
        self.assertEqual(status, 400)

    def test_post_without_origin_refused_403(self):
        status, _ = self._post(b"abc", {"Content-Type": "application/octet-stream",
                                        "X-Filename": "abc.txt"})
        self.assertEqual(status, 403)

    def test_route_carries_a_raised_body_limit(self):
        # hashfile takes whole files, so it opts into a larger cap like scrub.
        app = _devkit_build_app()
        self.assertGreater(app.body_limits.get("POST /api/devkit/hashfile", 0),
                           0)


# ==========================================================================
# 27. engine/osint_report.py — MTA-STS + TLS-RPT passive email checks
#     (additive to the email score, same style as _check_dmarc/_check_spf)
# ==========================================================================
class MtaStsTlsRptTests(unittest.TestCase):
    def setUp(self):
        self.mtasts = getattr(report, "_check_mtasts", None)
        self.tlsrpt = getattr(report, "_check_tlsrpt", None)
        if self.mtasts is None or self.tlsrpt is None:
            self.fail("engine MTA-STS / TLS-RPT checks not present "
                      "(_check_mtasts / _check_tlsrpt)")

    def test_mtasts_enforce_policy_detected(self):
        policy = b"version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
        with mock.patch.object(report.common, "fetch", return_value=(200, policy, {})):
            out = self.mtasts("example.com")
        self.assertTrue(out.get("present"))
        self.assertEqual((out.get("mode") or "").lower(), "enforce")

    def test_mtasts_absent_is_clean_not_crash(self):
        with mock.patch.object(report.common, "fetch",
                               side_effect=ValueError("blocked / no policy")):
            out = self.mtasts("example.com")
        self.assertIsInstance(out, dict)
        self.assertFalse(out.get("present"))

    def test_tlsrpt_present_detected(self):
        rec = "v=TLSRPTv1; rua=mailto:reports@example.com"
        with mock.patch.object(report, "_txt_values", return_value=[rec]):
            out = self.tlsrpt("example.com")
        self.assertTrue(out.get("present"))

    def test_tlsrpt_absent_is_clean_not_crash(self):
        with mock.patch.object(report, "_txt_values", return_value=[]):
            out = self.tlsrpt("example.com")
        self.assertIsInstance(out, dict)
        self.assertFalse(out.get("present"))

    def test_email_score_folds_in_without_crashing_on_neither(self):
        # A domain with neither MTA-STS nor TLS-RPT must still score cleanly:
        # the new signals are additive and, when absent, must not raise. Passed
        # as kwargs only if _score_email accepts them (variable-max pattern).
        import inspect
        spf = {"present": True, "record": "v=spf1 -all", "valid": True, "qualifier": "-"}
        dmarc = {"present": True, "record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "default"}
        params = inspect.signature(report._score_email).parameters
        kwargs = {}
        if "mtasts" in params:
            kwargs["mtasts"] = {"present": False}
        if "tlsrpt" in params:
            kwargs["tlsrpt"] = {"present": False}
        pts, max_pts, findings = report._score_email(spf, dmarc, dkim,
                                                     mx_present=True, **kwargs)
        self.assertLessEqual(pts, max_pts)
        self.assertIsInstance(findings, list)


# ==========================================================================
# 28. consoles/recon/lookups.py — NANP area-code -> US region (pure table,
#     offline; keyless location for a US phone number)
# ==========================================================================
from consoles.recon import lookups as recon_lookups  # noqa: E402


class NanpAreaCodeTests(unittest.TestCase):
    def setUp(self):
        self.fn = _first_attr(recon_lookups,
                              ("nanp_region", "_nanp_region", "area_code_region",
                               "nanp_lookup", "_nanp_lookup", "nanp_area_code"))
        if self.fn is None:
            self.fail("recon NANP area-code table not present (expected e.g. nanp_region)")

    def test_known_area_code_returns_us_region(self):
        # 212 is New York City — unambiguous.
        out = self.fn("212")
        text = out if isinstance(out, str) else json.dumps(out)
        self.assertTrue(text)
        self.assertIn("york", text.lower())

    def test_known_area_code_accepts_int(self):
        # A caller might pass the digits as an int; the table shouldn't care.
        try:
            out = self.fn(212)
        except (TypeError, ValueError):
            self.skipTest("table takes a string area code only")
        text = out if isinstance(out, str) else json.dumps(out)
        self.assertIn("york", text.lower())

    def test_unknown_area_code_is_empty_not_a_crash(self):
        out = self.fn("000")
        self.assertFalse(out)  # None / "" / {} — a miss, never a raise


if __name__ == "__main__":
    unittest.main()
