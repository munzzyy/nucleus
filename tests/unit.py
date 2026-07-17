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

import hashlib
import http.client
import json
import os
import socket
import sys
import tempfile
import unittest
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
        spf = {"present": False, "record": None, "valid": False}
        dmarc = {"present": False, "record": None, "policy": None}
        dkim = {"found": False, "selector": None}
        pts, max_pts, findings = report._score_email(spf, dmarc, dkim, mx_present=True)
        self.assertEqual(pts, 0)
        self.assertTrue(findings)
        self.assertTrue(any(f["severity"] == "high" for f in findings))

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
        http_res = {"ok": True, "status": 200, "body_len": 100}
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
        urls, skipped = secretscan._collect_script_urls(html, "https://example.com/", "example.com")
        self.assertEqual(skipped, 1)
        self.assertEqual(urls, ["https://example.com/app.js"])


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


class WebScanTitleTests(unittest.TestCase):
    def test_title_extraction_linear_on_unclosed_tags(self):
        import time
        t0 = time.monotonic()
        webscan._extract_title(b"<title>" * 300_000)  # ~2MB unclosed
        self.assertLess(time.monotonic() - t0, 2.0)

    def test_title_extracted_normally(self):
        self.assertEqual(webscan._extract_title(b"<html><title>Hi There</title></html>"), "Hi There")


if __name__ == "__main__":
    unittest.main()
