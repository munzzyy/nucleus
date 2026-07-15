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
        for binary in ("exiftool", "nmap", "mitmproxy", "tshark", "nuclei"):
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


if __name__ == "__main__":
    unittest.main()
