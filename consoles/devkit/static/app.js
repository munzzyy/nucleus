(function () {
  "use strict";
  const N = window.Nucleus;

  // XSS posture for this whole file: every value we render is either something
  // the user typed or something a pure transform derived from it (a hashed
  // string, a decoded JWT payload, a regex match). None of it is trusted, so
  // nothing here touches innerHTML — we build DOM with N.el and set text via
  // textContent only. See scrub in bastion/app.js for the same discipline.

  const $ = (id) => document.getElementById(id);

  function errLine(msg) {
    return N.el("p", { class: "muted m0", text: String(msg || "request failed") });
  }

  function outPre(text) {
    return N.el("pre", { class: "dk-out", text: String(text == null ? "" : text) });
  }

  function copyBtn(getText) {
    const b = N.el("button", { class: "ghost dk-copy", type: "button", text: "copy" });
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(String(getText())); N.toast("copied", "ok"); }
      catch (_) { N.toast("copy failed — select manually", "bad"); }
    });
    return b;
  }

  // pairs: [{ key, val, copy?, cls? }]
  function kvList(pairs) {
    const wrap = N.el("div", { class: "dk-kv" });
    pairs.forEach((p) => {
      if (p.val == null || p.val === "") return;
      const row = N.el("div", { class: "dk-kv-row" }, [
        N.el("span", { class: "dk-kv-key", text: p.key }),
        N.el("span", { class: "dk-kv-val mono" + (p.cls ? " " + p.cls : ""), text: String(p.val) }),
      ]);
      if (p.copy) row.appendChild(copyBtn(() => String(p.val)));
      wrap.appendChild(row);
    });
    return wrap;
  }

  function waiting(el) {
    el.replaceChildren(N.el("div", { class: "dk-wait muted" }, [
      N.el("span", { class: "spinner" }), "working…",
    ]));
  }

  // Run a POST, render the result via `render`, or an inline error. Never throws.
  async function run(outEl, path, body, render) {
    waiting(outEl);
    try {
      const j = await N.post(path, body);
      render(j);
    } catch (e) {
      outEl.replaceChildren(errLine(e && e.message ? e.message : "request failed"));
    }
  }

  function onEnter(el, fn) {
    if (!el) return;
    el.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); fn(); } });
  }

  const val = (id) => { const el = $(id); return el ? el.value : ""; };
  const checked = (id) => { const el = $(id); return !!(el && el.checked); };

  // ---- hashing --------------------------------------------------------
  function doHash() {
    const out = $("dk-hash-out");
    run(out, "/api/devkit/hash", { text: val("dk-input") }, (j) => {
      const pairs = Object.keys(j).filter((k) => k !== "ok")
        .map((k) => ({ key: k, val: j[k], copy: true }));
      out.replaceChildren(kvList(pairs));
    });
  }

  // ---- encode / decode ------------------------------------------------
  function doEnc(dir) {
    const out = $("dk-enc-out");
    run(out, "/api/devkit/" + dir, { text: val("dk-enc-input"), scheme: val("dk-enc-scheme") }, (j) => {
      const block = outPre(j.result);
      const row = N.el("div", { class: "dk-out-row" }, [block, copyBtn(() => j.result)]);
      out.replaceChildren(row);
    });
  }

  // ---- JWT ------------------------------------------------------------
  function pillEl(label, kind) {
    return N.el("span", { class: "pill " + (kind || ""), text: label });
  }

  function doJwt() {
    const out = $("dk-jwt-out");
    run(out, "/api/devkit/jwt", {
      token: val("dk-jwt-input"), secret: val("dk-jwt-secret"), verify: checked("dk-jwt-verify"),
    }, (j) => {
      const frag = document.createDocumentFragment();
      const badges = N.el("div", { class: "dk-badges" });
      badges.appendChild(pillEl("alg " + (j.alg || "?"), ""));
      if (j.typ) badges.appendChild(pillEl("typ " + j.typ, ""));
      if (j.verified === true) badges.appendChild(pillEl("signature verified", "ok"));
      else if (j.verified === false) badges.appendChild(pillEl("signature invalid", "bad"));
      if (j.expired === true) badges.appendChild(pillEl("expired", "bad"));
      else if (j.expired === false) badges.appendChild(pillEl("not expired", "ok"));
      frag.appendChild(badges);

      frag.appendChild(N.el("div", { class: "dk-sub faint", text: "Header" }));
      frag.appendChild(outPre(JSON.stringify(j.header, null, 2)));
      frag.appendChild(N.el("div", { class: "dk-sub faint", text: "Payload" }));
      frag.appendChild(outPre(JSON.stringify(j.payload, null, 2)));

      const times = [
        { key: "iat", val: j.iat_human }, { key: "nbf", val: j.nbf_human }, { key: "exp", val: j.exp_human },
      ].filter((t) => t.val);
      if (times.length) frag.appendChild(kvList(times));

      (j.warnings || []).forEach((w) => frag.appendChild(N.el("div", { class: "dk-warn", text: w })));
      out.replaceChildren(frag);
    });
  }

  // ---- JSON -----------------------------------------------------------
  function doJson(mode) {
    const out = $("dk-json-out");
    run(out, "/api/devkit/json", { text: val("dk-json-input"), mode, sort_keys: checked("dk-json-sort") }, (j) => {
      const frag = document.createDocumentFragment();
      if (mode === "validate") frag.appendChild(N.el("div", { class: "dk-verdict ok", text: "✓ valid JSON" }));
      const block = outPre(j.result);
      frag.appendChild(N.el("div", { class: "dk-out-row" }, [block, copyBtn(() => j.result)]));
      out.replaceChildren(frag);
    });
  }

  // ---- generators -----------------------------------------------------
  function listOut(out, items) {
    const wrap = N.el("div", { class: "dk-list" });
    items.forEach((s) => {
      wrap.appendChild(N.el("div", { class: "dk-out-row" }, [
        N.el("code", { class: "dk-code", text: String(s) }), copyBtn(() => String(s)),
      ]));
    });
    out.replaceChildren(wrap);
  }

  function doUuid() {
    const out = $("dk-uuid-out");
    run(out, "/api/devkit/gen", { kind: "uuid", version: val("dk-uuid-version"), count: val("dk-uuid-count") },
      (j) => listOut(out, j.uuids || []));
  }
  function doPassword() {
    const out = $("dk-pw-out");
    run(out, "/api/devkit/gen", {
      kind: "password", length: val("dk-pw-length"), count: val("dk-pw-count"),
      upper: checked("dk-pw-upper"), lower: checked("dk-pw-lower"),
      digits: checked("dk-pw-digits"), symbols: checked("dk-pw-symbols"),
    }, (j) => listOut(out, j.passwords || []));
  }
  function doRandom() {
    const out = $("dk-rand-out");
    run(out, "/api/devkit/gen", { kind: "random", nbytes: val("dk-rand-nbytes"), encoding: val("dk-rand-enc") },
      (j) => listOut(out, [j.result]));
  }
  function doSecret() {
    const out = $("dk-secret-out");
    run(out, "/api/devkit/gen", { kind: "secret", nbytes: val("dk-secret-nbytes") },
      (j) => listOut(out, [j.result]));
  }

  // ---- time -----------------------------------------------------------
  function doNow() {
    const out = $("dk-now-out");
    run(out, "/api/devkit/time", { op: "now" }, (j) => out.replaceChildren(kvList([
      { key: "unix", val: j.unix, copy: true }, { key: "unix (ms)", val: j.unix_ms, copy: true },
      { key: "ISO UTC", val: j.iso_utc, copy: true }, { key: "ISO local", val: j.iso_local, copy: true },
    ])));
  }
  function doU2i() {
    const out = $("dk-time-out");
    run(out, "/api/devkit/time", { op: "unix_to_iso", ts: val("dk-u2i") }, (j) => out.replaceChildren(kvList([
      { key: "ISO UTC", val: j.iso_utc, copy: true }, { key: "ISO local", val: j.iso_local, copy: true },
    ])));
  }
  function doI2u() {
    const out = $("dk-time-out");
    run(out, "/api/devkit/time", { op: "iso_to_unix", iso: val("dk-i2u") }, (j) => out.replaceChildren(kvList([
      { key: "unix", val: j.unix, copy: true }, { key: "ISO UTC", val: j.iso_utc, copy: true },
    ])));
  }
  function doTz() {
    const out = $("dk-tz-out");
    run(out, "/api/devkit/time", { op: "tz_convert", iso: val("dk-tz-iso"), from_tz: val("dk-tz-from"), to_tz: val("dk-tz-to") },
      (j) => out.replaceChildren(kvList([
        { key: "source", val: j.source }, { key: "result", val: j.result, copy: true },
      ])));
  }
  function doDur() {
    const out = $("dk-dur-out");
    run(out, "/api/devkit/time", { op: "humanize_duration", seconds: val("dk-dur") },
      (j) => out.replaceChildren(kvList([{ key: "duration", val: j.result, copy: true }])));
  }

  // ---- cron -----------------------------------------------------------
  function doCron() {
    const out = $("dk-cron-out");
    run(out, "/api/devkit/cron", { expr: val("dk-cron-expr"), count: val("dk-cron-count") }, (j) => {
      const frag = document.createDocumentFragment();
      if (j.description) frag.appendChild(N.el("div", { class: "dk-desc", text: j.description }));
      const ol = N.el("ol", { class: "dk-cron-list" });
      (j.next || []).forEach((iso) => ol.appendChild(N.el("li", { class: "mono", text: iso })));
      if (!(j.next || []).length) ol.appendChild(N.el("li", { class: "muted", text: "no fire times within the search horizon" }));
      frag.appendChild(ol);
      out.replaceChildren(frag);
    });
  }

  // ---- numbers & color ------------------------------------------------
  function doBase() {
    const out = $("dk-base-out");
    run(out, "/api/devkit/base", { value: val("dk-base-value"), from_base: val("dk-base-from"), to_base: val("dk-base-to") },
      (j) => out.replaceChildren(kvList([
        { key: "result", val: j.result, copy: true }, { key: "decimal", val: j.decimal, copy: true },
      ])));
  }
  function doColor() {
    const out = $("dk-color-out");
    run(out, "/api/devkit/color", { value: val("dk-color-value") }, (j) => {
      const sw = N.el("span", { class: "dk-swatch" });
      // j.hex is server-validated (#rrggbb[aa]); setting it via el.style is
      // allowed under the CSP (only inline style="" attributes are blocked).
      sw.style.backgroundColor = j.hex;
      const head = N.el("div", { class: "dk-color-head" }, [sw, N.el("span", { class: "faint", text: "preview" })]);
      const pairs = [
        { key: "hex", val: j.hex, copy: true }, { key: "rgb", val: j.rgb, copy: true }, { key: "hsl", val: j.hsl, copy: true },
      ];
      if (j.alpha != null) pairs.push({ key: "alpha", val: j.alpha });
      const frag = document.createDocumentFragment();
      frag.appendChild(head);
      frag.appendChild(kvList(pairs));
      out.replaceChildren(frag);
    });
  }
  function doBytesHuman() {
    const out = $("dk-bytes-out");
    run(out, "/api/devkit/bytes", { op: "humanize", n: val("dk-bytes-n"), binary: true },
      (j) => out.replaceChildren(kvList([{ key: "human", val: j.result, copy: true }])));
  }
  function doBytesParse() {
    const out = $("dk-bytes-out");
    run(out, "/api/devkit/bytes", { op: "parse", text: val("dk-bytes-text") },
      (j) => out.replaceChildren(kvList([
        { key: "bytes", val: j.bytes, copy: true }, { key: "human", val: j.human },
      ])));
  }

  // ---- text -----------------------------------------------------------
  function doText() {
    const out = $("dk-text-out");
    run(out, "/api/devkit/text", {
      text: val("dk-text-input"), op: val("dk-text-op"),
      reverse: checked("dk-text-reverse"), unique: checked("dk-text-unique"),
      numeric: checked("dk-text-numeric"), casefold: checked("dk-text-casefold"),
    }, (j) => {
      if (j.counts) {
        const c = j.counts;
        out.replaceChildren(kvList([
          { key: "characters", val: c.chars }, { key: "chars (no spaces)", val: c.chars_no_spaces },
          { key: "words", val: c.words }, { key: "lines", val: c.lines }, { key: "bytes", val: c.bytes },
        ]));
      } else {
        out.replaceChildren(N.el("div", { class: "dk-out-row" }, [outPre(j.result), copyBtn(() => j.result)]));
      }
    });
  }

  // ---- diff -----------------------------------------------------------
  function doDiff() {
    const out = $("dk-diff-out");
    run(out, "/api/devkit/diff", { a: val("dk-diff-a"), b: val("dk-diff-b"), mode: val("dk-diff-mode") }, (j) => {
      const frag = document.createDocumentFragment();
      const summary = j.changed
        ? "+" + j.added + " / -" + j.removed
        : "no differences";
      frag.appendChild(N.el("div", { class: "dk-desc" + (j.changed ? "" : " ok"), text: summary }));
      if (j.diff) frag.appendChild(N.el("pre", { class: "dk-out dk-diff", text: j.diff }));
      out.replaceChildren(frag);
    });
  }

  // ---- regex ----------------------------------------------------------
  function doRegex() {
    const out = $("dk-regex-out");
    run(out, "/api/devkit/regex", { pattern: val("dk-regex-pattern"), flags: val("dk-regex-flags"), text: val("dk-regex-text") }, (j) => {
      const frag = document.createDocumentFragment();
      const n = j.count || 0;
      frag.appendChild(N.el("div", { class: "dk-desc" + (n ? " ok" : ""), text: n + (n === 1 ? " match" : " matches") + (j.capped ? " (capped at 1000)" : "") }));
      (j.matches || []).forEach((m, i) => {
        const row = N.el("div", { class: "dk-match" });
        row.appendChild(N.el("div", { class: "dk-match-head" }, [
          N.el("span", { class: "faint", text: "#" + (i + 1) + "  [" + m.start + "–" + m.end + "]" }),
          N.el("code", { class: "dk-code", text: m.match }),
        ]));
        if (m.groups && m.groups.length) {
          row.appendChild(N.el("div", { class: "faint small", text: "groups: " + m.groups.map((g) => g == null ? "∅" : g).join(" · ") }));
        }
        const named = m.named && Object.keys(m.named).length
          ? Object.keys(m.named).map((k) => k + "=" + m.named[k]).join(" · ") : "";
        if (named) row.appendChild(N.el("div", { class: "faint small", text: "named: " + named }));
        frag.appendChild(row);
      });
      out.replaceChildren(frag);
    });
  }

  // ---- CIDR -----------------------------------------------------------
  function doCidr() {
    const out = $("dk-cidr-out");
    const ip = val("dk-cidr-ip").trim();
    run(out, "/api/devkit/cidr", { cidr: val("dk-cidr-value"), ip: ip || undefined }, (j) => {
      if ("contains" in j) {
        out.replaceChildren(N.el("div", { class: "dk-verdict " + (j.contains ? "ok" : "bad"),
          text: (j.contains ? "✓ " : "✗ ") + j.ip + (j.contains ? " is in " : " is NOT in ") + j.cidr }));
        return;
      }
      out.replaceChildren(kvList([
        { key: "network", val: j.network, copy: true },
        { key: "broadcast", val: j.broadcast, copy: true },
        { key: "netmask", val: j.netmask }, { key: "hostmask", val: j.hostmask },
        { key: "prefix", val: "/" + j.prefixlen },
        { key: "addresses", val: j.num_addresses }, { key: "usable hosts", val: j.num_usable_hosts },
        { key: "first host", val: j.first_host, copy: true }, { key: "last host", val: j.last_host, copy: true },
        { key: "private", val: String(j.is_private) }, { key: "version", val: "IPv" + j.version },
      ]));
    });
  }

  // ---- wiring ---------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    $("dk-hash-run").addEventListener("click", doHash);

    $("dk-enc-encode").addEventListener("click", () => doEnc("encode"));
    $("dk-enc-decode").addEventListener("click", () => doEnc("decode"));

    $("dk-jwt-run").addEventListener("click", doJwt);

    $("dk-json-pretty").addEventListener("click", () => doJson("pretty"));
    $("dk-json-minify").addEventListener("click", () => doJson("minify"));
    $("dk-json-validate").addEventListener("click", () => doJson("validate"));

    $("dk-uuid-run").addEventListener("click", doUuid);
    $("dk-pw-run").addEventListener("click", doPassword);
    $("dk-rand-run").addEventListener("click", doRandom);
    $("dk-secret-run").addEventListener("click", doSecret);

    $("dk-now-run").addEventListener("click", doNow);
    $("dk-u2i-run").addEventListener("click", doU2i);
    $("dk-i2u-run").addEventListener("click", doI2u);
    $("dk-tz-run").addEventListener("click", doTz);
    $("dk-dur-run").addEventListener("click", doDur);

    $("dk-cron-run").addEventListener("click", doCron);

    $("dk-base-run").addEventListener("click", doBase);
    $("dk-color-run").addEventListener("click", doColor);
    $("dk-bytes-h-run").addEventListener("click", doBytesHuman);
    $("dk-bytes-p-run").addEventListener("click", doBytesParse);

    $("dk-text-run").addEventListener("click", doText);
    $("dk-diff-run").addEventListener("click", doDiff);

    $("dk-regex-run").addEventListener("click", doRegex);
    $("dk-cidr-run").addEventListener("click", doCidr);

    // Enter-to-run on the single-line inputs where it reads naturally.
    onEnter($("dk-u2i"), doU2i);
    onEnter($("dk-i2u"), doI2u);
    onEnter($("dk-tz-to"), doTz);
    onEnter($("dk-dur"), doDur);
    onEnter($("dk-cron-expr"), doCron);
    onEnter($("dk-base-value"), doBase);
    onEnter($("dk-color-value"), doColor);
    onEnter($("dk-bytes-n"), doBytesHuman);
    onEnter($("dk-bytes-text"), doBytesParse);
    onEnter($("dk-regex-pattern"), doRegex);
    onEnter($("dk-cidr-value"), doCidr);
    onEnter($("dk-cidr-ip"), doCidr);
  });
})();
