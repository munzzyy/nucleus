(function () {
  "use strict";
  const N = window.Nucleus;

  // XSS posture for this whole file: every value we render is either something
  // the user typed or something a pure transform derived from it (a hashed
  // string, a decoded JWT payload, a regex match). None of it is trusted, so
  // nothing here touches innerHTML — we build DOM with N.el and set text via
  // textContent only. See scrub in bastion/app.js for the same discipline.

  const $ = (id) => document.getElementById(id);

  // Errors render as the shared RED state card (role=alert), not a muted grey
  // line — a failure should LOOK like a failure everywhere in the app.
  function errLine(msg) {
    return N.stateCard("error", String(msg || "request failed"));
  }

  function outPre(text) {
    return N.el("pre", { class: "dk-out", text: String(text == null ? "" : text) });
  }

  // Per-value "copy" button, now routed through the shared kit (clipboard with
  // a legacy fallback + a screen-reader announce). Keeps the .dk-copy styling.
  function copyBtn(getText) {
    return N.copyButton(getText, { cls: "ghost dk-copy", label: "copy" });
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

  // Flatten a set of key/value pairs to a plain-text block — the "copy all" /
  // download form of a kv result.
  function pairsToText(pairs) {
    return pairs.filter((p) => p.val != null && p.val !== "")
      .map((p) => p.key + ": " + p.val).join("\n");
  }

  // Column of single-value chips (uuids, passwords, secrets), each with its own
  // copy button.
  function listContent(items) {
    const wrap = N.el("div", { class: "dk-list" });
    items.forEach((s) => {
      wrap.appendChild(N.el("div", { class: "dk-out-row" }, [
        N.el("code", { class: "dk-code", text: String(s) }), copyBtn(() => String(s)),
      ]));
    });
    return wrap;
  }

  // Render a result: the content, then the shared affordance bar underneath it
  // (Copy / Copy JSON / Download / Download JSON — whatever `bar` asks for).
  function paintResult(out, content, bar) {
    out.replaceChildren(content);
    if (bar) out.appendChild(N.resultBar(bar));
  }

  function waiting(el) {
    el.replaceChildren(N.el("div", { class: "dk-wait muted" }, [
      N.el("span", { class: "spinner" }), "working…",
    ]));
  }

  // Run a POST, render via `render`, or an inline error. Never throws. Every run
  // also snapshots the current inputs (so they come back next visit) and stamps
  // the URL hash with this tool, so a run is deep-linkable / reload-stable.
  async function run(outEl, path, body, render) {
    snapshotInputs();
    reflectHash(outEl);
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

  // ---- remembered inputs ----------------------------------------------
  // Persist every tool's inputs so the console reopens where you left it. One
  // snapshot object keyed by element id (each tool's ids are unique, so this is
  // effectively per-tool). The JWT secret is deliberately excluded — a secret
  // shouldn't linger in localStorage.
  const NO_REMEMBER = { "dk-jwt-secret": true };

  function inputsStore() { return N.remember("inputs"); }

  function eachInput(fn) {
    N.$$("input, textarea, select", document).forEach((el) => {
      if (!el.id || el.type === "file" || NO_REMEMBER[el.id]) return;
      fn(el);
    });
  }

  function snapshotInputs() {
    const store = {};
    eachInput((el) => { store[el.id] = el.type === "checkbox" ? !!el.checked : el.value; });
    inputsStore().set(store);
  }

  function restoreInputs() {
    const store = inputsStore().get(null);
    if (!store || typeof store !== "object") return;
    eachInput((el) => {
      if (!(el.id in store)) return;
      if (el.type === "checkbox") el.checked = !!store[el.id];
      else el.value = store[el.id];
    });
  }

  let snapT = null;
  function scheduleSnapshot() { clearTimeout(snapT); snapT = setTimeout(snapshotInputs, 400); }

  // ---- deep-linkable tools (#tool=cidr) -------------------------------
  // Each tool maps to a section anchor to scroll to and the input to focus. On
  // load (and on a manual hash change) we jump to + focus the named tool; every
  // run rewrites the hash (via replaceState, so it doesn't spam history or
  // re-fire the hashchange handler).
  const TOOL_ANCHOR = {
    hashing: { at: "tool-hashing", focus: "dk-input" },
    encode: { at: "tool-encode", focus: "dk-enc-input" },
    jwt: { at: "tool-jwt", focus: "dk-jwt-input" },
    json: { at: "tool-json", focus: "dk-json-input" },
    generators: { at: "tool-generators", focus: "dk-uuid-count" },
    time: { at: "tool-time", focus: "dk-u2i" },
    cron: { at: "tool-cron", focus: "dk-cron-expr" },
    numbers: { at: "tool-numbers", focus: "dk-base-value" },
    text: { at: "tool-text", focus: "dk-text-input" },
    regex: { at: "tool-regex", focus: "dk-regex-pattern" },
    cidr: { at: "tool-cidr", focus: "dk-cidr-value" },
  };

  // Which tool an output element belongs to, so run() can stamp the hash.
  const OUT_TO_TOOL = {
    "dk-hash-out": "hashing", "dk-hashfile-out": "hashing",
    "dk-hmac-out": "hashing", "dk-cksum-out": "hashing",
    "dk-enc-out": "encode", "dk-jwt-out": "jwt", "dk-json-out": "json",
    "dk-uuid-out": "generators", "dk-pw-out": "generators",
    "dk-rand-out": "generators", "dk-secret-out": "generators",
    "dk-now-out": "time", "dk-time-out": "time", "dk-tz-out": "time", "dk-dur-out": "time",
    "dk-cron-out": "cron",
    "dk-base-out": "numbers", "dk-color-out": "numbers", "dk-bytes-out": "numbers",
    "dk-text-out": "text", "dk-diff-out": "text",
    "dk-regex-out": "regex", "dk-cidr-out": "cidr",
  };

  function reflectHash(outEl) {
    const slug = outEl && OUT_TO_TOOL[outEl.id];
    if (!slug) return;
    try { history.replaceState(null, "", "#tool=" + slug); } catch (_) { /* not fatal */ }
  }

  function openFromHash() {
    const m = /(?:^|[#&])tool=([a-z0-9]+)/i.exec(location.hash || "");
    if (!m) return;
    const t = TOOL_ANCHOR[m[1].toLowerCase()];
    if (!t) return;
    const at = $(t.at);
    if (at && at.scrollIntoView) at.scrollIntoView({ behavior: "smooth", block: "start" });
    const f = $(t.focus);
    if (f && f.focus) setTimeout(() => { try { f.focus(); } catch (_) { /* gone */ } }, 80);
  }

  // ---- hashing --------------------------------------------------------
  function doHash() {
    const out = $("dk-hash-out");
    run(out, "/api/devkit/hash", { text: val("dk-input") }, (j) => {
      const pairs = Object.keys(j).filter((k) => k !== "ok")
        .map((k) => ({ key: k, val: j[k], copy: true }));
      const hashes = {};
      pairs.forEach((p) => { hashes[p.key] = p.val; });
      paintResult(out, kvList(pairs),
        { getText: () => pairsToText(pairs), json: () => hashes, filename: "devkit-hashes" });
    });
  }

  // ---- hash a file (in-memory upload) ---------------------------------
  function humanBytes(n) {
    n = Number(n) || 0;
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    if (i === 0) return n + " B";
    return v.toFixed(2).replace(/\.?0+$/, "") + " " + u[i] + " (" + n + " bytes)";
  }

  async function hashFile(file) {
    if (!file) return;
    const out = $("dk-hashfile-out");
    reflectHash(out);
    waiting(out);
    try {
      const buf = await file.arrayBuffer();
      // Raw bytes as the body; the filename rides in X-Filename (percent-encoded
      // UTF-8, decoded server-side). Same-origin POST, so the browser attaches
      // the Origin header the CSRF guard needs, and no CORS preflight applies.
      const r = await fetch("/api/devkit/hashfile", {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Filename": encodeURIComponent(file.name || "file"),
          "Accept": "application/json",
        },
        body: buf,
      });
      const t = await r.text();
      let j; try { j = t ? JSON.parse(t) : {}; } catch (_) { j = {}; }
      if (!r.ok) throw new Error((j && j.error) || r.statusText || "hash failed");
      const hashes = j.hashes || {};
      const pairs = Object.keys(hashes).map((k) => ({ key: k, val: hashes[k], copy: true }));
      const frag = document.createDocumentFragment();
      frag.appendChild(kvList([
        { key: "file", val: j.filename || file.name || "" },
        { key: "size", val: humanBytes(j.size) },
      ]));
      frag.appendChild(kvList(pairs));
      paintResult(out, frag,
        { getText: () => pairsToText(pairs), json: () => j, filename: "devkit-filehash" });
    } catch (e) {
      out.replaceChildren(errLine(e && e.message ? e.message : "hash failed"));
    }
  }

  // ---- HMAC + checksums -----------------------------------------------
  function doHmac() {
    const out = $("dk-hmac-out");
    run(out, "/api/devkit/hmac", { text: val("dk-hmac-text"), key: val("dk-hmac-key"), algo: val("dk-hmac-algo") }, (j) => {
      const pairs = [{ key: "algo", val: j.algo }, { key: "hmac", val: j.hmac, copy: true }];
      paintResult(out, kvList(pairs),
        { getText: () => j.hmac, json: () => j, filename: "devkit-hmac" });
    });
  }

  function doChecksums() {
    const out = $("dk-cksum-out");
    run(out, "/api/devkit/checksums", { text: val("dk-cksum-text") }, (j) => {
      const pairs = [
        { key: "crc32", val: j.crc32, copy: true }, { key: "crc32 (int)", val: j.crc32_int, copy: true },
        { key: "adler32", val: j.adler32, copy: true }, { key: "adler32 (int)", val: j.adler32_int, copy: true },
      ];
      paintResult(out, kvList(pairs),
        { getText: () => pairsToText(pairs), json: () => j, filename: "devkit-checksums" });
    });
  }

  // ---- encode / decode ------------------------------------------------
  function doEnc(dir) {
    const out = $("dk-enc-out");
    run(out, "/api/devkit/" + dir, { text: val("dk-enc-input"), scheme: val("dk-enc-scheme") }, (j) => {
      const block = outPre(j.result);
      const row = N.el("div", { class: "dk-out-row" }, [block, copyBtn(() => j.result)]);
      paintResult(out, row, { getText: () => j.result, filename: "devkit-" + dir });
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

      const decoded = {
        header: j.header, payload: j.payload, alg: j.alg, typ: j.typ,
        expired: j.expired, verified: j.verified, warnings: j.warnings,
      };
      paintResult(out, frag, {
        getText: () => JSON.stringify({ header: j.header, payload: j.payload }, null, 2),
        json: () => decoded, filename: "devkit-jwt",
      });
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
      paintResult(out, frag,
        { getText: () => j.result, filename: "devkit-json", mime: "application/json" });
    });
  }

  // ---- generators -----------------------------------------------------
  function doUuid() {
    const out = $("dk-uuid-out");
    run(out, "/api/devkit/gen", {
      kind: "uuid", version: val("dk-uuid-version"), count: val("dk-uuid-count"),
      namespace: val("dk-uuid-ns"), name: val("dk-uuid-name"),
    }, (j) => {
      const items = j.uuids || [];
      paintResult(out, listContent(items),
        { getText: () => items.join("\n"), json: () => j, filename: "devkit-uuid" });
    });
  }
  function doPassword() {
    const out = $("dk-pw-out");
    run(out, "/api/devkit/gen", {
      kind: "password", length: val("dk-pw-length"), count: val("dk-pw-count"),
      upper: checked("dk-pw-upper"), lower: checked("dk-pw-lower"),
      digits: checked("dk-pw-digits"), symbols: checked("dk-pw-symbols"),
    }, (j) => {
      const items = j.passwords || [];
      paintResult(out, listContent(items),
        { getText: () => items.join("\n"), json: () => j, filename: "devkit-passwords" });
    });
  }
  function doRandom() {
    const out = $("dk-rand-out");
    run(out, "/api/devkit/gen", { kind: "random", nbytes: val("dk-rand-nbytes"), encoding: val("dk-rand-enc") },
      (j) => paintResult(out, listContent([j.result]),
        { getText: () => j.result, json: () => j, filename: "devkit-random" }));
  }
  function doSecret() {
    const out = $("dk-secret-out");
    run(out, "/api/devkit/gen", { kind: "secret", nbytes: val("dk-secret-nbytes") },
      (j) => paintResult(out, listContent([j.result]),
        { getText: () => j.result, json: () => j, filename: "devkit-secret" }));
  }

  // ---- time -----------------------------------------------------------
  function kvResult(out, pairs, j, filename) {
    paintResult(out, kvList(pairs),
      { getText: () => pairsToText(pairs), json: () => j, filename: filename });
  }

  function doNow() {
    const out = $("dk-now-out");
    run(out, "/api/devkit/time", { op: "now" }, (j) => kvResult(out, [
      { key: "unix", val: j.unix, copy: true }, { key: "unix (ms)", val: j.unix_ms, copy: true },
      { key: "ISO UTC", val: j.iso_utc, copy: true }, { key: "ISO local", val: j.iso_local, copy: true },
    ], j, "devkit-now"));
  }
  function doU2i() {
    const out = $("dk-time-out");
    run(out, "/api/devkit/time", { op: "unix_to_iso", ts: val("dk-u2i") }, (j) => kvResult(out, [
      { key: "ISO UTC", val: j.iso_utc, copy: true }, { key: "ISO local", val: j.iso_local, copy: true },
    ], j, "devkit-time"));
  }
  function doI2u() {
    const out = $("dk-time-out");
    run(out, "/api/devkit/time", { op: "iso_to_unix", iso: val("dk-i2u") }, (j) => kvResult(out, [
      { key: "unix", val: j.unix, copy: true }, { key: "ISO UTC", val: j.iso_utc, copy: true },
    ], j, "devkit-time"));
  }
  function doTz() {
    const out = $("dk-tz-out");
    run(out, "/api/devkit/time", { op: "tz_convert", iso: val("dk-tz-iso"), from_tz: val("dk-tz-from"), to_tz: val("dk-tz-to") },
      (j) => kvResult(out, [
        { key: "source", val: j.source }, { key: "result", val: j.result, copy: true },
      ], j, "devkit-tz"));
  }
  function doDur() {
    const out = $("dk-dur-out");
    run(out, "/api/devkit/time", { op: "humanize_duration", seconds: val("dk-dur") },
      (j) => kvResult(out, [{ key: "duration", val: j.result, copy: true }], j, "devkit-duration"));
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
      const text = () => (j.description ? j.description + "\n" : "") + (j.next || []).join("\n");
      paintResult(out, frag, { getText: text, json: () => j, filename: "devkit-cron" });
    });
  }

  // ---- numbers & color ------------------------------------------------
  function doBase() {
    const out = $("dk-base-out");
    run(out, "/api/devkit/base", { value: val("dk-base-value"), from_base: val("dk-base-from"), to_base: val("dk-base-to") },
      (j) => kvResult(out, [
        { key: "result", val: j.result, copy: true }, { key: "decimal", val: j.decimal, copy: true },
      ], j, "devkit-base"));
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
      paintResult(out, frag,
        { getText: () => pairsToText(pairs), json: () => j, filename: "devkit-color" });
    });
  }
  function doBytesHuman() {
    const out = $("dk-bytes-out");
    run(out, "/api/devkit/bytes", { op: "humanize", n: val("dk-bytes-n"), binary: true },
      (j) => kvResult(out, [{ key: "human", val: j.result, copy: true }], j, "devkit-bytes"));
  }
  function doBytesParse() {
    const out = $("dk-bytes-out");
    run(out, "/api/devkit/bytes", { op: "parse", text: val("dk-bytes-text") },
      (j) => kvResult(out, [
        { key: "bytes", val: j.bytes, copy: true }, { key: "human", val: j.human },
      ], j, "devkit-bytes"));
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
        const pairs = [
          { key: "characters", val: c.chars }, { key: "chars (no spaces)", val: c.chars_no_spaces },
          { key: "words", val: c.words }, { key: "lines", val: c.lines }, { key: "bytes", val: c.bytes },
        ];
        kvResult(out, pairs, j, "devkit-count");
      } else {
        paintResult(out, N.el("div", { class: "dk-out-row" }, [outPre(j.result), copyBtn(() => j.result)]),
          { getText: () => j.result, filename: "devkit-text" });
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
      const bar = j.diff
        ? { getText: () => j.diff, json: () => j, filename: "devkit-diff" }
        : null;
      paintResult(out, frag, bar);
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
      const text = () => (j.matches || [])
        .map((m, i) => "#" + (i + 1) + " [" + m.start + "-" + m.end + "] " + m.match).join("\n");
      const bar = n ? { getText: text, json: () => j, filename: "devkit-regex" } : null;
      paintResult(out, frag, bar);
    });
  }

  // ---- CIDR -----------------------------------------------------------
  function doCidr() {
    const out = $("dk-cidr-out");
    const ip = val("dk-cidr-ip").trim();
    run(out, "/api/devkit/cidr", { cidr: val("dk-cidr-value"), ip: ip || undefined }, (j) => {
      if ("contains" in j) {
        const verdict = (j.contains ? "✓ " : "✗ ") + j.ip + (j.contains ? " is in " : " is NOT in ") + j.cidr;
        paintResult(out, N.el("div", { class: "dk-verdict " + (j.contains ? "ok" : "bad"), text: verdict }),
          { getText: () => verdict, json: () => j, filename: "devkit-cidr" });
        return;
      }
      kvResult(out, [
        { key: "network", val: j.network, copy: true },
        { key: "broadcast", val: j.broadcast, copy: true },
        { key: "netmask", val: j.netmask }, { key: "hostmask", val: j.hostmask },
        { key: "prefix", val: "/" + j.prefixlen },
        { key: "addresses", val: j.num_addresses }, { key: "usable hosts", val: j.num_usable_hosts },
        { key: "first host", val: j.first_host, copy: true }, { key: "last host", val: j.last_host, copy: true },
        { key: "private", val: String(j.is_private) }, { key: "version", val: "IPv" + j.version },
      ], j, "devkit-cidr");
    });
  }

  // ---- UUID namespace fields (v3/v5 only) -----------------------------
  function toggleUuidNs() {
    const v = String(val("dk-uuid-version"));
    const nsMode = (v === "5" || v === "3");
    const row = $("dk-uuid-ns-fields");
    if (row) row.classList.toggle("dk-hide", !nsMode);
  }

  // ---- file drop/pick wiring ------------------------------------------
  function wireFileHash() {
    const drop = $("dk-file-drop");
    const input = $("dk-file-input");
    if (!drop || !input) return;
    drop.addEventListener("click", () => input.click());
    drop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    input.addEventListener("change", () => {
      if (input.files && input.files[0]) hashFile(input.files[0]);
    });
    ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation(); drop.classList.add("drag");
    }));
    ["dragleave", "dragend"].forEach((ev) => drop.addEventListener(ev, (e) => {
      e.preventDefault(); e.stopPropagation(); drop.classList.remove("drag");
    }));
    drop.addEventListener("drop", (e) => {
      e.preventDefault(); e.stopPropagation();
      drop.classList.remove("drag");
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) hashFile(f);
    });
  }

  // ---- wiring ---------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    $("dk-hash-run").addEventListener("click", doHash);
    $("dk-hmac-run").addEventListener("click", doHmac);
    $("dk-cksum-run").addEventListener("click", doChecksums);
    wireFileHash();

    $("dk-enc-encode").addEventListener("click", () => doEnc("encode"));
    $("dk-enc-decode").addEventListener("click", () => doEnc("decode"));

    $("dk-jwt-run").addEventListener("click", doJwt);

    $("dk-json-pretty").addEventListener("click", () => doJson("pretty"));
    $("dk-json-minify").addEventListener("click", () => doJson("minify"));
    $("dk-json-validate").addEventListener("click", () => doJson("validate"));

    $("dk-uuid-run").addEventListener("click", doUuid);
    $("dk-uuid-version").addEventListener("change", toggleUuidNs);
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
    onEnter($("dk-hmac-key"), doHmac);
    onEnter($("dk-uuid-name"), doUuid);
    onEnter($("dk-uuid-ns"), doUuid);
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

    // Restore remembered inputs, then react to the deep-link. Order matters:
    // toggleUuidNs after restore so a remembered v5 shows its namespace fields.
    restoreInputs();
    toggleUuidNs();
    document.addEventListener("input", scheduleSnapshot);
    document.addEventListener("change", scheduleSnapshot);
    window.addEventListener("hashchange", openFromHash);
    openFromHash();
  });
})();
