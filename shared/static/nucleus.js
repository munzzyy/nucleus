/* Nucleus shared shell — topbar switcher, health poller, and small helpers.
   Loaded by the hub and every console. No external deps. */
(function () {
  "use strict";

  const N = (window.Nucleus = window.Nucleus || {});

  // --- tiny DOM helper -----------------------------------------------------
  N.el = function (tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") e.className = attrs[k];
      else if (k === "html") e.innerHTML = attrs[k];
      else if (k === "text") e.textContent = attrs[k];
      else if (k.startsWith("on") && typeof attrs[k] === "function") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(c => e.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return e;
  };
  N.$ = (sel, root) => (root || document).querySelector(sel);
  N.$$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  // --- fetch wrappers ------------------------------------------------------
  N.get = async function (path) {
    const r = await fetch(path, { headers: { "Accept": "application/json" } });
    const t = await r.text();
    let j; try { j = t ? JSON.parse(t) : {}; } catch (_) { j = { raw: t }; }
    if (!r.ok) throw Object.assign(new Error(j.error || r.statusText), { status: r.status, body: j });
    return j;
  };
  N.post = async function (path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const t = await r.text();
    let j; try { j = t ? JSON.parse(t) : {}; } catch (_) { j = { raw: t }; }
    if (!r.ok) throw Object.assign(new Error(j.error || r.statusText), { status: r.status, body: j });
    return j;
  };

  // --- screen-reader announcements -----------------------------------------
  // One shared visually-hidden live region for the whole page. Every toast
  // goes through here too, so a status message that only ever appeared as a
  // floating pill in the corner now also reaches assistive tech.
  N.announce = function (msg) {
    const text = String(msg == null ? "" : msg);
    if (!text) return;
    let r = document.getElementById("nuc-live");
    if (!r) {
      r = N.el("div", { id: "nuc-live", class: "sr-only", "aria-live": "polite", "aria-atomic": "true" });
      (document.body || document.documentElement).appendChild(r);
    }
    // Re-announce identical text: clearing first makes the region "change"
    // again, otherwise a repeated message is silently dropped by the AT.
    if (r.textContent === text) r.textContent = "";
    r.textContent = text;
  };

  // --- toast ---------------------------------------------------------------
  N.toast = function (msg, kind) {
    let t = document.getElementById("toast");
    if (!t) { t = N.el("div", { id: "toast" }); document.body.appendChild(t); }
    t.textContent = msg;
    t.className = (kind || "") + " show";
    clearTimeout(N._toastT);
    N._toastT = setTimeout(() => { t.className = t.className.replace("show", "").trim(); }, 2600);
    N.announce(msg);
  };

  // --- copy / download -----------------------------------------------------
  // navigator.clipboard only exists in a secure context. http://127.0.0.1 IS
  // one per the spec, but a console opened through some other loopback alias
  // (or an old browser) isn't, so there's a textarea + execCommand fallback:
  // copying a result is too core to this app to just fail there.
  function legacyCopy(s) {
    const prev = document.activeElement;   // the copy button, usually
    try {
      const ta = N.el("textarea", { class: "copy-fallback", "aria-hidden": "true", tabindex: "-1" });
      ta.value = s;
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      if (ta.setSelectionRange) ta.setSelectionRange(0, s.length);
      const ok = !!(document.execCommand && document.execCommand("copy"));
      ta.remove();
      return ok;
    } catch (_) {
      return false;
    } finally {
      // Selecting requires focus; a keyboard user must not lose their place
      // to a textarea that only existed for a millisecond.
      if (prev && prev.focus) { try { prev.focus(); } catch (_) { /* gone */ } }
    }
  }

  N.copy = async function (text, okMsg) {
    const s = String(text == null ? "" : text);
    let ok = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(s);
        ok = true;
      }
    } catch (_) { ok = false; }
    if (!ok) ok = legacyCopy(s);
    // N.toast announces, so the result reaches assistive tech either way.
    N.toast(ok ? (okMsg || "copied") : "copy failed — select manually", ok ? "ok" : "bad");
    return ok;
  };

  // A pre-wired copy button. `getText` may be a string or a function, and the
  // function form is re-evaluated on every click — so a button built once
  // against a panel that re-renders still copies what's on screen NOW.
  N.copyButton = function (getText, opts) {
    opts = opts || {};
    const label = opts.label || "copy";
    const btn = N.el("button", { type: "button", class: opts.cls || "ghost" });
    if (opts.title) btn.setAttribute("title", opts.title);
    const lab = N.el("span", { class: "copy-label", text: label, "aria-live": "polite" });
    btn.appendChild(lab);
    btn.addEventListener("click", async () => {
      const text = typeof getText === "function" ? getText() : getText;
      const ok = await N.copy(text, opts.okMsg);
      lab.textContent = ok ? "copied ✓" : "failed";
      clearTimeout(btn._nucT);
      btn._nucT = setTimeout(() => { lab.textContent = label; }, 1200);
    });
    return btn;
  };

  N.download = function (filename, content, mime) {
    const type = mime || "text/plain";
    const blob = (typeof Blob !== "undefined" && content instanceof Blob)
      ? content
      : new Blob([String(content == null ? "" : content)], { type: type });
    const url = URL.createObjectURL(blob);
    const name = filename || "nucleus-export.txt";
    const a = N.el("a", { href: url, download: name, class: "sr-only" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    N.announce("downloaded " + name);
  };

  N.downloadJson = function (obj, filename) {
    N.download(filename, JSON.stringify(obj, null, 2), "application/json");
  };

  const _EXT_FOR_MIME = {
    "application/json": ".json", "text/markdown": ".md", "text/csv": ".csv",
    "text/html": ".html", "application/x-sh": ".sh", "text/plain": ".txt",
  };

  function extFor(mime) {
    const base = String(mime || "text/plain").split(";")[0].trim().toLowerCase();
    return _EXT_FOR_MIME[base] || ".txt";
  }

  // Callers pass a base name. Appending unconditionally would double up on a
  // caller that already added the extension, and testing for "any extension"
  // is wrong too — a scan named after a domain ("recon-example.com") would
  // then never get one.
  function withExt(base, ext) {
    return String(base).toLowerCase().endsWith(ext) ? String(base) : base + ext;
  }

  // The standard row of affordances under a result: copy it, copy the raw
  // JSON, keep either as a file. Every console renders the same four buttons
  // in the same order so the muscle memory carries across the whole app.
  N.resultBar = function (opts) {
    opts = opts || {};
    const bar = N.el("div", { class: "result-bar" });
    const val = (v) => (typeof v === "function" ? v() : v);
    const hasText = opts.getText != null;
    const hasJson = opts.json != null;
    if (hasText) {
      bar.appendChild(N.copyButton(() => String(val(opts.getText) == null ? "" : val(opts.getText)),
        { label: opts.copyLabel || "Copy", title: "Copy this result to the clipboard" }));
    }
    if (hasJson) {
      bar.appendChild(N.copyButton(() => JSON.stringify(val(opts.json), null, 2),
        { label: "Copy JSON", title: "Copy the raw JSON" }));
    }
    if (hasText && opts.filename) {
      const b = N.el("button", { class: "ghost", type: "button", text: "Download" });
      b.addEventListener("click", () => {
        const t = val(opts.getText);
        N.download(withExt(opts.filename, extFor(opts.mime)),
          String(t == null ? "" : t), opts.mime || "text/plain");
      });
      bar.appendChild(b);
    }
    if (hasJson && opts.filename) {
      const b = N.el("button", { class: "ghost", type: "button", text: "Download JSON" });
      b.addEventListener("click", () => N.downloadJson(val(opts.json), withExt(opts.filename, ".json")));
      bar.appendChild(b);
    }
    (opts.extra || []).forEach(e => { if (e) bar.appendChild(e); });
    return bar;
  };

  // --- remembered state ----------------------------------------------------
  // localStorage, namespaced per console so recon's "last target" can never
  // collide with redcell's. Every path is guarded: private-mode, a disabled
  // storage policy, or a full quota degrade to "nothing remembered", never to
  // a thrown exception in the middle of a render.
  N.remember = function (key) {
    const app = (document.body && document.body.getAttribute("data-app")) || "app";
    const full = "nuc:" + app + ":" + key;
    return {
      get(fallback) {
        try {
          const raw = window.localStorage.getItem(full);
          return raw == null ? fallback : JSON.parse(raw);
        } catch (_) { return fallback; }
      },
      set(value) {
        try { window.localStorage.setItem(full, JSON.stringify(value)); return true; }
        catch (_) { return false; }
      },
      clear() {
        try { window.localStorage.removeItem(full); } catch (_) { /* nothing to clear */ }
      },
    };
  };

  // --- standard loading / empty / error block ------------------------------
  // One shape for all three so a failure LOOKS like a failure (red, role=alert)
  // in every console instead of a grey line that reads like "no results".
  N.stateCard = function (kind, msg) {
    const k = (kind === "loading" || kind === "error") ? kind : "empty";
    const card = N.el("div", { class: "card state-" + k });
    if (k === "loading") card.appendChild(N.el("span", { class: "spinner" }));
    if (k === "error") card.setAttribute("role", "alert");
    card.appendChild(N.el("span", { class: "state-msg", text: String(msg == null ? "" : msg) ||
      (k === "loading" ? "Working…" : k === "error" ? "Something went wrong." : "Nothing to show.") }));
    return card;
  };

  // --- visibility-aware polling -------------------------------------------
  // A background tab shouldn't keep hammering loopback endpoints. Pauses on
  // hide, catches up with one immediate run when the tab comes back.
  N.pollWhileVisible = function (fn, ms) {
    let timer = null;
    let wasHidden = !!document.hidden;
    const tick = () => { try { fn(); } catch (_) { /* a bad tick must not kill the timer */ } };
    const start = () => { if (timer == null) timer = setInterval(tick, ms); };
    const stop = () => { if (timer != null) { clearInterval(timer); timer = null; } };
    const onVis = () => {
      if (document.hidden) { wasHidden = true; stop(); return; }
      start();
      if (wasHidden) { wasHidden = false; tick(); }
    };
    document.addEventListener("visibilitychange", onVis);
    window.addEventListener("focus", onVis);
    if (!document.hidden) start();
    return {
      start: start, stop: stop, tick: tick,
      dispose() {
        stop();
        document.removeEventListener("visibilitychange", onVis);
        window.removeEventListener("focus", onVis);
      },
    };
  };

  N.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  };

  // Defense-in-depth for every href built from server/remote data (scan
  // results, pivot links, etc). Every such value is a fixed https template
  // server-side today — this just makes it impossible to regress into a
  // javascript:/data: URI later. Always pair with N.esc() on the attribute.
  N.safeUrl = function (url) {
    const s = String(url == null ? "" : url).trim();
    return /^(https?:|mailto:)/i.test(s) ? s : "#";
  };

  // --- topbar + switcher ---------------------------------------------------
  // Each page sets <body data-app="recon">. We render the switcher and poll
  // /api/siblings (server-side health, so no cross-origin calls) to light dots.
  N.mountShell = function (opts) {
    opts = opts || {};
    const self = document.body.getAttribute("data-app") || "hub";
    const bar = N.el("div", { class: "topbar" });
    const brand = N.el("div", { class: "brand" }, []);
    brand.appendChild(N.el("span", { class: "logo" }));
    const bt = N.el("div", {}, []);
    bt.appendChild(N.el("div", { text: "NUCLEUS" }));
    bt.appendChild(N.el("small", { text: opts.subtitle || "security command center" }));
    brand.appendChild(bt);
    const brandLink = N.el("a", { href: portUrl(8890) + "/", class: "brand-link" }, [brand]);
    bar.appendChild(brandLink);

    const sw = N.el("div", { class: "switcher", id: "nuc-switcher" });
    bar.appendChild(sw);

    // Topbar + opsec bar share one sticky wrapper, stacked in normal flow
    // relative to each other, so the opsec bar never needs a hardcoded pixel
    // offset that breaks when the switcher wraps to two rows on a narrow
    // viewport — it just sits right below however tall the topbar rendered.
    const shellWrap = N.el("div", { class: "topbar-wrap" });
    shellWrap.appendChild(bar);
    const opsec = N.el("div", { class: "opsec-bar", id: "nuc-opsec" });
    shellWrap.appendChild(opsec);
    document.body.insertBefore(shellWrap, document.body.firstChild);

    renderSwitcher([], self);
    // Both pollers pause while the tab is hidden — six consoles left open in
    // background tabs otherwise keep pinging loopback (and the opsec oracles)
    // forever for a UI nobody is looking at.
    pollSiblings(self);
    N.pollWhileVisible(() => pollSiblings(self), 8000);
    pollOpsec();
    N.pollWhileVisible(pollOpsec, 15000);
    mountShortcuts();
  };

  async function pollOpsec() {
    const el = document.getElementById("nuc-opsec");
    if (!el) return;
    let o;
    try { o = await N.get("/api/opsec"); }
    catch (_) { return; }
    window.Nucleus._opsec = o;
    document.dispatchEvent(new CustomEvent("nucleus:opsec", { detail: o }));
    if (o.exposed) {
      const where = [o.org, o.city, o.country].filter(Boolean).join(" · ");
      el.className = "opsec-bar exposed";
      el.innerHTML =
        '<span class="od"></span><b>EXPOSED</b> — your real IP ' +
        '<span class="mono">' + N.esc(o.public_ip || "?") + '</span>' +
        (where ? ' (' + N.esc(where) + ')' : '') +
        ' is what any target sees. Turn on your VPN (Mullvad) before scanning.';
    } else {
      el.className = "opsec-bar safe";
      el.innerHTML = '<span class="od"></span>Protected — ' + N.esc(o.reason || "VPN active") +
        (o.public_ip ? ' · exit <span class="mono">' + N.esc(o.public_ip) + '</span>' : '');
    }
  }

  function portUrl(port) { return location.protocol + "//" + location.hostname + ":" + port; }

  // Fixed console order, known client-side so the switcher draws before health
  // arrives and the command palette can offer "Go to X" without a round-trip.
  const SWITCHER_BASE = [
    { slug: "hub", name: "Hub", port: 8890 },
    { slug: "recon", name: "Recon", port: 8900 },
    { slug: "redcell", name: "Redcell", port: 8910 },
    { slug: "bastion", name: "Bastion", port: 8920 },
    { slug: "devkit", name: "Devkit", port: 8930 },
    { slug: "systems", name: "Systems", port: 8940 },
  ];

  function renderSwitcher(list, self) {
    const sw = document.getElementById("nuc-switcher");
    if (!sw) return;
    sw.innerHTML = "";
    const base = SWITCHER_BASE;
    const health = {};
    list.forEach(c => { health[c.slug] = c.up; });
    base.forEach(c => {
      const up = health[c.slug];
      const cls = "sw " + (c.slug === self ? "active " : "") + (up === true ? "up" : up === false ? "down" : "");
      const a = N.el("a", { class: cls.trim(), href: portUrl(c.port) + "/", title: c.name + " · :" + c.port });
      a.appendChild(N.el("span", { class: "dot" }));
      a.appendChild(document.createTextNode(c.name));
      sw.appendChild(a);
    });
  }

  async function pollSiblings(self) {
    try {
      const j = await N.get("/api/siblings");
      renderSwitcher(j.consoles || [], self);
      N._siblings = j.consoles || [];
      document.dispatchEvent(new CustomEvent("nucleus:siblings", { detail: j.consoles || [] }));
    } catch (_) { /* stay quiet; dots just won't light */ }
  }

  // --- global keyboard shortcuts + help overlay -----------------------------
  // g then h/r/d/b/e/s (or plain 1..6) jumps consoles; Ctrl-K opens the command
  // palette; / focuses the page's primary input; ? toggles this help. Never
  // fires while a field is focused, except Escape (blurs it) and Ctrl-K (the
  // palette works from anywhere) — matching every console's own keydown
  // handlers (Enter-to-run etc), which still work normally since we bail out
  // before touching typed keys.
  const SHORTCUT_PORTS = { h: 8890, r: 8900, d: 8910, b: 8920, e: 8930, s: 8940,
    "1": 8890, "2": 8900, "3": 8910, "4": 8920, "5": 8930, "6": 8940 };
  let helpOverlayEl = null;
  let helpCloseEl = null;
  let helpPrevFocus = null;
  let helpOpen = false;
  let gPending = false;
  let gPendingTimer = null;

  function isTypingTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  function primaryInput() {
    return document.querySelector("#q, #run-target, #report-domain, #dk-input");
  }

  // --- modal focus trap ----------------------------------------------------
  // Both shared overlays are aria-modal, so Tab must not walk out of them into
  // the page behind. getClientRects() is the visibility test (offsetParent is
  // null for anything inside a position:fixed overlay, which would hide every
  // candidate).
  const FOCUS_SEL = 'a[href], button:not([disabled]), input:not([disabled]), ' +
    'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function focusables(root) {
    return N.$$(FOCUS_SEL, root).filter(el => el.getClientRects().length > 0);
  }

  function trapTab(e, root) {
    if (e.key !== "Tab") return;
    const items = focusables(root);
    if (!items.length) { e.preventDefault(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    const inside = root.contains(active);
    if (e.shiftKey) {
      if (!inside || active === first) { e.preventDefault(); last.focus(); }
    } else if (!inside || active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  // Capture phase: the palette input stops propagation on its own keydown, so
  // a bubbling listener on the overlay would never see Tab at all.
  function wireTrap(overlay) {
    overlay.addEventListener("keydown", (e) => trapTab(e, overlay), true);
  }

  // Put focus back where it was before the modal opened. If that element is
  // gone (or was just the body), blur whatever is focused inside the modal
  // instead — leaving focus parked on a now-hidden input strands the keyboard.
  function restoreFocus(el) {
    if (el && el.focus && el !== document.body && document.contains(el)) {
      try { el.focus(); return; } catch (_) { /* element went away mid-close */ }
    }
    const active = document.activeElement;
    if (active && active !== document.body && active.blur) active.blur();
  }

  function buildHelpOverlay() {
    if (helpOverlayEl) return helpOverlayEl;
    const overlay = N.el("div", { class: "shortcuts-overlay hidden", id: "nuc-shortcuts",
      role: "dialog", "aria-modal": "true", "aria-label": "Keyboard shortcuts" });
    const panel = N.el("div", { class: "shortcuts-panel" });
    panel.appendChild(N.el("h2", { text: "Keyboard shortcuts" }));
    const rows = [
      ["Ctrl-K", "command palette"],
      ["/", "focus the main input"],
      ["g h", "go to Hub"],
      ["g r", "go to Recon"],
      ["g d", "go to Redcell"],
      ["g b", "go to Bastion"],
      ["g e", "go to Devkit"],
      ["g s", "go to Systems"],
      ["1 2 3 4 5 6", "same, one key"],
      ["?", "toggle this help"],
      ["Esc", "close this / blur a field"],
    ];
    const dl = N.el("dl", { class: "shortcuts-list" });
    rows.forEach(([keys, desc]) => {
      dl.appendChild(N.el("dt", {}, [N.el("span", { class: "kbd", text: keys })]));
      dl.appendChild(N.el("dd", { text: desc }));
    });
    panel.appendChild(dl);
    const close = N.el("button", { class: "ghost mt", type: "button", text: "Close" });
    close.addEventListener("click", closeHelp);
    panel.appendChild(close);
    helpCloseEl = close;
    overlay.appendChild(panel);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) closeHelp(); });
    wireTrap(overlay);
    document.body.appendChild(overlay);
    helpOverlayEl = overlay;
    return overlay;
  }

  function openHelp() {
    buildHelpOverlay().classList.remove("hidden");
    helpOpen = true;
    helpPrevFocus = document.activeElement;
    if (helpCloseEl) helpCloseEl.focus();
  }

  function closeHelp() {
    if (helpOverlayEl) helpOverlayEl.classList.add("hidden");
    helpOpen = false;
    restoreFocus(helpPrevFocus);
    helpPrevFocus = null;
  }

  function toggleHelp() { helpOpen ? closeHelp() : openHelp(); }

  // --- command palette (Ctrl-K / Cmd-K) -------------------------------------
  // A fuzzy launcher that works on EVERY page because it rediscovers its own
  // commands from the DOM each time it opens: one "Go to X" per console, plus
  // every section title and card heading on the current page (so any tool is
  // a couple of keystrokes away). Nothing per-console has to register.
  let cmdOverlayEl = null;
  let cmdInputEl = null;
  let cmdResultsEl = null;
  let cmdOpen = false;
  let cmdCommands = [];   // everything available for this open
  let cmdFiltered = [];   // what's currently shown, post-filter
  let cmdActive = 0;      // highlighted row index into cmdFiltered
  let cmdPrevFocus = null;

  const CMD_KIND_LABEL = { go: "console", section: "section", tool: "tool", custom: "command" };
  const CMD_MRU_MAX = 6;

  // Commands a console adds by hand, for things the DOM walk can't discover —
  // "Run the last scan again", "Clear saved inputs". Optional: a console that
  // registers nothing still gets the full auto-discovered palette.
  const registered = [];
  N.registerCommand = function (cmd) {
    if (!cmd || typeof cmd.run !== "function" || !cmd.label) return null;
    const entry = { label: String(cmd.label), run: cmd.run,
      section: cmd.section ? String(cmd.section) : "" };
    // Registering the same label twice replaces the old entry rather than
    // stacking duplicates — a console that registers inside a render function
    // would otherwise grow this list forever.
    const key = (c) => c.section + "\x00" + c.label;
    const at = registered.findIndex(c => key(c) === key(entry));
    if (at >= 0) { registered[at] = entry; return entry; }
    registered.push(entry);
    return entry;
  };

  function mruStore() { return N.remember("cmd-mru"); }

  function mruList() {
    const v = mruStore().get([]);
    return Array.isArray(v) ? v.filter(x => typeof x === "string") : [];
  }

  function mruPush(label) {
    const list = mruList().filter(l => l !== label);
    list.unshift(label);
    mruStore().set(list.slice(0, CMD_MRU_MAX));
  }

  function scrollToEl(el) {
    if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function computeCommands() {
    const self = document.body.getAttribute("data-app") || "hub";
    const cmds = [];
    // (1) jump to any other console
    SWITCHER_BASE.forEach(c => {
      if (c.slug === self) return;
      cmds.push({ label: "Go to " + c.name, kind: "go",
        run: () => { location.href = portUrl(c.port) + "/"; } });
    });
    const seen = new Set();
    // (2) anything the page registered explicitly. These sit ahead of the DOM
    // walk because a console only registers a command for something the walk
    // CAN'T find — burying them under fifty auto-discovered headings would
    // make registerCommand pointless.
    registered.forEach(c => {
      const label = c.section ? c.section + " · " + c.label : c.label;
      if (seen.has(label)) return;
      seen.add(label);
      cmds.push({ label: label, kind: "custom", hint: c.section || "", run: c.run });
    });
    // (3) every section + card heading on this page, walked in document order
    // so a card heading inherits the section title it sits under. De-duped by
    // the final label.
    let section = "";
    N.$$(".section-title, .card h2, .card h3").forEach(el => {
      const text = (el.textContent || "").trim();
      if (!text) return;
      if (el.classList.contains("section-title")) {
        section = text;
        if (seen.has(text)) return;
        seen.add(text);
        cmds.push({ label: text, kind: "section", run: () => scrollToEl(el) });
      } else {
        const label = section ? section + " · " + text : text;
        if (seen.has(label)) return;
        seen.add(label);
        cmds.push({ label: label, kind: "tool", run: () => scrollToEl(el) });
      }
    });
    return cmds;
  }

  // Case-insensitive fuzzy score: a contiguous substring outranks a scattered
  // subsequence; -1 means no match at all. Empty query keeps the natural order.
  function cmdScore(label, q) {
    if (!q) return 0;
    const L = label.toLowerCase();
    const idx = L.indexOf(q);
    if (idx >= 0) return 1000 - idx;   // substring; an earlier hit ranks higher
    let li = 0;
    for (let i = 0; i < q.length; i++) {
      li = L.indexOf(q[i], li);
      if (li < 0) return -1;
      li++;
    }
    return 100;                         // scattered subsequence; below any substring
  }

  function paintActive() {
    if (!cmdResultsEl) return;
    Array.prototype.forEach.call(cmdResultsEl.children, (li, i) => {
      const on = i === cmdActive;
      li.classList.toggle("active", on);
      if (li.setAttribute) li.setAttribute("aria-selected", on ? "true" : "false");
    });
  }

  function renderCmdResults() {
    if (!cmdResultsEl || !cmdInputEl) return;
    const q = (cmdInputEl.value || "").trim().toLowerCase();
    const scored = [];
    cmdCommands.forEach((c, i) => {
      const s = cmdScore(c.label, q);
      if (s >= 0) scored.push({ c: c, s: s, i: i });
    });
    scored.sort((a, b) => (b.s - a.s) || (a.i - b.i));  // by score, then natural order
    let list = scored.map(x => x.c);
    // Empty query = "what do I usually do here", so the recently-run commands
    // float to the top in recency order. A typed query is pure relevance —
    // history should never outrank what you actually asked for.
    let recent = [];
    if (!q) {
      const mru = mruList();
      recent = mru.map(label => list.find(c => c.label === label)).filter(Boolean);
      const inRecent = new Set(recent.map(c => c.label));
      list = recent.concat(list.filter(c => !inRecent.has(c.label)));
    }
    const recentLabels = new Set(recent.map(c => c.label));
    cmdFiltered = list.slice(0, 12);
    if (cmdActive >= cmdFiltered.length) cmdActive = 0;
    cmdResultsEl.innerHTML = "";
    if (!cmdFiltered.length) {
      cmdResultsEl.appendChild(N.el("li", { class: "cmd-empty", text: "No matches" }));
      return;
    }
    cmdFiltered.forEach((c, i) => {
      const li = N.el("li", { class: "cmd-item" + (i === cmdActive ? " active" : ""),
        role: "option", "aria-selected": i === cmdActive ? "true" : "false" });
      li.appendChild(N.el("span", { text: c.label }));
      const kind = recentLabels.has(c.label) ? "recent" : (c.hint || CMD_KIND_LABEL[c.kind] || "");
      li.appendChild(N.el("span", { class: "cmd-kind", text: kind }));
      li.addEventListener("mousemove", () => { if (cmdActive !== i) { cmdActive = i; paintActive(); } });
      li.addEventListener("click", () => runCmd(i));
      cmdResultsEl.appendChild(li);
    });
  }

  function moveCmd(delta) {
    if (!cmdFiltered.length) return;
    cmdActive = (cmdActive + delta + cmdFiltered.length) % cmdFiltered.length;
    paintActive();
    const active = cmdResultsEl.children[cmdActive];
    if (active && active.scrollIntoView) active.scrollIntoView({ block: "nearest" });
  }

  function runCmd(i) {
    const c = cmdFiltered[i != null ? i : cmdActive];
    if (!c) return;
    mruPush(c.label);
    closeCommandPalette();
    c.run();
  }

  function buildCommandPalette() {
    if (cmdOverlayEl) return cmdOverlayEl;
    const overlay = N.el("div", { class: "cmd-overlay hidden", id: "nuc-cmd",
      role: "dialog", "aria-modal": "true", "aria-label": "Command palette" });
    const panel = N.el("div", { class: "cmd-panel" });
    cmdInputEl = N.el("input", { class: "cmd-input", id: "nuc-cmd-input", type: "text",
      autocomplete: "off", spellcheck: "false", "aria-label": "Command palette",
      placeholder: "Jump to a console or a tool…" });
    cmdResultsEl = N.el("ul", { class: "cmd-results", role: "listbox" });
    const hint = N.el("div", { class: "cmd-hint" },
      [N.el("span", { class: "kbd", text: "↑↓" }), " move · ",
       N.el("span", { class: "kbd", text: "↵" }), " open · ",
       N.el("span", { class: "kbd", text: "esc" }), " close"]);
    panel.appendChild(cmdInputEl);
    panel.appendChild(cmdResultsEl);
    panel.appendChild(hint);
    overlay.appendChild(panel);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) closeCommandPalette(); });
    // The palette owns its keys — stop them here so the global shortcut handler
    // never treats a search keystroke (or the closing Ctrl-K) as a jump.
    cmdInputEl.addEventListener("keydown", (e) => {
      e.stopPropagation();
      if (e.key === "Escape") { e.preventDefault(); closeCommandPalette(); return; }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); closeCommandPalette(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); moveCmd(1); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); moveCmd(-1); return; }
      if (e.key === "Enter") { e.preventDefault(); runCmd(); return; }
    });
    cmdInputEl.addEventListener("input", renderCmdResults);
    wireTrap(overlay);
    document.body.appendChild(overlay);
    cmdOverlayEl = overlay;
    return overlay;
  }

  function openCommandPalette() {
    buildCommandPalette();
    // Only capture the return-focus target on a real open — re-opening an
    // already-open palette would otherwise "restore" focus to its own input.
    if (!cmdOpen) cmdPrevFocus = document.activeElement;
    cmdCommands = computeCommands();
    cmdActive = 0;
    cmdInputEl.value = "";
    renderCmdResults();
    cmdOverlayEl.classList.remove("hidden");
    cmdOpen = true;
    cmdInputEl.focus();
  }

  function closeCommandPalette() {
    if (cmdOverlayEl) cmdOverlayEl.classList.add("hidden");
    cmdOpen = false;
    if (cmdPrevFocus && cmdPrevFocus.focus) { try { cmdPrevFocus.focus(); } catch (_) { /* gone */ } }
    cmdPrevFocus = null;
  }

  function toggleCommandPalette() { cmdOpen ? closeCommandPalette() : openCommandPalette(); }

  N.openCommandPalette = openCommandPalette;
  N.closeCommandPalette = closeCommandPalette;

  function mountShortcuts() {
    if (N._shortcutsWired) return;
    N._shortcutsWired = true;
    document.addEventListener("keydown", (e) => {
      // Command palette wins first: it must fire even while a field is focused
      // and even though it's a modifier combo, so it goes AHEAD of the modifier
      // early-return below. (While the palette itself is open, focus is on its
      // input, whose own keydown stops propagation and handles the toggle.)
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        toggleCommandPalette();
        return;
      }
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const typing = isTypingTarget(document.activeElement);

      if (e.key === "Escape") {
        if (cmdOpen) { closeCommandPalette(); return; }
        if (helpOpen) { closeHelp(); return; }
        if (typing && document.activeElement.blur) document.activeElement.blur();
        return;
      }
      if (typing) return; // never hijack keys while the user is typing

      if (e.key === "?") { e.preventDefault(); toggleHelp(); return; }

      if (gPending) {
        gPending = false;
        clearTimeout(gPendingTimer);
        const port = SHORTCUT_PORTS[e.key.toLowerCase()];
        if (port) { e.preventDefault(); location.href = portUrl(port) + "/"; }
        return;
      }
      if (e.key === "g") {
        gPending = true;
        clearTimeout(gPendingTimer);
        gPendingTimer = setTimeout(() => { gPending = false; }, 1200);
        return;
      }
      if (/^[1-6]$/.test(e.key)) {
        e.preventDefault();
        location.href = portUrl(SHORTCUT_PORTS[e.key]) + "/";
        return;
      }
      if (e.key === "/") {
        const el = primaryInput();
        if (el) { e.preventDefault(); el.focus(); }
        return;
      }
    });
  }

  // Auto-mount if the page opted in.
  document.addEventListener("DOMContentLoaded", function () {
    if (document.body && document.body.hasAttribute("data-auto-shell")) N.mountShell();
  });
})();
