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

  // --- toast ---------------------------------------------------------------
  N.toast = function (msg, kind) {
    let t = document.getElementById("toast");
    if (!t) { t = N.el("div", { id: "toast" }); document.body.appendChild(t); }
    t.textContent = msg;
    t.className = (kind || "") + " show";
    clearTimeout(N._toastT);
    N._toastT = setTimeout(() => { t.className = t.className.replace("show", "").trim(); }, 2600);
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
    pollSiblings(self);
    setInterval(() => pollSiblings(self), 8000);
    pollOpsec();
    setInterval(pollOpsec, 15000);
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

  function renderSwitcher(list, self) {
    const sw = document.getElementById("nuc-switcher");
    if (!sw) return;
    sw.innerHTML = "";
    // Fixed console order even before health arrives.
    const base = [
      { slug: "hub", name: "Hub", port: 8890 },
      { slug: "recon", name: "Recon", port: 8900 },
      { slug: "redcell", name: "Redcell", port: 8910 },
      { slug: "bastion", name: "Bastion", port: 8920 },
    ];
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
  // g then h/r/d/b (or plain 1/2/3/4) jumps consoles; / focuses the page's
  // primary input; ? toggles this help. Never fires while a field is
  // focused, except Escape (blurs it) — matching every console's own
  // keydown handlers (Enter-to-run etc), which still work normally since we
  // bail out before touching typed keys.
  const SHORTCUT_PORTS = { h: 8890, r: 8900, d: 8910, b: 8920, "1": 8890, "2": 8900, "3": 8910, "4": 8920 };
  let helpOverlayEl = null;
  let helpOpen = false;
  let gPending = false;
  let gPendingTimer = null;

  function isTypingTarget(el) {
    if (!el) return false;
    const tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  function primaryInput() {
    return document.querySelector("#q, #run-target, #report-domain");
  }

  function buildHelpOverlay() {
    if (helpOverlayEl) return helpOverlayEl;
    const overlay = N.el("div", { class: "shortcuts-overlay hidden", id: "nuc-shortcuts",
      role: "dialog", "aria-modal": "true", "aria-label": "Keyboard shortcuts" });
    const panel = N.el("div", { class: "shortcuts-panel" });
    panel.appendChild(N.el("h2", { text: "Keyboard shortcuts" }));
    const rows = [
      ["/", "focus the main input"],
      ["g h", "go to Hub"],
      ["g r", "go to Recon"],
      ["g d", "go to Redcell"],
      ["g b", "go to Bastion"],
      ["1 2 3 4", "same, one key"],
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
    overlay.appendChild(panel);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) closeHelp(); });
    document.body.appendChild(overlay);
    helpOverlayEl = overlay;
    return overlay;
  }

  function openHelp() { buildHelpOverlay().classList.remove("hidden"); helpOpen = true; }
  function closeHelp() { if (helpOverlayEl) helpOverlayEl.classList.add("hidden"); helpOpen = false; }
  function toggleHelp() { helpOpen ? closeHelp() : openHelp(); }

  function mountShortcuts() {
    if (N._shortcutsWired) return;
    N._shortcutsWired = true;
    document.addEventListener("keydown", (e) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      const typing = isTypingTarget(document.activeElement);

      if (e.key === "Escape") {
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
      if (/^[1-4]$/.test(e.key)) {
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
