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
    document.body.insertBefore(bar, document.body.firstChild);

    renderSwitcher([], self);
    pollSiblings(self);
    setInterval(() => pollSiblings(self), 8000);
  };

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

  // Auto-mount if the page opted in.
  document.addEventListener("DOMContentLoaded", function () {
    if (document.body && document.body.hasAttribute("data-auto-shell")) N.mountShell();
  });
})();
