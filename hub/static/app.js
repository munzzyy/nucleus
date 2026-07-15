/* Nucleus hub UI. Pulls one aggregated view from /api/overview and paints it. */
(function () {
  "use strict";
  const N = window.Nucleus;
  const url = (port) => location.protocol + "//" + location.hostname + ":" + port;

  const CONSOLE_ORDER = ["recon", "redcell", "bastion"];

  async function load() {
    let data;
    try { data = await N.get("/api/overview"); }
    catch (e) { N.toast("hub overview failed: " + e.message, "bad"); return; }

    const bySlug = {};
    (data.consoles || []).forEach(c => { bySlug[c.slug] = c; });

    // Consoles
    const cwrap = document.getElementById("consoles");
    cwrap.innerHTML = "";
    CONSOLE_ORDER.forEach(slug => {
      const c = bySlug[slug];
      if (!c) return;
      cwrap.appendChild(consoleCard(c));
    });

    // Stats row
    const stats = document.getElementById("stats");
    stats.innerHTML = "";
    const upCount = (data.consoles || []).filter(c => c.up && c.slug !== "hub").length;
    stats.appendChild(statCard(upCount + " / " + CONSOLE_ORDER.length, "consoles online"));
    if (data.tools) {
      const inst = data.tools.installed != null ? data.tools.installed : (data.tools.installed_count || 0);
      const total = data.tools.total != null ? data.tools.total : (data.tools.total_count || 0);
      stats.appendChild(statCard(inst + (total ? " / " + total : ""), "pentest tools installed",
        url(8910) + "/"));
    } else {
      stats.appendChild(statCard("—", "tools (start Redcell)", url(8910) + "/"));
    }
    if (data.posture) {
      const score = data.posture.score != null ? data.posture.score
        : (data.posture.ok != null ? data.posture.ok + " ok" : "—");
      stats.appendChild(statCard(String(score), "opsec posture", url(8920) + "/"));
    } else {
      stats.appendChild(statCard("—", "posture (start Bastion)", url(8920) + "/"));
    }

    // Connected local apps (external, e.g. coleos-hub)
    const apps = document.getElementById("apps");
    apps.innerHTML = "";
    (data.consoles || []).filter(c => c.path !== undefined || c.slug === "coleos-hub").forEach(a => {
      apps.appendChild(appCard(a));
    });
    if (!apps.children.length) apps.appendChild(N.el("p", { class: "faint", text: "No external apps registered." }));

    // Published tools
    const pub = document.getElementById("published");
    pub.innerHTML = "";
    (data.published_tools || []).forEach(t => {
      const a = N.el("a", { class: "card link pub", href: N.safeUrl(t.url), target: "_blank", rel: "noreferrer" });
      a.appendChild(N.el("span", { class: "name", text: t.name }));
      a.appendChild(N.el("span", { class: "desc", text: t.desc }));
      pub.appendChild(a);
    });
  }

  async function loadSettings() {
    const wrap = document.getElementById("settings");
    if (!wrap) return;
    let s;
    try { s = await N.get("/api/settings"); } catch (_) { return; }
    const keys = s.keys || [];
    const setCount = keys.filter(k => k.set).length;
    const note = document.getElementById("settings-note");
    if (note) note.textContent = `${setCount} of ${keys.length} keys set. All optional — Recon works keyless, but each key you add unlocks more data. Keys stay local (var/.env).`;
    const nudge = document.getElementById("keys-nudge");
    if (nudge) {
      if (setCount === 0 && keys.length) {
        nudge.innerHTML = "";
        nudge.appendChild(N.el("span", { text: `0/${keys.length} keys set — add one to unlock more OSINT sources. ` }));
        nudge.appendChild(N.el("a", { href: "#settings", text: "Add a key →" }));
        nudge.classList.remove("hidden");
      } else {
        nudge.classList.add("hidden");
      }
    }
    wrap.innerHTML = "";
    keys.forEach(k => {
      const card = N.el("div", { class: "card keycard" });
      const head = N.el("div", { class: "row-top" });
      const lt = N.el("div", {});
      lt.appendChild(N.el("h2", { text: k.label }));
      lt.appendChild(N.el("span", { class: "faint small", text: k.provider + " · " + k.free }));
      head.appendChild(lt);
      head.appendChild(N.el("span", { class: "pill " + (k.set ? "ok" : "warn"),
        html: '<span class="dot"></span>' + (k.set ? "set" : "not set") }));
      card.appendChild(head);
      card.appendChild(N.el("p", { class: "sub", text: k.unlocks }));
      const field = N.el("div", { class: "field" });
      const input = N.el("input", { type: "text",
        placeholder: k.set ? "•••••••• saved — paste a new key to replace" : "paste your key" });
      field.appendChild(input);
      card.appendChild(field);
      const row = N.el("div", { class: "row keyrow" });
      const save = N.el("button", { text: "Save" });
      save.addEventListener("click", async () => {
        save.disabled = true;
        try {
          const r = await N.post("/api/settings", { name: k.name, value: input.value.trim() });
          N.toast(r.set ? k.label + " key saved — live now" : k.label + " cleared", "ok");
          loadSettings();
        } catch (e) { N.toast(e.message || "save failed", "bad"); save.disabled = false; }
      });
      row.appendChild(save);
      if (k.set) {
        const clear = N.el("button", { class: "ghost", text: "Clear" });
        clear.addEventListener("click", async () => {
          try { await N.post("/api/settings", { name: k.name, value: "" }); N.toast(k.label + " cleared", "ok"); loadSettings(); }
          catch (e) { N.toast(e.message || "failed", "bad"); }
        });
        row.appendChild(clear);
      }
      row.appendChild(N.el("a", { class: "btn ghost", href: N.safeUrl(k.get_url), target: "_blank", rel: "noreferrer", text: "Get a free key ↗" }));
      card.appendChild(row);
      wrap.appendChild(card);
    });
  }

  function consoleCard(c) {
    const card = N.el("div", { class: "card console-card accent-" + c.slug });
    const top = N.el("div", { class: "row-top" });
    const left = N.el("div", {});
    left.appendChild(N.el("h2", { text: c.name }));
    left.appendChild(N.el("span", { class: "tag", text: c.tag || "" }));
    top.appendChild(left);
    top.appendChild(N.el("span", { class: "dotbig " + (c.up ? "up" : "down"), title: c.up ? "online" : "offline" }));
    card.appendChild(top);
    card.appendChild(N.el("p", { class: "sub", text: c.desc || "" }));
    card.appendChild(N.el("div", { class: "meta", text: "127.0.0.1:" + c.port + "  ·  " + (c.up ? "online" : "offline — start it with the launcher") }));
    const act = N.el("div", { class: "actions" });
    if (c.up) act.appendChild(N.el("a", { class: "btn", href: url(c.port) + "/", text: "Open " + c.name }));
    else act.appendChild(N.el("span", { class: "btn ghost", text: "Offline" }));
    card.appendChild(act);
    return card;
  }

  function appCard(a) {
    const card = N.el("div", { class: "card console-card" });
    const top = N.el("div", { class: "row-top" });
    top.appendChild(N.el("h2", { text: a.name }));
    top.appendChild(N.el("span", { class: "dotbig " + (a.up ? "up" : "down") }));
    card.appendChild(top);
    card.appendChild(N.el("p", { class: "sub", text: a.desc || "" }));
    card.appendChild(N.el("div", { class: "meta", text: "127.0.0.1:" + a.port }));
    const act = N.el("div", { class: "actions" });
    if (a.up) act.appendChild(N.el("a", { class: "btn", href: url(a.port) + (a.path || "/"), text: "Open" }));
    else act.appendChild(N.el("span", { class: "btn ghost", text: "Offline" }));
    card.appendChild(act);
    return card;
  }

  function statCard(num, lbl, href) {
    const inner = N.el("div", { class: "stat" });
    inner.appendChild(N.el("span", { class: "num", text: String(num) }));
    inner.appendChild(N.el("span", { class: "lbl", text: lbl }));
    if (href) {
      const a = N.el("a", { class: "card link", href: href });
      a.appendChild(inner); return a;
    }
    const card = N.el("div", { class: "card" }); card.appendChild(inner); return card;
  }

  document.addEventListener("DOMContentLoaded", () => {
    load(); loadSettings(); setInterval(load, 8000);
  });
})();
