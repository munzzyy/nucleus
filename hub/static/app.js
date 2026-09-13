/* Nucleus hub UI. Pulls one aggregated view from /api/overview and paints it.

   Two rules the rest of this file exists to keep:
   1. Never lie. A number the hub couldn't get says WHY — "offline",
      "starting…", "error" — instead of an em dash that reads like zero.
   2. Never flicker. Cards and stats are built once and updated in place, so an
      8-second poll doesn't rebuild the page under the cursor. */
(function () {
  "use strict";
  const N = window.Nucleus;
  const url = (port) => location.protocol + "//" + location.hostname + ":" + port;

  const CONSOLE_ORDER = ["recon", "redcell", "bastion", "devkit", "systems"];
  const STAT_ORDER = ["consoles", "tools", "posture", "devkit", "systems"];
  const POLL_MS = 8000;

  // How a failed probe reads to a human. These are the four statuses
  // /api/overview reports per source.
  const STATE_WORD = { down: "offline", timeout: "starting…", error: "error" };

  let lastOverview = null;
  let inFlight = false;      // a slow posture probe must not stack up polls
  let failStreak = 0;        // toast the FIRST failure of a streak, then shut up
  let consolesBuilt = false;
  let statsBuilt = false;
  let appsBuilt = false;
  let publishedBuilt = false;
  const cardCache = {};
  const appCache = {};
  const statCache = {};

  // ---- skeletons ----------------------------------------------------------
  function skelConsoleCard() {
    const card = N.el("div", { class: "card console-card skelcard" });
    card.appendChild(N.el("span", { class: "skel tall" }));
    card.appendChild(N.el("span", { class: "skel wide" }));
    card.appendChild(N.el("span", { class: "skel wide" }));
    return card;
  }

  function skelStat() {
    const card = N.el("div", { class: "card skelcard" });
    const inner = N.el("div", { class: "stat" });
    inner.appendChild(N.el("span", { class: "skel tall" }));
    inner.appendChild(N.el("span", { class: "skel" }));
    card.appendChild(inner);
    return card;
  }

  function paintSkeletons() {
    const cwrap = document.getElementById("consoles");
    const swrap = document.getElementById("stats");
    if (cwrap) { cwrap.innerHTML = ""; CONSOLE_ORDER.forEach(() => cwrap.appendChild(skelConsoleCard())); }
    if (swrap) { swrap.innerHTML = ""; STAT_ORDER.forEach(() => swrap.appendChild(skelStat())); }
  }

  // ---- load ---------------------------------------------------------------
  async function load() {
    if (inFlight) return;
    inFlight = true;
    let data;
    try {
      data = await N.get("/api/overview");
    } catch (e) {
      failStreak++;
      if (failStreak === 1) N.toast("hub overview failed: " + e.message, "bad");
      if (!lastOverview) {
        const cwrap = document.getElementById("consoles");
        if (cwrap) {
          cwrap.innerHTML = "";
          consolesBuilt = true;
          cwrap.appendChild(N.stateCard("error", "Can't reach the hub's own API: " + e.message));
        }
      }
      return;
    } finally {
      inFlight = false;
    }
    if (failStreak) { failStreak = 0; N.toast("hub reconnected", "ok"); }
    lastOverview = data;

    const bySlug = {};
    (data.consoles || []).forEach(c => { bySlug[c.slug] = c; });

    renderConsoles(bySlug);
    renderStats(data);
    renderApps(data);
    renderPublished(data);
    updateSearchHint(bySlug);
    wireExport();
  }

  // ---- console cards ------------------------------------------------------
  function buildConsoleCard(c) {
    const card = N.el("div", { class: "card console-card accent-" + c.slug });
    const top = N.el("div", { class: "row-top" });
    const left = N.el("div", {});
    left.appendChild(N.el("h2", { text: c.name }));
    left.appendChild(N.el("span", { class: "tag", text: c.tag || "" }));
    top.appendChild(left);
    const dot = N.el("span", { class: "dotbig" });
    top.appendChild(dot);
    card.appendChild(top);
    card.appendChild(N.el("p", { class: "sub", text: c.desc || "" }));
    const meta = N.el("div", { class: "meta" });
    card.appendChild(meta);
    const act = N.el("div", { class: "actions" });
    const open = N.el("a", { class: "btn", href: url(c.port) + "/", text: "Open " + c.name });
    const off = N.el("span", { class: "btn ghost", text: "Offline" });
    act.appendChild(open);
    act.appendChild(off);
    card.appendChild(act);
    return { card: card, dot: dot, meta: meta, open: open, off: off };
  }

  function updateConsoleCard(refs, c) {
    const up = !!c.up;
    refs.dot.className = "dotbig " + (up ? "up" : "down");
    refs.dot.setAttribute("title", up ? "online" : "offline");
    refs.meta.textContent = "127.0.0.1:" + c.port + "  ·  " +
      (up ? "online" : "offline — start it with the launcher");
    refs.open.classList.toggle("hidden", !up);
    refs.off.classList.toggle("hidden", up);
  }

  function renderConsoles(bySlug) {
    const wrap = document.getElementById("consoles");
    if (!wrap) return;
    if (!consolesBuilt) { wrap.innerHTML = ""; consolesBuilt = true; }
    CONSOLE_ORDER.forEach(slug => {
      const c = bySlug[slug];
      if (!c) return;
      let refs = cardCache[slug];
      if (!refs) { refs = cardCache[slug] = buildConsoleCard(c); wrap.appendChild(refs.card); }
      updateConsoleCard(refs, c);
    });
  }

  // ---- stats --------------------------------------------------------------
  // Each stat carries the status of the source it came from, so "I couldn't
  // ask" never renders as a value.
  function statFrom(src, value, lbl, href, fmt) {
    const status = (src && src.status) || (value ? "ok" : "error");
    if (status === "ok" && value) {
      let out;
      try { out = fmt(value); } catch (_) { out = null; }
      if (out != null) return { num: out.num != null ? out.num : out, lbl: out.lbl || lbl, href: href, state: "ok" };
    }
    return {
      num: STATE_WORD[status] || "unavailable",
      lbl: lbl, href: href, state: status === "ok" ? "error" : status,
      title: (src && src.detail) || "",
    };
  }

  function statValues(d) {
    const src = d.sources || {};
    const upCount = (d.consoles || []).filter(c => c.up && CONSOLE_ORDER.indexOf(c.slug) >= 0).length;
    return {
      consoles: { num: upCount + " / " + CONSOLE_ORDER.length, lbl: "consoles online", state: "ok" },
      tools: statFrom(src.tools, d.tools, "pentest tools installed", url(8910) + "/", t => {
        const inst = t.installed != null ? t.installed : (t.installed_count || 0);
        const total = t.total != null ? t.total : (t.total_count || 0);
        return inst + (total ? " / " + total : "");
      }),
      posture: statFrom(src.posture, d.posture, "opsec posture", url(8920) + "/", p =>
        p.score != null ? String(p.score) : (p.ok != null ? p.ok + " ok" : null)),
      devkit: statFrom(src.devkit, d.devkit, "devkit tools", url(8930) + "/", k =>
        k.tools != null ? String(k.tools) : null),
      systems: statFrom(src.systems, d.systems, "memory used", url(8940) + "/", s => {
        const load = s.load1 != null ? "load " + s.load1 : "";
        if (s.mem_percent != null) {
          return { num: s.mem_percent + "%", lbl: load ? "memory used · " + load : "memory used" };
        }
        return load ? { num: String(s.load1), lbl: "load average" } : null;
      }),
    };
  }

  function buildStat(v) {
    const inner = N.el("div", { class: "stat" });
    const num = N.el("span", { class: "num" });
    const lbl = N.el("span", { class: "lbl" });
    inner.appendChild(num);
    inner.appendChild(lbl);
    const root = v.href ? N.el("a", { class: "card link", href: v.href }) : N.el("div", { class: "card" });
    root.appendChild(inner);
    return { root: root, num: num, lbl: lbl };
  }

  function renderStats(d) {
    const wrap = document.getElementById("stats");
    if (!wrap) return;
    if (!statsBuilt) { wrap.innerHTML = ""; statsBuilt = true; }
    const vals = statValues(d);
    STAT_ORDER.forEach(k => {
      const v = vals[k];
      let refs = statCache[k];
      if (!refs) { refs = statCache[k] = buildStat(v); wrap.appendChild(refs.root); }
      refs.num.textContent = String(v.num);
      refs.num.className = "num" + (v.state && v.state !== "ok" ? " state-" + v.state : "");
      refs.lbl.textContent = v.lbl;
      if (v.title) refs.root.setAttribute("title", v.title);
      else refs.root.removeAttribute("title");
    });
  }

  // ---- connected local apps ----------------------------------------------
  function buildAppCard(a) {
    const card = N.el("div", { class: "card console-card" });
    const top = N.el("div", { class: "row-top" });
    top.appendChild(N.el("h2", { text: a.name }));
    const dot = N.el("span", { class: "dotbig" });
    top.appendChild(dot);
    card.appendChild(top);
    card.appendChild(N.el("p", { class: "sub", text: a.desc || "" }));
    card.appendChild(N.el("div", { class: "meta", text: "127.0.0.1:" + a.port }));
    const act = N.el("div", { class: "actions" });
    const open = N.el("a", { class: "btn", href: url(a.port) + (a.path || "/"), text: "Open" });
    const off = N.el("span", { class: "btn ghost", text: "Offline" });
    act.appendChild(open);
    act.appendChild(off);
    card.appendChild(act);
    return { card: card, dot: dot, open: open, off: off };
  }

  function renderApps(d) {
    const wrap = document.getElementById("apps");
    if (!wrap) return;
    const apps = (d.consoles || []).filter(c => c.path !== undefined || c.slug === "coleos-hub");
    if (!appsBuilt) { wrap.innerHTML = ""; appsBuilt = true; }
    if (!apps.length) {
      if (!wrap.children.length) {
        wrap.appendChild(N.stateCard("empty", "No external apps registered."));
      }
      return;
    }
    apps.forEach(a => {
      let refs = appCache[a.slug];
      if (!refs) { refs = appCache[a.slug] = buildAppCard(a); wrap.appendChild(refs.card); }
      const up = !!a.up;
      refs.dot.className = "dotbig " + (up ? "up" : "down");
      refs.open.classList.toggle("hidden", !up);
      refs.off.classList.toggle("hidden", up);
    });
  }

  // ---- shipped tools (static; paint once) ---------------------------------
  function renderPublished(d) {
    if (publishedBuilt) return;
    const pub = document.getElementById("published");
    if (!pub) return;
    pub.innerHTML = "";
    publishedBuilt = true;
    (d.published_tools || []).forEach(t => {
      const a = N.el("a", { class: "card link pub", href: N.safeUrl(t.url), target: "_blank", rel: "noreferrer" });
      a.appendChild(N.el("span", { class: "name", text: t.name }));
      a.appendChild(N.el("span", { class: "desc", text: t.desc }));
      pub.appendChild(a);
    });
  }

  // ---- search box ---------------------------------------------------------
  // The hub's one job for a target is handing it to the console that can act on
  // it — Recon reads #q= on load and runs itself.
  function reconLink(v) {
    return url(8900) + "/#q=" + encodeURIComponent(v) + "&type=auto";
  }

  function wireSearch() {
    const input = document.getElementById("q");
    const go = document.getElementById("hub-search-go");
    if (!input || !go) return;
    const run = () => {
      const v = (input.value || "").trim();
      if (!v) { input.focus(); return; }
      location.href = reconLink(v);
    };
    go.addEventListener("click", run);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); run(); }
    });
  }

  function updateSearchHint(bySlug) {
    const hint = document.getElementById("hub-search-hint");
    const go = document.getElementById("hub-search-go");
    if (!hint || !go) return;
    const up = !!(bySlug.recon && bySlug.recon.up);
    go.disabled = !up;
    hint.textContent = up
      ? "Opens Recon with this target and runs it."
      : "Recon is offline — start it with the launcher to search.";
  }

  // ---- export + palette commands -----------------------------------------
  function overviewText(d) {
    if (!d) return "";
    const lines = ["Nucleus overview — " + new Date().toISOString(), ""];
    (d.consoles || []).forEach(c => {
      lines.push("  " + String(c.slug).padEnd(11) + (c.up ? "online " : "offline") +
        "  127.0.0.1:" + c.port);
    });
    lines.push("");
    const src = d.sources || {};
    STAT_ORDER.forEach(k => {
      if (k === "consoles") return;
      const s = src[k] || {};
      const v = d[k];
      lines.push("  " + k.padEnd(11) + (s.status || "?") +
        (s.detail ? " (" + s.detail + ")" : "") +
        (v ? "  " + JSON.stringify(v) : ""));
    });
    return lines.join("\n") + "\n";
  }

  function wireExport() {
    const bar = document.getElementById("overview-bar");
    if (!bar || bar.children.length) return;
    bar.appendChild(N.resultBar({
      getText: () => overviewText(lastOverview),
      json: () => lastOverview || {},
      filename: "nucleus-overview",
      mime: "text/plain",
    }));
  }

  function registerCommands() {
    if (!N.registerCommand) return;
    N.registerCommand({ section: "Hub", label: "Refresh overview", run: () => load() });
    N.registerCommand({ section: "Hub", label: "Copy overview JSON",
      run: () => N.copy(JSON.stringify(lastOverview || {}, null, 2)) });
    N.registerCommand({ section: "Hub", label: "Download overview JSON",
      run: () => N.downloadJson(lastOverview || {}, "nucleus-overview.json") });
  }

  // ---- settings -----------------------------------------------------------
  async function loadSettings() {
    const wrap = document.getElementById("settings");
    if (!wrap) return;
    if (!wrap.children.length) wrap.appendChild(N.stateCard("loading", "Loading keys…"));
    let s;
    try { s = await N.get("/api/settings"); }
    catch (e) {
      wrap.innerHTML = "";
      wrap.appendChild(N.stateCard("error", "Couldn't read key settings: " + e.message));
      return;
    }
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
    if (!keys.length) {
      wrap.appendChild(N.stateCard("empty", "No optional keys are defined in this build."));
      return;
    }
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

  // ---- first-run onboarding ----------------------------------------------
  // A dismissible "try one of these in 5 minutes" panel with concrete click
  // paths, so a first-time visitor knows where to start. Remembered once
  // dismissed, plus a nod to the Ctrl-K palette.
  function renderOnboarding() {
    const host = document.getElementById("hub-onboard");
    if (!host) return;
    const store = N.remember("onboard-dismissed");
    if (store.get(false)) return;
    const head = N.el("div", { class: "onboard-head" });
    head.appendChild(N.el("h2", { text: "New here? Try one of these in 5 minutes" }));
    const dismiss = N.el("button", { type: "button", class: "ghost onboard-x", text: "Dismiss" });
    dismiss.addEventListener("click", () => { store.set(true); host.replaceChildren(); host.classList.add("hidden"); });
    head.appendChild(dismiss);
    host.appendChild(head);

    const paths = [
      ["Grade a domain's security", "Bastion", 8920],
      ["Decode or inspect a JWT", "Devkit", 8930],
      ["See what your machine exposes", "Bastion opsec", 8920],
      ["Recon a username or email", "Recon", 8900],
    ];
    const list = N.el("div", { class: "onboard-paths" });
    paths.forEach(([what, where, port]) => {
      const a = N.el("a", { class: "onboard-path", href: url(port) + "/" });
      a.appendChild(N.el("span", { class: "op-what", text: what }));
      a.appendChild(N.el("span", { class: "op-where", text: "→ " + where }));
      list.appendChild(a);
    });
    host.appendChild(list);
    host.appendChild(N.el("p", { class: "faint small m0 mt" },
      [N.el("span", { class: "kbd", text: "Ctrl-K" }), " jumps to any tool or console from anywhere."]));
    host.classList.remove("hidden");
  }

  document.addEventListener("DOMContentLoaded", () => {
    renderOnboarding();
    paintSkeletons();
    wireSearch();
    registerCommands();
    load();
    loadSettings();
    // Polling stops while the tab is hidden and catches up on focus — the hub
    // is a tab people leave open all day.
    N.pollWhileVisible(load, POLL_MS);
  });
})();
