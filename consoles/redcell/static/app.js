(function () {
  "use strict";
  const N = window.Nucleus;
  const TABS = ["run", "arsenal", "build", "tools", "history", "expert"];
  let INV = null;          // last /api/inventory payload
  let ACTIVE_CAT = "";
  let INV_SEARCH = "";
  let EXPANDED = new Set(); // categories the user has manually opened in the arsenal accordion
  let WL_SEARCH_TIMER = null;
  let WL_SEARCH_SEQ = 0;   // monotonic id — drops a stale wordlist response if a newer query already started
  let runTickerId = null;
  let expertTickerId = null;

  // -- elapsed-seconds ticker (nmap "full" etc can run 600s — an honest
  // clock beats a static spinner that looks hung) ---------------------------
  function tickerStart(elId, label) {
    const el = document.getElementById(elId);
    const start = Date.now();
    el.textContent = `${label} — 0.0s`;
    return setInterval(() => {
      el.textContent = `${label} — ${((Date.now() - start) / 1000).toFixed(1)}s`;
    }, 200);
  }
  function tickerStop(id) {
    if (id) clearInterval(id);
  }

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    wireTabs();
    wireAuthGate();
    wireRunner();
    wireBuilder();
    wireArsenal();
    wireExpert();
    document.getElementById("hist-refresh").addEventListener("click", loadHistory);
    document.getElementById("outputs-refresh").addEventListener("click", loadOutputs);
    await loadInventory(false);
    await loadHistory();
    await loadOutputs();
  }

  // ------------------------------------------------------------------
  // Tabs
  // ------------------------------------------------------------------
  function wireTabs() {
    TABS.forEach(tab => {
      document.getElementById("tabbtn-" + tab).addEventListener("click", () => switchTab(tab));
    });
    document.getElementById("tabbar").addEventListener("keydown", onTabKeydown);
    const initial = TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : "run";
    switchTab(initial);
  }

  function onTabKeydown(e) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const idx = TABS.indexOf(document.activeElement.dataset.tab);
    if (idx === -1) return;
    e.preventDefault();
    const next = TABS[(idx + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
    switchTab(next);
    document.getElementById("tabbtn-" + next).focus();
  }

  function switchTab(tab) {
    if (!TABS.includes(tab)) tab = "run";
    TABS.forEach(t => {
      const active = t === tab;
      const btn = document.getElementById("tabbtn-" + t);
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
      btn.tabIndex = active ? 0 : -1;
      document.getElementById("tab-" + t).classList.toggle("hidden", !active);
    });
    if (history.replaceState) history.replaceState(null, "", "#" + tab);
    if (tab === "history") { loadHistory(); loadOutputs(); }
    if (tab === "expert") loadExpertTools();
  }

  // ------------------------------------------------------------------
  // Authorization gate (client-side UX only — the real gate is server-side)
  // ------------------------------------------------------------------
  function wireAuthGate() {
    const box = document.getElementById("g-authorized");
    const btn = document.getElementById("run-btn");
    box.addEventListener("change", () => { btn.disabled = !box.checked; });
  }

  // ------------------------------------------------------------------
  // Expert mode — run any installed tool with your own args (argv, no shell)
  // ------------------------------------------------------------------
  let EXPERT_LOADED = false;
  async function loadExpertTools() {
    if (EXPERT_LOADED) return;
    const sel = document.getElementById("x-tool");
    try {
      const j = await N.get("/api/expert-tools");
      sel.innerHTML = "";
      (j.tools || []).forEach(t => {
        const o = document.createElement("option");
        o.value = t; o.textContent = t; sel.appendChild(o);
      });
      EXPERT_LOADED = true;
      updateExpertPreview();
    } catch (e) { N.toast("expert tools load failed: " + e.message, "bad"); }
  }

  function updateExpertPreview() {
    const tool = document.getElementById("x-tool").value;
    const args = document.getElementById("x-args").value;
    document.getElementById("x-preview").textContent = tool ? (tool + " " + args) : "";
  }

  function expertGateOk() {
    return document.getElementById("x-authorized").checked &&
           document.getElementById("x-ack").checked;
  }

  function wireExpert() {
    const btn = document.getElementById("x-run");
    const sync = () => { btn.disabled = !expertGateOk(); };
    document.getElementById("x-authorized").addEventListener("change", sync);
    document.getElementById("x-ack").addEventListener("change", sync);
    document.getElementById("x-tool").addEventListener("change", updateExpertPreview);
    const args = document.getElementById("x-args");
    args.addEventListener("input", updateExpertPreview);
    args.addEventListener("keydown", e => { if (e.key === "Enter" && !btn.disabled) runExpert(); });
    btn.addEventListener("click", runExpert);
    document.getElementById("x-copy").addEventListener("click", () => {
      const text = document.getElementById("x-output").textContent;
      navigator.clipboard.writeText(text).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
    });
  }

  async function runExpert() {
    const btn = document.getElementById("x-run");
    const out = document.getElementById("x-output");
    const status = document.getElementById("x-status");
    const tool = document.getElementById("x-tool").value;
    const args = document.getElementById("x-args").value;
    btn.disabled = true;
    out.classList.remove("hidden");
    out.textContent = "running " + tool + " …";
    document.getElementById("x-copy").classList.remove("hidden");
    expertTickerId = tickerStart("x-status", "running " + tool);
    try {
      const r = await N.post("/api/expert", {
        tool, args,
        authorized: document.getElementById("x-authorized").checked,
        expert_ack: document.getElementById("x-ack").checked,
      });
      tickerStop(expertTickerId); expertTickerId = null;
      status.textContent = `exit ${r.returncode} · ${r.duration}s` + (r.timed_out ? " · TIMED OUT" : "");
      const head = "$ " + (r.argv || []).join(" ") + "\n[exit " + r.returncode +
        " · " + r.duration + "s" + (r.timed_out ? " · TIMED OUT" : "") + "]\n\n";
      // raw tool output via textContent — never innerHTML — so it can't inject markup
      out.textContent = head + (r.stdout || "") + (r.stderr ? "\n" + r.stderr : "");
      loadHistory();
    } catch (e) {
      tickerStop(expertTickerId); expertTickerId = null;
      status.textContent = "error";
      out.textContent = "error: " + (e.message || "run failed");
      N.toast(e.message || "expert run failed", "bad");
    } finally {
      btn.disabled = !expertGateOk();
    }
  }

  // ------------------------------------------------------------------
  // Inventory
  // ------------------------------------------------------------------
  async function loadInventory(refresh) {
    const stat = document.getElementById("inv-stat-num");
    stat.textContent = "…";
    try {
      if (refresh) await N.post("/api/inventory/refresh", {});
      INV = await N.get("/api/inventory");
    } catch (e) {
      stat.textContent = "error";
      N.toast("inventory load failed: " + e.message, "bad");
      return;
    }
    renderCategorySelect();
    renderSummary();
    renderAccordion();
    renderRunnerSelect();
    renderBuilderSelect();
    renderLocalTools();
    document.getElementById("tabcount-arsenal").textContent = "· " + INV.summary.total;
  }

  function renderSummary() {
    const s = INV.summary;
    document.getElementById("inv-stat-num").textContent = `${s.installed} / ${s.total}`;
  }

  function renderCategorySelect() {
    const sel = document.getElementById("inv-cat");
    const prev = sel.value;
    sel.innerHTML = "";
    sel.appendChild(N.el("option", { value: "", text: "All categories" }));
    INV.categories.forEach(c => {
      sel.appendChild(N.el("option", { value: c.key, text: `${c.label} (${c.installed}/${c.total})` }));
    });
    sel.value = prev || "";
    sel.onchange = () => { ACTIVE_CAT = sel.value; renderAccordion(); };
  }

  function wireArsenal() {
    document.getElementById("inv-search").addEventListener("input", e => {
      INV_SEARCH = e.target.value;
      renderAccordion();
    });
    document.getElementById("inv-installed-only").addEventListener("change", renderAccordion);
    document.getElementById("inv-refresh").addEventListener("click", () => loadInventory(true));
  }

  // Collapsible per-category accordion — replaces one flat 81-row table.
  // Sections are collapsed by default; a text search or the category filter
  // forces the matching section(s) open so results are never hidden.
  function renderAccordion() {
    const wrap = document.getElementById("inv-accordion");
    wrap.innerHTML = "";
    if (!INV) return;
    const installedOnly = document.getElementById("inv-installed-only").checked;
    const q = INV_SEARCH.trim().toLowerCase();
    const cats = ACTIVE_CAT ? INV.categories.filter(c => c.key === ACTIVE_CAT) : INV.categories;
    let shown = 0;
    cats.forEach(c => {
      const rows = INV.tools.filter(t => t.category === c.key
        && (!installedOnly || t.installed)
        && (!q || t.name.toLowerCase().includes(q) || (t.purpose || "").toLowerCase().includes(q)));
      if (!rows.length) return;
      shown++;
      wrap.appendChild(renderAccordionSection(c, rows, !!q));
    });
    if (!shown) {
      wrap.appendChild(N.el("div", { class: "card muted", text: "No tools match this filter." }));
    }
  }

  function categoryOpen(key, forced) {
    return ACTIVE_CAT === key || forced || EXPANDED.has(key);
  }

  function toggleCategory(key) {
    if (EXPANDED.has(key)) EXPANDED.delete(key); else EXPANDED.add(key);
    renderAccordion();
  }

  function renderAccordionSection(c, rows, forcedOpen) {
    const open = categoryOpen(c.key, forcedOpen);
    const item = N.el("div", { class: "acc-item" + (open ? " open" : "") });
    const bodyId = "acc-body-" + c.key;
    const btn = N.el("button", {
      type: "button", class: "acc-head", id: "acc-btn-" + c.key,
      "aria-expanded": String(open), "aria-controls": bodyId,
      onclick: () => toggleCategory(c.key),
    });
    btn.appendChild(N.el("span", { class: "acc-chev", "aria-hidden": "true", text: "›" }));
    btn.appendChild(N.el("span", { class: "acc-title", text: c.label }));
    btn.appendChild(N.el("span", { class: "acc-count", text: `${rows.length} shown` }));
    btn.appendChild(N.el("span", { class: "pill " + (c.installed === c.total ? "ok" : "warn") }, [
      N.el("span", { class: "dot" }), document.createTextNode(`${c.installed} / ${c.total} installed`),
    ]));
    item.appendChild(btn);
    const body = N.el("div", { class: "acc-body" + (open ? "" : " hidden"), id: bodyId, role: "region", "aria-labelledby": "acc-btn-" + c.key });
    body.appendChild(buildToolsTable(rows));
    item.appendChild(body);
    return item;
  }

  function buildToolsTable(rows) {
    const table = N.el("table");
    table.appendChild(N.el("thead", {}, [N.el("tr", {}, [
      N.el("th", { text: "Tool" }), N.el("th", { text: "Purpose" }), N.el("th", { text: "Status" }),
      N.el("th", { text: "Version" }), N.el("th", { text: "Install" }),
    ])]));
    const tbody = N.el("tbody");
    rows.forEach(t => {
      const tr = N.el("tr");
      tr.appendChild(N.el("td", {}, [N.el("strong", { text: t.name }),
        document.createTextNode(" "), N.el("span", { class: "src-badge", text: t.source })]));
      tr.appendChild(N.el("td", { class: "muted", text: t.purpose }));
      const statusTd = N.el("td");
      statusTd.appendChild(N.el("span", { class: "pill " + (t.installed ? "ok" : "bad") }, [
        N.el("span", { class: "dot" }), document.createTextNode(t.installed ? "installed" : "not installed"),
      ]));
      tr.appendChild(statusTd);
      tr.appendChild(N.el("td", { class: "mono small muted", text: t.version || (t.path || "") }));
      tr.appendChild(N.el("td", { class: "mono small muted", text: t.installed ? (t.path || "") : t.install }));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  // ------------------------------------------------------------------
  // Safe runner
  // ------------------------------------------------------------------
  function renderRunnerSelect() {
    const sel = document.getElementById("run-tool");
    sel.innerHTML = "";
    INV.safe_runners.forEach(r => {
      sel.appendChild(N.el("option", { value: r.key, text: r.key
        + (r.installed ? "" : "  (not installed)") + (r.known_broken ? "  ⚠ known broken" : "") }));
    });
    sel.onchange = renderRunnerDetail;
    renderRunnerDetail();
  }

  function currentRunnerSpec() {
    const key = document.getElementById("run-tool").value;
    return (INV.safe_runners || []).find(r => r.key === key);
  }

  function renderRunnerDetail() {
    const spec = currentRunnerSpec();
    const descEl = document.getElementById("run-desc");
    const optRow = document.getElementById("run-options-row");
    const wlRow = document.getElementById("run-wordlist-row");
    optRow.innerHTML = "";
    if (!spec) { descEl.textContent = ""; wlRow.classList.add("hidden"); return; }
    descEl.innerHTML = "";
    descEl.appendChild(document.createTextNode(spec.desc + (spec.installed ? "" : `  — not installed: ${spec.install}`)
      + `  (timeout ${spec.timeout}s)`));
    if (spec.known_broken) {
      descEl.appendChild(document.createTextNode(" "));
      descEl.appendChild(N.el("span", { class: "pill bad" }, [
        N.el("span", { class: "dot" }), document.createTextNode("known broken on this box"),
      ]));
    }

    (spec.options || []).forEach(opt => {
      const field = N.el("div", { class: "field w-220" });
      field.appendChild(N.el("label", { text: opt.label || opt.name }));
      const sel = N.el("select", { "data-option": opt.name });
      opt.choices.forEach(v => sel.appendChild(N.el("option", {
        value: v, text: v + (v === opt.default ? " (default)" : ""),
      })));
      sel.value = opt.default;
      field.appendChild(sel);
      optRow.appendChild(field);
    });

    if (spec.needs_wordlist) {
      wlRow.classList.remove("hidden");
      document.getElementById("run-wordlist-search").value = "";
      populateWordlistSelect(INV.wordlists_common || []);
    } else {
      wlRow.classList.add("hidden");
    }
  }

  function populateWordlistSelect(results) {
    const sel = document.getElementById("run-wordlist");
    const countEl = document.getElementById("run-wordlist-count");
    sel.innerHTML = "";
    results.forEach(w => sel.appendChild(N.el("option", {
      value: w.id, text: `${w.label}  (${w.root}, ${(w.size / 1024).toFixed(1)}KB)`,
    })));
    countEl.textContent = results.length ? `· ${results.length} shown` : "· no matches";
  }

  function wireRunner() {
    const runBtn = document.getElementById("run-btn");
    runBtn.addEventListener("click", runSafeTool);
    document.getElementById("run-copy").addEventListener("click", () => {
      const text = document.getElementById("run-output").textContent;
      navigator.clipboard.writeText(text).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
    });
    // Enter-to-run on the target field, same pattern as Bastion's report-domain —
    // respects the auth-gate disabled state so it can't fire before authorization.
    document.getElementById("run-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !runBtn.disabled) runSafeTool();
    });
    document.getElementById("run-wordlist-search").addEventListener("input", e => {
      const q = e.target.value.trim();
      clearTimeout(WL_SEARCH_TIMER);
      WL_SEARCH_TIMER = setTimeout(async () => {
        const seq = ++WL_SEARCH_SEQ;
        try {
          const r = await N.get("/api/wordlists?q=" + encodeURIComponent(q) + "&limit=50");
          if (seq !== WL_SEARCH_SEQ) return; // a newer query started after this one — drop the stale reply
          populateWordlistSelect(r.results || []);
        } catch (err) { /* leave the previous list showing */ }
      }, 200);
    });
  }

  async function runSafeTool() {
    const spec = currentRunnerSpec();
    const target = document.getElementById("run-target").value.trim();
    const authorized = document.getElementById("g-authorized").checked;
    const lab = document.getElementById("g-lab").checked;
    const out = document.getElementById("run-output");
    const status = document.getElementById("run-status");
    if (!spec) return;
    if (!target) { N.toast("enter a target first", "bad"); return; }
    if (!authorized) { N.toast("check the authorization box first", "bad"); return; }

    const body = { tool: spec.key, target, authorized, lab };
    const optSelects = document.querySelectorAll("#run-options-row [data-option]");
    if (optSelects.length) {
      body.options = {};
      optSelects.forEach(sel => { body.options[sel.getAttribute("data-option")] = sel.value; });
    }
    if (spec.needs_wordlist) {
      const wl = document.getElementById("run-wordlist").value;
      if (!wl) { N.toast("pick a wordlist first", "bad"); return; }
      body.wordlist = wl;
    }

    out.classList.remove("hidden");
    out.textContent = "";
    document.getElementById("run-copy").classList.remove("hidden");
    document.getElementById("run-btn").disabled = true;
    runTickerId = tickerStart("run-status", "running " + spec.key);
    try {
      const r = await N.post("/api/run", body);
      tickerStop(runTickerId); runTickerId = null;
      status.textContent = `exit ${r.returncode} · ${r.duration}s` + (r.timed_out ? " · TIMED OUT" : "");
      let text = "$ " + r.argv.map(a => (/\s/.test(a) ? `'${a}'` : a)).join(" ") + "\n\n";
      text += (r.stdout || "").trim();
      if (r.stderr && r.stderr.trim()) text += "\n\n[stderr]\n" + r.stderr.trim();
      if (r.error) text += "\n\n[error] " + r.error;
      if (r.out_path) text += "\n\n[saved] " + r.out_path;
      out.textContent = text || "(no output)";
      loadHistory();
    } catch (e) {
      tickerStop(runTickerId); runTickerId = null;
      status.textContent = "refused";
      out.textContent = "REFUSED: " + (e.body && e.body.error ? e.body.error : e.message);
      N.toast("run refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      document.getElementById("run-btn").disabled = !authorized;
    }
  }

  // ------------------------------------------------------------------
  // Command builder (exec-free)
  // ------------------------------------------------------------------
  function renderBuilderSelect() {
    const sel = document.getElementById("build-tool");
    sel.innerHTML = "";
    (INV.build_tools || []).forEach(b => sel.appendChild(N.el("option", { value: b.key, text: b.key })));
    sel.onchange = renderBuilderFields;
    renderBuilderFields();
  }

  function currentBuildSpec() {
    const key = document.getElementById("build-tool").value;
    return (INV.build_tools || []).find(b => b.key === key);
  }

  function renderBuilderFields() {
    const spec = currentBuildSpec();
    const wrap = document.getElementById("build-fields");
    const descEl = document.getElementById("build-desc");
    const noteEl = document.getElementById("build-note");
    wrap.innerHTML = "";
    document.getElementById("build-result-wrap").classList.add("hidden");
    descEl.textContent = spec ? spec.desc : "";
    if (spec && spec.note) { noteEl.textContent = spec.note; noteEl.classList.remove("hidden"); }
    else { noteEl.textContent = ""; noteEl.classList.add("hidden"); }
    if (!spec) return;
    spec.fields.forEach(f => {
      const isFileFlag = f.endsWith("_is_file");
      const isBoolFlag = f.endsWith("_flag");
      const field = N.el("div", { class: "field" });
      if (isFileFlag) {
        field.appendChild(N.el("label", { text: f.replace(/_/g, " ") }));
        const line = N.el("label", { class: "checkline" });
        line.appendChild(N.el("input", { type: "checkbox", "data-field": f }));
        line.appendChild(document.createTextNode("treat as a file/list path"));
        field.appendChild(line);
      } else if (isBoolFlag) {
        const name = f.replace(/_flag$/, "").replace(/_/g, " ");
        field.appendChild(N.el("label", { text: name }));
        const line = N.el("label", { class: "checkline" });
        line.appendChild(N.el("input", { type: "checkbox", "data-field": f }));
        line.appendChild(document.createTextNode("on"));
        field.appendChild(line);
      } else {
        field.appendChild(N.el("label", { text: f.replace(/_/g, " ") }));
        field.appendChild(N.el("input", { type: "text", "data-field": f, placeholder: f }));
      }
      wrap.appendChild(field);
    });
  }

  function wireBuilder() {
    document.getElementById("build-btn").addEventListener("click", buildCommand);
    document.getElementById("build-copy").addEventListener("click", () => {
      const text = document.getElementById("build-result").textContent;
      navigator.clipboard.writeText(text).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
    });
  }

  async function buildCommand() {
    const spec = currentBuildSpec();
    if (!spec) return;
    const params = {};
    document.querySelectorAll("#build-fields [data-field]").forEach(el => {
      params[el.getAttribute("data-field")] = el.type === "checkbox" ? el.checked : el.value;
    });
    try {
      const r = await N.post("/api/build", { tool: spec.key, params });
      document.getElementById("build-result").textContent = r.command;
      document.getElementById("build-result-wrap").classList.remove("hidden");
    } catch (e) {
      N.toast("build failed: " + e.message, "bad");
    }
  }

  // ------------------------------------------------------------------
  // Published tools
  // ------------------------------------------------------------------
  function renderLocalTools() {
    const wrap = document.getElementById("local-tools");
    wrap.innerHTML = "";
    (INV.local_tools || []).forEach(t => {
      const card = N.el("div", { class: "card local-tool-card" });
      const head = N.el("div", { class: "row2" });
      head.appendChild(N.el("strong", { text: t.key }));
      head.appendChild(N.el("span", { class: "pill " + (t.installed ? "ok" : "bad") }, [
        N.el("span", { class: "dot" }), document.createTextNode(t.installed ? "ready" : "not installed"),
      ]));
      card.appendChild(head);
      card.appendChild(N.el("p", { class: "sub", text: t.desc }));
      if (t.installed) {
        const row = N.el("div", { class: "path-input" });
        const input = N.el("input", { type: "text", placeholder: "path under your home directory to scan" });
        const btn = N.el("button", { class: "ghost", text: "Run" });
        const pre = N.el("pre", { class: "term mt hidden" });
        btn.addEventListener("click", async () => {
          const p = input.value.trim();
          if (!p) { N.toast("enter a path", "bad"); return; }
          btn.disabled = true;
          pre.classList.remove("hidden");
          pre.textContent = "running...";
          try {
            const r = await N.post("/api/local-tool", { tool: t.key, path: p });
            pre.textContent = `exit ${r.returncode} · ${r.duration}s\n\n` + (r.stdout || r.stderr || "(no output)");
          } catch (e) {
            pre.textContent = "REFUSED: " + (e.body && e.body.error ? e.body.error : e.message);
          } finally {
            btn.disabled = false;
          }
        });
        row.appendChild(input);
        row.appendChild(btn);
        card.appendChild(row);
        card.appendChild(pre);
      } else {
        const link = N.el("a", { href: N.safeUrl(t.github), target: "_blank", rel: "noopener", text: t.github });
        card.appendChild(link);
        card.appendChild(N.el("p", { class: "faint", text: `pipx install "git+${t.github}.git"` }));
      }
      wrap.appendChild(card);
    });
  }

  // ------------------------------------------------------------------
  // History
  // ------------------------------------------------------------------
  async function loadHistory() {
    let j;
    try { j = await N.get("/api/history"); } catch (e) { return; }
    const tbody = document.querySelector("#hist-table tbody");
    tbody.innerHTML = "";
    const empty = document.getElementById("hist-empty");
    if (!j.runs.length) { empty.classList.remove("hidden"); return; }
    empty.classList.add("hidden");
    j.runs.forEach(r => {
      const tr = N.el("tr");
      tr.appendChild(N.el("td", { class: "mono small muted", text: r.ts || "" }));
      tr.appendChild(N.el("td", { text: r.tool || "" }));
      tr.appendChild(N.el("td", { class: "mono small", text: r.target || "" }));
      tr.appendChild(N.el("td", { text: r.authorized ? "yes" : "no" }));
      tr.appendChild(N.el("td", { text: r.lab ? "yes" : "no" }));
      tr.appendChild(N.el("td", { text: String(r.returncode) }));
      tr.appendChild(N.el("td", { text: (r.duration != null ? r.duration + "s" : "") + (r.timed_out ? " (timeout)" : "") }));
      tbody.appendChild(tr);
    });
  }

  // ------------------------------------------------------------------
  // Saved outputs (feature-detected: hidden if /api/outputs isn't there yet)
  // ------------------------------------------------------------------
  function outputMtimeKey(m) {
    if (typeof m === "number") return m;
    const parsed = Date.parse(m);
    return isNaN(parsed) ? 0 : parsed;
  }

  function outputMtimeLabel(m) {
    if (m === undefined || m === null || m === "") return "";
    if (typeof m === "number") {
      const d = new Date(m < 2e10 ? m * 1000 : m); // heuristic: seconds vs ms epoch
      return isNaN(d.getTime()) ? String(m) : d.toLocaleString();
    }
    const d = new Date(m);
    return isNaN(d.getTime()) ? String(m) : d.toLocaleString();
  }

  async function loadOutputs() {
    let j;
    try { j = await N.get("/api/outputs"); } catch (e) { return; } // not implemented (yet) — stay quiet
    document.getElementById("outputs-wrap").classList.remove("hidden");
    const files = (j.files || []).slice().sort((a, b) => outputMtimeKey(b.mtime) - outputMtimeKey(a.mtime));
    const list = document.getElementById("outputs-list");
    const empty = document.getElementById("outputs-empty");
    list.innerHTML = "";
    if (!files.length) { empty.classList.remove("hidden"); return; }
    empty.classList.add("hidden");
    files.forEach(f => {
      const row = N.el("div", { class: "output-row" });
      row.appendChild(N.el("span", { class: "mono", text: f.name || "" }));
      row.appendChild(N.el("span", { class: "src-badge", text: f.tool || "" }));
      row.appendChild(N.el("span", { class: "faint small", text: f.size != null ? (f.size / 1024).toFixed(1) + "KB" : "" }));
      row.appendChild(N.el("span", { class: "faint small", text: outputMtimeLabel(f.mtime) }));
      const viewBtn = N.el("button", { class: "ghost", type: "button", text: "View" });
      viewBtn.addEventListener("click", () => viewOutput(f.name));
      row.appendChild(viewBtn);
      list.appendChild(row);
    });
  }

  async function fetchOutputFile(name) {
    const r = await fetch("/api/output-file?name=" + encodeURIComponent(name), { headers: { "Accept": "text/plain" } });
    const t = await r.text();
    if (!r.ok) throw new Error(t || r.statusText);
    return t;
  }

  async function viewOutput(name) {
    const pre = document.getElementById("outputs-view");
    pre.classList.remove("hidden");
    pre.textContent = "loading…";
    try {
      // raw file contents via textContent — never innerHTML — so a saved
      // output can't inject markup even if it were attacker-influenced
      pre.textContent = (await fetchOutputFile(name)) || "(empty)";
    } catch (e) {
      pre.textContent = "error: " + (e.message || "load failed");
    }
  }
})();
