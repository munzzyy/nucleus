(function () {
  "use strict";
  const N = window.Nucleus;
  const TABS = ["run", "web", "stress", "password", "arsenal", "build", "tools", "history", "expert"];
  let INV = null;          // last /api/inventory payload
  let ACTIVE_CAT = "";
  let INV_SEARCH = "";
  let EXPANDED = new Set(); // categories the user has manually opened in the arsenal accordion
  let WL_SEARCH_TIMER = null;
  let WL_SEARCH_SEQ = 0;   // monotonic id — drops a stale wordlist response if a newer query already started
  let runTickerId = null;
  let expertTickerId = null;

  // -- last-used target, remembered across tabs/reloads --------------------
  const LAST_TARGET_KEY = "nucleus.redcell.lastTarget";
  let LAST_TARGET = "";
  try { LAST_TARGET = localStorage.getItem(LAST_TARGET_KEY) || ""; } catch (_) { /* storage blocked — stay in-memory */ }

  function setLastTarget(v) {
    LAST_TARGET = v || "";
    try { localStorage.setItem(LAST_TARGET_KEY, LAST_TARGET); } catch (_) { /* ignore */ }
  }

  // Any input that should remember/share the last-used target: fills it from
  // LAST_TARGET on load (only if the field is empty) and writes back on input.
  function wireTargetField(id) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!el.value && LAST_TARGET) el.value = LAST_TARGET;
    el.addEventListener("input", () => setLastTarget(el.value.trim()));
  }

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
    wireRecipes();
    wireBuilder();
    wireArsenal();
    wireExpert();
    wireWebTab();
    wireStressTab();
    wirePasswordTab();
    wireTargetField("run-target");
    wireTargetField("web-target");
    wireTargetField("web-analyze-target");
    wireTargetField("secret-scan-target");
    wireTargetField("stress-probe-target");
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
    if (tab === "web") loadPlaybooks();
    if (tab === "password") loadWordlistBrowserDefault();
  }

  // ------------------------------------------------------------------
  // Authorization gate — the Run tab's g-authorized/g-lab and the Web tab's
  // w-authorized/w-lab are two DOM checkboxes sharing one logical state
  // (server-side enforcement doesn't care which pair was checked; this just
  // keeps the UI honest so checking one doesn't leave the other tab's copy
  // looking unauthorized). Client-side UX only — the real gate is server-side.
  // ------------------------------------------------------------------
  function wireAuthGate() {
    // Every tab's authorization/lab/opsec checkbox mirrors the Run tab's canonical
    // g-* box, so checking the gate on one tab keeps the others honest. Server-side
    // enforcement doesn't care which was checked — this is UI consistency only.
    const groups = [
      ["g-authorized", "w-authorized", "s-authorized"],
      ["g-lab", "w-lab", "s-lab"],
      ["g-proceed-exposed", "w-proceed-exposed", "s-proceed-exposed"],
    ];
    groups.forEach(ids => {
      const els = ids.map(id => document.getElementById(id)).filter(Boolean);
      els.forEach(el => el.addEventListener("change", () => {
        els.forEach(other => { if (other !== el) other.checked = el.checked; });
        syncGateButtons();
      }));
    });
    syncGateButtons();
  }

  function gateChecked() { return document.getElementById("g-authorized").checked; }
  function labChecked() { return document.getElementById("g-lab").checked; }

  // OpSec override: the server refuses a scan while your real IP is exposed
  // unless proceed_exposed is set. Any of the "scan anyway" boxes (Run / Web /
  // Expert) flips it — it's a session-level "I accept being exposed" ack.
  function opsecOverride() {
    return ["g-proceed-exposed", "w-proceed-exposed", "s-proceed-exposed", "x-proceed-exposed"].some(id => {
      const el = document.getElementById(id);
      return el && el.checked;
    });
  }

  function syncGateButtons() {
    document.getElementById("run-btn").disabled = !gateChecked();
    const analyzeBtn = document.getElementById("web-analyze-btn");
    if (analyzeBtn) analyzeBtn.disabled = !gateChecked();
    const secretBtn = document.getElementById("secret-scan-btn");
    if (secretBtn) secretBtn.disabled = !gateChecked();
    const stressBtn = document.getElementById("stress-probe-btn");
    if (stressBtn) stressBtn.disabled = !gateChecked();
    const tlsBtn = document.getElementById("tls-audit-btn");
    if (tlsBtn) tlsBtn.disabled = !gateChecked();
    const techBtn = document.getElementById("techfp-btn");
    if (techBtn) techBtn.disabled = !gateChecked();
    refreshPlaybookRunButton();
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
        proceed_exposed: opsecOverride(),
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

  // Quick-start recipe buttons: point the tool select at a sensible default
  // and hand focus to the target field. Tool keys are fixed strings that
  // match SAFE_RUNNERS on the server — if the inventory hasn't loaded yet (or
  // that tool isn't in this box's inventory for some reason) the click is a
  // harmless no-op with a toast, never a crash.
  function wireRecipes() {
    document.querySelectorAll("#run-recipes .recipe-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const tool = btn.getAttribute("data-tool");
        const sel = document.getElementById("run-tool");
        const hasTool = Array.from(sel.options).some(o => o.value === tool);
        if (!hasTool) { N.toast("tool inventory still loading — try again in a second", "bad"); return; }
        sel.value = tool;
        renderRunnerDetail();
        document.getElementById("run-target").focus();
      });
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

    const body = { tool: spec.key, target, authorized, lab, proceed_exposed: opsecOverride() };
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
  // Command builder (exec-free) — a small factory so the full Build tab and
  // the Password tab's hashcat/john-scoped builder share one implementation
  // instead of two near-identical copies. `ids` names the DOM elements;
  // `filterFn` (optional) narrows which INV.build_tools entries this panel
  // offers — the Password tab only wants hashcat + john.
  // ------------------------------------------------------------------
  function makeBuilderPanel(ids, filterFn) {
    function tools() {
      return (INV.build_tools || []).filter(b => !filterFn || filterFn(b));
    }
    function currentSpec() {
      const key = document.getElementById(ids.select).value;
      return tools().find(b => b.key === key);
    }
    function renderSelect() {
      const sel = document.getElementById(ids.select);
      const prev = sel.value;
      sel.innerHTML = "";
      tools().forEach(b => sel.appendChild(N.el("option", { value: b.key, text: b.key })));
      if (prev && tools().some(b => b.key === prev)) sel.value = prev;
      sel.onchange = renderFields;
      renderFields();
    }
    function renderFields() {
      const spec = currentSpec();
      const wrap = document.getElementById(ids.fields);
      const descEl = document.getElementById(ids.desc);
      const noteEl = document.getElementById(ids.note);
      wrap.innerHTML = "";
      document.getElementById(ids.resultWrap).classList.add("hidden");
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
    function wire() {
      document.getElementById(ids.buildBtn).addEventListener("click", build);
      document.getElementById(ids.copyBtn).addEventListener("click", () => {
        const text = document.getElementById(ids.result).textContent;
        navigator.clipboard.writeText(text).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
      });
    }
    async function build() {
      const spec = currentSpec();
      if (!spec) return;
      const params = {};
      document.querySelectorAll(`#${ids.fields} [data-field]`).forEach(el => {
        params[el.getAttribute("data-field")] = el.type === "checkbox" ? el.checked : el.value;
      });
      try {
        const r = await N.post("/api/build", { tool: spec.key, params });
        document.getElementById(ids.result).textContent = r.command;
        document.getElementById(ids.resultWrap).classList.remove("hidden");
      } catch (e) {
        N.toast("build failed: " + e.message, "bad");
      }
    }
    // Select a tool by key and pre-fill one of its fields (used by the hash
    // identifier's "use this mode" affordance) — renders fields first so the
    // input actually exists before we touch its value.
    function selectToolAndFill(key, fieldName, value) {
      const sel = document.getElementById(ids.select);
      if (!Array.from(sel.options).some(o => o.value === key)) return false;
      sel.value = key;
      renderFields();
      const input = document.querySelector(`#${ids.fields} [data-field="${fieldName}"]`);
      if (input) input.value = value;
      return true;
    }
    return { renderSelect, renderFields, wire, selectToolAndFill };
  }

  const buildPanel = makeBuilderPanel({
    select: "build-tool", desc: "build-desc", note: "build-note", fields: "build-fields",
    buildBtn: "build-btn", resultWrap: "build-result-wrap", result: "build-result", copyBtn: "build-copy",
  });
  const pwBuildPanel = makeBuilderPanel({
    select: "pw-build-tool", desc: "pw-build-desc", note: "pw-build-note", fields: "pw-build-fields",
    buildBtn: "pw-build-btn", resultWrap: "pw-build-result-wrap", result: "pw-build-result", copyBtn: "pw-build-copy",
  }, b => b.key === "hashcat" || b.key === "john");

  function renderBuilderSelect() { buildPanel.renderSelect(); pwBuildPanel.renderSelect(); }

  function wireBuilder() { buildPanel.wire(); pwBuildPanel.wire(); }

  // ------------------------------------------------------------------
  // Web tab — website assessment playbooks + the quick header/CORS analyzer.
  // Playbooks are pure data from the server; the browser walks the steps and
  // calls the same gated endpoints (/api/web-analyze, /api/run) a manual run
  // would use, sequentially, one at a time.
  // ------------------------------------------------------------------
  let PLAYBOOKS = [];
  let PLAYBOOKS_LOADED = false;
  let PB_SELECTED = null;   // the chosen playbook object, or null
  let PB_WORDLIST_ID = "";
  let PB_RUNNING = false;

  function wireWebTab() {
    const analyzeBtn = document.getElementById("web-analyze-btn");
    analyzeBtn.addEventListener("click", runWebAnalyze);
    document.getElementById("web-analyze-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !analyzeBtn.disabled) runWebAnalyze();
    });
    const secretBtn = document.getElementById("secret-scan-btn");
    secretBtn.addEventListener("click", runSecretScan);
    document.getElementById("secret-scan-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !secretBtn.disabled) runSecretScan();
    });
    document.getElementById("web-target").addEventListener("input", refreshPlaybookRunButton);

    const tlsBtn = document.getElementById("tls-audit-btn");
    tlsBtn.addEventListener("click", runTlsAudit);
    document.getElementById("tls-audit-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !tlsBtn.disabled) runTlsAudit();
    });
    const techBtn = document.getElementById("techfp-btn");
    techBtn.addEventListener("click", runTechFingerprint);
    document.getElementById("techfp-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !techBtn.disabled) runTechFingerprint();
    });
    const jwtBtn = document.getElementById("jwt-btn");  // offline, never gated
    jwtBtn.addEventListener("click", runJwtAudit);
    document.getElementById("jwt-input").addEventListener("keydown", e => {
      if (e.key === "Enter") runJwtAudit();
    });
  }

  async function loadPlaybooks() {
    if (PLAYBOOKS_LOADED) return;
    try {
      const j = await N.get("/api/playbooks");
      PLAYBOOKS = j.playbooks || [];
      PLAYBOOKS_LOADED = true;
      renderPlaybookCards();
    } catch (e) { N.toast("playbooks load failed: " + e.message, "bad"); }
  }

  function renderPlaybookCards() {
    const wrap = document.getElementById("playbook-cards");
    wrap.innerHTML = "";
    PLAYBOOKS.forEach(pb => {
      const card = N.el("button", {
        type: "button",
        class: "card playbook-card" + (PB_SELECTED && PB_SELECTED.key === pb.key ? " active" : ""),
      });
      card.addEventListener("click", () => selectPlaybook(pb.key));
      const head = N.el("div", { class: "playbook-card-head" });
      head.appendChild(N.el("strong", { text: pb.name }));
      head.appendChild(N.el("span", { class: "tag", text: pb.target_kind === "host" ? "host/domain" : "url" }));
      card.appendChild(head);
      card.appendChild(N.el("p", { class: "sub", text: pb.desc }));
      const n = pb.steps.length;
      card.appendChild(N.el("span", { class: "faint small", text:
        `${n} step${n === 1 ? "" : "s"}` + (pb.needs_wordlist ? " · needs a wordlist" : "") }));
      wrap.appendChild(card);
    });
  }

  function selectPlaybook(key) {
    PB_SELECTED = PLAYBOOKS.find(p => p.key === key) || null;
    PB_WORDLIST_ID = "";
    renderPlaybookCards();
    renderPlaybookRunPanel();
  }

  function refreshPlaybookRunButton() {
    const btn = document.getElementById("pb-start-btn");
    if (!btn || PB_RUNNING) return;
    const targetEl = document.getElementById("web-target");
    const target = targetEl ? targetEl.value.trim() : "";
    let ok = !!PB_SELECTED && !!target && gateChecked();
    if (PB_SELECTED && PB_SELECTED.needs_wordlist && !PB_WORDLIST_ID) ok = false;
    btn.disabled = !ok;
  }

  function renderPlaybookRunPanel() {
    const wrap = document.getElementById("playbook-run");
    wrap.innerHTML = "";
    if (!PB_SELECTED) { wrap.classList.add("hidden"); return; }
    wrap.classList.remove("hidden");
    const pb = PB_SELECTED;

    const panel = N.el("div", { class: "playbook-panel" });
    const head = N.el("div", { class: "panel-head" });
    head.appendChild(N.el("h3", { class: "m0", text: pb.name }));
    const closeBtn = N.el("button", { type: "button", class: "ghost", text: "Close" });
    closeBtn.addEventListener("click", () => { PB_SELECTED = null; renderPlaybookCards(); renderPlaybookRunPanel(); });
    head.appendChild(closeBtn);
    panel.appendChild(head);

    if (pb.needs_wordlist) {
      const wlRow = N.el("div", { class: "row mt" });
      const searchField = N.el("div", { class: "field grow-2" });
      searchField.appendChild(N.el("label", { text: "Wordlist search" }));
      const searchInput = N.el("input", { type: "text", placeholder: "type to filter, e.g. 'common'…" });
      searchField.appendChild(searchInput);
      const selField = N.el("div", { class: "field w-320" });
      selField.appendChild(N.el("label", { text: "Wordlist" }));
      const wlSelect = N.el("select");
      selField.appendChild(wlSelect);
      wlRow.appendChild(searchField);
      wlRow.appendChild(selField);
      panel.appendChild(wlRow);

      const fillWl = results => {
        wlSelect.innerHTML = "";
        results.forEach(w => wlSelect.appendChild(N.el("option", {
          value: w.id, text: `${w.label}  (${w.root}, ${(w.size / 1024).toFixed(1)}KB)`,
        })));
        PB_WORDLIST_ID = wlSelect.value || "";
        refreshPlaybookRunButton();
      };
      N.get("/api/wordlists?limit=50").then(r => fillWl(r.results || [])).catch(() => fillWl([]));
      wlSelect.addEventListener("change", () => { PB_WORDLIST_ID = wlSelect.value; refreshPlaybookRunButton(); });
      let wlTimer = null, wlSeq = 0;
      searchInput.addEventListener("input", e => {
        const q = e.target.value.trim();
        clearTimeout(wlTimer);
        wlTimer = setTimeout(async () => {
          const seq = ++wlSeq;
          try {
            const r = await N.get("/api/wordlists?q=" + encodeURIComponent(q) + "&limit=50");
            if (seq !== wlSeq) return;
            fillWl(r.results || []);
          } catch (_) { /* keep previous list */ }
        }, 200);
      });
    }

    const steps = N.el("div", { class: "pb-steps" });
    const stepEls = [];
    pb.steps.forEach(step => {
      const row = N.el("div", { class: "pb-step" });
      const headRow = N.el("div", { class: "pb-step-head" });
      const label = N.el("label", { class: "checkline" });
      const cb = N.el("input", { type: "checkbox" });
      if (step.optional) { cb.checked = false; } else { cb.checked = true; cb.disabled = true; }
      label.appendChild(cb);
      label.appendChild(N.el("span", { text: step.label + (step.optional ? " (optional)" : "") }));
      headRow.appendChild(label);
      headRow.appendChild(N.el("span", { class: "pill pb-status", text: "pending" }));
      row.appendChild(headRow);
      if (step.note) row.appendChild(N.el("p", { class: "sub pb-step-note", text: step.note }));
      const resultBox = N.el("div", { class: "pb-step-result hidden" });
      row.appendChild(resultBox);
      steps.appendChild(row);
      stepEls.push({ step, checkbox: cb, statusPill: headRow.lastChild, resultBox, ticker: null });
    });
    panel.appendChild(steps);

    const startBtn = N.el("button", { type: "button", id: "pb-start-btn", text: "Start assessment" });
    startBtn.addEventListener("click", () => runPlaybook(pb, stepEls, startBtn));
    panel.appendChild(startBtn);
    panel.appendChild(N.el("div", { class: "mt hidden", id: "pb-summary" }));

    wrap.appendChild(panel);
    refreshPlaybookRunButton();
  }

  // A playbook fans ONE typed target across steps whose runners disagree on
  // shape: url-kind tools (whatweb, nuclei, web-analyze, secret-scan) want a
  // full URL; host-kind tools (httpx, sslscan, testssl, subfinder…) want a
  // bare hostname. Derive the right form per step so the user can type either.
  function targetForKind(shared, kind) {
    const t = (shared || "").trim();
    if (kind === "host") {
      if (/^https?:\/\//i.test(t)) { try { return new URL(t).hostname; } catch (e) { return t; } }
      return t;
    }
    // url-kind (and the native analyzers) want a scheme
    return /^https?:\/\//i.test(t) ? t : "https://" + t;
  }

  function runnerKind(toolKey) {
    const r = (INV && INV.safe_runners || []).find(x => x.key === toolKey);
    return r ? r.kind : "url";
  }

  async function runPlaybook(pb, stepEls, startBtn) {
    if (PB_RUNNING) return;
    PB_RUNNING = true;
    startBtn.disabled = true;
    startBtn.textContent = "Running…";
    const summaryEl = document.getElementById("pb-summary");
    summaryEl.classList.add("hidden");
    const target = document.getElementById("web-target").value.trim();
    const authorized = gateChecked();
    const lab = labChecked();
    const agg = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ran: [] };

    for (const se of stepEls) {
      if (!se.checkbox.checked) {
        se.statusPill.textContent = "skipped";
        se.statusPill.className = "pill pb-status";
        continue;
      }
      se.statusPill.className = "pill pb-status warn";
      const started = Date.now();
      se.statusPill.textContent = "running — 0.0s";
      se.ticker = setInterval(() => {
        se.statusPill.textContent = `running — ${((Date.now() - started) / 1000).toFixed(1)}s`;
      }, 200);
      try {
        let node;
        if (se.step.kind === "web-analyze") {
          const r = await N.post("/api/web-analyze", { url: targetForKind(target, "url"), authorized, lab, proceed_exposed: opsecOverride() });
          if (r.ok === false) throw Object.assign(new Error(r.error || "analysis failed"), { body: r });
          agg.high += r.counts.high; agg.medium += r.counts.medium; agg.low += r.counts.low;
          agg.ran.push(`header/CORS analysis: grade ${r.grade}`);
          node = buildAnalyzeCard(r);
        } else if (se.step.kind === "secret-scan") {
          const r = await N.post("/api/secret-scan", { url: targetForKind(target, "url"), authorized, lab, proceed_exposed: opsecOverride() });
          if (r.ok === false) throw Object.assign(new Error(r.error || "secret scan failed"), { body: r });
          agg.critical += r.counts.critical || 0; agg.high += r.counts.high || 0;
          agg.medium += r.counts.medium || 0; agg.low += r.counts.low || 0; agg.info += r.counts.info || 0;
          const leaks = r.real_leak_count || 0;
          agg.ran.push(`secret scan: ${leaks} real leak${leaks === 1 ? "" : "s"}`);
          node = buildSecretScanCard(r);
        } else {
          const stepTarget = targetForKind(target, runnerKind(se.step.tool));
          const body = { tool: se.step.tool, target: stepTarget, authorized, lab, options: se.step.options || {}, proceed_exposed: opsecOverride() };
          if (se.step.needs_wordlist) body.wordlist = PB_WORDLIST_ID;
          const r = await N.post("/api/run", body);
          node = buildRunResultNode(r);
          const hasOutput = !!(r.stdout && r.stdout.trim());
          agg.ran.push(`${se.step.tool}: ${hasOutput ? "returned output" : "no output"}`);
        }
        clearInterval(se.ticker); se.ticker = null;
        se.statusPill.textContent = "done";
        se.statusPill.className = "pill pb-status ok";
        se.resultBox.innerHTML = "";
        const body = N.el("div", { class: "pb-step-body hidden" });
        body.appendChild(node);
        const toggle = N.el("button", { type: "button", class: "ghost small", text: "Show result" });
        toggle.addEventListener("click", () => {
          const nowHidden = body.classList.toggle("hidden");
          toggle.textContent = nowHidden ? "Show result" : "Hide result";
        });
        se.resultBox.appendChild(toggle);
        se.resultBox.appendChild(body);
        se.resultBox.classList.remove("hidden");
      } catch (e) {
        clearInterval(se.ticker); se.ticker = null;
        se.statusPill.textContent = "failed";
        se.statusPill.className = "pill pb-status bad";
        se.resultBox.innerHTML = "";
        se.resultBox.appendChild(N.el("p", { class: "sub", text:
          "error: " + ((e.body && e.body.error) ? e.body.error : e.message) }));
        se.resultBox.classList.remove("hidden");
        agg.ran.push(`${stepKindLabel(se.step)}: failed`);
      }
    }

    renderPlaybookSummary(agg);
    PB_RUNNING = false;
    startBtn.textContent = "Run again";
    refreshPlaybookRunButton();
  }

  function stepKindLabel(step) {
    if (step.kind === "web-analyze") return "header/CORS analysis";
    if (step.kind === "secret-scan") return "secret scan";
    return step.tool || "step";
  }

  function renderPlaybookSummary(agg) {
    const el = document.getElementById("pb-summary");
    el.innerHTML = "";
    el.classList.remove("hidden");
    el.appendChild(N.el("div", { class: "section-title", text: "Findings summary" }));
    const counts = N.el("div", { class: "row" });
    [["critical", agg.critical], ["high", agg.high], ["medium", agg.medium], ["low", agg.low], ["info", agg.info]]
      .forEach(([sev, n]) => counts.appendChild(N.el("span", { class: "pill " + severityPillClass(sev) },
        [N.el("span", { class: "dot" }), document.createTextNode(`${n} ${sev}`)])));
    el.appendChild(counts);
    el.appendChild(N.el("p", { class: "sub mt-8", text: agg.ran.join(" · ") || "no steps ran" }));
  }

  // $ argv header + raw stdout/stderr, same shape as the Run tab's own
  // output rendering — reused so a playbook's runner steps look identical to
  // running the tool by hand. Everything from the tool goes through
  // textContent, never innerHTML.
  function buildRunResultNode(r) {
    const wrap = N.el("div");
    wrap.appendChild(N.el("p", { class: "sub", text:
      `exit ${r.returncode} · ${r.duration}s` + (r.timed_out ? " · TIMED OUT" : "") }));
    const pre = N.el("pre", { class: "term" });
    let text = "$ " + (r.argv || []).map(a => (/\s/.test(a) ? `'${a}'` : a)).join(" ") + "\n\n";
    text += (r.stdout || "").trim();
    if (r.stderr && r.stderr.trim()) text += "\n\n[stderr]\n" + r.stderr.trim();
    if (r.error) text += "\n\n[error] " + r.error;
    if (r.out_path) text += "\n\n[saved] " + r.out_path;
    pre.textContent = text || "(no output)";
    wrap.appendChild(pre);
    return wrap;
  }

  async function runWebAnalyze() {
    const target = document.getElementById("web-analyze-target").value.trim();
    const status = document.getElementById("web-analyze-status");
    const resultWrap = document.getElementById("web-analyze-result");
    if (!target) { N.toast("enter a URL first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    const btn = document.getElementById("web-analyze-btn");
    btn.disabled = true;
    status.textContent = "analyzing…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const r = await N.post("/api/web-analyze", { url: target, authorized: gateChecked(), lab: labChecked(), proceed_exposed: opsecOverride() });
      status.textContent = "";
      resultWrap.appendChild(buildAnalyzeCard(r));
    } catch (e) {
      status.textContent = "refused";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("refused: " + (e.body && e.body.error ? e.body.error : e.message))]));
      N.toast("analyze refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = !gateChecked();
    }
  }

  async function runSecretScan() {
    const target = document.getElementById("secret-scan-target").value.trim();
    const status = document.getElementById("secret-scan-status");
    const resultWrap = document.getElementById("secret-scan-result");
    if (!target) { N.toast("enter a URL first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    const btn = document.getElementById("secret-scan-btn");
    btn.disabled = true;
    status.textContent = "scanning page + same-site JS…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const deep = !!document.getElementById("secret-scan-deep") && document.getElementById("secret-scan-deep").checked;
      const r = await N.post("/api/secret-scan", { url: target, authorized: gateChecked(), lab: labChecked(), deep, proceed_exposed: opsecOverride() });
      status.textContent = "";
      resultWrap.appendChild(buildSecretScanCard(r));
    } catch (e) {
      status.textContent = "refused";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("refused: " + (e.body && e.body.error ? e.body.error : e.message))]));
      N.toast("secret scan refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = !gateChecked();
    }
  }

  // ------------------------------------------------------------------
  // TLS deep-audit / tech fingerprint / JWT analyzer — the native tools
  // added alongside the header/CORS analyzer and secret scanner.
  // ------------------------------------------------------------------
  function gradePillClass(grade) {
    if (grade === "A" || grade === "B") return "ok";
    if (grade === "C") return "warn";
    return "bad";  // D / F
  }

  function buildFindingList(findings) {
    const wrap = N.el("div", { class: "mt-8" });
    if (!findings || !findings.length) {
      wrap.appendChild(N.el("p", { class: "sub", text: "No issues flagged." }));
      return wrap;
    }
    findings.forEach(f => {
      const row = N.el("div", { class: "finding-row sev-" + N.esc(f.severity) });
      const head = N.el("div");
      head.appendChild(N.el("span", { class: "pill " + severityPillClass(f.severity), text: f.severity }));
      head.appendChild(document.createTextNode(" "));
      head.appendChild(N.el("strong", { text: f.title }));
      row.appendChild(head);
      if (f.detail) row.appendChild(N.el("p", { class: "sub", text: f.detail }));
      wrap.appendChild(row);
    });
    return wrap;
  }

  function buildTlsCard(r) {
    const wrap = N.el("div", { class: "card" });
    if (!r.ok) {
      wrap.appendChild(N.el("p", { class: "sub", text: "TLS audit failed: " + (r.error || "unknown") }));
      return wrap;
    }
    wrap.appendChild(N.el("div", {}, [
      N.el("span", { class: "pill " + gradePillClass(r.grade), text: "Grade " + r.grade }),
      document.createTextNode(`  ${r.score_pct}%  ·  ${r.host} (${r.resolved_ip})`),
    ]));
    const parts = [];
    Object.entries(r.protocols || {}).forEach(([label, p]) => {
      const state = p.accepted === true ? "accepted" : p.accepted === false ? "refused" : "?";
      parts.push(`${label}: ${state}`);
    });
    if (parts.length) wrap.appendChild(N.el("p", { class: "sub mono small mt-8", text: parts.join("   ·   ") }));
    const c = r.cert || {};
    const certBits = [`issuer ${c.issuer || "?"}`, c.trusted ? "trusted" : "UNTRUSTED"];
    if (c.self_signed) certBits.push("self-signed");
    if (c.hostname_ok === false) certBits.push("name mismatch");
    if (c.days_left != null) certBits.push(`${c.days_left}d left`);
    if (c.subject_cn) certBits.push(`CN ${c.subject_cn}`);
    wrap.appendChild(N.el("p", { class: "sub mono small", text: "cert: " + certBits.join(" · ") }));
    wrap.appendChild(buildFindingList(r.findings));
    return wrap;
  }

  function buildTechCard(r) {
    const wrap = N.el("div", { class: "card" });
    if (!r.ok) {
      wrap.appendChild(N.el("p", { class: "sub", text: "Fingerprint failed: " + (r.error || "unknown") }));
      return wrap;
    }
    wrap.appendChild(N.el("p", { class: "sub", text: `${r.count} technolog${r.count === 1 ? "y" : "ies"} detected` }));
    const list = N.el("div", { class: "mt-8" });
    (r.technologies || []).forEach(t => {
      const row = N.el("div", { class: "finding-row" });
      const head = N.el("div");
      head.appendChild(N.el("strong", { text: t.name }));
      head.appendChild(document.createTextNode(`  —  ${t.category} · ${t.confidence} confidence`));
      row.appendChild(head);
      if (Array.isArray(t.evidence) && t.evidence.length) {
        row.appendChild(N.el("p", { class: "sub mono small", text: t.evidence.join(" ; ") }));
      }
      list.appendChild(row);
    });
    wrap.appendChild(list);
    return wrap;
  }

  function buildJwtCard(r) {
    const wrap = N.el("div", { class: "card" });
    if (!r.ok) {
      wrap.appendChild(N.el("p", { class: "sub", text: "Not a valid JWT: " + (r.error || "decode failed") }));
      return wrap;
    }
    wrap.appendChild(N.el("p", { class: "sub", text: "alg: " + (r.alg || "?") }));
    const pre = N.el("pre", { class: "term" });
    pre.textContent = "header:\n" + JSON.stringify(r.header, null, 2) +
      "\n\nclaims:\n" + JSON.stringify(r.payload, null, 2);
    wrap.appendChild(pre);
    wrap.appendChild(buildFindingList(r.findings));
    if (r.crack && (r.crack.hashcat || r.crack.john)) {
      wrap.appendChild(N.el("p", { class: "sub mt-8", text: "Offline crack commands — build-only, never run:" }));
      [r.crack.hashcat, r.crack.john].forEach(cmd => {
        if (cmd) { const p = N.el("pre", { class: "term" }); p.textContent = cmd; wrap.appendChild(p); }
      });
    }
    return wrap;
  }

  async function runTlsAudit() {
    const target = document.getElementById("tls-audit-target").value.trim();
    const status = document.getElementById("tls-audit-status");
    const resultWrap = document.getElementById("tls-audit-result");
    if (!target) { N.toast("enter a host first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    const btn = document.getElementById("tls-audit-btn");
    btn.disabled = true;
    status.textContent = "handshaking TLS 1.0–1.3…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const r = await N.post("/api/tls-audit", { host: target, authorized: gateChecked(), lab: labChecked(), proceed_exposed: opsecOverride() });
      status.textContent = "";
      resultWrap.appendChild(buildTlsCard(r));
    } catch (e) {
      status.textContent = "refused";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("refused: " + (e.body && e.body.error ? e.body.error : e.message))]));
      N.toast("TLS audit refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = !gateChecked();
    }
  }

  async function runTechFingerprint() {
    const target = document.getElementById("techfp-target").value.trim();
    const status = document.getElementById("techfp-status");
    const resultWrap = document.getElementById("techfp-result");
    if (!target) { N.toast("enter a URL first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    const btn = document.getElementById("techfp-btn");
    btn.disabled = true;
    status.textContent = "fetching + fingerprinting…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const r = await N.post("/api/tech-fingerprint", { url: target, authorized: gateChecked(), lab: labChecked(), proceed_exposed: opsecOverride() });
      status.textContent = "";
      resultWrap.appendChild(buildTechCard(r));
    } catch (e) {
      status.textContent = "refused";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("refused: " + (e.body && e.body.error ? e.body.error : e.message))]));
      N.toast("fingerprint refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = !gateChecked();
    }
  }

  async function runJwtAudit() {
    const token = document.getElementById("jwt-input").value.trim();
    const status = document.getElementById("jwt-status");
    const resultWrap = document.getElementById("jwt-result");
    if (!token) { N.toast("paste a JWT first", "bad"); return; }
    const btn = document.getElementById("jwt-btn");
    btn.disabled = true;
    status.textContent = "decoding…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const r = await N.post("/api/jwt-audit", { token });
      status.textContent = "";
      resultWrap.appendChild(buildJwtCard(r));
    } catch (e) {
      status.textContent = "error";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("error: " + (e.body && e.body.error ? e.body.error : e.message))]));
    } finally {
      btn.disabled = false;
    }
  }

  // Severity scale shared by the header/CORS analyzer (high/medium/low) and
  // the secret scanner (critical/high/medium/low/info) — one place to keep
  // the color mapping consistent across both.
  function severityPillClass(sev) {
    if (sev === "critical") return "critical";
    if (sev === "high") return "bad";
    if (sev === "medium") return "warn";
    if (sev === "info") return "info";
    return "low";
  }

  // Findings go back from the server with the full secret already in `match`
  // (see secretscan.py — masking is a report-formatting concern, not a
  // transport-secrecy one: this box already saw the page). The UI still only
  // ever puts `masked` in the DOM up front; `match` is rendered — via
  // textContent, never innerHTML — only after an explicit per-finding click,
  // so a secret can't be shoulder-surfed or screen-shared by accident.
  function buildSecretFindingRow(f) {
    const row = N.el("div", { class: "secret-finding" + (f.public_ok ? " public-ok" : "") });

    const head = N.el("div", { class: "secret-finding-head" });
    head.appendChild(N.el("span", { class: "pill " + severityPillClass(f.severity), text: f.severity }));
    head.appendChild(N.el("strong", { text: f.rule }));
    head.appendChild(N.el("span", { class: "faint small", text: `confidence: ${f.confidence} · entropy ${f.entropy}` }));
    row.appendChild(head);

    let sourceText = "source: " + f.source;
    if (Array.isArray(f.also_in) && f.also_in.length) {
      sourceText += "  ·  also in " + f.also_in.length + " more location" + (f.also_in.length === 1 ? "" : "s");
    }
    const sourceEl = N.el("p", { class: "sub mono small", text: sourceText });
    if (Array.isArray(f.also_in) && f.also_in.length) sourceEl.title = f.also_in.join("\n");
    row.appendChild(sourceEl);
    if (f.note) row.appendChild(N.el("p", { class: "sub build-note", text: f.note }));

    // Decoded JWT claims (offline, no network) — issuer/subject/expiry at a glance.
    if (f.jwt && f.jwt.payload) {
      const p = f.jwt.payload;
      const bits = [];
      if (p.iss) bits.push("iss=" + p.iss);
      if (p.sub) bits.push("sub=" + p.sub);
      if (p.aud) bits.push("aud=" + (Array.isArray(p.aud) ? p.aud.join(",") : p.aud));
      if (p.exp) { const d = new Date(p.exp * 1000); bits.push("exp=" + d.toISOString().slice(0, 19) + (d < new Date() ? " (EXPIRED)" : "")); }
      if (p.scope || p.scopes) bits.push("scope=" + (p.scope || p.scopes));
      row.appendChild(N.el("p", { class: "sub mono small", text: "JWT claims: " + (bits.join("  ·  ") || "(no standard claims)") }));
    }
    // The snippet is context AROUND the match, so the raw secret sits inside it
    // too (that's what makes it useful) -- it would otherwise leak the full
    // value even while `masked` is hidden. Redact every literal occurrence of
    // the matched secret out of the snippet by default, same reveal toggle.
    let snippetEl = null;
    if (f.snippet) {
      snippetEl = N.el("pre", { class: "term secret-snippet" });
      snippetEl.textContent = redactSnippet(f.snippet, f.match, f.masked); // textContent only, never innerHTML
      row.appendChild(snippetEl);
    }

    const valueRow = N.el("div", { class: "secret-value-row" });
    const valueEl = N.el("code", { class: "mono small", text: f.masked });
    valueRow.appendChild(valueEl);
    const revealBtn = N.el("button", { type: "button", class: "ghost small", text: "Reveal" });
    const copyBtn = N.el("button", { type: "button", class: "ghost small hidden", text: "Copy" });
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(f.match).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
    });
    let revealed = false;
    revealBtn.addEventListener("click", () => {
      revealed = !revealed;
      valueEl.textContent = revealed ? f.match : f.masked;
      if (snippetEl) snippetEl.textContent = revealed ? f.snippet : redactSnippet(f.snippet, f.match, f.masked);
      revealBtn.textContent = revealed ? "Hide" : "Reveal";
      copyBtn.classList.toggle("hidden", !revealed);
    });
    valueRow.appendChild(revealBtn);
    valueRow.appendChild(copyBtn);
    row.appendChild(valueRow);

    // Safe, read-only verification command — BUILT, never run by the tool. It
    // hits the credential's own provider (not the client site), so the operator
    // decides whether that's in scope and runs it themselves. Masked by default
    // (it embeds the secret), same reveal machinery as the value.
    if (f.verify && f.verify.command) {
      const v = f.verify;
      const box = N.el("div", { class: "secret-verify mt-8" });
      const label = N.el("div", { class: "sub small" });
      label.appendChild(N.el("strong", { text: "Verify (build-only): " }));
      label.appendChild(document.createTextNode(v.confirms || "confirms the key is live"));
      box.appendChild(label);
      const cmdEl = N.el("pre", { class: "term secret-verify-cmd" });
      const maskedCmd = redactSnippet(v.command, f.match, f.masked);
      cmdEl.textContent = maskedCmd;
      box.appendChild(cmdEl);
      const ctl = N.el("div", { class: "secret-value-row" });
      let vShown = false;
      const vReveal = N.el("button", { type: "button", class: "ghost small", text: "Reveal command" });
      const vCopy = N.el("button", { type: "button", class: "ghost small hidden", text: "Copy command" });
      vReveal.addEventListener("click", () => {
        vShown = !vShown;
        cmdEl.textContent = vShown ? v.command : maskedCmd;
        vReveal.textContent = vShown ? "Hide command" : "Reveal command";
        vCopy.classList.toggle("hidden", !vShown);
      });
      vCopy.addEventListener("click", () => {
        navigator.clipboard.writeText(v.command).then(() => N.toast("command copied", "ok"), () => N.toast("copy failed", "bad"));
      });
      ctl.appendChild(vReveal);
      ctl.appendChild(vCopy);
      box.appendChild(ctl);
      if (v.needs_pair) box.appendChild(N.el("p", { class: "sub small warn-text", text: "Fill in <SECRET> — this match is only half the credential." }));
      if (v.note) box.appendChild(N.el("p", { class: "sub small faint", text: v.note }));
      box.appendChild(N.el("p", { class: "sub small faint", text: "This request leaves the client's site and hits the key's provider — confirm it's in your engagement scope before running." }));
      row.appendChild(box);
    } else if (f.verify_note) {
      row.appendChild(N.el("p", { class: "sub small faint", text: "No safe live-check: " + f.verify_note }));
    }

    return row;
  }

  // Plain substring replace (not regex) so secret values containing regex
  // metacharacters can't break this or, worse, silently fail to redact.
  function redactSnippet(snippet, secret, masked) {
    if (!snippet || !secret) return snippet;
    return snippet.split(secret).join(masked);
  }

  // The flagship "website testing" feature: real credential leaks headlined
  // and separated from publishable-by-design keys, so the report doesn't cry
  // wolf over a Stripe pk_live or a Firebase browser key.
  function buildSecretScanCard(r) {
    if (r.ok === false) {
      const box = N.el("div", { class: "secret-card" });
      box.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }), document.createTextNode("unreachable")]));
      box.appendChild(N.el("p", { class: "sub mt-8", text: r.error || "unknown error" }));
      return box;
    }

    const card = N.el("div", { class: "secret-card" });
    const leaks = r.real_leak_count || 0;

    const headline = N.el("div", { class: "secret-headline" });
    headline.appendChild(N.el("span", { class: "pill " + (leaks > 0 ? "critical" : "ok") }, [
      N.el("span", { class: "dot" }),
      document.createTextNode(leaks > 0 ? `${leaks} real leak${leaks === 1 ? "" : "s"} found` : "no real leaks found"),
    ]));
    const countsRow = N.el("div", { class: "row" });
    ["critical", "high", "medium", "low", "info"].forEach(sev => {
      const n = (r.counts && r.counts[sev]) || 0;
      countsRow.appendChild(N.el("span", { class: "pill " + severityPillClass(sev), text: `${n} ${sev}` }));
    });
    headline.appendChild(countsRow);
    card.appendChild(headline);

    const findings = r.findings || [];
    const real = findings.filter(f => !f.public_ok);
    const publicOk = findings.filter(f => f.public_ok);

    card.appendChild(N.el("div", { class: "section-title", text: "Real leaks" }));
    if (!real.length) {
      card.appendChild(N.el("p", { class: "sub", text: "None found — clean scan." }));
    } else {
      const list = N.el("div", { class: "secret-findings" });
      real.forEach(f => list.appendChild(buildSecretFindingRow(f)));
      card.appendChild(list);
    }

    if (publicOk.length) {
      card.appendChild(N.el("div", { class: "section-title", text: "Public by design (expected)" }));
      const list = N.el("div", { class: "secret-findings secret-findings-public" });
      publicOk.forEach(f => list.appendChild(buildSecretFindingRow(f)));
      card.appendChild(list);
    }

    if (r.truncated) {
      card.appendChild(N.el("p", { class: "sub mt-8", text:
        `showing the top ${(r.findings || []).length} of ${r.total_findings} findings (every file was fully scanned — only the display list is trimmed, weakest-first).` }));
    }
    if (r.scan_truncated) {
      card.appendChild(N.el("p", { class: "sub mt-8 warn-text", text:
        "the scan hit its total-byte CPU budget — some fetched bytes were left unscanned. Findings below are complete up to that point." }));
    }

    const scripts = r.scripts_scanned || [];
    const totalKb = (scripts.reduce((s, x) => s + (x.bytes || 0), 0) / 1024).toFixed(1);
    const footer = N.el("div", { class: "secret-footer mt" });
    const parts = [`scanned ${scripts.length} same-site JS file${scripts.length === 1 ? "" : "s"} (${totalKb}KB)`];
    if (r.sourcemaps_scanned) parts.push(`${r.sourcemaps_scanned} source map${r.sourcemaps_scanned === 1 ? "" : "s"} recovered`);
    if (r.wayback_scripts_scanned) parts.push(`${r.wayback_scripts_scanned} historical (Wayback) file${r.wayback_scripts_scanned === 1 ? "" : "s"}`);
    if (r.scripts_skipped_cross_origin) parts.push(`skipped ${r.scripts_skipped_cross_origin} third-party script${r.scripts_skipped_cross_origin === 1 ? "" : "s"}`);
    if (r.scripts_skipped_over_cap) parts.push(`${r.scripts_skipped_over_cap} more same-site script${r.scripts_skipped_over_cap === 1 ? "" : "s"} past the fetch cap`);
    footer.appendChild(N.el("p", { class: "sub", text: parts.join(" · ") }));

    // Deep-mode exposed-file probe results.
    const probed = r.exposed_files_probed || [];
    const served = probed.filter(p => p.served);
    if (probed.length) {
      footer.appendChild(N.el("p", { class: "sub small", text:
        `deep: probed ${probed.length} exposed-file path${probed.length === 1 ? "" : "s"}, ${served.length} served`
        + (served.length ? ": " + served.map(p => p.path).join(", ") : "") }));
    }
    if (r.sourcemap_referenced && !r.sourcemaps_scanned) {
      footer.appendChild(N.el("span", { class: "pill warn" }, [N.el("span", { class: "dot" }),
        document.createTextNode("source maps referenced but not recovered — try again or fetch them manually")]));
    }
    card.appendChild(footer);

    return card;
  }

  // Shared by the standalone Quick analyzer and every web-analyze step inside
  // a playbook — one renderer, one place to keep the grade/findings read-out
  // consistent. All text from the response goes through N.el's text/
  // textContent path, never innerHTML.
  function buildAnalyzeCard(r) {
    if (r.ok === false) {
      const box = N.el("div", { class: "analyze-card" });
      box.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }), document.createTextNode("unreachable")]));
      box.appendChild(N.el("p", { class: "sub mt-8", text: r.error || "unknown error" }));
      return box;
    }

    const card = N.el("div", { class: "analyze-card" });

    const gradeRow = N.el("div", { class: "grade-row" });
    gradeRow.appendChild(N.el("div", { class: "grade-badge grade-" + r.grade, text: r.grade }));
    const meta = N.el("div", { class: "grade-meta" });
    meta.appendChild(N.el("div", { class: "grade-score", text: `${r.score_pct}%  (${r.points}/${r.max_points} pts)` }));
    meta.appendChild(N.el("div", { class: "sub mono", text:
      `${r.url}  ·  HTTP ${r.status}` + (r.content_type ? "  ·  " + r.content_type : "") }));
    if (r.title) meta.appendChild(N.el("div", { class: "sub", text: "Title: " + r.title }));
    if (r.server) meta.appendChild(N.el("div", { class: "sub", text: "Server: " + r.server }));
    gradeRow.appendChild(meta);
    const counts = N.el("div", { class: "grade-counts" });
    counts.appendChild(N.el("span", { class: "pill bad", text: r.counts.high + " high" }));
    counts.appendChild(N.el("span", { class: "pill warn", text: r.counts.medium + " medium" }));
    counts.appendChild(N.el("span", { class: "pill low", text: r.counts.low + " low" }));
    gradeRow.appendChild(counts);
    card.appendChild(gradeRow);

    card.appendChild(N.el("div", { class: "section-title", text: "Findings" }));
    if (!r.findings.length) {
      card.appendChild(N.el("p", { class: "sub", text: "No findings — clean read-out." }));
    } else {
      const list = N.el("div", { class: "findings-list" });
      r.findings.forEach(f => {
        const row = N.el("div", { class: "finding-row" });
        row.appendChild(N.el("span", { class: "pill " + severityPillClass(f.severity), text: f.severity }));
        const b = N.el("div", { class: "finding-body" });
        b.appendChild(N.el("div", { class: "finding-title", text: f.title }));
        b.appendChild(N.el("div", { class: "sub", text: f.detail }));
        row.appendChild(b);
        list.appendChild(row);
      });
      card.appendChild(list);
    }

    if (r.cookies && r.cookies.length) {
      card.appendChild(N.el("div", { class: "section-title", text: "Cookies" }));
      const table = N.el("table");
      table.appendChild(N.el("thead", {}, [N.el("tr", {}, [
        N.el("th", { text: "Name" }), N.el("th", { text: "Secure" }),
        N.el("th", { text: "HttpOnly" }), N.el("th", { text: "SameSite" }),
      ])]));
      const tbody = N.el("tbody");
      r.cookies.forEach(c => {
        const tr = N.el("tr");
        tr.appendChild(N.el("td", { class: "mono small", text: c.name }));
        tr.appendChild(N.el("td", {}, [N.el("span", { class: "pill " + (c.secure ? "ok" : "bad"), text: c.secure ? "yes" : "no" })]));
        tr.appendChild(N.el("td", {}, [N.el("span", { class: "pill " + (c.httponly ? "ok" : "bad"), text: c.httponly ? "yes" : "no" })]));
        tr.appendChild(N.el("td", { class: "small muted", text: c.samesite }));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      card.appendChild(table);
    }

    if (r.disclosures && r.disclosures.length) {
      card.appendChild(N.el("div", { class: "section-title", text: "Disclosures" }));
      const list = N.el("div", { class: "disclosure-list" });
      r.disclosures.forEach(d => {
        list.appendChild(N.el("div", { class: "disclosure-row" }, [
          N.el("span", { class: "mono small", text: d.header }),
          document.createTextNode(": "),
          N.el("span", { class: "muted", text: d.value }),
        ]));
      });
      card.appendChild(list);
    }

    card.appendChild(N.el("div", { class: "section-title", text: "CORS" }));
    card.appendChild(buildCorsVerdict(r.cors));

    return card;
  }

  function buildCorsVerdict(cors) {
    if (!cors || !cors.tested) {
      return N.el("span", { class: "pill" }, [N.el("span", { class: "dot" }), document.createTextNode("not tested (probe failed)")]);
    }
    let cls = "ok", text = "no obvious misconfiguration";
    if (cors.reflected && cors.allow_credentials) { cls = "bad"; text = "reflects any Origin + credentials — high risk"; }
    else if (cors.reflected) { cls = "warn"; text = "reflects arbitrary Origin"; }
    else if (cors.wildcard && cors.allow_credentials) { cls = "warn"; text = "wildcard (*) with credentials — verify"; }
    else if (cors.wildcard) { cls = "warn"; text = "wildcard (*) — fine for a public, credential-free API"; }
    const wrap = N.el("div");
    wrap.appendChild(N.el("span", { class: "pill " + cls }, [N.el("span", { class: "dot" }), document.createTextNode(text)]));
    if (cors.acao) wrap.appendChild(N.el("div", { class: "sub mono mt-8", text: "Access-Control-Allow-Origin: " + cors.acao }));
    return wrap;
  }

  // ------------------------------------------------------------------
  // Password tab — offline hash identifier + a hashcat/john-scoped command
  // builder + a wordlist search/preview browser.
  // ------------------------------------------------------------------
  let PW_WL_TIMER = null;
  let PW_WL_SEQ = 0;
  let PW_WL_LOADED = false;

  function wirePasswordTab() {
    document.getElementById("hash-id-btn").addEventListener("click", runHashId);
    document.getElementById("hash-input").addEventListener("keydown", e => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); runHashId(); }
    });
    document.getElementById("pw-wl-search").addEventListener("input", e => {
      const q = e.target.value.trim();
      clearTimeout(PW_WL_TIMER);
      PW_WL_TIMER = setTimeout(async () => {
        const seq = ++PW_WL_SEQ;
        try {
          const r = await N.get("/api/wordlists?q=" + encodeURIComponent(q) + "&limit=50");
          if (seq !== PW_WL_SEQ) return;
          renderWlResults(r.results || []);
        } catch (_) { /* keep previous list */ }
      }, 200);
    });
  }

  function loadWordlistBrowserDefault() {
    if (PW_WL_LOADED) return;
    PW_WL_LOADED = true;
    N.get("/api/wordlists?limit=50").then(r => renderWlResults(r.results || [])).catch(() => renderWlResults([]));
  }

  function renderWlResults(results) {
    const wrap = document.getElementById("pw-wl-results");
    wrap.innerHTML = "";
    if (!results.length) {
      wrap.appendChild(N.el("p", { class: "sub", text: "No matches." }));
      return;
    }
    results.forEach(w => {
      const row = N.el("button", { type: "button", class: "wl-row" });
      row.appendChild(N.el("span", { class: "mono small", text: w.label }));
      row.appendChild(N.el("span", { class: "src-badge", text: w.root }));
      row.appendChild(N.el("span", { class: "faint small", text: (w.size / 1024).toFixed(1) + "KB" }));
      row.addEventListener("click", () => loadWlPreview(w.id, row));
      wrap.appendChild(row);
    });
  }

  async function loadWlPreview(id, rowEl) {
    document.querySelectorAll("#pw-wl-results .wl-row").forEach(r => r.classList.remove("active"));
    if (rowEl) rowEl.classList.add("active");
    const wrap = document.getElementById("pw-wl-preview");
    wrap.innerHTML = "";
    wrap.appendChild(N.el("p", { class: "sub", text: "loading…" }));
    try {
      const r = await N.get("/api/wordlist-preview?id=" + encodeURIComponent(id));
      wrap.innerHTML = "";
      wrap.appendChild(N.el("p", { class: "mono small muted", text: r.id }));
      const count = r.count_capped ? `${r.line_count}+ lines` : `${r.line_count} lines`;
      wrap.appendChild(N.el("p", { class: "sub", text: `${count} · ${(r.size / 1024).toFixed(1)}KB` }));
      const pre = N.el("pre", { class: "term" });
      // raw wordlist lines via textContent — never innerHTML
      pre.textContent = (r.preview || []).join("\n") || "(empty)";
      wrap.appendChild(pre);
    } catch (e) {
      wrap.innerHTML = "";
      wrap.appendChild(N.el("p", { class: "sub", text: "error: " + (e.body && e.body.error ? e.body.error : e.message) }));
    }
  }

  async function runHashId() {
    const hash = document.getElementById("hash-input").value;
    const attack = document.getElementById("hash-attack").value;
    const status = document.getElementById("hash-id-status");
    const resultWrap = document.getElementById("hash-id-result");
    if (!hash.trim()) { N.toast("paste a hash first", "bad"); return; }
    const btn = document.getElementById("hash-id-btn");
    btn.disabled = true;
    status.textContent = "identifying…";
    try {
      const r = await N.post("/api/hash-id", { hash, attack });
      status.textContent = "";
      resultWrap.classList.remove("hidden");
      resultWrap.innerHTML = "";
      resultWrap.appendChild(buildHashIdResult(r));
    } catch (e) {
      status.textContent = "error";
      N.toast("identify failed: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = false;
    }
  }

  function buildHashIdResult(r) {
    const wrap = N.el("div");
    if (!r.count) {
      wrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }), document.createTextNode("not recognized")]));
      wrap.appendChild(N.el("p", { class: "sub mt-8", text:
        `${r.input_len}-char value doesn't match any known hash shape in the catalog.` }));
      return wrap;
    }
    const ambiguous = r.candidates[0].ambiguous;
    wrap.appendChild(N.el("div", { class: "section-title", text: ambiguous
      ? `${r.input_len}-char value — ambiguous, could be any of these:`
      : "Identified — high confidence:" }));
    const list = N.el("div", { class: "hash-candidates" });
    r.candidates.forEach((c, idx) => list.appendChild(buildHashCandidateCard(c, idx === 0)));
    wrap.appendChild(list);
    return wrap;
  }

  function buildHashCandidateCard(c, top) {
    const card = N.el("div", { class: "hash-card" + (top ? " top" : "") });
    const head = N.el("div", { class: "hash-card-head" });
    head.appendChild(N.el("strong", { text: c.name }));
    head.appendChild(N.el("span", { class: "pill " + (c.hashcat != null ? "ok" : "") },
      [document.createTextNode(c.hashcat != null ? "-m " + c.hashcat : "no hashcat mode")]));
    head.appendChild(N.el("span", { class: "pill " + (c.john ? "ok" : "") },
      [document.createTextNode(c.john ? "--format=" + c.john : "no john format")]));
    card.appendChild(head);

    if (c.example) card.appendChild(N.el("p", { class: "sub mono small", text: "example: " + c.example }));
    if (c.note) card.appendChild(N.el("p", { class: "sub build-note", text: c.note }));

    if (c.commands && (c.commands.hashcat || c.commands.john)) {
      const cmds = N.el("div", { class: "cmd-list" });
      if (c.commands.hashcat) cmds.appendChild(buildCmdLine(c.commands.hashcat));
      if (c.commands.john) cmds.appendChild(buildCmdLine(c.commands.john));
      card.appendChild(cmds);
    }

    const actions = N.el("div", { class: "row mt-8" });
    if (c.hashcat != null) {
      const b = N.el("button", { type: "button", class: "ghost small", text: "Use in hashcat builder" });
      b.addEventListener("click", () => usePwBuilderMode("hashcat", "mode", String(c.hashcat)));
      actions.appendChild(b);
    }
    if (c.john) {
      const b = N.el("button", { type: "button", class: "ghost small", text: "Use in John builder" });
      b.addEventListener("click", () => usePwBuilderMode("john", "format", c.john));
      actions.appendChild(b);
    }
    if (actions.childNodes.length) card.appendChild(actions);

    return card;
  }

  function buildCmdLine(cmd) {
    const row = N.el("div", { class: "cmd-line" });
    row.appendChild(N.el("code", { class: "mono small", text: cmd }));
    const btn = N.el("button", { type: "button", class: "ghost small", text: "Copy" });
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(cmd).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad"));
    });
    row.appendChild(btn);
    return row;
  }

  function usePwBuilderMode(tool, field, value) {
    const ok = pwBuildPanel.selectToolAndFill(tool, field, value);
    if (!ok) { N.toast("builder tool list still loading — try again in a second", "bad"); return; }
    N.toast(`pre-filled the ${tool} builder's ${field} field`, "ok");
    const target = document.getElementById("pw-build-tool");
    if (target.scrollIntoView) target.scrollIntoView({ block: "center", behavior: "smooth" });
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

  // ------------------------------------------------------------------
  // Resilience tab — DDoS resilience testing. A bounded native probe
  // (/api/stress-probe, same gate stack as the runners) plus optional
  // ownership verification and a copy-paste load-test command builder.
  // Everything renders via N.el/textContent — server strings never touch
  // innerHTML — so a reflected header value can't inject markup.
  // ------------------------------------------------------------------
  let STRESS_TOKEN = "";

  function wireStressTab() {
    const tokenBtn = document.getElementById("stress-token-btn");
    if (!tokenBtn) return; // tab not present
    tokenBtn.addEventListener("click", getStressToken);
    document.getElementById("stress-verify-btn").addEventListener("click", verifyStressOwnership);
    const probeBtn = document.getElementById("stress-probe-btn");
    probeBtn.addEventListener("click", runStressProbe);
    document.getElementById("stress-probe-target").addEventListener("keydown", e => {
      if (e.key === "Enter" && !probeBtn.disabled) runStressProbe();
    });
    // Custom intensity reveals the request-count / duration / concurrency inputs.
    const tierSel = document.getElementById("stress-probe-tier");
    const customRow = document.getElementById("stress-custom-row");
    const syncCustomRow = () => customRow.classList.toggle("hidden", tierSel.value !== "custom");
    tierSel.addEventListener("change", syncCustomRow);
    syncCustomRow();
    document.getElementById("stress-build-btn").addEventListener("click", buildLoadTest);
  }

  async function getStressToken() {
    const target = document.getElementById("stress-verify-target").value.trim();
    const out = document.getElementById("stress-token-out");
    try {
      const r = await N.post("/api/stress-token", { target });
      STRESS_TOKEN = r.token;
      out.classList.remove("hidden");
      out.innerHTML = "";
      out.appendChild(N.el("p", { class: "sub", text: "Place EITHER of these, then verify:" }));
      const dns = N.el("div", { class: "mono small mb-8" });
      dns.appendChild(N.el("b", { text: "DNS TXT  " }));
      dns.appendChild(document.createTextNode(`${r.dns.name}  →  ${r.dns.value}`));
      const file = N.el("div", { class: "mono small" });
      file.appendChild(N.el("b", { text: "File     " }));
      file.appendChild(document.createTextNode(`${r.file.url}  contains  ${r.file.content}`));
      out.appendChild(dns);
      out.appendChild(file);
      out.appendChild(N.el("p", { class: "faint small mt-8", text: r.note }));
      document.getElementById("stress-verify-row").classList.remove("hidden");
    } catch (e) {
      N.toast("token failed: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    }
  }

  async function verifyStressOwnership() {
    const target = document.getElementById("stress-verify-target").value.trim();
    const method = document.getElementById("stress-verify-method").value;
    const status = document.getElementById("stress-verify-status");
    if (!target) { N.toast("enter a target first", "bad"); return; }
    if (!STRESS_TOKEN) { N.toast("get a token first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    status.textContent = "checking…";
    try {
      const r = await N.post("/api/stress-verify", { target, token: STRESS_TOKEN, method,
                                                     authorized: gateChecked(), proceed_exposed: opsecOverride() });
      status.innerHTML = "";
      const pill = N.el("span", { class: "pill " + (r.verified ? "ok" : "bad") }, [
        N.el("span", { class: "dot" }),
        document.createTextNode(r.verified ? "scope verified" : "not verified"),
      ]);
      status.appendChild(pill);
      status.appendChild(N.el("span", { class: "faint small ml-10", text: r.detail || "" }));
    } catch (e) {
      status.textContent = "error: " + (e.body && e.body.error ? e.body.error : e.message);
    }
  }

  async function runStressProbe() {
    const target = document.getElementById("stress-probe-target").value.trim();
    const tier = document.getElementById("stress-probe-tier").value;
    const status = document.getElementById("stress-probe-status");
    const resultWrap = document.getElementById("stress-probe-result");
    if (!target) { N.toast("enter a URL first", "bad"); return; }
    if (!gateChecked()) { N.toast("check the authorization box first", "bad"); return; }
    const btn = document.getElementById("stress-probe-btn");
    btn.disabled = true;
    const tick = tickerStart("stress-probe-status", "ramping load");
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    const body = { url: target, tier, authorized: gateChecked(), lab: labChecked(),
                   proceed_exposed: opsecOverride() };
    // Custom intensity: send the operator's request count / duration / concurrency.
    // The server clamps each to the hard caps, so raw text is safe to pass through.
    if (tier === "custom") {
      body.requests = document.getElementById("stress-custom-requests").value.trim();
      body.duration = document.getElementById("stress-custom-duration").value.trim();
      body.concurrency = document.getElementById("stress-custom-concurrency").value.trim();
    }
    // Attach the verified scope stamp if the operator verified this run's target.
    const vtarget = document.getElementById("stress-verify-target").value.trim();
    if (STRESS_TOKEN && vtarget && target.indexOf(vtarget) !== -1) {
      body.verify = { token: STRESS_TOKEN, method: document.getElementById("stress-verify-method").value };
    }
    try {
      const r = await N.post("/api/stress-probe", body);
      tickerStop(tick);
      status.textContent = "";
      resultWrap.appendChild(buildStressCard(r));
    } catch (e) {
      tickerStop(tick);
      status.textContent = "refused";
      resultWrap.appendChild(N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }),
        document.createTextNode("refused: " + (e.body && e.body.error ? e.body.error : e.message))]));
      N.toast("resilience test refused: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    } finally {
      btn.disabled = !gateChecked();
    }
  }

  function stressStatusClass(s) {
    if (s === "good") return "ok";
    if (s === "watch") return "warn";
    return "bad"; // gap
  }

  // Seconds from a "90s" / "2m" / "1h" / bare-number string — mirrors the
  // server's parse so the clamp note below can compare like-for-like. Returns
  // null when the value can't be read as a duration.
  function parseDurationSecs(v) {
    if (v == null) return null;
    const s = String(v).trim().toLowerCase();
    const num = parseFloat(s.replace(/[^0-9.]/g, ""));
    if (isNaN(num)) return null;
    if (s.endsWith("m")) return num * 60;
    if (s.endsWith("h")) return num * 3600;
    return num;
  }

  // If a custom run asked for more than a cap allows, the server clamped it —
  // surface exactly what was trimmed so the operator isn't misled about the load.
  function customClampNote(r) {
    if (r.tier !== "custom" || !r.effective || !r.requested) return "";
    const eff = r.effective, req = r.requested, parts = [];
    const reqN = parseInt(String(req.requests).replace(/[^0-9]/g, ""), 10);
    if (!isNaN(reqN) && reqN > eff.requests) parts.push(`requests ${reqN}→${eff.requests}`);
    const concN = parseInt(String(req.concurrency).replace(/[^0-9]/g, ""), 10);
    if (!isNaN(concN) && concN > eff.concurrency) parts.push(`concurrency ${concN}→${eff.concurrency}`);
    const durS = parseDurationSecs(req.duration);
    if (durS != null && durS > eff.duration_s) parts.push(`duration ${durS}s→${eff.duration_s}s`);
    return parts.length ? "clamped to the caps: " + parts.join(", ") : "";
  }

  function buildStressCard(r) {
    const wrap = N.el("div", { class: "stress-result" });
    if (!r.ok) {
      wrap.appendChild(N.el("p", { class: "pill bad", text: r.error || "probe failed" }));
      return wrap;
    }
    // Headline: grade + key totals — reuses the analyzer's grade-row look.
    const head = N.el("div", { class: "grade-row" });
    head.appendChild(N.el("div", { class: "grade-badge grade-" + r.grade, text: r.grade }));
    const meta = N.el("div", { class: "grade-meta" });
    // For a custom run, name the load the operator dialed in; else the tier.
    let intensity = "tier " + r.tier;
    if (r.tier === "custom" && r.effective) {
      const e = r.effective;
      intensity = `custom · ${e.requests} req · ${e.duration_s}s · ${e.concurrency} concurrent`;
    }
    meta.appendChild(N.el("div", { class: "grade-score", text: `Resilience ${r.score}/100 · ${intensity}` }));
    const t = r.totals || {};
    meta.appendChild(N.el("div", { class: "sub", text:
      `${t.requests} requests · peak ${t.peak_rps} rps · ${Math.round((t.distress_rate||0)*100)}% failed · ${t.timeouts} timeouts` }));
    head.appendChild(meta);
    wrap.appendChild(head);

    if (r.scope_verified && r.scope_verified.verified) {
      wrap.appendChild(N.el("p", { class: "pill ok mt-8" }, [N.el("span", { class: "dot" }),
        document.createTextNode("scope verified — " + (r.scope_verified.detail || ""))]));
    }
    // A custom run whose values got clamped to the caps — tell the operator so
    // "1000 requests" isn't silently trimmed without a word.
    const clampMsg = customClampNote(r);
    if (clampMsg) {
      wrap.appendChild(N.el("p", { class: "faint small mt-8", text: "ℹ︎ " + clampMsg }));
    }
    if (r.graceful_stop) {
      wrap.appendChild(N.el("p", { class: "faint small mt-8", text: "✓ " + r.graceful_stop }));
    }
    if (r.aborted) {
      wrap.appendChild(N.el("p", { class: "faint small mt-8", text: "⛔ " + r.aborted }));
    }

    // Defense verdicts
    const vwrap = N.el("div", { class: "mt" });
    (r.verdicts || []).forEach(v => {
      const row = N.el("div", { class: "verdict-row" });
      row.appendChild(N.el("span", { class: "pill " + stressStatusClass(v.status), text: v.status }));
      const body = N.el("div", {});
      body.appendChild(N.el("b", { text: v.area }));
      body.appendChild(N.el("div", { class: "sub", text: v.detail }));
      row.appendChild(body);
      vwrap.appendChild(row);
    });
    wrap.appendChild(vwrap);

    // Latency + degradation summary
    const lat = r.latency_overall_ms || {};
    const latLine = N.el("p", { class: "sub mt", text:
      `Latency p50/p95/p99: ${lat.p50}/${lat.p95}/${lat.p99} ms` +
      (r.degradation_p95_ratio != null ? ` · p95 grew ×${r.degradation_p95_ratio} across the ramp` : "") });
    wrap.appendChild(latLine);

    // Per-step ramp table
    if ((r.steps || []).length) {
      const details = N.el("details", { class: "mt" });
      details.appendChild(N.el("summary", { text: "Ramp steps" }));
      const tbl = N.el("table", { class: "stress-steps" });
      const hr = N.el("tr", {});
      ["conc", "req", "ok", "5xx", "timeout", "429", "rps", "p95 ms"].forEach(h =>
        hr.appendChild(N.el("th", { text: h })));
      tbl.appendChild(hr);
      r.steps.forEach(st => {
        const tr = N.el("tr", {});
        [st.concurrency, st.requests, st.ok, st.http_5xx, st.timeouts, st.rate_limited,
         st.rps, st.latency.p95].forEach(c => tr.appendChild(N.el("td", { text: String(c) })));
        tbl.appendChild(tr);
      });
      details.appendChild(tbl);
      wrap.appendChild(details);
    }

    // Remediation
    if ((r.remediation || []).length) {
      const rem = N.el("details", { class: "mt" });
      rem.appendChild(N.el("summary", { text: `Remediation (${r.remediation.length})` }));
      r.remediation.forEach(item => {
        const b = N.el("div", { class: "remediation-item" });
        b.appendChild(N.el("b", { text: item.area }));
        b.appendChild(N.el("div", { class: "sub", text: item.fix }));
        if (item.verify) b.appendChild(N.el("div", { class: "faint small", text: "Verify: " + item.verify }));
        rem.appendChild(b);
      });
      wrap.appendChild(rem);
    }

    // Honesty notes
    if ((r.notes || []).length) {
      const notes = N.el("details", { class: "mt" });
      notes.appendChild(N.el("summary", { text: "Method + limits" }));
      r.notes.forEach(n => notes.appendChild(N.el("p", { class: "faint small", text: n })));
      wrap.appendChild(notes);
    }
    return wrap;
  }

  async function buildLoadTest() {
    const engine = document.getElementById("stress-build-engine").value;
    const out = document.getElementById("stress-build-out");
    const params = {
      url: document.getElementById("stress-build-url").value.trim(),
      rate: document.getElementById("stress-build-rate").value.trim(),
      concurrency: document.getElementById("stress-build-concurrency").value.trim(),
      duration: document.getElementById("stress-build-duration").value.trim(),
    };
    try {
      const r = await N.post("/api/stress-build", { engine, params });
      out.classList.remove("hidden");
      out.innerHTML = "";
      if (r.files && r.files.length) {
        r.files.forEach(f => {
          out.appendChild(N.el("div", { class: "small faint", text: f.name }));
          const pre = N.el("pre", { class: "term", text: f.content });
          out.appendChild(pre);
          out.appendChild(mkCopyBtn(f.content));
        });
      }
      if (r.command) {
        out.appendChild(N.el("pre", { class: "term", text: r.command }));
        out.appendChild(mkCopyBtn(r.command));
      }
      out.appendChild(N.el("p", { class: "faint small mt-8", text: r.note || "" }));
      out.appendChild(N.el("p", { class: "faint small", text:
        "Not executed here — copy and run it yourself against an authorized target." }));
    } catch (e) {
      N.toast("build failed: " + (e.body && e.body.error ? e.body.error : e.message), "bad");
    }
  }

  function mkCopyBtn(text) {
    const btn = N.el("button", { type: "button", class: "secondary small mt-8", text: "Copy" });
    btn.addEventListener("click", () =>
      navigator.clipboard.writeText(text).then(() => N.toast("copied", "ok"), () => N.toast("copy failed", "bad")));
    return btn;
  }
})();
