(function () {
  "use strict";
  const N = window.Nucleus;
  let INV = null;          // last /api/inventory payload
  let ACTIVE_CAT = "";

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    wireAuthGate();
    wireRunner();
    wireBuilder();
    document.getElementById("inv-refresh").addEventListener("click", () => loadInventory(true));
    await loadInventory(false);
    await loadHistory();
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
  // Inventory
  // ------------------------------------------------------------------
  async function loadInventory(refresh) {
    const summary = document.getElementById("inv-summary");
    summary.textContent = "Scanning...";
    try {
      INV = await N.get("/api/inventory" + (refresh ? "?refresh=1" : ""));
    } catch (e) {
      summary.textContent = "Failed to load inventory: " + e.message;
      N.toast("inventory load failed", "bad");
      return;
    }
    renderCategorySelect();
    renderCategoryChips();
    renderInvTable();
    renderSummary();
    renderRunnerSelect();
    renderBuilderSelect();
    renderLocalTools();
  }

  function renderSummary() {
    const s = INV.summary;
    document.getElementById("inv-summary").textContent =
      `${s.installed} / ${s.total} tools installed on this box`;
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
    sel.onchange = () => { ACTIVE_CAT = sel.value; renderInvTable(); renderCategoryChips(); };
    document.getElementById("inv-installed-only").onchange = renderInvTable;
  }

  function renderCategoryChips() {
    const wrap = document.getElementById("inv-cats");
    wrap.innerHTML = "";
    INV.categories.forEach(c => {
      const active = ACTIVE_CAT === c.key;
      const card = N.el("div", {
        class: "card cat-chip stat" + (active ? " active" : ""),
        onclick: () => {
          ACTIVE_CAT = active ? "" : c.key;
          document.getElementById("inv-cat").value = ACTIVE_CAT;
          renderInvTable();
          renderCategoryChips();
        },
      });
      card.appendChild(N.el("div", { class: "num", text: String(c.installed) }));
      card.appendChild(N.el("div", { class: "lbl", text: c.label }));
      card.appendChild(N.el("div", { class: "frac", text: `${c.installed} of ${c.total}` }));
      wrap.appendChild(card);
    });
  }

  function renderInvTable() {
    const tbody = document.querySelector("#inv-table tbody");
    tbody.innerHTML = "";
    const installedOnly = document.getElementById("inv-installed-only").checked;
    const rows = INV.tools.filter(t =>
      (!ACTIVE_CAT || t.category === ACTIVE_CAT) && (!installedOnly || t.installed));
    if (!rows.length) {
      tbody.appendChild(N.el("tr", {}, [N.el("td", { colspan: "6", class: "muted", text: "No tools match this filter." })]));
      return;
    }
    rows.forEach(t => {
      const tr = N.el("tr");
      tr.appendChild(N.el("td", {}, [N.el("strong", { text: t.name }),
        document.createTextNode(" "), N.el("span", { class: "src-badge", text: t.source })]));
      tr.appendChild(N.el("td", { class: "muted", text: t.category_label }));
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
  }

  // ------------------------------------------------------------------
  // Safe runner
  // ------------------------------------------------------------------
  function renderRunnerSelect() {
    const sel = document.getElementById("run-tool");
    sel.innerHTML = "";
    INV.safe_runners.forEach(r => {
      sel.appendChild(N.el("option", { value: r.key, text: r.key + (r.installed ? "" : "  (not installed)") }));
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
    const optWrap = document.getElementById("run-option-wrap");
    const optSel = document.getElementById("run-option");
    const optLabel = document.getElementById("run-option-label");
    if (!spec) { descEl.textContent = ""; optWrap.classList.add("hidden"); return; }
    descEl.textContent = spec.desc + (spec.installed ? "" : `  — not installed: ${spec.install}`);
    if (spec.option_key) {
      optWrap.classList.remove("hidden");
      optLabel.textContent = spec.option_key;
      optSel.innerHTML = "";
      spec.option_choices.forEach(v => optSel.appendChild(N.el("option", {
        value: v, text: v + (v === spec.option_default ? " (default)" : ""),
      })));
      optSel.value = spec.option_default;
    } else {
      optWrap.classList.add("hidden");
    }
  }

  function wireRunner() {
    document.getElementById("run-btn").addEventListener("click", runSafeTool);
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
    if (spec.option_key) body.options = { [spec.option_key]: document.getElementById("run-option").value };

    status.textContent = "running...";
    out.classList.remove("hidden");
    out.textContent = "";
    document.getElementById("run-btn").disabled = true;
    try {
      const r = await N.post("/api/run", body);
      status.textContent = `exit ${r.returncode} · ${r.duration}s` + (r.timed_out ? " · TIMED OUT" : "");
      let text = "$ " + r.argv.map(a => (/\s/.test(a) ? `'${a}'` : a)).join(" ") + "\n\n";
      text += (r.stdout || "").trim();
      if (r.stderr && r.stderr.trim()) text += "\n\n[stderr]\n" + r.stderr.trim();
      if (r.error) text += "\n\n[error] " + r.error;
      out.textContent = text || "(no output)";
      loadHistory();
    } catch (e) {
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
    wrap.innerHTML = "";
    document.getElementById("build-result-wrap").classList.add("hidden");
    if (!spec) return;
    spec.fields.forEach(f => {
      const isFlag = f.endsWith("_is_file");
      const field = N.el("div", { class: "field" });
      field.appendChild(N.el("label", { text: f.replace(/_/g, " ") }));
      if (isFlag) {
        const line = N.el("label", { class: "checkline" });
        line.appendChild(N.el("input", { type: "checkbox", "data-field": f }));
        line.appendChild(document.createTextNode("treat as a file/list path"));
        field.appendChild(line);
      } else {
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
        const link = N.el("a", { href: t.github, target: "_blank", rel: "noopener", text: t.github });
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
})();
