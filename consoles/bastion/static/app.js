(function () {
  "use strict";
  const N = window.Nucleus;

  const STATUS_LABEL = { ok: "ok", warn: "warn", bad: "bad", unknown: "n/a" };

  function pill(status) {
    const cls = status === "unknown" ? "" : status;
    return `<span class="pill ${cls}"><span class="dot"></span>${N.esc(STATUS_LABEL[status] || status)}</span>`;
  }

  // ---- posture -------------------------------------------------------
  function renderHeadline(summary) {
    const el = document.getElementById("posture-headline");
    const scoreClass = summary.score >= 80 ? "" : summary.score >= 50 ? "warn" : "bad";
    el.innerHTML = `
      <div class="card headline-card">
        <div class="score ${scoreClass}">${summary.score}</div>
        <div>
          <div class="sub">opsec score</div>
          <div class="faint">${summary.total} checks</div>
        </div>
      </div>
      <div class="card">
        <div class="stat"><div class="num">${summary.counts.ok}</div><div class="lbl">ok</div></div>
      </div>
      <div class="card">
        <div class="stat"><div class="num">${summary.counts.warn + summary.counts.bad}</div><div class="lbl">warn / bad</div></div>
      </div>`;
  }

  function checkCard(c) {
    return `
      <div class="card check-card">
        <div class="head">
          <div><div class="cat">${N.esc(c.category)}</div><h3>${N.esc(c.label)}</h3></div>
          ${pill(c.status)}
        </div>
        <div class="detail">${N.esc(c.detail)}</div>
        ${c.fix_hint ? `<div class="fix">${N.esc(c.fix_hint)}</div>` : ""}
      </div>`;
  }

  async function loadPosture() {
    try {
      const j = await N.get("/api/posture");
      renderHeadline(j.summary);
      document.getElementById("posture-grid").innerHTML = j.checks.map(checkCard).join("");
    } catch (e) {
      document.getElementById("posture-grid").innerHTML =
        `<div class="card"><p class="muted">posture check failed: ${N.esc(e.message)}</p></div>`;
    }
  }

  // ---- hardening panel ------------------------------------------------
  function scriptCard(s) {
    const appliedPill = s.applied === true ? pill("ok")
      : s.applied === false ? `<span class="pill">not detected</span>`
      : `<span class="pill">n/a</span>`;
    return `
      <div class="card script-card">
        <div class="head"><h3>${N.esc(s.file)}</h3>${appliedPill}</div>
        <div class="desc">${N.esc(s.description)}</div>
        <div class="cmdrow">
          <code>${N.esc(s.command)}</code>
          <button class="ghost copy" data-cmd="${N.esc(s.command)}">copy</button>
        </div>
      </div>`;
  }

  async function loadHardening() {
    const el = document.getElementById("hardening-list");
    try {
      const j = await N.get("/api/hardening");
      el.innerHTML = j.scripts.map(scriptCard).join("");
      el.querySelectorAll("button.copy").forEach(btn => {
        btn.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(btn.getAttribute("data-cmd"));
            N.toast("command copied", "ok");
          } catch (_) {
            N.toast("copy failed — select manually", "bad");
          }
        });
      });
    } catch (e) {
      el.innerHTML = `<div class="card"><p class="muted">hardening panel failed: ${N.esc(e.message)}</p></div>`;
    }
  }

  // ---- report engine ---------------------------------------------------
  function findingRow(f) {
    return `
      <div class="finding-row sev-${N.esc(f.severity)}">
        <div class="sev">${N.esc(f.severity.toUpperCase())}</div>
        <div>
          <div class="ftitle">${N.esc(f.title)}</div>
          ${f.recommendation ? `<div class="frec">${N.esc(f.recommendation)}</div>` : ""}
        </div>
      </div>`;
  }

  function renderReport(j) {
    const el = document.getElementById("report-result");
    const links = [];
    if (j.files && j.files.html) links.push(`<a href="${j.files.html.url}" target="_blank" rel="noopener">open HTML report</a>`);
    if (j.files && j.files.md) links.push(`<a href="${j.files.md.url}" target="_blank" rel="noopener">open Markdown</a>`);

    el.innerHTML = `
      <div class="card">
        <div class="grade-hero">
          <div class="letter g-${N.esc(j.grade)}">${N.esc(j.grade)}</div>
          <div>
            <div class="sub">${j.score_pct}% weighted &middot; ${N.esc(j.domain)}</div>
            <div class="sub">email ${j.score_breakdown.email.points}/${j.score_breakdown.email.max}
              &middot; web ${j.score_breakdown.web.points}/${j.score_breakdown.web.max}
              &middot; attack surface ${j.score_breakdown.attack_surface.points}/${j.score_breakdown.attack_surface.max}</div>
            <div class="links mt">${links.join(" ")}</div>
          </div>
        </div>
        <h2>Findings</h2>
        ${j.findings.length ? j.findings.map(findingRow).join("") : '<p class="muted">No findings — every checked signal came back clean.</p>'}
      </div>`;
  }

  async function runReport() {
    const input = document.getElementById("report-domain");
    const domain = (input.value || "").trim();
    if (!domain) { N.toast("enter a domain first", "bad"); return; }
    const btn = document.getElementById("report-run");
    const el = document.getElementById("report-result");
    btn.disabled = true;
    el.innerHTML = `<div class="card"><span class="spinner"></span> assessing ${N.esc(domain)}…</div>`;
    try {
      const j = await N.post("/api/report", { domain });
      renderReport(j);
    } catch (e) {
      el.innerHTML = `<div class="card"><p class="muted">assessment failed: ${N.esc(e.message)}</p></div>`;
      N.toast("assessment failed", "bad");
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    loadPosture();
    loadHardening();
    document.getElementById("report-run").addEventListener("click", runReport);
    document.getElementById("report-domain").addEventListener("keydown", e => {
      if (e.key === "Enter") runReport();
    });
  });
})();
