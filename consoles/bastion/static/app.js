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

  // ---- opsec / anonymity ---------------------------------------------
  async function loadAnonymity() {
    try {
      const j = await N.get("/api/anonymity");
      const v = j.verdict || {};
      const where = [v.org, v.city, v.country].filter(Boolean).join(" · ");
      const vd = document.getElementById("anon-verdict");
      if (v.exposed) {
        vd.className = "anon-verdict exposed";
        vd.innerHTML =
          `<div class="big">⚠ EXPOSED</div>
           <div class="line">Your real IP <span class="mono">${N.esc(v.public_ip || "?")}</span>${where ? " (" + N.esc(where) + ")" : ""} is what any target you scan will see.</div>
           <div class="line faint">${N.esc(v.reason || "")}</div>
           <div class="line">Turn on your VPN before scanning. Set it up below.</div>`;
      } else {
        vd.className = "anon-verdict safe";
        vd.innerHTML =
          `<div class="big">✓ PROTECTED</div>
           <div class="line">${N.esc(v.reason || "VPN active")} — exit <span class="mono">${N.esc(v.public_ip || "?")}</span>${where ? " (" + N.esc(where) + ")" : ""}.</div>
           <div class="line faint">Your real IP is not what targets see.</div>`;
      }
      document.getElementById("anon-grid").innerHTML = (j.checks || []).map(checkCard).join("");
      const recs = document.getElementById("anon-recs");
      recs.innerHTML = `<h2>What to have on</h2><ul class="rec-list">` +
        (j.recommendations || []).map(r => `<li>${N.esc(r)}</li>`).join("") + `</ul>`;
    } catch (e) {
      document.getElementById("anon-verdict").innerHTML =
        `<div class="card"><p class="muted">anonymity check failed: ${N.esc(e.message)}</p></div>`;
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
      wireCopyButtons(el);
    } catch (e) {
      el.innerHTML = `<div class="card"><p class="muted">hardening panel failed: ${N.esc(e.message)}</p></div>`;
    }
  }

  // ---- priority fix plan ----------------------------------------------
  function planStep(s, i) {
    return `
      <div class="card script-card">
        <div class="head"><h3>${i + 1}. ${N.esc(s.label)}</h3></div>
        ${s.why ? `<div class="desc">${N.esc(s.why)}</div>` : ""}
        <div class="cmdrow">
          <code>${N.esc(s.command)}</code>
          <button class="ghost copy" data-cmd="${N.esc(s.command)}">copy</button>
        </div>
      </div>`;
  }

  function wireCopyButtons(el) {
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
  }

  async function loadHardeningPlan() {
    const el = document.getElementById("hardening-plan");
    try {
      const j = await N.get("/api/hardening-plan");
      if (!j.steps || !j.steps.length) {
        el.innerHTML = `<div class="card"><p class="muted">Nothing to fix — every posture check that has a fix is already passing.</p></div>`;
        return;
      }
      el.innerHTML = `<div class="grid cols-2">${j.steps.map(planStep).join("")}</div>`;
      wireCopyButtons(el);
    } catch (e) {
      el.innerHTML = `<div class="card"><p class="muted">fix plan failed: ${N.esc(e.message)}</p></div>`;
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

  function renderGradeDelta(j) {
    if (!j.previous || !j.delta) return "";
    const dir = j.delta.grade_direction;
    const dirClass = dir === "up" ? "ok" : dir === "down" ? "bad" : "";
    const arrow = dir === "up" ? "▲" : dir === "down" ? "▼" : "•";
    const pct = j.delta.score_pct;
    const pctStr = pct == null ? "" : (pct > 0 ? `+${pct}` : `${pct}`);
    return `
      <div class="grade-delta ${dirClass}">
        <span class="arrow">${arrow}</span>
        <span>grade ${N.esc(j.previous.grade)} &rarr; ${N.esc(j.grade)}</span>
        ${pctStr ? `<span class="pct">(${N.esc(pctStr)}%)</span>` : ""}
        ${j.previous.date ? `<span class="faint">since ${N.esc(j.previous.date)}</span>` : ""}
      </div>`;
  }

  function renderReport(j) {
    const el = document.getElementById("report-result");
    const links = [];
    if (j.files && j.files.html) links.push(`<a href="${N.esc(N.safeUrl(j.files.html.url))}" target="_blank" rel="noopener">open HTML report</a>`);
    if (j.files && j.files.md) links.push(`<a href="${N.esc(N.safeUrl(j.files.md.url))}" target="_blank" rel="noopener">open Markdown</a>`);

    el.innerHTML = `
      <div class="card">
        <div class="grade-hero">
          <div class="letter g-${N.esc(j.grade)}">${N.esc(j.grade)}</div>
          <div>
            <div class="sub">${j.score_pct}% weighted &middot; ${N.esc(j.domain)}</div>
            <div class="sub">email ${j.score_breakdown.email.points}/${j.score_breakdown.email.max}
              &middot; web ${j.score_breakdown.web.points}/${j.score_breakdown.web.max}
              &middot; attack surface ${j.score_breakdown.attack_surface.points}/${j.score_breakdown.attack_surface.max}</div>
            ${renderGradeDelta(j)}
            <div class="links mt">${links.join(" ")}</div>
          </div>
        </div>
        <button class="ghost mt" id="report-print" type="button">Print / Save as PDF</button>
        <h2 class="mt">Findings</h2>
        ${j.findings.length ? j.findings.map(findingRow).join("") : '<p class="muted">No findings — every checked signal came back clean.</p>'}
      </div>`;
    const printBtn = document.getElementById("report-print");
    if (printBtn) printBtn.addEventListener("click", () => window.print());
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

  // ---- scrub — mat2 metadata cleaner -----------------------------------
  // XSS rule for this panel: every string it renders — metadata keys and
  // values, filenames, notes, mat2 error text — came out of a hostile file
  // via the server, so treat it all as attacker-controlled. The panels above
  // build innerHTML from Bastion's own data with N.esc(); here nothing
  // touches innerHTML at all — N.el() text nodes / textContent only, belt
  // and braces.
  const SCRUB_TOKEN_RE = /^[A-Za-z0-9_-]+$/;
  let scrubStatus = null;          // /api/scrub/status payload
  let scrubFormats = new Set();    // lowercase extensions with the dot, ".jpg"
  const scrubCards = [];           // per-file card state, oldest first

  function humanSize(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    const units = ["KB", "MB", "GB"];
    let v = n, u = -1;
    do { v /= 1024; u++; } while (v >= 1024 && u < units.length - 1);
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + " " + units[u];
  }

  function extOf(name) {
    const s = String(name || "");
    const i = s.lastIndexOf(".");
    return i > 0 ? s.slice(i).toLowerCase() : "";
  }

  // Raw-body upload. N.post can't be reused here (it JSON.stringifies the
  // body), but the response is parsed exactly the way N.post parses its own.
  async function scrubUploadRequest(file) {
    const r = await fetch("/api/scrub/upload", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": encodeURIComponent(file.name),
        "Accept": "application/json",
      },
      body: file,
    });
    const t = await r.text();
    let j; try { j = t ? JSON.parse(t) : {}; } catch (_) { j = { raw: t }; }
    if (!r.ok) throw Object.assign(new Error(j.error || r.statusText), { status: r.status, body: j });
    return j;
  }

  function scrubOpts() {
    const lw = document.getElementById("scrub-lightweight");
    const um = document.getElementById("scrub-unknown");
    return {
      lightweight: !!(lw && lw.checked),
      unknown_members: um ? um.value : "abort",
    };
  }

  function scrubPillEl(state) {
    const cls = state === "cleaned" ? "ok" : state === "error" ? "bad" : "";
    return N.el("span", { class: ("pill " + cls).trim() }, [
      N.el("span", { class: "dot" }), state,
    ]);
  }

  function metadataTable(pairs) {
    const wrap = N.el("div", { class: "meta-wrap" });
    const build = (all) => {
      const tbody = N.el("tbody");
      (all ? pairs : pairs.slice(0, 30)).forEach(p => {
        tbody.appendChild(N.el("tr", {}, [
          N.el("td", { class: "mkey", text: String(p.key == null ? "" : p.key) }),
          N.el("td", { class: "mval", text: String(p.value == null ? "" : p.value) }),
        ]));
      });
      return N.el("table", { class: "meta-table" }, [tbody]);
    };
    const scroller = N.el("div", { class: "meta-scroll" }, [build(false)]);
    wrap.appendChild(scroller);
    if (pairs.length > 30) {
      const more = N.el("button", { class: "ghost meta-more", type: "button", text: "show all " + pairs.length });
      more.addEventListener("click", () => { scroller.replaceChildren(build(true)); more.remove(); });
      wrap.appendChild(more);
    }
    return wrap;
  }

  function noteLines(notes) {
    return (notes || []).map(n => N.el("div", { class: "fc-note faint", text: String(n) }));
  }

  function scrubRemoveBtn(c) {
    const b = N.el("button", { class: "ghost", type: "button", text: "Remove" });
    b.addEventListener("click", () => removeScrubCard(c));
    return b;
  }

  function scrubCardBody(c) {
    const body = N.el("div", { class: "fc-body" });
    if (c.state === "inspecting") {
      body.appendChild(N.el("div", { class: "fc-wait muted" }, [
        N.el("span", { class: "spinner" }), "reading metadata…",
      ]));
      return body;
    }
    if (c.state === "error") {
      body.appendChild(N.el("div", { class: "fc-error", text: c.error || "failed" }));
      const row = N.el("div", { class: "fc-actions" });
      if (c.token) {
        // Clean failed but the upload session is still alive — let the user
        // act on mat2's message (e.g. flip unknown members to omit) and retry.
        const retry = N.el("button", { class: "ghost", type: "button", text: "Try again" });
        retry.addEventListener("click", () => { c.error = null; c.state = "ready"; renderScrubCard(c); });
        row.appendChild(retry);
      }
      row.appendChild(scrubRemoveBtn(c));
      body.appendChild(row);
      return body;
    }
    if (c.state === "ready" || c.state === "cleaning") {
      noteLines(c.notes).forEach(el => body.appendChild(el));
      if ((c.metadata || []).length) body.appendChild(metadataTable(c.metadata));
      else body.appendChild(N.el("p", { class: "muted m0", text: "No metadata found — cleaning will still normalize the file." }));
      const row = N.el("div", { class: "fc-actions" });
      const clean = N.el("button", { type: "button" });
      if (c.state === "cleaning") {
        clean.disabled = true;
        clean.appendChild(N.el("span", { class: "spinner" }));
        clean.appendChild(document.createTextNode("Cleaning…"));
      } else {
        clean.textContent = "Clean";
        clean.addEventListener("click", () => cleanScrubCard(c));
      }
      row.appendChild(clean);
      const rm = scrubRemoveBtn(c);
      if (c.state === "cleaning") rm.disabled = true;
      row.appendChild(rm);
      body.appendChild(row);
      return body;
    }
    // cleaned — the re-check verdict, what changed, and the download
    const r = c.result || {};
    const after = r.metadata_after || [];
    if (r.clean) {
      body.appendChild(N.el("div", { class: "fc-verdict ok", text: "✓ Cleaned — re-checked: no metadata left" }));
    } else {
      body.appendChild(N.el("div", {
        class: "fc-verdict warn",
        text: "Cleaned — " + after.length + (after.length === 1 ? " entry remains" : " entries remain")
          + " (lightweight mode keeps some)",
      }));
    }
    noteLines(r.notes).forEach(el => body.appendChild(el));
    if (!r.clean && after.length) body.appendChild(metadataTable(after));
    body.appendChild(N.el("div", {
      class: "fc-sizes faint",
      text: humanSize(r.size_before) + " → " + humanSize(r.size_after)
        + (r.cleaned_name ? " · " + String(r.cleaned_name) : ""),
    }));
    const row = N.el("div", { class: "fc-actions" });
    if (c.token && SCRUB_TOKEN_RE.test(c.token)) {
      // Relative URL built from the validated token — deliberately NOT
      // N.safeUrl(), which whitelists absolute http(s)/mailto and would
      // rewrite a relative path to "#". The token can't smuggle a scheme or
      // an extra query param past the character class above.
      row.appendChild(N.el("a", {
        class: "btn", text: "Download cleaned file",
        href: "/api/scrub/file?token=" + c.token,
      }));
    }
    row.appendChild(scrubRemoveBtn(c));
    body.appendChild(row);
    return body;
  }

  function renderScrubCard(c) {
    if (!c.el) {
      c.el = N.el("div", { class: "card file-card" });
      document.getElementById("scrub-list").appendChild(c.el);
    }
    const head = N.el("div", { class: "fc-head" }, [
      N.el("div", { class: "fc-id" }, [
        N.el("span", { class: "fc-name", text: c.name }),
        N.el("span", { class: "fc-ext", text: (c.ext || "?").replace(/^\./, "") }),
        N.el("span", { class: "fc-size", text: humanSize(c.size) }),
      ]),
      scrubPillEl(c.state),
    ]);
    c.el.replaceChildren(head, scrubCardBody(c));
    updateScrubControls();
  }

  async function uploadScrubFile(c, file) {
    try {
      const j = await scrubUploadRequest(file);
      c.token = SCRUB_TOKEN_RE.test(String(j.token || "")) ? j.token : null;
      c.name = j.name || c.name;
      c.size = j.size != null ? j.size : c.size;
      c.ext = j.ext || c.ext;
      c.metadata = j.metadata || [];
      c.notes = j.notes || [];
      if (j.error) {            // tolerated shape: 200 with an error field
        c.error = String(j.error);
        c.state = "error";
      } else if (!c.token) {
        c.error = "server returned a malformed token";
        c.state = "error";
      } else {
        c.state = "ready";
      }
    } catch (e) {
      c.error = e.message;
      c.state = "error";
    }
    renderScrubCard(c);
  }

  function addScrubFiles(fileList) {
    if (!scrubStatus || !scrubStatus.available) return;
    Array.from(fileList || []).forEach(file => {
      if (!file.size) { N.toast("skipped " + file.name + " — empty file", "bad"); return; }
      const c = {
        name: file.name, size: file.size, ext: extOf(file.name),
        token: null, state: "inspecting", metadata: [], notes: [],
        result: null, error: null, el: null,
      };
      scrubCards.push(c);
      // client-side pre-checks — the server revalidates every one of these
      if (file.size > scrubStatus.max_upload_bytes) {
        c.state = "error";
        c.error = "too big — " + humanSize(file.size) + " (limit " + humanSize(scrubStatus.max_upload_bytes) + ")";
        renderScrubCard(c);
        return;
      }
      if (!c.ext || !scrubFormats.has(c.ext)) {
        c.state = "error";
        c.error = "mat2 can't clean " + (c.ext || "extension-less") + " files (" + scrubFormats.size + " formats supported)";
        renderScrubCard(c);
        return;
      }
      renderScrubCard(c);
      uploadScrubFile(c, file);
    });
  }

  async function cleanScrubCard(c) {
    if (c.state !== "ready" || !c.token) return;
    c.state = "cleaning";
    renderScrubCard(c);
    const o = scrubOpts();
    try {
      c.result = await N.post("/api/scrub/clean", {
        token: c.token, lightweight: o.lightweight, unknown_members: o.unknown_members,
      });
      c.state = "cleaned";
    } catch (e) {
      c.error = e.message;
      c.state = "error";
    }
    renderScrubCard(c);
  }

  async function removeScrubCard(c) {
    const i = scrubCards.indexOf(c);
    if (i >= 0) scrubCards.splice(i, 1);
    if (c.el) c.el.remove();
    updateScrubControls();
    if (c.token) {
      try { await N.post("/api/scrub/delete", { token: c.token }); }
      catch (_) { /* server purges stale sessions anyway */ }
    }
  }

  async function cleanAllScrub() {
    const btn = document.getElementById("scrub-clean-all");
    if (btn) btn.disabled = true;
    // sequential on purpose — one mat2 subprocess at a time
    for (const c of scrubCards.slice()) {
      if (c.state === "ready") await cleanScrubCard(c);
    }
    if (btn) btn.disabled = false;
  }

  async function clearAllScrub() {
    for (const c of scrubCards.slice()) await removeScrubCard(c);
  }

  function updateScrubControls() {
    const ready = scrubCards.filter(c => c.state === "ready").length;
    const cleanAll = document.getElementById("scrub-clean-all");
    const clearAll = document.getElementById("scrub-clear-all");
    if (cleanAll) cleanAll.classList.toggle("hidden", ready < 2);
    if (clearAll) clearAll.classList.toggle("hidden", scrubCards.length === 0);
  }

  function renderScrubZone(st) {
    const wrap = document.getElementById("scrub-zone-wrap");
    const input = N.el("input", { type: "file", multiple: "", class: "hidden" });
    input.addEventListener("change", () => { addScrubFiles(input.files); input.value = ""; });
    const zone = N.el("div", {
      class: "drop-zone", role: "button", tabindex: "0",
      "aria-label": "Add files to scrub — opens the file picker",
    }, [
      N.el("div", { class: "dz-main", text: "Add files — click or drop them here" }),
      N.el("div", { class: "dz-sub", text: "Cleaned on this machine by " + (st.version || "mat2") + ". Nothing leaves loopback." }),
    ]);
    zone.addEventListener("click", () => input.click());
    zone.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    ["dragenter", "dragover"].forEach(ev => zone.addEventListener(ev, e => {
      e.preventDefault(); zone.classList.add("drag");
    }));
    zone.addEventListener("dragleave", () => zone.classList.remove("drag"));
    zone.addEventListener("drop", e => {
      e.preventDefault(); zone.classList.remove("drag");
      if (e.dataTransfer) addScrubFiles(e.dataTransfer.files);
    });
    wrap.replaceChildren(zone, input);
  }

  function renderScrubOptions() {
    const el = document.getElementById("scrub-options");
    const lw = N.el("input", { type: "checkbox", id: "scrub-lightweight" });
    const lwLine = N.el("label", { class: "checkline" }, [
      lw,
      N.el("span", {}, [
        "Lightweight mode ",
        N.el("span", { class: "faint", text: "— keeps more quality, removes less; full clean is the default" }),
      ]),
    ]);
    const um = N.el("select", { id: "scrub-unknown" }, [
      N.el("option", { value: "abort", text: "abort (default)" }),
      N.el("option", { value: "omit", text: "omit" }),
      N.el("option", { value: "keep", text: "keep" }),
    ]);
    const umLine = N.el("label", { class: "checkline" }, ["Archives with unknown members:", um]);
    const cleanAll = N.el("button", { type: "button", id: "scrub-clean-all", class: "hidden", text: "Clean all" });
    cleanAll.addEventListener("click", cleanAllScrub);
    const clearAll = N.el("button", { type: "button", id: "scrub-clear-all", class: "ghost hidden", text: "Clear all" });
    clearAll.addEventListener("click", clearAllScrub);
    el.replaceChildren(N.el("div", { class: "scrub-opts" }, [
      lwLine, umLine,
      N.el("div", { class: "scrub-actions" }, [cleanAll, clearAll]),
    ]));
  }

  async function loadScrub() {
    const note = document.getElementById("scrub-status-note");
    let st;
    try { st = await N.get("/api/scrub/status"); }
    catch (e) { note.textContent = "scrub status failed: " + e.message; return; }
    scrubStatus = st;
    if (!st.available) {
      // fail loud — no drop zone, just the fix
      const card = N.el("div", { class: "card" }, [
        N.el("p", { class: "muted m0" }, [
          "mat2 is not installed — the scrub panel is offline. Install it: ",
          N.el("code", { text: "sudo pacman -S mat2" }),
        ]),
      ]);
      if (st.reason) card.appendChild(N.el("p", { class: "faint small", text: String(st.reason) }));
      document.getElementById("scrub-zone-wrap").replaceChildren(card);
      return;
    }
    scrubFormats = new Set((st.formats || []).map(f => String(f).toLowerCase()));
    note.textContent = (st.version || "mat2") + " · " + (st.format_count || scrubFormats.size) + " formats · "
      + (st.sandbox ? "parsers sandboxed (bwrap)" : "bwrap missing — parsers run unsandboxed")
      + " · uploads auto-purge after 24h";
    renderScrubZone(st);
    renderScrubOptions();
  }

  document.addEventListener("DOMContentLoaded", function () {
    loadAnonymity();
    setInterval(loadAnonymity, 20000);
    loadPosture();
    loadHardeningPlan();
    loadHardening();
    loadScrub();
    document.getElementById("report-run").addEventListener("click", runReport);
    document.getElementById("report-domain").addEventListener("keydown", e => {
      if (e.key === "Enter") runReport();
    });
  });
})();
