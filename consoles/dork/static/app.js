(function () {
  "use strict";
  const N = window.Nucleus;
  const esc = N.esc;

  const form = document.getElementById("dork-form");
  const domainInput = document.getElementById("dork-domain");
  const brandInput = document.getElementById("dork-brand");
  const engineSelect = document.getElementById("dork-engine");
  const genBtn = document.getElementById("dork-btn");
  const statusLine = document.getElementById("dork-status");
  const metaEl = document.getElementById("dork-meta");
  const toolbar = document.getElementById("dork-toolbar");
  const resultsEl = document.getElementById("dork-results");
  const sourcesWrap = document.getElementById("dork-sources-wrap");
  const sourcesEl = document.getElementById("dork-sources");

  // Engine URL templates — the one place link construction lives (the server
  // sends raw queries so it stays pure logic). Keep in sync with the <select>
  // AND with generator.ENGINE_SEARCH_URL (a unit test asserts server parity).
  const ENGINE = {
    google: q => "https://www.google.com/search?q=" + encodeURIComponent(q),
    bing: q => "https://www.bing.com/search?q=" + encodeURIComponent(q),
    duckduckgo: q => "https://duckduckgo.com/?q=" + encodeURIComponent(q),
    yandex: q => "https://yandex.com/search/?text=" + encodeURIComponent(q),
    brave: q => "https://search.brave.com/search?q=" + encodeURIComponent(q),
  };
  const ENGINE_LABEL = { google: "Google", bing: "Bing", duckduckgo: "DuckDuckGo", yandex: "Yandex", brave: "Brave" };
  const ENGINE_ORDER = ["google", "bing", "duckduckgo", "yandex", "brave"];
  const RISK_WORD = { info: "info", recon: "recon", sensitive: "sensitive" };

  // Matches MAX_OPEN_URLS in app.py — cap a bulk "open all" so one click can't
  // spawn hundreds of tabs. The server rejects more; we cap client-side first
  // so we can warn instead of erroring.
  const MAX_FF = 40;

  const lastDomainStore = N.remember("last-domain");
  const engineStore = N.remember("engine");
  const ffStore = N.remember("open-firefox");   // route link clicks into Firefox

  let lastData = null;
  let ffOn = ffStore.get(true) !== false;       // default ON — the whole point

  function currentEngine() {
    const e = engineSelect.value;
    return ENGINE[e] ? e : "google";
  }

  function engineLink(query, engine) {
    return N.safeUrl((ENGINE[engine] || ENGINE.google)(query));
  }

  // -- open in firefox ------------------------------------------------------
  // Hands the server a list of {engine, query} and/or {url} targets; it rebuilds
  // engine URLs from its own template map and host-allowlists source URLs, then
  // launches Firefox. Falls back to opening plain tabs in the host browser if
  // Firefox isn't installed (501) so a click always does something.
  async function openInFirefox(targets, opts) {
    opts = opts || {};
    if (!targets.length) return;
    let list = targets;
    if (list.length > MAX_FF) {
      list = list.slice(0, MAX_FF);
      N.toast("opening the first " + MAX_FF + " of " + targets.length, "warn");
    }
    try {
      const r = await N.post("/api/open", { targets: list });
      const n = r.opened || 0;
      const skip = (r.skipped || []).length;
      N.toast("opened " + n + " in Firefox" + (skip ? " · " + skip + " skipped" : ""), "ok");
    } catch (e) {
      if (e.status === 501) {          // no Firefox — degrade to normal tabs
        N.toast("Firefox not found — opening in this browser", "warn");
        list.forEach(t => {
          const url = t.url || engineLink(t.query, t.engine);
          window.open(url, "_blank", "noopener,noreferrer");
        });
        return;
      }
      N.toast(e.message || "Firefox launch failed", "bad");
    }
  }

  // the per-engine query variant the server built (Google syntax translated to
  // the engine's dialect); falls back to the canonical query for safety
  function engEntry(d, engine) {
    return (d.eng && d.eng[engine]) ? d.eng[engine] : { q: d.query, level: "full" };
  }
  function engQ(d, engine) { return engEntry(d, engine).q; }

  function dorkTarget(query, engine) {
    return { engine: engine || currentEngine(), query: query };
  }
  function categoryTargets(data, key) {
    const cat = (data.categories || []).find(c => c.key === key);
    if (!cat) return [];
    const eng = currentEngine();
    return cat.dorks.map(d => dorkTarget(engQ(d, eng), eng));
  }
  function allDorkTargets(data, riskFilter) {
    const eng = currentEngine();
    return (data.categories || []).flatMap(c => c.dorks)
      .filter(d => !riskFilter || d.risk === riskFilter)
      .map(d => dorkTarget(engQ(d, eng), eng));
  }
  function sourceTargets(data) {
    return (data.sources || []).map(s => ({ url: s.url }));
  }

  // -- rendering ------------------------------------------------------------
  function renderMeta(data) {
    metaEl.innerHTML =
      'target <b>' + esc(data.host) + '</b>' +
      (data.apex && data.apex !== data.host ? ' · apex <b>' + esc(data.apex) + '</b>' : '') +
      ' · brand <b>' + esc(data.brand) + '</b>' +
      ' · <span class="count">' + esc(data.count) + '</span> dorks' +
      ' · <span class="count">' + esc((data.sources || []).length) + '</span> sources';
    metaEl.classList.remove("hidden");
  }

  // one engine link, built from the server's per-engine query variant. A
  // "degraded" engine (it has no equivalent for an operator the dork uses) is
  // dimmed and gets a "~" and a tooltip, so we never pretend a query runs the
  // same everywhere.
  function engineAnchor(d, e, isPrimary) {
    const ent = engEntry(d, e);
    const deg = ent.level === "degraded";
    const cls = (isPrimary ? "btn primary-engine" : "") + (deg ? " deg" : "");
    const title = deg
      ? ENGINE_LABEL[e] + " ignores an operator in this dork — results are approximate"
      : (isPrimary ? "" : ENGINE_LABEL[e] + " ↗");
    const label = isPrimary ? esc(ENGINE_LABEL[e]) + " ↗" : esc(ENGINE_LABEL[e]) + (deg ? " ~" : "");
    return '<a class="' + cls.trim() + '" href="' + esc(engineLink(ent.q, e)) +
      '" data-engine="' + e + '" data-q="' + esc(ent.q) + '"' +
      (title ? ' title="' + esc(title) + '"' : '') +
      ' target="_blank" rel="noopener noreferrer">' + label + '</a>';
  }

  function dorkRow(d, primary) {
    const risk = RISK_WORD[d.risk] ? d.risk : "recon";
    const q = esc(d.query);
    const alts = ENGINE_ORDER.filter(e => e !== primary).map(e => engineAnchor(d, e, false)).join("");
    return '' +
      '<div class="dork">' +
        '<div class="dork-head">' +
          '<span class="label">' + esc(d.label) + '</span>' +
          '<span class="risk ' + risk + '">' + esc(RISK_WORD[risk]) + '</span>' +
        '</div>' +
        '<div class="dork-q" data-q="' + q + '" title="click to copy the Google-syntax query" role="button" tabindex="0">' + q + '</div>' +
        '<div class="dork-why">' + esc(d.why) + '</div>' +
        '<div class="dork-engines">' +
          engineAnchor(d, primary, true) +
          '<div class="alts">' + alts + '</div>' +
        '</div>' +
      '</div>';
  }

  function categoryCard(cat, primary) {
    const rows = cat.dorks.map(d => dorkRow(d, primary)).join("");
    return '' +
      '<div class="card cat-card" data-cat="' + esc(cat.key) + '">' +
        '<div class="cat-head">' +
          '<h2>' + esc(cat.name) + ' <span class="faint">(' + cat.dorks.length + ')</span></h2>' +
          '<div class="cat-actions">' +
            '<button type="button" class="ghost cat-ff" data-cat-open="' + esc(cat.key) + '" title="Open every dork in this group as Firefox tabs">🦊 Open all</button>' +
            '<button type="button" class="ghost cat-copy" data-cat-copy="' + esc(cat.key) + '">Copy all</button>' +
          '</div>' +
        '</div>' +
        '<p class="cat-why">' + esc(cat.why) + '</p>' +
        rows +
      '</div>';
  }

  function renderResults(data) {
    const primary = currentEngine();
    resultsEl.innerHTML = (data.categories || []).map(c => categoryCard(c, primary)).join("");
    renderSources(data);
  }

  function renderSources(data) {
    const items = data.sources || [];
    if (!items.length) { sourcesWrap.classList.add("hidden"); return; }
    sourcesEl.innerHTML = items.map(s =>
      '<a class="card link" href="' + esc(N.safeUrl(s.url)) + '" data-src="' + esc(N.safeUrl(s.url)) + '" target="_blank" rel="noopener noreferrer">' +
        '<div class="r-name">' + esc(s.name) + '</div>' +
        '<div class="r-note faint">' + esc(s.why) + '</div>' +
      '</a>'
    ).join("");
    sourcesWrap.classList.remove("hidden");
  }

  // -- copy / export --------------------------------------------------------
  function allQueries(data) {
    return (data.categories || []).flatMap(c => c.dorks.map(d => d.query)).join("\n");
  }

  function categoryQueries(data, key) {
    const cat = (data.categories || []).find(c => c.key === key);
    return cat ? cat.dorks.map(d => d.query).join("\n") : "";
  }

  function toMarkdown(data) {
    const primary = currentEngine();
    const lines = [];
    lines.push("# Dork sheet — " + data.host);
    lines.push("Target: `" + data.host + "` · apex `" + data.apex + "` · brand `" + data.brand +
      "` · " + data.count + " dorks · engine: " + ENGINE_LABEL[primary]);
    lines.push("");
    lines.push("> Passive recon only — run these only against assets you own or are authorized to test.");
    lines.push("");
    (data.categories || []).forEach(cat => {
      lines.push("## " + cat.name);
      lines.push("_" + cat.why + "_");
      lines.push("");
      cat.dorks.forEach(d => {
        lines.push("- **" + d.label + "** [" + d.risk + "] — `" + d.query + "`");
        lines.push("  " + (ENGINE[primary] || ENGINE.google)(d.query));
      });
      lines.push("");
    });
    if ((data.sources || []).length) {
      lines.push("## Specialist sources");
      data.sources.forEach(s => lines.push("- [" + s.name + "](" + s.url + ") — " + s.why));
      lines.push("");
    }
    return lines.join("\n").trim() + "\n";
  }

  function buildToolbar() {
    toolbar.innerHTML = "";

    // the Firefox routing toggle — when on, clicking any engine/source link
    // opens it in Firefox instead of a tab in whatever browser hosts this page
    const tgl = N.el("label", { class: "ff-toggle", title: "When on, engine and source links open in Firefox via the launcher" });
    const cb = N.el("input", { type: "checkbox" });
    cb.checked = ffOn;
    cb.addEventListener("change", () => { ffOn = cb.checked; ffStore.set(ffOn); });
    tgl.appendChild(cb);
    tgl.appendChild(N.el("span", { text: "🦊 Links → Firefox" }));
    toolbar.appendChild(tgl);

    const ffAll = N.el("button", { class: "ghost", type: "button", text: "🦊 Open all", title: "Open every dork as a Firefox tab (capped at " + MAX_FF + ")" });
    ffAll.addEventListener("click", () => { if (lastData) openInFirefox(allDorkTargets(lastData)); });
    toolbar.appendChild(ffAll);

    const ffSens = N.el("button", { class: "ghost", type: "button", text: "🦊 Open sensitive", title: "Open only the sensitive-risk dorks in Firefox" });
    ffSens.addEventListener("click", () => { if (lastData) openInFirefox(allDorkTargets(lastData, "sensitive")); });
    toolbar.appendChild(ffSens);

    toolbar.appendChild(N.copyButton(() => allQueries(lastData),
      { label: "Copy all queries", title: "Copy every dork query, one per line" }));
    toolbar.appendChild(N.copyButton(() => toMarkdown(lastData),
      { label: "Copy as Markdown", title: "Copy the whole sheet as Markdown" }));
    const dl = N.el("button", { class: "ghost", type: "button", text: "Download .md" });
    dl.addEventListener("click", () => {
      if (!lastData) return;
      N.download("dork-" + lastData.host + ".md", toMarkdown(lastData), "text/markdown");
    });
    toolbar.appendChild(dl);
    const dlTxt = N.el("button", { class: "ghost", type: "button", text: "Download .txt" });
    dlTxt.addEventListener("click", () => {
      if (!lastData) return;
      N.download("dork-" + lastData.host + ".txt", allQueries(lastData), "text/plain");
    });
    toolbar.appendChild(dlTxt);
    toolbar.classList.remove("hidden");
  }

  // clicks inside the results grid: category open/copy, engine-link routing,
  // and click-a-query-to-copy
  resultsEl.addEventListener("click", (e) => {
    const catOpen = e.target.closest("[data-cat-open]");
    if (catOpen) {
      e.preventDefault();
      if (lastData) openInFirefox(categoryTargets(lastData, catOpen.getAttribute("data-cat-open")));
      return;
    }
    const catCopy = e.target.closest("[data-cat-copy]");
    if (catCopy) {
      N.copy(categoryQueries(lastData, catCopy.getAttribute("data-cat-copy")), "category copied");
      return;
    }
    // an engine link — route to Firefox when the toggle is on
    const eng = e.target.closest("a[data-engine]");
    if (eng && ffOn) {
      e.preventDefault();
      openInFirefox([dorkTarget(eng.getAttribute("data-q"), eng.getAttribute("data-engine"))]);
      return;
    }
    if (eng) return;   // toggle off → let the anchor open normally
    const q = e.target.closest(".dork-q");
    if (q) N.copy(q.getAttribute("data-q"), "query copied");
  });
  resultsEl.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const q = e.target.closest(".dork-q");
    if (q) { e.preventDefault(); N.copy(q.getAttribute("data-q"), "query copied"); }
  });

  // source cards — route to Firefox when the toggle is on
  sourcesEl.addEventListener("click", (e) => {
    const src = e.target.closest("a[data-src]");
    if (src && ffOn) {
      e.preventDefault();
      openInFirefox([{ url: src.getAttribute("data-src") }]);
    }
  });

  // -- run ------------------------------------------------------------------
  async function generate(domain, keyword) {
    genBtn.disabled = true;
    statusLine.classList.remove("hidden");
    statusLine.innerHTML = '<span class="spinner"></span> building dork set…';
    resultsEl.innerHTML = "";
    metaEl.classList.add("hidden");
    toolbar.classList.add("hidden");
    sourcesWrap.classList.add("hidden");
    try {
      const data = await N.post("/api/dork", { domain: domain, keyword: keyword || "" });
      lastData = data;
      renderMeta(data);
      renderResults(data);
      buildToolbar();
      statusLine.textContent = data.count + " dorks + " + (data.sources || []).length +
        " sources for " + data.host;
      lastDomainStore.set(domain);
      writeHash(domain, keyword);
    } catch (e) {
      statusLine.textContent = "";
      resultsEl.innerHTML = '<div class="card"><p class="bad">' + esc(e.message || "generation failed") + '</p></div>';
      N.toast(e.message || "generation failed", "bad");
    } finally {
      genBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const domain = domainInput.value.trim();
    if (!domain) { N.toast("enter a website first", "bad"); return; }
    generate(domain, brandInput.value.trim());
  });

  // switching the primary engine re-renders the links without re-fetching
  engineSelect.addEventListener("change", () => {
    engineStore.set(engineSelect.value);
    if (lastData) { renderResults(lastData); buildToolbar(); }
  });

  // -- deep link + empty state ---------------------------------------------
  function writeHash(domain, keyword) {
    try {
      let h = "#d=" + encodeURIComponent(domain);
      if (keyword) h += "&k=" + encodeURIComponent(keyword);
      history.replaceState(null, "", h);
    } catch (_) { /* deep-link is a nicety */ }
  }
  function readHash() {
    const h = (location.hash || "").replace(/^#/, "");
    if (!h) return null;
    const p = {};
    h.split("&").forEach(part => {
      const i = part.indexOf("=");
      if (i < 0) return;
      try { p[decodeURIComponent(part.slice(0, i))] = decodeURIComponent(part.slice(i + 1)); }
      catch (_) { /* skip a malformed pair */ }
    });
    return p.d ? { d: p.d, k: p.k || "" } : null;
  }

  const EXAMPLES = ["gomoon.ai", "example.com", "target.com"];
  function renderEmptyState() {
    const wrap = N.el("div", { class: "card" });
    wrap.appendChild(N.el("h2", { text: "Generate a dork set" }));
    wrap.appendChild(N.el("p", { class: "sub", text: "Paste a website above and hit Generate, or start from an example:" }));
    const row = N.el("div", { class: "row mt" });
    EXAMPLES.forEach(ex => {
      const b = N.el("button", { class: "ghost", type: "button", text: ex });
      b.addEventListener("click", () => { domainInput.value = ex; generate(ex, ""); });
      row.appendChild(b);
    });
    wrap.appendChild(row);
    resultsEl.innerHTML = "";
    resultsEl.appendChild(wrap);
  }

  // a couple of palette commands for muscle memory
  N.registerCommand({ label: "Copy all queries", section: "Dork",
    run: () => { if (lastData) N.copy(allQueries(lastData), "queries copied"); } });
  N.registerCommand({ label: "Copy sheet as Markdown", section: "Dork",
    run: () => { if (lastData) N.copy(toMarkdown(lastData), "markdown copied"); } });
  N.registerCommand({ label: "Open all dorks in Firefox", section: "Dork",
    run: () => { if (lastData) openInFirefox(allDorkTargets(lastData)); } });
  N.registerCommand({ label: "Open sensitive dorks in Firefox", section: "Dork",
    run: () => { if (lastData) openInFirefox(allDorkTargets(lastData, "sensitive")); } });

  (function init() {
    const savedEngine = engineStore.get(null);
    if (savedEngine && ENGINE[savedEngine]) engineSelect.value = savedEngine;
    const linked = readHash();
    if (linked) {
      domainInput.value = linked.d;
      if (linked.k) brandInput.value = linked.k;
      generate(linked.d, linked.k);
      return;
    }
    const lastDomain = lastDomainStore.get(null);
    if (lastDomain) domainInput.value = lastDomain;
    renderEmptyState();
  })();
})();
