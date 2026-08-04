(function () {
  "use strict";
  const N = window.Nucleus;

  // Everything on this page comes from /proc, /sys, or a process cmdline —
  // i.e. strings this box happens to be running. We treat all of it as
  // untrusted and build the DOM with N.el / textContent only; nothing here
  // ever touches innerHTML.

  // The last successful response from every panel, kept so the sort/filter
  // controls and the snapshot export can work off what's on screen without
  // re-hitting the collectors. Purely client-side — no server state.
  const state = {
    overview: null, cpu: null, memory: null, disks: null, network: null,
    listening: null, processes: null, sensors: null, services: null,
  };

  // Short in-browser ring buffers behind the headline sparklines. Client-side
  // only: the systems collectors stay stateless and keep no history server-side.
  const SPARK_MAX = 60;
  const cpuHistory = [];
  const memHistory = [];

  // ---- small render helpers ------------------------------------------------
  function barClass(p) { return p >= 90 ? "bad" : p >= 70 ? "warn" : ""; }

  function bar(pct) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    const fill = N.el("div", { class: "bar-fill " + barClass(p) });
    fill.style.width = p + "%";  // CSSOM write — allowed under the strict CSP
    return N.el("div", { class: "bar" }, [fill]);
  }

  function td(cell) {
    if (cell && cell.nodeType) return N.el("td", {}, [cell]);
    return N.el("td", { text: cell == null ? "" : String(cell) });
  }

  function mono(text) { return N.el("span", { class: "mono", text: text == null ? "" : String(text) }); }

  function table(headers, rows) {
    const thead = N.el("thead", {}, [N.el("tr", {}, headers.map(h => N.el("th", { text: h })))]);
    const tbody = N.el("tbody", {}, rows.map(r => N.el("tr", {}, r.map(td))));
    return N.el("div", { class: "table-scroll" }, [N.el("table", {}, [thead, tbody])]);
  }

  function kv(pairs) {
    const dl = N.el("dl", { class: "kv" });
    pairs.forEach(([k, v]) => {
      dl.appendChild(N.el("dt", { text: k }));
      dl.appendChild(N.el("dd", {}, [
        v && v.nodeType ? v : document.createTextNode(v == null || v === "" ? "n/a" : String(v)),
      ]));
    });
    return dl;
  }

  // ---- plain-text builders for the copy/download buttons -------------------
  function linesText(pairs) {
    return pairs.map(p => {
      const v = p[1];
      return p[0] + ": " + (v == null || v === "" ? "n/a" : String(v));
    }).join("\n");
  }

  function tableText(headers, rows) {
    const out = [headers.join("\t")];
    rows.forEach(r => out.push(r.map(c => (c == null ? "" : String(c))).join("\t")));
    return out.join("\n");
  }

  // ---- state blocks --------------------------------------------------------
  // A failure looks like a failure (red, role=alert); an honest "nothing here"
  // reads as empty, not broken. Clearing a table panel's cached scaffold makes
  // the next successful load rebuild it from scratch.
  function panelError(el, msg) { el._scaffold = null; el.replaceChildren(N.stateCard("error", msg)); }
  function panelEmpty(el, msg) { el._scaffold = null; el.replaceChildren(N.stateCard("empty", msg)); }

  // ---- headline stat cards -------------------------------------------------
  function hlCard(id, label, withSpark) {
    const kids = [
      N.el("div", { class: "stat" }, [
        N.el("div", { class: "num", id: id + "-num", text: "—" }),
        N.el("div", { class: "lbl", text: label }),
      ]),
      N.el("div", { class: "bar", id: id + "-bar" }, [N.el("div", { class: "bar-fill" })]),
    ];
    if (withSpark) kids.push(N.el("div", { class: "spark-wrap", id: id + "-spark" }));
    return N.el("div", { class: "card hl-card" }, kids);
  }

  function buildHeadline() {
    document.getElementById("sys-headline").replaceChildren(
      hlCard("hl-cpu", "cpu", true),
      hlCard("hl-mem", "memory", true),
      hlCard("hl-disk", "disk /", false),
    );
  }

  function setHl(id, pct) {
    const num = document.getElementById(id + "-num");
    const barEl = document.getElementById(id + "-bar");
    if (num) num.textContent = pct == null ? "—" : Math.round(pct) + "%";
    if (barEl && barEl.firstChild) {
      const p = Math.max(0, Math.min(100, Number(pct) || 0));
      barEl.firstChild.className = "bar-fill " + barClass(p);
      barEl.firstChild.style.width = p + "%";
    }
  }

  // ---- sparklines (inline SVG, no external deps) ---------------------------
  const SVG_NS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs, children) {
    const e = document.createElementNS(SVG_NS, tag);
    if (attrs) for (const k in attrs) { if (attrs[k] != null) e.setAttribute(k, String(attrs[k])); }
    (children || []).forEach(c => e.appendChild(c));
    return e;
  }

  function sparkLabel(name, values) {
    if (!values.length) return name + " history: collecting samples";
    const last = Math.round(values[values.length - 1]);
    const hi = Math.round(Math.max.apply(null, values));
    const lo = Math.round(Math.min.apply(null, values));
    return name + " history: latest " + last + "%, ranging " + lo + " to " + hi
      + "% over the last " + values.length + " samples";
  }

  // y is fixed to a 0..100 scale so CPU and memory sparklines are directly
  // comparable and an idle box reads as a flat line near the floor, not a
  // deceptively dramatic auto-scaled wiggle.
  function sparkline(name, values) {
    const w = 140, h = 34, pad = 3;
    const last = values.length ? values[values.length - 1] : null;
    const cls = last == null ? "" : barClass(last);
    const svg = svgEl("svg", {
      class: ("spark " + cls).trim(), viewBox: "0 0 " + w + " " + h,
      preserveAspectRatio: "none", width: w, height: h,
      role: "img", "aria-label": sparkLabel(name, values),
    });
    const n = values.length;
    if (n < 2) {
      svg.appendChild(svgEl("line", { class: "spark-base",
        x1: 0, y1: h - pad, x2: w, y2: h - pad }));
      return svg;
    }
    const yFor = v => (h - pad) - (Math.max(0, Math.min(100, v)) / 100) * (h - pad * 2);
    const xFor = i => (i / (n - 1)) * w;
    const pts = values.map((v, i) => xFor(i).toFixed(1) + "," + yFor(v).toFixed(1)).join(" ");
    svg.appendChild(svgEl("polygon", { class: "spark-area", points: "0," + h + " " + pts + " " + w + "," + h }));
    svg.appendChild(svgEl("polyline", { class: "spark-line", points: pts }));
    svg.appendChild(svgEl("circle", { class: "spark-dot",
      cx: xFor(n - 1).toFixed(1), cy: yFor(last).toFixed(1), r: 2.2 }));
    return svg;
  }

  function pushHistory(kind, pct) {
    if (pct == null) return;
    const buf = kind === "cpu" ? cpuHistory : memHistory;
    buf.push(Math.max(0, Math.min(100, Number(pct) || 0)));
    while (buf.length > SPARK_MAX) buf.shift();
    const wrap = document.getElementById(kind === "cpu" ? "hl-cpu-spark" : "hl-mem-spark");
    if (wrap) wrap.replaceChildren(sparkline(kind === "cpu" ? "CPU" : "Memory", buf));
  }

  // ---- overview ------------------------------------------------------------
  async function loadOverview() {
    const el = document.getElementById("sys-overview");
    try {
      const j = await N.get("/api/systems/overview");
      state.overview = j;
      const load = j.loadavg ? j.loadavg.map(x => Number(x).toFixed(2)).join("  ") : "n/a";
      const boot = j.boot_time ? new Date(j.boot_time * 1000).toLocaleString() : "n/a";
      el.replaceChildren(N.el("div", { class: "card" }, [
        kv([
          ["hostname", j.hostname],
          ["os", j.os_name],
          ["kernel", mono(j.kernel)],
          ["arch", j.arch],
          ["uptime", j.uptime_human],
          ["booted", boot],
          ["load avg", mono(load)],
          ["cpu count", j.cpu_count],
          ["memory", j.mem_total_human],
          ["python", mono(j.python)],
          ["user", j.user],
        ]),
        N.resultBar({
          getText: () => linesText([
            ["hostname", j.hostname], ["os", j.os_name], ["kernel", j.kernel], ["arch", j.arch],
            ["uptime", j.uptime_human], ["booted", boot], ["load avg", load],
            ["cpu count", j.cpu_count], ["memory", j.mem_total_human], ["python", j.python], ["user", j.user],
          ]),
          json: j, filename: "systems-overview",
        }),
      ]));
    } catch (e) {
      panelError(el, "overview failed: " + e.message);
    }
  }

  // ---- cpu -----------------------------------------------------------------
  async function loadCpu() {
    const el = document.getElementById("sys-cpu");
    try {
      const j = await N.get("/api/systems/cpu");
      state.cpu = j;
      setHl("hl-cpu", j.overall_percent);
      pushHistory("cpu", j.overall_percent);

      const meta = kv([
        ["model", j.model],
        ["cores", (j.physical_cores != null ? j.physical_cores : "?") + " physical · "
          + (j.logical_cores != null ? j.logical_cores : "?") + " logical"],
        ["overall", j.overall_percent == null ? "n/a" : j.overall_percent + "%"],
        ["flags", (j.flags_of_interest || []).length ? mono((j.flags_of_interest).join(" ")) : "n/a"],
      ]);

      const coreGrid = N.el("div", { class: "core-grid" });
      (j.per_core || []).forEach(c => {
        coreGrid.appendChild(N.el("div", { class: "core-item" }, [
          N.el("div", { class: "core-top" }, [
            N.el("span", { class: "core-lbl", text: "cpu" + c.core }),
            N.el("span", { class: "core-pct mono", text: (c.percent == null ? "—" : c.percent + "%") }),
          ]),
          bar(c.percent),
          N.el("div", { class: "core-mhz faint", text: c.mhz == null ? "" : c.mhz + " MHz" }),
        ]));
      });

      const barKit = N.resultBar({
        getText: () => linesText([
          ["model", j.model],
          ["cores", (j.physical_cores != null ? j.physical_cores : "?") + " physical / "
            + (j.logical_cores != null ? j.logical_cores : "?") + " logical"],
          ["overall", j.overall_percent == null ? "n/a" : j.overall_percent + "%"],
          ["flags", (j.flags_of_interest || []).join(" ")],
        ]) + "\n\n" + tableText(["core", "cpu %", "MHz"],
          (j.per_core || []).map(c => ["cpu" + c.core, c.percent == null ? "n/a" : c.percent, c.mhz == null ? "" : c.mhz])),
        json: j, filename: "systems-cpu",
      });

      el.replaceChildren(N.el("div", { class: "card" }, [meta, coreGrid, barKit]));
    } catch (e) {
      panelError(el, "cpu failed: " + e.message);
    }
  }

  // ---- memory --------------------------------------------------------------
  async function loadMemory() {
    const el = document.getElementById("sys-memory");
    try {
      const j = await N.get("/api/systems/memory");
      state.memory = j;
      if (j.available === false) {
        setHl("hl-mem", null);
        panelEmpty(el, "memory: " + (j.reason || "unavailable"));
        return;
      }
      setHl("hl-mem", j.percent);
      pushHistory("mem", j.percent);
      const h = j.human || {};
      const memBlock = N.el("div", { class: "mem-block" }, [
        N.el("div", { class: "mem-head" }, [
          N.el("span", { text: "RAM" }),
          N.el("span", { class: "mono", text: h.used + " / " + h.total + " (" + j.percent + "%)" }),
        ]),
        bar(j.percent),
      ]);
      const swapBlock = N.el("div", { class: "mem-block" }, [
        N.el("div", { class: "mem-head" }, [
          N.el("span", { text: "swap" }),
          N.el("span", { class: "mono", text: (j.swap_total ? h.swap_used + " / " + h.swap_total + " (" + j.swap_percent + "%)" : "none") }),
        ]),
        bar(j.swap_percent),
      ]);
      const breakdown = kv([
        ["available", h.available],
        ["free", h.free],
        ["cached", h.cached],
        ["buffers", h.buffers],
      ]);
      const barKit = N.resultBar({
        getText: () => linesText([
          ["RAM", h.used + " / " + h.total + " (" + j.percent + "%)"],
          ["swap", j.swap_total ? h.swap_used + " / " + h.swap_total + " (" + j.swap_percent + "%)" : "none"],
          ["available", h.available], ["free", h.free], ["cached", h.cached], ["buffers", h.buffers],
        ]),
        json: j, filename: "systems-memory",
      });
      el.replaceChildren(N.el("div", { class: "card" }, [memBlock, swapBlock, breakdown, barKit]));
    } catch (e) {
      panelError(el, "memory failed: " + e.message);
    }
  }

  // ---- disks ---------------------------------------------------------------
  async function loadDisks() {
    const el = document.getElementById("sys-disks");
    try {
      const j = await N.get("/api/systems/disks");
      state.disks = j;
      const disks = j.disks || [];
      const root = disks.find(d => d.mount === "/");
      setHl("hl-disk", root ? root.percent : null);
      if (!disks.length) { panelEmpty(el, "no mounted block filesystems found"); return; }
      const rows = disks.map(d => {
        const h = d.human || {};
        const pctCell = N.el("div", { class: "pct-cell" }, [
          bar(d.percent), N.el("span", { class: "pct-num mono", text: d.percent + "%" }),
        ]);
        return [mono(d.mount), mono(d.device), d.fstype, h.total, h.used, h.free, pctCell];
      });
      const barKit = N.resultBar({
        getText: () => tableText(["mount", "device", "fstype", "size", "used", "free", "usage %"],
          disks.map(d => [d.mount, d.device, d.fstype, (d.human || {}).total, (d.human || {}).used, (d.human || {}).free, d.percent])),
        json: j, filename: "systems-disks",
      });
      el.replaceChildren(N.el("div", { class: "card" }, [
        table(["mount", "device", "fstype", "size", "used", "free", "usage"], rows),
        barKit,
      ]));
    } catch (e) {
      panelError(el, "disks failed: " + e.message);
    }
  }

  // ---- network -------------------------------------------------------------
  function addrCell(addresses) {
    if (!addresses || !addresses.length) return N.el("span", { class: "faint", text: "—" });
    const wrap = N.el("div", { class: "addr-list" });
    addresses.forEach(a => {
      wrap.appendChild(N.el("div", {}, [
        N.el("span", { class: "addr-fam faint", text: a.family === "ipv6" ? "v6" : "v4" }),
        mono(a.address + (a.prefixlen != null ? "/" + a.prefixlen : "")),
      ]));
    });
    return wrap;
  }

  function addrText(addresses) {
    return (addresses || []).map(a => a.address + (a.prefixlen != null ? "/" + a.prefixlen : "")).join(" ");
  }

  async function loadNetwork() {
    const el = document.getElementById("sys-network");
    try {
      const j = await N.get("/api/systems/network");
      state.network = j;
      const ifaces = j.interfaces || [];
      if (!ifaces.length) { panelEmpty(el, "no network interfaces found"); return; }
      const rows = ifaces.map(i => {
        const st = N.el("span", { class: "pill " + (i.is_up ? "ok" : "") }, [
          N.el("span", { class: "dot" }), i.operstate,
        ]);
        const name = N.el("span", {}, [
          mono(i.name), i.is_loopback ? N.el("span", { class: "faint small", text: " (loopback)" }) : "",
        ]);
        return [name, st, mono(i.mac || "—"), i.mtu == null ? "—" : i.mtu,
                i.rx_human, i.tx_human, addrCell(i.addresses)];
      });
      const barKit = N.resultBar({
        getText: () => tableText(["interface", "state", "MAC", "MTU", "rx", "tx", "addresses"],
          ifaces.map(i => [i.name, i.operstate, i.mac || "", i.mtu == null ? "" : i.mtu, i.rx_human, i.tx_human, addrText(i.addresses)])),
        json: j, filename: "systems-network",
      });
      el.replaceChildren(N.el("div", { class: "card" }, [
        table(["interface", "state", "MAC", "MTU", "rx", "tx", "addresses"], rows),
        barKit,
      ]));
    } catch (e) {
      panelError(el, "network failed: " + e.message);
    }
  }

  // ---- generic sortable + filterable table panel --------------------------
  // A panel that stays put across background refreshes: the filter box and the
  // copy/download bar are built once (so typing keeps focus and the caret), and
  // only the table body is swapped when data or the sort/filter changes.
  function applyView(rows, view, cols, rowText) {
    const q = (view.filter || "").trim().toLowerCase();
    let out = q ? rows.filter(r => rowText(r).toLowerCase().indexOf(q) >= 0) : rows.slice();
    const col = cols.find(c => c.key === view.sort.key) || cols[0];
    const dir = view.sort.dir === "asc" ? 1 : -1;
    out.sort((a, b) => {
      const va = col.sortVal(a), vb = col.sortVal(b);
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
    return out;
  }

  function buildSortTable(cols, rows, view, rerender) {
    const ths = cols.map(c => {
      const active = view.sort.key === c.key;
      const th = N.el("th", {
        class: "sortable" + (active ? " sorted" : ""), "data-key": c.key,
        role: "button", tabindex: "0", title: "Sort by " + c.label,
        "aria-sort": active ? (view.sort.dir === "asc" ? "ascending" : "descending") : "none",
      });
      th.appendChild(document.createTextNode(c.label));
      if (active) th.appendChild(N.el("span", { class: "sort-arrow", text: view.sort.dir === "asc" ? "▲" : "▼" }));
      const onSort = () => {
        if (view.sort.key === c.key) view.sort.dir = view.sort.dir === "asc" ? "desc" : "asc";
        else { view.sort.key = c.key; view.sort.dir = c.defaultDir || "asc"; }
        view._refocus = c.key;
        rerender();
      };
      th.addEventListener("click", onSort);
      th.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSort(); }
      });
      return th;
    });
    const thead = N.el("thead", {}, [N.el("tr", {}, ths)]);
    const tbody = N.el("tbody", {}, rows.map(r => N.el("tr", {}, cols.map(c => {
      const cell = c.cell(r);
      return (cell && cell.nodeType) ? N.el("td", {}, [cell]) : N.el("td", { text: cell == null ? "" : String(cell) });
    }))));
    return N.el("div", { class: "table-scroll" }, [N.el("table", {}, [thead, tbody])]);
  }

  // Keyboard sorters lose focus when the header they clicked gets replaced;
  // put it back on the matching column so a keyboard user can keep toggling.
  function applyRefocus(host, view) {
    if (!view._refocus) return;
    const key = view._refocus;
    view._refocus = null;
    const th = host.querySelector('th[data-key="' + key + '"]');
    if (th && th.focus) { try { th.focus(); } catch (_) { /* gone */ } }
  }

  function ensureTablePanel(el, view, opts) {
    if (el._scaffold) return el._scaffold;
    const filter = N.el("input", { type: "search", class: "tbl-filter",
      placeholder: opts.placeholder, "aria-label": opts.placeholder });
    filter.value = view.filter || "";
    filter.addEventListener("input", () => { view.filter = filter.value; opts.rerender(); });
    const count = N.el("span", { class: "faint small tbl-count" });
    const controls = N.el("div", { class: "tbl-controls" }, [filter, count]);
    const tableHost = N.el("div", { class: "tbl-host" });
    const bar = N.resultBar({ getText: opts.barText, json: opts.barJson, filename: "systems-" + opts.barName });
    const card = N.el("div", { class: "card" }, [controls, tableHost, bar]);
    el.replaceChildren(card);
    el._scaffold = { filter, count, tableHost };
    return el._scaffold;
  }

  function countLabel(shown, total) {
    return shown + (shown === total ? "" : " of " + total) + " shown";
  }

  // ---- listening ports -----------------------------------------------------
  const LISTEN_COLS = [
    { key: "proto", label: "proto", defaultDir: "asc", sortVal: r => r.proto, cell: r => r.proto },
    { key: "address", label: "address", defaultDir: "asc", sortVal: r => r.address, cell: r => mono(r.address) },
    { key: "port", label: "port", defaultDir: "asc", sortVal: r => r.port, cell: r => mono(String(r.port)) },
    { key: "state", label: "state", defaultDir: "asc", sortVal: r => r.state, cell: r => r.state },
    { key: "pid", label: "pid", defaultDir: "asc", sortVal: r => (r.pid == null ? -1 : r.pid),
      cell: r => r.pid == null ? N.el("span", { class: "faint", text: "—" }) : mono(String(r.pid)) },
    { key: "process", label: "process", defaultDir: "asc", sortVal: r => (r.process || "").toLowerCase(),
      cell: r => r.process ? r.process : N.el("span", { class: "faint", text: "unattributed" }) },
  ];
  const listenView = { sort: { key: "port", dir: "asc" }, filter: "" };

  function listenRows(j) { return ((j && j.tcp) || []).concat((j && j.udp) || []); }
  function listenRowText(r) { return r.proto + " " + r.address + " " + r.port + " " + r.state + " " + (r.process || ""); }
  function currentListenRows() { return applyView(listenRows(state.listening), listenView, LISTEN_COLS, listenRowText); }

  function renderListening() {
    const el = document.getElementById("sys-listening");
    const j = state.listening;
    if (!j) return;
    const all = listenRows(j);
    if (!all.length) { panelEmpty(el, "nothing listening"); return; }
    const sc = ensureTablePanel(el, listenView, {
      placeholder: "filter by address, port, or process",
      rerender: renderListening,
      barText: () => tableText(["proto", "address", "port", "state", "pid", "process"],
        currentListenRows().map(r => [r.proto, r.address, r.port, r.state, r.pid == null ? "" : r.pid, r.process || ""])),
      barJson: () => state.listening,
      barName: "listening",
    });
    const rows = applyView(all, listenView, LISTEN_COLS, listenRowText);
    sc.count.textContent = countLabel(rows.length, all.length);
    const parts = [buildSortTable(LISTEN_COLS, rows, listenView, renderListening)];
    if (!j.resolved) {
      parts.push(N.el("p", { class: "faint small m0",
        text: "Process names need matching /proc/<pid>/fd access — run as the socket owner (or root) to attribute more." }));
    }
    if (j.truncated) {
      parts.push(N.el("p", { class: "faint small m0", text: "list truncated" }));
    }
    sc.tableHost.replaceChildren.apply(sc.tableHost, parts);
    applyRefocus(sc.tableHost, listenView);
  }

  async function loadListening() {
    const el = document.getElementById("sys-listening");
    try {
      state.listening = await N.get("/api/systems/listening");
      renderListening();
    } catch (e) {
      panelError(el, "listening ports failed: " + e.message);
    }
  }

  // ---- processes -----------------------------------------------------------
  const PROC_COLS = [
    { key: "pid", label: "pid", defaultDir: "asc", sortVal: p => p.pid, cell: p => mono(String(p.pid)) },
    { key: "name", label: "name", defaultDir: "asc", sortVal: p => (p.name || "").toLowerCase(),
      cell: p => N.el("span", { class: "proc-name", title: p.cmdline || p.name, text: p.name }) },
    { key: "cpu", label: "cpu %", defaultDir: "desc", sortVal: p => p.cpu_pct, cell: p => mono(p.cpu_pct + "%") },
    { key: "mem", label: "memory", defaultDir: "desc", sortVal: p => p.rss,
      cell: p => N.el("span", {}, [mono(p.rss_human), N.el("span", { class: "faint small", text: " · " + p.mem_pct + "%" })]) },
  ];
  const procView = { sort: { key: "cpu", dir: "desc" }, filter: "" };

  // The collector returns two top-N lists (by cpu, by memory); merge them into
  // one deduped set so a single table can be sorted either way — the union of
  // the two tops is exactly the interesting-processes window.
  function mergeProcs(j) {
    const byPid = new Map();
    ((j && j.by_cpu) || []).forEach(p => byPid.set(p.pid, p));
    ((j && j.by_mem) || []).forEach(p => { if (!byPid.has(p.pid)) byPid.set(p.pid, p); });
    return Array.from(byPid.values());
  }

  function procRowText(p) { return p.name + " " + (p.cmdline || "") + " " + p.pid; }
  function currentProcRows() { return applyView(mergeProcs(state.processes), procView, PROC_COLS, procRowText); }

  function renderProcesses() {
    const el = document.getElementById("sys-processes");
    const j = state.processes;
    if (!j) return;
    const merged = mergeProcs(j);
    if (!merged.length) { panelEmpty(el, "no processes readable"); return; }
    const sc = ensureTablePanel(el, procView, {
      placeholder: "filter by name, pid, or command",
      rerender: renderProcesses,
      barText: () => tableText(["pid", "name", "cpu %", "memory %", "rss"],
        currentProcRows().map(p => [p.pid, p.name, p.cpu_pct, p.mem_pct, p.rss_human])),
      barJson: () => state.processes,
      barName: "processes",
    });
    const rows = applyView(merged, procView, PROC_COLS, procRowText);
    sc.count.textContent = countLabel(rows.length, merged.length);
    sc.tableHost.replaceChildren(buildSortTable(PROC_COLS, rows, procView, renderProcesses));
    applyRefocus(sc.tableHost, procView);
  }

  async function loadProcesses() {
    const el = document.getElementById("sys-processes");
    try {
      state.processes = await N.get("/api/systems/processes");
      renderProcesses();
    } catch (e) {
      panelError(el, "processes failed: " + e.message);
    }
  }

  // ---- sensors -------------------------------------------------------------
  function tempClass(c) { return c >= 85 ? "bad" : c >= 70 ? "warn" : ""; }

  async function loadSensors() {
    const el = document.getElementById("sys-sensors");
    try {
      const j = await N.get("/api/systems/sensors");
      state.sensors = j;
      const temps = j.temps || [];
      const bats = j.batteries || [];
      const parts = [];

      if (temps.length) {
        const grid = N.el("div", { class: "grid cols-4" });
        temps.forEach(t => {
          grid.appendChild(N.el("div", { class: "card temp-card" }, [
            N.el("div", { class: "temp-val mono " + tempClass(t.celsius), text: t.celsius + "°C" }),
            N.el("div", { class: "temp-lbl faint", text: t.label }),
          ]));
        });
        parts.push(grid);
      }

      if (bats.length) {
        const bgrid = N.el("div", { class: "grid cols-3 mt" });
        bats.forEach(b => {
          const cap = b.capacity == null ? null : b.capacity;
          bgrid.appendChild(N.el("div", { class: "card" }, [
            N.el("div", { class: "mem-head" }, [
              N.el("span", { text: b.name }),
              N.el("span", { class: "mono", text: (cap == null ? "?" : cap + "%") + " · " + b.status }),
            ]),
            bar(cap),
          ]));
        });
        parts.push(bgrid);
      }

      if (j.ac != null) {
        parts.push(N.el("p", { class: "faint small",
          text: "AC power: " + (j.ac ? "connected" : "on battery") }));
      }

      if (!parts.length) {
        panelEmpty(el, "no temperature or power sensors exposed on this machine");
        return;
      }
      parts.push(N.resultBar({
        getText: () => {
          const lines = temps.map(t => t.label + ": " + t.celsius + "°C");
          bats.forEach(b => lines.push(b.name + ": " + (b.capacity == null ? "?" : b.capacity + "%") + " (" + b.status + ")"));
          if (j.ac != null) lines.push("AC power: " + (j.ac ? "connected" : "on battery"));
          return lines.join("\n");
        },
        json: j, filename: "systems-sensors",
      }));
      el.replaceChildren.apply(el, parts);
    } catch (e) {
      panelError(el, "sensors failed: " + e.message);
    }
  }

  // ---- services ------------------------------------------------------------
  async function loadServices() {
    const el = document.getElementById("sys-services");
    try {
      const j = await N.get("/api/systems/services");
      state.services = j;
      if (j.available === false) {
        panelEmpty(el, "services: " + (j.reason || "systemctl unavailable"));
        return;
      }
      const head = N.el("div", { class: "svc-head" }, [
        N.el("div", { class: "stat" }, [
          N.el("div", { class: "num", text: String(j.running_count) }),
          N.el("div", { class: "lbl", text: "running (user)" }),
        ]),
        N.el("div", { class: "stat" }, [
          N.el("div", { class: "num " + (j.failed_count ? "bad-num" : ""), text: String(j.failed_count) }),
          N.el("div", { class: "lbl", text: "failed" }),
        ]),
      ]);
      const parts = [head];
      if ((j.failed || []).length) {
        const list = N.el("div", { class: "svc-failed" });
        j.failed.forEach(name => list.appendChild(
          N.el("div", { class: "svc-fail-row" }, [
            N.el("span", { class: "pill bad" }, [N.el("span", { class: "dot" }), "failed"]),
            mono(name),
          ])));
        parts.push(list);
      }
      if ((j.running || []).length) {
        const scroll = N.el("div", { class: "svc-scroll" },
          j.running.map(name => N.el("div", { class: "svc-run-row" }, [mono(name)])));
        parts.push(N.el("details", { class: "svc-details" }, [
          N.el("summary", { text: "running services (" + j.running.length + ")" }),
          scroll,
        ]));
      }
      parts.push(N.resultBar({
        getText: () => linesText([
          ["running (user)", j.running_count], ["failed", j.failed_count],
        ]) + (((j.failed || []).length) ? "\n\nfailed:\n" + j.failed.join("\n") : "")
          + (((j.running || []).length) ? "\n\nrunning:\n" + j.running.join("\n") : ""),
        json: j, filename: "systems-services",
      }));
      el.replaceChildren(N.el("div", { class: "card" }, parts));
    } catch (e) {
      panelError(el, "services failed: " + e.message);
    }
  }

  // ---- snapshot export -----------------------------------------------------
  function snapshot() {
    return {
      generated_at: new Date().toISOString(),
      host: (state.overview && state.overview.hostname) || null,
      overview: state.overview,
      cpu: state.cpu,
      memory: state.memory,
      disks: state.disks,
      network: state.network,
      listening: state.listening,
      processes: state.processes,
      sensors: state.sensors,
      services: state.services,
      history: { cpu_percent: cpuHistory.slice(), mem_percent: memHistory.slice() },
    };
  }

  // ---- refresh orchestration ----------------------------------------------
  // Each panel reschedules itself after it finishes (setTimeout, not a fixed
  // interval) so a slow collector never stacks overlapping requests. The whole
  // set honours one pause flag, one cadence multiplier, and the tab's
  // visibility — a backgrounded console stops polling loopback entirely.
  const PANELS = [
    { name: "overview", load: loadOverview, base: 30000 },
    { name: "cpu", load: loadCpu, base: 5000 },
    { name: "memory", load: loadMemory, base: 5000 },
    { name: "disks", load: loadDisks, base: 15000 },
    { name: "network", load: loadNetwork, base: 15000 },
    { name: "listening", load: loadListening, base: 10000 },
    { name: "processes", load: loadProcesses, base: 10000 },
    { name: "sensors", load: loadSensors, base: 15000 },
    { name: "services", load: loadServices, base: 30000 },
  ];

  let lastUpdate = 0;

  const poller = (function () {
    let userPaused = false;
    let mult = 1;
    let started = false;
    const timers = new Map();

    function running() { return !userPaused && !document.hidden; }

    function scheduleOne(p) {
      clearTimeout(timers.get(p.name));
      if (!running()) return;
      const ms = Math.max(1000, Math.round(p.base * mult));
      timers.set(p.name, setTimeout(async function () {
        try { await p.load(); } catch (_) { /* loaders render their own errors */ }
        markUpdated();
        if (running()) scheduleOne(p);   // a pause/hide during the await stops the loop
      }, ms));
    }

    function startAll() { started = true; PANELS.forEach(scheduleOne); }
    function stopAll() { timers.forEach(t => clearTimeout(t)); timers.clear(); }
    function restart() { stopAll(); if (running()) PANELS.forEach(scheduleOne); }

    return {
      startAll, stopAll,
      setMult(m) { mult = Number(m) || 1; if (started) restart(); },
      setPaused(p) {
        userPaused = !!p;
        if (userPaused) stopAll();
        else { loadAll(); if (started) restart(); }
      },
      onVisibility() {
        if (document.hidden) stopAll();
        else if (!userPaused) { loadAll(); if (started) restart(); }
      },
      isPaused() { return userPaused; },
      isHidden() { return !!document.hidden; },
    };
  })();

  function markUpdated() { lastUpdate = Date.now(); renderUpdatedLabel(); }

  function loadAll() {
    return Promise.allSettled(PANELS.map(p => {
      try { return Promise.resolve(p.load()); } catch (_) { return Promise.resolve(); }
    })).then(markUpdated);
  }

  function agoText(secs) {
    if (secs < 60) return secs + "s";
    const m = Math.floor(secs / 60), r = secs % 60;
    return r ? m + "m " + r + "s" : m + "m";
  }

  function renderUpdatedLabel() {
    const el = document.getElementById("sys-updated");
    if (!el) return;
    if (poller.isPaused()) { el.textContent = "paused"; return; }
    if (poller.isHidden()) { el.textContent = "paused — tab hidden"; return; }
    if (!lastUpdate) { el.textContent = ""; return; }
    const secs = Math.max(0, Math.round((Date.now() - lastUpdate) / 1000));
    el.textContent = secs < 2 ? "updated just now" : "updated " + agoText(secs) + " ago";
  }

  function updateControls() {
    const btn = document.getElementById("sys-pause");
    if (btn) {
      const paused = poller.isPaused();
      btn.textContent = paused ? "Resume" : "Pause";
      btn.setAttribute("aria-pressed", paused ? "true" : "false");
      btn.classList.toggle("active", paused);
    }
    renderUpdatedLabel();
  }

  function wireControls() {
    const cadence = document.getElementById("sys-cadence");
    if (cadence) {
      const remembered = N.remember("cadence").get(null);
      if (remembered != null) cadence.value = String(remembered);
      poller.setMult(Number(cadence.value) || 1);
      cadence.addEventListener("change", () => {
        poller.setMult(Number(cadence.value) || 1);
        N.remember("cadence").set(cadence.value);
      });
    }
    const pause = document.getElementById("sys-pause");
    if (pause) pause.addEventListener("click", () => {
      poller.setPaused(!poller.isPaused());
      updateControls();
      N.toast(poller.isPaused() ? "auto-refresh paused" : "auto-refresh resumed", "ok");
    });
    const snap = document.getElementById("sys-snapshot");
    if (snap) snap.addEventListener("click", () => {
      N.downloadJson(snapshot(), "systems-snapshot");
      N.toast("snapshot downloaded", "ok");
    });
    const refresh = document.getElementById("sys-refresh");
    if (refresh) refresh.addEventListener("click", () => { loadAll(); N.toast("refreshing", "ok"); });
    updateControls();
  }

  document.addEventListener("DOMContentLoaded", function () {
    buildHeadline();
    ["sys-overview", "sys-cpu", "sys-memory", "sys-disks", "sys-network",
     "sys-listening", "sys-processes", "sys-sensors", "sys-services"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.replaceChildren(N.stateCard("loading", "loading…"));
    });
    wireControls();
    loadAll();
    poller.startAll();
    document.addEventListener("visibilitychange", () => { poller.onVisibility(); updateControls(); });
    setInterval(renderUpdatedLabel, 1000);
  });
})();
