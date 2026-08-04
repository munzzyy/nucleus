(function () {
  "use strict";
  const N = window.Nucleus;

  // Everything on this page comes from /proc, /sys, or a process cmdline —
  // i.e. strings this box happens to be running. We treat all of it as
  // untrusted and build the DOM with N.el / textContent only; nothing here
  // ever touches innerHTML.

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

  function panelMsg(el, msg, cls) {
    el.replaceChildren(N.el("div", { class: "card" }, [
      N.el("p", { class: (cls || "muted") + " m0", text: msg }),
    ]));
  }

  // ---- headline stat cards -------------------------------------------------
  function hlCard(id, label) {
    return N.el("div", { class: "card hl-card" }, [
      N.el("div", { class: "stat" }, [
        N.el("div", { class: "num", id: id + "-num", text: "—" }),
        N.el("div", { class: "lbl", text: label }),
      ]),
      N.el("div", { class: "bar", id: id + "-bar" }, [N.el("div", { class: "bar-fill" })]),
    ]);
  }

  function buildHeadline() {
    document.getElementById("sys-headline").replaceChildren(
      hlCard("hl-cpu", "cpu"),
      hlCard("hl-mem", "memory"),
      hlCard("hl-disk", "disk /"),
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

  // ---- overview ------------------------------------------------------------
  async function loadOverview() {
    const el = document.getElementById("sys-overview");
    try {
      const j = await N.get("/api/systems/overview");
      const load = j.loadavg ? j.loadavg.map(x => Number(x).toFixed(2)).join("  ") : "n/a";
      const boot = j.boot_time ? new Date(j.boot_time * 1000).toLocaleString() : "n/a";
      el.replaceChildren(kv([
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
      ]));
    } catch (e) {
      panelMsg(el, "overview failed: " + e.message);
    }
  }

  // ---- cpu -----------------------------------------------------------------
  async function loadCpu() {
    const el = document.getElementById("sys-cpu");
    try {
      const j = await N.get("/api/systems/cpu");
      setHl("hl-cpu", j.overall_percent);

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

      el.replaceChildren(N.el("div", { class: "card" }, [meta, coreGrid]));
    } catch (e) {
      panelMsg(el, "cpu failed: " + e.message);
    }
  }

  // ---- memory --------------------------------------------------------------
  async function loadMemory() {
    const el = document.getElementById("sys-memory");
    try {
      const j = await N.get("/api/systems/memory");
      if (j.available === false) {
        setHl("hl-mem", null);
        panelMsg(el, "memory: " + (j.reason || "unavailable"));
        return;
      }
      setHl("hl-mem", j.percent);
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
      el.replaceChildren(N.el("div", { class: "card" }, [memBlock, swapBlock, breakdown]));
    } catch (e) {
      panelMsg(el, "memory failed: " + e.message);
    }
  }

  // ---- disks ---------------------------------------------------------------
  async function loadDisks() {
    const el = document.getElementById("sys-disks");
    try {
      const j = await N.get("/api/systems/disks");
      const disks = j.disks || [];
      const root = disks.find(d => d.mount === "/");
      setHl("hl-disk", root ? root.percent : null);
      if (!disks.length) { panelMsg(el, "no mounted block filesystems found"); return; }
      const rows = disks.map(d => {
        const h = d.human || {};
        const pctCell = N.el("div", { class: "pct-cell" }, [
          bar(d.percent), N.el("span", { class: "pct-num mono", text: d.percent + "%" }),
        ]);
        return [mono(d.mount), mono(d.device), d.fstype, h.total, h.used, h.free, pctCell];
      });
      el.replaceChildren(N.el("div", { class: "card" }, [
        table(["mount", "device", "fstype", "size", "used", "free", "usage"], rows),
      ]));
    } catch (e) {
      panelMsg(el, "disks failed: " + e.message);
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

  async function loadNetwork() {
    const el = document.getElementById("sys-network");
    try {
      const j = await N.get("/api/systems/network");
      const ifaces = j.interfaces || [];
      if (!ifaces.length) { panelMsg(el, "no network interfaces found"); return; }
      const rows = ifaces.map(i => {
        const state = N.el("span", { class: "pill " + (i.is_up ? "ok" : "") }, [
          N.el("span", { class: "dot" }), i.operstate,
        ]);
        const name = N.el("span", {}, [
          mono(i.name), i.is_loopback ? N.el("span", { class: "faint small", text: " (loopback)" }) : "",
        ]);
        return [name, state, mono(i.mac || "—"), i.mtu == null ? "—" : i.mtu,
                i.rx_human, i.tx_human, addrCell(i.addresses)];
      });
      el.replaceChildren(N.el("div", { class: "card" }, [
        table(["interface", "state", "MAC", "MTU", "rx", "tx", "addresses"], rows),
      ]));
    } catch (e) {
      panelMsg(el, "network failed: " + e.message);
    }
  }

  // ---- listening ports -----------------------------------------------------
  async function loadListening() {
    const el = document.getElementById("sys-listening");
    try {
      const j = await N.get("/api/systems/listening");
      const all = (j.tcp || []).concat(j.udp || []);
      if (!all.length) { panelMsg(el, "nothing listening"); return; }
      const rows = all.map(r => [
        r.proto,
        mono(r.address),
        mono(String(r.port)),
        r.state,
        r.pid == null ? N.el("span", { class: "faint", text: "—" }) : mono(String(r.pid)),
        r.process ? r.process : N.el("span", { class: "faint", text: "unattributed" }),
      ]);
      const parts = [table(["proto", "address", "port", "state", "pid", "process"], rows)];
      if (!j.resolved) {
        parts.push(N.el("p", { class: "faint small m0",
          text: "Process names need matching /proc/<pid>/fd access — run as the socket owner (or root) to attribute more." }));
      }
      if (j.truncated) {
        parts.push(N.el("p", { class: "faint small m0", text: "list truncated" }));
      }
      el.replaceChildren(N.el("div", { class: "card" }, parts));
    } catch (e) {
      panelMsg(el, "listening ports failed: " + e.message);
    }
  }

  // ---- processes -----------------------------------------------------------
  function procTable(list, valueLabel, valueFn) {
    const rows = (list || []).map(p => {
      const name = N.el("span", { class: "proc-name", title: p.cmdline || p.name, text: p.name });
      return [mono(String(p.pid)), name, valueFn(p)];
    });
    return table(["pid", "name", valueLabel], rows);
  }

  async function loadProcesses() {
    const el = document.getElementById("sys-processes");
    try {
      const j = await N.get("/api/systems/processes");
      const cpuCard = N.el("div", { class: "card" }, [
        N.el("h3", { text: "Top by CPU" }),
        procTable(j.by_cpu, "cpu %", p => mono(p.cpu_pct + "%")),
      ]);
      const memCard = N.el("div", { class: "card" }, [
        N.el("h3", { text: "Top by memory" }),
        procTable(j.by_mem, "rss", p => N.el("span", {}, [
          mono(p.rss_human), N.el("span", { class: "faint small", text: " · " + p.mem_pct + "%" }),
        ])),
      ]);
      el.replaceChildren(N.el("div", { class: "grid cols-2" }, [cpuCard, memCard]));
    } catch (e) {
      panelMsg(el, "processes failed: " + e.message);
    }
  }

  // ---- sensors -------------------------------------------------------------
  function tempClass(c) { return c >= 85 ? "bad" : c >= 70 ? "warn" : ""; }

  async function loadSensors() {
    const el = document.getElementById("sys-sensors");
    try {
      const j = await N.get("/api/systems/sensors");
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
        panelMsg(el, "no temperature or power sensors exposed on this machine");
        return;
      }
      el.replaceChildren.apply(el, parts);
    } catch (e) {
      panelMsg(el, "sensors failed: " + e.message);
    }
  }

  // ---- services ------------------------------------------------------------
  async function loadServices() {
    const el = document.getElementById("sys-services");
    try {
      const j = await N.get("/api/systems/services");
      if (j.available === false) {
        panelMsg(el, "services: " + (j.reason || "systemctl unavailable"));
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
      el.replaceChildren(N.el("div", { class: "card" }, parts));
    } catch (e) {
      panelMsg(el, "services failed: " + e.message);
    }
  }

  // ---- refresh orchestration ----------------------------------------------
  function loadAll() {
    loadOverview();
    loadCpu();
    loadMemory();
    loadDisks();
    loadNetwork();
    loadListening();
    loadProcesses();
    loadSensors();
    loadServices();
  }

  const timers = [];
  function every(ms, fn) { timers.push(setInterval(fn, ms)); }

  document.addEventListener("DOMContentLoaded", function () {
    buildHeadline();
    loadAll();

    // Cheap, "right now" panels refresh fastest; the scan-heavy ones slower.
    every(5000, loadCpu);
    every(5000, loadMemory);
    every(10000, loadProcesses);
    every(10000, loadListening);
    every(15000, loadDisks);
    every(15000, loadNetwork);
    every(15000, loadSensors);
    every(30000, loadOverview);
    every(30000, loadServices);

    const btn = document.getElementById("sys-refresh");
    if (btn) btn.addEventListener("click", () => { loadAll(); N.toast("refreshed", "ok"); });
  });
})();
