(function () {
  "use strict";
  const N = window.Nucleus;
  const esc = N.esc;

  const form = document.getElementById("scan-form");
  const qInput = document.getElementById("q");
  const typeSelect = document.getElementById("type");
  const scanBtn = document.getElementById("scan-btn");
  const statusLine = document.getElementById("status-line");
  const results = document.getElementById("results");
  const arsenalEl = document.getElementById("arsenal");

  const TYPE_LABEL = {
    username: "Username", email: "Email", domain: "Domain", ip: "IP address",
    phone: "Phone", name: "Name", company: "Company", crypto: "Crypto address",
    image: "Image URL", geo: "Geo coordinates",
  };

  function pill(kind, text) {
    return `<span class="pill ${kind}"><span class="dot"></span>${esc(text)}</span>`;
  }

  function card(title, bodyHtml) {
    return `<div class="card module-card"><h2>${esc(title)}</h2>${bodyHtml}</div>`;
  }

  // Values are HTML-escaped by default. Wrap a value in raw() to opt out when
  // it's intentional markup (a link, a <br>-joined list) that's already safe.
  const raw = (html) => ({ __html: html });

  function kv(pairs) {
    let rows = "";
    for (const [k, v] of pairs) {
      if (v === undefined || v === null || v === "") continue;
      const cell = (v && typeof v === "object" && "__html" in v) ? v.__html : esc(v);
      rows += `<dt>${esc(k)}</dt><dd>${cell}</dd>`;
    }
    return `<dl class="kv">${rows}</dl>`;
  }

  function list(items) {
    if (!items || !items.length) return '<p class="faint">none</p>';
    return `<div class="subdomain-list">${items.map(i => `<div>${esc(i)}</div>`).join("")}</div>`;
  }

  // -- pivots + dorks (shared by every type) --------------------------------
  function renderPivots(pivots) {
    if (!pivots || !pivots.length) return "";
    const links = pivots.map(p =>
      `<a class="card link" href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.title)}</a>`
    ).join("");
    return card("Pivot links", `<div class="pivot-grid">${links}</div>`);
  }

  function renderDorks(dorks) {
    if (!dorks || !dorks.length) return "";
    const rows = dorks.map(d => `
      <div class="dork-row">
        <div class="label">${esc(d.label)}</div>
        <div class="q">${esc(d.query)}</div>
        <a class="btn ghost" href="${esc(d.google)}" target="_blank" rel="noopener noreferrer">Google</a>
        <a class="btn ghost" href="${esc(d.bing)}" target="_blank" rel="noopener noreferrer">Bing</a>
      </div>`).join("");
    return card("Dork builder", rows);
  }

  // -- per-module renderers ---------------------------------------------------
  function renderUsername(m) {
    const sites = (m.sites || []).map(s => {
      const kind = s.found === true ? "found" : s.found === false ? "notfound" : "unknown";
      const inner = s.url
        ? `<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer" title="${esc(s.note)}">${esc(s.site)}</a>`
        : `<span title="${esc(s.note)}">${esc(s.site)}</span>`;
      return `<div class="site-pill ${kind}"><span class="dot"></span>${inner}</div>`;
    }).join("");
    const summary = `<div class="badge-row">
        ${pill("ok", `${m.found_count} found`)}
        ${pill("bad", `${m.not_found_count} not found`)}
        ${pill("warn", `${m.unknown_count} unknown`)}
        <span class="faint">checked ${m.checked} sites in ${m.took_ms}ms</span>
      </div>`;
    return card("Username", summary + `<div class="site-grid">${sites}</div>`);
  }

  function renderEmail(m) {
    const bc = m.breach_check || {};
    const an = m.breach_analytics || {};
    const gv = m.gravatar || {};
    const summary = kv([
      ["Breached", bc.ok ? (bc.breached ? `yes — ${bc.breaches.length} breach(es)` : "no known exposure") : "check failed"],
      ["Risk", an.risk_label ? `${an.risk_label} (${an.risk_score})` : "n/a"],
      ["Gravatar", gv.checked ? (gv.exists ? "profile exists" : "no profile") : "check failed"],
      ["MX records", m.has_mx ? (m.mx || []).join(", ") : "none found"],
    ]);
    let breachList = "";
    if (an.breaches && an.breaches.length) {
      breachList = an.breaches.slice(0, 25).map(b => `
        <div class="breach-row">
          <div class="name">${esc(b.name || "unknown")} <span class="faint">— ${esc(b.domain || "")}</span></div>
          <div class="meta">${esc(b.year || "")} · ${b.records ? b.records.toLocaleString() + " records" : ""}
            · password risk: ${esc(b.password_risk || "unknown")} · verified: ${esc(String(b.verified))}</div>
          <div class="classes">${(b.data_classes || []).slice(0, 10).map(c => `<span class="tag">${esc(c)}</span>`).join("")}</div>
        </div>`).join("");
      breachList = `<div class="mt">${breachList}</div>`;
    }
    return card("Email", summary + breachList);
  }

  function renderDomain(m) {
    const dns = m.dns || {};
    const dnsHtml = kv([
      ["A", (dns.A || []).join(", ")],
      ["AAAA", (dns.AAAA || []).join(", ")],
      ["MX", (dns.MX || []).join(", ")],
      ["NS", (dns.NS || []).join(", ")],
      ["CNAME", (dns.CNAME || []).join(", ")],
      ["TXT", raw((dns.TXT || []).map(esc).join("<br>"))],
    ]);

    const w = m.whois || {};
    const whoisHtml = kv([
      ["Registrar", w.registrar],
      ["Handle", w.handle],
      ["Status", (w.status || []).join(", ")],
      ["Events", raw((w.events || []).map(e => `${esc(e.action)}: ${esc(e.date)}`).join("<br>"))],
      ["Error", w.error],
    ]);

    const posture = m.email_posture || {};
    const postureHtml = `<div class="badge-row">
        ${pill(posture.spf_present ? "ok" : "bad", posture.spf_present ? "SPF present" : "no SPF")}
        ${pill(posture.dmarc_present ? "ok" : "bad", posture.dmarc_present ? "DMARC present" : "no DMARC")}
      </div>` + kv([["SPF", posture.spf || ""], ["DMARC", posture.dmarc || ""]]);

    const http = m.http || {};
    let httpHtml = '<p class="faint">no response</p>';
    if (http.ok) {
      const sh = http.security_headers || {};
      const hpills = Object.entries(sh).map(([k, v]) => pill(v ? "ok" : "bad", k.replace(/_/g, " "))).join(" ");
      httpHtml = kv([
        ["Status", `${http.scheme}:// → HTTP ${http.status}`],
        ["Server", http.server],
        ["X-Powered-By", http.powered_by],
        ["Security score", http.security_score],
      ]) + `<div class="badge-row mt">${hpills}</div>`;
    }

    const subs = m.subdomains || {};
    const subsHtml = subs.ok
      ? `<p class="faint mb">${subs.count} unique name(s) via crt.sh</p>${list(subs.names)}`
      : `<p class="faint">${esc(subs.error || "unavailable")}</p>`;

    const wb = m.wayback || {};
    const wbHtml = wb.ok
      ? kv([["Archived", wb.archived ? "yes" : "no"], ["Latest snapshot", wb.url ? raw(`<a href="${esc(wb.url)}" target="_blank" rel="noopener noreferrer">${esc(wb.timestamp || "")}</a>`) : ""]])
      : `<p class="faint">${esc(wb.error || "unavailable")}</p>`;

    const h = m.hosting || {};
    const hostingHtml = kv([
      ["IP", h.ip],
      ["Open ports", (h.ports || []).join(", ")],
      ["CVEs", (h.cves || []).join(", ")],
      ["Tags", (h.tags || []).join(", ")],
      ["Geo", h.geo ? `${h.geo.city || ""}, ${h.geo.country || ""} — ${h.geo.org || h.geo.isp || ""}` : ""],
      ["Error", h.error],
    ]);

    return [
      card("DNS", dnsHtml),
      card("WHOIS (RDAP)", whoisHtml),
      card("Email posture (SPF / DMARC)", postureHtml),
      card("HTTP + security headers", httpHtml),
      card("Hosting chain", hostingHtml),
      card("Subdomains (crt.sh)", subsHtml),
      card("Wayback Machine", wbHtml),
    ].join("");
  }

  function renderIp(m) {
    if (m.error) return card("IP", `<p class="bad">${esc(m.error)}</p>`);
    const idb = m.internetdb || {};
    const idbHtml = idb.ok
      ? kv([
          ["Open ports", (idb.ports || []).join(", ") || "none"],
          ["CVEs", (idb.cves || []).join(", ") || "none"],
          ["Hostnames", (idb.hostnames || []).join(", ")],
          ["Tags", (idb.tags || []).join(", ")],
        ])
      : `<p class="faint">${esc(idb.error || "unavailable")}</p>`;

    const geo = m.geo;
    const geoHtml = geo
      ? kv([["Location", `${geo.city || ""}, ${geo.region || ""}, ${geo.country || ""}`],
            ["ASN / org", geo.asn || geo.org || geo.isp || ""], ["Coordinates", `${geo.lat}, ${geo.lon}`]])
      : '<p class="faint">unavailable</p>';

    const rdns = m.reverse_dns || {};
    const rdnsHtml = rdns.ok ? kv([["Hostname", rdns.hostname]]) : `<p class="faint">${esc(rdns.error || "no PTR record")}</p>`;

    const rdap = m.rdap || {};
    const rdapHtml = rdap.ok
      ? kv([["Netblock", `${rdap.start} — ${rdap.end}`], ["Name", rdap.name], ["Type", rdap.type]])
      : `<p class="faint">${esc(rdap.error || "unavailable")}</p>`;

    const tor = m.tor || {};
    let torHtml = `<p class="faint">${esc(tor.error || "unavailable")}</p>`;
    if (tor.ok) {
      torHtml = `<div class="badge-row">
          ${pill(tor.is_relay ? "warn" : "ok", tor.is_relay ? "Tor relay" : "not a Tor relay")}
          ${tor.is_exit ? pill("bad", "Exit node") : ""}
        </div>` + list((tor.relays || []).map(r => r.nickname || "(unnamed)"));
    }

    return [
      card("InternetDB (Shodan)", idbHtml),
      card("Geolocation", geoHtml),
      card("Reverse DNS", rdnsHtml),
      card("RDAP netblock", rdapHtml),
      card("Tor (Onionoo)", torHtml),
    ].join("");
  }

  function renderPhone(m) {
    const l = m.lookup || {};
    const top = kv([["Country (guess)", m.country_guess || "unknown"], ["Digits", m.digit_count]]);
    let lookupHtml;
    if (!l.configured) {
      lookupHtml = `<p class="faint">${esc(l.note)}</p>`;
    } else if (l.ok) {
      lookupHtml = kv([
        ["Valid", l.valid === true ? "yes" : l.valid === false ? "no" : "unknown"],
        ["Carrier", l.carrier], ["Line type", l.line_type], ["Location", l.location],
        ["Country", l.country_name], ["International format", l.international_format],
      ]);
    } else {
      lookupHtml = `<p class="bad">${esc(l.error || "lookup failed")}</p>`;
    }
    return card("Phone", top + lookupHtml);
  }

  const RENDERERS = {
    username: renderUsername, email: renderEmail, domain: renderDomain,
    ip: renderIp, phone: renderPhone,
  };

  async function runScan(q, type) {
    scanBtn.disabled = true;
    statusLine.classList.remove("hidden");
    statusLine.innerHTML = '<span class="spinner"></span> scanning…';
    results.innerHTML = "";
    try {
      const data = await N.post("/api/scan", { type, q });
      renderResults(data);
      statusLine.textContent = `detected: ${TYPE_LABEL[data.detected_type] || data.detected_type} · ${data.took_ms}ms`;
    } catch (e) {
      statusLine.textContent = "";
      N.toast(e.message || "scan failed", "bad");
      results.innerHTML = `<div class="card"><p class="bad">${esc(e.message || "scan failed")}</p></div>`;
    } finally {
      scanBtn.disabled = false;
    }
  }

  function renderResults(data) {
    let html = "";
    const mod = data.modules && data.modules[data.detected_type];
    if (mod && RENDERERS[data.detected_type]) {
      html += RENDERERS[data.detected_type](mod);
    } else if (data.errors && data.errors[data.detected_type]) {
      html += card("Error", `<p class="bad">${esc(data.errors[data.detected_type])}</p>`);
    } else {
      html += card(`No live module for "${TYPE_LABEL[data.detected_type] || data.detected_type}"`,
        '<p class="faint">Use the pivot links and dorks below.</p>');
    }
    html += renderPivots(data.pivots);
    html += renderDorks(data.dorks);
    results.innerHTML = html;
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const q = qInput.value.trim();
    if (!q) { N.toast("enter a selector first", "bad"); return; }
    runScan(q, typeSelect.value);
  });

  async function loadArsenal() {
    try {
      const data = await N.get("/api/arsenal");
      arsenalEl.innerHTML = (data.tools || []).map(t => `
        <div class="card">
          <div class="badge-row">
            <strong>${esc(t.name)}</strong>
            ${pill(t.installed ? "ok" : "bad", t.installed ? "installed" : "not installed")}
          </div>
          <p class="sub mono">${esc(t.usage)}</p>
          ${t.path ? `<p class="faint mono">${esc(t.path)}</p>` : ""}
        </div>`).join("") + `
        <div class="card">
          <div class="badge-row"><strong>Bastion</strong> ${pill("ok", "full report engine")}</div>
          <p class="sub">Run a full domain security report.</p>
          <a class="btn" href="${esc(data.bastion_url)}" target="_blank" rel="noopener noreferrer">Open Bastion</a>
        </div>`;
    } catch (e) {
      arsenalEl.innerHTML = `<p class="faint">arsenal status unavailable</p>`;
    }
  }

  loadArsenal();
})();
