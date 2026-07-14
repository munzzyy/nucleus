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
  const resourcesEl = document.getElementById("resources");
  const resSearch = document.getElementById("res-search");

  const TYPE_LABEL = {
    username: "Username", email: "Email", domain: "Domain", ip: "IP address",
    phone: "Phone", name: "Name", company: "Company", crypto: "Crypto address",
    image: "Image URL", geo: "Geo coordinates", hash: "File hash", mac: "MAC address",
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
    let githubCard = "";
    if (m.github) {
      githubCard = card("GitHub profile", kv([
        ["Name", m.github.name], ["Bio", m.github.bio],
        ["Public repos", m.github.public_repos], ["Followers", m.github.followers],
        ["Created", m.github.created_at], ["Blog", m.github.blog], ["Location", m.github.location],
      ]));
    }
    return card("Username", summary + `<div class="site-grid">${sites}</div>`) + githubCard;
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
      ["CAA", (dns.CAA || []).join(", ")],
      ["SOA", raw((dns.SOA || []).map(esc).join("<br>"))],
      ["SRV", (dns.SRV || []).join(", ")],
      ["DNSKEY", raw((dns.DNSKEY || []).map(esc).join("<br>"))],
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
    const crtSrc = subs.crt_sh || {};
    const htSrc = subs.hackertarget || {};
    const subsHtml = (subs.names || []).length
      ? `<p class="faint mb">${subs.count} unique name(s) — crt.sh: ${crtSrc.count || 0}${crtSrc.error ? ` (${esc(crtSrc.error)})` : ""}, `
        + `hackertarget: ${htSrc.count || 0}${htSrc.error ? ` (${esc(htSrc.error)})` : ""}</p>${list(subs.names)}`
      : `<p class="faint">crt.sh: ${esc(crtSrc.error || "unavailable")} · hackertarget: ${esc(htSrc.error || "unavailable")}</p>`;

    const us = m.urlscan || {};
    let urlscanHtml;
    if (us.ok && us.scans && us.scans.length) {
      urlscanHtml = us.scans.map(s => `
        <div class="breach-row">
          <div class="name">${esc(s.url || "")}</div>
          <div class="meta">${esc(s.time || "")}${s.ip ? " · " + esc(s.ip) : ""}</div>
          ${s.screenshot ? `<a class="btn ghost mt" href="${esc(s.screenshot)}" target="_blank" rel="noopener noreferrer">Screenshot</a>` : ""}
        </div>`).join("");
    } else {
      urlscanHtml = `<p class="faint">${esc(us.error || "no recent scans")}</p>`;
    }

    const otx = m.otx || {};
    const otxHtml = otx.ok
      ? kv([["Pulse count", otx.pulse_count], ["Pulse names", (otx.pulse_names || []).join(", ") || "none"]])
      : `<p class="faint">${esc(otx.error || "unavailable")}</p>`;

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
      card("Subdomains (crt.sh + hackertarget)", subsHtml),
      card("urlscan.io recent scans", urlscanHtml),
      card("AlienVault OTX reputation", otxHtml),
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

    const otx = m.otx || {};
    const otxHtml = otx.ok
      ? kv([["Pulse count", otx.pulse_count], ["Pulse names", (otx.pulse_names || []).join(", ") || "none"]])
      : `<p class="faint">${esc(otx.error || "unavailable")}</p>`;

    return [
      card("InternetDB (Shodan)", idbHtml),
      card("Geolocation", geoHtml),
      card("Reverse DNS", rdnsHtml),
      card("RDAP netblock", rdapHtml),
      card("Tor (Onionoo)", torHtml),
      card("AlienVault OTX reputation", otxHtml),
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

  function renderHash(m) {
    if (m.known === null && m.error) return card("Hash lookup", `<p class="bad">${esc(m.error)}</p>`);
    const body = m.known
      ? kv([
          ["Algorithm", (m.algo || "").toUpperCase()],
          ["Known file", "yes"],
          ["Filename", m.filename],
          ["Size", m.size],
          ["Source", m.source],
          ["Trust", m.trust],
        ])
      : kv([
          ["Algorithm", (m.algo || "").toUpperCase()],
          ["Known file", "no"],
          ["Note", m.note || "not found in CIRCL hashlookup"],
        ]);
    return card("Hash lookup (CIRCL hashlookup)", body);
  }

  function renderCrypto(m) {
    if (!m.ok) return card("Crypto address", `<p class="bad">${esc(m.error || "lookup failed")}</p>`);
    if (m.chain === "BTC") {
      return card("Crypto address (Bitcoin)", kv([
        ["Balance", `${m.balance_btc} BTC`],
        ["Total received", `${m.total_received_btc} BTC`],
        ["Total sent", `${m.total_sent_btc} BTC`],
        ["Transaction count", m.n_tx],
        ["Note", m.note],
      ]));
    }
    const tokens = (m.tokens || []).map(t => `${t.name || "?"} (${t.symbol || "?"})`).join(", ");
    return card("Crypto address (Ethereum)", kv([
      ["Balance", `${m.balance_eth} ETH`],
      ["Total in", m.total_in_eth != null ? `${m.total_in_eth} ETH` : ""],
      ["Total out", m.total_out_eth != null ? `${m.total_out_eth} ETH` : ""],
      ["Token count", m.token_count],
      ["Tokens", tokens],
      ["Note", m.note],
    ]));
  }

  function renderMac(m) {
    if (m.error) return card("MAC vendor lookup", `<p class="bad">${esc(m.error)}</p>`);
    return card("MAC vendor lookup (macvendors.com)", kv([
      ["Vendor", m.known ? m.vendor : "unknown"],
      ["Note", m.note],
    ]));
  }

  function renderWikipedia(m) {
    if (!m.found) return card("Wikipedia", `<p class="faint">${esc(m.note || m.error || "no page found")}</p>`);
    return card("Wikipedia", kv([
      ["Title", m.title],
      ["Description", m.description],
      ["Extract", m.extract],
      ["URL", m.url ? raw(`<a href="${esc(m.url)}" target="_blank" rel="noopener noreferrer">${esc(m.url)}</a>`) : ""],
    ]));
  }

  const RENDERERS = {
    username: renderUsername, email: renderEmail, domain: renderDomain,
    ip: renderIp, phone: renderPhone, hash: renderHash, crypto: renderCrypto,
    mac: renderMac, name: renderWikipedia, company: renderWikipedia,
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

  // -- OSINT resources directory --------------------------------------------
  let RESOURCE_CATEGORIES = [];

  function renderResourceDirectory(filterText) {
    const q = (filterText || "").trim().toLowerCase();
    let html = "";
    let shown = 0;
    for (const cat of RESOURCE_CATEGORIES) {
      const items = q
        ? cat.items.filter(it =>
            (it.name || "").toLowerCase().includes(q) ||
            (it.note || "").toLowerCase().includes(q) ||
            cat.name.toLowerCase().includes(q))
        : cat.items;
      if (!items.length) continue;
      shown += items.length;
      const links = items.map(it => `
        <a class="card link resource-link" href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">
          <div class="r-name">${esc(it.name)}</div>
          <div class="r-note">${esc(it.note || "")}</div>
        </a>`).join("");
      html += `<div class="resource-cat">
          <h3>${esc(cat.name)} <span class="faint">(${items.length})</span></h3>
          <div class="pivot-grid">${links}</div>
        </div>`;
    }
    resourcesEl.innerHTML = shown ? html : '<p class="faint">no resources match your search</p>';
  }

  async function loadResources() {
    try {
      const data = await N.get("/api/resources");
      RESOURCE_CATEGORIES = data.categories || [];
      renderResourceDirectory("");
      resSearch.addEventListener("input", () => renderResourceDirectory(resSearch.value));
    } catch (e) {
      resourcesEl.innerHTML = '<p class="faint">resources directory unavailable</p>';
    }
  }

  loadResources();
})();
