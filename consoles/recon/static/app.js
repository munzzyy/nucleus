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
  const resultsToolbar = document.getElementById("results-toolbar");
  const btnCopyJson = document.getElementById("res-copy-json");
  const btnCopyMd = document.getElementById("res-copy-md");
  const btnDownload = document.getElementById("res-download");
  const historyWrap = document.getElementById("recon-history-wrap");
  const historyList = document.getElementById("recon-history");
  const trailEl = document.getElementById("pivot-trail");

  let lastScanData = null;
  let lastScanQuery = "";
  let scanTicker = null;
  let pivotTrail = [];
  const MAX_TRAIL = 8;

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

  function boolStr(v) {
    return v === true ? "yes" : v === false ? "no" : "";
  }

  // -- pivot chips: turn a discovered entity Nucleus can itself scan into a
  // "run it here" affordance instead of a dead end out to an external site.
  // Every chip just carries the value/type in data-* attrs; the click is
  // handled by one delegated listener on #results (see launchPivot below).
  function pivotChip(value, type) {
    if (!value) return "";
    return `<button type="button" class="pivot-chip" data-pivot-value="${esc(value)}" data-pivot-type="${esc(type)}">⇢ scan</button>`;
  }

  function pivotRow(value, type) {
    return `<div class="pivot-row"><span class="pivot-val">${esc(value)}</span>${pivotChip(value, type)}</div>`;
  }

  function pivotValue(value, type) {
    return `<span class="pivot-inline">${esc(value)}${pivotChip(value, type)}</span>`;
  }

  function pivotArrayList(items, type) {
    if (!items || !items.length) return "";
    return items.map(v => pivotRow(v, type)).join("");
  }

  function pivotList(items, type) {
    if (!items || !items.length) return '<p class="faint">none</p>';
    return `<div class="subdomain-list">${items.map(i => pivotRow(i, type)).join("")}</div>`;
  }

  // MX answers come back "<preference> <exchange>." e.g. "10 mail.example.com." --
  // pivot on the exchange hostname, not the whole record.
  function mxHostname(entry) {
    const parts = String(entry || "").trim().split(/\s+/);
    const host = parts.length > 1 ? parts[parts.length - 1] : (parts[0] || "");
    return host.replace(/\.$/, "");
  }

  function pivotMxList(mx) {
    if (!mx || !mx.length) return "";
    return mx.map(entry => {
      const host = mxHostname(entry);
      return `<div class="pivot-row"><span class="pivot-val">${esc(entry)}</span>${host ? pivotChip(host, "domain") : ""}</div>`;
    }).join("");
  }

  // -- keyed-source cards: only rendered when the module actually ran the
  // source (i.e. its key was set server-side); a missing key surfaces as an
  // unlock hint instead, never an empty card. ---------------------------
  const SETTINGS_URL = "http://127.0.0.1:8890/#settings";

  function keyedBody(o, rows) {
    if (!o) return null;
    if (o.ok === false) return `<p class="bad">${esc(o.error || "lookup failed")}</p>`;
    let html = kv(rows);
    if (o.note) html += `<p class="faint mt">${esc(o.note)}</p>`;
    return html;
  }

  function keyedCard(title, obj, rows) {
    const body = keyedBody(obj, rows);
    return body ? card(title, body) : "";
  }

  function renderUnlock(unlock) {
    if (!unlock || !unlock.length) return "";
    const lines = unlock.map(u => {
      const parts = u.split("Settings");
      const html = parts.length === 2
        ? `${esc(parts[0])}<a href="${esc(SETTINGS_URL)}" target="_blank" rel="noopener noreferrer">Settings</a>${esc(parts[1])}`
        : esc(u);
      return `<div class="unlock-line">${html}</div>`;
    }).join("");
    return `<div class="unlock-hints">${lines}</div>`;
  }

  // -- pivots + dorks (shared by every type) --------------------------------
  function renderPivots(pivots) {
    if (!pivots || !pivots.length) return "";
    const links = pivots.map(p =>
      `<a class="card link" href="${esc(N.safeUrl(p.url))}" target="_blank" rel="noopener noreferrer">${esc(p.title)}</a>`
    ).join("");
    return card("Pivot links", `<div class="pivot-grid">${links}</div>`);
  }

  function renderDorks(dorks) {
    if (!dorks || !dorks.length) return "";
    const rows = dorks.map(d => `
      <div class="dork-row">
        <div class="label">${esc(d.label)}</div>
        <div class="q">${esc(d.query)}</div>
        <a class="btn ghost" href="${esc(N.safeUrl(d.google))}" target="_blank" rel="noopener noreferrer">Google</a>
        <a class="btn ghost" href="${esc(N.safeUrl(d.bing))}" target="_blank" rel="noopener noreferrer">Bing</a>
      </div>`).join("");
    return card("Dork builder", rows);
  }

  // -- per-module renderers ---------------------------------------------------
  function renderUsername(m) {
    const sites = (m.sites || []).map(s => {
      const kind = s.found === true ? "found" : s.found === false ? "notfound" : "unknown";
      const inner = s.url
        ? `<a href="${esc(N.safeUrl(s.url))}" target="_blank" rel="noopener noreferrer" title="${esc(s.note)}">${esc(s.site)}</a>`
        : `<span title="${esc(s.note)}">${esc(s.site)}</span>`;
      return `<div class="site-pill ${kind}"><span class="dot"></span>${inner}</div>`;
    }).join("");
    const summary = `<div class="badge-row">
        ${pill("ok", `${m.found_count} found`)}
        ${pill("bad", `${m.not_found_count} not found`)}
        ${pill("warn", `${m.unknown_count} unknown`)}
        <span class="faint">checked ${m.checked}${m.total_available ? ` of ${m.total_available}` : ""} sites in ${m.took_ms}ms${m.dataset ? ` · ${esc(m.dataset)}` : ""}</span>
      </div>`;
    const sampleNote = (m.total_available && m.checked < m.total_available)
      ? `<p class="faint mt small">Sample within the time budget — ${m.total_available - m.checked} more sites weren't checked. Re-run to cover more.</p>`
      : "";
    let githubCard = "";
    if (m.github) {
      githubCard = card("GitHub profile", kv([
        ["Name", m.github.name], ["Bio", m.github.bio],
        ["Public repos", m.github.public_repos], ["Followers", m.github.followers],
        ["Created", m.github.created_at], ["Blog", m.github.blog], ["Location", m.github.location],
      ]));
    }
    return card("Username", summary + `<div class="site-grid">${sites}</div>` + sampleNote) + githubCard;
  }

  function renderEmail(m) {
    const bc = m.breach_check || {};
    const an = m.breach_analytics || {};
    const gv = m.gravatar || {};
    const k = m.keyed || {};
    const summary = kv([
      ["Domain", m.domain ? raw(pivotValue(m.domain, "domain")) : ""],
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

    let hibpHtml = "";
    if (k.hibp) {
      if (k.hibp.ok === false) {
        hibpHtml = keyedBody(k.hibp);
      } else if (k.hibp.breach_count) {
        hibpHtml = k.hibp.breaches.map(b => `
          <div class="breach-row">
            <div class="name">${esc(b.name || "unknown")}</div>
            <div class="meta">${esc(b.date || "")}</div>
            <div class="classes">${(b.data_classes || []).slice(0, 10).map(c => `<span class="tag">${esc(c)}</span>`).join("")}</div>
          </div>`).join("");
      } else {
        hibpHtml = `<p class="ok">no breaches on file</p>`;
      }
    }

    return card("Email", summary + breachList + renderUnlock(m.unlock))
      + keyedCard("Hunter.io verifier", k.hunter, [
          ["Result", k.hunter && k.hunter.result], ["Score", k.hunter && k.hunter.score],
          ["Disposable", k.hunter && boolStr(k.hunter.disposable)],
          ["Webmail", k.hunter && boolStr(k.hunter.webmail)],
          ["MX records", k.hunter && boolStr(k.hunter.mx_records)],
        ])
      + keyedCard("IPQualityScore", k.ipqs, [
          ["Valid", k.ipqs && boolStr(k.ipqs.valid)], ["Disposable", k.ipqs && boolStr(k.ipqs.disposable)],
          ["Recent abuse", k.ipqs && boolStr(k.ipqs.recent_abuse)], ["Fraud score", k.ipqs && k.ipqs.fraud_score],
          ["Leaked", k.ipqs && boolStr(k.ipqs.leaked)],
        ])
      + (k.hibp ? card("Have I Been Pwned", hibpHtml) : "");
  }

  function renderDomain(m) {
    const k = m.keyed || {};
    const dns = m.dns || {};
    const dnsHtml = kv([
      ["A", (dns.A || []).length ? raw(pivotArrayList(dns.A, "ip")) : ""],
      ["AAAA", (dns.AAAA || []).length ? raw(pivotArrayList(dns.AAAA, "ip")) : ""],
      ["MX", (dns.MX || []).length ? raw(pivotMxList(dns.MX)) : ""],
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
    const stSrc = subs.securitytrails || {};
    const stPart = stSrc.error != null || stSrc.count
      ? `, SecurityTrails: ${stSrc.count || 0}${stSrc.error ? ` (${esc(stSrc.error)})` : ""}` : "";
    const subsHtml = (subs.names || []).length
      ? `<p class="faint mb">${subs.count} unique name(s) — crt.sh: ${crtSrc.count || 0}${crtSrc.error ? ` (${esc(crtSrc.error)})` : ""}, `
        + `hackertarget: ${htSrc.count || 0}${htSrc.error ? ` (${esc(htSrc.error)})` : ""}${stPart}</p>${pivotList(subs.names, "domain")}`
      : `<p class="faint">crt.sh: ${esc(crtSrc.error || "unavailable")} · hackertarget: ${esc(htSrc.error || "unavailable")}${stPart}</p>`;

    const us = m.urlscan || {};
    let urlscanHtml;
    if (us.ok && us.scans && us.scans.length) {
      urlscanHtml = us.scans.map(s => `
        <div class="breach-row">
          <div class="name">${esc(s.url || "")}</div>
          <div class="meta">${esc(s.time || "")}${s.ip ? " · " + esc(s.ip) : ""}</div>
          ${s.screenshot ? `<a class="btn ghost mt" href="${esc(N.safeUrl(s.screenshot))}" target="_blank" rel="noopener noreferrer">Screenshot</a>` : ""}
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
      ? kv([["Archived", wb.archived ? "yes" : "no"], ["Latest snapshot", wb.url ? raw(`<a href="${esc(N.safeUrl(wb.url))}" target="_blank" rel="noopener noreferrer">${esc(wb.timestamp || "")}</a>`) : ""]])
      : `<p class="faint">${esc(wb.error || "unavailable")}</p>`;

    const h = m.hosting || {};
    const hostingHtml = kv([
      ["IP", h.ip ? raw(pivotValue(h.ip, "ip")) : ""],
      ["Open ports", (h.ports || []).join(", ")],
      ["CVEs", (h.cves || []).join(", ")],
      ["Tags", (h.tags || []).join(", ")],
      ["Geo", h.geo ? `${h.geo.city || ""}, ${h.geo.country || ""} — ${h.geo.org || h.geo.isp || ""}` : ""],
      ["Error", h.error],
    ]);

    const hunterEmails = (k.hunter && k.hunter.emails || []).map(e =>
      `${e.value || "?"}${e.type ? ` (${e.type})` : ""}${e.confidence != null ? ` — ${e.confidence}%` : ""}`).join(", ");

    return [
      card("DNS", dnsHtml + renderUnlock(m.unlock)),
      card("WHOIS (RDAP)", whoisHtml),
      keyedCard("WhoisXML WHOIS", k.whoisxml, [
        ["Registrar", k.whoisxml && k.whoisxml.registrar], ["Created", k.whoisxml && k.whoisxml.created],
        ["Updated", k.whoisxml && k.whoisxml.updated], ["Expires", k.whoisxml && k.whoisxml.expires],
        ["Registrant org", k.whoisxml && k.whoisxml.registrant_org],
      ]),
      card("Email posture (SPF / DMARC)", postureHtml),
      card("HTTP + security headers", httpHtml),
      card("Hosting chain", hostingHtml),
      card("Subdomains (crt.sh + hackertarget + SecurityTrails)", subsHtml),
      card("urlscan.io recent scans", urlscanHtml),
      card("AlienVault OTX reputation", otxHtml),
      card("Wayback Machine", wbHtml),
      keyedCard("VirusTotal (domain reputation)", k.virustotal, [
        ["Malicious", k.virustotal && k.virustotal.malicious], ["Suspicious", k.virustotal && k.virustotal.suspicious],
        ["Harmless", k.virustotal && k.virustotal.harmless], ["Reputation", k.virustotal && k.virustotal.reputation],
        ["Categories", k.virustotal && (k.virustotal.categories || []).join(", ")],
      ]),
      keyedCard("Hunter.io (corporate emails)", k.hunter, [
        ["Organization", k.hunter && k.hunter.organization], ["Pattern", k.hunter && k.hunter.pattern],
        ["Emails found", k.hunter && k.hunter.email_count], ["Emails", hunterEmails],
      ]),
    ].join("");
  }

  function renderIp(m) {
    if (m.error) return card("IP", `<p class="bad">${esc(m.error)}</p>`);
    const k = m.keyed || {};
    const idb = m.internetdb || {};
    const idbHtml = idb.ok
      ? kv([
          ["Open ports", (idb.ports || []).join(", ") || "none"],
          ["CVEs", (idb.cves || []).join(", ") || "none"],
          ["Hostnames", (idb.hostnames || []).length ? raw(pivotArrayList(idb.hostnames, "domain")) : ""],
          ["Tags", (idb.tags || []).join(", ")],
        ]) + renderUnlock(m.unlock)
      : `<p class="faint">${esc(idb.error || "unavailable")}</p>` + renderUnlock(m.unlock);

    const geo = m.geo;
    const geoHtml = geo
      ? kv([["Location", `${geo.city || ""}, ${geo.region || ""}, ${geo.country || ""}`],
            ["ASN / org", geo.asn || geo.org || geo.isp || ""], ["Coordinates", `${geo.lat}, ${geo.lon}`]])
      : '<p class="faint">unavailable</p>';

    const rdns = m.reverse_dns || {};
    const rdnsHtml = rdns.ok
      ? kv([["Hostname", rdns.hostname ? raw(pivotValue(rdns.hostname, "domain")) : ""]])
      : `<p class="faint">${esc(rdns.error || "no PTR record")}</p>`;

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
      keyedCard("IPinfo", k.ipinfo, [
        ["Org / ASN", k.ipinfo && k.ipinfo.org], ["City", k.ipinfo && k.ipinfo.city],
        ["Region", k.ipinfo && k.ipinfo.region], ["Country", k.ipinfo && k.ipinfo.country],
        ["VPN", k.ipinfo && boolStr(k.ipinfo.vpn)], ["Proxy", k.ipinfo && boolStr(k.ipinfo.proxy)],
        ["Tor", k.ipinfo && boolStr(k.ipinfo.tor)], ["Hosting", k.ipinfo && boolStr(k.ipinfo.hosting)],
        ["Abuse contact", k.ipinfo && k.ipinfo.abuse_contact],
      ]),
      keyedCard("VirusTotal (IP reputation)", k.virustotal, [
        ["Malicious", k.virustotal && k.virustotal.malicious], ["Suspicious", k.virustotal && k.virustotal.suspicious],
        ["Harmless", k.virustotal && k.virustotal.harmless], ["AS owner", k.virustotal && k.virustotal.as_owner],
        ["Country", k.virustotal && k.virustotal.country], ["Reputation", k.virustotal && k.virustotal.reputation],
      ]),
      keyedCard("AbuseIPDB", k.abuseipdb, [
        ["Abuse confidence", k.abuseipdb && `${k.abuseipdb.abuse_confidence_score}%`],
        ["Total reports", k.abuseipdb && k.abuseipdb.total_reports],
        ["Usage type", k.abuseipdb && k.abuseipdb.usage_type], ["ISP", k.abuseipdb && k.abuseipdb.isp],
        ["Domain", k.abuseipdb && k.abuseipdb.domain],
      ]),
      keyedCard("GreyNoise", k.greynoise, [
        ["Noise", k.greynoise && boolStr(k.greynoise.noise)], ["RIOT (known service)", k.greynoise && boolStr(k.greynoise.riot)],
        ["Classification", k.greynoise && k.greynoise.classification], ["Name", k.greynoise && k.greynoise.name],
        ["Last seen", k.greynoise && k.greynoise.last_seen],
      ]),
      keyedCard("Shodan (full host)", k.shodan, [
        ["Org", k.shodan && k.shodan.org], ["OS", k.shodan && k.shodan.os],
        ["Hostnames", k.shodan && (k.shodan.hostnames || []).join(", ")],
        ["Open ports", k.shodan && (k.shodan.ports || []).join(", ")],
        ["Vulns (CVEs)", k.shodan && (k.shodan.vulns || []).join(", ")],
      ]),
      keyedCard("IPQualityScore", k.ipqs, [
        ["Fraud score", k.ipqs && k.ipqs.fraud_score], ["Proxy", k.ipqs && boolStr(k.ipqs.proxy)],
        ["VPN", k.ipqs && boolStr(k.ipqs.vpn)], ["Tor", k.ipqs && boolStr(k.ipqs.tor)],
        ["Recent abuse", k.ipqs && boolStr(k.ipqs.recent_abuse)],
      ]),
    ].join("");
  }

  function renderPhone(m) {
    const l = m.lookup || {};
    const k = m.keyed || {};
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
    return card("Phone", top + lookupHtml + renderUnlock(m.unlock))
      + keyedCard("IPQualityScore", k.ipqs, [
          ["Valid", k.ipqs && boolStr(k.ipqs.valid)], ["Active", k.ipqs && boolStr(k.ipqs.active)],
          ["Carrier", k.ipqs && k.ipqs.carrier], ["Line type", k.ipqs && k.ipqs.line_type],
          ["Fraud score", k.ipqs && k.ipqs.fraud_score], ["Risky", k.ipqs && boolStr(k.ipqs.risky)],
        ]);
  }

  function renderHash(m) {
    if (m.known === null && m.error) return card("Hash lookup", `<p class="bad">${esc(m.error)}</p>`);
    const k = m.keyed || {};
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
    return card("Hash lookup (CIRCL hashlookup)", body + renderUnlock(m.unlock))
      + keyedCard("VirusTotal (file reputation)", k.virustotal, [
          ["Detections", k.virustotal && k.virustotal.malicious != null
            ? `${k.virustotal.malicious} / ${k.virustotal.total}` : ""],
          ["Name", k.virustotal && k.virustotal.meaningful_name],
          ["Type", k.virustotal && k.virustotal.type_description],
          ["Threat label", k.virustotal && k.virustotal.threat_label],
        ]);
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
      ["URL", m.url ? raw(`<a href="${esc(N.safeUrl(m.url))}" target="_blank" rel="noopener noreferrer">${esc(m.url)}</a>`) : ""],
    ]));
  }

  const RENDERERS = {
    username: renderUsername, email: renderEmail, domain: renderDomain,
    ip: renderIp, phone: renderPhone, hash: renderHash, crypto: renderCrypto,
    mac: renderMac, name: renderWikipedia, company: renderWikipedia,
  };

  // -- copy / export toolbar -------------------------------------------------
  function copyText(text, okMsg) {
    navigator.clipboard.writeText(text).then(
      () => N.toast(okMsg || "copied", "ok"),
      () => N.toast("copy failed — clipboard blocked", "bad"),
    );
  }

  function downloadJson(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Generic JSON -> markdown bullet digest — one function that reads any
  // module's shape, so the export doesn't have to be hand-mirrored every
  // time a renderer above changes.
  function mdInline(v) {
    if (Array.isArray(v)) return v.map(mdInline).join(", ");
    return v === null || v === undefined ? "" : String(v);
  }

  function mdList(obj, depth) {
    const pad = "  ".repeat(depth);
    const lines = [];
    Object.entries(obj || {}).forEach(([k, v]) => {
      if (v === null || v === undefined || v === "") return;
      if (Array.isArray(v)) {
        if (!v.length) return;
        const allPrimitive = v.every(x => x === null || typeof x !== "object");
        if (allPrimitive) {
          lines.push(`${pad}- **${k}**: ${mdInline(v)}`);
        } else {
          lines.push(`${pad}- **${k}**:`);
          v.forEach((item) => {
            if (item && typeof item === "object") lines.push(...mdList(item, depth + 1));
            else if (item !== null && item !== undefined && item !== "") lines.push(`${pad}  - ${item}`);
          });
        }
      } else if (typeof v === "object") {
        const nested = mdList(v, depth + 1);
        if (nested.length) { lines.push(`${pad}- **${k}**:`); lines.push(...nested); }
      } else {
        lines.push(`${pad}- **${k}**: ${v}`);
      }
    });
    return lines;
  }

  function scanToMarkdown(data) {
    const lines = [];
    const label = TYPE_LABEL[data.detected_type] || data.detected_type || "unknown";
    lines.push(`# Recon scan — ${label}`);
    if (lastScanQuery) lines.push(`Query: \`${lastScanQuery}\``);
    if (data.took_ms != null) lines.push(`Took: ${data.took_ms}ms`);
    lines.push("");
    const mod = data.modules && data.modules[data.detected_type];
    if (mod) {
      lines.push(`## ${label}`);
      lines.push(...mdList(mod, 0));
      lines.push("");
    }
    if (data.pivots && data.pivots.length) {
      lines.push("## Pivot links");
      data.pivots.forEach(p => lines.push(`- [${p.title}](${p.url})`));
      lines.push("");
    }
    if (data.dorks && data.dorks.length) {
      lines.push("## Dorks");
      data.dorks.forEach(d => lines.push(`- **${d.label}**: \`${d.query}\``));
      lines.push("");
    }
    return lines.join("\n").trim() + "\n";
  }

  if (btnCopyJson) btnCopyJson.addEventListener("click", () => {
    if (!lastScanData) return;
    copyText(JSON.stringify(lastScanData, null, 2));
  });
  if (btnCopyMd) btnCopyMd.addEventListener("click", () => {
    if (!lastScanData) return;
    copyText(scanToMarkdown(lastScanData), "copied as markdown");
  });
  if (btnDownload) btnDownload.addEventListener("click", () => {
    if (!lastScanData) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    downloadJson(lastScanData, `recon-${lastScanData.detected_type || "scan"}-${stamp}.json`);
  });

  // -- elapsed-time ticker (nmap "full" etc can run 600s — an honest clock
  // beats a static spinner that looks hung) -----------------------------
  function startTicker(label) {
    stopTicker();
    const start = Date.now();
    statusLine.classList.remove("hidden");
    const tick = () => {
      statusLine.innerHTML = `<span class="spinner"></span> ${esc(label)} — ${((Date.now() - start) / 1000).toFixed(1)}s`;
    };
    tick();
    scanTicker = setInterval(tick, 200);
  }
  function stopTicker() {
    if (scanTicker) { clearInterval(scanTicker); scanTicker = null; }
  }

  // -- pivot trail: an in-session breadcrumb of the scans chained together
  // in this investigation. Purely client-side (no server round-trip to show
  // lineage); clicking back into a crumb truncates the trail there and
  // re-runs that scan for real. -----------------------------------------
  function renderTrail() {
    if (!trailEl) return;
    if (!pivotTrail.length) { trailEl.classList.add("hidden"); trailEl.innerHTML = ""; return; }
    trailEl.classList.remove("hidden");
    trailEl.innerHTML = pivotTrail.map((t, i) => {
      const isLast = i === pivotTrail.length - 1;
      const sep = i === 0 ? "" : '<span class="trail-sep">›</span>';
      const cls = "trail-crumb" + (isLast ? " current" : "");
      return `${sep}<button type="button" class="${cls}" data-trail-index="${i}"${isLast ? " disabled" : ""}>${esc(t.value)}</button>`;
    }).join("");
  }

  function pushTrail(value, type) {
    const last = pivotTrail[pivotTrail.length - 1];
    if (last && last.value === value && last.type === type) { renderTrail(); return; }
    pivotTrail.push({ value, type });
    if (pivotTrail.length > MAX_TRAIL) pivotTrail.splice(0, pivotTrail.length - MAX_TRAIL);
    renderTrail();
  }

  function goToTrail(i) {
    const entry = pivotTrail[i];
    if (!entry) return;
    pivotTrail = pivotTrail.slice(0, i + 1);
    launchPivot(entry.value, entry.type);
  }

  if (trailEl) trailEl.addEventListener("click", (e) => {
    const btn = e.target.closest(".trail-crumb");
    if (!btn || btn.disabled) return;
    const i = Number(btn.dataset.trailIndex);
    if (!Number.isNaN(i)) goToTrail(i);
  });

  // -- pivot chips: fill the search box with the discovered value, set its
  // type, and re-run the scan in-app. Shared by every "⇢ scan" chip and by
  // trail crumbs. -----------------------------------------------------------
  function launchPivot(value, type) {
    qInput.value = value;
    if (type && TYPE_LABEL[type]) typeSelect.value = type;
    else typeSelect.value = "auto";
    window.scrollTo({ top: 0, behavior: "smooth" });
    runScan(value, type || "auto");
  }

  results.addEventListener("click", (e) => {
    const chip = e.target.closest(".pivot-chip");
    if (!chip) return;
    const value = chip.dataset.pivotValue;
    const type = chip.dataset.pivotType;
    if (!value) return;
    launchPivot(value, type);
  });

  async function runScan(q, type) {
    scanBtn.disabled = true;
    results.innerHTML = "";
    startTicker("scanning");
    try {
      const data = await N.post("/api/scan", { type, q });
      stopTicker();
      lastScanData = data;
      lastScanQuery = q;
      renderResults(data);
      statusLine.classList.remove("hidden");
      statusLine.textContent = `detected: ${TYPE_LABEL[data.detected_type] || data.detected_type} · ${data.took_ms}ms`;
      if (resultsToolbar) resultsToolbar.classList.remove("hidden");
      pushTrail(q, data.detected_type || type);
      loadReconHistory();
    } catch (e) {
      stopTicker();
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

  // -- first-run empty state — before any scan, offer clickable examples ---
  const EXAMPLES = [
    { label: "torvalds", type: "username" },
    { label: "example.com", type: "domain" },
    { label: "8.8.8.8", type: "ip" },
  ];

  function renderEmptyState() {
    const wrap = N.el("div", { class: "card" });
    wrap.appendChild(N.el("h2", { text: "Try a scan" }));
    wrap.appendChild(N.el("p", { class: "sub", text: "Pick an example below, or paste your own selector above and hit Scan." }));
    const row = N.el("div", { class: "row mt" });
    EXAMPLES.forEach(ex => {
      const btn = N.el("button", { class: "ghost", type: "button", text: ex.label });
      btn.addEventListener("click", () => {
        qInput.value = ex.label;
        typeSelect.value = ex.type;
        runScan(ex.label, ex.type);
      });
      row.appendChild(btn);
    });
    wrap.appendChild(row);
    results.innerHTML = "";
    results.appendChild(wrap);
  }

  renderEmptyState();

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
          <a class="btn" href="${esc(N.safeUrl(data.bastion_url))}" target="_blank" rel="noopener noreferrer">Open Bastion</a>
        </div>`;
    } catch (e) {
      arsenalEl.innerHTML = `<p class="faint">arsenal status unavailable</p>`;
    }
  }

  loadArsenal();

  // -- scan history (feature-detected: hidden if the backend doesn't have
  // /api/recon-history yet, or ever 404s) -----------------------------------
  async function loadReconHistory() {
    if (!historyWrap || !historyList) return;
    let j;
    try { j = await N.get("/api/recon-history?limit=50"); }
    catch (e) { return; } // endpoint not there (yet) — stay quiet, leave it hidden
    historyWrap.classList.remove("hidden");
    renderReconHistory(j.scans || []);
  }

  function renderReconHistory(scans) {
    if (!scans.length) {
      historyList.innerHTML = '<p class="faint">No scans logged yet.</p>';
      return;
    }
    historyList.innerHTML = "";
    scans.forEach(s => {
      const item = N.el("button", { class: "hist-item", type: "button" });
      const top = N.el("div", { class: "hist-top" });
      top.appendChild(N.el("span", { class: "pill", text: TYPE_LABEL[s.type] || s.type || "?" }));
      top.appendChild(N.el("span", { class: "faint small", text: s.ts || "" }));
      item.appendChild(top);
      item.appendChild(N.el("div", { class: "hist-q mono", text: s.q || "" }));
      if (s.summary) item.appendChild(N.el("div", { class: "sub", text: s.summary }));
      item.addEventListener("click", () => reopenScan(s.id, s.q));
      historyList.appendChild(item);
    });
  }

  async function reopenScan(id, q) {
    if (id === undefined || id === null) return;
    startTicker("loading saved scan");
    try {
      const data = await N.get("/api/recon-scan?id=" + encodeURIComponent(String(id)));
      stopTicker();
      lastScanData = data;
      // the full scan payload's own field is `input`, not `q` — prefer the
      // query text the history list already gave us, then fall back through
      // both possible response shapes before giving up on repopulating it.
      lastScanQuery = q || data.input || data.q || qInput.value;
      qInput.value = lastScanQuery;
      renderResults(data);
      statusLine.classList.remove("hidden");
      statusLine.textContent = `reopened: ${TYPE_LABEL[data.detected_type] || data.detected_type}`
        + (data.took_ms != null ? ` · ${data.took_ms}ms` : "");
      if (resultsToolbar) resultsToolbar.classList.remove("hidden");
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      stopTicker();
      N.toast(e.message || "couldn't load that scan", "bad");
    }
  }

  loadReconHistory();

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
        <a class="card link resource-link" href="${esc(N.safeUrl(it.url))}" target="_blank" rel="noopener noreferrer">
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
