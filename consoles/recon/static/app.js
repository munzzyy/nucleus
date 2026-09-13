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
  const historyWrap = document.getElementById("recon-history-wrap");
  const historyList = document.getElementById("recon-history");
  const historyNote = document.getElementById("recon-history-note");
  const trailEl = document.getElementById("pivot-trail");

  let lastScanData = null;
  let lastScanQuery = "";
  let lastTakeoverData = null;
  let lastUsernameSites = [];
  let scanTicker = null;
  let siteFilterTimer = null;
  let pivotTrail = [];
  const MAX_TRAIL = 8;

  // Client-side memory via the shared kit (namespaced per console).
  const recentsStore = N.remember("recents");
  const lastTypeStore = N.remember("last-type");
  const RECENTS_MAX = 12;
  // Mirror takeover._MAX_SUBS_PER_REQUEST so the one-click "check these for
  // takeover" button never sends more than the server will accept.
  const TAKEOVER_MAX_SUBS = 200;

  const TYPE_LABEL = {
    username: "Username", email: "Email", domain: "Domain", ip: "IP address",
    phone: "Phone", name: "Name", company: "Company", crypto: "Crypto address",
    image: "Image URL", geo: "Geo coordinates", hash: "File hash", mac: "MAC address",
    asn: "ASN", discord: "Discord ID",
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

  // A "count" from a third-party API is only a number by convention. String
  // also has .toLocaleString(), so `provider.count.toLocaleString()` happily
  // returns an attacker's markup verbatim and it lands in innerHTML. Coerce
  // and drop anything non-finite: safe by construction, and a bad value shows
  // as blank instead of as HTML.
  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? n.toLocaleString() : "";
  }

  // -- pivot chips: turn a discovered entity Nucleus can itself scan into a
  // "run it here" affordance instead of a dead end out to an external site.
  // Every chip just carries the value/type in data-* attrs; the click is
  // handled by one delegated listener on #results (see launchPivot below).
  function pivotChip(value, type) {
    if (!value) return "";
    return `<button type="button" class="pivot-chip" data-pivot-value="${esc(value)}" data-pivot-type="${esc(type)}" aria-label="Scan ${esc(value)}">⇢ scan</button>`;
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

  // HudsonRock infostealer exposure — same shape for both email and username
  // lookups (a person got popped by an infostealer, here's what it grabbed).
  // The provider already masks logins/passwords before it ever reaches us
  // (e.g. "S******8"), so we render those as-is but small and unlabeled-loud —
  // they're a sample, not a real credential leak, and shouldn't read like one.
  function infostealerBlock(o) {
    if (!o) return "";
    if (o.ok === false) return card("Infostealer exposure (HudsonRock)", `<p class="faint">${esc(o.error || "check failed")}</p>`);
    if (o.error) return card("Infostealer exposure (HudsonRock)", `<p class="faint">${esc(o.error)}</p>`);
    if (o.infected === false) {
      return card("Infostealer exposure (HudsonRock)", `<p class="ok">no infostealer infection on file (HudsonRock)</p>`);
    }
    if (o.infected !== true) return "";
    // Built as a list and joined, so the markup can't end up unbalanced (the
    // old inline-ternary version emitted a stray </span> when corporate
    // services were present but personal ones were not).
    const svc = [];
    if (num(o.total_user_services)) svc.push(num(o.total_user_services) + " personal service(s)");
    if (num(o.total_corporate_services)) svc.push(num(o.total_corporate_services) + " corporate service(s)");
    const summary = `<div class="badge-row">
        ${pill("bad", `${num(o.stealer_count)} infection(s)`)}
        ${svc.length ? `<span class="faint">${svc.join(" · ")}</span>` : ""}
      </div>`;
    const rows = (o.stealers || []).map(s => {
      const logins = (s.top_logins || []).filter(Boolean);
      const passwords = (s.top_passwords || []).filter(Boolean);
      let sample = "";
      if (logins.length || passwords.length) {
        sample = `<p class="faint small mt">provider-masked sample (values are redacted by HudsonRock)`
          + (logins.length ? `<br>logins: ${logins.map(esc).join(", ")}` : "")
          + (passwords.length ? `<br>passwords: ${passwords.map(esc).join(", ")}` : "")
          + `</p>`;
      }
      return `<div class="breach-row">
          <div class="name">${esc(s.computer_name || "unknown machine")}</div>
          <div class="meta">${esc(s.date_compromised || "")}${s.operating_system ? " · " + esc(s.operating_system) : ""}${s.stealer_family ? " · " + esc(s.stealer_family) : ""}</div>
          ${(s.antiviruses || []).length ? `<div class="classes">${s.antiviruses.map(a => `<span class="tag">${esc(a)}</span>`).join("")}</div>` : ""}
          ${sample}
        </div>`;
    }).join("");
    return card(`Infostealer exposure — ${o.stealer_count} infection(s)`, summary + rows);
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
  // One site pill, with a visually-hidden status word so found/not-found is
  // conveyed to a screen reader, not by colour alone.
  function sitePill(s) {
    const kind = s.found === true ? "found" : s.found === false ? "notfound" : "unknown";
    const word = s.found === true ? "found" : s.found === false ? "not found" : "unconfirmed";
    const inner = s.url
      ? `<a href="${esc(N.safeUrl(s.url))}" target="_blank" rel="noopener noreferrer" title="${esc(s.note)}">${esc(s.site)}</a>`
      : `<span title="${esc(s.note)}">${esc(s.site)}</span>`;
    return `<div class="site-pill ${kind}" role="listitem"><span class="dot"></span>${inner}`
      + `<span class="sr-only"> — ${word}</span></div>`;
  }

  // found → unconfirmed → not-found, stable within each rank so the server's
  // priority ordering (curated high-signal sites first) survives the sort.
  function foundRank(f) { return f === true ? 0 : (f === false ? 2 : 1); }
  function sortedSites(sites) {
    return sites
      .map((s, i) => [s, i])
      .sort((a, b) => (foundRank(a[0].found) - foundRank(b[0].found)) || (a[1] - b[1]))
      .map(x => x[0]);
  }
  function renderSiteGrid(sites) { return sortedSites(sites).map(sitePill).join(""); }

  function applyUsernameFilter() {
    const grid = document.getElementById("site-grid");
    if (!grid) return;
    const filterEl = document.getElementById("site-filter");
    const foundOnlyEl = document.getElementById("site-found-only");
    const countEl = document.getElementById("site-count");
    const q = ((filterEl && filterEl.value) || "").trim().toLowerCase();
    const foundOnly = !!(foundOnlyEl && foundOnlyEl.checked);
    let list = lastUsernameSites;
    if (foundOnly) list = list.filter(s => s.found === true);
    if (q) list = list.filter(s => (s.site || "").toLowerCase().includes(q));
    grid.innerHTML = list.length ? renderSiteGrid(list)
      : '<p class="faint" role="listitem">no sites match</p>';
    if (countEl) countEl.textContent = `${list.length} of ${lastUsernameSites.length} shown`;
  }

  function wireUsernameControls() {
    const filterEl = document.getElementById("site-filter");
    const foundOnlyEl = document.getElementById("site-found-only");
    if (filterEl) filterEl.addEventListener("input", () => {
      clearTimeout(siteFilterTimer);
      siteFilterTimer = setTimeout(applyUsernameFilter, 140);
    });
    if (foundOnlyEl) foundOnlyEl.addEventListener("change", applyUsernameFilter);
    applyUsernameFilter();  // sets the initial "N of M shown" count
  }

  function renderUsername(m) {
    lastUsernameSites = m.sites || [];
    const summary = `<div class="badge-row">
        ${pill("ok", `${m.found_count} found`)}
        ${pill("bad", `${m.not_found_count} not found`)}
        ${pill("warn", `${m.unknown_count} unknown`)}
        <span class="faint">checked ${m.checked}${m.total_available ? ` of ${m.total_available}` : ""} sites in ${m.took_ms}ms${m.dataset ? ` · ${esc(m.dataset)}` : ""}</span>
      </div>`;
    const controls = `<div class="site-controls">
        <input type="search" id="site-filter" class="site-filter" autocomplete="off" spellcheck="false"
               placeholder="filter sites…" aria-label="Filter checked sites">
        <label class="site-foundonly"><input type="checkbox" id="site-found-only"> found only</label>
        <span class="faint small" id="site-count"></span>
      </div>`;
    const grid = `<div class="site-grid" id="site-grid" role="list">${renderSiteGrid(lastUsernameSites)}</div>`;
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
    return card("Username", summary + controls + grid + sampleNote) + githubCard + infostealerBlock(m.infostealer);
  }

  // Gravatar's public profile API — when it exists it's a strong identity
  // anchor (real name, employer, verified linked accounts). Each linked
  // account is itself a pivot: re-scan the handle on its own site.
  function gravatarProfileCard(gp) {
    if (!gp) return "";
    if (gp.error) return card("Gravatar profile", `<p class="faint">${esc(gp.error)}</p>`);
    if (!gp.exists) return "";
    // CSP here is img-src 'self' data: — no external images load, so the
    // avatar is a link out rather than a broken/blocked <img>.
    const avatarLink = gp.avatar
      ? `<a class="gravatar-avatar-link" href="${esc(N.safeUrl(gp.avatar))}" target="_blank" rel="noopener noreferrer">view avatar</a>` : "";
    const nameLine = [gp.job_title, gp.company].filter(Boolean).join(" @ ");
    const accounts = (gp.accounts || []).map(a => {
      const link = a.url
        ? `<a href="${esc(N.safeUrl(a.url))}" target="_blank" rel="noopener noreferrer">${esc(a.name || a.shortname || "link")}</a>`
        : esc(a.name || a.shortname || "link");
      return `<div class="pivot-row">
          <span class="pivot-val">${link}${a.username ? ` — @${esc(a.username)}` : ""}${a.verified ? " ✓" : ""}</span>
          ${a.username ? pivotChip(a.username, "username") : ""}
        </div>`;
    }).join("");
    const body = `<div class="gravatar-identity">
        <div class="gravatar-identity-text">
          <div class="name">${esc(gp.display_name || gp.username || "")}</div>
          ${nameLine ? `<div class="sub">${esc(nameLine)}</div>` : ""}
          ${gp.location ? `<div class="sub">${esc(gp.location)}</div>` : ""}
          ${gp.pronouns ? `<div class="faint small">${esc(gp.pronouns)}</div>` : ""}
        </div>
        ${avatarLink}
      </div>`
      + (gp.about ? `<p class="sub mt">${esc(gp.about)}</p>` : "")
      + (accounts ? `<div class="mt subdomain-list">${accounts}</div>` : "");
    return card("Gravatar profile", body);
  }

  function renderEmail(m) {
    const bc = m.breach_check || {};
    const an = m.breach_analytics || {};
    const gv = m.gravatar || {};
    const k = m.keyed || {};
    // The local-part is a common username elsewhere — offer a one-click pivot
    // that re-runs the username scan on it.
    const localPart = (m.input || "").split("@")[0];
    const summary = kv([
      ["Local part", localPart ? raw(pivotValue(localPart, "username")) : ""],
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
          <div class="meta">${esc(b.year || "")} · ${num(b.records) ? num(b.records) + " records" : ""}
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
      + gravatarProfileCard(m.gravatar_profile)
      + infostealerBlock(m.infostealer)
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
    const csSrc = subs.certspotter || {};
    const rdSrc = subs.rapiddns || {};
    const stPart = stSrc.error != null || stSrc.count
      ? `, SecurityTrails: ${stSrc.count || 0}${stSrc.error ? ` (${esc(stSrc.error)})` : ""}` : "";
    const csPart = csSrc.error != null || csSrc.count
      ? `, certspotter: ${csSrc.count || 0}${csSrc.error ? ` (${esc(csSrc.error)})` : ""}` : "";
    const rdPart = rdSrc.error != null || rdSrc.count
      ? `, rapiddns: ${rdSrc.count || 0}${rdSrc.error ? ` (${esc(rdSrc.error)})` : ""}` : "";
    const nTakeover = Math.min((subs.names || []).length, TAKEOVER_MAX_SUBS);
    const takeoverBtn = (subs.names || []).length
      ? `<button type="button" class="ghost mt sub-takeover-btn">Check these ${nTakeover} for takeover</button>`
      : "";
    const subsHtml = (subs.names || []).length
      ? `<p class="faint mb">${subs.count} unique name(s) — crt.sh: ${crtSrc.count || 0}${crtSrc.error ? ` (${esc(crtSrc.error)})` : ""}, `
        + `hackertarget: ${htSrc.count || 0}${htSrc.error ? ` (${esc(htSrc.error)})` : ""}${stPart}${csPart}${rdPart}</p>${pivotList(subs.names, "domain")}${takeoverBtn}`
      : `<p class="faint">crt.sh: ${esc(crtSrc.error || "unavailable")} · hackertarget: ${esc(htSrc.error || "unavailable")}${stPart}${csPart}${rdPart}</p>`;

    const dnssec = m.dnssec || {};
    const dnssecHtml = `<div class="badge-row">
        ${pill(dnssec.signed ? "ok" : "warn", dnssec.signed ? "DNSSEC signed" : "not signed")}
        ${dnssec.dnskey_count ? `<span class="faint">${dnssec.dnskey_count} DNSKEY record(s)</span>` : ""}
      </div>` + (dnssec.note ? `<p class="faint small">${esc(dnssec.note)}</p>` : "");

    const wu = m.wayback_urls || {};
    let wbUrlsHtml;
    if (wu.ok && (wu.urls || []).length) {
      wbUrlsHtml = `<p class="faint mb">${wu.count} historical URL(s) on record (showing ${wu.urls.length})</p>`
        + `<div class="subdomain-list wayback-list">${wu.urls.map(u =>
            `<div><a href="${esc(N.safeUrl(u))}" target="_blank" rel="noopener noreferrer">${esc(u)}</a></div>`).join("")}</div>`;
    } else {
      wbUrlsHtml = `<p class="faint">${esc(wu.error || "no historical URLs on record")}</p>`;
    }

    const dinf = m.infostealer || {};
    let dinfHtml;
    if (dinf.error) {
      dinfHtml = `<p class="faint">${esc(dinf.error)}</p>`;
    } else if (dinf.ok === false) {
      dinfHtml = `<p class="faint">${esc(dinf.error || "check failed")}</p>`;
    } else if (dinf.total) {
      const urlLine = (u) => `<div>${esc(u.url)} <span class="faint">(seen ${num(u.occurrence)}${u.type ? `, ${esc(u.type)}` : ""} time(s))</span></div>`;
      dinfHtml = `<div class="badge-row">
          ${pill("warn", `${num(dinf.total)} compromised credential(s)`)}
          <span class="faint">${num(dinf.employees || 0)} employee(s) · ${num(dinf.users || 0)} user(s) · ${num(dinf.third_parties || 0)} third-part(y/ies)</span>
        </div>`
        + (dinf.employee_urls && dinf.employee_urls.length
            ? `<p class="faint mb mt">Employee-side URLs seen in stealer logs</p><div class="subdomain-list">${dinf.employee_urls.map(urlLine).join("")}</div>` : "")
        + (dinf.client_urls && dinf.client_urls.length
            ? `<p class="faint mb mt">Customer / user-side URLs seen in stealer logs</p><div class="subdomain-list">${dinf.client_urls.map(urlLine).join("")}</div>` : "");
    } else {
      dinfHtml = `<p class="ok">no infostealer exposure on file (HudsonRock)</p>`;
    }

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
      card("DNSSEC", dnssecHtml),
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
      card("Historical URLs (Wayback)", wbUrlsHtml),
      card("Infostealer exposure (org, HudsonRock)", dinfHtml),
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

    const ripe = m.ripestat || {};
    const ripeHtml = ripe.ok
      ? kv([
          ["Announcing ASN(s)", (ripe.asns || []).length
            ? raw((ripe.asns || []).map(a => pivotValue("AS" + a, "asn")).join(", ")) : ""],
          ["Covering prefix", ripe.prefix],
          ["AS holder", ripe.holder],
        ])
      : `<p class="faint">${esc(ripe.error || "unavailable")}</p>`;

    const isc = m.isc || {};
    let iscHtml;
    if (isc.ok) {
      const feedPills = (isc.threatfeeds || []).map(f => pill("warn", f)).join(" ");
      iscHtml = kv([
        ["Attacks", isc.attacks], ["Reports", isc.reports],
        ["AS name", isc.asname], ["AS country", isc.ascountry],
        ["Abuse contact", isc.abuse_contact], ["Network", isc.network],
      ]) + (feedPills ? `<div class="badge-row mt">${feedPills}</div>` : "")
        + (isc.comment ? `<p class="faint small mt">${esc(isc.comment)}</p>` : "");
    } else {
      iscHtml = `<p class="faint">${esc(isc.error || "unavailable")}</p>`;
    }

    return [
      card("InternetDB (Shodan)", idbHtml),
      card("Geolocation", geoHtml),
      card("Reverse DNS", rdnsHtml),
      card("RDAP netblock", rdapHtml),
      card("RIPEstat routing", ripeHtml),
      card("SANS ISC threat intel", iscHtml),
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
    const a = m.analysis || {};
    const l = m.lookup || {};
    const k = m.keyed || {};
    const c = a.country || {};

    // The offline analysis is the headline -- it shows real data with no key.
    let analysisHtml;
    if (a.ok) {
      const validTxt = a.valid === true ? "yes" : a.valid === false ? "no" : "unknown";
      const rows = [
        ["Country", c.name ? `${c.flag ? c.flag + " " : ""}${c.name}${c.calling_code ? ` (+${c.calling_code})` : ""}` : "unknown"],
        ["Number type", a.number_type],
        ["Valid (structure)", validTxt],
        ["E.164", a.e164],
        ["National format", a.national_format],
        ["International format", a.international_format],
      ];
      const n = a.nanp || {};
      if (n.region) rows.push(["Region", `${n.region}${n.area_code ? ` (area code ${n.area_code})` : ""}`]);
      if (n.timezone) rows.push(["Time zone", n.timezone + (n.timezone_approx ? " (approx.)" : "")]);
      if (n.local_time) rows.push(["Local time now", n.local_time]);
      analysisHtml = kv(rows);
      if (a.notes && a.notes.length) {
        analysisHtml += `<div class="phone-notes mt">${a.notes.map(t => `<p class="faint">${esc(t)}</p>`).join("")}</div>`;
      }
    } else {
      analysisHtml = `<p class="bad">${esc(a.error || "could not parse this number")}</p>`;
    }

    let lookupHtml;
    if (!l.configured) {
      lookupHtml = `<p class="faint">${esc(l.note || "add a NumLookupAPI key in Settings for live carrier and line-type data")}</p>`;
    } else if (l.ok) {
      lookupHtml = kv([
        ["Valid", l.valid === true ? "yes" : l.valid === false ? "no" : "unknown"],
        ["Carrier", l.carrier], ["Line type", l.line_type], ["Location", l.location],
        ["Country", l.country_name], ["International format", l.international_format],
      ]);
    } else {
      lookupHtml = `<p class="bad">${esc(l.error || "lookup failed")}</p>`;
    }

    return card("Phone number", analysisHtml)
      + card("Live carrier lookup (NumLookupAPI)", lookupHtml + renderUnlock(m.unlock))
      + keyedCard("IPQualityScore (fraud + carrier)", k.ipqs, [
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
    const mb = m.malwarebazaar || {};
    let mbHtml;
    if (mb.ok === false) {
      mbHtml = `<p class="faint">${esc(mb.error || "unavailable")}</p>`;
    } else if (mb.known) {
      mbHtml = kv([
        ["Known malware", "yes"],
        ["Signature", mb.signature],
        ["File type", mb.file_type],
        ["File name", mb.file_name],
        ["First seen", mb.first_seen],
        ["Delivery method", mb.delivery_method],
        ["Tags", (mb.tags || []).join(", ")],
      ]);
    } else {
      mbHtml = kv([["Known malware", "no"], ["Note", mb.note || "not a known sample"]]);
    }

    return card("Hash lookup (CIRCL hashlookup)", body + renderUnlock(m.unlock))
      + card("MalwareBazaar (abuse.ch)", mbHtml)
      + keyedCard("VirusTotal (file reputation)", k.virustotal, [
          ["Detections", k.virustotal && k.virustotal.malicious != null
            ? `${k.virustotal.malicious} / ${k.virustotal.total}` : ""],
          ["Name", k.virustotal && k.virustotal.meaningful_name],
          ["Type", k.virustotal && k.virustotal.type_description],
          ["Threat label", k.virustotal && k.virustotal.threat_label],
        ]);
  }

  // OFAC hit is the one crypto finding that needs to read as urgent rather
  // than as another kv row — a sanctioned address changes what you can legally
  // do next, so it gets its own loud banner instead of blending into the card.
  function sanctionsBanner(s) {
    if (!s) return "";
    if (s.error) return `<p class="faint small mt">sanctions check: ${esc(s.error)}</p>`;
    if (!s.checked) return `<p class="faint small mt">sanctions check not run</p>`;
    if (s.sanctioned === true) {
      return `<div class="sanctions-banner bad mt">
          <strong>OFAC SANCTIONED ADDRESS</strong>
          <span>${esc(s.source || "OFAC SDN")}${s.note ? " — " + esc(s.note) : ""}</span>
        </div>`;
    }
    return `<p class="ok small mt">not on OFAC list${s.source ? ` (${esc(s.source)})` : ""}</p>`;
  }

  function renderCrypto(m) {
    if (!m.ok) return card("Crypto address", `<p class="bad">${esc(m.error || "lookup failed")}</p>`);
    if (m.chain === "BTC") {
      const mp = m.mempool || {};
      const mpHtml = mp.ok
        ? kv([
            ["mempool.space balance", `${mp.balance_btc} BTC`],
            ["mempool.space received/sent", `${mp.total_received_btc} / ${mp.total_sent_btc} BTC`],
            ["mempool.space tx count", mp.tx_count],
            ["Pending tx", mp.pending_tx],
          ])
        : (mp.error ? `<p class="faint small">mempool.space: ${esc(mp.error)}</p>` : "");
      return card("Crypto address (Bitcoin)", kv([
        ["Balance", `${m.balance_btc} BTC`],
        ["Total received", `${m.total_received_btc} BTC`],
        ["Total sent", `${m.total_sent_btc} BTC`],
        ["Transaction count", m.n_tx],
        ["Note", m.note],
      ]) + mpHtml + sanctionsBanner(m.sanctions));
    }
    const tokens = (m.tokens || []).map(t => `${t.name || "?"} (${t.symbol || "?"})`).join(", ");
    return card("Crypto address (Ethereum)", kv([
      ["Balance", `${m.balance_eth} ETH`],
      ["Total in", m.total_in_eth != null ? `${m.total_in_eth} ETH` : ""],
      ["Total out", m.total_out_eth != null ? `${m.total_out_eth} ETH` : ""],
      ["Token count", m.token_count],
      ["Tokens", tokens],
      ["Note", m.note],
    ]) + sanctionsBanner(m.sanctions));
  }

  function renderMac(m) {
    if (m.error) return card("MAC vendor lookup", `<p class="bad">${esc(m.error)}</p>`);
    return card("MAC vendor lookup (macvendors.com)", kv([
      ["Vendor", m.known ? m.vendor : "unknown"],
      ["Note", m.note],
    ]));
  }

  function renderAsn(m) {
    if (m.ok === false || m.error) return card("ASN", `<p class="bad">${esc(m.error || "lookup failed")}</p>`);
    const v4 = (m.prefixes_v4 || []).slice(0, 25);
    const v6 = (m.prefixes_v6 || []).slice(0, 25);
    return card("ASN " + (m.asn || m.input || ""), kv([
      ["Holder", m.holder],
      ["Registry", m.registry],
      ["Announced", boolStr(m.announced)],
      ["Total prefixes", m.prefix_count],
    ]) + (v4.length ? `<p class="faint mb mt">IPv4 prefixes (sample)</p>${list(v4)}` : "")
      + (v6.length ? `<p class="faint mb mt">IPv6 prefixes (sample)</p>${list(v6)}` : ""));
  }

  // Discord snowflake IDs encode their own creation timestamp — no network
  // call needed, it's just bit math on the ID. created_utc is already an
  // ISO string from the server; render it plainly rather than reformatting.
  function renderDiscord(m) {
    if (m.ok === false || m.error) return card("Discord ID", `<p class="bad">${esc(m.error || "decode failed")}</p>`);
    return card("Discord ID", kv([
      ["Created", m.created_utc],
      ["Worker ID", m.worker_id],
      ["Process ID", m.process_id],
      ["Increment", m.increment],
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
    asn: renderAsn, discord: renderDiscord,
  };

  // -- copy / export toolbar (built from the shared kit) ---------------------
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

  // The scan results toolbar: Copy Markdown / Copy JSON / Download .md /
  // Download .json, all from N.resultBar so recon exports the same way every
  // other console does. getText/json are functions so the buttons always act
  // on the current scan even after a pivot re-render.
  function buildResultsToolbar() {
    if (!resultsToolbar) return;
    resultsToolbar.innerHTML = "";
    resultsToolbar.appendChild(N.resultBar({
      getText: () => (lastScanData ? scanToMarkdown(lastScanData) : ""),
      json: () => lastScanData,
      filename: "recon-" + ((lastScanData && lastScanData.detected_type) || "scan"),
      mime: "text/markdown",
      copyLabel: "Copy Markdown",
    }));
  }

  // A takeover run as a shareable markdown report (for the takeover result bar).
  function takeoverToMarkdown(data) {
    if (!data) return "";
    const c = data.counts || {};
    const lines = ["# Subdomain takeover check"];
    if (data.domain) lines.push("Domain: `" + data.domain + "`");
    lines.push(`Checked ${data.checked} host(s): ${c.vulnerable || 0} vulnerable, `
      + `${c.likely || 0} likely, ${c.safe || 0} safe`
      + (c.error ? `, ${c.error} error` : ""));
    lines.push("");
    (data.results || []).forEach(r => {
      lines.push(`## ${r.subdomain} — ${r.verdict}`);
      if (r.service) lines.push(`- service: ${r.service}`);
      if (r.cname_chain && r.cname_chain.length) lines.push(`- CNAME: ${r.cname_chain.join(" -> ")}`);
      if (r.http_status) lines.push(`- HTTP: ${r.http_status}`);
      (r.evidence || []).forEach(e => lines.push(`- ${e}`));
      if (r.note) lines.push(`- note: ${r.note}`);
      lines.push("");
    });
    return lines.join("\n").trim() + "\n";
  }

  // -- elapsed-time ticker (nmap "full" etc can run 600s — an honest clock
  // beats a static spinner that looks hung) -----------------------------
  function startTicker(label) {
    stopTicker();
    const start = Date.now();
    statusLine.classList.remove("hidden");
    // #status-line is an aria-live region; the 5x/sec ticker would flood a
    // screen reader, so mark it busy while it spins and clear that when the
    // final "detected: …" line lands (settleStatus) so only that is announced.
    statusLine.setAttribute("aria-busy", "true");
    const tick = () => {
      statusLine.innerHTML = `<span class="spinner"></span> ${esc(label)} — ${((Date.now() - start) / 1000).toFixed(1)}s`;
    };
    tick();
    scanTicker = setInterval(tick, 200);
  }

  // Set the final (announced) status text and release the aria-busy hold.
  function settleStatus(text) {
    statusLine.classList.remove("hidden");
    statusLine.textContent = text;
    statusLine.removeAttribute("aria-busy");
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
      const label = isLast ? `Current scan: ${esc(t.value)}` : `Re-run scan for ${esc(t.value)}`;
      return `${sep}<button type="button" class="${cls}" data-trail-index="${i}" aria-label="${label}"${isLast ? " disabled" : ""}>${esc(t.value)}</button>`;
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

  // One-click discovery -> takeover: carry the domain scan's subdomains into
  // the takeover checker (capped at the server's per-request limit) and run it.
  function launchSubsTakeover() {
    const mod = lastScanData && lastScanData.modules && lastScanData.modules.domain;
    const names = (mod && mod.subdomains && mod.subdomains.names) || [];
    if (!names.length) { N.toast("no subdomains to check", "bad"); return; }
    const input = document.getElementById("takeover-input");
    const takeoverCard = document.getElementById("takeover-card");
    if (input) input.value = names.slice(0, TAKEOVER_MAX_SUBS).join(" ");
    if (takeoverCard) takeoverCard.scrollIntoView({ behavior: "smooth", block: "start" });
    runTakeover();
  }

  results.addEventListener("click", (e) => {
    if (e.target.closest(".sub-takeover-btn")) { launchSubsTakeover(); return; }
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
      const resolvedType = data.detected_type || type;
      renderResults(data);
      settleStatus(`detected: ${TYPE_LABEL[data.detected_type] || data.detected_type} · ${data.took_ms}ms`);
      buildResultsToolbar();
      if (resultsToolbar) resultsToolbar.classList.remove("hidden");
      pushTrail(q, resolvedType);
      // Remember for the recents panel + deep-link, and make this scan
      // shareable/reloadable via the URL hash (replaceState so we don't spam
      // browser history on every pivot).
      lastTypeStore.set(typeSelect.value);
      pushRecent(q, resolvedType);
      writeHash(q, resolvedType);
      loadReconHistory();
    } catch (e) {
      stopTicker();
      settleStatus("");
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
    // The username site grid has interactive controls (filter / found-only)
    // that must be wired after the innerHTML swap.
    if (data.detected_type === "username") wireUsernameControls();
  }

  // -- recents + deep-link ---------------------------------------------------
  function currentRecents() {
    const v = recentsStore.get([]);
    return Array.isArray(v) ? v : [];
  }
  function pushRecent(q, type) {
    let list = currentRecents().filter(r => !(r.q === q && r.type === type));
    list.unshift({ q: q, type: type, ts: new Date().toISOString() });
    recentsStore.set(list.slice(0, RECENTS_MAX));
  }
  function writeHash(q, type) {
    try {
      const h = "#q=" + encodeURIComponent(q) + "&type=" + encodeURIComponent(type || "auto");
      history.replaceState(null, "", h);
    } catch (_) { /* replaceState can throw in odd sandboxes — deep-link is a nicety */ }
  }
  function readHash() {
    const h = (location.hash || "").replace(/^#/, "");
    if (!h) return null;
    const params = {};
    h.split("&").forEach(part => {
      const i = part.indexOf("=");
      if (i < 0) return;
      try { params[decodeURIComponent(part.slice(0, i))] = decodeURIComponent(part.slice(i + 1)); }
      catch (_) { /* skip a malformed pair */ }
    });
    return params.q ? { q: params.q, type: params.type || "auto" } : null;
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

  // Initial load: restore the last-used type, then honor a deep-link
  // (#q=…&type=…) by running that scan straight away; otherwise show the
  // clickable empty state.
  (function initFromEnv() {
    const savedType = lastTypeStore.get(null);
    if (savedType && (savedType === "auto" || TYPE_LABEL[savedType])) typeSelect.value = savedType;
    const linked = readHash();
    if (linked) {
      qInput.value = linked.q;
      if (linked.type && (linked.type === "auto" || TYPE_LABEL[linked.type])) typeSelect.value = linked.type;
      runScan(linked.q, typeSelect.value);
    } else {
      renderEmptyState();
    }
  })();

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

  // -- scan history -----------------------------------------------------------
  // Two honest sources: the disk-backed server log (only populated when
  // NUCLEUS_LOGGING=1) and this browser's client-side recents. When the server
  // has entries we show those (reopen-by-id, full stored scan); otherwise we
  // show the recents this browser remembers (re-run-by-query). The panel is
  // always visible with a clear note, so it never reads as broken/empty.
  function setHistoryNote(text) { if (historyNote) historyNote.textContent = text; }

  async function loadReconHistory() {
    if (!historyWrap || !historyList) return;
    historyWrap.classList.remove("hidden");
    let scans = null;
    try {
      const j = await N.get("/api/recon-history?limit=50");
      scans = j.scans || [];
    } catch (e) { scans = null; }  // endpoint missing / errored — fall back to recents
    if (scans && scans.length) {
      setHistoryNote("Persisted scans — server-side history is on. Click one to reopen the full saved result.");
      renderHistoryItems(scans, "disk");
    } else {
      setHistoryNote("Recent scans this browser remembers (client-side only). "
        + "Set NUCLEUS_LOGGING=1 for a persistent server-side trail you can reopen in full.");
      renderHistoryItems(currentRecents(), "recents");
    }
  }

  function renderHistoryItems(items, mode) {
    historyList.innerHTML = "";
    if (!items.length) {
      historyList.appendChild(N.stateCard("empty",
        "No scans yet — run one above. On-disk history is off by default; set NUCLEUS_LOGGING=1 to keep a persistent trail."));
      return;
    }
    items.forEach(s => {
      const item = N.el("button", { class: "hist-item", type: "button" });
      const top = N.el("div", { class: "hist-top" });
      top.appendChild(N.el("span", { class: "pill", text: TYPE_LABEL[s.type] || s.type || "?" }));
      top.appendChild(N.el("span", { class: "faint small", text: s.ts || "" }));
      item.appendChild(top);
      item.appendChild(N.el("div", { class: "hist-q mono", text: s.q || "" }));
      if (s.summary) item.appendChild(N.el("div", { class: "sub", text: s.summary }));
      if (mode === "disk") {
        item.addEventListener("click", () => reopenScan(s.id, s.q));
      } else {
        item.addEventListener("click", () => {
          qInput.value = s.q || "";
          if (s.type && (s.type === "auto" || TYPE_LABEL[s.type])) typeSelect.value = s.type;
          runScan(s.q, s.type || "auto");
          window.scrollTo({ top: 0, behavior: "smooth" });
        });
      }
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
      settleStatus(`reopened: ${TYPE_LABEL[data.detected_type] || data.detected_type}`
        + (data.took_ms != null ? ` · ${data.took_ms}ms` : ""));
      buildResultsToolbar();
      if (resultsToolbar) resultsToolbar.classList.remove("hidden");
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      stopTicker();
      settleStatus("");
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

  // ---- subdomain takeover checker ----
  function takeoverVerdictPill(v) {
    if (v === "vulnerable") return "bad";
    if (v === "likely") return "warn";
    if (v === "safe") return "ok";
    return "";  // error
  }

  function renderTakeover(data) {
    const c = data.counts || {};
    let body = `<p class="sub">Checked ${data.checked} host(s): `
      + `<span class="pill bad">${c.vulnerable || 0} vulnerable</span> `
      + `<span class="pill warn">${c.likely || 0} likely</span> `
      + `<span class="pill ok">${c.safe || 0} safe</span>`
      + (c.error ? ` <span class="pill">${c.error} error</span>` : "")
      + `</p>`;
    (data.results || []).forEach((r) => {
      const chain = (r.cname_chain && r.cname_chain.length) ? esc(r.cname_chain.join(" → ")) : "no CNAME";
      body += `<div class="takeover-row">`
        + `<div><span class="pill ${takeoverVerdictPill(r.verdict)}">${esc(r.verdict)}</span> `
        + `<strong>${esc(r.subdomain)}</strong>`
        + (r.service ? ` <span class="faint small">— ${esc(r.service)}</span>` : "")
        + `</div>`
        + `<p class="sub mono small">CNAME: ${chain}${r.http_status ? " · HTTP " + esc(String(r.http_status)) : ""}</p>`;
      if (r.evidence && r.evidence.length) body += `<p class="sub">${esc(r.evidence.join("; "))}</p>`;
      if (r.note) body += `<p class="sub faint">${esc(r.note)}</p>`;
      body += `</div>`;
    });
    return body;
  }

  async function runTakeover() {
    const input = document.getElementById("takeover-input");
    const status = document.getElementById("takeover-status");
    const resultWrap = document.getElementById("takeover-result");
    const rawVal = (input.value || "").trim();
    if (!rawVal) { N.toast("enter a host first", "bad"); return; }
    const parts = rawVal.split(/[\s,]+/).filter(Boolean);
    const btn = document.getElementById("takeover-btn");
    btn.disabled = true;
    status.textContent = "following CNAME chains…";
    resultWrap.classList.remove("hidden");
    resultWrap.innerHTML = "";
    try {
      const payload = parts.length === 1 ? { domain: parts[0] } : { subdomains: parts };
      const data = await N.post("/api/takeover", payload);
      status.textContent = "";
      lastTakeoverData = data;
      resultWrap.innerHTML = renderTakeover(data);
      resultWrap.appendChild(N.resultBar({
        getText: () => takeoverToMarkdown(lastTakeoverData),
        json: () => lastTakeoverData,
        filename: "takeover-" + ((lastTakeoverData && lastTakeoverData.domain) || "check"),
        mime: "text/markdown",
        copyLabel: "Copy",
      }));
    } catch (e) {
      status.textContent = "";
      resultWrap.innerHTML = `<p class="bad">${esc(e.message || "takeover check failed")}</p>`;
      N.toast(e.message || "takeover check failed", "bad");
    } finally {
      btn.disabled = false;
    }
  }

  const takeoverBtn = document.getElementById("takeover-btn");
  if (takeoverBtn) {
    takeoverBtn.addEventListener("click", runTakeover);
    document.getElementById("takeover-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") runTakeover();
    });
  }

  loadResources();
})();
