// Certificate Observatory - Chart Rendering
// Uses uPlot (https://github.com/leeoniya/uPlot)

import uPlot from './lib/dist/uPlot.esm.js';

const DATA_DIR = 'data/';
// Default number of snapshots shown on the line graphs; overridable
// per chart via the settings dialog (stored in localStorage).
const MAX_POINTS = 25;
const METRICS = [
  { id: 'tls-versions', group: 'Protocol', title: 'SSL/TLS Versions Negotiated', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Transport_Layer_Security',
    description: 'Share of scanned sites whose TLS handshake negotiated each protocol version (SSL 3.0 and TLS 1.0–1.3). The pie chart shows the breakdown of the most recent scan. A growing TLS 1.3 share and shrinking legacy versions indicate the ecosystem is modernising; older versions stay visible because some servers still accept them.' },
  { id: 'cipher-suites', group: 'Protocol', title: 'Cipher Suites (Top 15)', type: 'stacked', unit: '%', limit: 15,
    wiki: 'https://en.wikipedia.org/wiki/Cipher_suite',
    description: 'The 15 most common cipher suites negotiated during handshakes, as a percentage of the sample (renormalised over the top 15). Weak or deprecated suites — such as those using RC4, 3DES or CBC with SHA-1 — signal outdated server configuration.' },
  { id: 'key-algorithms', group: 'Keys & Signatures', title: 'Public Key Algorithms', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Public-key_cryptography',
    description: 'Distribution of the algorithms used in certificate public keys (RSA, ECDSA, EdDSA, …). A shift towards ECDSA and EdDSA reflects migration to shorter, faster keys.' },
  { id: 'signature-algorithms', group: 'Keys & Signatures', title: 'Signature Algorithms', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Digital_signature',
    description: 'Algorithms used to sign the certificates themselves (e.g. sha256WithRSAEncryption, ecdsa-with-SHA384). SHA-1 signatures are deprecated and should no longer appear on publicly trusted certificates.' },
  { id: 'validity-periods', group: 'Certificates', title: 'Certificate Validity Periods', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/X.509',
    description: 'How long certificates are issued for, bucketed by lifetime. Public CAs cap subscriber certificates at 398 days, so longer lifetimes usually mean internal, self-signed or legacy certificates.' },
  { id: 'certificate-lifetime-trends', group: 'Certificates', title: 'Certificate Lifetime Trends', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/X.509',
    description: 'Certificate lifetimes grouped around policy thresholds: 0-90 days (short-lived, e.g. Let\'s Encrypt style), 91-398 days (CA/Browser Forum maximum for subscriber certificates), 399-825 days (legacy Apple cap), and 826+ days (multi-year). Tracks the industry shift towards shorter-lived certificates.' },
  { id: 'san-counts', group: 'Certificates', title: 'SAN Entry Count per Certificate', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Subject_Alternative_Name',
    description: 'Number of Subject Alternative Name entries per certificate, in buckets. Certificates with many SANs cover several hostnames at once, common for multi-domain setups.' },
  { id: 'ca-market-share', group: 'Trust & Validation', title: 'CA Market Share (Top 10)', type: 'stacked', unit: '%', limit: 10,
    wiki: 'https://en.wikipedia.org/wiki/Certificate_authority',
    description: 'Share of certificates issued by the top 10 certificate authorities across the sampled sites (percentages renormalised over the top 10). Shows how concentrated the CA ecosystem is.' },
  { id: 'ocsp-stapling', group: 'Trust & Validation', title: 'OCSP Stapling Support', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/OCSP_stapling',
    description: 'Whether servers deliver a stapled OCSP response during the handshake. Stapling improves privacy and reliability compared with clients querying the CA directly; "Supported" means the server returned a valid, unexpired staple.' },
  { id: 'ocsp-must-staple', group: 'Trust & Validation', title: 'OCSP Must-Staple', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/OCSP_stapling',
    description: 'Share of certificates carrying the OCSP Must-Staple extension (RFC 7633), which obliges the server to staple a fresh OCSP response. "must-staple" means the extension is present; "not-must-staple" means it is absent.' },
  { id: 'certificate-transparency', group: 'Trust & Validation', title: 'Certificate Transparency (SCTs)', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Certificate_Transparency',
    description: 'Number of Signed Certificate Timestamps attached to each certificate. CT is mandatory for publicly trusted certificates; multiple SCTs mean the certificate is logged in several independent CT logs.' },
  { id: 'extensions', group: 'Trust & Validation', title: 'X.509 Extensions Present', type: 'grouped', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/X.509',
    description: 'The share of certificates containing each X.509 extension (key usage, SAN, basic constraints, …). A certificate can carry several extensions at once, so the lines are independent and do not add up to 100%.' },
  { id: 'key-sizes', group: 'Keys & Signatures', title: 'Public Key Sizes', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Key_size',
    description: 'Strength of certificate public keys: RSA key sizes (1024 / 2048 / 4096+ bits) and ECDSA curve sizes (P-256 / P-384 / P-521). RSA-1024 is considered insecure; RSA-2048 and P-256 are the current baseline.' },
  { id: 'hash-algorithms', group: 'Keys & Signatures', title: 'Hash Algorithms', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Cryptographic_hash_function',
    description: 'Hash algorithms used in certificate signatures (SHA-1, SHA-256, SHA-384, SHA-512, MD5). MD5 and SHA-1 are deprecated and should not appear in modern certificates.' },
  { id: 'wildcard-certs', group: 'Certificates', title: 'Wildcard Certificates', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Wildcard_certificate',
    description: 'Share of certificates whose primary domain starts with "*.", i.e. wildcards covering a whole subdomain level (e.g. *.example.com).' },
  { id: 'self-signed', group: 'Certificates', title: 'Self-Signed Certificates', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Self-signed_certificate',
    description: 'Share of certificates where issuer equals subject, i.e. self-signed. These are typically internal, test or IoT certificates rather than publicly trusted ones.' },
  { id: 'expired-certs', group: 'Certificates', title: 'Expired Certificates in Use', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/X.509',
    description: 'Share of sampled sites serving a certificate that had already passed its notAfter date at scan time. Browsers reject these, so the signal indicates misconfiguration or neglect.' },
  { id: 'forward-secrecy', group: 'Protocol', title: 'Forward Secrecy Support', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Forward_secrecy',
    description: 'Share of connections whose negotiated cipher uses ECDHE or DHE key exchange (Perfect Forward Secrecy). "forward-secret" means the cipher is ephemeral; "not-forward-secret" means a static key exchange was used.' },
  { id: 'chain-completeness', group: 'Trust & Validation', title: 'Certificate Chain Completeness', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Chain_of_trust',
    description: 'Whether the server sends a complete chain that builds to a trusted root. "complete" means the leaf verifies against the system trust store using the supplied intermediates; "incomplete" means it does not.' },
  { id: 'root-ca-distribution', group: 'Trust & Validation', title: 'Root CA Distribution', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Certificate_authority',
    description: 'Distribution of the root certificate authorities that ultimately issued the sampled certificates (top roots by count).' },
  { id: 'key-reuse', group: 'Keys & Signatures', title: 'Certificate Key Reuse', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Public-key_cryptography',
    description: 'Share of certificates whose public key is reused across multiple sampled domains ("reused") vs. unique keys ("unique"). Widespread reuse can indicate shared infrastructure or key compromise.' },
  { id: 'ct-log-diversity', group: 'Trust & Validation', title: 'CT Log Diversity', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Certificate_Transparency',
    description: 'Number of distinct Certificate Transparency logs an entry is logged in, bucketed. More logs means broader independent verification.' },
  { id: 'hsts', group: 'Trust & Validation', title: 'HSTS Support', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security',
    description: 'Share of sites sending an HTTP Strict-Transport-Security header ("hsts") vs. not ("no-hsts").' },
  { id: 'caa-records', group: 'Trust & Validation', title: 'CAA Records', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/DNS_Certification_Authority_Authorization',
    description: 'Share of domains publishing a Certificate Authority Authorization DNS record ("caa") vs. not ("no-caa").' },
  { id: 'rc4-support', group: 'Protocol', title: 'RC4 Support', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/RC4',
    description: 'Servers still accepting RC4 (deprecated, insecure). Modern TLS stacks have removed RC4, so this is expected to be 0.' },
  { id: 'tls-compression', group: 'Protocol', title: 'TLS Compression (CRIME)', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/CRIME',
    description: 'Share of servers supporting TLS-level compression ("compression"), which enables the CRIME attack. "no-compression" is the safe state.' },
  { id: 'secure-renegotiation', group: 'Protocol', title: 'Secure Renegotiation', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Transport_Layer_Security_renegotiation_attack',
    description: 'Servers supporting secure (RFC 5746) renegotiation ("secure") vs. not ("insecure").' },
  { id: 'poodle', group: 'Protocol', title: 'POODLE (SSL 3.0)', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/POODLE',
    description: 'Servers still supporting SSL 3.0 ("vulnerable") vs. not ("not-vulnerable"). SSL 3.0 is vulnerable to POODLE.' },
  { id: 'freak', group: 'Protocol', title: 'FREAK', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/FREAK',
    description: 'Servers supporting export-grade RSA ("vulnerable"). Export ciphers have been removed from modern stacks, so this is expected to be 0.' },
  { id: 'logjam', group: 'Protocol', title: 'Logjam', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Logjam_(computer_security)',
    description: 'Servers vulnerable to Logjam (weak DHE). Reported as 0 when not detectable with current tooling.' },
  { id: 'ech', group: 'Protocol', title: 'Encrypted Client Hello (ECH)', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Encrypted_Client_Hello',
    description: 'Share of domains publishing an ECH configuration in their DNS HTTPS record ("ech") vs. not ("no-ech").' },
  { id: 'pqc', group: 'Keys & Signatures', title: 'Post-Quantum Cryptography', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/Post-quantum_cryptography',
    description: 'Servers supporting hybrid post-quantum key exchange (X25519MLKEM768) ("pqc") vs. not ("no-pqc").' },
  { id: 'ipv6-support', group: 'Infrastructure', title: 'IPv6 Support', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/IPv6',
    description: 'Domains with IPv6 support ("ipv6") vs. IPv4-only ("ipv4-only"). When the scanner has IPv6 egress this reflects a successful TLS handshake over IPv6; otherwise it falls back to DNS (AAAA record presence), so the metric is never falsely 0% on IPv4-only runners.' },
  { id: 'issuance-volume', group: 'Certificates', title: 'Certificate Issuance Volume', type: 'stacked', unit: '%',
    wiki: 'https://en.wikipedia.org/wiki/X.509',
    description: 'Share of sampled certificates issued within the last 7 days ("issued-last-7d") vs. older ("older").' },

];

const COLORS = [
  '#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f',
  '#edc949', '#af7aa1', '#ff9da7', '#9c755f', '#bab0ac',
  '#86bcb6', '#d7b5a6', '#a0cbe8', '#f1ce63', '#d4a6c8',
];

async function fetchJSON(name) {
  const res = await fetch(`${DATA_DIR}${name}.json?v=${Date.now()}`);
  if (res.status === 404) return null; // no data yet (e.g. before first scan)
  if (!res.ok) throw new Error(`Failed to load ${name}: ${res.status}`);
  return res.json();
}

function normalizeHistory(history) {
  // Convert [{timestamp, sample_size, data: {...}}, ...] to uPlot format
  // uPlot expects: [ [timestamps], [series1], [series2], ... ]
  if (!history || history.length === 0) return null;

  // Collect all keys across all snapshots
  const allKeys = new Set();
  for (const snap of history) {
    for (const key of Object.keys(snap.data)) {
      allKeys.add(key);
    }
  }
  const keys = Array.from(allKeys).sort();

  // Build series: first row is timestamps, then one row per key
  const series = new Array(keys.length + 1); // +1 for timestamps
  series[0] = history.map(s => new Date(s.timestamp).getTime());

  for (let i = 0; i < keys.length; i++) {
    series[i + 1] = history.map(s => {
      const val = s.data[keys[i]];
      return typeof val === 'number' ? val : (val || 0);
    });
  }

  return { keys, series };
}

function computePercentages(series) {
  // Convert absolute counts to percentages per timestamp
  const n = series[0].length;
  const m = series.length - 1;
  for (let i = 0; i < n; i++) {
    let total = 0;
    for (let j = 1; j <= m; j++) {
      total += series[j][i];
    }
    if (total > 0) {
      for (let j = 1; j <= m; j++) {
        series[j][i] = (series[j][i] / total) * 100;
      }
    }
  }
  return series;
}

function createStackedChart(container, { keys, series }, title, colorMap) {
  // Use non-stacked lines for percentage data - each series shows its % over time
  // Explicitly set width/height from container since uPlot doesn't auto-read CSS dimensions
  const width = container.clientWidth;
  const height = container.clientHeight || 300;
  const opts = {
    width: width,
    height: height,
    series: [
      { label: 'Time', value: (u, v) => new Date(v).toLocaleDateString() },
      ...keys.map((key, i) => ({
        label: key,
        stroke: colorMap[key] || COLORS[i % COLORS.length],
        fill: null, // No fill - lines only
        width: 2,
        paths: uPlot.paths.linear(),
      })),
    ],
    axes: [
      { scale: 'x', stroke: '#ccc', grid: { stroke: '#eee' },
        values: (u, splits) => splits.map(s => (isNaN(s) ? '' : new Date(s).toLocaleDateString())) },
      { scale: 'y', stroke: '#ccc', grid: { stroke: '#eee' }, label: '%' },
    ],
    scales: {
      x: { time: true },
      y: { min: 0, max: 100 },
    },
    cursor: { show: true, x: false, y: false, focus: { prox: 100 } },
    legend: { show: false },
  };

  return new uPlot(opts, series, container);
}

function createGroupedChart(container, { keys, series }, title, colorMap, legendContainer) {
  // Build custom legend first (sorted by percentage descending)
  if (legendContainer) {
    legendContainer.innerHTML = '';
    const lastIdx = series[0].length - 1;
    const percentages = keys.map((key, i) => series[i + 1][lastIdx]);
    const sorted = keys.map((key, i) => ({ key, pct: percentages[i], color: colorMap[key] || COLORS[i % COLORS.length] }))
      .sort((a, b) => b.pct - a.pct);
    sorted.forEach(({ key, color }) => {
      const item = document.createElement('div');
      item.style.display = 'flex';
      item.style.alignItems = 'center';
      item.style.gap = '6px';
      item.style.marginBottom = '4px';
      item.style.fontSize = '11px';
      const marker = document.createElement('div');
      marker.style.width = '12px';
      marker.style.height = '12px';
      marker.style.backgroundColor = color;
      marker.style.borderRadius = '2px';
      marker.style.flexShrink = '0';
      const label = document.createElement('div');
      label.textContent = key;
      label.style.color = '#333';
      item.appendChild(marker);
      item.appendChild(label);
      legendContainer.appendChild(item);
    });
    // Force layout reflow so container.clientWidth reflects legend width
    void legendContainer.offsetHeight;
  }

  // For extensions: grouped bar chart (not stacked)
  // Explicitly set width/height from container since uPlot doesn't auto-read CSS dimensions
  const width = container.clientWidth;
  const height = container.clientHeight || 300;
  const opts = {
    width: width,
    height: height,
    series: [
      { label: 'Time', value: (u, v) => new Date(v).toLocaleDateString() },
      ...keys.map((key, i) => ({
        label: key,
        stroke: colorMap[key] || COLORS[i % COLORS.length],
        fill: null,
        width: 2,
        paths: uPlot.paths.linear(),
      })),
    ],
    axes: [
      { scale: 'x', stroke: '#ccc', grid: { stroke: '#eee' },
        values: (u, splits) => splits.map(s => (isNaN(s) ? '' : new Date(s).toLocaleDateString())) },
      { scale: 'y', stroke: '#ccc', grid: { stroke: '#eee' }, label: '%' },
    ],
    scales: {
      x: { time: true },
      y: { min: 0, max: 100 },
    },
    cursor: { show: true, x: false, y: false, focus: { prox: 100 } },
    legend: { show: false },
  };

  const chart = new uPlot(opts, series, container);

  return chart;
}
 
function drawPieChart(canvas, legendEl, keys, series, colorMap) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = 160;
  const cssHeight = 160;
  canvas.width = cssWidth * dpr;
  canvas.height = cssHeight * dpr;
  canvas.style.width = cssWidth + 'px';
  canvas.style.height = cssHeight + 'px';
  ctx.scale(dpr, dpr);

  const lastIdx = series[0].length - 1;
  const percentages = keys.map((key, i) => series[i + 1][lastIdx]);

  const centerX = cssWidth / 2;
  const centerY = cssHeight / 2;
  const radius = Math.min(cssWidth, cssHeight) / 2 - 5;

  let startAngle = -Math.PI / 2;
  for (let i = 0; i < keys.length; i++) {
    const sliceAngle = (percentages[i] / 100) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
    ctx.closePath();
    ctx.fillStyle = colorMap[keys[i]] || COLORS[i % COLORS.length];
    ctx.fill();
    startAngle += sliceAngle;
  }

  // Draw legend (sorted by percentage descending)
  if (legendEl) {
    legendEl.innerHTML = '';
    // Sort keys by percentage descending
    const sortedIndices = keys.map((key, i) => ({ key, pct: percentages[i], color: colorMap[key] || COLORS[i % COLORS.length], idx: i }))
      .sort((a, b) => b.pct - a.pct);
    for (const { key, pct, color } of sortedIndices) {
      const item = document.createElement('div');
      item.className = 'pie-legend-item';
      const colorEl = document.createElement('div');
      colorEl.className = 'pie-legend-color';
      colorEl.style.backgroundColor = color;
      const label = document.createElement('div');
      label.className = 'pie-legend-label';
      label.textContent = `${key}: ${pct.toFixed(1)}%`;
      item.appendChild(colorEl);
      item.appendChild(label);
      legendEl.appendChild(item);
    }
  }
}
// Group metrics by their `group` field, preserving first-seen order.
function groupedMetrics() {
  const groups = [];
  const byName = new Map();
  for (const metric of METRICS) {
    const target = document.getElementById(metric.id);
    if (!target) continue;
    if (!byName.has(metric.group)) {
      byName.set(metric.group, []);
      groups.push(metric.group);
    }
    byName.get(metric.group).push(metric);
  }
  return groups.map(name => ({ name, metrics: byName.get(name) }));
}

function expandGroup(groupEl) {
  // Single-open accordion: collapse siblings, expand this one.
  const all = document.querySelectorAll('#menu-list .menu-group');
  all.forEach(g => {
    const items = g.querySelector('.menu-group-items');
    const toggle = g.querySelector('.menu-group-toggle');
    const chev = g.querySelector('.menu-group-chevron');
    const open = g === groupEl;
    g.classList.toggle('collapsed', !open);
    if (items) items.style.display = open ? '' : 'none';
    if (toggle) toggle.setAttribute('aria-expanded', String(open));
    if (chev) chev.textContent = open ? '▾' : '▸';
  });
}

function buildSideMenu() {
  const menuList = document.getElementById('menu-list');
  if (!menuList) return;
  menuList.innerHTML = '';

  for (const group of groupedMetrics()) {
    const groupLi = document.createElement('li');
    groupLi.className = 'menu-group';

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'menu-group-toggle';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.textContent = group.name;
    const chevron = document.createElement('span');
    chevron.className = 'menu-group-chevron';
    chevron.textContent = '▸';
    toggle.appendChild(chevron);
    toggle.addEventListener('click', () => {
      const collapsed = groupLi.classList.contains('collapsed');
      expandGroup(collapsed ? groupLi : null);
      // clicking an already-open group collapses it
      if (!collapsed) {
        groupLi.classList.add('collapsed');
        const items = groupLi.querySelector('.menu-group-items');
        if (items) items.style.display = 'none';
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
    groupLi.appendChild(toggle);

    const items = document.createElement('ul');
    items.className = 'menu-group-items';
    items.style.display = 'none';
    for (const metric of group.metrics) {
      const target = document.getElementById(metric.id);
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = `#${metric.id}`;
      a.textContent = metric.title;
      a.addEventListener('click', (e) => {
        e.preventDefault();
        pinnedLink = a;
        setActiveMenuLink(a);
        history.replaceState(null, '', `#${metric.id}`);
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      li.appendChild(a);
      items.appendChild(li);
    }
    groupLi.appendChild(items);
    menuList.appendChild(groupLi);
  }

  // Unpin when the user scrolls themselves (wheel/touch/keys/scrollbar)
  const unpin = () => { pinnedLink = null; };
  window.addEventListener('wheel', unpin, { passive: true });
  window.addEventListener('touchmove', unpin, { passive: true });
  window.addEventListener('keydown', unpin);

  // Scrollspy: highlight the menu item of the chart at the top of the viewport
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      const links = menuList.querySelectorAll('a');
      if (pinnedLink && menuList.contains(pinnedLink)) {
        setActiveMenuLink(pinnedLink);
        return;
      }
      let activeLink = null;
      for (const link of links) {
        const el = document.getElementById(link.getAttribute('href').slice(1));
        if (el && el.getBoundingClientRect().top <= 150) activeLink = link;
      }
      if (!activeLink && links.length) activeLink = links[0];
      if (activeLink) {
        // keep the group containing the active item expanded
        const g = activeLink.closest('.menu-group');
        if (g && g.classList.contains('collapsed')) expandGroup(g);
        setActiveMenuLink(activeLink);
      }
    });
  }, { passive: true });

  // Initial highlight on load
  requestAnimationFrame(() => {
    const first = menuList.querySelector('a');
    if (first) {
      const g = first.closest('.menu-group');
      if (g) expandGroup(g);
      setActiveMenuLink(first);
    }
  });
}

let pinnedLink = null;

function setActiveMenuLink(active) {
  const menuList = document.getElementById('menu-list');
  if (!menuList) return;
  menuList.querySelectorAll('a').forEach(a => a.classList.toggle('active', a === active));
}

// --- Info dialogs -------------------------------------------------------
// One shared <dialog> element, populated per metric on open.
let infoDialog = null;

function showInfoDialog(title, description) {
  if (!infoDialog) {
    infoDialog = document.createElement('dialog');
    infoDialog.id = 'info-dialog';
    infoDialog.innerHTML = `
      <div class="dialog-header">
        <h3 class="dialog-title"></h3>
        <button class="dialog-close" type="button" aria-label="Close dialog">&times;</button>
      </div>
      <div class="dialog-body"></div>`;
    document.body.appendChild(infoDialog);
    infoDialog.querySelector('.dialog-close').addEventListener('click', () => infoDialog.close());
    // Click on the backdrop (the dialog element itself, outside its box) closes it
    infoDialog.addEventListener('click', (e) => {
      if (e.target === infoDialog) infoDialog.close();
    });
  }
  infoDialog.querySelector('.dialog-title').textContent = title;
  infoDialog.querySelector('.dialog-body').textContent =
    `${description} Data: 2,500 random domains from the Tranco Top 1M list, scanned weekly.`;
  infoDialog.showModal();
}

// --- Chart settings (data range slider) ---------------------------------
// One shared settings dialog; the slider controls how many of the most
// recent snapshots the line graph of the selected chart displays.
let settingsDialog = null;
let activeRangeEntry = null;

// Return `normalized` limited to snapshot indices [start, end] (inclusive).
function sliceSeries(normalized, start, end) {
  const n = normalized.series[0].length;
  const from = Math.max(0, Math.min(start, n - 1));
  const to = Math.max(from, Math.min(end, n - 1));
  return {
    keys: normalized.keys,
    series: normalized.series.map(row => row.slice(from, to + 1)),
  };
}

// (Re)draw the line chart of one chartData entry with its current range.
function renderLineChart(entry) {
  const { canvas, legendContainer, normalized, metric } = entry;
  if (!canvas || canvas.clientWidth <= 0 || canvas.clientHeight <= 0) return;
  if (entry.u) {
    entry.u.destroy();
    entry.u = null;
  }
  if (legendContainer) legendContainer.innerHTML = '';
  const view = sliceSeries(normalized, entry.rangeStart, entry.rangeEnd);
  if (metric.type === 'grouped') {
    entry.u = createGroupedChart(canvas, view, metric.title, {}, legendContainer);
  } else {
    entry.u = createStackedChart(canvas, view, metric.title, {});
  }
}

// Read the stored [start, end] range for a metric, clamped to the data;
// defaults to the last MAX_POINTS snapshots.
function loadStoredRange(metricId, total) {
  let stored = null;
  try {
    stored = JSON.parse(localStorage.getItem(`chartRange:${metricId}`));
  } catch { /* ignore */ }
  if (Array.isArray(stored) && stored.length === 2 &&
      Number.isFinite(stored[0]) && Number.isFinite(stored[1])) {
    const start = Math.max(0, Math.min(stored[0], total - 1));
    const end = Math.max(start, Math.min(stored[1], total - 1));
    return [start, end];
  }
  return [Math.max(0, total - MAX_POINTS), total - 1];
}

function storeRange(metricId, range) {
  try {
    localStorage.setItem(`chartRange:${metricId}`, JSON.stringify(range));
  } catch { /* ignore */ }
}

function updateRangeLabels(entry) {
  const times = entry.normalized.series[0];
  const fmt = (i) => new Date(times[i]).toLocaleDateString();
  settingsDialog.querySelector('#range-start-value').textContent = fmt(entry.rangeStart);
  settingsDialog.querySelector('#range-end-value').textContent = fmt(entry.rangeEnd);
  settingsDialog.querySelector('#range-length').textContent =
    `${entry.rangeEnd - entry.rangeStart + 1} scan(s)`;
  // Paint the blue fill exactly between the two thumbs.
  // Thumb centre for fraction f: f*(W - T) + T/2  ==  W*f + T*(0.5 - f)
  const total = times.length;
  const sFrac = total > 1 ? entry.rangeStart / (total - 1) : 0;
  const eFrac = total > 1 ? entry.rangeEnd / (total - 1) : 0;
  const T = 20; // thumb width incl. border, must match CSS
  const fill = settingsDialog.querySelector('#range-fill');
  fill.style.left =
    `calc(${(sFrac * 100).toFixed(2)}% + ${((0.5 - sFrac) * T).toFixed(2)}px)`;
  fill.style.width =
    `calc(${((eFrac - sFrac) * 100).toFixed(2)}% + ${((sFrac - eFrac) * T).toFixed(2)}px)`;
}

// Sync entry range from the two sliders, clamping them so start <= end.
function applyRangeFromSliders(changed) {
  if (!activeRangeEntry) return;
  const entry = activeRangeEntry;
  const startSlider = settingsDialog.querySelector('#range-start');
  const endSlider = settingsDialog.querySelector('#range-end');
  let s = parseInt(startSlider.value, 10);
  let e = parseInt(endSlider.value, 10);
  if (s > e) {
    if (changed === 'start') { e = s; endSlider.value = e; }
    else { s = e; startSlider.value = s; }
  }
  entry.rangeStart = s;
  entry.rangeEnd = e;
  storeRange(entry.metric.id, [s, e]);
  updateRangeLabels(entry);
  renderLineChart(entry);
}

function showRangeDialog(entry) {
  if (!settingsDialog) {
    settingsDialog = document.createElement('dialog');
    settingsDialog.id = 'settings-dialog';
    settingsDialog.innerHTML = `
      <div class="dialog-header">
        <h3 class="dialog-title">Chart settings</h3>
        <button class="dialog-close" type="button" aria-label="Close dialog">&times;</button>
      </div>
      <div class="dialog-body">
        <div class="range-row">
          <label>From: <strong id="range-start-value"></strong> — To: <strong id="range-end-value"></strong></label>
          <div class="range-track">
            <div class="range-fill" id="range-fill"></div>
            <input type="range" id="range-start" class="range-slider dual" aria-label="Range start">
            <input type="range" id="range-end" class="range-slider dual" aria-label="Range end">
          </div>
        </div>
        <div class="range-summary">Displaying <span id="range-length"></span></div>
      </div>`;
    document.body.appendChild(settingsDialog);
    settingsDialog.querySelector('.dialog-close').addEventListener('click', () => settingsDialog.close());
    settingsDialog.addEventListener('click', (e) => {
      if (e.target === settingsDialog) settingsDialog.close();
    });
    settingsDialog.querySelector('#range-start').addEventListener('input', () => applyRangeFromSliders('start'));
    settingsDialog.querySelector('#range-end').addEventListener('input', () => applyRangeFromSliders('end'));
    // Keep the thumb you grabbed on top when they overlap
    const startSlider = settingsDialog.querySelector('#range-start');
    const endSlider = settingsDialog.querySelector('#range-end');
    startSlider.addEventListener('pointerdown', () => { startSlider.style.zIndex = 5; endSlider.style.zIndex = 3; });
    endSlider.addEventListener('pointerdown', () => { endSlider.style.zIndex = 5; startSlider.style.zIndex = 3; });
  }

  activeRangeEntry = entry;
  const total = entry.normalized.series[0].length;
  const startSlider = settingsDialog.querySelector('#range-start');
  const endSlider = settingsDialog.querySelector('#range-end');
  startSlider.max = total - 1;
  endSlider.max = total - 1;
  startSlider.value = entry.rangeStart;
  endSlider.value = entry.rangeEnd;
  updateRangeLabels(entry);
  settingsDialog.showModal();
}

async function loadAndRender() {
  const chartsContainer = document.getElementById('charts');
 
  let latestTimestamp = '';
  let latestSampleSize = 0;
  const chartData = [];
 
  // First pass: fetch all data and create chart cards
  for (const metric of METRICS) {
    try {
      const history = await fetchJSON(metric.id);
 
      if (!history || history.length === 0) {
        console.warn(`No data for ${metric.id}`);
        const card = document.createElement('div');
        card.className = 'chart-card';
        card.id = metric.id;
        card.innerHTML = `<div class="card-header">
            <h2>${metric.title}</h2>
            <div class="card-actions">
              <button class="info-btn" type="button" aria-label="What this graph shows">i</button>
              <a class="wiki-btn" href="${metric.wiki}" target="_blank" rel="noopener noreferrer" aria-label="Wikipedia article about this topic" title="Wikipedia article">&#8599;</a>
            </div>
          </div><p class="error" style="color:#495057">No scan data yet.</p>`;
        chartsContainer.appendChild(card);
        card.querySelector('.info-btn').addEventListener('click', () =>
          showInfoDialog(metric.title, metric.description || ''));
        continue;
      }
 
      // Track latest timestamp across all metrics
      const lastSnap = history[history.length - 1];
      if (new Date(lastSnap.timestamp) > new Date(latestTimestamp)) {
        latestTimestamp = lastSnap.timestamp;
        latestSampleSize = lastSnap.sample_size;
      }
 
      // Normalize full history (display range is applied at render time)
      let normalized = normalizeHistory(history);
      if (!normalized) continue;
 
      // Apply limit for top-N metrics
      if (metric.limit && normalized.keys.length > metric.limit) {
        const lastIdx = normalized.series[0].length - 1;
        const keyValues = normalized.keys.map((key, i) => ({
          key,
          value: normalized.series[i + 1][lastIdx],
          color: COLORS[i % COLORS.length],
        }));
        keyValues.sort((a, b) => b.value - a.value);
        const topKeys = keyValues.slice(0, metric.limit).map(k => k.key);
        const topColors = Object.fromEntries(keyValues.slice(0, metric.limit).map(k => [k.key, k.color]));
 
        const indices = normalized.keys.map((k, i) => topKeys.includes(k) ? i : -1).filter(i => i >= 0);
        normalized.keys = topKeys;
        normalized.series = [normalized.series[0], ...indices.map(i => normalized.series[i + 1])];
        computePercentages(normalized.series);
      } else {
        computePercentages(normalized.series);
      }
 
      // Create chart container
      const card = document.createElement('div');
      card.className = 'chart-card';
      card.id = metric.id;
      if (metric.id === 'extensions') {
        card.innerHTML = `<div class="card-header">
            <h2>${metric.title}</h2>
            <div class="card-actions">
              <button class="gear-btn" type="button" aria-label="Chart settings" title="Chart settings">&#9881;</button>
              <button class="info-btn" type="button" aria-label="What this graph shows">i</button>
              <a class="wiki-btn" href="${metric.wiki}" target="_blank" rel="noopener noreferrer" aria-label="Wikipedia article about this topic" title="Wikipedia article">&#8599;</a>
            </div>
          </div>
          <div class="chart-row">
            <div class="chart-canvas"></div>
            <div class="chart-legend"></div>
          </div>`;
      } else {
        card.innerHTML = `<div class="card-header">
            <h2>${metric.title}</h2>
            <div class="card-actions">
              <button class="gear-btn" type="button" aria-label="Chart settings" title="Chart settings">&#9881;</button>
              <button class="info-btn" type="button" aria-label="What this graph shows">i</button>
              <a class="wiki-btn" href="${metric.wiki}" target="_blank" rel="noopener noreferrer" aria-label="Wikipedia article about this topic" title="Wikipedia article">&#8599;</a>
            </div>
          </div>
          <div class="chart-row">
            <div class="chart-canvas"></div>
            <div class="pie-container">
              <canvas class="pie-canvas"></canvas>
              <div class="pie-legend"></div>
            </div>
          </div>`;
      }
      chartsContainer.appendChild(card);
      card.querySelector('.info-btn').addEventListener('click', () =>
        showInfoDialog(metric.title, metric.description || ''));
  
      const canvas = card.querySelector('.chart-canvas');
      const legendContainer = metric.id === 'extensions' ? card.querySelector('.chart-legend') : null;
      const pieCanvas = metric.id === 'extensions' ? null : card.querySelector('.pie-canvas');
      const pieLegend = metric.id === 'extensions' ? null : card.querySelector('.pie-legend');
  
      // Store for second pass; default range is the last MAX_POINTS snapshots
      // unless the user chose a specific range before
      const [rangeStart, rangeEnd] = loadStoredRange(metric.id, normalized.series[0].length);
      const entry = {
        canvas, legendContainer, pieCanvas, pieLegend, normalized, metric,
        rangeStart, rangeEnd,
        u: null,
      };
      card.querySelector('.gear-btn').addEventListener('click', () => showRangeDialog(entry));
      chartData.push(entry);
 
    } catch (err) {
      console.error(`Failed to render ${metric.id}:`, err);
      const card = document.createElement('div');
      card.className = 'chart-card error';
      card.id = metric.id;
      card.innerHTML = `<div class="card-header">
          <h2>${metric.title}</h2>
          <div class="card-actions">
            <button class="info-btn" type="button" aria-label="What this graph shows">i</button>
            <a class="wiki-btn" href="${metric.wiki}" target="_blank" rel="noopener noreferrer" aria-label="Wikipedia article about this topic" title="Wikipedia article">&#8599;</a>
          </div>
        </div><p class="error">Failed to load: ${err.message}</p>`;
      chartsContainer.appendChild(card);
      card.querySelector('.info-btn').addEventListener('click', () =>
        showInfoDialog(metric.title, metric.description || ''));
    }
  }

  // Build the left navigation menu now that cards exist
  buildSideMenu();

  // Second pass: create all charts after layout settles
  requestAnimationFrame(() => {
    for (const entry of chartData) {
      renderLineChart(entry);
      if (entry.pieCanvas) {
        drawPieChart(entry.pieCanvas, entry.pieLegend, entry.normalized.keys, entry.normalized.series, {});
      }
    }
  });
}
 
// Handle window resize
let resizeTimeout;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimeout);
  resizeTimeout = setTimeout(() => {
    location.reload(); // Simple approach: reload to recalculate chart sizes
  }, 250);
});
 
// Start
loadAndRender().catch(console.error);