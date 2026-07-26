/* ==========================================================================
   Sentinel SOC console — front-end controller
   Wires the dashboard to the real API: /metrics, /dashboard/overview,
   /dashboard/attack-replay, /investigate/*, /copilot, and the live
   /ws/alerts WebSocket. No hardcoded telemetry.
   ========================================================================== */
/* =====================================================================
   Session / auth
   ---------------------------------------------------------------------
   Login now lives on its own page (/login). By the time this dashboard
   loads, the analyst is already authenticated and POST /auth/admin/login
   has started the backend replay server-side. Here we only (a) guard the
   page, (b) show who's signed in, and (c) handle sign out.
   ===================================================================== */
const AUTH_KEY = "sentinel_auth";
const USER_KEY = "sentinel_user";

// Belt-and-suspenders guard (index.html also checks before render).
if (!sessionStorage.getItem(AUTH_KEY)) {
  location.replace("/login");
}

function initSession() {
  const who = document.getElementById("sessionUser");
  if (who) who.textContent = sessionStorage.getItem(USER_KEY) || "analyst";
  const out = document.getElementById("signoutBtn");
  if (out)
    out.addEventListener("click", () => {
      sessionStorage.removeItem(AUTH_KEY);
      sessionStorage.removeItem(USER_KEY);
      location.replace("/login");
    });
}

const LABEL_COLORS = {
  brute_force: "#A3271E",
  credential_misuse: "#8A5A00",
  lateral_movement: "#35318C",
  impossible_travel: "#0E6B4F",
  device_spoofing: "#9D174D",
  unknown: "#948C7A",
};

// One-click response action per attack type (label mirrors the backend
// REMEDIATION_MAP in routes/remediation.py; the backend is authoritative for
// the action + target that actually gets stored).
const REMEDIATION_LABELS = {
  brute_force: "Block source IP",
  credential_misuse: "Block device",
  lateral_movement: "Isolate host",
  impossible_travel: "Lock account",
  device_spoofing: "Block device",
};
const remediationLabel = (lbl) => REMEDIATION_LABELS[lbl] || "Contain threat";

// POST the action, then reflect the result on the button itself.
async function runRemediation(btn) {
  if (!btn || btn.disabled) return;
  const alertId = btn.dataset.alertId;
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Applying…";
  try {
    const res = await getJson("/remediation", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: alertId }),
    });
    btn.classList.add("done");
    btn.textContent = "✓ " + (res.done || "Done");
    btn.title = res.message || "";
  } catch (e) {
    btn.disabled = false;
    btn.textContent = original;
    btn.classList.add("err");
    setTimeout(() => btn.classList.remove("err"), 1200);
  }
}

// Reference cities (mirror the log generator) so the map has recognizable anchors.
const CITIES = [
  ["Bengaluru", 12.9716, 77.5946],
  ["Mumbai", 19.076, 72.8777],
  ["Delhi", 28.7041, 77.1025],
  ["Singapore", 1.3521, 103.8198],
  ["London", 51.5074, -0.1278],
  ["New York", 40.7128, -74.006],
  ["Frankfurt", 50.1109, 8.6821],
  ["Sydney", -33.8688, 151.2093],
  ["Toronto", 43.6532, -79.3832],
  ["São Paulo", -23.5505, -46.6333],
  ["Moscow", 55.7558, 37.6173],
  ["Lagos", 6.5244, 3.3792],
  ["Johannesburg", -26.2041, 28.0473],
  ["Dubai", 25.2048, 55.2708],
  ["Tehran", 35.6892, 51.389],
  ["Beijing", 39.9042, 116.4074],
  ["Jakarta", -6.2088, 106.8456],
  ["Bucharest", 44.4268, 26.1025],
  ["Manila", 14.5995, 120.9842],
  ["Buenos Aires", -34.6037, -58.3816],
  ["Karachi", 24.8607, 67.0011],
  ["Kyiv", 50.4501, 30.5234],
];

const state = {
  hq: { lat: 12.9716, lon: 77.5946 },
  arcs: [],
  seenAlerts: new Set(),
};

async function getJson(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}
const fmtPct = (v) => `${((v || 0) * 100).toFixed(1)}%`;
const titleize = (s) =>
  (s || "unknown").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

/* --------------------------------------------------------------------------
   Tab navigation
   -------------------------------------------------------------------------- */
document.getElementById("nav").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-view]");
  if (!btn) return;
  document
    .querySelectorAll("#nav button")
    .forEach((b) => b.classList.toggle("active", b === btn));
  const view = btn.dataset.view;
  document
    .querySelectorAll(".view")
    .forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
  if (view === "investigation") loadUserPills();
  if (view === "copilot") loadCopilotList();
});

/* --------------------------------------------------------------------------
   Overview: metrics + eval bars + drift
   -------------------------------------------------------------------------- */
async function loadMetrics() {
  try {
    const m = await getJson("/metrics");
    if (!m.ready) return;
    document.getElementById("mAlerts").textContent = m.alerts_raised ?? 0;
    document.getElementById("mAlertRate").textContent =
      `alert rate ${fmtPct(m.alert_rate)}`;
    document.getElementById("mEvents").textContent = (
      m.events_processed ?? 0
    ).toLocaleString();
    document.getElementById("mF1").textContent = (m.macro_f1 ?? 0).toFixed(3);
    document.getElementById("mClasses").textContent =
      Object.keys(m.per_class || {}).length || 5;
    renderRecall(m.per_class || {});
  } catch (e) {
    /* startup still training; retried by caller */
  }
}
async function renderTrend() {
  const { points } = await getJson("/dashboard/trend?limit=40");
  new Chart(document.getElementById("riskTrend"), {
    type: "line",
    data: {
      labels: points.map((p) => p.t),
      datasets: [
        {
          label: "Risk",
          data: points.map((p) => p.risk),
          borderColor: "#fb7185",
          tension: 0.3,
        },
        {
          label: "5-pt avg",
          data: points.map((p) => p.risk_avg),
          borderColor: "#22d3ee",
          borderDash: [5, 5],
          tension: 0.3,
        },
      ],
    },
    options: { scales: { y: { min: 0, max: 1 } } },
  });
}
function renderRecall(perClass) {
  const box = document.getElementById("recallBars");
  const rows = Object.entries(perClass);
  if (!rows.length) {
    box.innerHTML = '<div class="empty">Evaluation pending…</div>';
    return;
  }
  box.innerHTML = rows
    .map(([cls, m]) => {
      const pct = Math.round((m.recall || 0) * 100);
      const color = LABEL_COLORS[cls] || "#35318C";
      return `<div class="bar-row">
        <span class="name">${titleize(cls)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:linear-gradient(90deg,${color},#35318C)"></div></div>
        <span class="val">${pct}%</span>
      </div>`;
    })
    .join("");
}

async function loadDrift() {
  try {
    const d = await getJson("/feedback/drift-status");
    const box = document.getElementById("driftPanel");
    document.getElementById("driftTag").textContent = d.should_retrain
      ? "retrain recommended"
      : "stable";
    if (d.rolling_fp_rate === null || d.rolling_fp_rate === undefined) {
      box.innerHTML = `<div class="empty">${d.reason || "Awaiting analyst feedback."}</div>`;
      return;
    }
    const rows = [
      ["Rolling false-positive rate", d.rolling_fp_rate],
      ["Older-window FP rate", d.old_half_fp_rate],
      ["Recent-window FP rate", d.new_half_fp_rate],
    ];
    box.innerHTML =
      rows
        .map(([name, v]) => {
          const pct = Math.round((v || 0) * 100);
          return `<div class="bar-row"><span class="name">${name}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
            <span class="val">${pct}%</span></div>`;
        })
        .join("") +
      `<div class="${d.drift_detected ? "hunt" : "empty"}" style="margin-top:.6rem">${d.reason}</div>`;
  } catch (e) {
    /* endpoint present only after startup */
  }
}

/* --------------------------------------------------------------------------
   Live alert feed (WebSocket)
   -------------------------------------------------------------------------- */
function connectWs() {
  const dot = document.getElementById("wsDot");
  const label = document.getElementById("wsLabel");
  const proto = location.protocol === "https:" ? "wss" : "ws";
  let ws;
  try {
    ws = new WebSocket(`${proto}://${location.host}/ws/alerts`);
  } catch (e) {
    dot.className = "dot offline";
    label.textContent = "offline";
    return;
  }
  ws.onopen = () => {
    dot.className = "dot live";
    label.textContent = "live stream";
  };
  ws.onclose = () => {
    dot.className = "dot offline";
    label.textContent = "reconnecting…";
    setTimeout(connectWs, 2500);
  };
  ws.onerror = () => {
    dot.className = "dot offline";
    label.textContent = "offline";
  };
  ws.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (msg.type === "alert") handleAlert(msg);
  };
}

function handleAlert(a) {
  if (a.alert_id && state.seenAlerts.has(a.alert_id)) return;
  if (a.alert_id) state.seenAlerts.add(a.alert_id);
  pushFeed(a);
  spawnArc(a);
  // keep counters fresh without hammering the endpoint
  const el = document.getElementById("mAlerts");
  if (el) el.textContent = (parseInt(el.textContent, 10) || 0) + 1;
}

function pushFeed(a) {
  const feed = document.getElementById("feed");
  const first = feed.querySelector(".heartbeat");
  if (first) first.remove();
  const li = document.createElement("li");
  const risk = Math.round((a.risk_score || 0) * 100);
  const riskClass = risk >= 70 ? "" : "low";
  const color = LABEL_COLORS[a.predicted_label] || "#A3271E";
  li.style.borderLeftColor = color;
  li.innerHTML = `
    <div class="row1">
      <span class="who">${a.user_id} · ${titleize(a.predicted_label)}</span>
      <span class="risk ${riskClass}">${risk}/100</span>
    </div>
    <div class="meta">${a.geo_country || "??"} · ${a.resource || ""} · ${a.action || ""} ${a.true_label && a.true_label !== "none" ? "· truth:" + a.true_label : ""}</div>
    <div class="why">${a.explanation || "No explanation available."}</div>
    <div class="cta">
      <button class="remediate-btn" data-alert-id="${a.alert_id}">${remediationLabel(a.predicted_label)}</button>
      <button class="chip-btn" data-alert='${JSON.stringify({ alert_id: a.alert_id }).replace(/'/g, "&#39;")}'>Ask Copilot →</button>
    </div>`;
  feed.prepend(li);
  while (feed.children.length > 30) feed.lastChild.remove();
}

// delegate remediation buttons from the feed
document.getElementById("feed").addEventListener("click", (e) => {
  const btn = e.target.closest(".remediate-btn");
  if (btn) runRemediation(btn);
});

// delegate copilot buttons from the feed
document.getElementById("feed").addEventListener("click", (e) => {
  const btn = e.target.closest(".chip-btn");
  if (!btn) return;
  const { alert_id } = JSON.parse(btn.dataset.alert);
  document.querySelector('#nav button[data-view="copilot"]').click();
  generateBrief({ alert_id });
});

/* --------------------------------------------------------------------------
   Threat map — canvas equirectangular projection + animated arcs
   -------------------------------------------------------------------------- */
const canvas = document.getElementById("threatMap");
const ctx = canvas.getContext("2d");
let W = 0,
  H = 0,
  dpr = 1;

function sizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  W = rect.width;
  H = rect.height;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
const project = (lat, lon) => ({
  x: ((lon + 180) / 360) * W,
  y: ((90 - lat) / 180) * H,
});

function spawnArc(a) {
  if (a.geo_lat == null || a.geo_lon == null) return;
  state.arcs.push({
    from: { lat: a.geo_lat, lon: a.geo_lon },
    to: state.hq,
    color: LABEL_COLORS[a.predicted_label || a.label] || "#A3271E",
    t: 0,
    speed: 0.006 + Math.random() * 0.004,
    life: 1,
    label: a.predicted_label || a.label,
  });
  if (state.arcs.length > 60) state.arcs.splice(0, state.arcs.length - 60);
}

function drawGraticule() {
  ctx.strokeStyle = "rgba(28,26,20,0.07)";
  ctx.lineWidth = 1;
  for (let lon = -150; lon <= 150; lon += 30) {
    const a = project(-85, lon),
      b = project(85, lon);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const a = project(lat, -180),
      b = project(lat, 180);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  }
}

function drawCities() {
  ctx.font = "10px 'JetBrains Mono', monospace";
  for (const [name, lat, lon] of CITIES) {
    const p = project(lat, lon);
    ctx.beginPath();
    ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(28,26,20,0.4)";
    ctx.fill();
    ctx.fillStyle = "rgba(28,26,20,0.38)";
    ctx.fillText(name, p.x + 5, p.y + 3);
  }
}

let pulse = 0;
function drawHQ() {
  const p = project(state.hq.lat, state.hq.lon);
  pulse = (pulse + 0.02) % 1;
  const r = 6 + pulse * 16;
  ctx.beginPath();
  ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
  ctx.strokeStyle = `rgba(14,107,79,${0.55 * (1 - pulse)})`;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
  ctx.fillStyle = "#0E6B4F";
  ctx.fill();
  ctx.fillStyle = "#0E6B4F";
  ctx.font = "600 11px 'JetBrains Mono', monospace";
  ctx.fillText("SOC HQ", p.x + 8, p.y - 6);
}

function drawArcs() {
  for (const arc of state.arcs) {
    const s = project(arc.from.lat, arc.from.lon);
    const d = project(arc.to.lat, arc.to.lon);
    const mx = (s.x + d.x) / 2,
      my = (s.y + d.y) / 2;
    const dx = d.x - s.x,
      dy = d.y - s.y;
    const len = Math.hypot(dx, dy) || 1;
    // lift control point perpendicular for a curved arc
    const cx = mx - (dy / len) * len * 0.22;
    const cy = my + (dx / len) * len * 0.22;

    // faint full path
    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.quadraticCurveTo(cx, cy, d.x, d.y);
    ctx.strokeStyle = hexA(arc.color, 0.12 * arc.life);
    ctx.lineWidth = 1;
    ctx.stroke();

    // comet: draw the leading segment of the curve up to t
    const head = quad(s, { x: cx, y: cy }, d, Math.min(arc.t, 1));
    const tailT = Math.max(0, arc.t - 0.18);
    const tail = quad(s, { x: cx, y: cy }, d, tailT);
    ctx.beginPath();
    ctx.moveTo(tail.x, tail.y);
    const midT = (tailT + arc.t) / 2;
    const mid = quad(s, { x: cx, y: cy }, d, midT);
    ctx.quadraticCurveTo(mid.x, mid.y, head.x, head.y);
    ctx.strokeStyle = hexA(arc.color, 0.9 * arc.life);
    ctx.lineWidth = 2.2;
    ctx.stroke();

    // glowing head
    ctx.beginPath();
    ctx.arc(head.x, head.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = hexA(arc.color, arc.life);
    ctx.fill();

    // source ring
    ctx.beginPath();
    ctx.arc(s.x, s.y, 3, 0, Math.PI * 2);
    ctx.strokeStyle = hexA(arc.color, 0.7 * arc.life);
    ctx.lineWidth = 1.5;
    ctx.stroke();

    arc.t += arc.speed;
    if (arc.t >= 1) {
      // impact ripple at HQ then fade
      const imp = 1 - Math.min((arc.t - 1) * 3, 1);
      if (imp > 0) {
        ctx.beginPath();
        ctx.arc(d.x, d.y, 6 + (arc.t - 1) * 40, 0, Math.PI * 2);
        ctx.strokeStyle = hexA(arc.color, 0.4 * imp);
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      arc.life -= 0.02;
    }
  }
  state.arcs = state.arcs.filter((a) => a.life > 0);
}

function quad(p0, p1, p2, t) {
  const u = 1 - t;
  return {
    x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
    y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
  };
}
function hexA(hex, a) {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16),
    g = parseInt(h.slice(2, 4), 16),
    b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${Math.max(0, Math.min(1, a))})`;
}

function frame() {
  ctx.clearRect(0, 0, W, H);
  drawGraticule();
  drawCities();
  drawArcs();
  drawHQ();
  requestAnimationFrame(frame);
}

function initLegend() {
  const legend = document.getElementById("mapLegend");
  legend.innerHTML = Object.entries(LABEL_COLORS)
    .filter(([k]) => k !== "unknown")
    .map(
      ([k, c]) =>
        `<span><i class="swatch" style="background:${c}"></i>${titleize(k)}</span>`,
    )
    .join("");
}

async function seedReplay(attempt = 0) {
  try {
    const data = await getJson("/dashboard/attack-replay?limit=30");
    if (data.hq) state.hq = data.hq;
    if ((!data.arcs || !data.arcs.length) && attempt < 6) {
      // No alerts stored yet (page loaded right after server startup,
      // before the replay loop produced anything) -- retry for a bit
      // instead of silently giving up forever.
      setTimeout(() => seedReplay(attempt + 1), 3000);
      return;
    }
    // stagger historical arcs so they play back as a sequence
    data.arcs.forEach((arc, i) => {
      setTimeout(() => {
        spawnArc({
          geo_lat: arc.source.lat,
          geo_lon: arc.source.lon,
          predicted_label: arc.label,
          risk_score: arc.risk_score,
        });
      }, i * 350);
    });
  } catch (e) {
    if (attempt < 6) setTimeout(() => seedReplay(attempt + 1), 3000);
  }
}

/* --------------------------------------------------------------------------
   Investigation
   -------------------------------------------------------------------------- */
async function loadUserPills() {
  try {
    const data = await getJson("/investigate/users");
    const box = document.getElementById("userPills");
    if (!data.ready || !data.users.length) {
      box.innerHTML = "";
      return;
    }
    box.innerHTML = data.users
      .slice(0, 12)
      .map(
        (u) =>
          `<button class="user-pill" data-uid="${u.user_id}">${u.user_id} · ${u.events_observed}ev${u.failed_auth_count ? " · " + u.failed_auth_count + "✗" : ""}</button>`,
      )
      .join("");
  } catch (e) {
    /* not ready */
  }
}
document.getElementById("userPills").addEventListener("click", (e) => {
  const b = e.target.closest(".user-pill");
  if (b) {
    document.getElementById("userSearch").value = b.dataset.uid;
    investigate(b.dataset.uid);
  }
});
document
  .getElementById("userSearchBtn")
  .addEventListener("click", () =>
    investigate(document.getElementById("userSearch").value.trim()),
  );
document.getElementById("userSearch").addEventListener("keydown", (e) => {
  if (e.key === "Enter") investigate(e.target.value.trim());
});

async function investigate(uid) {
  if (!uid) return;
  const body = document.getElementById("investBody");
  body.innerHTML = '<div class="spinner"></div>';
  let data;
  try {
    data = await getJson(`/investigate/${encodeURIComponent(uid)}`);
  } catch (e) {
    body.innerHTML = `<div class="empty">No data found for <b>${uid}</b>. Try one of the suggested users above.</div>`;
    return;
  }
  const p = data.profile;
  const profileHtml = p
    ? `<div class="profile-grid">
        <div class="fact"><div class="k">Events observed</div><div class="v">${p.events_observed}</div></div>
        <div class="fact"><div class="k">Known devices</div><div class="v small">${p.known_devices.join(", ") || "—"}</div></div>
        <div class="fact"><div class="k">Known countries</div><div class="v small">${p.known_countries.join(", ") || "—"}</div></div>
        <div class="fact"><div class="k">Typical hours</div><div class="v small">${p.typical_hours.join(", ")}</div></div>
        <div class="fact"><div class="k">Home (lat, lon)</div><div class="v small">${p.home_location.lat}, ${p.home_location.lon}</div></div>
        <div class="fact"><div class="k">Avg session</div><div class="v">${p.avg_session_duration_s}s</div></div>
        <div class="fact"><div class="k">Failed auths</div><div class="v">${p.failed_auth_count}</div></div>
        <div class="fact"><div class="k">Top resources</div><div class="v small">${p.top_resources.map((r) => r.resource).join(", ") || "—"}</div></div>
      </div>
      <div class="panel" style="margin-top:.9rem">
        <div class="panel-head"><h3>Baseline confidence</h3><span class="tag">${p.is_cold_start ? "cold start" : "established"}</span></div>
        <div class="gauge"><div class="gauge-track"><div class="gauge-fill" style="width:${Math.round(p.baseline_confidence * 100)}%"></div></div><span class="mono">${(p.baseline_confidence * 100).toFixed(1)}%</span></div>
      </div>`
    : `<div class="empty">This user has alerts on record but no live baseline (they were only in the held-out replay slice, not the training window).</div>`;

  const spark = renderSparkline(data.risk_timeline);
  const alertsHtml = data.alerts.length
    ? data.alerts
        .map((a) => {
          const risk = Math.round((a.risk_score || 0) * 100);
          const color = LABEL_COLORS[a.predicted_label] || "#A3271E";
          return `<li style="border-left-color:${color}">
            <div class="row1"><span class="who">${titleize(a.predicted_label)}</span><span class="risk">${risk}/100</span></div>
            <div class="why">${a.explanation || ""}</div>
            <div class="cta"><button class="chip-btn" data-alert-id="${a.alert_id}">Ask Copilot →</button></div>
          </li>`;
        })
        .join("")
    : '<li class="heartbeat"><div class="why">No alerts on record for this user.</div></li>';

  const eventsHtml = data.recent_events.length
    ? `<table class="evt-table"><thead><tr><th>Time</th><th>Resource</th><th>Action</th><th>Country</th><th>Auth</th></tr></thead><tbody>
        ${data.recent_events
          .slice(0, 12)
          .map(
            (e) =>
              `<tr><td>${(e.timestamp || "").replace("T", " ").slice(5, 16)}</td><td>${e.resource || ""}</td><td>${e.action || ""}</td><td>${e.geo_country || ""}</td><td>${e.auth_result || ""}</td></tr>`,
          )
          .join("")}
      </tbody></table>`
    : '<div class="empty">No stored events for this user.</div>';

  body.innerHTML = `
    <div class="topbar" style="margin-bottom:.8rem"><div><div class="eyebrow">${uid}</div><h2 style="font-size:1.2rem">${data.alert_count} alert${data.alert_count === 1 ? "" : "s"} on record</h2></div></div>
    ${profileHtml}
    <div class="grid two-even" style="margin-top:.9rem">
      <div class="panel"><div class="panel-head"><h3>Risk timeline</h3><span class="tag">${data.risk_timeline.length} points</span></div>${spark}</div>
      <div class="panel"><div class="panel-head"><h3>Recent events</h3><span class="tag">last ${Math.min(12, data.recent_events.length)}</span></div>${eventsHtml}</div>
    </div>
    <div class="panel" style="margin-top:.9rem"><div class="panel-head"><h3>Alert history</h3><span class="tag">${data.alerts.length}</span></div><ul class="feed">${alertsHtml}</ul></div>`;

  body.querySelectorAll(".chip-btn[data-alert-id]").forEach((btn) =>
    btn.addEventListener("click", () => {
      document.querySelector('#nav button[data-view="copilot"]').click();
      generateBrief({ alert_id: btn.dataset.alertId });
    }),
  );
}

function renderSparkline(points) {
  if (!points || !points.length)
    return '<div class="empty">No risk history yet.</div>';
  const w = 100,
    h = 30,
    n = points.length;
  const pts = points
    .map((p, i) => `${(i / Math.max(1, n - 1)) * w},${h - (p.risk || 0) * h}`)
    .join(" ");
  return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <polyline points="${pts}" fill="none" stroke="#35318C" stroke-width="1.2" vector-effect="non-scaling-stroke"/>
    ${points.map((p, i) => `<circle cx="${(i / Math.max(1, n - 1)) * w}" cy="${h - (p.risk || 0) * h}" r="1.4" fill="${LABEL_COLORS[p.label] || "#A3271E"}"/>`).join("")}
  </svg>`;
}

/* --------------------------------------------------------------------------
   Copilot
   -------------------------------------------------------------------------- */
async function loadCopilotMode() {
  try {
    const h = await getJson("/copilot/health");
    const live = h.llm_available
      ? `live · ${h.provider || "llm"}${h.model ? " · " + h.model : ""}`
      : "offline playbook mode";
    document.getElementById("copilotMode").textContent = live;
  } catch (e) {
    /* ignore */
  }
}

async function loadCopilotList() {
  const box = document.getElementById("copilotList");
  try {
    const alerts = await getJson("/alerts?limit=25");
    document.getElementById("copilotCount").textContent = alerts.length;
    if (!alerts.length) {
      box.innerHTML =
        '<div class="empty">No alerts yet. They appear as the stream replays.</div>';
      return;
    }
    box.innerHTML = alerts
      .map((a) => {
        const color = LABEL_COLORS[a.predicted_label] || "#A3271E";
        return `<div class="item" data-alert-id="${a.alert_id}">
          <div class="l1"><span style="color:${color}">${titleize(a.predicted_label)}</span><span class="mono">${Math.round((a.risk_score || 0) * 100)}</span></div>
          <div class="l2">${a.user_id} · ${(a.created_at || "").slice(11, 19)}</div>
        </div>`;
      })
      .join("");
    box.querySelectorAll(".item").forEach((it) =>
      it.addEventListener("click", () => {
        box
          .querySelectorAll(".item")
          .forEach((x) => x.classList.toggle("active", x === it));
        generateBrief({ alert_id: it.dataset.alertId });
      }),
    );
  } catch (e) {
    box.innerHTML = '<div class="empty">Could not load alerts.</div>';
  }
}

async function generateBrief(payload) {
  const box = document.getElementById("briefBox");
  box.innerHTML =
    '<div class="spinner"></div><div class="empty">Generating analyst briefing…</div>';
  let b;
  try {
    b = await getJson("/copilot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    box.innerHTML =
      '<div class="empty">Could not generate a briefing for that alert.</div>';
    return;
  }
  box.innerHTML = `
    <div class="headline">
      <h3>${titleize(b.headline.split("—")[0])}</h3>
      <span class="sev ${b.severity}">${b.severity}</span>
      <span class="source-badge">${b.source === "llm" ? "LLM" : "playbook"}</span>
      <span class="source-badge">risk ${b.risk_score}/100</span>
    </div>
    <div class="mitre">MITRE ATT&CK · ${b.mitre}</div>
    <p class="summary">${b.summary}</p>
    <h4>Recommended response</h4>
    <ol>${b.recommended_actions.map((a) => `<li>${a}</li>`).join("")}</ol>
    <div class="hunt"><b>Threat hunt:</b> ${b.threat_hunt}</div>`;
}

/* --------------------------------------------------------------------------
   Ensure a live stream
   ---------------------------------------------------------------------
   The replay is a one-shot: it streams the held-out slice through the
   pipeline once, then stops. Model training now runs in the background, so
   sign-in can land before it's ready. This waits until the pipeline is
   trained, then starts a fresh replay so the feed + map always populate for
   the dashboard that's currently watching — regardless of timing.
   -------------------------------------------------------------------------- */
async function ensureLiveStream(attempt = 0) {
  let ready = false;
  try {
    const h = await getJson("/health");
    // Wait for the pre-scored records to exist — not just for the models to be
    // trained. On a large dataset the SHAP pre-scoring takes a while, and
    // /replay/start 503s until it's done.
    ready = !!(h && h.replay_ready);
  } catch (e) {
    /* server not up yet */
  }
  if (ready) {
    try {
      await getJson("/replay/start", { method: "POST" });
      // give the backend a beat to clear tables + emit the first alerts
      setTimeout(() => {
        loadMetrics();
        loadDrift();
        seedReplay();
      }, 700);
      return; // success — stop polling
    } catch (e) {
      /* brief race: records vanished/rebuilding — fall through and retry */
    }
  }
  if (attempt < 160) setTimeout(() => ensureLiveStream(attempt + 1), 1500); // wait up to ~4min
}

/* --------------------------------------------------------------------------
   Boot
   -------------------------------------------------------------------------- */
function boot() {
  initSession();
  sizeCanvas();
  initLegend();
  window.addEventListener("resize", sizeCanvas);
  requestAnimationFrame(frame);

  loadMetrics();
  loadDrift();
  loadCopilotMode();
  seedReplay();
  connectWs();
  ensureLiveStream(); // wait for training, then start a fresh live run

  // periodic refresh for counters/eval/drift (WS handles instant alerts)
  setInterval(loadMetrics, 6000);
  setInterval(loadDrift, 8000);
}
boot();
