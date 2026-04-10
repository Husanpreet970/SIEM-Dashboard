import { useEffect, useState, useRef, useCallback } from "react";
import axios from "axios";
import { io } from "socket.io-client";

const API = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";
const socket = io(API);

// ─── Severity config ────────────────────────────────────────────────────────
const SEV = {
  critical: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", glow: "0 0 12px rgba(255,45,85,0.5)", label: "CRIT" },
  high:     { color: "#ff6b35", bg: "rgba(255,107,53,0.12)", glow: "0 0 12px rgba(255,107,53,0.4)", label: "HIGH" },
  medium:   { color: "#f5c542", bg: "rgba(245,197,66,0.10)", glow: "0 0 10px rgba(245,197,66,0.3)", label: "MED" },
  low:      { color: "#4ecdc4", bg: "rgba(78,205,196,0.08)", glow: "none", label: "LOW" },
  info:     { color: "#6b8cba", bg: "rgba(107,140,186,0.06)", glow: "none", label: "INFO" },
};

const ALERT_TYPE_ICONS = {
  brute_force: "🔨", port_scan: "🔍", anomaly: "📊",
  attack: "💥", malware_c2: "☠️", port_access: "🔌", generic: "⚠️",
};
const ALERT_TYPE_COLORS = {
  brute_force: "#ff6b35", port_scan: "#f5c542", anomaly: "#4ecdc4",
  attack: "#ff2d55", malware_c2: "#ff2d55", port_access: "#ff6b35", generic: "#6b8cba",
};

const EVENT_TYPE_ICONS = {
  attack: "💥", malware_c2: "☠️", auth_attempt: "🔐", port_scan: "🔍",
  port_access: "🔌", https_visit: "🔒", http_visit: "🌐", dns_lookup: "🔎",
  icmp: "📶", udp_traffic: "📡", generic: "•",
};

// ─── Mini sparkline ────────────────────────────────────────────────────────
function Sparkline({ data, color = "#00f5c4", width = 120, height = 32 }) {
  if (!data || data.length < 2) return <svg width={width} height={height} />;
  const vals = data.map(d => parseInt(d.count) || 0);
  const max = Math.max(...vals, 1);
  const step = width / (vals.length - 1);
  const pts = vals.map((v, i) => `${i * step},${height - (v / max) * (height - 4) - 2}`).join(" ");
  return (
    <svg width={width} height={height} style={{ overflow: "visible" }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ─── Donut chart ─────────────────────────────────────────────────────────────
function DonutChart({ data, size = 100 }) {
  const colors = { critical: "#ff2d55", high: "#ff6b35", medium: "#f5c542", low: "#4ecdc4", info: "#6b8cba" };
  const total = data.reduce((s, d) => s + parseInt(d.count), 0) || 1;
  let offset = 0;
  const r = 36; const cx = size / 2; const cy = size / 2;
  const circ = 2 * Math.PI * r;
  return (
    <svg width={size} height={size}>
      {data.map((d, i) => {
        const pct = parseInt(d.count) / total;
        const dash = pct * circ;
        const slice = (
          <circle key={d.severity || i} cx={cx} cy={cy} r={r}
            fill="none" stroke={colors[d.severity] || "#444"} strokeWidth="16"
            strokeDasharray={`${dash} ${circ - dash}`}
            strokeDashoffset={-offset * circ}
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        );
        offset += pct;
        return slice;
      })}
      <circle cx={cx} cy={cy} r={28} fill="#0a0f1e" />
      <text x={cx} y={cy + 5} textAnchor="middle" fontSize="13" fontWeight="700" fill="#e0e8ff" fontFamily="monospace">
        {total}
      </text>
    </svg>
  );
}

// ─── Bar chart ────────────────────────────────────────────────────────────────
function BarChart({ data, color = "#00f5c4", labelKey = "ip", valueKey = "count" }) {
  if (!data || data.length === 0) return <div style={{ color: "#3a4a6a", fontSize: 12, padding: 8 }}>No data yet</div>;
  const max = Math.max(...data.map(d => parseInt(d[valueKey])), 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {data.slice(0, 8).map((d, i) => {
        const pct = (parseInt(d[valueKey]) / max) * 100;
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 120, fontSize: 10, color: "#8ba0c4", fontFamily: "monospace", textAlign: "right", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {d[labelKey]}
            </div>
            <div style={{ flex: 1, height: 14, background: "rgba(255,255,255,0.04)", borderRadius: 2, overflow: "hidden" }}>
              <div style={{ width: `${pct}%`, height: "100%", background: `linear-gradient(90deg, ${color}, ${color}88)`, borderRadius: 2, transition: "width 0.5s ease" }} />
            </div>
            <div style={{ width: 36, fontSize: 10, color, fontFamily: "monospace" }}>{d[valueKey]}</div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Activity chart ────────────────────────────────────────────────────────────
function ActivityChart({ data, height = 60 }) {
  const vals = (data || []).map(d => parseInt(d.count) || 0);
  if (vals.length < 2) return <div style={{ color: "#3a4a6a", fontSize: 11, paddingTop: 20, textAlign: "center" }}>Waiting for live packets...</div>;
  const max = Math.max(...vals, 1);
  const W = 600; const H = height;
  const step = W / (vals.length - 1);
  const pts = vals.map((v, i) => `${i * step},${H - (v / max) * (H - 6) - 3}`).join(" ");
  const area = `0,${H} ` + pts + ` ${(vals.length-1)*step},${H}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height, overflow: "visible" }} preserveAspectRatio="none">
      <defs>
        <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#00f5c4" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#00f5c4" stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={area} fill="url(#ag)" />
      <polyline points={pts} fill="none" stroke="#00f5c4" strokeWidth="2" strokeLinejoin="round" />
    </svg>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, color = "#00f5c4", icon, sub }) {
  return (
    <div style={{
      background: "linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)",
      border: `1px solid ${color}30`, borderRadius: 12, padding: "18px 20px",
      position: "relative", overflow: "hidden", boxShadow: `inset 0 1px 0 ${color}20`,
    }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}60, transparent)` }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: 10, color: "#4a6a8a", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>{label}</div>
          <div style={{ fontSize: 30, fontWeight: 800, color, fontFamily: "monospace", lineHeight: 1 }}>{value}</div>
          {sub && <div style={{ fontSize: 10, color: "#4a6a8a", marginTop: 4 }}>{sub}</div>}
        </div>
        <div style={{ fontSize: 26, opacity: 0.6 }}>{icon}</div>
      </div>
    </div>
  );
}

// ─── Alert pill ────────────────────────────────────────────────────────────────
function AlertPill({ alert, onResolve }) {
  const sev = SEV[alert.severity] || SEV.medium;
  const icon = ALERT_TYPE_ICONS[alert.type] || "⚠️";
  const typeColor = ALERT_TYPE_COLORS[alert.type] || sev.color;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10,
      background: alert._new ? sev.bg : "rgba(255,255,255,0.02)",
      border: `1px solid ${alert.resolved ? "#1a2a3a" : sev.color + "40"}`,
      borderRadius: 8, padding: "10px 14px",
      opacity: alert.resolved ? 0.45 : 1,
      transition: "all 0.4s",
      boxShadow: alert._new ? sev.glow : "none",
      animation: alert._new ? "slideIn 0.3s ease" : "none",
    }}>
      <div style={{ fontSize: 18, flexShrink: 0 }}>{icon}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
          <span style={{ fontSize: 9, fontWeight: 700, color: sev.color, letterSpacing: "0.1em", background: sev.bg, padding: "2px 6px", borderRadius: 3, border: `1px solid ${sev.color}30` }}>
            {sev.label}
          </span>
          <span style={{ fontSize: 9, color: typeColor, letterSpacing: "0.08em", textTransform: "uppercase" }}>
            {alert.type?.replace(/_/g, " ")}
          </span>
          {alert.site && (
            <span style={{ fontSize: 9, color: "#4a6a8a" }}>→ {alert.site}</span>
          )}
        </div>
        <div style={{ fontSize: 12, color: "#c0d4ec", wordBreak: "break-word" }}>{alert.message}</div>
        <div style={{ fontSize: 9, color: "#2a4a6a", marginTop: 3 }}>
          {alert.ip && <span>{alert.ip} · </span>}
          {new Date(alert.created_at).toLocaleTimeString()}
        </div>
      </div>
      {!alert.resolved && (
        <button onClick={() => onResolve(alert.id)} style={{
          background: "none", border: "1px solid #1a3a5a", color: "#2a6a8a",
          borderRadius: 4, padding: "3px 8px", fontSize: 9, cursor: "pointer",
          fontFamily: "inherit", letterSpacing: "0.06em", flexShrink: 0,
        }}>✓ ACK</button>
      )}
    </div>
  );
}

// ─── Log row ────────────────────────────────────────────────────────────────────
function LogRow({ log }) {
  const sev = SEV[log.severity] || SEV.info;
  const icon = EVENT_TYPE_ICONS[log.event_type] || "•";
  const isAttack = log.event_type === "attack" || log.event_type === "malware_c2" || log.event?.includes("[ATTACK:");
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "150px 110px 44px 18px 1fr",
      gap: 8, padding: "6px 10px", fontSize: 11,
      borderBottom: "1px solid rgba(255,255,255,0.02)",
      background: log._new ? sev.bg : isAttack ? "rgba(255,45,85,0.04)" : "transparent",
      animation: log._new ? "slideIn 0.3s ease" : "none",
      transition: "background 0.5s",
      borderLeft: isAttack ? "2px solid #ff2d5550" : "2px solid transparent",
    }}>
      <span style={{ color: "#2a4a6a", fontFamily: "monospace", fontSize: 10 }}>
        {new Date(log.timestamp).toLocaleTimeString()}
      </span>
      <span style={{ color: "#58a6d4", fontFamily: "monospace" }}>{log.ip}</span>
      <span style={{
        fontSize: 9, fontWeight: 700, color: sev.color,
        background: sev.bg, padding: "1px 4px", borderRadius: 3,
        textAlign: "center", alignSelf: "center",
      }}>{sev.label}</span>
      <span style={{ alignSelf: "center", fontSize: 13 }}>{icon}</span>
      <span style={{ color: isAttack ? "#ff6b35" : "#8ba0c4", wordBreak: "break-all", fontSize: 10 }}>
        {log.event}
      </span>
    </div>
  );
}

// ─── Session badge ────────────────────────────────────────────────────────────
function SessionBadge({ sessionStart }) {
  const [elapsed, setElapsed] = useState("");
  useEffect(() => {
    if (!sessionStart) return;
    const tick = () => {
      const s = Math.floor((Date.now() - new Date(sessionStart)) / 1000);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      setElapsed(h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`);
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => clearInterval(iv);
  }, [sessionStart]);
  return (
    <div style={{ fontSize: 10, color: "#2a4a6a", display: "flex", alignItems: "center", gap: 5 }}>
      <span>SESSION</span>
      <span style={{ fontSize: 11, color: "#00f5c4", fontFamily: "monospace", fontWeight: 700 }}>{elapsed}</span>
    </div>
  );
}

// ─── Sites visited panel ───────────────────────────────────────────────────────
function SiteRow({ site, isNew }) {
  const isMalware = site.site?.includes("malware") || site.site?.includes("botnet") ||
    site.site?.includes("c2-") || site.site?.includes(".ru") || site.site?.includes(".tk");
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "1fr 70px 60px 90px",
      gap: 6, padding: "6px 10px", fontSize: 10,
      borderBottom: "1px solid rgba(255,255,255,0.02)",
      background: isNew ? "rgba(0,245,196,0.04)" : isMalware ? "rgba(255,45,85,0.06)" : "transparent",
      borderLeft: isMalware ? "2px solid #ff2d5560" : "2px solid transparent",
      animation: isNew ? "slideIn 0.3s ease" : "none",
    }}>
      <span style={{ color: isMalware ? "#ff6b35" : "#8ba0c4", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {isMalware ? "☠️ " : ""}{site.site}
      </span>
      <span style={{ color: "#4a6a8a", textAlign: "center" }}>{site.unique_ips || 1} IP{(site.unique_ips || 1) > 1 ? "s" : ""}</span>
      <span style={{ color: "#00f5c4", fontFamily: "monospace", textAlign: "right", fontWeight: 700 }}>{site.total_visits || site.visit_count}</span>
      <span style={{ color: "#2a4a6a", textAlign: "right" }}>
        {site.last_seen ? new Date(site.last_seen).toLocaleTimeString() : "—"}
      </span>
    </div>
  );
}

// ─── Attack stats bar ──────────────────────────────────────────────────────────
function AttackStatsBar({ attackStats }) {
  if (!attackStats || attackStats.length === 0) return null;
  const typeConfig = {
    attack: { label: "Attacks", color: "#ff2d55", icon: "💥" },
    malware_c2: { label: "Malware C2", color: "#ff2d55", icon: "☠️" },
    auth_attempt: { label: "Brute Force", color: "#ff6b35", icon: "🔐" },
    port_scan: { label: "Port Scans", color: "#f5c542", icon: "🔍" },
    port_access: { label: "Port Access", color: "#f5c542", icon: "🔌" },
  };
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      {attackStats.map(s => {
        const cfg = typeConfig[s.event_type] || { label: s.event_type, color: "#6b8cba", icon: "⚠️" };
        return (
          <div key={s.event_type} style={{
            background: `${cfg.color}10`,
            border: `1px solid ${cfg.color}30`,
            borderRadius: 8, padding: "10px 16px",
            display: "flex", alignItems: "center", gap: 10, flex: "1 1 140px",
          }}>
            <span style={{ fontSize: 20 }}>{cfg.icon}</span>
            <div>
              <div style={{ fontSize: 10, color: cfg.color, letterSpacing: "0.08em", textTransform: "uppercase" }}>{cfg.label}</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: cfg.color, fontFamily: "monospace" }}>{s.count}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [sites, setSites] = useState([]);
  const [status, setStatus] = useState("connecting");
  const [activeTab, setActiveTab] = useState("overview");
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [showResolved, setShowResolved] = useState(false);
  const [alertBell, setAlertBell] = useState(false);
  const [sessionStart, setSessionStart] = useState(null);
  const [siteFilter, setSiteFilter] = useState("");
  const logsRef = useRef(null);
  const statsIntervalRef = useRef(null);

  const fetchStats = useCallback(async () => {
    try {
      const sr = await axios.get(`${API}/stats`);
      setStats(sr.data);
      if (sr.data.session_start) setSessionStart(sr.data.session_start);
    } catch {}
  }, []);

  const fetchSessionAlerts = useCallback(async () => {
    try {
      const ar = await axios.get(`${API}/alerts`);
      setAlerts(ar.data);
    } catch {}
  }, []);

  const fetchSites = useCallback(async () => {
    try {
      const sr = await axios.get(`${API}/sites/summary`);
      setSites(sr.data);
    } catch {}
  }, []);

  useEffect(() => {
    fetchStats();
    fetchSessionAlerts();
    fetchSites();
    statsIntervalRef.current = setInterval(() => {
      fetchStats();
      fetchSites();
    }, 5000);

    socket.on("connect", () => setStatus("live"));
    socket.on("disconnect", () => setStatus("offline"));

    socket.on("session_start", ({ session_start }) => {
      setSessionStart(session_start);
      setLogs([]); setAlerts([]); setStats(null); setSites([]);
      fetchStats(); fetchSessionAlerts(); fetchSites();
    });

    socket.on("new_log", (log) => {
      setLogs(prev => [{ ...log, _new: true }, ...prev].slice(0, 500));
      setTimeout(() => setLogs(prev => prev.map(l => l.id === log.id ? { ...l, _new: false } : l)), 2000);
    });

    socket.on("new_alert", (alert) => {
      setAlerts(prev => [{ ...alert, _new: true }, ...prev]);
      setAlertBell(true);
      setTimeout(() => {
        setAlerts(prev => prev.map(a => a.id === alert.id ? { ...a, _new: false } : a));
        setAlertBell(false);
      }, 3000);
    });

    socket.on("alert_resolved", ({ id }) => {
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, resolved: true } : a));
    });

    return () => {
      ["new_log","new_alert","alert_resolved","connect","disconnect","session_start"].forEach(e => socket.off(e));
      clearInterval(statsIntervalRef.current);
    };
  }, [fetchStats, fetchSessionAlerts, fetchSites]);

  const resolveAlert = async (id) => {
    try {
      await axios.patch(`${API}/alerts/${id}/resolve`);
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, resolved: true } : a));
    } catch {}
  };

  const visibleAlerts = alerts.filter(a => showResolved ? true : !a.resolved);
  const unresolved = alerts.filter(a => !a.resolved).length;
  const criticalAlerts = alerts.filter(a => !a.resolved && a.severity === "critical").length;

  // Log filters
  let filteredLogs = filterSev === "all" ? logs : logs.filter(l => l.severity === filterSev);
  if (filterType !== "all") {
    if (filterType === "attacks") filteredLogs = filteredLogs.filter(l => l.event_type === "attack" || l.event_type === "malware_c2" || l.event?.includes("[ATTACK:"));
    else if (filterType === "browsing") filteredLogs = filteredLogs.filter(l => ["https_visit","http_visit","dns_lookup"].includes(l.event_type));
    else filteredLogs = filteredLogs.filter(l => l.event_type === filterType);
  }

  const filteredSites = sites.filter(s => !siteFilter || s.site?.toLowerCase().includes(siteFilter.toLowerCase()));

  const statusColors = { live: "#00f5c4", offline: "#ff2d55", connecting: "#f5c542" };
  const statusDot = statusColors[status] || "#888";

  return (
    <div style={{
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      background: "#060c1a", color: "#c0d4ec", minHeight: "100vh",
      display: "flex", flexDirection: "column",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700;800&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0a0f1e; }
        ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }
        @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.2; } }
        @keyframes shake { 0%,100% { transform: rotate(0); } 25% { transform: rotate(-15deg); } 75% { transform: rotate(15deg); } }
        .tab-btn { background: none; border: none; cursor: pointer; font-family: inherit; font-size: 12px; letter-spacing: 0.1em; padding: 8px 14px; border-radius: 6px; transition: all 0.2s; }
        .tab-btn:hover { background: rgba(0,245,196,0.08); }
        .bell-shake { animation: shake 0.4s ease; }
        .live-dot { animation: blink 1.2s infinite; }
      `}</style>

      {/* Scanline */}
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)" }} />

      {/* ─── Header ─── */}
      <header style={{
        borderBottom: "1px solid rgba(0,245,196,0.08)", padding: "12px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "rgba(6,12,26,0.97)", backdropFilter: "blur(20px)",
        position: "sticky", top: 0, zIndex: 100,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ fontSize: 20 }}>🛡️</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 800, color: "#e0f0ff", letterSpacing: "0.05em", fontFamily: "'Syne', sans-serif" }}>
              AEGIS<span style={{ color: "#00f5c4" }}>·</span>SIEM
            </div>
            <div style={{ fontSize: 9, color: "#2a4a6a", letterSpacing: "0.2em", textTransform: "uppercase" }}>Gateway Network Monitor</div>
          </div>
          {criticalAlerts > 0 && (
            <div style={{ background: "#ff2d5520", border: "1px solid #ff2d5560", borderRadius: 6, padding: "3px 10px", fontSize: 10, color: "#ff2d55", fontWeight: 700, animation: "pulse 1s infinite" }}>
              ⚠ {criticalAlerts} CRITICAL
            </div>
          )}
        </div>

        <nav style={{ display: "flex", gap: 4 }}>
          {[
            ["overview", "📊 Overview"],
            ["attacks", "💥 Attacks"],
            ["alerts", "🚨 Alerts"],
            ["sites", "🌐 Sites"],
            ["logs", "📡 Packets"],
          ].map(([id, label]) => (
            <button key={id} className="tab-btn"
              onClick={() => setActiveTab(id)}
              style={{
                color: activeTab === id ? "#00f5c4" : "#4a6a8a",
                background: activeTab === id ? "rgba(0,245,196,0.08)" : "none",
                borderBottom: activeTab === id ? "1px solid #00f5c480" : "1px solid transparent",
                position: "relative",
              }}>
              {label}
              {id === "alerts" && unresolved > 0 && (
                <span style={{ position: "absolute", top: 2, right: 4, background: "#ff2d55", color: "#fff", borderRadius: 8, fontSize: 8, padding: "1px 4px", fontWeight: 700 }}>{unresolved}</span>
              )}
              {id === "attacks" && stats?.attackStats?.length > 0 && (
                <span style={{ position: "absolute", top: 2, right: 4, background: "#ff6b35", color: "#fff", borderRadius: 8, fontSize: 8, padding: "1px 4px", fontWeight: 700 }}>
                  {stats.attackStats.reduce((s, a) => s + parseInt(a.count), 0)}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <SessionBadge sessionStart={sessionStart} />
          <div style={{ fontSize: 22, cursor: "default" }} className={alertBell ? "bell-shake" : ""}>
            {unresolved > 0 ? "🔔" : "🔕"}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: statusDot, animation: status === "live" ? "pulse 2s infinite" : "none", boxShadow: status === "live" ? `0 0 6px ${statusDot}` : "none" }} />
            <span style={{ fontSize: 11, color: statusDot, letterSpacing: "0.08em" }}>{status.toUpperCase()}</span>
          </div>
        </div>
      </header>

      <main style={{ flex: 1, padding: "20px 24px", maxWidth: 1440, width: "100%", margin: "0 auto", position: "relative", zIndex: 1 }}>

        {/* ─── OVERVIEW TAB ─── */}
        {activeTab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            {/* Session banner */}
            <div style={{ display: "flex", alignItems: "center", gap: 10, background: "rgba(0,245,196,0.04)", border: "1px solid rgba(0,245,196,0.12)", borderRadius: 8, padding: "8px 16px" }}>
              <span className="live-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: "#00f5c4", display: "inline-block", flexShrink: 0 }} />
              <span style={{ fontSize: 10, color: "#2a8a6a", letterSpacing: "0.1em" }}>
                GATEWAY-WIDE CAPTURE · All devices on your network · Session since{" "}
                <span style={{ color: "#00f5c4" }}>{sessionStart ? new Date(sessionStart).toLocaleTimeString() : "startup"}</span>
              </span>
            </div>

            {/* Stat cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
              <StatCard label="Packets Captured" value={stats?.totals?.logs ?? "—"} color="#00f5c4" icon="📡" sub="this session" />
              <StatCard label="Threats Detected" value={stats?.totals?.alerts ?? "—"} color="#f5c542" icon="🚨" sub="alerts triggered" />
              <StatCard label="Active Threats" value={stats?.totals?.unresolvedAlerts ?? "—"} color="#ff2d55" icon="🔴" sub="unacknowledged" />
              <StatCard label="Sites Tracked" value={sites.length ?? "—"} color="#9b59b6" icon="🌐" sub="unique domains" />
              <StatCard label="Top Threat IP" value={stats?.topIPs?.[0]?.ip ?? "—"} color="#ff6b35" icon="🎯" sub={stats?.topIPs?.[0] ? `${stats.topIPs[0].count} events` : "no threats"} />
            </div>

            {/* Attack stats */}
            {stats?.attackStats?.length > 0 && (
              <div style={{ background: "rgba(255,45,85,0.03)", border: "1px solid rgba(255,45,85,0.1)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ fontSize: 10, color: "#6a2a3a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>
                  ⚡ Attack Event Breakdown
                </div>
                <AttackStatsBar attackStats={stats.attackStats} />
              </div>
            )}

            {/* Timeline + donut */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 260px", gap: 14 }}>
              <div style={{ background: "linear-gradient(135deg, rgba(0,245,196,0.03), rgba(0,0,0,0))", border: "1px solid rgba(0,245,196,0.08)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
                  <div style={{ fontSize: 10, color: "#2a5a4a", letterSpacing: "0.15em", textTransform: "uppercase" }}>Live Packet Activity</div>
                  <div style={{ fontSize: 9, color: "#2a4a4a" }}>past 30 min</div>
                </div>
                <ActivityChart data={stats?.timelineData} height={65} />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#2a4a6a", marginTop: 4 }}>
                  <span>30 min ago</span><span>now</span>
                </div>
              </div>
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ fontSize: 10, color: "#3a5a7a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>Severity Breakdown</div>
                <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
                  {stats?.severityBreakdown?.length > 0
                    ? <DonutChart data={stats.severityBreakdown} size={90} />
                    : <div style={{ width: 90, height: 90, borderRadius: "50%", border: "2px dashed #1a2a3a", display:"flex", alignItems:"center", justifyContent:"center", fontSize:10, color:"#2a4a6a", textAlign:"center", padding:8 }}>No data</div>
                  }
                  <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                    {(stats?.severityBreakdown || []).map(d => (
                      <div key={d.severity} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: SEV[d.severity]?.color || "#888" }} />
                        <span style={{ color: "#4a6a8a", width: 55 }}>{d.severity}</span>
                        <span style={{ color: SEV[d.severity]?.color || "#888", fontWeight: 700 }}>{d.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Top IPs + Top Sites */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ fontSize: 10, color: "#3a5a7a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>Top Source IPs</div>
                <BarChart data={stats?.topIPs || []} color="#58a6d4" labelKey="ip" valueKey="count" />
              </div>
              <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ fontSize: 10, color: "#3a5a7a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>🌐 Top Sites Visited</div>
                <BarChart
                  data={(stats?.topSites || []).map(d => ({ ...d, label: d.site }))}
                  color="#9b59b6" labelKey="site" valueKey="total_visits"
                />
              </div>
            </div>

            {/* Active threats or clear */}
            {alerts.filter(a => !a.resolved).length > 0 ? (
              <div style={{ background: "rgba(255,45,85,0.04)", border: "1px solid rgba(255,45,85,0.12)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                  <div style={{ fontSize: 10, color: "#8a2a3a", letterSpacing: "0.15em", textTransform: "uppercase" }}>🚨 Active Threats</div>
                  <button onClick={() => setActiveTab("alerts")} style={{ background: "none", border: "1px solid rgba(255,45,85,0.3)", color: "#ff2d55", borderRadius: 4, padding: "3px 10px", fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>
                    View All →
                  </button>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {alerts.filter(a => !a.resolved).slice(0, 5).map(a => <AlertPill key={a.id} alert={a} onResolve={resolveAlert} />)}
                </div>
              </div>
            ) : (
              <div style={{ background: "rgba(0,245,196,0.02)", border: "1px solid rgba(0,245,196,0.08)", borderRadius: 12, padding: "24px", textAlign: "center", color: "#2a6a5a" }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>✅</div>
                <div style={{ fontSize: 12 }}>No active threats detected</div>
                <div style={{ fontSize: 10, marginTop: 4, color: "#1a4a3a" }}>Monitoring all gateway devices</div>
              </div>
            )}
          </div>
        )}

        {/* ─── ATTACKS TAB ─── */}
        {activeTab === "attacks" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "#ff2d55" }}>💥 Attack Intelligence</div>
                <div style={{ fontSize: 11, color: "#3a5a7a", marginTop: 2 }}>Real-time attack detection and threat analysis</div>
              </div>
            </div>

            {/* Attack breakdown */}
            {stats?.attackStats?.length > 0 && (
              <div style={{ background: "rgba(255,45,85,0.04)", border: "1px solid rgba(255,45,85,0.12)", borderRadius: 12, padding: "16px 20px" }}>
                <div style={{ fontSize: 10, color: "#6a2a3a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>Attack Event Counts</div>
                <AttackStatsBar attackStats={stats.attackStats} />
              </div>
            )}

            {/* Attack alerts */}
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "16px 20px" }}>
              <div style={{ fontSize: 10, color: "#3a5a7a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>
                Attack Alerts ({alerts.filter(a => ["attack","malware_c2","brute_force"].includes(a.type)).length})
              </div>
              {alerts.filter(a => ["attack","malware_c2","brute_force","port_access"].includes(a.type)).length === 0 ? (
                <div style={{ textAlign: "center", padding: "30px 0", color: "#2a4a6a" }}>
                  <div style={{ fontSize: 30, marginBottom: 8 }}>🛡️</div>
                  <div>No attack alerts this session</div>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {alerts.filter(a => ["attack","malware_c2","brute_force","port_access"].includes(a.type))
                    .map(a => <AlertPill key={a.id} alert={a} onResolve={resolveAlert} />)}
                </div>
              )}
            </div>

            {/* Attack logs */}
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, padding: "16px 20px" }}>
              <div style={{ fontSize: 10, color: "#3a5a7a", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 14 }}>
                Live Attack Events ({logs.filter(l => l.event_type === "attack" || l.event_type === "malware_c2" || l.event?.includes("[ATTACK:")).length})
              </div>
              <div style={{ maxHeight: 400, overflowY: "auto" }}>
                {logs.filter(l => l.event_type === "attack" || l.event_type === "malware_c2" || l.event?.includes("[ATTACK:") || l.event?.includes("[MALWARE")).length === 0 ? (
                  <div style={{ textAlign: "center", padding: "30px 0", color: "#2a4a6a", fontSize: 12 }}>
                    No attacks detected in this session
                  </div>
                ) : (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "150px 110px 44px 18px 1fr", gap: 8, padding: "4px 10px", fontSize: 9, color: "#2a4a6a", letterSpacing: "0.1em", textTransform: "uppercase", borderBottom: "1px solid #0a2a3a", marginBottom: 4 }}>
                      <span>Time</span><span>Source IP</span><span>Sev</span><span></span><span>Event</span>
                    </div>
                    {logs.filter(l => l.event_type === "attack" || l.event_type === "malware_c2" || l.event?.includes("[ATTACK:") || l.event?.includes("[MALWARE")).map(l => <LogRow key={l.id} log={l} />)}
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ─── ALERTS TAB ─── */}
        {activeTab === "alerts" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "#e0f0ff" }}>Session Alerts</div>
                <div style={{ fontSize: 11, color: "#3a5a7a", marginTop: 2 }}>
                  {unresolved} active · {alerts.length - unresolved} acknowledged
                </div>
              </div>
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "#4a6a8a", cursor: "pointer" }}>
                <input type="checkbox" checked={showResolved} onChange={e => setShowResolved(e.target.checked)} style={{ accentColor: "#00f5c4" }} />
                Show acknowledged
              </label>
            </div>
            {visibleAlerts.length === 0 ? (
              <div style={{ textAlign: "center", padding: "60px 0", color: "#2a4a6a" }}>
                <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
                <div style={{ fontSize: 14 }}>No active alerts this session</div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {visibleAlerts.map(a => <AlertPill key={a.id} alert={a} onResolve={resolveAlert} />)}
              </div>
            )}
          </div>
        )}

        {/* ─── SITES TAB ─── */}
        {activeTab === "sites" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
              <div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "#9b59b6" }}>🌐 Sites Visited — Gateway</div>
                <div style={{ fontSize: 11, color: "#3a5a7a", marginTop: 2 }}>
                  {sites.length} unique domains tracked across all devices
                </div>
              </div>
              <input
                placeholder="Filter domain..."
                value={siteFilter}
                onChange={e => setSiteFilter(e.target.value)}
                style={{
                  background: "rgba(255,255,255,0.04)", border: "1px solid #1a3a5a",
                  borderRadius: 6, padding: "6px 12px", color: "#c0d4ec", fontSize: 11,
                  fontFamily: "monospace", outline: "none", width: 200,
                }}
              />
            </div>

            {/* Site table */}
            <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 12, overflow: "hidden" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 70px 60px 90px", gap: 6, padding: "8px 10px", fontSize: 9, color: "#2a4a6a", letterSpacing: "0.1em", textTransform: "uppercase", borderBottom: "1px solid #0a2a3a", background: "rgba(0,0,0,0.2)" }}>
                <span>Domain</span><span style={{ textAlign: "center" }}>Devices</span><span style={{ textAlign: "right" }}>Visits</span><span style={{ textAlign: "right" }}>Last Seen</span>
              </div>
              <div style={{ maxHeight: "calc(100vh - 320px)", overflowY: "auto" }}>
                {filteredSites.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "60px 0", color: "#2a4a6a" }}>
                    <div style={{ fontSize: 30, marginBottom: 8 }}>🌐</div>
                    <div>No sites tracked yet</div>
                    <div style={{ fontSize: 10, marginTop: 4 }}>Sites appear as devices on your network browse the web</div>
                  </div>
                ) : (
                  filteredSites.map((s, i) => <SiteRow key={s.site} site={s} isNew={i === 0} />)
                )}
              </div>
            </div>
          </div>
        )}

        {/* ─── LIVE PACKETS TAB ─── */}
        {activeTab === "logs" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "#e0f0ff" }}>Live Packet Stream</div>
                  <span className="live-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: "#00f5c4", display: "inline-block" }} />
                </div>
                <div style={{ fontSize: 11, color: "#3a5a7a", marginTop: 2 }}>
                  {logs.length} packets this session (all gateway devices)
                </div>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {[["all","All"], ["attacks","Attacks 💥"], ["browsing","Browsing 🌐"], ["auth_attempt","Auth 🔐"], ["port_scan","Scan 🔍"]].map(([v, l]) => (
                  <button key={v} onClick={() => setFilterType(v)} style={{
                    background: filterType === v ? "rgba(0,245,196,0.1)" : "none",
                    border: `1px solid ${filterType === v ? "#00f5c4" : "#1a3a5a"}40`,
                    color: filterType === v ? "#00f5c4" : "#3a5a7a",
                    borderRadius: 4, padding: "4px 10px", fontSize: 10, cursor: "pointer",
                    fontFamily: "inherit", letterSpacing: "0.06em",
                  }}>{l}</button>
                ))}
                <div style={{ width: 1, background: "#1a3a5a", margin: "0 4px" }} />
                {["all","critical","high","medium","low","info"].map(s => (
                  <button key={s} onClick={() => setFilterSev(s)} style={{
                    background: filterSev === s ? (SEV[s]?.bg || "rgba(0,245,196,0.1)") : "none",
                    border: `1px solid ${filterSev === s ? (SEV[s]?.color || "#00f5c4") : "#1a3a5a"}40`,
                    color: filterSev === s ? (SEV[s]?.color || "#00f5c4") : "#3a5a7a",
                    borderRadius: 4, padding: "4px 10px", fontSize: 10, cursor: "pointer",
                    fontFamily: "inherit", textTransform: "uppercase",
                  }}>{s}</button>
                ))}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "150px 110px 44px 18px 1fr", gap: 8, padding: "6px 10px", fontSize: 9, color: "#2a4a6a", letterSpacing: "0.12em", textTransform: "uppercase", borderBottom: "1px solid #0a2a3a" }}>
              <span>Timestamp</span><span>Source IP</span><span>Sev</span><span></span><span>Event</span>
            </div>

            <div ref={logsRef} style={{ maxHeight: "calc(100vh - 300px)", overflowY: "auto" }}>
              {filteredLogs.length === 0 ? (
                <div style={{ textAlign: "center", padding: "60px 0", color: "#2a4a6a" }}>
                  <div style={{ fontSize: 32, marginBottom: 8 }}>📡</div>
                  <div style={{ fontSize: 14, marginBottom: 4 }}>Waiting for gateway packets...</div>
                  <div style={{ fontSize: 11, color: "#1a3a5a" }}>
                    Make sure the sniffer is running as root/admin.<br />
                    It will capture traffic from all devices on your network.
                  </div>
                </div>
              ) : (
                filteredLogs.map(l => <LogRow key={l.id} log={l} />)
              )}
            </div>
          </div>
        )}
      </main>

      <footer style={{ borderTop: "1px solid rgba(0,245,196,0.05)", padding: "8px 24px", display: "flex", justifyContent: "space-between", fontSize: 10, color: "#1a3a5a" }}>
        <span>AEGIS·SIEM v4 · Gateway Monitor · {sites.length} sites · {logs.length} packets this session</span>
        <span>{new Date().toLocaleString([], { dateStyle: "short", timeStyle: "medium" })}</span>
      </footer>
    </div>
  );
}
