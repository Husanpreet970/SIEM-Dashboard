const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const pool = new Pool({
  user: process.env.DB_USER || "siem",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "siemdb",
  password: process.env.DB_PASSWORD || "siem",
  port: parseInt(process.env.DB_PORT) || 5432,
});

app.use(cors());
app.use(express.json());

const SESSION_START = new Date();
console.log(`Session started at ${SESSION_START.toISOString()}`);

async function initDB() {
  try {
    await pool.connect();
    console.log("Connected to DB");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        event TEXT,
        severity TEXT DEFAULT 'info',
        port INTEGER,
        protocol TEXT DEFAULT 'TCP',
        site TEXT,
        event_type TEXT DEFAULT 'generic'
      );
      CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        message TEXT,
        severity TEXT DEFAULT 'medium',
        type TEXT DEFAULT 'generic',
        ip TEXT,
        site TEXT,
        resolved BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS site_visits (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        site TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        visit_count INTEGER DEFAULT 1,
        protocol TEXT DEFAULT 'HTTPS',
        UNIQUE(ip, site)
      );
    `);

    // Add columns if missing (idempotent upgrades)
    const upgrades = [
      "ALTER TABLE logs ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'info'",
      "ALTER TABLE logs ADD COLUMN IF NOT EXISTS port INTEGER",
      "ALTER TABLE logs ADD COLUMN IF NOT EXISTS protocol TEXT DEFAULT 'TCP'",
      "ALTER TABLE logs ADD COLUMN IF NOT EXISTS site TEXT",
      "ALTER TABLE logs ADD COLUMN IF NOT EXISTS event_type TEXT DEFAULT 'generic'",
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS severity TEXT DEFAULT 'medium'",
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS type TEXT DEFAULT 'generic'",
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ip TEXT",
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS site TEXT",
      "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved BOOLEAN DEFAULT FALSE",
    ];
    for (const q of upgrades) await pool.query(q).catch(() => {});
    console.log("Tables ready");
  } catch (err) {
    console.error("DB init error:", err.message);
    process.exit(1);
  }
}

function extractPort(event) {
  const m = event.match(/port\s+(\d+)/i);
  return m ? parseInt(m[1]) : null;
}

function getSeverity(event, port, eventType) {
  const criticalPorts = [23, 445, 6379, 27017, 4444, 6667, 11211, 9200];
  const highPorts = [22, 3389, 1433, 3306, 5432, 5900, 2222];

  if (event.includes("[ATTACK:SHELL_INJECTION]") || event.includes("[ATTACK:SQL_INJECTION]")) return "critical";
  if (event.includes("[MALWARE-C2]")) return "critical";
  if (event.includes("[ATTACK:XSS") || event.includes("[ATTACK:PATH_TRAVERSAL]")) return "high";
  if (event.includes("[ATTACK:RECON_TOOL]")) return "medium";
  if (event.includes("auth_attempt") || event.includes("auth_failure") || event.includes("failed_login")) return "medium";
  if (port && criticalPorts.includes(port)) return "critical";
  if (port && highPorts.includes(port)) return "high";
  if (eventType === "malware_c2") return "critical";
  if (eventType === "attack") return "high";
  if (eventType === "port_scan" || eventType === "port_access") return "low";
  if (event.includes("[ATTACK:")) return "high";
  return "info";
}

async function upsertSiteVisit(ip, site, protocol) {
  if (!site) return;
  try {
    const clean = site.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
    if (!clean || clean.length < 3) return;
    await pool.query(`
      INSERT INTO site_visits (ip, site, protocol)
      VALUES ($1, $2, $3)
      ON CONFLICT (ip, site) DO UPDATE
        SET last_seen = CURRENT_TIMESTAMP,
            visit_count = site_visits.visit_count + 1,
            protocol = EXCLUDED.protocol
    `, [ip, clean, protocol]);
  } catch (err) {
    // ignore constraint errors silently
  }
}

async function createAlert(message, severity, type, ip, site = null) {
  // De-duplicate within 5 min this session
  const existing = await pool.query(
    "SELECT id FROM alerts WHERE message=$1 AND created_at > $2 AND created_at > NOW() - INTERVAL '5 minutes'",
    [message, SESSION_START]
  );
  if (existing.rows.length === 0) {
    const r = await pool.query(
      "INSERT INTO alerts (message, severity, type, ip, site) VALUES ($1,$2,$3,$4,$5) RETURNING *",
      [message, severity, type, ip, site]
    );
    io.emit("new_alert", r.rows[0]);
    console.log(`ALERT [${severity.toUpperCase()}] ${message}`);
  }
}

async function runDetectionEngine(ip, event, port, eventType, site) {
  // --- Brute force detection ---
  if (event.includes("auth_attempt") || event.includes("failed_login") || event.includes("auth_failure")) {
    const r = await pool.query(
      `SELECT COUNT(*) FROM logs WHERE ip=$1
       AND (event LIKE '%auth_attempt%' OR event LIKE '%failed_login%' OR event LIKE '%auth_failure%')
       AND timestamp > $2 AND timestamp > NOW() - INTERVAL '1 minute'`,
      [ip, SESSION_START]
    );
    const c = parseInt(r.rows[0].count);
    if (c >= 5) await createAlert(
      `Brute force attack from ${ip} — ${c} attempts in 1 min`,
      c > 15 ? "critical" : "high", "brute_force", ip
    );
  }

  // --- Malware C2 communication ---
  if (event.includes("[MALWARE-C2]")) {
    const domain = site || event.split(": ").pop();
    await createAlert(
      `Malware C2 communication detected from ${ip} → ${domain}`,
      "critical", "malware_c2", ip, site
    );
  }

  // --- Active attack detected ---
  if (event.includes("[ATTACK:")) {
    const typeMatch = event.match(/\[ATTACK:([^\]]+)\]/);
    const atype = typeMatch ? typeMatch[1].toLowerCase() : "attack";
    const host = site || "unknown target";
    const sevMap = {
      shell_injection: "critical", sql_injection: "critical",
      xss_attempt: "high", path_traversal: "high",
      recon_tool: "medium",
    };
    const sev = sevMap[atype] || "high";
    await createAlert(
      `${atype.replace("_", " ").toUpperCase()} attack from ${ip} targeting ${host}`,
      sev, "attack", ip, site
    );
  }

  // --- Suspicious port access ---
  const suspiciousPorts = {
    22: ["SSH","high"], 23: ["Telnet","critical"], 3389: ["RDP","high"],
    445: ["SMB","critical"], 1433: ["MSSQL","high"], 3306: ["MySQL","high"],
    5432: ["PostgreSQL","high"], 6379: ["Redis","critical"],
    27017: ["MongoDB","critical"], 4444: ["Metasploit","critical"],
    6667: ["IRC/Botnet","critical"], 5900: ["VNC","high"],
    9200: ["Elasticsearch","critical"], 11211: ["Memcached","critical"],
  };
  const p = port || extractPort(event);
  if (p && suspiciousPorts[p]) {
    const [name, sev] = suspiciousPorts[p];
    await createAlert(`Suspicious ${name} (port ${p}) access from ${ip}`, sev, "port_access", ip);
  }

  // --- Port scan detection ---
  const ps = await pool.query(
    `SELECT COUNT(DISTINCT port) as up FROM logs
     WHERE ip=$1 AND port IS NOT NULL AND timestamp > $2 AND timestamp > NOW() - INTERVAL '30 seconds'`,
    [ip, SESSION_START]
  );
  const up = parseInt(ps.rows[0].up);
  if (up >= 10) await createAlert(
    `Port scan from ${ip} — ${up} unique ports scanned in 30s`,
    "high", "port_scan", ip
  );

  // --- High volume ONLY flag if it looks like an attack (not normal browsing) ---
  // Only trigger for non-browsing IPs doing excessive non-HTTP connections
  const vol = await pool.query(
    `SELECT COUNT(*) FROM logs WHERE ip=$1 AND timestamp > $2
     AND timestamp > NOW() - INTERVAL '1 minute'
     AND event_type NOT IN ('https_visit','http_visit','dns_lookup')`,
    [ip, SESSION_START]
  );
  const v = parseInt(vol.rows[0].count);
  if (v > 200) await createAlert(
    `Anomalous non-browsing traffic from ${ip} — ${v} suspicious events/min`,
    "high", "anomaly", ip
  );
}

io.on("connection", (s) => {
  console.log("Client connected:", s.id);
  s.emit("session_start", { session_start: SESSION_START.toISOString() });
  s.on("disconnect", () => console.log("Disconnected:", s.id));
});

app.post("/logs", async (req, res) => {
  try {
    const { ip, event, site, event_type, severity_hint } = req.body;
    if (!ip || !event) return res.status(400).json({ error: "Missing ip or event" });

    const port = extractPort(event);
    const eventType = event_type || "generic";
    const severity = severity_hint || getSeverity(event, port, eventType);

    // Determine protocol for site visit
    let protocol = "TCP";
    if (event.includes("HTTPS") || eventType === "https_visit") protocol = "HTTPS";
    else if (event.includes("HTTP") || eventType === "http_visit") protocol = "HTTP";
    else if (eventType === "dns_lookup") protocol = "DNS";

    const r = await pool.query(
      "INSERT INTO logs (ip, event, severity, port, site, event_type) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [ip, event, severity, port, site || null, eventType]
    );

    // Update site visits table
    if (site && ["https_visit","http_visit","dns_lookup","malware_c2"].includes(eventType)) {
      await upsertSiteVisit(ip, site, protocol);
    }

    io.emit("new_log", r.rows[0]);
    await runDetectionEngine(ip, event, port, eventType, site);
    res.json({ status: "ok", log: r.rows[0] });
  } catch (err) {
    console.error("/logs error:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/logs", async (req, res) => {
  try {
    const { limit = 500, severity, ip } = req.query;
    let q = "SELECT * FROM logs WHERE timestamp >= $1";
    const p = [SESSION_START];
    if (severity) { q += ` AND severity=$${p.length+1}`; p.push(severity); }
    if (ip)       { q += ` AND ip=$${p.length+1}`;       p.push(ip); }
    q += ` ORDER BY id DESC LIMIT $${p.length+1}`;
    p.push(parseInt(limit));
    const logs = await pool.query(q, p);
    res.json(logs.rows);
  } catch { res.status(500).json({ error: "Error fetching logs" }); }
});

app.get("/alerts", async (req, res) => {
  try {
    const a = await pool.query(
      "SELECT * FROM alerts WHERE created_at >= $1 ORDER BY id DESC LIMIT 200",
      [SESSION_START]
    );
    res.json(a.rows);
  } catch { res.status(500).json({ error: "Error fetching alerts" }); }
});

app.patch("/alerts/:id/resolve", async (req, res) => {
  try {
    await pool.query("UPDATE alerts SET resolved=TRUE WHERE id=$1", [req.params.id]);
    io.emit("alert_resolved", { id: parseInt(req.params.id) });
    res.json({ status: "resolved" });
  } catch { res.status(500).json({ error: "Error resolving alert" }); }
});

// New: GET /sites — top sites visited per IP this session
app.get("/sites", async (req, res) => {
  try {
    const { ip, limit = 50 } = req.query;
    let q = "SELECT * FROM site_visits WHERE first_seen >= $1";
    const p = [SESSION_START];
    if (ip) { q += ` AND ip=$${p.length+1}`; p.push(ip); }
    q += ` ORDER BY visit_count DESC LIMIT $${p.length+1}`;
    p.push(parseInt(limit));
    const r = await pool.query(q, p);
    res.json(r.rows);
  } catch { res.status(500).json({ error: "Error fetching sites" }); }
});

// New: GET /sites/summary — top sites across all IPs
app.get("/sites/summary", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT site, protocol,
             COUNT(DISTINCT ip) as unique_ips,
             SUM(visit_count) as total_visits,
             MAX(last_seen) as last_seen
      FROM site_visits
      WHERE first_seen >= $1
      GROUP BY site, protocol
      ORDER BY total_visits DESC
      LIMIT 30
    `, [SESSION_START]);
    res.json(r.rows);
  } catch { res.status(500).json({ error: "Error fetching site summary" }); }
});

app.get("/stats", async (req, res) => {
  try {
    const [tl, ta, ua, sev, ips, activity, types, timeline, topSites, attackStats] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM logs WHERE timestamp >= $1", [SESSION_START]),
      pool.query("SELECT COUNT(*) FROM alerts WHERE created_at >= $1", [SESSION_START]),
      pool.query("SELECT COUNT(*) FROM alerts WHERE resolved=FALSE AND created_at >= $1", [SESSION_START]),
      pool.query("SELECT severity, COUNT(*) as count FROM logs WHERE timestamp >= $1 GROUP BY severity ORDER BY count DESC", [SESSION_START]),
      pool.query("SELECT ip, COUNT(*) as count FROM logs WHERE timestamp >= $1 GROUP BY ip ORDER BY count DESC LIMIT 10", [SESSION_START]),
      pool.query(`SELECT DATE_TRUNC('minute', timestamp) as minute, COUNT(*) as count
        FROM logs WHERE timestamp >= $1 AND timestamp > NOW() - INTERVAL '30 minutes'
        GROUP BY minute ORDER BY minute`, [SESSION_START]),
      pool.query("SELECT type, COUNT(*) as count FROM alerts WHERE created_at >= $1 GROUP BY type", [SESSION_START]),
      pool.query(`SELECT DATE_TRUNC('minute', timestamp) as hour, COUNT(*) as count
        FROM logs WHERE timestamp >= $1 GROUP BY hour ORDER BY hour`, [SESSION_START]),
      pool.query(`SELECT site, SUM(visit_count) as total_visits, COUNT(DISTINCT ip) as unique_ips
        FROM site_visits WHERE first_seen >= $1
        GROUP BY site ORDER BY total_visits DESC LIMIT 10`, [SESSION_START]),
      pool.query(`SELECT event_type, COUNT(*) as count FROM logs
        WHERE timestamp >= $1 AND event_type IN ('attack','malware_c2','port_scan','auth_attempt','port_access')
        GROUP BY event_type ORDER BY count DESC`, [SESSION_START]),
    ]);
    res.json({
      session_start: SESSION_START.toISOString(),
      totals: {
        logs: parseInt(tl.rows[0].count),
        alerts: parseInt(ta.rows[0].count),
        unresolvedAlerts: parseInt(ua.rows[0].count),
      },
      severityBreakdown: sev.rows,
      topIPs: ips.rows,
      recentActivity: activity.rows,
      alertTypes: types.rows,
      timelineData: timeline.rows,
      topSites: topSites.rows,
      attackStats: attackStats.rows,
    });
  } catch (err) {
    console.error("/stats error:", err.message);
    res.status(500).json({ error: "Error fetching stats" });
  }
});

app.get("/session", (req, res) => res.json({ session_start: SESSION_START.toISOString() }));

app.delete("/logs/clear", async (req, res) => {
  try {
    await pool.query("DELETE FROM logs");
    await pool.query("DELETE FROM alerts");
    await pool.query("DELETE FROM site_visits");
    res.json({ status: "cleared" });
  } catch { res.status(500).json({ error: "Error clearing" }); }
});

app.get("/", (req, res) => res.send("AEGIS SIEM Backend v4 running"));

async function start() {
  await initDB();
  const PORT = process.env.PORT || 5000;
  server.listen(PORT, () => console.log(`Backend on http://localhost:${PORT}`));
}
start();
