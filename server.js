import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import pg from "pg";

/**
 * HELM's self-hosted waitlist sink — demand data we OWN, no form vendor.
 *
 *   POST /join    {email, source?}  → stores the signup (idempotent per email)
 *   GET  /count                     → public counter for the landing page
 *   GET  /export?token=ADMIN_TOKEN  → full rows, control-plane only
 *   GET  /healthz                   → liveness
 *
 * Spam posture (validation-play grade, not bank grade): honeypot field,
 * per-IP rate limit, email shape check, unique-per-email. IPs are stored
 * only as truncated hashes — we count demand, we don't surveil it.
 */

const PORT = Number(process.env.PORT ?? 8080);
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL required");

const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  max: 5,
  // Render's external hostnames need TLS; internal ones don't speak it.
  ssl: /render\.com/.test(DATABASE_URL) ? { rejectUnauthorized: false } : undefined,
});
pool.on("error", (e) => console.error("pg idle error (recovered):", e.message));

await pool.query(`CREATE TABLE IF NOT EXISTS signups (
  id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email   TEXT NOT NULL UNIQUE,
  source  TEXT,
  ua      TEXT,
  ip_hash TEXT,
  at      TIMESTAMPTZ NOT NULL DEFAULT now()
)`);
await pool.query(`CREATE TABLE IF NOT EXISTS visits (
  id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source  TEXT,
  ua      TEXT,
  ip_hash TEXT,
  at      TIMESTAMPTZ NOT NULL DEFAULT now()
)`);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const hits = new Map(); // ip → recent timestamps (naive rate limit)

function cors(res) {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-allow-methods", "POST,GET,OPTIONS");
}

function json(res, code, body) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = createServer(async (req, res) => {
  cors(res);
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }
  try {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (req.method === "POST" && url.pathname === "/join") {
      const ip =
        String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() ||
        req.socket.remoteAddress ||
        "?";
      const now = Date.now();
      const recent = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
      if (recent.length >= 10) return json(res, 429, { ok: false, error: "slow down" });
      recent.push(now);
      hits.set(ip, recent);
      if (hits.size > 10_000) hits.clear(); // memory backstop

      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 10_000) {
          req.destroy();
          return;
        }
      }
      let data = {};
      if ((req.headers["content-type"] ?? "").includes("json")) {
        try {
          data = JSON.parse(body);
        } catch {
          /* fall through to validation */
        }
      } else {
        data = Object.fromEntries(new URLSearchParams(body));
      }

      // Honeypot: bots fill "website"; humans never see it. Pretend success.
      if (String(data.website ?? "").trim() !== "") return json(res, 200, { ok: true });

      const email = String(data.email ?? "").trim().toLowerCase();
      if (!EMAIL_RE.test(email) || email.length > 254) {
        return json(res, 400, { ok: false, error: "a valid email is required" });
      }
      const ipHash = createHash("sha256").update(ip).digest("hex").slice(0, 16);
      await pool.query(
        `INSERT INTO signups (email, source, ua, ip_hash) VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO NOTHING`,
        [
          email,
          String(data.source ?? "").slice(0, 100),
          String(req.headers["user-agent"] ?? "").slice(0, 300),
          ipHash,
        ],
      );
      const { rows } = await pool.query(`SELECT count(*)::int AS n FROM signups`);
      return json(res, 200, { ok: true, count: rows[0].n });
    }

    // One beacon per session from the landing page (sessionStorage-guarded
    // client-side). Unique visitors ≈ distinct ip_hash — the GO threshold is
    // conversion-based, so this denominator matters.
    if (req.method === "POST" && url.pathname === "/visit") {
      const ip =
        String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() ||
        req.socket.remoteAddress ||
        "?";
      const now = Date.now();
      const recent = (hits.get("v:" + ip) ?? []).filter((t) => now - t < 60_000);
      if (recent.length >= 20) return json(res, 429, { ok: false });
      recent.push(now);
      hits.set("v:" + ip, recent);
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 2_000) {
          req.destroy();
          return;
        }
      }
      let data = {};
      try {
        data = JSON.parse(body || "{}");
      } catch {
        /* beacon body optional */
      }
      const ipHash = createHash("sha256").update(ip).digest("hex").slice(0, 16);
      await pool.query(`INSERT INTO visits (source, ua, ip_hash) VALUES ($1, $2, $3)`, [
        String(data.source ?? "").slice(0, 100),
        String(req.headers["user-agent"] ?? "").slice(0, 300),
        ipHash,
      ]);
      return json(res, 200, { ok: true });
    }

    if (req.method === "GET" && url.pathname === "/stats") {
      const got = Buffer.from(url.searchParams.get("token") ?? "");
      const want = Buffer.from(process.env.ADMIN_TOKEN ?? "");
      if (!want.length || got.length !== want.length || !timingSafeEqual(got, want)) {
        return json(res, 401, { ok: false });
      }
      const { rows } = await pool.query(`SELECT
        (SELECT count(DISTINCT ip_hash)::int FROM visits) AS visitors,
        (SELECT count(*)::int FROM signups WHERE source IS DISTINCT FROM 'provision-smoke-test' AND email NOT LIKE '%@helm.internal') AS signups`);
      const { visitors, signups } = rows[0];
      return json(res, 200, {
        visitors,
        signups,
        conversion: visitors ? Number(((signups / visitors) * 100).toFixed(1)) : null,
      });
    }

    if (req.method === "GET" && url.pathname === "/count") {
      const { rows } = await pool.query(`SELECT count(*)::int AS n FROM signups`);
      return json(res, 200, { count: rows[0].n });
    }

    if (req.method === "GET" && url.pathname === "/export") {
      const got = Buffer.from(url.searchParams.get("token") ?? "");
      const want = Buffer.from(process.env.ADMIN_TOKEN ?? "");
      if (!want.length || got.length !== want.length || !timingSafeEqual(got, want)) {
        return json(res, 401, { ok: false });
      }
      const { rows } = await pool.query(`SELECT email, source, at FROM signups ORDER BY at`);
      return json(res, 200, rows);
    }

    if (url.pathname === "/healthz") {
      res.writeHead(200).end("ok");
      return;
    }
    res.writeHead(404).end();
  } catch (err) {
    console.error("request error:", err);
    json(res, 500, { ok: false, error: "server error" });
  }
});

server.listen(PORT, () => console.log(`waitlist up on :${PORT}`));
