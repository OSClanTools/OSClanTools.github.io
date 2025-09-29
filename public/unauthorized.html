// server.js
// Discord-only auth that only grants access if the user is ADMIN in at least one guild
// that the bot is also in. Includes backend audit logging and simple ACP route.

const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const express = require("express");
const cookieSession = require("cookie-session");
const crypto = require("crypto");

// ── ENV ─────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const APP_SESSION_SECRET = process.env.APP_SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`; // e.g., https://yourdomain.com

// Discord OAuth app creds (app/client, not the bot)
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "YOUR_CLIENT_ID";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "YOUR_CLIENT_SECRET";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `${BASE_URL}/auth/callback`;

// Bot token (used to determine which guilds the bot is in)
// If the API call fails in your environment, you can set BOT_GUILD_IDS as a fallback.
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const BOT_GUILD_IDS = (process.env.BOT_GUILD_IDS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// Optional: send audit lines to a Discord webhook (e.g., your admin log sink)
const ADMIN_AUDIT_WEBHOOK_URL = process.env.ADMIN_AUDIT_WEBHOOK_URL || "";

// ── Helpers ────────────────────────────────────────────────────────────────────
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));

app.use(
  cookieSession({
    name: "sess",
    keys: [APP_SESSION_SECRET],
    sameSite: "lax",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 12 // 12h
  })
);

const PUBLIC_DIR = path.join(process.cwd(), "public");
const DATA_DIR = path.join(process.cwd(), "data");
const LOG_DIR = path.join(DATA_DIR, "logs");
const AUDIT_LOG_PATH = path.join(LOG_DIR, "admin-portal.log");

async function ensureDirs() {
  await fsp.mkdir(LOG_DIR, { recursive: true }).catch(() => {});
}
ensureDirs().catch(() => {});

function nowISO() {
  return new Date().toISOString();
}

// Admin permission bit on Discord (bit 3 => value 0x8)
const PERM_ADMIN = 1n << 3n;

function hasAdminPerm(permString, ownerFlag) {
  if (ownerFlag) return true;
  try {
    const n = BigInt(permString);
    return (n & PERM_ADMIN) !== 0n;
  } catch {
    return false;
  }
}

async function postWebhook(text) {
  if (!ADMIN_AUDIT_WEBHOOK_URL) return;
  try {
    await fetch(ADMIN_AUDIT_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: text.slice(0, 1900) })
    });
  } catch {
    // ignore webhook errors
  }
}

async function audit(event, meta = {}) {
  const line = {
    ts: nowISO(),
    event,
    meta
  };
  const text = JSON.stringify(line) + "\n";
  try {
    await fsp.appendFile(AUDIT_LOG_PATH, text);
  } catch (e) {
    // last-ditch: log to console
    console.warn("[AUDIT APPEND FAIL]", e);
  }
  // Optional webhook mirror
  const pretty = `**[ACP]** ${event}\n\`\`\`json\n${JSON.stringify(meta, null, 2)}\n\`\`\``;
  await postWebhook(pretty);
}

// Fetch JSON helper (Node 18+ has global fetch)
async function getJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    const err = new Error(`HTTP ${res.status} for ${url}: ${t}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Try to fetch bot's guilds; if not allowed, falls back to env list
async function getBotGuildIds() {
  if (!DISCORD_BOT_TOKEN) return BOT_GUILD_IDS;
  try {
    const list = await getJSON("https://discord.com/api/users/@me/guilds", {
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    });
    const ids = Array.isArray(list) ? list.map(g => g.id).filter(Boolean) : [];
    return ids.length ? ids : BOT_GUILD_IDS;
  } catch {
    return BOT_GUILD_IDS;
  }
}

function buildAuthURL(state = "") {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    scope: "identify guilds",
    redirect_uri: DISCORD_REDIRECT_URI,
    prompt: "consent",
    state
  });
  return `https://discord.com/api/oauth2/authorize?${params.toString()}`;
}

// ── Auth Routes ────────────────────────────────────────────────────────────────
app.get("/auth/login", (req, res) => {
  const url = buildAuthURL(crypto.randomUUID());
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    await audit("login_denied", { ip: req.ip, reason: error || "missing_code" });
    return res.redirect("/?auth=denied");
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    if (!tokenRes.ok) {
      const t = await tokenRes.text();
      throw new Error(`Token exchange failed: ${t}`);
    }
    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;
    const tokenType = tokenData.token_type || "Bearer";

    // Get user and user guilds
    const headers = { Authorization: `${tokenType} ${accessToken}` };
    const me = await getJSON("https://discord.com/api/users/@me", { headers });
    const userGuilds = await getJSON("https://discord.com/api/users/@me/guilds", { headers });

    // Bot guilds
    const botGuildIds = await getBotGuildIds();

    // Find mutual guilds where user has ADMIN (or is owner)
    const eligibleGuilds = (Array.isArray(userGuilds) ? userGuilds : []).filter(g => {
      const mutual = botGuildIds.includes(g.id);
      const isAdmin = hasAdminPerm(g.permissions, !!g.owner);
      return mutual && isAdmin;
    });

    if (!eligibleGuilds.length) {
      await audit("login_rejected_not_admin_mutual", {
        ip: req.ip,
        user: { id: me.id, username: `${me.username}#${me.discriminator ?? "0000"}` }
      });
      // clear session if any
      req.session = null;
      return res.redirect("/?auth=denied");
    }

    // Store minimal session
    req.session = {
      user: {
        id: me.id,
        username: me.username,
        discriminator: me.discriminator ?? "0000",
        avatar: me.avatar || null
      },
      adminGuilds: eligibleGuilds.map(g => ({ id: g.id, name: g.name })),
      isAdmin: true,
      ts: Date.now()
    };

    await audit("login_success", {
      ip: req.ip,
      user: { id: me.id, username: `${me.username}#${me.discriminator ?? "0000"}` },
      guilds: eligibleGuilds.map(g => ({ id: g.id, name: g.name }))
    });

    res.redirect("/admin");
  } catch (e) {
    await audit("login_error", { ip: req.ip, error: String(e && e.message || e) });
    res.redirect("/?auth=error");
  }
});

app.post("/auth/logout", (req, res) => {
  if (req.session?.user) {
    audit("logout", { user: req.session.user }).catch(() => {});
  }
  req.session = null;
  res.json({ ok: true });
});

app.get("/auth/me", (req, res) => {
  const u = req.session?.user || null;
  const isAdmin = !!req.session?.isAdmin;
  res.json({
    loggedIn: !!u && isAdmin,
    isAdmin,
    user: u,
    adminGuilds: req.session?.adminGuilds || []
  });
});

// ── Auth Guard ────────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session?.isAdmin && req.session?.user) return next();
  return res.status(401).sendFile(path.join(PUBLIC_DIR, "unauthorized.html"));
}

// ── Audit Endpoint (front-end calls) ──────────────────────────────────────────
app.post("/audit", requireAdmin, async (req, res) => {
  const payload = req.body || {};
  const user = req.session.user;
  const fromIP = req.ip;
  await audit("fe_event", {
    user,
    ip: fromIP,
    ...payload
  });
  res.json({ ok: true });
});

// ── Static + ACP route ────────────────────────────────────────────────────────
app.use(express.static(PUBLIC_DIR, { extensions: ["html"] }));

app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "admin.html"));
});

app.listen(PORT, () => {
  console.log(`[Web] http://localhost:${PORT}`);
  console.log(`BASE_URL=${BASE_URL}`);
});
