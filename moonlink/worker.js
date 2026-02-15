/**
 * MoonLink - Cloudflare Workers Link Shortener
 * Uses Cloudflare KV for storage
 *
 * KV Namespace binding: LINKS (bind in wrangler.toml)
 *
 * KV Key schema:
 *   link:{slug}      → JSON LinkRecord
 *   analytics:{slug} → JSON AnalyticsRecord
 *   meta:slugs       → JSON array of all slugs (for listing)
 */

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
const CONFIG = {
  ADMIN_TOKEN: "CHANGE_ME_STRONG_SECRET", // Set this via Cloudflare secret: wrangler secret put ADMIN_TOKEN
  BASE_URL: "https://short.moonim.live",
  SLUG_LENGTH: 6,
  MAX_CUSTOM_SLUG_LENGTH: 64,
  DEFAULT_TTL_DAYS: null, // null = no expiry
};

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function randomSlug(length = CONFIG.SLUG_LENGTH) {
  const chars = "abcdefghijkmnpqrstuvwxyz23456789";
  let result = "";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  for (const b of bytes) result += chars[b % chars.length];
  return result;
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      ...headers,
    },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function isExpired(record) {
  if (!record.expiresAt) return false;
  return Date.now() > record.expiresAt;
}

function getAdminToken(env) {
  return env.ADMIN_TOKEN || CONFIG.ADMIN_TOKEN;
}

function isAuthorized(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
  return token === getAdminToken(env);
}

// ─── KV HELPERS ───────────────────────────────────────────────────────────────
async function getLink(env, slug) {
  const raw = await env.LINKS.get(`link:${slug}`);
  return raw ? JSON.parse(raw) : null;
}

async function saveLink(env, slug, record) {
  await env.LINKS.put(`link:${slug}`, JSON.stringify(record));
}

async function deleteLink(env, slug) {
  await env.LINKS.delete(`link:${slug}`);
  await env.LINKS.delete(`analytics:${slug}`);
  // Remove from slug list
  const slugs = await getSlugs(env);
  const updated = slugs.filter((s) => s !== slug);
  await env.LINKS.put("meta:slugs", JSON.stringify(updated));
}

async function getSlugs(env) {
  const raw = await env.LINKS.get("meta:slugs");
  return raw ? JSON.parse(raw) : [];
}

async function addSlug(env, slug) {
  const slugs = await getSlugs(env);
  if (!slugs.includes(slug)) {
    slugs.unshift(slug);
    await env.LINKS.put("meta:slugs", JSON.stringify(slugs));
  }
}

async function getAnalytics(env, slug) {
  const raw = await env.LINKS.get(`analytics:${slug}`);
  return raw
    ? JSON.parse(raw)
    : { total: 0, recentClicks: [], countries: {} };
}

async function recordClick(env, slug, request) {
  const analytics = await getAnalytics(env, slug);
  analytics.total = (analytics.total || 0) + 1;

  const country =
    request.cf?.country || request.headers.get("CF-IPCountry") || "Unknown";
  analytics.countries[country] = (analytics.countries[country] || 0) + 1;

  // Keep last 100 clicks
  if (!analytics.recentClicks) analytics.recentClicks = [];
  analytics.recentClicks.unshift({
    timestamp: Date.now(),
    country,
    referer: request.headers.get("Referer") || "",
    ua: (request.headers.get("User-Agent") || "").slice(0, 100),
  });
  if (analytics.recentClicks.length > 100) analytics.recentClicks.length = 100;

  await env.LINKS.put(`analytics:${slug}`, JSON.stringify(analytics));
}

// ─── ROUTE HANDLERS ───────────────────────────────────────────────────────────

// GET /:slug  — redirect
async function handleRedirect(env, slug, request) {
  const record = await getLink(env, slug);

  if (!record) {
    return new Response("Link not found", { status: 404 });
  }

  if (isExpired(record)) {
    return new Response("This link has expired", { status: 410 });
  }

  // Password-protected: redirect to a gate page
  if (record.password) {
    const provided = new URL(request.url).searchParams.get("pw");
    if (!provided) {
      return new Response(passwordGatePage(slug), {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    }
    if (provided !== record.password) {
      return new Response(passwordGatePage(slug, true), {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    }
  }

  await recordClick(env, slug, request);
  return Response.redirect(record.destination, 302);
}

// POST /api/links — create a link
async function handleCreate(env, request) {
  if (!isAuthorized(request, env)) return errorResponse("Unauthorized", 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse("Invalid JSON");
  }

  const { destination, slug: customSlug, password, ttlDays } = body;

  if (!destination) return errorResponse("destination is required");

  // Validate URL
  try {
    new URL(destination);
  } catch {
    return errorResponse("Invalid destination URL");
  }

  let slug = customSlug ? customSlug.trim().toLowerCase() : randomSlug();

  // Validate custom slug
  if (customSlug) {
    if (!/^[a-z0-9_-]+$/i.test(slug)) {
      return errorResponse(
        "Slug can only contain letters, numbers, hyphens, underscores"
      );
    }
    if (slug.length > CONFIG.MAX_CUSTOM_SLUG_LENGTH) {
      return errorResponse(
        `Slug too long (max ${CONFIG.MAX_CUSTOM_SLUG_LENGTH} chars)`
      );
    }
  }

  // Collision check (retry for auto slugs)
  let attempt = 0;
  while (attempt < 5) {
    const existing = await getLink(env, slug);
    if (!existing) break;
    if (customSlug) return errorResponse("This slug is already taken");
    slug = randomSlug();
    attempt++;
  }

  const now = Date.now();
  const record = {
    destination,
    slug,
    password: password || null,
    createdAt: now,
    expiresAt: ttlDays ? now + ttlDays * 86400 * 1000 : null,
  };

  await saveLink(env, slug, record);
  await addSlug(env, slug);

  return jsonResponse({
    slug,
    shortUrl: `${CONFIG.BASE_URL}/${slug}`,
    ...record,
  });
}

// GET /api/links — list all links
async function handleList(env, request) {
  if (!isAuthorized(request, env)) return errorResponse("Unauthorized", 401);

  const slugs = await getSlugs(env);
  const links = await Promise.all(
    slugs.map(async (slug) => {
      const record = await getLink(env, slug);
      if (!record) return null;
      const analytics = await getAnalytics(env, slug);
      return {
        ...record,
        shortUrl: `${CONFIG.BASE_URL}/${slug}`,
        clicks: analytics.total,
        expired: isExpired(record),
      };
    })
  );

  return jsonResponse({ links: links.filter(Boolean) });
}

// GET /api/links/:slug/analytics
async function handleAnalytics(env, slug, request) {
  if (!isAuthorized(request, env)) return errorResponse("Unauthorized", 401);

  const record = await getLink(env, slug);
  if (!record) return errorResponse("Link not found", 404);

  const analytics = await getAnalytics(env, slug);
  return jsonResponse({
    slug,
    shortUrl: `${CONFIG.BASE_URL}/${slug}`,
    destination: record.destination,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analytics,
  });
}

// DELETE /api/links/:slug
async function handleDelete(env, slug, request) {
  if (!isAuthorized(request, env)) return errorResponse("Unauthorized", 401);

  const record = await getLink(env, slug);
  if (!record) return errorResponse("Link not found", 404);

  await deleteLink(env, slug);
  return jsonResponse({ success: true, slug });
}

// ─── PASSWORD GATE HTML ────────────────────────────────────────────────────────
function passwordGatePage(slug, wrongPassword = false) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Password Required</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0a0a0f;
    font-family: 'Syne', sans-serif;
    color: #e8e8f0;
  }
  .card {
    background: #13131a;
    border: 1px solid #2a2a3a;
    border-radius: 16px;
    padding: 48px;
    width: 100%;
    max-width: 420px;
    text-align: center;
  }
  .icon { font-size: 48px; margin-bottom: 24px; }
  h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
  p { color: #888; font-size: 14px; margin-bottom: 32px; }
  input {
    width: 100%; padding: 14px 18px;
    background: #0a0a0f; border: 1px solid ${wrongPassword ? "#ff4d6d" : "#2a2a3a"};
    border-radius: 10px; color: #e8e8f0; font-size: 16px;
    font-family: inherit; outline: none; margin-bottom: 16px;
  }
  input:focus { border-color: #7c6dfa; }
  .error { color: #ff4d6d; font-size: 13px; margin-bottom: 16px; }
  button {
    width: 100%; padding: 14px;
    background: #7c6dfa; border: none; border-radius: 10px;
    color: white; font-size: 16px; font-weight: 700;
    font-family: inherit; cursor: pointer;
  }
  button:hover { background: #6a5de0; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">🔒</div>
  <h1>Password Required</h1>
  <p>This link is protected. Enter the password to continue.</p>
  ${wrongPassword ? '<p class="error">Incorrect password. Try again.</p>' : ""}
  <form method="GET" action="/${slug}">
    <input type="password" name="pw" placeholder="Enter password" autofocus required>
    <button type="submit">Unlock →</button>
  </form>
</div>
</body>
</html>`;
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        },
      });
    }

    // API routes
    if (path.startsWith("/api/")) {
      // POST /api/links
      if (method === "POST" && path === "/api/links") {
        return handleCreate(env, request);
      }

      // GET /api/links
      if (method === "GET" && path === "/api/links") {
        return handleList(env, request);
      }

      // Analytics: GET /api/links/:slug/analytics
      const analyticsMatch = path.match(/^\/api\/links\/([^/]+)\/analytics$/);
      if (method === "GET" && analyticsMatch) {
        return handleAnalytics(env, analyticsMatch[1], request);
      }

      // Delete: DELETE /api/links/:slug
      const deleteMatch = path.match(/^\/api\/links\/([^/]+)$/);
      if (method === "DELETE" && deleteMatch) {
        return handleDelete(env, deleteMatch[1], request);
      }

      return errorResponse("Not found", 404);
    }

    // Root: serve admin UI (you'd serve from Pages or inline HTML)
    if (path === "/" || path === "") {
      return new Response("MoonLink API is running. Use the admin dashboard.", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // Slug redirect
    const slug = path.slice(1); // remove leading /
    if (slug && /^[a-z0-9_-]+$/i.test(slug)) {
      return handleRedirect(env, slug, request);
    }

    return new Response("Not found", { status: 404 });
  },
};
