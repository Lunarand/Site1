export async function onRequest(context) {    
  const { request, env } = context;    
  const url = new URL(request.url);    
  const path = url.pathname.replace(/^\/api\/?/, ""); // "" or "posts/123"    
  const method = request.method.toUpperCase();    
    
  // ---------- CORS ----------    
  if (method === "OPTIONS") {    
    return withCors(new Response(null, { status: 204 }));    
  }    
    
  try {    
    // ---------- ROUTES ----------    
    // Status    
    if (method === "GET" && (path === "" || path === "status")) {    
      const maintenance = await getMaintenance(env);    
      return json({ maintenance }, 200);    
    }    
    
    // Login (admin)    
    if (method === "POST" && path === "login") {    
      const body = await safeJson(request);    
      const password = String(body?.password || "").trim();    
      const adminPass = String(env.ADMIN_PASSWORD || "").trim();    
    
      if (!adminPass || adminPass === "change-this-password") {    
        return json({ success: false, error: "ADMIN_PASSWORD is not set" }, 400);    
      }    
    
      if (password !== adminPass) {    
        return json({ success: false }, 200);    
      }    
    
      const token = crypto.randomUUID();    
      await env.DB.put(`admin:token:${token}`, "1", { expirationTtl: 60 * 60 * 24 * 14 }); // 14 days    
      return json({ success: true, token }, 200);    
    }    
    
    // Posts list    
    if (method === "GET" && path === "posts") {    
      const posts = await listPosts(env);    
      return json(posts, 200);    
    }    
    
    // Get single post    
    if (method === "GET" && path.startsWith("posts/")) {    
      const parts = path.split("/");    
      const id = parts[1];    
      const post = await getPost(env, id);    
      if (!post) return json({ error: "Post not found" }, 404);    
      return json(post, 200);    
    }    
    
    // Like    
    if (method === "POST" && path.match(/^posts\/[^/]+\/like$/)) {    
      const id = path.split("/")[1];    
      const maintenance = await getMaintenance(env);    
      if (maintenance && !(await isAdmin(request, env))) {    
        return json({ error: "Maintenance mode" }, 403);    
      }    
      const updated = await bumpReaction(env, id, "like");    
      if (!updated) return json({ error: "Post not found" }, 404);    
      return json({ likes: updated.likes, dislikes: updated.dislikes }, 200);    
    }    
    
    // Dislike    
    if (method === "POST" && path.match(/^posts\/[^/]+\/dislike$/)) {    
      const id = path.split("/")[1];    
      const maintenance = await getMaintenance(env);    
      if (maintenance && !(await isAdmin(request, env))) {    
        return json({ error: "Maintenance mode" }, 403);    
      }    
      const updated = await bumpReaction(env, id, "dislike");    
      if (!updated) return json({ error: "Post not found" }, 404);    
      return json({ likes: updated.likes, dislikes: updated.dislikes }, 200);    
    }    
    
    // Comment    
    if (method === "POST" && path.match(/^posts\/[^/]+\/comment$/)) {    
      const id = path.split("/")[1];    
    
      const maintenance = await getMaintenance(env);    
      if (maintenance && !(await isAdmin(request, env))) {    
        return json({ error: "Maintenance mode" }, 403);    
      }    
    
      const banIp = await isBanned(request, env);    
      if (banIp && !(await isAdmin(request, env))) {    
        return json({ error: "You are banned" }, 403);    
      }    
    
      const body = await safeJson(request);    
      const text = String(body?.text || "").trim();    
      if (!text) return json({ error: "Empty comment" }, 400);    
    
      const updated = await addComment(env, id, text);    
      if (!updated) return json({ error: "Post not found" }, 404);    
    
      return json({ ok: true, comments: updated.comments.length }, 200);    
    }    
    
    // Report    
    if (method === "POST" && path.match(/^posts\/[^/]+\/report$/)) {    
      const id = path.split("/")[1];    
    
      const maintenance = await getMaintenance(env);    
      if (maintenance && !(await isAdmin(request, env))) {    
        return json({ error: "Maintenance mode" }, 403);    
      }    
    
      const banIp = await isBanned(request, env);    
      if (banIp && !(await isAdmin(request, env))) {    
        return json({ error: "You are banned" }, 403);    
      }    
    
      const body = await safeJson(request);    
      const reason = String(body?.reason || "Spam");    
      const message = String(body?.message || "").trim();    
    
      await addReport(env, request, id, reason, message);    
      return json({ ok: true }, 200);    
    }    
    
    // Upload (create post) - multipart form data    
    if (method === "POST" && path === "upload") {    
      const maintenance = await getMaintenance(env);    
      if (maintenance && !(await isAdmin(request, env))) {    
        return json({ error: "Maintenance mode" }, 403);    
      }    
    
      const banIp = await isBanned(request, env);    
      if (banIp && !(await isAdmin(request, env))) {    
        return json({ error: "You are banned" }, 403);    
      }    
    
      const form = await request.formData();    
      const title = String(form.get("title") || "").trim();    
      const text = String(form.get("text") || "").trim();    
    
      // collect files (multiple "files")    
      const files = form.getAll("files").filter(Boolean);    
    
      const postId = crypto.randomUUID();    
      const createdAt = new Date().toISOString();    
    
      const ownerIp = getClientIp(request);    
    
      const attachments = [];    
      for (const f of files) {    
        // f can be a File    
        if (!(f instanceof File)) continue;    
    
        const buf = await f.arrayBuffer();    
        const size = buf.byteLength;    
    
        // KV file limit is 25 MiB 1    
        if (size > 25 * 1024 * 1024) {    
          return json({ error: `File too large (max 25MB): ${f.name}` }, 400);    
        }    
    
        const fileKey = `file:${postId}:${crypto.randomUUID()}`;    
        // store bytes as base64 (KV stores strings)    
        const b64 = arrayBufferToBase64(buf);    
    
        await env.DB.put(fileKey, b64);    
    
        const kind = kindFromMime(f.type);    
        attachments.push({    
          key: fileKey,    
          url: `/api/file/${encodeURIComponent(fileKey)}`,    
          kind,    
          name: f.name || "file",    
          mimetype: f.type || "application/octet-stream",    
          size    
        });    
      }    
    
      const post = {    
        id: postId,    
        title: title || "Untitled",    
        text: text || "",    
        date: createdAt,    
        likes: 0,    
        dislikes: 0,    
        comments: [],    
        attachments,    
        ownerIp    
      };    
    
      await env.DB.put(`post:${postId}`, JSON.stringify(post));    
      await addPostToIndex(env, postId);    
    
      return json({ ok: true, id: postId }, 200);    
    }    
    
    // Serve stored file    
    if (method === "GET" && path.startsWith("file/")) {    
      const key = decodeURIComponent(path.slice("file/".length));    
      if (!key.startsWith("file:")) return new Response("Not found", { status: 404 });    
    
      const b64 = await env.DB.get(key);    
      if (!b64) return new Response("Not found", { status: 404 });    
    
      // try read metadata from posts (to set correct mimetype + filename)    
      const meta = await findFileMeta(env, key);    
    
      const bytes = base64ToUint8Array(b64);    
      const headers = new Headers();    
      headers.set("Content-Type", meta?.mimetype || "application/octet-stream");    
    
      // inline so images/videos open properly    
      const safeName = (meta?.name || "file").replace(/["\\]/g, "");    
      headers.set("Content-Disposition", `inline; filename="${safeName}"`);    
      headers.set("Cache-Control", "public, max-age=31536000, immutable");    
    
      return withCors(new Response(bytes, { status: 200, headers }));    
    }    
    
    // ---------- ADMIN API ----------    
    if (path === "admin/status" && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
    
      const maintenance = await getMaintenance(env);    
      const banned = await getBans(env);    
      const reports = await getReports(env);    
      return json({    
        maintenance,    
        bannedCount: banned.length,    
        reportsCount: reports.length    
      }, 200);    
    }    
    
    if (path === "admin/posts" && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const posts = await listPosts(env, { includePrivate: true });    
      // includePrivate shows ownerIp    
      const full = [];    
      for (const p of posts) {    
        const post = await getPost(env, p.id);    
        if (post) full.push(post);    
      }    
      return json(full, 200);    
    }    
    
    if (path.match(/^admin\/posts\/[^/]+$/) && method === "DELETE") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const id = path.split("/")[2];    
      const ok = await deletePost(env, id);    
      if (!ok) return json({ error: "Not found" }, 404);    
      return json({ ok: true }, 200);    
    }    
    
    if (path.match(/^admin\/posts\/[^/]+\/details$/) && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const id = path.split("/")[2];    
      const post = await getPost(env, id);    
      if (!post) return json({ error: "Not found" }, 404);    
    
      // return minimal safety info that your frontend expects    
      return json({    
        ip: post.ownerIp || null,    
        device: { type: "unknown" },    
        browser: { name: "unknown" },    
        os: { name: "unknown" },    
        network: { acceptLanguage: request.headers.get("accept-language") || "unknown" },    
        geo: {} // optional, can add later if you want    
      }, 200);    
    }    
    
    if (path.match(/^admin\/posts\/[^/]+\/comments\/[^/]+\/details$/) && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const postId = path.split("/")[2];    
      const post = await getPost(env, postId);    
      if (!post) return json({ error: "Not found" }, 404);    
    
      return json({    
        ip: post.ownerIp || null,    
        device: { type: "unknown" },    
        browser: { name: "unknown" },    
        os: { name: "unknown" },    
        network: { acceptLanguage: request.headers.get("accept-language") || "unknown" },    
        geo: {}    
      }, 200);    
    }    
    
    if (path === "admin/reports" && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const reports = await getReports(env);    
      return json(reports, 200);    
    }    
    
    if (path.match(/^admin\/reports\/[^/]+\/ignore$/) && method === "POST") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const rid = path.split("/")[2];    
      await ignoreReport(env, rid);    
      return json({ ok: true }, 200);    
    }    
    
    if (path === "admin/bans" && method === "GET") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const banned = await getBans(env);    
      return json({ banned }, 200);    
    }    
    
    if (path === "admin/ban" && method === "POST") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const body = await safeJson(request);    
      const ip = String(body?.ip || "").trim();    
      if (!ip) return json({ error: "Missing ip" }, 400);    
      await banIp(env, ip);    
      return json({ ok: true }, 200);    
    }    
    
    if (path === "admin/unban" && method === "POST") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const body = await safeJson(request);    
      const ip = String(body?.ip || "").trim();    
      if (!ip) return json({ error: "Missing ip" }, 400);    
      await unbanIp(env, ip);    
      return json({ ok: true }, 200);    
    }    
    
    if (path === "admin/maintenance" && method === "POST") {    
      if (!(await isAdmin(request, env))) return json({ error: "Admin only" }, 403);    
      const body = await safeJson(request);    
      const enabled = !!body?.enabled;    
      await env.DB.put("maintenance", enabled ? "1" : "0");    
      return json({ ok: true, maintenance: enabled }, 200);    
    }    
    
    // Not found    
    return withCors(new Response("Not found", { status: 404 }));    
    
  } catch (err) {    
    return json({ error: "Server error", detail: String(err?.message || err) }, 500);    
  }    
}    
    
/* -------------------- helpers -------------------- */    
    
function withCors(res) {    
  const h = new Headers(res.headers);    
  h.set("Access-Control-Allow-Origin", "*");    
  h.set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");    
  h.set("Access-Control-Allow-Headers", "Content-Type, x-admin-token");    
  return new Response(res.body, { status: res.status, headers: h });    
}    
    
function json(obj, status = 200) {    
  return withCors(new Response(JSON.stringify(obj), {    
    status,    
    headers: { "Content-Type": "application/json" }    
  }));    
}    
    
async function safeJson(request) {    
  try { return await request.json(); } catch { return {}; }    
}    
    
function getClientIp(request) {    
  return request.headers.get("cf-connecting-ip") ||    
         request.headers.get("x-forwarded-for") ||    
         "unknown";    
}    
    
function kindFromMime(mime) {    
  const t = String(mime || "").toLowerCase();    
  if (t.startsWith("image/")) return "image";    
  if (t.startsWith("video/")) return "video";    
  if (t.startsWith("audio/")) return "audio";    
  return "file";    
}    
    
function arrayBufferToBase64(buffer) {    
  const bytes = new Uint8Array(buffer);    
  let bin = "";    
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);    
  return btoa(bin);    
}    
    
function base64ToUint8Array(b64) {    
  const bin = atob(b64);    
  const out = new Uint8Array(bin.length);    
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);    
  return out;    
}    
    
/* -------------------- storage model --------------------    
KV keys:    
- post:<id>                    -> JSON post    
- posts:index                  -> JSON array of post ids (newest first)    
- maintenance                  -> "1" or "0"    
- bans                         -> JSON array of IPs    
- reports:index                -> JSON array of report ids (newest first)    
- report:<rid>                 -> JSON report object    
- admin:token:<token>          -> "1" (TTL)    
- file:<postId>:<uuid>         -> base64 bytes    
-------------------------------------------------------- */    
    
async function getMaintenance(env) {    
  const v = await env.DB.get("maintenance");    
  return v === "1";    
}    
    
async function getIndex(env) {    
  const raw = await env.DB.get("posts:index");    
  if (!raw) return [];    
  try { return JSON.parse(raw); } catch { return []; }    
}    
    
async function setIndex(env, arr) {    
  await env.DB.put("posts:index", JSON.stringify(arr.slice(0, 500))); // keep latest 500 posts    
}    
    
async function addPostToIndex(env, id) {    
  const idx = await getIndex(env);    
  idx.unshift(id);    
  await setIndex(env, dedupe(idx));    
}    
    
function dedupe(arr) {    
  const seen = new Set();    
  const out = [];    
  for (const x of arr) {    
    if (seen.has(x)) continue;    
    seen.add(x);    
    out.push(x);    
  }    
  return out;    
}    
    
async function listPosts(env, opts = {}) {    
  const includePrivate = !!opts.includePrivate;    
  const ids = await getIndex(env);    
    
  const posts = [];    
  for (const id of ids) {    
    const post = await getPost(env, id);    
    if (!post) continue;    
    
    // list view expects comments count number, not array    
    posts.push({    
      id: post.id,    
      title: post.title,    
      text: post.text,    
      date: post.date,    
      likes: post.likes || 0,    
      dislikes: post.dislikes || 0,    
      comments: Array.isArray(post.comments) ? post.comments.length : 0,    
      attachments: Array.isArray(post.attachments) ? post.attachments : [],    
      ...(includePrivate ? { ownerIp: post.ownerIp || null } : {})    
    });    
  }    
  return posts;    
}    
    
async function getPost(env, id) {    
  const raw = await env.DB.get(`post:${id}`);    
  if (!raw) return null;    
  try { return JSON.parse(raw); } catch { return null; }    
}    
    
async function savePost(env, post) {    
  await env.DB.put(`post:${post.id}`, JSON.stringify(post));    
}    
    
async function bumpReaction(env, id, kind) {    
  const post = await getPost(env, id);    
  if (!post) return null;    
  if (kind === "like") post.likes = (post.likes || 0) + 1;    
  if (kind === "dislike") post.dislikes = (post.dislikes || 0) + 1;    
  await savePost(env, post);    
  return post;    
}    
    
async function addComment(env, id, text) {    
  const post = await getPost(env, id);    
  if (!post) return null;    
  if (!Array.isArray(post.comments)) post.comments = [];    
    
  post.comments.push({    
    id: Date.now(),    
    text,    
    date: new Date().toISOString()    
  });    
    
  await savePost(env, post);    
  return post;    
}    
    
async function deletePost(env, id) {    
  const post = await getPost(env, id);    
  if (!post) return false;    
    
  // delete attached files    
  const at = Array.isArray(post.attachments) ? post.attachments : [];    
  for (const a of at) {    
    if (a?.key && String(a.key).startsWith("file:")) {    
      await env.DB.delete(a.key);    
    }    
  }    
    
  await env.DB.delete(`post:${id}`);    
    
  // remove from index    
  const idx = await getIndex(env);    
  await setIndex(env, idx.filter(x => x !== id));    
    
  return true;    
}    
    
async function findFileMeta(env, key) {    
  // quick scan newest posts for this key (small usage, fine for 10–15 users)    
  const ids = await getIndex(env);    
  for (const id of ids.slice(0, 80)) {    
    const post = await getPost(env, id);    
    if (!post) continue;    
    const at = Array.isArray(post.attachments) ? post.attachments : [];    
    const found = at.find(x => x.key === key);    
    if (found) return found;    
  }    
  return null;    
}    
    
/* -------------------- admin / bans -------------------- */    
    
async function isAdmin(request, env) {    
  const token = request.headers.get("x-admin-token");    
  if (!token) return false;    
  const v = await env.DB.get(`admin:token:${token}`);    
  return v === "1";    
}    
    
async function getBans(env) {    
  const raw = await env.DB.get("bans");    
  if (!raw) return [];    
  try { return JSON.parse(raw); } catch { return []; }    
}    
    
async function setBans(env, arr) {    
  await env.DB.put("bans", JSON.stringify(dedupe(arr)));    
}    
    
async function isBanned(request, env) {    
  const ip = getClientIp(request);    
  const banned = await getBans(env);    
  return banned.includes(ip);    
}    
    
async function banIp(env, ip) {    
  const banned = await getBans(env);    
  banned.push(ip);    
  await setBans(env, banned);    
}    
    
async function unbanIp(env, ip) {    
  const banned = await getBans(env);    
  await setBans(env, banned.filter(x => x !== ip));    
}    
    
/* -------------------- reports -------------------- */    
    
async function getReportIndex(env) {    
  const raw = await env.DB.get("reports:index");    
  if (!raw) return [];    
  try { return JSON.parse(raw); } catch { return []; }    
}    
    
async function setReportIndex(env, arr) {    
  await env.DB.put("reports:index", JSON.stringify(arr.slice(0, 500)));    
}    
    
async function addReport(env, request, postId, reason, message) {    
  const rid = crypto.randomUUID();    
  const reporterIp = getClientIp(request);    
    
  const post = await getPost(env, postId);    
    
  const report = {    
    id: rid,    
    postId,    
    reason,    
    message,    
    timestamp: new Date().toISOString(),    
    reporterIp,    
    post: post    
      ? {    
          id: post.id,    
          title: post.title,    
          text: post.text,    
          ownerIp: post.ownerIp || null    
        }    
      : null    
  };    
    
  await env.DB.put(`report:${rid}`, JSON.stringify(report));    
    
  const idx = await getReportIndex(env);    
  idx.unshift(rid);    
  await setReportIndex(env, dedupe(idx));    
}    
    
async function getReports(env) {    
  const idx = await getReportIndex(env);    
  const out = [];    
  for (const rid of idx) {    
    const raw = await env.DB.get(`report:${rid}`);    
    if (!raw) continue;    
    try { out.push(JSON.parse(raw)); } catch {}    
  }    
  return out;    
}    
    
async function ignoreReport(env, rid) {    
  await env.DB.delete(`report:${rid}`);    
  const idx = await getReportIndex(env);    
  await setReportIndex(env, idx.filter(x => x !== rid));    
}
