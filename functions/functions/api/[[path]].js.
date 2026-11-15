const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}
async function makeToken(secret) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60,
    purpose: "nextmusicpty-admin",
  })));
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(payload));
  return payload + "." + base64url(new Uint8Array(signature));
}
async function validToken(request, secret) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  try {
    const ok = await crypto.subtle.verify(
      "HMAC", await hmacKey(secret), fromBase64url(parts[1]),
      new TextEncoder().encode(parts[0])
    );
    if (!ok) return false;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    return payload.purpose === "nextmusicpty-admin" && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}
function validExternalLink(value) {
  try {
    const u = new URL(value);
    return (u.protocol === "https:" || u.protocol === "http:") ? u.href : null;
  } catch {
    return null;
  }
}
function publicMix(row) {
  return {
    id: row.id,
    title: row.title,
    dj: row.dj,
    link: row.link,
    cover: row.cover_key ? `/api/covers/${encodeURIComponent(row.cover_key)}` : "",
    created_at: row.created_at,
  };
}
async function readMixForm(request) {
  const form = await request.formData();
  const title = String(form.get("title") || "").trim();
  const dj = String(form.get("dj") || "").trim();
  const link = validExternalLink(String(form.get("link") || "").trim());
  const cover = form.get("cover");
  if (!title || title.length > 100) throw new Error("Escribe un nombre de mix (máximo 100 caracteres).");
  if (!dj || dj.length > 70) throw new Error("Escribe el nombre del DJ (máximo 70 caracteres).");
  if (!link) throw new Error("El enlace debe comenzar con http:// o https://.");
  let coverFile = null;
  if (cover && typeof cover === "object" && "arrayBuffer" in cover && cover.size > 0) {
    if (cover.size > 5 * 1024 * 1024) throw new Error("La portada no puede pesar más de 5 MB.");
    const allowed = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp",
    };
    if (!allowed[cover.type]) throw new Error("La portada debe ser JPG, PNG o WEBP.");
    coverFile = { file: cover, extension: allowed[cover.type], type: cover.type };
  }
  return { title, dj, link, coverFile };
}
async function saveCover(env, coverFile) {
  if (!coverFile) return null;
  const key = `covers/${crypto.randomUUID()}.${coverFile.extension}`;
  await env.COVERS.put(key, await coverFile.file.arrayBuffer(), {
    httpMetadata: { contentType: coverFile.type, cacheControl: "public, max-age=31536000, immutable" },
  });
  return key;
}
async function onRequest({ request, env }) {
  try {
    if (!env.DB || !env.COVERS) return json({ error: "Faltan las conexiones DB o COVERS en Cloudflare Pages." }, 503);
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api\/?/, "");
    const method = request.method.toUpperCase();

    if (path.startsWith("covers/") && method === "GET") {
      const key = decodeURIComponent(path.slice("covers/".length));
      if (!key.startsWith("covers/") || key.includes("..")) return json({ error: "Portada no válida." }, 400);
      const object = await env.COVERS.get(key);
      if (!object) return new Response("No encontrada", { status: 404 });
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("ETag", object.httpEtag);
      headers.set("Cache-Control", "public, max-age=31536000, immutable");
      return new Response(object.body, { headers });
    }

    if (path === "login" && method === "POST") {
      if (!env.ADMIN_PASSWORD || !env.AUTH_SECRET) return json({ error: "Faltan los secretos de administrador en Cloudflare." }, 503);
      const body = await request.json().catch(() => ({}));
      const supplied = String(body.password || "");
      if (supplied !== env.ADMIN_PASSWORD) return json({ error: "Contraseña incorrecta." }, 401);
      return json({ token: await makeToken(env.AUTH_SECRET) });
    }

    if (path === "mixes" && method === "GET") {
      const result = await env.DB.prepare(
        "SELECT id, title, dj, link, cover_key, created_at FROM mixes ORDER BY created_at DESC, id DESC"
      ).all();
      return json((result.results || []).map(publicMix));
    }

    const isMixItem = /^mixes\/\d+$/.test(path);
    if ((path === "mixes" && method === "POST") || (isMixItem && ["PUT", "DELETE"].includes(method))) {
      if (!env.ADMIN_PASSWORD || !env.AUTH_SECRET || !(await validToken(request, env.AUTH_SECRET))) {
        return json({ error: "Tu sesión venció. Vuelve a entrar al administrador." }, 401);
      }

      if (path === "mixes" && method === "POST") {
        const data = await readMixForm(request);
        const coverKey = await saveCover(env, data.coverFile);
        const createdAt = Math.floor(Date.now() / 1000);
        const result = await env.DB.prepare(
          "INSERT INTO mixes (title, dj, link, cover_key, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id, title, dj, link, cover_key, created_at"
        ).bind(data.title, data.dj, data.link, coverKey, createdAt).first();
        return json(publicMix(result), 201);
      }

      const id = Number(path.split("/")[1]);
      const current = await env.DB.prepare(
        "SELECT id, title, dj, link, cover_key, created_at FROM mixes WHERE id = ?"
      ).bind(id).first();
      if (!current) return json({ error: "Ese mix no existe." }, 404);

      if (method === "DELETE") {
        // No se borran objetos de R2: así evitamos eliminar archivos por accidente.
        await env.DB.prepare("DELETE FROM mixes WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }

      const data = await readMixForm(request);
      const newCoverKey = await saveCover(env, data.coverFile);
      const coverKey = newCoverKey || current.cover_key;
      const result = await env.DB.prepare(
        "UPDATE mixes SET title = ?, dj = ?, link = ?, cover_key = ? WHERE id = ? RETURNING id, title, dj, link, cover_key, created_at"
      ).bind(data.title, data.dj, data.link, coverKey, id).first();
      return json(publicMix(result));
    }

    return json({ error: "Ruta no encontrada." }, 404);
  } catch (error) {
    return json({ error: error?.message || "Error interno." }, 400);
  }
}
export const onRequestGet = onRequest;
export const onRequestPost = onRequest;
export const onRequestPut = onRequest;
export const onRequestDelete = onRequest;
