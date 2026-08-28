import { getStore } from "@netlify/blobs";

function json(status, body) {
  return {
    statusCode: status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    body: JSON.stringify(body),
  };
}

function extractKey(event) {
  const auth = event.headers && (event.headers.authorization || event.headers.Authorization);
  if (auth && auth.startsWith("Bearer ")) return auth.substring(7).trim();
  try {
    const body = JSON.parse(event.body || "{}");
    if (body.key) return body.key;
  } catch { /* ignore */ }
  const q = event.queryStringParameters || {};
  return q.key || null;
}

function extractServerId(event) {
  try {
    const body = JSON.parse(event.body || "{}");
    if (body.serverId) return String(body.serverId);
  } catch { /* ignore */ }
  return null;
}

// Netlify inyecta SITE_ID y NETLIFY_BLOBS_TOKEN automáticamente en los deploys
// enlazados; si no, se leen de las variables de entorno que configures tú.
function blobOptions() {
  const opts = { name: "keys" };
  if (process.env.SITE_ID) opts.siteID = process.env.SITE_ID;
  if (process.env.NETLIFY_BLOBS_TOKEN) opts.token = process.env.NETLIFY_BLOBS_TOKEN;
  return opts;
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST" && event.httpMethod !== "GET") {
    return json(405, { error: "Método no permitido" });
  }

  const key = extractKey(event);
  if (!key) return json(200, { valid: false, message: "No API key provided", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });

  try {
    const store = getStore(blobOptions());
    const raw = await store.get(key);
    if (!raw) {
      return json(200, { valid: false, message: "Clave no encontrada", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
    }
    const rec = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!rec.active) {
      return json(200, { valid: false, message: "Clave revocada", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
    }

    // Vincular la clave a un único servidor: la primera validación exitosa la
    // "reclama"; si otro serverId intenta usarla, se rechaza (una clave por servidor).
    const serverId = extractServerId(event);
    if (!rec.boundServerId) {
      rec.boundServerId = serverId || "unknown";
      await store.set(key, JSON.stringify(rec), { metadata: { active: "true" } });
    } else if (serverId && rec.boundServerId !== serverId) {
      return json(200, { valid: false, message: "Clave ya en uso en otro servidor", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
    }

    if (rec.expiresAt && rec.expiresAt < Date.now()) {
      return json(200, { valid: false, message: "Suscripción expirada", expiresAt: rec.expiresAt, plan: rec.plan, premiumFeaturesEnabled: false });
    }

    return json(200, {
      valid: true,
      message: "OK",
      expiresAt: rec.expiresAt || -1,
      plan: rec.plan || "PREMIUM",
      serverId: rec.boundServerId,
      premiumFeaturesEnabled: true,
    });
  } catch (e) {
    return json(200, { valid: false, message: "Error de validación: " + e.message, expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
  }
};
