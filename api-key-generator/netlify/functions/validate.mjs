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

export const handler = async (event) => {
  if (event.httpMethod !== "POST" && event.httpMethod !== "GET") {
    return json(405, { error: "Método no permitido" });
  }

  const key = extractKey(event);
  if (!key) return json(200, { valid: false, message: "No API key provided", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });

  try {
    const store = getStore({ name: "keys" });
    const raw = await store.get(key);
    if (!raw) {
      return json(200, { valid: false, message: "Clave no encontrada", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
    }
    const rec = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!rec.active) {
      return json(200, { valid: false, message: "Clave revocada", expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
    }
    return json(200, {
      valid: true,
      message: "OK",
      expiresAt: rec.expiresAt || -1,
      plan: rec.plan || "PREMIUM",
      serverId: rec.serverId || key,
      premiumFeaturesEnabled: true,
    });
  } catch (e) {
    return json(200, { valid: false, message: "Error de validación: " + e.message, expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false });
  }
};
