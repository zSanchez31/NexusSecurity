import { getStore } from "@netlify/blobs";

// Contraseña de propietario (dueño). Cámbiala aquí directamente.
// Ya no hace falta configurarla en las variables de entorno de Netlify.
const OWNER_PASSWORD = "NexusSecurityAdmin";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

function generateKey() {
  let out = "sk-";
  for (let i = 0; i < 24; i++) {
    out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  }
  return out;
}

function json(status, body) {
  return {
    statusCode: status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    body: JSON.stringify(body),
  };
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
  if (event.httpMethod !== "POST") return json(405, { error: "Método no permitido" });

  let payload = {};
  try { payload = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "JSON inválido" }); }

  if (payload.password !== OWNER_PASSWORD) {
    return json(401, { error: "Contraseña de propietario incorrecta." });
  }

  // Modo verificación: solo comprobamos la contraseña, no creamos clave.
  if (payload.verify) return json(200, { ok: true });

  const key = generateKey();
  const record = {
    key,
    label: payload.label || "",
    createdAt: Date.now(),
    active: true,
    plan: "PREMIUM",
    expiresAt: Date.now() + ONE_YEAR_MS,
    boundServerId: "",
  };

  try {
    const store = getStore(blobOptions());
    await store.set(key, JSON.stringify(record), { metadata: { active: "true" } });
  } catch (e) {
    return json(500, { error: "No se pudo guardar la clave: " + e.message });
  }

  return json(200, { key, label: record.label, expiresAt: record.expiresAt });
};
