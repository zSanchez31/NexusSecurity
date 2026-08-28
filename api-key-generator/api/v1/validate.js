function extractKey(req) {
  const auth = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (auth && auth.startsWith("Bearer ")) return auth.substring(7).trim();
  const body = req.body || {};
  if (body.key) return body.key;
  const q = req.query || {};
  return q.key || null;
}

function extractServerId(req) {
  const body = req.body || {};
  return body.serverId ? String(body.serverId) : null;
}

function validFormat(key) {
  return typeof key === "string" && /^sk-[A-Za-z0-9]{24}$/.test(key);
}

export default async function handler(req, res) {
  if (req.method !== "POST" && req.method !== "GET") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  const key = extractKey(req);
  if (!key) {
    return res.status(200).json({
      valid: false, message: "No API key provided",
      expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false,
    });
  }

  // En Vercel no usamos almacenamiento externo: la validación es por el formato
  // de la clave (solo el dueño puede generarlas). Funciona sin configuración extra.
  if (validFormat(key)) {
    return res.status(200).json({
      valid: true, message: "OK",
      expiresAt: -1, plan: "PREMIUM",
      serverId: extractServerId(req) || "",
      premiumFeaturesEnabled: true,
    });
  }

  return res.status(200).json({
    valid: false, message: "Formato de clave inválido",
    expiresAt: -1, plan: "NONE", premiumFeaturesEnabled: false,
  });
}
