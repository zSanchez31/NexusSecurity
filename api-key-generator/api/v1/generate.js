const OWNER_PASSWORD = "NexusSecurity!";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

function generateKey() {
  let out = "sk-";
  for (let i = 0; i < 24; i++) {
    out += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
  }
  return out;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  const payload = req.body || {};

  if (payload.password !== OWNER_PASSWORD) {
    return res.status(401).json({ error: "Contraseña de propietario incorrecta." });
  }

  if (payload.verify) {
    return res.status(200).json({ ok: true });
  }

  const key = generateKey();
  return res.status(200).json({
    key,
    label: payload.label || "",
    expiresAt: Date.now() + ONE_YEAR_MS,
  });
}
