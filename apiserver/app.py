# NexusSecurity API Server — FastAPI
# Web de prueba para generar y gestionar las API keys que valida el plugin.
#
# Endpoints:
#   GET  /               -> Web UI para generar/revocar claves
#   POST /v1/validate    -> Endpoint que llama el plugin (Authorization: Bearer <key>)
#   POST /v1/keys        -> Crear una clave (JSON)
#   GET  /v1/keys        -> Listar claves
#   DELETE /v1/keys/{id} -> Revocar clave
#
# Ejecutar en local:
#   pip install -r requirements.txt
#   uvicorn app:app --reload --port 8000

import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional

DB_PATH = Path(__file__).parent / "keys.db"
PLANS = {"FREE": 30, "BASIC": 90, "PRO": 365, "LIFETIME": 36500}


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                id TEXT PRIMARY KEY,
                api_key TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL,
                owner TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )
            """
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="NexusSecurity API", lifespan=lifespan)


def generate_key() -> str:
    raw = secrets.token_hex(8).upper()
    return f"NXS-{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def response_json(api_key: str) -> dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE api_key = ?", (api_key,)).fetchone()
    if row is None:
        return {"valid": False, "message": "API key not found", "expiresAt": -1,
                "plan": "NONE", "serverId": None, "premiumFeaturesEnabled": False}
    if row["revoked"]:
        return {"valid": False, "message": "API key revoked", "expiresAt": -1,
                "plan": "NONE", "serverId": None, "premiumFeaturesEnabled": False}
    if row["expires_at"] < int(time.time() * 1000):
        return {"valid": False, "message": "Subscription expired", "expiresAt": row["expires_at"],
                "plan": row["plan"], "serverId": None, "premiumFeaturesEnabled": False}
    return {"valid": True, "message": "OK", "expiresAt": row["expires_at"],
            "plan": row["plan"], "serverId": str(uuid.uuid4()), "premiumFeaturesEnabled": True}


# ============================================================
# Endpoint que usa el plugin (POST /v1/validate)
# ============================================================

class ValidateBody(BaseModel):
    serverId: Optional[str] = None
    serverVersion: Optional[str] = None
    pluginVersion: Optional[str] = None


@app.post("/v1/validate")
def validate(authorization: Optional[str] = Header(None), body: Optional[ValidateBody] = None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    api_key = authorization[7:].strip()
    return response_json(api_key)


# ============================================================
# API de gestión de claves
# ============================================================

class CreateKeyRequest(BaseModel):
    plan: str = "FREE"
    owner: str = "anonymous"
    expires_in_days: Optional[int] = None


@app.post("/v1/keys")
def create_key(req: CreateKeyRequest):
    plan = req.plan.upper()
    if plan not in PLANS:
        raise HTTPException(status_code=400, detail=f"Plan must be one of: {list(PLANS)}")
    days = req.expires_in_days or PLANS[plan]
    api_key = generate_key()
    now = int(time.time() * 1000)
    expires = now + int(timedelta(days=days).total_seconds() * 1000)
    with db() as conn:
        conn.execute(
            "INSERT INTO keys (id, api_key, plan, owner, created_at, expires_at, revoked) VALUES (?,?,?,?,?,?,0)",
            (str(uuid.uuid4()), api_key, plan, req.owner, now, expires),
        )
    return {"apiKey": api_key, "plan": plan, "expiresAt": expires}


@app.get("/v1/keys")
def list_keys():
    with db() as conn:
        rows = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.delete("/v1/keys/{key_id}")
def revoke_key(key_id: str):
    with db() as conn:
        cur = conn.execute("UPDATE keys SET revoked = 1 WHERE id = ?", (key_id,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"ok": True}


# ============================================================
# Web UI
# ============================================================

PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NexusSecurity — API Keys</title>
<style>
  body { font-family: system-ui, sans-serif; background:#0f1220; color:#e6e9f5; margin:0; padding:2rem; }
  h1 { font-size:1.4rem; }
  .card { background:#1a1f33; border:1px solid #2b3252; border-radius:10px; padding:1.5rem; margin-bottom:1.5rem; max-width:760px; }
  label { display:block; margin-top:0.8rem; font-size:0.85rem; color:#aab2d5; }
  select, input { width:100%; padding:0.5rem; margin-top:0.3rem; background:#0f1220; color:#e6e9f5; border:1px solid #2b3252; border-radius:6px; }
  button { margin-top:1rem; background:#3b82f6; color:#fff; border:0; padding:0.6rem 1.2rem; border-radius:6px; cursor:pointer; font-weight:600; }
  button:hover { background:#2563eb; }
  .key { background:#0f1220; border:1px solid #2b3252; border-radius:6px; padding:0.6rem; font-family:monospace; word-break:break-all; margin-top:0.5rem; }
  table { width:100%; border-collapse:collapse; margin-top:1rem; }
  th, td { text-align:left; padding:0.5rem; border-bottom:1px solid #2b3252; font-size:0.85rem; }
  .badge { display:inline-block; padding:0.15rem 0.5rem; border-radius:999px; font-size:0.7rem; font-weight:600; }
  .ok { background:#16a34a; } .no { background:#dc2626; } .warn { background:#d97706; }
  .copy { cursor:pointer; color:#93c5fd; text-decoration:underline; }
  .danger { background:#dc2626; margin-left:0.5rem; }
  .okmsg { color:#4ade80; margin-top:0.5rem; font-weight:600; }
</style>
</head>
<body>
<h1>NexusSecurity — Generador de API Keys</h1>

<div class="card">
  <h2 style="margin-top:0">Generar nueva clave</h2>
  <form id="createForm">
    <label>Plan</label>
    <select name="plan">
      <option value="FREE">FREE (30 días)</option>
      <option value="BASIC">BASIC (90 días)</option>
      <option value="PRO" selected>PRO (365 días)</option>
      <option value="LIFETIME">LIFETIME</option>
    </select>
    <label>Propietario (opcional)</label>
    <input name="owner" placeholder="nombre del servidor o cliente">
    <button type="submit">Generar API Key</button>
  </form>
  <div id="result" class="key" style="display:none"></div>
</div>

<div class="card">
  <h2 style="margin-top:0">Claves existentes</h2>
  <table>
    <thead><tr><th>API Key</th><th>Plan</th><th>Estado</th><th>Expira</th><th>Acciones</th></tr></thead>
    <tbody id="keysBody"></tbody>
  </table>
</div>

<script>
const fmt = ts => ts === -1 ? "-" : new Date(ts).toLocaleString("es-ES");

function badge(row) {
  if (row.revoked) return '<span class="badge no">REVOCADA</span>';
  if (row.expires_at < Date.now()) return '<span class="badge warn">EXPIRADA</span>';
  return '<span class="badge ok">ACTIVA</span>';
}

async function loadKeys() {
  const res = await fetch("/v1/keys");
  const keys = await res.json();
  const body = document.getElementById("keysBody");
  body.innerHTML = "";
  for (const k of keys) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><span class="copy" onclick="copyKey('${k.api_key}')">${k.api_key}</span></td>
      <td>${k.plan}</td><td>${badge(k)}</td><td>${fmt(k.expires_at)}</td>
      <td><button class="danger" onclick="revoke('${k.id}')">Revocar</button></td>`;
    body.appendChild(tr);
  }
}

async function copyKey(k) { await navigator.clipboard.writeText(k); alert("Copiada: " + k); }

async function revoke(id) {
  if (!confirm("¿Revocar esta clave?")) return;
  await fetch("/v1/keys/" + id, { method: "DELETE" });
  loadKeys();
}

document.getElementById("createForm").addEventListener("submit", async e => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  const res = await fetch("/v1/keys", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  const j = await res.json();
  if (res.ok) {
    const el = document.getElementById("result");
    el.style.display = "block";
    el.innerHTML = `Clave generada: <b>${j.apiKey}</b> &nbsp; <span class="copy" onclick="copyKey('${j.apiKey}')">[copiar]</span>`;
    loadKeys();
  } else {
    alert(j.detail || "Error");
  }
});

loadKeys();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE
