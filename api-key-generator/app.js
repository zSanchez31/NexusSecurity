const $ = (id) => document.getElementById(id);

async function apiGenerate(owner, label, verify = false) {
  const res = await fetch("/api/v1/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: owner, label: label || "", verify }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
  return data;
}

function setLoading(on) {
  const btn = $("gen");
  btn.disabled = on;
  btn.querySelector(".txt").textContent = on ? "Generando…" : "Generar clave API";
  btn.querySelector(".spin").hidden = !on;
}

function addToHistory(key, label) {
  $("historyWrap").classList.remove("hidden");
  const li = document.createElement("li");
  li.innerHTML = "<span>" + key + "</span><span class='tag'>" + (label || "sin etiqueta") + "</span>";
  $("history").prepend(li);
}

// --- Desbloquear (verifica la contraseña contra el servidor sin crear clave) ---
async function unlock() {
  const pw = $("owner").value.trim();
  if (!pw) { $("gateErr").textContent = "Introduce la contraseña."; return; }
  $("gateErr").textContent = "";
  try {
    await apiGenerate(pw, "", true);
    sessionStorage.setItem("nx_owner", pw);
    $("gate").classList.add("hidden");
    $("panel").classList.remove("hidden");
    $("owner").value = "";
  } catch (e) {
    $("gateErr").textContent = e.message;
  }
}

$("unlock").addEventListener("click", unlock);
$("owner").addEventListener("keydown", (e) => { if (e.key === "Enter") unlock(); });

$("lock").addEventListener("click", () => {
  sessionStorage.removeItem("nx_owner");
  $("panel").classList.add("hidden");
  $("gate").classList.remove("hidden");
});

// --- Generar clave ---
$("gen").addEventListener("click", async () => {
  const owner = sessionStorage.getItem("nx_owner") || $("owner").value;
  const label = $("label").value.trim();
  $("genErr").textContent = "";
  setLoading(true);
  try {
    const data = await apiGenerate(owner, label);
    $("keyOut").textContent = data.key;
    $("result").classList.remove("hidden");
    addToHistory(data.key, label);
    $("label").value = "";
  } catch (e) {
    $("genErr").textContent = e.message;
    if (/propietario|owner|401/i.test(e.message)) {
      sessionStorage.removeItem("nx_owner");
      $("panel").classList.add("hidden");
      $("gate").classList.remove("hidden");
    }
  } finally {
    setLoading(false);
  }
});

// --- Copiar ---
$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("keyOut").textContent);
    const b = $("copy");
    b.textContent = "¡Copiado!";
    setTimeout(() => (b.textContent = "Copiar"), 1400);
  } catch (_) {}
});

// Auto-restaurar sesión si ya desbloqueamos en esta pestaña
if (sessionStorage.getItem("nx_owner")) {
  $("gate").classList.add("hidden");
  $("panel").classList.remove("hidden");
}
