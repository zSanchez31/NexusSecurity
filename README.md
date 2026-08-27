# NexusSecurity

Plugin de seguridad todo‑en‑uno para servidores **Minecraft Paper** (1.21+), escrito en Java 21.
Protege tu servidor con 11 módulos, un **panel web embebido**, auditoría, copias de seguridad y
notificaciones externas (Discord / Telegram).

> Versión: **1.1.4**

---

## Índice

- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Configuración (`config.yml`)](#configuración-configyml)
- [Acceso al panel web (login)](#acceso-al-panel-web-login)
- [Usuarios, roles y 2FA](#usuarios-roles-y-2fa)
- [Notificaciones externas](#notificaciones-externas)
- [Módulos](#módulos)
- [Comandos](#comandos)
- [Descarga (Release / JAR)](#descarga-release--jar)
- [Seguridad del panel](#seguridad-del-panel)

---

## Requisitos

| Requisito | Detalle |
|-----------|---------|
| Servidor  | Paper 1.21 o superior (compatible con Spigot/Folia con matices) |
| Java      | 21 |
| Dependencias externas | Ninguna (todo va empaquetado / *shaded*) |

---

## Instalación

1. Descarga el JAR desde la sección de [Releases](#descarga-release--jar).
2. Colócalo en la carpeta `plugins/` de tu servidor.
3. Arranca (o recarga) el servidor. Se generará `plugins/NexusSecurity/config.yml`.
4. Edita la configuración y usa `/security reload` (o reinicia) para aplicar cambios.

---

## Configuración (`config.yml`)

El archivo `config.yml` se crea solo la primera vez. Aquí los bloques clave.

### API key y modo

```yaml
api:
  key: "TU_CLAVE_API_AQUI"   # pon tu clave real para activar funciones premium
```

- `TU_CLAVE_API_AQUI` (por defecto) → **modo LIMITADO** (módulos premium inactivos).
- Cualquier clave que empiece por `DEV-` o `TEST-` (p. ej. `DEV-NEXUS-KEY`) → **activa todo sin
  validación remota** (solo para pruebas en local).
- Una clave válida real → desbloquea módulos según tu suscripción.

### Panel web (`web-panel`)

```yaml
web-panel:
  enabled: false                 # pon true para activar el panel
  port: 25580                    # puerto del panel (ver notas abajo)
  bind-address: "0.0.0.0"        # 127.0.0.1 = solo local, 0.0.0.0 = accesible desde fuera
  host: ""                       # opcional: fuerza la IP/host mostrada en el panel
  require-password: true
  password: "NexusSecurity123"   # contraseña por defecto (cámbiala)
  session-timeout-minutes: 60
  public-ip-url: "https://api.ipify.org"
  max-failed-logins: 5
  lockout-minutes: 10
  two-factor: false              # activa TOTP (Google Authenticator / Authy)
  users:                         # opcional: varios usuarios con roles
    admin:
      password: "NexusSecurity123"
      role: "admin"              # admin = acciones; viewer = solo lectura
    soporte:
      password: "viewerpass"
      role: "viewer"
```

**Puerto:** si tu servidor Minecraft escucha en `169.58.119.187:25578`, usa un puerto distinto para el
panel, por ejemplo `25580` → el panel quedará en `http://169.58.119.187:25580`.

### Notificaciones (`notifications`)

```yaml
notifications:
  console: true
  console-min-level: info
  in-game: true
  in-game-min-level: warning
  external:
    enabled: false
    min-level: critical           # info | warning | critical
  discord:
    webhook-url: ""               # URL del webhook de Discord
  telegram:
    token: ""                     # token del bot de Telegram
    chat-id: ""                   # ID del chat de destino
```

### Módulos

Cada módulo se activa/desactiva de forma independiente:

```yaml
modules:
  hack-detector:
    enabled: true
  shield:
    enabled: true
  # ...
```

Nombres válidos (en `kebab-case`): `shield`, `guardian`, `sentinel`, `defender-ai`, `vault`,
`integrity`, `vulnerability-center`, `threat-intelligence`, `compliance`, `autopilot`, `hack-detector`.

---

## Acceso al panel web (login)

1. Asegúrate de que `web-panel.enabled: true` y reinicia/recarga.
2. Abre en el navegador: `http://<host-del-servidor>:<puerto-panel>/`
   (por defecto `http://localhost:25580/`).
3. Inicia sesión con la contraseña configurada (`NexusSecurity123` por defecto).
   - El panel **avisa si sigues usando la contraseña por defecto**: cámbiala cuanto antes.
4. Tras N intentos fallidos (`max-failed-logins`, por defecto 5) la IP queda bloqueada
   `lockout-minutes` (10 min).

### Secciones del panel

- **Dashboard**: TPS, CPU, RAM, módulos activos, estado de emergencia, **stats del servidor**
  (uptime, Java, SO, núcleos, mundos, entidades, chunks, disco y *score de salud*).
- **Jugadores**: lista en vivo con IP, ping, op; ficha por jugador con botones para
  `kick` / `ban` / `mute` / `freeze` / teleport e historial de violaciones.
- **Sospechosos** (HackDetector): jugadores con violaciones activas.
- **Backups** (Vault): lista de copias con tamaño/fecha y botón de **restaurar**; acciones de jugador.
- **Auditoría**: registro de acciones con filtros (actor / acción / búsqueda) y exportación CSV.
- **Eventos**: feed en vivo (SSE) de alertas del sistema.
- **Ajustes**: usuario/rol, cambio de contraseña y (si 2FA está activo) el secreto TOTP.

---

## Usuarios, roles y 2FA

- **Roles**: `admin` puede realizar acciones (kick, ban, restore, etc.); `viewer` solo puede ver.
- **Varios usuarios**: define `web-panel.users` (ver arriba). El login pedirá usuario + contraseña.
- **2FA (TOTP)**: pon `web-panel.two-factor: true`. En el primer login el panel genera un secreto
  (base32) que se muestra en **Ajustes** con una `otpauth://` URL para escanear en Google
  Authenticator / Authy. El login pedirá entonces un código de 6 dígitos.
- **Cambiar contraseña**: desde **Ajustes → Cambiar contraseña** (verifica la actual y guarda).

---

## Notificaciones externas

Cuando una alerta alcanza el nivel configurado (`external.min-level`, por defecto `critical`),
`ExternalNotifier` la reenvía a:

- **Discord**: vía *webhook* (`notifications.discord.webhook-url`).
- **Telegram**: vía bot (`notifications.telegram.token` + `chat-id`).

Los envíos se hacen fuera del hilo principal (thread pool) para no bloquear el servidor.

---

## Módulos

| Módulo | Función principal |
|--------|-------------------|
| Shield | Rate‑limiting / protección de conexiones |
| Guardian | Escaneo y defensa activa |
| Sentinel | Monitoreo de rendimiento |
| DefenderAI | Detección inteligente de amenazas |
| Vault | Copias de seguridad del servidor |
| Integrity | Integridad de archivos / config |
| VulnerabilityCenter | Detección de vulnerabilidades |
| ThreatIntelligence | Listas negras / inteligencia de amenazas |
| Compliance | Auditoría y cumplimiento |
| Autopilot | Respuesta automática / modo de emergencia |
| HackDetector | Detección de clientes ilegales (hacks) |

---

## Comandos

- `/security panel` — muestra la URL de acceso al panel.
- `/security reload` — recarga la configuración.
- Subcomandos: `status`, `shield`, `guardian`, `vault`, `autopilot`, `hackdetector`,
  `vulnerability`, `compliance`, `memory`, `panel`.

---

## Descarga (Release / JAR)

La última versión compilada está en **[Releases](https://github.com/zSanchez31/NexusSecurity/releases)**:
descarga `NexusSecurity-1.1.4.jar` y súbelo a `plugins/`.

> El JAR de la release es *shaded*: incluye todas las dependencias (Gson, etc.) y está
> relocalizado a `nx.zsanchez.nexussecurity.libs.*` para evitar conflictos.

---

## Seguridad del panel

- Usa `bind-address: "127.0.0.1"` si solo lo consumes desde la misma máquina (recomendado).
- Si lo expones (`0.0.0.0`), ponlo detrás de un proxy/nginx con HTTPS y firewall, y cambia la
  contraseña por defecto inmediatamente.
- Activa **2FA** y considera usuarios `viewer` para personal de soporte.

---

## Licencia

Uso interno / proyecto del autor. Consulta el repositorio para detalles.
