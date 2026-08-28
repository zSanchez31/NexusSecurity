# NexusSecurity

Plugin de seguridad todo‑en‑uno para servidores **Minecraft Paper** (1.21+), escrito en Java 21.
Protege tu servidor con 11 módulos, un **panel web embebido**, auditoría, copias de seguridad y
notificaciones externas (Discord / Telegram).

> Versión: **1.1.7**

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
- Con una clave válida (la que te proporciona el dueño) → desbloquea las funciones del plugin.
  Cada clave está **vinculada a un único servidor** y no puede usarse en varios a la vez.

El endpoint de validación por defecto es `https://api-keys.nexusnodes.online/v1/validate`
(configurable con `api.validation-endpoint`). La clave te la proporciona el dueño/administrador.

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
  slack:
    webhook-url: ""               # webhook de Slack (incoming)
  webhook:
    url: ""                       # webhook genérico (POST JSON: module/severity/source/message)
  pushover:
    token: ""                     # token de aplicación Pushover
    user: ""                      # usuario Pushover
  smtp:
    host: ""                      # servidor SMTP (STARTTLS + AUTH LOGIN)
    port: 587
    user: ""
    password: ""
    from: "nexussecurity@localhost"
    to: ""
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
- **Eventos**: feed en vivo (SSE) de alertas del sistema; las alertas **críticas** muestran un
  *toast* emergente en el navegador.
- **Consola**: consola del servidor en vivo (SSE) + caja para **ejecutar comandos** como consola
  (rol `admin`). Logs del servidor en tiempo real.
- **Config**: editor del `config.yml` desde el navegador (guarda y recarga la config del plugin).
- **Ajustes**: usuario/rol, cambio de contraseña y (si 2FA está activo) el secreto TOTP.
- **Tema**: botón 🌓 en la barra para alternar modo claro/oscuro (se recuerda en una cookie).

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
- **Slack**: vía *webhook* de entrada (`notifications.slack.webhook-url`).
- **Webhook genérico**: POST JSON con `module`/`severity`/`source`/`message` (`notifications.webhook.url`).
- **Pushover**: notificación push móvil (`notifications.pushover.token` + `user`).
- **SMTP**: correo vía STARTTLS + AUTH LOGIN (`notifications.smtp.*`).

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

**Novedades por módulo (v1.1.6):**

- **Guardian** incluye ahora **anti-bot / detección de join-flood** por IP
  (`modules.guardian.anti-bot.*`): si una misma IP supera `max-joins-per-ip` en `window-seconds`,
  se marca como bot y se expulsa (si `kick: true`).
- **Vault** calcula y guarda el **SHA‑256** de cada backup (`.sha256` junto al archivo) y permite
  subirlo a un destino **offsite** tras cada copia mediante un comando externo
  (`modules.vault.offsite.command`, p. ej. `rclone copy %FILE% remote:backups/` o
  `aws s3 cp %FILE% s3://bucket/`).
- El panel expone métricas en formato **Prometheus** en `GET /api/metrics`
  (TPS, CPU, RAM, jugadores, módulos, disco, entidades, chunks, mundos, salud, GC, hilos, uptime),
  útiles para Grafana.

---

## Comandos

- `/security panel` — muestra la URL de acceso al panel.
- `/security reload` — recarga la configuración.
- Subcomandos: `status`, `shield`, `guardian`, `vault`, `autopilot`, `hackdetector`,
  `vulnerability`, `compliance`, `memory`, `panel`.

---

## Descarga (Release / JAR)

La última versión compilada está en **[Releases](https://github.com/zSanchez31/NexusSecurity/releases)**:
descarga `NexusSecurity-1.1.7.jar` y súbelo a `plugins/`.

> El JAR de la release es *shaded*: incluye todas las dependencias (Gson, etc.) y está
> relocalizado a `nx.zsanchez.nexussecurity.libs.*` para evitar conflictos.

---

## Seguridad del panel

- Usa `bind-address: "127.0.0.1"` si solo lo consumes desde la misma máquina (recomendado).
- Si lo expones (`0.0.0.0`), ponlo detrás de un proxy/nginx con HTTPS y firewall, y cambia la
  contraseña por defecto inmediatamente.
- Activa **2FA** y considera usuarios `viewer` para personal de soporte.

---

## Clave de API

La clave de API (`api.key`) es **proporcionada por el dueño/administrador**; no se genera por tu
cuenta. Pon la clave que te faciliten en `config.yml` (`api.key`) para activar las funciones del
plugin. El plugin la valida contra el servidor de licencias por defecto
(`https://api-keys.nexusnodes.online/v1/validate`).

---

## Licencia

Uso interno / proyecto del autor. Consulta el repositorio para detalles.
