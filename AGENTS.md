# AGENTS.md

NexusSecurity — Minecraft **Paper** server security plugin (Java 21, single Maven module).

## Build & Test

**Build**: `mvn -q -o compile` (cached deps) or `mvn package` for shaded JAR at `target/NexusSecurity-${project.version}.jar`.

**Versioning**: Every update bumps the version by **+0.0.1** (patch): 1.1.1 → 1.1.2 → 1.1.3... Bump `<version>` in `pom.xml` and the `Versión:` header in `src/main/resources/config.yml` (the only two places it appears).

**Test**: No tests exist yet. `mvn test` runs nothing. Add tests under `src/test/java/`.

**Lint/Typecheck**: None configured. Code style follows patterns in existing files.

## Key Constraints

**Threading**: All DB I/O and network calls must run off main thread. Use `ThreadPoolManager.submit()` or `scheduleAtFixedRate()`. From async workers, touch Bukkit APIs via `Bukkit.getScheduler().runTask(plugin, ...)`.

**Relocations**: Third-party libs are shaded to `nx.zsanchez.nexussecurity.libs.*`. Add `<relocation>` in `pom.xml` for any new runtime dependency.

**SQLite is single-writer**: Only 1 connection in pool; no concurrent writes.

## Development Setup

Set `api.key: "DEV-NEXUS-KEY"` in `config.yml` to bypass remote HTTP validation for local testing (keys with `DEV-`/`TEST-` prefix also bypass; `api.dev-mode` config option still honored by code but removed from config).

Default key `TU_CLAVE_API_AQUI` → LIMITED mode (modules inactive).

## Architecture

**Module lifecycle**: Modules implement `SecurityModule` with `enable()`/`disable()` methods. `ModuleManager` coordinates activation based on subscription validation and performance thresholds.

**11 modules**: Shield, Guardian, Sentinel, DefenderAI, Vault, Integrity, VulnerabilityCenter, ThreatIntelligence, Compliance, Autopilot, HackDetector.

**Config toggles**: `modules.<name-lowercased-with-dashes>.enabled` (e.g., `modules.hack-detector.enabled`).

**Entry point**: `NexusSecurity.java` wires core services and registers modules in `registerModules()`.