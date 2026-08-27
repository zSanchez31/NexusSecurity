package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.util.MessageFormatter;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Central orchestrator for all NexusSecurity modules.
 * Responsible for registering, enabling, disabling and querying modules.
 * All module state changes are logged and propagated via the {@link AlertSystem}.
 *
 * <p>Thread-safe: all internal state is protected by concurrent collections.</p>
 */
public class ModuleManager {

    private final NexusSecurity plugin;
    private final Logger logger;
    /** Map of module name (lowercase) to module instance. */
    private final Map<String, SecurityModule> modules = new ConcurrentHashMap<>();
    /** Set of currently active module names. */
    private final Set<String> activeModules = ConcurrentHashMap.newKeySet();

    /**
     * Creates a new ModuleManager.
     *
     * @param plugin The main plugin instance
     */
    public ModuleManager(NexusSecurity plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
    }

    /**
     * Registers a module with the manager. Does not enable it.
     *
     * @param module The module to register
     */
    public void register(SecurityModule module) {
        String key = module.getName().toLowerCase();
        if (modules.containsKey(key)) {
            logger.warning("[ModuleManager] Module already registered: " + module.getName());
            return;
        }
        modules.put(key, module);
        logger.fine("[ModuleManager] Registered module: " + module.getName());
    }

    /**
     * Enables all registered modules that are configured as enabled.
     * Called after subscription validation succeeds.
     */
    public void enableAll() {
        logger.info("[ModuleManager] Enabling all security modules...");
        for (SecurityModule module : modules.values()) {
            String configKey = "modules." + module.getConfigKey() + ".enabled";
            boolean configEnabled = plugin.getConfig().getBoolean(configKey, true);
            if (configEnabled) {
                enableModule(module.getName());
            } else {
                logger.info("[ModuleManager] Module " + module.getName() + " is disabled in config, skipping.");
            }
        }
    }

    /**
     * Disables all currently active modules.
     * Called on plugin shutdown or subscription expiry.
     */
    public void disableAll() {
        logger.info("[ModuleManager] Disabling all security modules...");
        // Create a copy to avoid ConcurrentModificationException
        List<String> toDisable = new ArrayList<>(activeModules);
        for (String name : toDisable) {
            disableModule(name);
        }
    }

    /**
     * Enables a specific module by name.
     *
     * @param name The module name (case-insensitive)
     * @return true if successfully enabled, false otherwise
     */
    public boolean enableModule(String name) {
        SecurityModule module = modules.get(name.toLowerCase());
        if (module == null) {
            logger.warning("[ModuleManager] Unknown module: " + name);
            return false;
        }
        if (activeModules.contains(name.toLowerCase())) {
            return true; // Already enabled
        }
        try {
            module.enable();
            activeModules.add(name.toLowerCase());
            logger.info("[ModuleManager] Module enabled: " + module.getName());
            return true;
        } catch (Exception e) {
            logger.severe("[ModuleManager] Failed to enable module " + module.getName() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Disables a specific module by name.
     *
     * @param name The module name (case-insensitive)
     * @return true if successfully disabled, false otherwise
     */
    public boolean disableModule(String name) {
        SecurityModule module = modules.get(name.toLowerCase());
        if (module == null) {
            return false;
        }
        if (!activeModules.contains(name.toLowerCase())) {
            return true; // Already disabled
        }
        try {
            module.disable();
            activeModules.remove(name.toLowerCase());
            logger.info("[ModuleManager] Module disabled: " + module.getName());
            return true;
        } catch (Exception e) {
            logger.severe("[ModuleManager] Failed to disable module " + module.getName() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Returns the module instance for the given name.
     *
     * @param name Module name (case-insensitive)
     * @return The module, or null if not found
     */
    public SecurityModule getModule(String name) {
        return modules.get(name.toLowerCase());
    }

    /**
     * Returns a typed module instance, cast to the expected type.
     *
     * @param name        Module name
     * @param moduleClass Expected class type
     * @param <T>         Module type
     * @return Cast module instance, or null if not found or wrong type
     */
    @SuppressWarnings("unchecked")
    public <T extends SecurityModule> T getModule(String name, Class<T> moduleClass) {
        SecurityModule module = modules.get(name.toLowerCase());
        if (moduleClass.isInstance(module)) {
            return (T) module;
        }
        return null;
    }

    /**
     * Returns an unmodifiable view of all registered modules.
     *
     * @return Unmodifiable map of module name to module instance
     */
    public Map<String, SecurityModule> getAllModules() {
        return Collections.unmodifiableMap(modules);
    }

    /**
     * Returns whether a module is currently active.
     *
     * @param name Module name (case-insensitive)
     * @return true if the module is enabled
     */
    public boolean isModuleActive(String name) {
        return activeModules.contains(name.toLowerCase());
    }

    /**
     * Returns the count of currently active modules.
     *
     * @return Number of active modules
     */
    public int getActiveModuleCount() {
        return activeModules.size();
    }

    /**
     * Returns the total count of registered modules.
     *
     * @return Number of registered modules
     */
    public int getTotalModuleCount() {
        return modules.size();
    }

    /**
     * Returns a formatted list of all modules with their status.
     * Used for the /security status command.
     *
     * @return List of formatted status strings
     */
    public List<String> getStatusLines() {
        List<String> lines = new ArrayList<>();
        for (SecurityModule module : modules.values()) {
            lines.add(MessageFormatter.moduleStatus(module.getName(), activeModules.contains(module.getName().toLowerCase())));
        }
        return lines;
    }
}
