package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;

import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Manages a shared, bounded thread pool for all NexusSecurity asynchronous operations.
 * Using a central pool prevents unbounded thread creation and allows controlled resource usage.
 *
 * <p>Key design decisions:</p>
 * <ul>
 *   <li>Core pool size is configurable via config.yml (default: 4)</li>
 *   <li>All submitted tasks have exception handling to prevent silent failures</li>
 *   <li>The pool is named with "NexusSec-Worker" prefix for easy identification in thread dumps</li>
 *   <li>Tasks submitted to the pool must NEVER call Bukkit API directly; use
 *       {@code Bukkit.getScheduler().runTask()} to switch back to the main thread</li>
 * </ul>
 */
public class ThreadPoolManager {

    private final Logger logger;
    private final ThreadPoolExecutor executor;
    private final ScheduledExecutorService scheduledExecutor;

    /**
     * Creates and configures the thread pool.
     *
     * @param plugin The main plugin instance (used for config access)
     */
    public ThreadPoolManager(NexusSecurity plugin) {
        this.logger = plugin.getLogger();
        int poolSize = plugin.getConfig().getInt("performance.thread-pool-size", 4);
        // Clamp between 2 and 16
        poolSize = Math.max(2, Math.min(16, poolSize));

        // Named thread factory for identification in thread dumps
        ThreadFactory namedFactory = new ThreadFactory() {
            private int counter = 0;
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "NexusSec-Worker-" + (++counter));
                t.setDaemon(true); // Daemon threads won't prevent JVM shutdown
                return t;
            }
        };

        // Main async pool for ad-hoc tasks
        this.executor = new ThreadPoolExecutor(
                poolSize,
                poolSize * 2,         // Allow burst up to 2x core size
                60L, TimeUnit.SECONDS, // Idle threads expire after 60s
                new LinkedBlockingQueue<>(1000), // Bounded queue prevents OOM
                namedFactory,
                new RejectedExecutionHandler() {
                    @Override
                    public void rejectedExecution(Runnable r, ThreadPoolExecutor ex) {
                        logger.warning("[ThreadPool] Task rejected - pool is saturated! " +
                                "Consider increasing performance.thread-pool-size.");
                    }
                }
        );
        this.executor.allowCoreThreadTimeOut(true);

        // Scheduled pool for periodic tasks (module scanners, cache cleanup, etc.)
        ThreadFactory scheduledFactory = r -> {
            Thread t = new Thread(r, "NexusSec-Scheduler");
            t.setDaemon(true);
            return t;
        };
        this.scheduledExecutor = Executors.newScheduledThreadPool(2, scheduledFactory);

        logger.info("[ThreadPool] Initialized with " + poolSize + " core threads.");
    }

    /**
     * Submits an asynchronous task for execution.
     * All exceptions are caught and logged to prevent silent task failures.
     *
     * @param taskName Descriptive name for logging purposes
     * @param task     The task to execute
     * @return A Future representing the pending task
     */
    public Future<?> submit(String taskName, Runnable task) {
        return executor.submit(() -> {
            try {
                task.run();
            } catch (Exception e) {
                logger.severe("[ThreadPool] Uncaught exception in task '" + taskName + "': " + e.getMessage());
            }
        });
    }

    /**
     * Submits a value-returning async task.
     *
     * @param taskName Descriptive name for logging purposes
     * @param task     The callable to execute
     * @param <T>      Return type
     * @return Future with the result
     */
    public <T> Future<T> submit(String taskName, Callable<T> task) {
        return executor.submit(() -> {
            try {
                return task.call();
            } catch (Exception e) {
                logger.severe("[ThreadPool] Uncaught exception in task '" + taskName + "': " + e.getMessage());
                return null;
            }
        });
    }

    /**
     * Schedules a repeating task with fixed delay between completions.
     *
     * @param taskName     Descriptive name for logging
     * @param task         The task to execute
     * @param initialDelay Initial delay before first execution
     * @param period       Period between executions
     * @param unit         Time unit for delay and period
     * @return A ScheduledFuture that can be cancelled
     */
    public ScheduledFuture<?> scheduleAtFixedRate(String taskName, Runnable task,
                                                   long initialDelay, long period, TimeUnit unit) {
        return scheduledExecutor.scheduleAtFixedRate(() -> {
            try {
                task.run();
            } catch (Exception e) {
                logger.severe("[ThreadPool] Scheduled task '" + taskName + "' threw exception: " + e.getMessage());
            }
        }, initialDelay, period, unit);
    }

    /**
     * Schedules a one-shot delayed task.
     *
     * @param taskName Descriptive name for logging
     * @param task     The task to execute
     * @param delay    Delay before execution
     * @param unit     Time unit for delay
     * @return A ScheduledFuture that can be cancelled
     */
    public ScheduledFuture<?> schedule(String taskName, Runnable task, long delay, TimeUnit unit) {
        return scheduledExecutor.schedule(() -> {
            try {
                task.run();
            } catch (Exception e) {
                logger.severe("[ThreadPool] Delayed task '" + taskName + "' threw exception: " + e.getMessage());
            }
        }, delay, unit);
    }

    /**
     * Returns current pool statistics for performance monitoring.
     *
     * @return A string with pool stats
     */
    public String getStats() {
        return String.format("Pool: active=%d, queued=%d, completed=%d, threads=%d",
                executor.getActiveCount(),
                executor.getQueue().size(),
                executor.getCompletedTaskCount(),
                executor.getPoolSize());
    }

    /**
     * Gracefully shuts down both thread pools.
     * Called during plugin disable. Waits up to 10 seconds for running tasks to finish.
     */
    public void shutdown() {
        logger.info("[ThreadPool] Shutting down thread pools...");
        executor.shutdown();
        scheduledExecutor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                logger.warning("[ThreadPool] Main pool did not terminate gracefully, forcing shutdown.");
            }
            if (!scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduledExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            scheduledExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("[ThreadPool] All threads terminated.");
    }

    /**
     * Returns the main executor for direct CompletableFuture usage.
     *
     * @return The underlying ThreadPoolExecutor
     */
    public Executor getExecutor() {
        return executor;
    }
}
