package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Batches security event writes to reduce database I/O pressure.
 * Instead of writing each event individually, events are queued in memory
 * and flushed to the database every {@code batchFlushIntervalMs} milliseconds,
 * or when the batch reaches {@code batchSize} events.
 *
 * <p>This significantly reduces I/O overhead in high-activity scenarios (e.g., DDoS events).</p>
 * <p>All operations are thread-safe. The queue is bounded to prevent unbounded memory growth.</p>
 */
public class BatchWriter {

    /** Simple record representing a queued security event. */
    private record QueuedEvent(
            String severity,
            String module,
            String source,
            String description,
            String data
    ) {}

    private final NexusSecurity plugin;
    private final Logger logger;
    private final DatabaseManager databaseManager;
    private final ThreadPoolManager threadPoolManager;

    private final int batchSize;
    private final long flushIntervalMs;
    /** Bounded queue to prevent OOM in high-traffic scenarios. */
    private final BlockingQueue<QueuedEvent> eventQueue;
    private ScheduledFuture<?> flushTask;

    /**
     * Creates and starts the batch writer.
     *
     * @param plugin            Main plugin instance
     * @param databaseManager   Database for persisting events
     * @param threadPoolManager Thread pool for scheduling the flush task
     */
    public BatchWriter(NexusSecurity plugin, DatabaseManager databaseManager, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
        this.threadPoolManager = threadPoolManager;
        this.batchSize = plugin.getConfig().getInt("performance.batch-size", 100);
        this.flushIntervalMs = plugin.getConfig().getLong("performance.batch-flush-interval-ms", 5000);
        // Queue capacity = 10x batch size to allow for bursts
        this.eventQueue = new ArrayBlockingQueue<>(batchSize * 10);
    }

    /**
     * Starts the periodic flush scheduler.
     * Must be called after plugin initialization.
     */
    public void start() {
        flushTask = threadPoolManager.scheduleAtFixedRate(
                "BatchWriter-Flush",
                this::flush,
                flushIntervalMs,
                flushIntervalMs,
                TimeUnit.MILLISECONDS
        );
        logger.info("[BatchWriter] Started (batchSize=" + batchSize + ", interval=" + flushIntervalMs + "ms).");
    }

    /**
     * Queues a security event for batch writing.
     * If the queue is full, the event is dropped and a warning is logged.
     *
     * @param severity    Event severity
     * @param module      Source module
     * @param source      Source identifier
     * @param description Description
     * @param data        Optional JSON data
     */
    public void queueEvent(String severity, String module, String source, String description, String data) {
        QueuedEvent event = new QueuedEvent(severity, module, source, description, data);
        boolean added = eventQueue.offer(event);
        if (!added) {
            // Queue is full — flush immediately to make room
            flush();
            eventQueue.offer(event); // Try once more
        }
        // If batch is full, trigger an early flush
        if (eventQueue.size() >= batchSize) {
            threadPoolManager.submit("BatchWriter-EarlyFlush", this::flush);
        }
    }

    /**
     * Flushes all pending events to the database.
     * Thread-safe; called by the scheduler and can be called manually.
     */
    public synchronized void flush() {
        if (eventQueue.isEmpty() || !databaseManager.isConnected()) return;

        List<QueuedEvent> batch = new ArrayList<>(batchSize);
        eventQueue.drainTo(batch, batchSize);

        if (batch.isEmpty()) return;

        for (QueuedEvent event : batch) {
            databaseManager.insertSecurityEvent(
                    event.severity(),
                    event.module(),
                    event.source(),
                    event.description(),
                    event.data()
            );
        }
    }

    /**
     * Stops the flush scheduler and flushes any remaining events.
     * Called during plugin disable.
     */
    public void stop() {
        if (flushTask != null && !flushTask.isCancelled()) {
            flushTask.cancel(false);
        }
        // Final flush to ensure no events are lost
        flush();
        logger.info("[BatchWriter] Stopped. All pending events flushed.");
    }

    /**
     * Returns the current number of events waiting to be flushed.
     *
     * @return Queue size
     */
    public int getQueueSize() {
        return eventQueue.size();
    }
}
