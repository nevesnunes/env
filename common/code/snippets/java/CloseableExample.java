static class IdleConnectionEvictor implements Closeable {

    private final Thread thread;

    public IdleConnectionEvictor(final H2ConnPool connPool, final TimeValue maxIdleTime) {
        this.thread = new DefaultThreadFactory("idle-connection-evictor", true).newThread(new Runnable() {
            @Override
            public void run() {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        Thread.sleep(maxIdleTime.toMillis());
                        connPool.closeIdle(maxIdleTime);
                    }
                } catch (final InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } catch (final Exception ex) {
                }

            }
        });
    }

    public void start() {
        thread.start();
    }

    public void shutdown() {
        thread.interrupt();
    }

    @Override
    public void close() throws IOException {
        shutdown();
    }

}
