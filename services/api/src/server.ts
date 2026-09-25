import { loadConfig } from '@sug/shared/config';
import { createApp, type AppOptions } from './app.js';

/**
 * Boots the Fastify API HTTP server and binds to configured host and port.
 * Configures graceful shutdown listeners on SIGTERM and SIGINT.
 */
export async function startServer(options: AppOptions = {}): Promise<void> {
  const config = options.config ?? loadConfig();
  const app = await createApp({
    config,
    ...options,
    logger: options.logger ?? {
      level: config.logLevel,
    },
  });

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'Received termination signal, shutting down gracefully...');
    try {
      await app.close();
      app.log.info('Server closed cleanly');
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'Error during server shutdown');
      process.exit(1);
    }
  };

  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  try {
    const address = await app.listen({
      port: config.port,
      host: config.host,
    });
    app.log.info({ address, service: config.serviceName }, 'Secure Upload Gateway API running');
  } catch (err) {
    app.log.fatal({ err }, 'Failed to start Fastify API server');
    process.exit(1);
  }
}

// Allow direct CLI execution if executed as main module
const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('server.js') || process.argv[1].endsWith('server.ts'));
if (isMain) {
  startServer().catch((err) => {
    console.error('Fatal startup error:', err);
    process.exit(1);
  });
}
