import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@sug/shared/config': path.resolve(__dirname, 'packages/shared/src/config.ts'),
      '@sug/shared': path.resolve(__dirname, 'packages/shared/src/index.ts'),
      '@sug/audit': path.resolve(__dirname, 'packages/audit/src/index.ts'),
      '@sug/storage': path.resolve(__dirname, 'packages/storage/src/index.ts'),
      '@sug/policy-engine': path.resolve(__dirname, 'packages/policy-engine/src/index.ts'),
      '@sug/security-engine': path.resolve(__dirname, 'packages/security-engine/src/index.ts'),
      '@sug/scanner': path.resolve(__dirname, 'packages/scanner/src/index.ts'),
      '@sug/decision-engine': path.resolve(__dirname, 'packages/decision-engine/src/index.ts'),
      '@sug/crypto': path.resolve(__dirname, 'packages/crypto/src/index.ts'),
      '@sug/sdk': path.resolve(__dirname, 'packages/sdk/src/index.ts'),
    },
  },
  test: {
    globals: true,
    clearMocks: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'packages/**/*.test.ts', 'services/**/*.test.ts'],
  },
});
