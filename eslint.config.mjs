import boundaries from 'eslint-plugin-boundaries';
import tseslint from 'typescript-eslint';

export default [
  ...tseslint.configs.recommended,
  {
    plugins: {
      boundaries,
    },
    settings: {
      'boundaries/elements': [
        { type: 'app-dashboard', pattern: 'apps/dashboard/**' },
        { type: 'app-client', pattern: 'apps/demo-client/**' },
        { type: 'service-api', pattern: 'services/api/**' },
        { type: 'service-scanner', pattern: 'services/scanner/**' },
        { type: 'service-promotion', pattern: 'services/promotion/**' },
        { type: 'service-replication', pattern: 'services/replication/**' },
        { type: 'pkg-shared', pattern: 'packages/shared/**' },
        { type: 'pkg-storage', pattern: 'packages/storage/**' },
        { type: 'pkg-policy', pattern: 'packages/policy-engine/**' },
        { type: 'pkg-security', pattern: 'packages/security-engine/**' },
        { type: 'pkg-scanner', pattern: 'packages/scanner/**' },
        { type: 'pkg-decision', pattern: 'packages/decision-engine/**' },
        { type: 'pkg-crypto', pattern: 'packages/crypto/**' },
        { type: 'pkg-audit', pattern: 'packages/audit/**' },
        { type: 'pkg-sdk', pattern: 'packages/sdk/**' },
      ],
      'boundaries/ignore': ['**/*.test.ts', '**/*.spec.ts', 'tests/**'],
    },
    rules: {
      'boundaries/dependencies': [
        'error',
        {
          default: 'disallow',
          policies: [
            {
              from: { element: { type: 'pkg-shared' } },
              allow: [],
            },
            {
              from: { element: { type: 'pkg-storage' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-policy' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-security' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-scanner' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-decision' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-crypto' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-audit' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'pkg-sdk' } },
              allow: [{ to: { element: { type: 'pkg-shared' } } }],
            },
            {
              from: { element: { type: 'service-api' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-storage' } } },
                { to: { element: { type: 'pkg-policy' } } },
              ],
            },
            {
              from: { element: { type: 'service-scanner' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-storage' } } },
                { to: { element: { type: 'pkg-scanner' } } },
                { to: { element: { type: 'pkg-security' } } },
              ],
            },
            {
              from: { element: { type: 'service-promotion' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-storage' } } },
                { to: { element: { type: 'pkg-crypto' } } },
                { to: { element: { type: 'pkg-decision' } } },
              ],
            },
            {
              from: { element: { type: 'service-replication' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-storage' } } },
              ],
            },
            {
              from: { element: { type: 'app-dashboard' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-sdk' } } },
              ],
            },
            {
              from: { element: { type: 'app-client' } },
              allow: [
                { to: { element: { type: 'pkg-shared' } } },
                { to: { element: { type: 'pkg-sdk' } } },
              ],
            },
          ],
        },
      ],
    },
  },
  {
    ignores: [
      '**/dist/**',
      '**/build/**',
      '**/node_modules/**',
      'coverage/**',
      '**/*.d.ts',
      'DOCUMENTS/**',
    ],
  },
];
