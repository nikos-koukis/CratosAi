import { defineConfig, globalIgnores } from 'eslint/config'
import nextVitals from 'eslint-config-next/core-web-vitals'
import nextTs from 'eslint-config-next/typescript'

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    rules: {
      // Client components (src/components) and shared code (src/lib) must
      // not reach server modules; those also import 'server-only'.
      'no-restricted-imports': [
        'error',
        { patterns: [{ group: ['@/server', '@/server/*'], message: 'Server modules stay on the server.' }] },
      ],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      eqeqeq: ['error', 'always'],
    },
  },
  {
    // Server code, pages and actions may use the server modules.
    files: [
      'src/server/**',
      'src/actions/**',
      'src/app/**',
      'src/proxy.ts',
      'src/instrumentation.ts',
      'tests/**',
      'e2e/**',
    ],
    rules: { 'no-restricted-imports': 'off' },
  },
  {
    // Tests import modules after setting up their environment: typeof import() is on purpose.
    files: ['tests/**'],
    rules: { '@typescript-eslint/consistent-type-imports': ['error', { disallowTypeAnnotations: false }] },
  },
  globalIgnores([
    '.next/**',
    'out/**',
    'build/**',
    'next-env.d.ts',
    'playwright-report/**',
    'test-results/**',
  ]),
])
