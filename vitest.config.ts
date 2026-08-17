/** Unit tests: no subprocess, no network, no harness checkout required. */
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/unit/**/*.spec.ts'],
    coverage: {
      include: ['src/**/*.ts'],
      // Per file, not in aggregate: ADR §12 describes the bar as per-file, and
      // a project-wide total lets one uncovered module hide behind the rest.
      thresholds: { perFile: true, lines: 100, functions: 100, branches: 100, statements: 100 },
    },
  },
})
