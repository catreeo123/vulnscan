import { defineConfig, configDefaults } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    // Stale git worktrees under .claude/worktrees/ hold copies of this suite;
    // without this they get globbed and run as phantom duplicate tests.
    exclude: [...configDefaults.exclude, '**/.claude/**'],
  },
})
