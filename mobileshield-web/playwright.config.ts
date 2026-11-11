import { defineConfig, devices } from '@playwright/test';

/**
 * Cross-browser checks: Chromium, Firefox and WebKit (Safari's engine) on
 * desktop, tablet and phone viewports. The API is the synthetic fixture server,
 * so no real site is ever contacted.
 *
 * LOCAL_CHROME=1 runs only the Chromium projects with the installed Chrome.
 */
const local = Boolean(process.env.LOCAL_CHROME);
const chrome = local ? { channel: 'chrome' as const } : {};

const allProjects = [
  { name: 'desktop-chrome', use: { ...devices['Desktop Chrome'], ...chrome } },
  { name: 'desktop-firefox', use: { ...devices['Desktop Firefox'] } },
  { name: 'desktop-safari', use: { ...devices['Desktop Safari'] } },
  { name: 'tablet-safari', use: { ...devices['iPad (gen 7)'] } },
  { name: 'phone-chrome', use: { ...devices['Pixel 7'], ...chrome } },
  { name: 'phone-safari', use: { ...devices['iPhone 14'] } },
  { name: 'small-phone-chrome', use: { ...devices['Galaxy S9+'], viewport: { width: 320, height: 640 }, ...chrome } },
];

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:3100',
    trace: 'retain-on-failure',
  },
  projects: local ? allProjects.filter(project => project.name.includes('chrome')) : allProjects,
  webServer: [
    {
      command: 'cd .. && DATABASE_URL=sqlite:// CORS_ORIGINS=http://127.0.0.1:3100 python -m uvicorn tests.fixture_server:app --port 8100',
      url: 'http://127.0.0.1:8100/health',
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      // Build first with NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8100.
      command: 'npm run start -- --port 3100',
      url: 'http://127.0.0.1:3100',
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
