import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const PAGES = ['/', '/privacy', '/cookies', '/terms', '/accessibility'];

async function expectNoViolations(page: Page, label: string) {
  const { violations } = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  const summary = violations.map(v => `${v.id} (${v.impact}): ${v.nodes.map(n => n.target.join(' ')).join(', ')}`);
  expect(summary, `${label} has WCAG 2.1 AA violations`).toEqual([]);
}

test.describe('WCAG 2.1 AA (axe-core)', () => {
  for (const path of PAGES) {
    test(`${path} in Hebrew and English`, async ({ page }) => {
      await page.addInitScript(() => localStorage.setItem('ms_storage_choice', 'denied'));
      await page.goto(path);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await expectNoViolations(page, `${path} (he)`);
      await page.getByRole('button', { name: /מעבר לאנגלית/ }).click();
      await expect(page.locator('html')).toHaveAttribute('lang', 'en');
      await expectNoViolations(page, `${path} (en)`);
    });
  }

  test('result screen and link details', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('ms_storage_choice', 'denied'));
    await page.goto('/');
    await page.getByRole('textbox').fill('PayPal: your account is locked. Log in now: https://paypal-login.attacker.example/');
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: 'בדקו את ההודעה' }).click();
    await expect(page.getByRole('heading', { level: 2, name: 'זו כנראה הונאה.' })).toBeVisible({ timeout: 20_000 });
    await page.getByText(/פרטי הקישורים/).click();
    await expectNoViolations(page, 'result');
  });

  test('storage notice on a first visit', async ({ page, browserName }) => {
    await page.goto('/');
    const notice = page.getByRole('region', { name: 'עוגיות ואחסון' });
    await expect(notice).toBeVisible();
    // Headless Firefox in CI crashes inside axe's analysis of this fixed-position
    // region (a test-tool crash, not a page error). Chromium and WebKit audit it;
    // Firefox still runs the behavior checks below.
    if (browserName !== 'firefox') await expectNoViolations(page, 'storage notice');
    // Nothing optional is stored before a choice, and the page stays usable.
    await page.getByRole('button', { name: /מעבר לאנגלית/ }).click();
    expect(await page.evaluate(() => localStorage.getItem('ms_lang'))).toBeNull();
    await page.getByRole('button', { name: 'Allow' }).click();
    await expect(notice).toBeHidden();
    expect(await page.evaluate(() => localStorage.getItem('ms_lang'))).toBe('en');
  });
});
