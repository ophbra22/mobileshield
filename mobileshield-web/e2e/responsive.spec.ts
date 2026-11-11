import { expect, test, type Page } from '@playwright/test';

const SCAM = 'PayPal: your account is locked. Log in now to confirm your password: https://paypal-login.attacker.example/';

async function expectNoHorizontalScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

async function expectTouchTargets(page: Page) {
  const small = await page.locator('button:visible, a:visible, summary:visible').evaluateAll(elements => elements
    .filter(element => !element.classList.contains('skip-link'))
    .map(element => ({ label: element.textContent?.trim() || element.getAttribute('aria-label'), height: element.getBoundingClientRect().height }))
    .filter(item => item.height < 44));
  expect(small).toEqual([]);
}

test('home page fits the screen in Hebrew and English', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('dir', 'rtl');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expectNoHorizontalScroll(page);
  await expectTouchTargets(page);
  await page.screenshot({ path: testInfo.outputPath(`home-he-${testInfo.project.name}.png`), fullPage: true });

  await page.getByRole('button', { name: 'מעבר לאנגלית' }).click();
  await expect(page.locator('html')).toHaveAttribute('dir', 'ltr');
  await expect(page.getByRole('heading', { level: 1, name: 'Got a message you are not sure about?' })).toBeVisible();
  await expectNoHorizontalScroll(page);
});

test('a scam message gets a clear verdict that fits the screen', async ({ page }, testInfo) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'מעבר לאנגלית' }).click();
  await page.getByRole('textbox', { name: 'Message to check' }).fill(SCAM);
  await page.getByRole('checkbox', { name: 'Inspect linked pages too' }).check();
  await page.getByRole('button', { name: 'Check message' }).click();

  const verdict = page.getByRole('heading', { level: 2, name: 'This is probably a scam.' });
  await expect(verdict).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('heading', { name: 'What to do now' })).toBeVisible();
  await page.getByText(/Link details/).click();
  await expect(page.getByRole('heading', { level: 4, name: 'paypal-login.attacker.example' })).toBeVisible();
  await expectNoHorizontalScroll(page);
  await expectTouchTargets(page);
  await verdict.scrollIntoViewIfNeeded();
  await page.screenshot({ path: testInfo.outputPath(`result-en-${testInfo.project.name}.png`), fullPage: true });
});

test('keyboard users can reach the form and submit', async ({ page, browserName, isMobile }) => {
  test.skip(isMobile, 'No hardware keyboard on phone viewports');
  // WebKit skips links on Tab unless "Tab highlights each item" is enabled, like Safari.
  test.skip(browserName === 'webkit', 'Safari focuses links only with Option+Tab');
  await page.goto('/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'דילוג לתוכן' })).toBeFocused();
  await page.keyboard.press('Enter');
  await page.getByRole('textbox').focus();
  await page.keyboard.type('שלח לי את הסיסמה שלך עכשיו');
  await page.getByRole('button', { name: 'בדקו את ההודעה' }).press('Enter');
  await expect(page.getByRole('heading', { level: 2 })).toBeVisible({ timeout: 20_000 });
});
