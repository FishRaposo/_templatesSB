/**
 * FILE: e2e-tests.tpl.jsx
 * PURPOSE: End-to-end test skeleton for Next.js projects using Playwright
 * AUTHOR: [[.Author]]
 * VERSION: [[.Version]]
 * SINCE: [[.Version]]
 */

import { test, expect } from '@playwright/test';

test.describe('E2E Tests', () => {
  test('e2e_homepage__happy_path', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/.*/);
  });

  test('e2e_navigation__happy_path', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link').first().click();
    await expect(page).toHaveURL(/.*/);
  });
});
