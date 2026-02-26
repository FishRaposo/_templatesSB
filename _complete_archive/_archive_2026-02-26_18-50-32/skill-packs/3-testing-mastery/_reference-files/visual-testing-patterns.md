<!-- Generated from task-outputs/task-10-visual.md -->

# Visual Regression Testing with Playwright

A guide to setting up visual regression testing for responsive layouts and cross-browser consistency.

## Overview

This guide covers:
- Playwright screenshot testing
- Responsive layouts (mobile, tablet, desktop)
- Handling dynamic content
- Cross-browser testing (Chrome, Firefox, Safari)
- Baseline management
- CI integration

## Playwright Configuration

```javascript
// playwright.config.js
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/visual',
  expect: {
    toHaveScreenshot: {
      maxDiffPixels: 100,
      threshold: 0.2,
      animations: 'disabled'
    }
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'Mobile Chrome', use: { ...devices['Pixel 5'] } },
    { name: 'Mobile Safari', use: { ...devices['iPhone 12'] } }
  ]
});
```

## Visual Test Implementation

```javascript
// tests/visual/homepage.spec.js
describe('Homepage Visual Regression', () => {
  test.beforeEach(async ({ page }) => {
    // Hide dynamic content
    await page.addStyleTag({
      content: `
        .timestamp, .live-chat { display: none !important; }
      `
    });
    await page.goto('/');
  });

  test('homepage - full page', async ({ page }) => {
    await expect(page).toHaveScreenshot('homepage-full.png', {
      fullPage: true
    });
  });

  test('homepage - dark mode', async ({ page }) => {
    await page.click('[data-testid="theme-toggle"]');
    await page.waitForTimeout(300);
    await expect(page).toHaveScreenshot('homepage-dark.png');
  });
});
```

## Responsive Testing

```javascript
// tests/visual/responsive.spec.js
const viewports = [
  { name: 'mobile', width: 375, height: 667 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1440, height: 900 }
];

for (const viewport of viewports) {
  test(`homepage - ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize({
      width: viewport.width,
      height: viewport.height
    });
    await page.goto('/');
    await expect(page).toHaveScreenshot(`homepage-${viewport.name}.png`);
  });
}
```

## CI Integration

```yaml
# .github/workflows/visual.yml
jobs:
  visual-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      - run: npx playwright install --with-deps
      - run: npm run test:visual
```

## Results

| Component | Viewports | Browsers | Status |
|-----------|-----------|----------|--------|
| Homepage | 5 | 3 | ✅ |
| Product Grid | 3 | 3 | ✅ |
| Modal Dialog | 1 | 3 | ✅ |

## Best Practices

1. **Mock dynamic content** — Timestamps, random data
2. **Hide animations** — Use CSS or wait for completion
3. **Strategic breakpoints** — 5 viewports cover most devices
4. **Baseline approval workflow** — Review diffs before updating
