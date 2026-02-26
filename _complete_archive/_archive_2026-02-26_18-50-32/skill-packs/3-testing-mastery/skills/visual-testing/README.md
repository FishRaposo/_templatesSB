# Visual Testing

Implement visual regression testing to detect unintended UI changes.

## Quick Start

```javascript
// Playwright
test('homepage visual', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveScreenshot('homepage.png');
});
```

## How It Works

1. **Capture** — Take screenshot
2. **Compare** — Diff against baseline
3. **Report** — Highlight differences
4. **Approve** — Update baseline if intentional

## Tools

| Tool | Best For |
|------|----------|
| **Playwright** | E2E visual tests |
| **Chromatic** | Component libraries |
| **Percy** | CI integration |
| **Storybook** | Component development |

## Handle Dynamic Content

```javascript
test('page', async ({ page }) => {
  await page.goto('/');
  
  // Hide dynamic elements
  await page.addStyleTag({
    content: '.timestamp { visibility: hidden; }'
  });
  
  await expect(page).toHaveScreenshot();
});
```

## Responsive Testing

```javascript
test('responsive', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 667 });
  await expect(page).toHaveScreenshot('mobile.png');
  
  await page.setViewportSize({ width: 1920, height: 1080 });
  await expect(page).toHaveScreenshot('desktop.png');
});
```

## Key Principles

- Mask dynamic content (timestamps, random data)
- Disable animations
- Store baselines in version control
- Review diffs in PRs

## Examples

See `examples/basic-examples.md` for full visual testing examples.

## Related Skills

- `test-automation` — Integrate visual tests in CI
- `test-strategy` — Decide when to visual test
