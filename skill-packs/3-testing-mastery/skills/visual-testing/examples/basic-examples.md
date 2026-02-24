# Visual Testing Examples

## Playwright Screenshot Test

```javascript
const { test, expect } = require('@playwright/test');

test('homepage visual', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveScreenshot('homepage.png', {
    maxDiffPixels: 100,
  });
});

test('responsive layouts', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 667 });
  await page.goto('/');
  await expect(page).toHaveScreenshot('homepage-mobile.png');
  
  await page.setViewportSize({ width: 1920, height: 1080 });
  await expect(page).toHaveScreenshot('homepage-desktop.png');
});
```

## Handling Dynamic Content

```javascript
test('dashboard visual', async ({ page }) => {
  await page.goto('/dashboard');
  
  // Hide dynamic elements
  await page.addStyleTag({
    content: `
      .current-time { visibility: hidden !important; }
      .random-chart-data { visibility: hidden !important; }
    `
  });
  
  // Mock API for consistent data
  await page.route('/api/metrics', route => {
    route.fulfill({
      body: JSON.stringify({
        revenue: 10000,
        users: 5000,
      }),
    });
  });
  
  await expect(page).toHaveScreenshot('dashboard.png');
});
```

## Storybook + Chromatic

```javascript
// Button.stories.js
export default {
  title: 'Components/Button',
  component: Button,
  parameters: {
    chromatic: {
      viewports: [320, 768, 1920],
    },
  },
};

export const Primary = {
  args: { variant: 'primary', children: 'Click me' },
};

export const Secondary = {
  args: { variant: 'secondary', children: 'Click me' },
};

export const Loading = {
  args: { loading: true, children: 'Loading...' },
};
```

## Cypress + Percy

```javascript
describe('Visual Regression', () => {
  it('homepage looks correct', () => {
    cy.visit('/');
    cy.percySnapshot('homepage');
  });
  
  it('responsive layouts', () => {
    cy.viewport('iphone-6');
    cy.visit('/');
    cy.percySnapshot('homepage-mobile');
    
    cy.viewport('macbook-15');
    cy.percySnapshot('homepage-desktop');
  });
});
```

## Best Practices

- Hide dynamic content (timestamps, random data)
- Disable animations
- Test multiple viewports
- Cross-browser testing
- Baseline review process
