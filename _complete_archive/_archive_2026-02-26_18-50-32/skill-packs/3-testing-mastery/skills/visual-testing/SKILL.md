---
name: visual-testing
description: Use this skill when implementing visual regression testing to detect unintended UI changes. This includes capturing screenshots, comparing against baselines, handling dynamic content, and integrating visual tests into CI/CD pipelines. Focus on detecting visual bugs that functional tests miss.
---

# Visual Testing

I'll help you implement visual regression testing to catch unintended UI changes — detecting visual bugs that functional tests miss.

## Core Approach

### How Visual Testing Works

1. **Capture** — Take screenshot of UI
2. **Compare** — Diff against baseline image
3. **Report** — Highlight pixel differences
4. **Approve** — Update baseline if change is intentional

### When to Use

- Component libraries
- Critical user flows
- Responsive layouts
- Cross-browser consistency
- Design system compliance

## Step-by-Step Instructions

### 1. Set Up Visual Testing Tool

**JavaScript (Playwright + Argos CI)**
```javascript
// playwright.config.js
module.exports = {
  use: {
    screenshot: 'only-on-failure',
  },
};

// Visual test
test('homepage visual', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveScreenshot('homepage.png', {
    maxDiffPixels: 100,  // Allow small anti-aliasing diffs
  });
});
```

**JavaScript (Storybook + Chromatic)**
```javascript
// .storybook/main.js
module.exports = {
  addons: ['@chromatic-com/storybook'],
};

// Component automatically visually tested via stories
```

**JavaScript (Cypress + Percy)**
```javascript
// cypress/e2e/visual.cy.js
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

**Python (Selenium + Pillow)**
```python
import pytest
from PIL import Image, ImageChops
import io

def test_homepage_visual(driver):
    driver.get('/')
    
    # Capture screenshot
    screenshot = driver.get_screenshot_as_png()
    current = Image.open(io.BytesIO(screenshot))
    
    # Load baseline
    baseline = Image.open('baselines/homepage.png')
    
    # Compare
    diff = ImageChops.difference(current, baseline)
    
    if diff.getbbox():
        # Save diff for review
        diff.save('diffs/homepage.png')
        pytest.fail("Visual regression detected")
```

### 2. Handle Dynamic Content

**JavaScript (Playwright)**
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
        revenue: 10000,  // Fixed value
        users: 5000,
      }),
    });
  });
  
  await expect(page).toHaveScreenshot('dashboard.png');
});
```

**Stabilize animations:**
```javascript
// Pause animations
test('modal visual', async ({ page }) => {
  await page.goto('/');
  await page.click('[data-testid="open-modal"]');
  
  // Wait for animation to complete
  await page.waitForTimeout(500);
  
  // Or disable animations in test environment
  await page.addStyleTag({
    content: '* { animation-duration: 0s !important; }'
  });
  
  await expect(page).toHaveScreenshot('modal.png');
});
```

### 3. Test Component Variants

**JavaScript (Storybook)**
```javascript
// Button.stories.js
export const Primary = {
  args: {
    variant: 'primary',
    children: 'Click me',
  },
};

export const Secondary = {
  args: {
    variant: 'secondary',
    children: 'Click me',
  },
};

export const Loading = {
  args: {
    variant: 'primary',
    loading: true,
    children: 'Loading...',
  },
};

export const Disabled = {
  args: {
    variant: 'primary',
    disabled: true,
    children: 'Disabled',
  },
};

// All variants automatically tested visually
```

### 4. Cross-Browser Testing

**Playwright multi-browser:**
```javascript
// playwright.config.js
module.exports = {
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
};
```

### 5. Responsive Testing

**JavaScript (Playwright)**
```javascript
test('responsive layout', async ({ page }) => {
  const viewports = [
    { name: 'mobile', width: 375, height: 667 },
    { name: 'tablet', width: 768, height: 1024 },
    { name: 'desktop', width: 1920, height: 1080 },
  ];
  
  for (const viewport of viewports) {
    await page.setViewportSize({
      width: viewport.width,
      height: viewport.height,
    });
    
    await page.goto('/');
    
    await expect(page).toHaveScreenshot(
      `homepage-${viewport.name}.png`
    );
  }
});
```

## Multi-Language Examples

### Complete Visual Test Suite

**JavaScript (Playwright)**
```javascript
// tests/visual.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Visual Regression', () => {
  test.beforeEach(async ({ page }) => {
    // Disable animations globally
    await page.addStyleTag({
      content: `
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      `
    });
  });
  
  test('homepage', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveScreenshot('homepage.png');
  });
  
  test('product page', async ({ page }) => {
    await page.goto('/products/123');
    
    // Mock product data for consistency
    await page.route('/api/products/123', route => {
      route.fulfill({
        body: JSON.stringify({
          id: '123',
          name: 'Test Product',
          price: 99.99,
          image: '/test-product.jpg',
        }),
      });
    });
    
    await expect(page).toHaveScreenshot('product-page.png');
  });
  
  test('cart modal', async ({ page }) => {
    await page.goto('/');
    await page.click('[data-testid="cart-button"]');
    
    // Wait for modal animation
    await page.waitForSelector('[data-testid="cart-modal"]', {
      state: 'visible',
    });
    
    await expect(page).toHaveScreenshot('cart-modal.png', {
      clip: {  // Only capture modal area
        x: 0,
        y: 0,
        width: 500,
        height: 600,
      },
    });
  });
  
  test('dark mode', async ({ page }) => {
    await page.goto('/');
    await page.click('[data-testid="theme-toggle"]');
    await expect(page).toHaveScreenshot('homepage-dark.png');
  });
});
```

### Component-Level Visual Testing

**JavaScript (React + Storybook)**
```javascript
// Card.stories.js
export default {
  title: 'Components/Card',
  component: Card,
  parameters: {
    chromatic: {
      viewports: [320, 768, 1920],  // Test multiple viewports
    },
  },
};

export const Default = {
  args: {
    title: 'Card Title',
    description: 'This is a card description.',
    image: '/card-image.jpg',
  },
};

export const LongContent = {
  args: {
    title: 'This is a very long card title that might wrap',
    description: 'Lorem ipsum '.repeat(50),
    image: '/card-image.jpg',
  },
};

export const NoImage = {
  args: {
    title: 'Card without image',
    description: 'This card has no image.',
  },
};
```

## Best Practices

### Test Selection

**Visual test when:**
- UI is stable
- Design is important
- Regression risk is high
- Manual testing is tedious

**Don't visual test when:**
- UI changes frequently (WIP)
- Content is highly dynamic
- Functional tests suffice

### Baseline Management

1. **Store baselines in version control**
   ```bash
   git add tests/__snapshots__/
   ```

2. **Review diffs in PRs**
   - Visual changes show as image diffs
   - Approve intentional changes
   - Reject unintended changes

3. **Update baselines intentionally**
   ```bash
   # Playwright
   npx playwright test --update-snapshots
   
   # Jest
   npm test -- --updateSnapshot
   ```

### Threshold Configuration

```javascript
// Allow small anti-aliasing differences
expect(page).toHaveScreenshot('page.png', {
  maxDiffPixels: 100,        // Pixel count
  maxDiffPixelRatio: 0.02,   // Percentage
  threshold: 0.2,            // Color threshold (0-1)
});
```

## Common Pitfalls

❌ **Testing everything visually**
- Slow and brittle
- Focus on critical UI

❌ **Dynamic content without masking**
```javascript
// Bad: timestamps cause diffs
test('page', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveScreenshot();  // Fails due to time
});

// Good: hide dynamic content
test('page', async ({ page }) => {
  await page.goto('/');
  await page.addStyleTag({
    content: '.timestamp { visibility: hidden; }'
  });
  await expect(page).toHaveScreenshot();
});
```

❌ **Large threshold hiding real bugs**
```javascript
// Bad: threshold too high
{ threshold: 0.5 }  // 50% color difference allowed!

// Good: specific threshold
{ maxDiffPixels: 50 }
```

## Validation Checklist

- [ ] Dynamic content is masked/stabilized
- [ ] Baselines are stored and versioned
- [ ] Thresholds are appropriate (not too strict/loose)
- [ ] CI runs visual tests
- [ ] Review process for visual changes
- [ ] Cross-browser testing configured
- [ ] Responsive breakpoints tested
- [ ] Animations disabled or completed

## Related Skills

- **test-automation** — Integrate visual tests in CI
- **test-strategy** — Decide when to visual test
- **e2e-testing** — Functional tests before visual
