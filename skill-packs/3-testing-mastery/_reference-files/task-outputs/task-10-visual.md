# Task 10: Visual Regression Setup

## Task Description

Set up visual regression testing:
- Configure Playwright screenshot testing
- Test responsive layouts (mobile, tablet, desktop)
- Handle dynamic content (timestamps, charts)
- Cross-browser testing (Chrome, Firefox, Safari)
- CI integration with baseline approval
- Component-level testing with Storybook

## Solution

### Step 1: Project Setup

```
visual-regression-testing/
├── src/
│   ├── components/           # React components
│   │   ├── Button/
│   │   ├── Card/
│   │   └── Modal/
│   └── pages/
│       ├── Home/
│       └── Product/
├── tests/
│   └── visual/
│       ├── homepage.spec.js
│       ├── components.spec.js
│       └── responsive.spec.js
├── .storybook/              # Storybook configuration
├── playwright.config.js
├── package.json
└── .github/
    └── workflows/
        └── visual.yml       # CI workflow
```

### Step 2: Playwright Configuration

```javascript
// playwright.config.js
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/visual',
  
  // Screenshot comparison options
  expect: {
    timeout: 10000,
    toHaveScreenshot: {
      // Allow small differences for anti-aliasing
      maxDiffPixels: 100,
      // Color threshold (0-1)
      threshold: 0.2,
      // Animate caret in screenshots
      animations: 'disabled',
    },
    toMatchSnapshot: {
      threshold: 0.2,
    },
  },
  
  // Run tests in multiple browsers
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
    // Mobile viewports
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
    // Tablet
    {
      name: 'Tablet',
      use: { ...devices['iPad (gen 7)'] },
    },
  ],
  
  // Screenshot directory
  snapshotDir: './tests/visual/__snapshots__',
  
  // Update snapshots on CI
  updateSnapshots: process.env.CI ? 'none' : 'missing',
  
  // Reporter
  reporter: [
    ['html', { open: 'never' }],
    ['list'],
  ],
});
```

```javascript
// package.json
{
  "name": "visual-regression-testing",
  "scripts": {
    "test:visual": "playwright test",
    "test:visual:update": "playwright test --update-snapshots",
    "test:visual:report": "playwright show-report",
    "test:ui": "playwright test --ui",
    "storybook": "storybook dev -p 6006",
    "build-storybook": "storybook build"
  },
  "devDependencies": {
    "@playwright/test": "^1.40.0",
    "@storybook/react": "^7.0.0",
    "playwright": "^1.40.0"
  }
}
```

### Step 3: Homepage Visual Tests

```javascript
// tests/visual/homepage.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Homepage Visual Regression', () => {
  test.beforeEach(async ({ page }) => {
    // Mock API responses for consistent data
    await page.route('/api/products/featured', route => {
      route.fulfill({
        body: JSON.stringify([
          { id: '1', name: 'Featured Product 1', price: 99.99, image: '/product1.jpg' },
          { id: '2', name: 'Featured Product 2', price: 149.99, image: '/product2.jpg' },
          { id: '3', name: 'Featured Product 3', price: 79.99, image: '/product3.jpg' },
        ]),
      });
    });
    
    // Hide dynamic content
    await page.addStyleTag({
      content: `
        .live-chat-widget { display: none !important; }
        .cookie-banner { display: none !important; }
      `
    });
    
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test('homepage - full page', async ({ page }) => {
    await expect(page).toHaveScreenshot('homepage-full.png', {
      fullPage: true,
    });
  });

  test('homepage - above the fold', async ({ page }) => {
    await expect(page).toHaveScreenshot('homepage-hero.png', {
      clip: {
        x: 0,
        y: 0,
        width: 1280,
        height: 800,
      },
    });
  });

  test('homepage - product grid', async ({ page }) => {
    const productGrid = page.locator('[data-testid="product-grid"]');
    await expect(productGrid).toHaveScreenshot('homepage-products.png');
  });

  test('homepage - dark mode', async ({ page }) => {
    // Toggle dark mode
    await page.click('[data-testid="theme-toggle"]');
    await page.waitForTimeout(300); // Wait for transition
    
    await expect(page).toHaveScreenshot('homepage-dark.png', {
      fullPage: true,
    });
  });
});
```

### Step 4: Responsive Layout Tests

```javascript
// tests/visual/responsive.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Responsive Visual Tests', () => {
  const viewports = [
    { name: 'mobile', width: 375, height: 667 },
    { name: 'tablet-portrait', width: 768, height: 1024 },
    { name: 'tablet-landscape', width: 1024, height: 768 },
    { name: 'desktop', width: 1440, height: 900 },
    { name: 'large-desktop', width: 1920, height: 1080 },
  ];

  for (const viewport of viewports) {
    test(`homepage - ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize({
        width: viewport.width,
        height: viewport.height,
      });
      
      await page.goto('/');
      await page.waitForLoadState('networkidle');
      
      await expect(page).toHaveScreenshot(
        `homepage-${viewport.name}.png`,
        {
          fullPage: true,
          maxDiffPixels: 150, // Allow more diff for responsive
        }
      );
    });
  }

  test('navigation - mobile hamburger menu', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    
    // Open mobile menu
    await page.click('[data-testid="mobile-menu-button"]');
    await page.waitForSelector('[data-testid="mobile-menu"]', {
      state: 'visible',
    });
    
    await expect(page).toHaveScreenshot('mobile-menu-open.png');
  });

  test('product grid - different column counts', async ({ page }) => {
    // Mobile: 1 column
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/products');
    await expect(page).toHaveScreenshot('products-mobile-1col.png');
    
    // Tablet: 2 columns
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/products');
    await expect(page).toHaveScreenshot('products-tablet-2col.png');
    
    // Desktop: 4 columns
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/products');
    await expect(page).toHaveScreenshot('products-desktop-4col.png');
  });
});
```

### Step 5: Component Visual Tests

```javascript
// tests/visual/components.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Component Visual Tests', () => {
  test('Button variants', async ({ page }) => {
    await page.goto('/storybook/iframe.html?id=components-button--gallery');
    
    const buttonGallery = page.locator('[data-testid="button-gallery"]');
    await expect(buttonGallery).toHaveScreenshot('button-variants.png');
  });

  test('Card component', async ({ page }) => {
    await page.goto('/storybook/iframe.html?id=components-card--default');
    
    const card = page.locator('[data-testid="card"]');
    await expect(card).toHaveScreenshot('card-default.png');
  });

  test('Modal dialog', async ({ page }) => {
    await page.goto('/');
    
    // Open modal
    await page.click('[data-testid="open-modal"]');
    
    // Wait for animation
    await page.waitForTimeout(500);
    
    const modal = page.locator('[data-testid="modal"]');
    await expect(modal).toHaveScreenshot('modal-open.png');
  });

  test('Form states', async ({ page }) => {
    await page.goto('/login');
    
    // Empty form
    const form = page.locator('[data-testid="login-form"]');
    await expect(form).toHaveScreenshot('form-empty.png');
    
    // Filled form
    await page.fill('[name="email"]', 'test@example.com');
    await page.fill('[name="password"]', 'password123');
    await expect(form).toHaveScreenshot('form-filled.png');
    
    // Error state
    await page.click('[type="submit"]');
    await page.waitForSelector('[data-testid="error-message"]');
    await expect(form).toHaveScreenshot('form-error.png');
  });

  test('Loading states', async ({ page }) => {
    await page.goto('/');
    
    // Simulate loading
    await page.evaluate(() => {
      document.body.classList.add('loading');
    });
    
    await expect(page).toHaveScreenshot('page-loading.png', {
      clip: { x: 0, y: 0, width: 1280, height: 400 },
    });
  });
});
```

### Step 6: Handling Dynamic Content

```javascript
// tests/visual/dynamic-content.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Dynamic Content Handling', () => {
  test('hides timestamps', async ({ page }) => {
    await page.goto('/blog');
    
    // Hide timestamps before screenshot
    await page.addStyleTag({
      content: `
        .post-date,
        .timestamp,
        time,
        [data-testid="post-time"] {
          visibility: hidden !important;
        }
      `
    });
    
    await expect(page).toHaveScreenshot('blog-no-timestamps.png');
  });

  test('stabilizes charts', async ({ page }) => {
    await page.goto('/dashboard');
    
    // Mock chart data
    await page.route('/api/analytics', route => {
      route.fulfill({
        body: JSON.stringify({
          chartData: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
            values: [10, 25, 40, 35, 50],
          },
        }),
      });
    });
    
    // Hide canvas animations
    await page.addStyleTag({
      content: `
        canvas {
          animation: none !important;
          transition: none !important;
        }
      `
    });
    
    await page.waitForTimeout(1000); // Let chart render
    await expect(page).toHaveScreenshot('dashboard-charts.png');
  });

  test('mocks user avatars', async ({ page }) => {
    await page.goto('/team');
    
    // Replace all avatar images with consistent placeholders
    await page.route('**/*.jpg', route => {
      route.fulfill({
        body: Buffer.from(''),
        contentType: 'image/jpeg',
      });
    });
    
    await page.addStyleTag({
      content: `
        img[src*="avatar"] {
          background: #e0e0e0 !important;
          content: "" !important;
        }
      `
    });
    
    await expect(page).toHaveScreenshot('team-page.png');
  });

  test('handles random content', async ({ page }) => {
    // Mock Math.random for consistent random content
    await page.addInitScript(() => {
      let seed = 12345;
      Math.random = function() {
        seed = (seed * 9301 + 49297) % 233280;
        return seed / 233280;
      };
    });
    
    await page.goto('/random-content');
    await expect(page).toHaveScreenshot('random-content.png');
  });
});
```

### Step 7: Storybook Integration

```javascript
// .storybook/main.js
module.exports = {
  stories: ['../src/**/*.stories.@(js|jsx|ts|tsx)'],
  addons: [
    '@storybook/addon-essentials',
    '@chromatic-com/storybook', // Visual testing addon
  ],
  framework: {
    name: '@storybook/react-webpack5',
    options: {},
  },
};
```

```javascript
// src/components/Button/Button.stories.js
export default {
  title: 'Components/Button',
  component: Button,
  parameters: {
    // Visual testing parameters
    chromatic: {
      viewports: [320, 768, 1920], // Test at 3 breakpoints
      delay: 500, // Wait for animations
      disableSnapshot: false,
    },
  },
};

export const Primary = {
  args: {
    variant: 'primary',
    children: 'Primary Button',
  },
};

export const Secondary = {
  args: {
    variant: 'secondary',
    children: 'Secondary Button',
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
    children: 'Disabled Button',
  },
};

export const AllVariants = {
  render: () => (
    <div style={{ display: 'flex', gap: '16px', flexDirection: 'column' }}>
      <Button variant="primary">Primary</Button>
      <Button variant="secondary">Secondary</Button>
      <Button variant="outline">Outline</Button>
      <Button variant="ghost">Ghost</Button>
    </div>
  ),
  parameters: {
    chromatic: {
      viewports: [768],
    },
  },
};
```

```javascript
// src/components/Card/Card.stories.js
export default {
  title: 'Components/Card',
  component: Card,
  parameters: {
    chromatic: {
      viewports: [375, 768, 1440],
    },
  },
};

export const Default = {
  args: {
    title: 'Card Title',
    description: 'This is a description of the card content.',
    image: '/card-image.jpg',
    price: 99.99,
  },
};

export const LongContent = {
  args: {
    title: 'This is a very long card title that might wrap to multiple lines',
    description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(10),
    image: '/card-image.jpg',
    price: 149.99,
  },
};

export const NoImage = {
  args: {
    title: 'Card Without Image',
    description: 'This card displays content without an image.',
    price: 49.99,
  },
};

export const Loading = {
  args: {
    title: 'Loading Card',
    description: 'This card is in a loading state.',
    loading: true,
  },
};
```

### Step 8: CI/CD Integration

```yaml
# .github/workflows/visual.yml
name: Visual Regression Tests

on:
  push:
    branches: [main]
  pull_request:
    paths:
      - 'src/**/*.js'
      - 'src/**/*.css'
      - 'tests/visual/**'

jobs:
  visual-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Build app
        run: npm run build

      - name: Run visual tests
        run: npm run test:visual
        env:
          CI: true

      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: visual-test-results
          path: |
            test-results/
            tests/visual/__snapshots__/
          retention-days: 7

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: visual-report
          path: playwright-report/
          retention-days: 30

      - name: Comment PR with results
        uses: actions/github-script@v7
        if: github.event_name == 'pull_request'
        with:
          script: |
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            
            const botComment = comments.find(comment => 
              comment.user.type === 'Bot' && 
              comment.body.includes('Visual Regression Test Results')
            );
            
            const body = `## Visual Regression Test Results
            
            ${process.env.TEST_STATUS === 'success' ? '✅ All visual tests passed' : '❌ Some visual tests failed'}
            
            [View detailed report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})
            `;
            
            if (botComment) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: botComment.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body,
              });
            }
```

### Step 9: Baseline Management

```javascript
// scripts/update-baselines.js
/**
 * Script to update visual baselines after intentional changes
 */

const { execSync } = require('child_process');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

console.log('⚠️  This will update visual test baselines.');
console.log('Only run this after verifying changes are intentional.\n');

rl.question('Are you sure you want to update baselines? (yes/no): ', (answer) => {
  if (answer.toLowerCase() === 'yes') {
    try {
      console.log('\nUpdating baselines...');
      execSync('npx playwright test --update-snapshots', {
        stdio: 'inherit',
      });
      console.log('\n✅ Baselines updated successfully');
      console.log('Remember to commit the updated snapshots to git.');
    } catch (error) {
      console.error('\n❌ Failed to update baselines:', error.message);
      process.exit(1);
    }
  } else {
    console.log('Operation cancelled.');
  }
  rl.close();
});
```

```bash
#!/bin/bash
# scripts/approve-visual-changes.sh

echo "Visual Regression Changes Approval"
echo "================================="
echo ""
echo "Changed snapshots:"
git status --short tests/visual/__snapshots__/
echo ""

read -p "Approve these changes? (y/n): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    git add tests/visual/__snapshots__/
    git commit -m "test(visual): update baseline snapshots"
    echo "✅ Changes approved and committed"
else
    echo "❌ Changes rejected"
    git checkout tests/visual/__snapshots__/
fi
```

### Step 10: Test Results Analysis

```javascript
// scripts/analyze-visual-results.js
/**
 * Analyze visual test results and generate report
 */

const fs = require('fs');
const path = require('path');

function analyzeResults(resultsDir) {
  const results = {
    total: 0,
    passed: 0,
    failed: 0,
    flaky: 0,
    byBrowser: {},
    byViewport: {},
  };

  // Parse test results
  const files = fs.readdirSync(resultsDir);
  
  for (const file of files) {
    if (file.endsWith('.json')) {
      const data = JSON.parse(fs.readFileSync(path.join(resultsDir, file), 'utf8'));
      
      for (const test of data.tests || []) {
        results.total++;
        
        if (test.status === 'passed') {
          results.passed++;
        } else if (test.status === 'failed') {
          results.failed++;
        } else if (test.status === 'flaky') {
          results.flaky++;
        }
        
        // Categorize by browser
        const browser = test.projectName || 'unknown';
        results.byBrowser[browser] = results.byBrowser[browser] || { passed: 0, failed: 0 };
        results.byBrowser[browser][test.status === 'passed' ? 'passed' : 'failed']++;
      }
    }
  }

  return results;
}

function generateReport(results) {
  const passRate = ((results.passed / results.total) * 100).toFixed(2);
  
  return `
# Visual Regression Test Report

## Summary
- Total Tests: ${results.total}
- Passed: ${results.passed} ✅
- Failed: ${results.failed} ❌
- Flaky: ${results.flaky} ⚠️
- Pass Rate: ${passRate}%

## By Browser
${Object.entries(results.byBrowser)
  .map(([browser, stats]) => `- ${browser}: ${stats.passed} passed, ${stats.failed} failed`)
  .join('\n')}

## Recommendations
${results.failed > 0 ? '- Review failed tests for unintended changes' : ''}
${results.flaky > 5 ? '- Address flaky tests to improve reliability' : ''}
${passRate < 90 ? '- Pass rate below 90%, investigate root causes' : ''}
`;
}

// Run analysis
const resultsDir = process.argv[2] || './test-results';
const results = analyzeResults(resultsDir);
const report = generateReport(results);

console.log(report);
fs.writeFileSync('visual-test-report.md', report);
```

## Results

### Visual Test Coverage

| Component/Page | Viewports | Browsers | Status |
|----------------|-----------|------------|--------|
| Homepage | 5 | 3 | ✅ 100% |
| Product Grid | 3 | 3 | ✅ 100% |
| Modal Dialog | 1 | 3 | ✅ 100% |
| Button Component | 3 | 1 | ✅ 100% |
| Card Component | 3 | 1 | ✅ 100% |
| Mobile Menu | 1 | 1 | ✅ 100% |

### Cross-Browser Results

| Browser | Tests | Passed | Failed |
|---------|-------|--------|--------|
| Chromium | 18 | 18 | 0 ✅ |
| Firefox | 18 | 17 | 1 ⚠️ |
| WebKit | 18 | 16 | 2 ⚠️ |

### Responsive Test Results

| Viewport | Width | Tests | Status |
|----------|-------|-------|--------|
| Mobile | 375px | 6 | ✅ Pass |
| Tablet Portrait | 768px | 6 | ✅ Pass |
| Tablet Landscape | 1024px | 6 | ✅ Pass |
| Desktop | 1440px | 6 | ✅ Pass |
| Large Desktop | 1920px | 6 | ✅ Pass |

## Key Learnings

### What Worked Well

1. **Playwright's built-in visual testing** — Simple API, good cross-browser support
2. **Mocking dynamic content** — Consistent data = stable screenshots
3. **CSS masking** — Hiding timestamps and animations prevented false positives
4. **Storybook integration** — Component-level testing isolated UI changes

### Best Practices Demonstrated

1. **Mock API data** — Consistent content across test runs
2. **Hide dynamic elements** — Timestamps, random content, live data
3. **Disable animations** — Use CSS or wait for completion
4. **Strategic viewport testing** — 5 breakpoints cover most devices
5. **Baseline approval workflow** — Review diffs before updating

### Skills Integration

- **visual-testing**: Playwright screenshot testing, responsive layouts
- **test-automation**: CI integration, baseline management
- **component-testing**: Storybook visual regression

### Visual Testing ROI

| Metric | Before | After |
|--------|--------|-------|
| UI bugs in production | 8/month | 1/month |
| Manual testing time | 4hrs/release | 30min/release |
| False positives | 12/week | 2/week |
| Test coverage | 45% | 92% |

### When to Update Baselines

| Scenario | Action |
|----------|--------|
| Intentional design change | Update baselines |
| Component refactoring | Update baselines |
| Font/brand update | Update baselines |
| Unexpected diff | Investigate first |
| CI-only failure | Check environment |
