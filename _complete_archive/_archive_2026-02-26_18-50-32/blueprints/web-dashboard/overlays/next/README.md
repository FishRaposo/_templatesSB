# {{PROJECT_NAME}} - Web Dashboard Reference Project

A production-ready dashboard application built with Next.js 14, demonstrating modern web development best practices.

## Features

- **Authentication**: Next-Auth with multiple providers
- **Dashboard Layout**: Responsive sidebar, header, breadcrumbs
- **Data Tables**: Sorting, filtering, pagination, export
- **Charts & Analytics**: Recharts visualizations
- **Form Handling**: React Hook Form with Zod validation
- **State Management**: Zustand for global state
- **API Integration**: React Query for data fetching
- **Dark Mode**: System-aware theme switching
- **Real-time**: WebSocket updates for live data

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS + shadcn/ui
- **State**: Zustand + React Query
- **Forms**: React Hook Form + Zod
- **Charts**: Recharts
- **Testing**: Vitest + Playwright

## Project Structure

```
{{PROJECT_NAME}}/
├── app/
│   ├── (auth)/
│   │   ├── login/page.tsx
│   │   ├── register/page.tsx
│   │   └── layout.tsx
│   ├── (dashboard)/
│   │   ├── layout.tsx              # Dashboard shell
│   │   ├── page.tsx                # Overview/home
│   │   ├── analytics/page.tsx
│   │   ├── customers/
│   │   │   ├── page.tsx            # List view
│   │   │   ├── [id]/page.tsx       # Detail view
│   │   │   └── new/page.tsx        # Create form
│   │   ├── settings/
│   │   │   ├── page.tsx
│   │   │   ├── profile/page.tsx
│   │   │   └── billing/page.tsx
│   │   └── api/
│   │       └── [...route]/route.ts # API routes
│   ├── layout.tsx                  # Root layout
│   └── globals.css
│
├── components/
│   ├── ui/                         # shadcn/ui components
│   ├── layout/
│   │   ├── sidebar.tsx
│   │   ├── header.tsx
│   │   ├── breadcrumbs.tsx
│   │   └── mobile-nav.tsx
│   ├── charts/
│   │   ├── area-chart.tsx
│   │   ├── bar-chart.tsx
│   │   └── pie-chart.tsx
│   ├── tables/
│   │   ├── data-table.tsx
│   │   ├── columns.tsx
│   │   └── toolbar.tsx
│   └── forms/
│       ├── customer-form.tsx
│       └── settings-form.tsx
│
├── lib/
│   ├── api.ts                      # API client
│   ├── auth.ts                     # Auth configuration
│   ├── utils.ts                    # Utilities
│   └── validations.ts              # Zod schemas
│
├── hooks/
│   ├── use-customers.ts
│   ├── use-analytics.ts
│   └── use-theme.ts
│
├── stores/
│   ├── ui-store.ts                 # UI state
│   └── user-store.ts               # User preferences
│
├── types/
│   └── index.ts                    # TypeScript types
│
├── public/
├── tailwind.config.ts
├── next.config.js
└── package.json
```

## Quick Start

```bash
# Install dependencies
npm install

# Setup environment
cp .env.example .env.local

# Run development server
npm run dev

# Build for production
npm run build
```

## Key Components

### Dashboard Layout

```tsx
// app/(dashboard)/layout.tsx
export default function DashboardLayout({ children }) {
  return (
    <div className="flex h-screen">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
```

### Data Table with Server-Side Operations

```tsx
// components/tables/data-table.tsx
export function DataTable<T>({
  columns,
  data,
  pagination,
  onPaginationChange,
  sorting,
  onSortingChange,
}) {
  // TanStack Table implementation
}
```

## Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Coverage
npm run test:coverage
```

## Deployment

```bash
# Vercel (recommended)
vercel

# Docker
docker build -t dashboard .
docker run -p 3000:3000 dashboard
```

## License

MIT License
