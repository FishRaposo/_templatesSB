"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
    ChevronLeft,
    LayoutDashboard,
    Users,
    BarChart3,
    Settings,
    HelpCircle,
    CreditCard,
    FileText,
    Bell,
    LogOut,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";

// ============================================================================
// Types
// ============================================================================

interface NavItem {
    title: string;
    href: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
    children?: NavItem[];
}

interface SidebarProps {
    className?: string;
}

// ============================================================================
// Navigation Items
// ============================================================================

const mainNavItems: NavItem[] = [
    {
        title: "Dashboard",
        href: "/",
        icon: LayoutDashboard,
    },
    {
        title: "Analytics",
        href: "/analytics",
        icon: BarChart3,
        badge: "New",
    },
    {
        title: "Customers",
        href: "/customers",
        icon: Users,
    },
    {
        title: "Billing",
        href: "/billing",
        icon: CreditCard,
    },
    {
        title: "Reports",
        href: "/reports",
        icon: FileText,
        children: [
            { title: "Overview", href: "/reports", icon: FileText },
            { title: "Revenue", href: "/reports/revenue", icon: FileText },
            { title: "Usage", href: "/reports/usage", icon: FileText },
        ],
    },
];

const bottomNavItems: NavItem[] = [
    {
        title: "Notifications",
        href: "/notifications",
        icon: Bell,
        badge: "3",
    },
    {
        title: "Settings",
        href: "/settings",
        icon: Settings,
    },
    {
        title: "Help",
        href: "/help",
        icon: HelpCircle,
    },
];

// ============================================================================
// Sidebar Component
// ============================================================================

export function Sidebar({ className }: SidebarProps) {
    const pathname = usePathname();
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [expandedItems, setExpandedItems] = useState<string[]>([]);

    const toggleExpanded = (title: string) => {
        setExpandedItems((prev) =>
            prev.includes(title)
                ? prev.filter((item) => item !== title)
                : [...prev, title]
        );
    };

    return (
        <TooltipProvider delayDuration={0}>
            <aside
                className={cn(
                    "relative flex h-screen flex-col border-r bg-background transition-all duration-300",
                    isCollapsed ? "w-16" : "w-64",
                    className
                )}
            >
                {/* Logo */}
                <div className="flex h-16 items-center border-b px-4">
                    <Link href="/" className="flex items-center gap-2">
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary">
                            <span className="text-lg font-bold text-primary-foreground">
                                D
                            </span>
                        </div>
                        {!isCollapsed && (
                            <span className="text-lg font-semibold">Dashboard</span>
                        )}
                    </Link>
                </div>

                {/* Main Navigation */}
                <ScrollArea className="flex-1 px-3 py-4">
                    <nav className="flex flex-col gap-1">
                        {mainNavItems.map((item) => (
                            <NavItem
                                key={item.href}
                                item={item}
                                isCollapsed={isCollapsed}
                                isActive={pathname === item.href}
                                isExpanded={expandedItems.includes(item.title)}
                                onToggleExpand={() => toggleExpanded(item.title)}
                                pathname={pathname}
                            />
                        ))}
                    </nav>
                </ScrollArea>

                {/* Bottom Navigation */}
                <div className="border-t px-3 py-4">
                    <nav className="flex flex-col gap-1">
                        {bottomNavItems.map((item) => (
                            <NavItem
                                key={item.href}
                                item={item}
                                isCollapsed={isCollapsed}
                                isActive={pathname === item.href}
                                pathname={pathname}
                            />
                        ))}
                    </nav>

                    <Separator className="my-4" />

                    {/* User */}
                    <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-muted">
                            <span className="text-sm font-medium">JD</span>
                        </div>
                        {!isCollapsed && (
                            <div className="flex flex-1 flex-col">
                                <span className="text-sm font-medium">John Doe</span>
                                <span className="text-xs text-muted-foreground">
                                    john@example.com
                                </span>
                            </div>
                        )}
                        <Button variant="ghost" size="icon" className="h-8 w-8">
                            <LogOut className="h-4 w-4" />
                        </Button>
                    </div>
                </div>

                {/* Collapse Toggle */}
                <Button
                    variant="ghost"
                    size="icon"
                    className="absolute -right-3 top-20 z-10 h-6 w-6 rounded-full border bg-background"
                    onClick={() => setIsCollapsed(!isCollapsed)}
                >
                    <ChevronLeft
                        className={cn(
                            "h-4 w-4 transition-transform",
                            isCollapsed && "rotate-180"
                        )}
                    />
                </Button>
            </aside>
        </TooltipProvider>
    );
}

// ============================================================================
// NavItem Component
// ============================================================================

interface NavItemProps {
    item: NavItem;
    isCollapsed: boolean;
    isActive: boolean;
    isExpanded?: boolean;
    onToggleExpand?: () => void;
    pathname: string;
}

function NavItem({
    item,
    isCollapsed,
    isActive,
    isExpanded,
    onToggleExpand,
    pathname,
}: NavItemProps) {
    const hasChildren = item.children && item.children.length > 0;
    const Icon = item.icon;

    const content = (
        <Link
            href={hasChildren ? "#" : item.href}
            onClick={hasChildren ? onToggleExpand : undefined}
            className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                "hover:bg-accent hover:text-accent-foreground",
                isActive && "bg-accent text-accent-foreground",
                isCollapsed && "justify-center px-2"
            )}
        >
            <Icon className="h-4 w-4 shrink-0" />
            {!isCollapsed && (
                <>
                    <span className="flex-1">{item.title}</span>
                    {item.badge && (
                        <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1.5 text-xs text-primary-foreground">
                            {item.badge}
                        </span>
                    )}
                    {hasChildren && (
                        <ChevronLeft
                            className={cn(
                                "h-4 w-4 transition-transform",
                                isExpanded && "-rotate-90"
                            )}
                        />
                    )}
                </>
            )}
        </Link>
    );

    if (isCollapsed) {
        return (
            <Tooltip>
                <TooltipTrigger asChild>{content}</TooltipTrigger>
                <TooltipContent side="right" className="flex items-center gap-2">
                    {item.title}
                    {item.badge && (
                        <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1.5 text-xs text-primary-foreground">
                            {item.badge}
                        </span>
                    )}
                </TooltipContent>
            </Tooltip>
        );
    }

    return (
        <div>
            {content}
            {hasChildren && isExpanded && (
                <div className="ml-4 mt-1 flex flex-col gap-1 border-l pl-3">
                    {item.children?.map((child) => (
                        <NavItem
                            key={child.href}
                            item={child}
                            isCollapsed={isCollapsed}
                            isActive={pathname === child.href}
                            pathname={pathname}
                        />
                    ))}
                </div>
            )}
        </div>
    );
}

export default Sidebar;
