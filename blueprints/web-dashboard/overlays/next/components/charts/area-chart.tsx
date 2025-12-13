"use client";

import {
    Area,
    AreaChart as RechartsAreaChart,
    CartesianGrid,
    Legend,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";
import { cn } from "@/lib/utils";

// ============================================================================
// Types
// ============================================================================

interface ChartDataPoint {
    [key: string]: string | number;
}

interface AreaChartProps {
    data: ChartDataPoint[];
    xKey: string;
    yKeys: string[];
    colors?: string[];
    className?: string;
    height?: number;
    showGrid?: boolean;
    showLegend?: boolean;
    stacked?: boolean;
    gradient?: boolean;
    curveType?: "linear" | "monotone" | "step";
    formatXAxis?: (value: string) => string;
    formatYAxis?: (value: number) => string;
    formatTooltip?: (value: number) => string;
}

// ============================================================================
// Default Colors
// ============================================================================

const DEFAULT_COLORS = [
    "hsl(var(--chart-1))",
    "hsl(var(--chart-2))",
    "hsl(var(--chart-3))",
    "hsl(var(--chart-4))",
    "hsl(var(--chart-5))",
];

// ============================================================================
// Area Chart Component
// ============================================================================

export function AreaChart({
    data,
    xKey,
    yKeys,
    colors = DEFAULT_COLORS,
    className,
    height = 350,
    showGrid = true,
    showLegend = true,
    stacked = false,
    gradient = true,
    curveType = "monotone",
    formatXAxis,
    formatYAxis,
    formatTooltip,
}: AreaChartProps) {
    return (
        <div className={cn("w-full", className)}>
            <ResponsiveContainer width="100%" height={height}>
                <RechartsAreaChart
                    data={data}
                    margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
                >
                    {/* Gradients */}
                    {gradient && (
                        <defs>
                            {yKeys.map((key, index) => (
                                <linearGradient
                                    key={`gradient-${key}`}
                                    id={`gradient-${key}`}
                                    x1="0"
                                    y1="0"
                                    x2="0"
                                    y2="1"
                                >
                                    <stop
                                        offset="5%"
                                        stopColor={colors[index % colors.length]}
                                        stopOpacity={0.8}
                                    />
                                    <stop
                                        offset="95%"
                                        stopColor={colors[index % colors.length]}
                                        stopOpacity={0.1}
                                    />
                                </linearGradient>
                            ))}
                        </defs>
                    )}

                    {/* Grid */}
                    {showGrid && (
                        <CartesianGrid
                            strokeDasharray="3 3"
                            className="stroke-muted"
                            vertical={false}
                        />
                    )}

                    {/* Axes */}
                    <XAxis
                        dataKey={xKey}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={formatXAxis}
                        className="text-xs fill-muted-foreground"
                    />
                    <YAxis
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={formatYAxis}
                        className="text-xs fill-muted-foreground"
                    />

                    {/* Tooltip */}
                    <Tooltip
                        content={({ active, payload, label }) => {
                            if (!active || !payload) return null;

                            return (
                                <div className="rounded-lg border bg-background p-2 shadow-sm">
                                    <div className="text-sm font-medium">{label}</div>
                                    <div className="mt-1 space-y-1">
                                        {payload.map((item: any) => (
                                            <div
                                                key={item.dataKey}
                                                className="flex items-center justify-between gap-4 text-sm"
                                            >
                                                <div className="flex items-center gap-1.5">
                                                    <div
                                                        className="h-2.5 w-2.5 rounded-full"
                                                        style={{ backgroundColor: item.color }}
                                                    />
                                                    <span className="text-muted-foreground capitalize">
                                                        {item.dataKey}
                                                    </span>
                                                </div>
                                                <span className="font-medium">
                                                    {formatTooltip
                                                        ? formatTooltip(item.value)
                                                        : item.value.toLocaleString()}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            );
                        }}
                    />

                    {/* Legend */}
                    {showLegend && (
                        <Legend
                            content={({ payload }) => (
                                <div className="flex justify-center gap-4 pt-4">
                                    {payload?.map((entry: any) => (
                                        <div
                                            key={entry.value}
                                            className="flex items-center gap-1.5 text-sm"
                                        >
                                            <div
                                                className="h-2.5 w-2.5 rounded-full"
                                                style={{ backgroundColor: entry.color }}
                                            />
                                            <span className="text-muted-foreground capitalize">
                                                {entry.value}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        />
                    )}

                    {/* Areas */}
                    {yKeys.map((key, index) => (
                        <Area
                            key={key}
                            type={curveType}
                            dataKey={key}
                            stroke={colors[index % colors.length]}
                            strokeWidth={2}
                            fill={gradient ? `url(#gradient-${key})` : colors[index % colors.length]}
                            fillOpacity={gradient ? 1 : 0.2}
                            stackId={stacked ? "stack" : undefined}
                        />
                    ))}
                </RechartsAreaChart>
            </ResponsiveContainer>
        </div>
    );
}

// ============================================================================
// Pre-configured Variants
// ============================================================================

interface SimpleAreaChartProps {
    data: ChartDataPoint[];
    xKey: string;
    yKey: string;
    color?: string;
    className?: string;
    height?: number;
}

export function SimpleAreaChart({
    data,
    xKey,
    yKey,
    color = "hsl(var(--primary))",
    className,
    height = 200,
}: SimpleAreaChartProps) {
    return (
        <AreaChart
            data={data}
            xKey={xKey}
            yKeys={[yKey]}
            colors={[color]}
            className={className}
            height={height}
            showGrid={false}
            showLegend={false}
            gradient={true}
        />
    );
}

// Sparkline variant (minimal, inline chart)
interface SparklineProps {
    data: number[];
    className?: string;
    color?: string;
}

export function Sparkline({
    data,
    className,
    color = "hsl(var(--primary))",
}: SparklineProps) {
    const chartData = data.map((value, index) => ({ index, value }));

    return (
        <div className={cn("h-8 w-24", className)}>
            <ResponsiveContainer width="100%" height="100%">
                <RechartsAreaChart data={chartData}>
                    <defs>
                        <linearGradient id="sparkline-gradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={color} stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <Area
                        type="monotone"
                        dataKey="value"
                        stroke={color}
                        strokeWidth={1.5}
                        fill="url(#sparkline-gradient)"
                    />
                </RechartsAreaChart>
            </ResponsiveContainer>
        </div>
    );
}

export default AreaChart;
