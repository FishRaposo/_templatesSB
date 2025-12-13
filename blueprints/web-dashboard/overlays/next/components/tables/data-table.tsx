"use client";

import * as React from "react";
import {
    ColumnDef,
    ColumnFiltersState,
    SortingState,
    VisibilityState,
    flexRender,
    getCoreRowModel,
    getFacetedRowModel,
    getFacetedUniqueValues,
    getFilteredRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    useReactTable,
} from "@tanstack/react-table";

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { DataTablePagination } from "./data-table-pagination";
import { DataTableToolbar } from "./data-table-toolbar";
import { Skeleton } from "@/components/ui/skeleton";

// ============================================================================
// Types
// ============================================================================

interface DataTableProps<TData, TValue> {
    columns: ColumnDef<TData, TValue>[];
    data: TData[];
    isLoading?: boolean;

    // Server-side operations
    pageCount?: number;
    pagination?: {
        pageIndex: number;
        pageSize: number;
    };
    onPaginationChange?: (pagination: { pageIndex: number; pageSize: number }) => void;

    sorting?: SortingState;
    onSortingChange?: (sorting: SortingState) => void;

    // Toolbar
    searchKey?: string;
    searchPlaceholder?: string;
    filterableColumns?: {
        id: string;
        title: string;
        options: { label: string; value: string }[];
    }[];

    // Selection
    enableRowSelection?: boolean;
    onRowSelectionChange?: (rows: TData[]) => void;

    // Actions
    bulkActions?: React.ReactNode;
}

// ============================================================================
// DataTable Component
// ============================================================================

export function DataTable<TData, TValue>({
    columns,
    data,
    isLoading = false,
    pageCount,
    pagination: controlledPagination,
    onPaginationChange,
    sorting: controlledSorting,
    onSortingChange,
    searchKey,
    searchPlaceholder,
    filterableColumns,
    enableRowSelection = false,
    onRowSelectionChange,
    bulkActions,
}: DataTableProps<TData, TValue>) {
    // State
    const [rowSelection, setRowSelection] = React.useState({});
    const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({});
    const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([]);

    // Uncontrolled state fallbacks
    const [uncontrolledSorting, setUncontrolledSorting] = React.useState<SortingState>([]);
    const [uncontrolledPagination, setUncontrolledPagination] = React.useState({
        pageIndex: 0,
        pageSize: 10,
    });

    // Use controlled or uncontrolled state
    const sorting = controlledSorting ?? uncontrolledSorting;
    const pagination = controlledPagination ?? uncontrolledPagination;

    const isServerSide = Boolean(onPaginationChange);

    // Table instance
    const table = useReactTable({
        data,
        columns,
        pageCount: isServerSide ? pageCount : undefined,
        state: {
            sorting,
            columnVisibility,
            rowSelection,
            columnFilters,
            pagination,
        },
        enableRowSelection,
        onRowSelectionChange: setRowSelection,
        onSortingChange: onSortingChange ?? setUncontrolledSorting,
        onColumnFiltersChange: setColumnFilters,
        onColumnVisibilityChange: setColumnVisibility,
        onPaginationChange: (updater) => {
            const newPagination = typeof updater === "function"
                ? updater(pagination)
                : updater;

            if (onPaginationChange) {
                onPaginationChange(newPagination);
            } else {
                setUncontrolledPagination(newPagination);
            }
        },
        getCoreRowModel: getCoreRowModel(),
        getFilteredRowModel: isServerSide ? undefined : getFilteredRowModel(),
        getPaginationRowModel: isServerSide ? undefined : getPaginationRowModel(),
        getSortedRowModel: isServerSide ? undefined : getSortedRowModel(),
        getFacetedRowModel: getFacetedRowModel(),
        getFacetedUniqueValues: getFacetedUniqueValues(),
        manualPagination: isServerSide,
        manualSorting: isServerSide,
    });

    // Row selection callback
    React.useEffect(() => {
        if (onRowSelectionChange) {
            const selectedRows = table.getFilteredSelectedRowModel().rows;
            onRowSelectionChange(selectedRows.map((row) => row.original));
        }
    }, [rowSelection, onRowSelectionChange, table]);

    return (
        <div className="space-y-4">
            {/* Toolbar */}
            <DataTableToolbar
                table={table}
                searchKey={searchKey}
                searchPlaceholder={searchPlaceholder}
                filterableColumns={filterableColumns}
            />

            {/* Bulk Actions */}
            {enableRowSelection && Object.keys(rowSelection).length > 0 && bulkActions && (
                <div className="flex items-center gap-2 rounded-lg border bg-muted/50 p-2">
                    <span className="text-sm text-muted-foreground">
                        {Object.keys(rowSelection).length} row(s) selected
                    </span>
                    <div className="flex-1" />
                    {bulkActions}
                </div>
            )}

            {/* Table */}
            <div className="rounded-md border">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => (
                                    <TableHead key={header.id} colSpan={header.colSpan}>
                                        {header.isPlaceholder
                                            ? null
                                            : flexRender(
                                                header.column.columnDef.header,
                                                header.getContext()
                                            )}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {isLoading ? (
                            // Loading skeleton
                            Array.from({ length: pagination.pageSize }).map((_, i) => (
                                <TableRow key={i}>
                                    {columns.map((_, j) => (
                                        <TableCell key={j}>
                                            <Skeleton className="h-6 w-full" />
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : table.getRowModel().rows?.length ? (
                            // Data rows
                            table.getRowModel().rows.map((row) => (
                                <TableRow
                                    key={row.id}
                                    data-state={row.getIsSelected() && "selected"}
                                >
                                    {row.getVisibleCells().map((cell) => (
                                        <TableCell key={cell.id}>
                                            {flexRender(
                                                cell.column.columnDef.cell,
                                                cell.getContext()
                                            )}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            // Empty state
                            <TableRow>
                                <TableCell
                                    colSpan={columns.length}
                                    className="h-24 text-center"
                                >
                                    No results.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>

            {/* Pagination */}
            <DataTablePagination table={table} />
        </div>
    );
}

// ============================================================================
// Column Header Component
// ============================================================================

import { Column } from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface DataTableColumnHeaderProps<TData, TValue>
    extends React.HTMLAttributes<HTMLDivElement> {
    column: Column<TData, TValue>;
    title: string;
}

export function DataTableColumnHeader<TData, TValue>({
    column,
    title,
    className,
}: DataTableColumnHeaderProps<TData, TValue>) {
    if (!column.getCanSort()) {
        return <div className={cn(className)}>{title}</div>;
    }

    return (
        <div className={cn("flex items-center space-x-2", className)}>
            <DropdownMenu>
                <DropdownMenuTrigger asChild>
                    <Button
                        variant="ghost"
                        size="sm"
                        className="-ml-3 h-8 data-[state=open]:bg-accent"
                    >
                        <span>{title}</span>
                        {column.getIsSorted() === "desc" ? (
                            <ArrowDown className="ml-2 h-4 w-4" />
                        ) : column.getIsSorted() === "asc" ? (
                            <ArrowUp className="ml-2 h-4 w-4" />
                        ) : (
                            <ChevronsUpDown className="ml-2 h-4 w-4" />
                        )}
                    </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start">
                    <DropdownMenuItem onClick={() => column.toggleSorting(false)}>
                        <ArrowUp className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                        Asc
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => column.toggleSorting(true)}>
                        <ArrowDown className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                        Desc
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => column.toggleVisibility(false)}>
                        <EyeOff className="mr-2 h-3.5 w-3.5 text-muted-foreground/70" />
                        Hide
                    </DropdownMenuItem>
                </DropdownMenuContent>
            </DropdownMenu>
        </div>
    );
}

// ============================================================================
// Exports
// ============================================================================

export { DataTableColumnHeader };
