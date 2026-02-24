import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { Customer, CustomerCreate, CustomerUpdate, PaginatedResponse } from "@/types";

// ============================================================================
// Query Keys
// ============================================================================

export const customerKeys = {
    all: ["customers"] as const,
    lists: () => [...customerKeys.all, "list"] as const,
    list: (filters: Record<string, unknown>) => [...customerKeys.lists(), filters] as const,
    details: () => [...customerKeys.all, "detail"] as const,
    detail: (id: string) => [...customerKeys.details(), id] as const,
};

// ============================================================================
// Types
// ============================================================================

interface UseCustomersOptions {
    page?: number;
    pageSize?: number;
    search?: string;
    status?: string;
    sortBy?: string;
    sortOrder?: "asc" | "desc";
}

// ============================================================================
// List Customers
// ============================================================================

export function useCustomers(options: UseCustomersOptions = {}) {
    const {
        page = 1,
        pageSize = 10,
        search,
        status,
        sortBy = "created_at",
        sortOrder = "desc",
    } = options;

    return useQuery({
        queryKey: customerKeys.list({ page, pageSize, search, status, sortBy, sortOrder }),
        queryFn: async () => {
            const params = new URLSearchParams({
                page: page.toString(),
                page_size: pageSize.toString(),
                sort_by: sortBy,
                sort_order: sortOrder,
            });

            if (search) params.append("search", search);
            if (status) params.append("status", status);

            const response = await api.get<PaginatedResponse<Customer>>(
                `/customers?${params.toString()}`
            );
            return response;
        },
        staleTime: 30 * 1000, // 30 seconds
        placeholderData: (previousData) => previousData,
    });
}

// ============================================================================
// Get Single Customer
// ============================================================================

export function useCustomer(id: string) {
    return useQuery({
        queryKey: customerKeys.detail(id),
        queryFn: async () => {
            const response = await api.get<Customer>(`/customers/${id}`);
            return response;
        },
        enabled: Boolean(id),
    });
}

// ============================================================================
// Create Customer
// ============================================================================

export function useCreateCustomer() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (data: CustomerCreate) => {
            const response = await api.post<Customer>("/customers", data);
            return response;
        },
        onSuccess: (newCustomer) => {
            // Invalidate list queries
            queryClient.invalidateQueries({ queryKey: customerKeys.lists() });

            // Optimistically add to cache
            queryClient.setQueryData(customerKeys.detail(newCustomer.id), newCustomer);

            toast.success("Customer created successfully");
        },
        onError: (error: Error) => {
            toast.error(`Failed to create customer: ${error.message}`);
        },
    });
}

// ============================================================================
// Update Customer
// ============================================================================

export function useUpdateCustomer(id: string) {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (data: CustomerUpdate) => {
            const response = await api.patch<Customer>(`/customers/${id}`, data);
            return response;
        },
        onMutate: async (data) => {
            // Cancel outgoing queries
            await queryClient.cancelQueries({ queryKey: customerKeys.detail(id) });

            // Snapshot previous value
            const previousCustomer = queryClient.getQueryData<Customer>(
                customerKeys.detail(id)
            );

            // Optimistically update
            if (previousCustomer) {
                queryClient.setQueryData(customerKeys.detail(id), {
                    ...previousCustomer,
                    ...data,
                });
            }

            return { previousCustomer };
        },
        onError: (error: Error, _data, context) => {
            // Rollback on error
            if (context?.previousCustomer) {
                queryClient.setQueryData(
                    customerKeys.detail(id),
                    context.previousCustomer
                );
            }
            toast.error(`Failed to update customer: ${error.message}`);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: customerKeys.lists() });
            toast.success("Customer updated successfully");
        },
    });
}

// ============================================================================
// Delete Customer
// ============================================================================

export function useDeleteCustomer() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (id: string) => {
            await api.delete(`/customers/${id}`);
            return id;
        },
        onSuccess: (deletedId) => {
            // Remove from cache
            queryClient.removeQueries({ queryKey: customerKeys.detail(deletedId) });

            // Invalidate list queries
            queryClient.invalidateQueries({ queryKey: customerKeys.lists() });

            toast.success("Customer deleted successfully");
        },
        onError: (error: Error) => {
            toast.error(`Failed to delete customer: ${error.message}`);
        },
    });
}

// ============================================================================
// Bulk Delete
// ============================================================================

export function useBulkDeleteCustomers() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (ids: string[]) => {
            await api.post("/customers/bulk-delete", { ids });
            return ids;
        },
        onSuccess: (deletedIds) => {
            // Remove from cache
            deletedIds.forEach((id) => {
                queryClient.removeQueries({ queryKey: customerKeys.detail(id) });
            });

            // Invalidate list queries
            queryClient.invalidateQueries({ queryKey: customerKeys.lists() });

            toast.success(`${deletedIds.length} customers deleted`);
        },
        onError: (error: Error) => {
            toast.error(`Failed to delete customers: ${error.message}`);
        },
    });
}

// ============================================================================
// Export Customers
// ============================================================================

export function useExportCustomers() {
    return useMutation({
        mutationFn: async (format: "csv" | "xlsx" = "csv") => {
            const response = await api.get<Blob>(
                `/customers/export?format=${format}`,
                { responseType: "blob" }
            );

            // Create download link
            const url = window.URL.createObjectURL(response);
            const link = document.createElement("a");
            link.href = url;
            link.download = `customers.${format}`;
            link.click();
            window.URL.revokeObjectURL(url);
        },
        onSuccess: () => {
            toast.success("Export started");
        },
        onError: (error: Error) => {
            toast.error(`Failed to export: ${error.message}`);
        },
    });
}

// ============================================================================
// Customer Stats
// ============================================================================

export function useCustomerStats() {
    return useQuery({
        queryKey: [...customerKeys.all, "stats"],
        queryFn: async () => {
            const response = await api.get<{
                total: number;
                active: number;
                inactive: number;
                newThisMonth: number;
                churnRate: number;
            }>("/customers/stats");
            return response;
        },
        staleTime: 5 * 60 * 1000, // 5 minutes
    });
}
