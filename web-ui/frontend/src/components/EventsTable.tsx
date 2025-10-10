import { useMemo } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table';
import { useState } from 'react';
import { ShieldCheck, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { format } from 'date-fns';
import Button from './Button';
import type { LogEvent } from '../lib/api';

interface EventsTableProps {
  events: (LogEvent & { hasAnomaly?: boolean; anomaly?: any })[];
  onEventClick: (event: LogEvent) => void;
}

export default function EventsTable({ events, onEventClick }: EventsTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  const columns = useMemo<ColumnDef<LogEvent & { hasAnomaly?: boolean }>[]>(
    () => [
      {
        id: 'status',
        header: '',
        accessorFn: (row) => row,
        cell: ({ getValue }) => {
          const row = getValue() as LogEvent & { hasAnomaly?: boolean; anomaly?: any };
          if (!row.hasAnomaly || !row.anomaly) return null;

          const isActualRisk = row.anomaly.is_actual_risk;

          if (isActualRisk) {
            // Dangerous - red alert
            return <AlertTriangle className="w-5 h-5 text-red-600" title="Threat detected" />;
          } else {
            // Benign - blue checkmark
            return <ShieldCheck className="w-5 h-5 text-blue-600" title="Analyzed - benign" />;
          }
        },
        size: 40,
      },
      {
        accessorKey: 'timestamp',
        header: 'Timestamp',
        cell: ({ getValue }) => {
          const value = getValue() as string;
          try {
            return format(new Date(value), 'MMM dd, yyyy HH:mm:ss');
          } catch {
            return value;
          }
        },
      },
      {
        accessorKey: 'event_name',
        header: 'Event Type',
        cell: ({ getValue }) => {
          const value = getValue() as string;
          const colors: Record<string, string> = {
            login_success: 'bg-green-100 text-green-800',
            login_failure: 'bg-red-100 text-red-800',
            login_verification: 'bg-blue-100 text-blue-800',
          };
          return (
            <span
              className={`px-2 py-1 rounded-full text-xs font-medium ${
                colors[value] || 'bg-gray-100 text-gray-800'
              }`}
            >
              {value}
            </span>
          );
        },
      },
      {
        accessorKey: 'user_email',
        header: 'User',
      },
      {
        accessorKey: 'ip_address',
        header: 'IP Address',
      },
      {
        accessorKey: 'enriched_location.city',
        header: 'Location',
        cell: ({ row }) => {
          const location = row.original.enriched_location;
          if (!location) return '-';
          return `${location.city}, ${location.country}`;
        },
      },
      {
        accessorKey: 'ip_reputation.overall_risk_score',
        header: 'Risk Score',
        cell: ({ getValue }) => {
          const score = getValue() as number | undefined;
          if (score === undefined) return '-';
          const color =
            score >= 60 ? 'text-red-600' : score >= 30 ? 'text-yellow-600' : 'text-green-600';
          return <span className={`font-medium ${color}`}>{score}/100</span>;
        },
      },
      {
        accessorKey: 'user_context.is_2fa_enrolled',
        header: '2FA',
        cell: ({ getValue }) => {
          const enrolled = getValue() as boolean | undefined;
          if (enrolled === undefined) return '-';
          return enrolled ? (
            <span className="text-green-600">✓</span>
          ) : (
            <span className="text-red-600">✗</span>
          );
        },
      },
    ],
    []
  );

  const table = useReactTable({
    data: events,
    columns,
    state: {
      sorting,
      globalFilter,
    },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: {
        pageSize: 20,
      },
    },
  });

  return (
    <div className="p-6">
      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          value={globalFilter ?? ''}
          onChange={(e) => setGlobalFilter(e.target.value)}
          placeholder="Search all columns..."
          className="w-full max-w-sm border border-gray-300 rounded-md px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    <div className="flex items-center gap-2">
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getIsSorted() && (
                        <span>
                          {header.column.getIsSorted() === 'asc' ? (
                            <ChevronUp className="w-4 h-4" />
                          ) : (
                            <ChevronDown className="w-4 h-4" />
                          )}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {table.getRowModel().rows.map((row) => {
              const isActualRisk = row.original.hasAnomaly && row.original.anomaly?.is_actual_risk;
              const isBenign = row.original.hasAnomaly && !row.original.anomaly?.is_actual_risk;

              return (
                <tr
                  key={row.id}
                  onClick={() => onEventClick(row.original)}
                  className={`cursor-pointer hover:bg-gray-50 transition-colors ${
                    isActualRisk
                      ? 'bg-red-50'
                      : isBenign
                      ? 'bg-blue-50'
                      : ''
                  }`}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="mt-4 flex items-center justify-between">
        <div className="text-sm text-gray-700">
          Showing {table.getState().pagination.pageIndex * table.getState().pagination.pageSize + 1}{' '}
          to{' '}
          {Math.min(
            (table.getState().pagination.pageIndex + 1) * table.getState().pagination.pageSize,
            events.length
          )}{' '}
          of {events.length} results
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
