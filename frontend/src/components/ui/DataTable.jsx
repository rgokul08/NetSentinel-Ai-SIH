import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { useMemo, useState } from 'react'
import { EmptyState, ErrorState, LoadingState } from './states'
import Pagination from './Pagination'

/**
 * Generic table used by every list page.
 *
 * `columns` = [{ key, header, render?, align?, width?, mono?, sortable?, hideBelow? }]
 * Server-side paging is driven by the backend `pagination` envelope; client-side
 * sorting is applied when `serverSort` is false (the default).
 */
export default function DataTable({
  columns,
  rows,
  loading = false,
  error = null,
  onRetry,
  empty,
  pagination,
  onPageChange,
  onRowClick,
  rowKey = (row) => row.id,
  selectedId,
  dense = false,
  maxHeight,
  serverSort = false,
  onSortChange,
  initialSort,
  footer,
  className = '',
}) {
  const [sort, setSort] = useState(initialSort || null)

  const sortedRows = useMemo(() => {
    if (!sort || serverSort) return rows || []
    const copy = [...(rows || [])]
    copy.sort((a, b) => {
      const left = a?.[sort.key]
      const right = b?.[sort.key]
      if (left === right) return 0
      if (left === null || left === undefined) return 1
      if (right === null || right === undefined) return -1
      const numeric = typeof left === 'number' && typeof right === 'number'
      const result = numeric ? left - right : String(left).localeCompare(String(right), undefined, { numeric: true })
      return sort.direction === 'asc' ? result : -result
    })
    return copy
  }, [rows, sort, serverSort])

  const toggleSort = (column) => {
    if (!column.sortable || serverSort) return
    const next =
      sort?.key === column.key
        ? { key: column.key, direction: sort.direction === 'asc' ? 'desc' : 'asc' }
        : { key: column.key, direction: 'desc' }
    setSort(next)
    onSortChange?.(next)
  }

  if (loading && !sortedRows.length) return <LoadingState label="Loading records…" className={className} />
  if (error && !sortedRows.length) return <ErrorState error={error} onRetry={onRetry} className={className} />
  if (!sortedRows.length) {
    return empty || <EmptyState title="No records match this view" message="Adjust the filters or widen the time window." className={className} />
  }

  return (
    <div className={`flex min-h-0 flex-col ${className}`}>
      <div className="min-h-0 flex-1 overflow-auto" style={maxHeight ? { maxHeight } : undefined}>
        <table className="table">
          <thead>
            <tr>
              {columns.map((column) => {
                const active = sort?.key === column.key
                const Icon = active ? (sort.direction === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown
                return (
                  <th
                    key={column.key}
                    style={column.width ? { width: column.width } : undefined}
                    className={`${column.align === 'right' ? 'text-right' : column.align === 'center' ? 'text-center' : ''} ${
                      column.sortable ? 'cursor-pointer select-none hover:text-slate-200' : ''
                    } ${column.hideBelow ? `hidden ${column.hideBelow}` : ''}`}
                    onClick={() => toggleSort(column)}
                  >
                    <span className="inline-flex items-center gap-1">
                      {column.header}
                      {column.sortable ? <Icon size={10} className={active ? 'text-cyan-400' : 'opacity-35'} /> : null}
                    </span>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((row) => {
              const key = rowKey(row)
              const selected = selectedId && selectedId === key
              return (
                <tr
                  key={key}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={`${onRowClick ? 'cursor-pointer' : ''} ${selected ? 'bg-cyan-500/8' : ''}`}
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={`${dense ? 'py-1.5' : ''} ${column.align === 'right' ? 'text-right' : column.align === 'center' ? 'text-center' : ''} ${
                        column.mono ? 'font-mono text-[11px]' : ''
                      } ${column.hideBelow ? `hidden ${column.hideBelow}` : ''} ${column.className || ''}`}
                    >
                      {column.render ? column.render(row) : row?.[column.key] ?? '-'}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {footer}
      {pagination && onPageChange ? <Pagination pagination={pagination} onChange={onPageChange} /> : null}
    </div>
  )
}
