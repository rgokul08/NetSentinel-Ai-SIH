import { ChevronLeft, ChevronRight } from 'lucide-react'
import { formatNumber } from '../../utils/format'
import { PAGE_SIZES } from '../../utils/constants'

/** Offset/limit pager matching the backend `pagination` envelope. */
export default function Pagination({ pagination, onChange, pageSizeOptions = PAGE_SIZES, className = '' }) {
  if (!pagination) return null
  const { total = 0, limit = 25, offset = 0, page = 1, pages = 1 } = pagination
  const from = total === 0 ? 0 : offset + 1
  const to = Math.min(offset + limit, total)

  const go = (nextPage) => {
    const clamped = Math.max(1, Math.min(pages || 1, nextPage))
    onChange?.({ limit, offset: (clamped - 1) * limit, page: clamped })
  }

  return (
    <div className={`flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/70 px-3 py-2 ${className}`}>
      <p className="muted">
        Showing <span className="font-mono text-slate-300">{formatNumber(from)}</span>–
        <span className="font-mono text-slate-300">{formatNumber(to)}</span> of{' '}
        <span className="font-mono text-slate-300">{formatNumber(total)}</span>
      </p>
      <div className="flex items-center gap-2">
        {pageSizeOptions?.length ? (
          <select
            className="input w-auto py-1 text-[11px]"
            value={limit}
            onChange={(event) => {
              const next = Number(event.target.value) || limit
              onChange?.({ limit: next, offset: 0, page: 1 })
            }}
            aria-label="Rows per page"
          >
            {pageSizeOptions.map((size) => (
              <option key={size} value={size}>
                {size} / page
              </option>
            ))}
          </select>
        ) : null}
        <div className="flex items-center gap-1">
          <button
            type="button"
            className="rounded-md border border-slate-700/70 bg-slate-800/50 p-1.5 text-slate-300 transition hover:border-slate-600 disabled:opacity-40"
            onClick={() => go(page - 1)}
            disabled={page <= 1}
            aria-label="Previous page"
          >
            <ChevronLeft size={13} />
          </button>
          <span className="mono px-1.5 text-slate-400">
            {page} / {pages || 1}
          </span>
          <button
            type="button"
            className="rounded-md border border-slate-700/70 bg-slate-800/50 p-1.5 text-slate-300 transition hover:border-slate-600 disabled:opacity-40"
            onClick={() => go(page + 1)}
            disabled={page >= pages}
            aria-label="Next page"
          >
            <ChevronRight size={13} />
          </button>
        </div>
      </div>
    </div>
  )
}
