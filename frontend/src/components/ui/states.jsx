import { AlertTriangle, Inbox, RefreshCw, ServerCrash, WifiOff } from 'lucide-react'
import { Button, Spinner } from './primitives'

export function Skeleton({ className = '', lines = 3 }) {
  return (
    <div className={`animate-pulse space-y-2 ${className}`} aria-hidden="true">
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className="h-2.5 rounded bg-slate-800/80"
          style={{ width: `${100 - index * 9}%` }}
        />
      ))}
    </div>
  )
}

export function LoadingState({ label = 'Loading data…', className = '', variant = 'spinner' }) {
  if (variant === 'skeleton') {
    return (
      <div className={`p-4 ${className}`}>
        <Skeleton lines={5} />
      </div>
    )
  }
  return (
    <div className={`flex flex-col items-center justify-center gap-2 py-10 text-slate-400 ${className}`}>
      <Spinner size={20} className="text-cyan-400" />
      <p className="text-xs">{label}</p>
    </div>
  )
}

export function ErrorState({ error, onRetry, className = '', compact = false }) {
  const status = error?.status
  const unreachable = !status || status === 0
  const Icon = unreachable ? WifiOff : status >= 500 ? ServerCrash : AlertTriangle
  const hint = unreachable
    ? 'The API server is not reachable. Start the backend (uvicorn app.main:app) and retry.'
    : status === 403
      ? 'Your role does not permit this action. Contact an administrator if you believe this is wrong.'
      : status === 404
        ? 'The requested resource no longer exists.'
        : error?.requestId
          ? `Reference ${error.requestId} — include this id when reporting the issue.`
          : null

  if (compact) {
    return (
      <div className={`flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/8 px-3 py-2 text-[11px] text-rose-200 ${className}`}>
        <Icon size={13} className="shrink-0" />
        <span className="min-w-0 flex-1 truncate">{error?.message || 'Request failed'}</span>
        {onRetry ? (
          <button type="button" onClick={onRetry} className="shrink-0 rounded p-1 hover:bg-rose-500/20" title="Retry">
            <RefreshCw size={12} />
          </button>
        ) : null}
      </div>
    )
  }

  return (
    <div className={`flex flex-col items-center justify-center gap-3 px-6 py-10 text-center ${className}`}>
      <div className="rounded-full border border-rose-500/30 bg-rose-500/10 p-3">
        <Icon size={20} className="text-rose-300" />
      </div>
      <div>
        <p className="text-sm font-semibold text-rose-200">
          {unreachable ? 'Backend unreachable' : `Request failed${status ? ` (${status})` : ''}`}
        </p>
        <p className="muted mt-1 max-w-md">{error?.message || 'An unexpected error occurred.'}</p>
        {hint ? <p className="muted mt-1 max-w-md opacity-75">{hint}</p> : null}
        {error?.fields?.length ? (
          <ul className="mx-auto mt-2 max-w-md space-y-0.5 text-left text-[11px] text-rose-300/80">
            {error.fields.slice(0, 5).map((field, index) => (
              <li key={index} className="font-mono">
                {field.field}: {field.message}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
      {onRetry ? (
        <Button variant="secondary" icon={RefreshCw} onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  )
}

export function EmptyState({ icon: Icon = Inbox, title = 'Nothing to show yet', message, action, className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center gap-2 px-6 py-10 text-center ${className}`}>
      <div className="rounded-full border border-slate-700/70 bg-slate-800/40 p-3">
        <Icon size={18} className="text-slate-400" />
      </div>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {message ? <p className="muted max-w-md">{message}</p> : null}
      {action ? <div className="mt-1.5">{action}</div> : null}
    </div>
  )
}

/** Panel that renders exactly one of: loading, error, empty or content. */
export function AsyncPanel({ state, empty, children, skeleton = false, className = '' }) {
  if (state.loading && state.data === null) {
    return skeleton ? <LoadingState variant="skeleton" className={className} /> : <LoadingState className={className} />
  }
  if (state.error && state.data === null) {
    return <ErrorState error={state.error} onRetry={state.refetch} className={className} />
  }
  if (state.isEmpty) {
    return typeof empty === 'function' ? empty() : empty || <EmptyState className={className} />
  }
  return <>{children(state.data)}</>
}
