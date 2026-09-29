import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'

const ToastContext = createContext(null)

const VARIANTS = {
  success: { icon: CheckCircle2, classes: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' },
  error: { icon: XCircle, classes: 'border-rose-500/40 bg-rose-500/10 text-rose-200' },
  warning: { icon: AlertTriangle, classes: 'border-amber-500/40 bg-amber-500/10 text-amber-200' },
  info: { icon: Info, classes: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200' },
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const counter = useRef(0)

  const dismiss = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
  }, [])

  const push = useCallback(
    (variant, title, message, timeout = 5200) => {
      counter.current += 1
      const id = `toast-${counter.current}`
      setToasts((current) => [...current.slice(-4), { id, variant, title, message }])
      if (timeout) setTimeout(() => dismiss(id), timeout)
      return id
    },
    [dismiss],
  )

  const value = useMemo(
    () => ({
      push,
      dismiss,
      success: (title, message) => push('success', title, message),
      error: (title, message) => push('error', title, message, 7000),
      warning: (title, message) => push('warning', title, message, 6000),
      info: (title, message) => push('info', title, message),
    }),
    [dismiss, push],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[100] flex w-[min(92vw,360px)] flex-col gap-2">
        {toasts.map((toast) => {
          const variant = VARIANTS[toast.variant] || VARIANTS.info
          const Icon = variant.icon
          return (
            <div
              key={toast.id}
              className={`animate-in-fast pointer-events-auto flex items-start gap-2.5 rounded-xl border px-3 py-2.5 shadow-2xl backdrop-blur ${variant.classes}`}
            >
              <Icon size={15} className="mt-0.5 shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold leading-tight">{toast.title}</p>
                {toast.message ? <p className="mt-0.5 text-[11px] leading-snug opacity-85">{toast.message}</p> : null}
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                className="shrink-0 rounded p-0.5 opacity-60 transition hover:opacity-100"
                aria-label="Dismiss notification"
              >
                <X size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast must be used inside <ToastProvider>')
  return context
}
