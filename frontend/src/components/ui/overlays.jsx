import { AlertTriangle, X } from 'lucide-react'
import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { Button } from './primitives'

function useEscape(active, onClose) {
  useEffect(() => {
    if (!active) return undefined
    const handler = (event) => {
      if (event.key === 'Escape') onClose?.()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [active, onClose])
}

export function Modal({ open, onClose, title, subtitle, children, footer, size = 'md', icon: Icon }) {
  useEscape(open, onClose)
  useEffect(() => {
    if (!open) return undefined
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [open])

  if (!open) return null
  const widths = { sm: 'max-w-md', md: 'max-w-2xl', lg: 'max-w-4xl', xl: 'max-w-6xl' }

  return createPortal(
    <div className="fixed inset-0 z-[90] flex items-start justify-center overflow-y-auto bg-slate-950/80 p-4 backdrop-blur-sm sm:items-center">
      <div
        className="absolute inset-0"
        onClick={onClose}
        role="presentation"
        aria-hidden="true"
      />
      <div
        className={`animate-in-fast relative w-full ${widths[size] || widths.md} rounded-2xl border border-slate-700/70 bg-slate-900 shadow-2xl`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header className="flex items-start justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              {Icon ? <Icon size={15} className="text-cyan-400" /> : null}
              {title}
            </h2>
            {subtitle ? <p className="muted mt-0.5">{subtitle}</p> : null}
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-slate-400 transition hover:bg-slate-800 hover:text-white" aria-label="Close dialog">
            <X size={16} />
          </button>
        </header>
        <div className="max-h-[70vh] overflow-y-auto px-4 py-4">{children}</div>
        {footer ? <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 px-4 py-3">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  )
}

export function Drawer({ open, onClose, title, subtitle, children, footer, width = 'max-w-xl' }) {
  useEscape(open, onClose)
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-[90] flex justify-end bg-slate-950/70 backdrop-blur-sm">
      <div className="absolute inset-0" onClick={onClose} role="presentation" aria-hidden="true" />
      <aside
        className={`animate-in-fast relative flex h-full w-full ${width} flex-col border-l border-slate-700/70 bg-slate-900 shadow-2xl`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <header className="flex items-start justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <div className="min-w-0">
            <h2 className="truncate text-sm font-semibold text-slate-100">{title}</h2>
            {subtitle ? <p className="muted mt-0.5 truncate">{subtitle}</p> : null}
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-slate-400 transition hover:bg-slate-800 hover:text-white" aria-label="Close panel">
            <X size={16} />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-4 py-4">{children}</div>
        {footer ? <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-800 px-4 py-3">{footer}</footer> : null}
      </aside>
    </div>,
    document.body,
  )
}

export function ConfirmDialog({ open, onClose, onConfirm, title = 'Are you sure?', message, confirmLabel = 'Confirm', tone = 'danger', busy = false }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size="sm"
      icon={AlertTriangle}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant={tone === 'danger' ? 'danger' : 'primary'} onClick={onConfirm} loading={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p className="text-xs leading-relaxed text-slate-300">{message}</p>
    </Modal>
  )
}
