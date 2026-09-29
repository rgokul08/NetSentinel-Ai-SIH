import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { copyToClipboard } from '../../utils/format'
import { attackColor, riskColor, severityColor, statusColor } from '../../utils/theme'

/* ---------------------------------------------------------------- surfaces */
export function Card({ title, subtitle, actions, children, className = '', bodyClass = '', icon: Icon, dense = false }) {
  return (
    <section className={`card flex flex-col ${className}`}>
      {(title || actions) && (
        <header className={`flex items-start justify-between gap-3 border-b border-slate-800/70 px-4 ${dense ? 'py-2.5' : 'py-3'}`}>
          <div className="min-w-0">
            <h2 className="section-title flex items-center gap-2">
              {Icon ? <Icon size={14} className="text-cyan-400/80" /> : null}
              {title}
            </h2>
            {subtitle ? <p className="muted mt-0.5 truncate">{subtitle}</p> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      )}
      <div className={`flex-1 ${dense ? 'p-3' : 'p-4'} ${bodyClass}`}>{children}</div>
    </section>
  )
}

export function SectionHeader({ title, description, actions, icon: Icon }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2 text-lg font-semibold tracking-tight text-slate-100">
          {Icon ? <Icon size={18} className="text-cyan-400" /> : null}
          {title}
        </h1>
        {description ? <p className="muted mt-1 max-w-3xl">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

/* ------------------------------------------------------------------ badges */
export function Badge({ children, tone = 'slate', className = '', dot = false }) {
  const tones = {
    slate: 'border-slate-700/70 bg-slate-800/60 text-slate-300',
    cyan: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300',
    green: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    amber: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    orange: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
    red: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
    purple: 'border-purple-500/40 bg-purple-500/10 text-purple-300',
    blue: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  }
  return (
    <span className={`badge ${tones[tone] || tones.slate} ${className}`}>
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current" /> : null}
      {children}
    </span>
  )
}

export function SeverityBadge({ severity, className = '' }) {
  const color = severityColor(severity)
  return (
    <span className={`badge ${color.border} ${color.bg} ${color.text} ${className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${color.dot}`} />
      {String(severity || 'unknown')}
    </span>
  )
}

export function AttackBadge({ type, className = '' }) {
  const hex = attackColor(type)
  return (
    <span className={`badge border-slate-700/70 bg-slate-800/50 ${className}`} style={{ color: hex }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: hex }} />
      {type || 'Unknown'}
    </span>
  )
}

export function RiskBadge({ level, score, className = '' }) {
  const hex = riskColor(level)
  return (
    <span className={`badge ${className}`} style={{ borderColor: `${hex}66`, background: `${hex}1a`, color: hex }}>
      {String(level || 'unknown')}
      {score !== undefined && score !== null ? <span className="opacity-70">· {(Number(score) * 100).toFixed(0)}%</span> : null}
    </span>
  )
}

export function StatusBadge({ status, className = '' }) {
  const hex = statusColor(status)
  return (
    <span className={`badge ${className}`} style={{ borderColor: `${hex}66`, background: `${hex}1a`, color: hex }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: hex }} />
      {String(status || 'unknown').replace(/[_-]/g, ' ')}
    </span>
  )
}

/* ----------------------------------------------------------------- buttons */
export function Button({
  children,
  variant = 'secondary',
  size = 'md',
  icon: Icon,
  loading = false,
  disabled = false,
  className = '',
  type = 'button',
  ...rest
}) {
  const variants = {
    primary: 'btn-primary',
    secondary: 'btn-secondary',
    ghost: 'btn-ghost',
    danger: 'btn-danger',
    success: 'btn-success',
  }
  const sizes = { xs: 'btn-xs', sm: 'btn-sm', md: '' }
  return (
    <button
      type={type}
      className={`${variants[variant] || variants.secondary} ${sizes[size] || ''} ${className}`}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Spinner size={12} /> : Icon ? <Icon size={size === 'xs' ? 11 : 13} /> : null}
      {children}
    </button>
  )
}

export function Spinner({ size = 14, className = '' }) {
  return (
    <span
      className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent ${className}`}
      style={{ width: size, height: size }}
      role="status"
      aria-label="Loading"
    />
  )
}

export function IconButton({ icon: Icon, label, onClick, tone = 'ghost', size = 14, disabled = false, active = false }) {
  const tones = {
    ghost: 'text-slate-400 hover:bg-slate-800 hover:text-slate-100',
    danger: 'text-rose-400 hover:bg-rose-500/15',
    cyan: 'text-cyan-400 hover:bg-cyan-500/15',
  }
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={label}
      aria-label={label}
      className={`rounded-md p-1.5 transition disabled:opacity-40 ${tones[tone] || tones.ghost} ${active ? 'bg-slate-800 text-cyan-300' : ''}`}
    >
      <Icon size={size} />
    </button>
  )
}

export function CopyButton({ value, label = 'Copy', size = 12, className = '' }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return undefined
    const timer = setTimeout(() => setCopied(false), 1600)
    return () => clearTimeout(timer)
  }, [copied])

  return (
    <button
      type="button"
      className={`inline-flex items-center gap-1 rounded border border-slate-700/70 bg-slate-800/50 px-1.5 py-0.5 text-[10px] font-medium text-slate-300 transition hover:border-cyan-500/50 hover:text-cyan-300 ${className}`}
      onClick={async () => {
        try {
          await copyToClipboard(value)
          setCopied(true)
        } catch {
          setCopied(false)
        }
      }}
      title={`${label}: ${value}`}
    >
      {copied ? <Check size={size} className="text-emerald-400" /> : <Copy size={size} />}
      {copied ? 'Copied' : label}
    </button>
  )
}

/* ------------------------------------------------------------------ meters */
export function Progress({ value = 0, max = 1, tone = 'cyan', className = '', showLabel = false, label }) {
  const percent = Math.max(0, Math.min(100, (Number(value) / (Number(max) || 1)) * 100))
  const tones = {
    cyan: 'bg-cyan-400',
    green: 'bg-emerald-400',
    amber: 'bg-amber-400',
    red: 'bg-rose-400',
    purple: 'bg-purple-400',
  }
  return (
    <div className={className}>
      {showLabel ? (
        <div className="mb-1 flex items-center justify-between text-[10px] text-slate-400">
          <span>{label}</span>
          <span className="font-mono text-slate-300">{percent.toFixed(0)}%</span>
        </div>
      ) : null}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full transition-all duration-500 ${tones[tone] || tones.cyan}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

export function Switch({ checked, onChange, label, disabled = false, hint }) {
  return (
    <label className={`flex cursor-pointer items-center justify-between gap-3 ${disabled ? 'opacity-50' : ''}`}>
      <span className="min-w-0">
        <span className="block text-xs font-medium text-slate-200">{label}</span>
        {hint ? <span className="muted block">{hint}</span> : null}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={Boolean(checked)}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full border transition-colors ${
          checked ? 'border-cyan-400/60 bg-cyan-500/30' : 'border-slate-700 bg-slate-800'
        }`}
      >
        <span
          className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${
            checked ? 'left-[18px] bg-cyan-300' : 'left-0.5 bg-slate-500'
          }`}
        />
      </button>
    </label>
  )
}

export function KeyValue({ items, columns = 2, className = '' }) {
  return (
    <dl className={`grid gap-x-4 gap-y-2.5 ${columns === 1 ? 'grid-cols-1' : columns === 3 ? 'grid-cols-1 sm:grid-cols-3' : 'grid-cols-1 sm:grid-cols-2'} ${className}`}>
      {items.filter(Boolean).map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">{item.label}</dt>
          <dd className={`mt-0.5 truncate text-xs text-slate-200 ${item.mono ? 'font-mono' : ''}`} title={String(item.value ?? '')}>
            {item.node || String(item.value ?? '-')}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export function Tabs({ items, value, onChange, className = '' }) {
  return (
    <div className={`flex flex-wrap gap-1 rounded-lg border border-slate-800 bg-slate-900/60 p-1 ${className}`}>
      {items.map((item) => {
        const active = item.value === value
        return (
          <button
            key={item.value}
            type="button"
            onClick={() => onChange(item.value)}
            className={`rounded-md px-2.5 py-1.5 text-[11px] font-semibold transition ${
              active ? 'bg-cyan-500/15 text-cyan-300 shadow-[inset_0_0_0_1px_rgba(34,211,238,0.25)]' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
            title={item.hint}
          >
            {item.icon ? <item.icon size={12} className="mr-1 inline align-[-1px]" /> : null}
            {item.label}
            {item.count !== undefined ? <span className="ml-1.5 opacity-60">{item.count}</span> : null}
          </button>
        )
      })}
    </div>
  )
}
