import { Search, X } from 'lucide-react'

export function Field({ label, hint, error, children, className = '', required = false }) {
  return (
    <div className={className}>
      {label ? (
        <label className="label">
          {label}
          {required ? <span className="ml-0.5 text-rose-400">*</span> : null}
        </label>
      ) : null}
      {children}
      {error ? <p className="mt-1 text-[10px] font-medium text-rose-400">{error}</p> : null}
      {hint && !error ? <p className="muted mt-1">{hint}</p> : null}
    </div>
  )
}

export function Input({ label, hint, error, className = '', ...props }) {
  return (
    <Field label={label} hint={hint} error={error} className={className}>
      <input className="input" {...props} />
    </Field>
  )
}

export function Textarea({ label, hint, error, className = '', rows = 4, ...props }) {
  return (
    <Field label={label} hint={hint} error={error} className={className}>
      <textarea className="input resize-y font-mono text-[11px]" rows={rows} {...props} />
    </Field>
  )
}

export function Select({ label, hint, error, options = [], className = '', placeholder, children, ...props }) {
  return (
    <Field label={label} hint={hint} error={error} className={className}>
      <select className="select" {...props}>
        {placeholder ? <option value="">{placeholder}</option> : null}
        {options.map((option) =>
          typeof option === 'string' ? (
            <option key={option} value={option}>
              {option}
            </option>
          ) : (
            <option key={option.value} value={option.value} disabled={option.disabled}>
              {option.label}
            </option>
          ),
        )}
        {children}
      </select>
    </Field>
  )
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className = '' }) {
  return (
    <div className={`relative ${className}`}>
      <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
      <input
        className="input pl-8 pr-7"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {value ? (
        <button
          type="button"
          onClick={() => onChange('')}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-200"
          aria-label="Clear search"
        >
          <X size={13} />
        </button>
      ) : null}
    </div>
  )
}

export function Checkbox({ checked, onChange, label, className = '' }) {
  return (
    <label className={`flex cursor-pointer items-center gap-2 text-xs text-slate-300 ${className}`}>
      <input
        type="checkbox"
        checked={Boolean(checked)}
        onChange={(event) => onChange(event.target.checked)}
        className="h-3.5 w-3.5 rounded border-slate-600 bg-slate-900 accent-cyan-500"
      />
      {label}
    </label>
  )
}

export function FileDrop({ onFile, accept = '.csv,.json', label = 'Drag a CSV or JSON dataset here', hint, busy = false, progress }) {
  return (
    <label
      className={`flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-xl border border-dashed px-4 py-6 text-center transition ${
        busy ? 'border-cyan-500/50 bg-cyan-500/5' : 'border-slate-700 bg-slate-900/40 hover:border-cyan-500/50 hover:bg-slate-800/40'
      }`}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault()
        const file = event.dataTransfer?.files?.[0]
        if (file) onFile(file)
      }}
    >
      <input
        type="file"
        accept={accept}
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) onFile(file)
          event.target.value = ''
        }}
      />
      <span className="text-xs font-medium text-slate-200">{label}</span>
      {hint ? <span className="muted">{hint}</span> : null}
      {progress !== undefined && progress !== null ? (
        <span className="mono mt-1 text-cyan-300">uploading… {progress}%</span>
      ) : null}
    </label>
  )
}
