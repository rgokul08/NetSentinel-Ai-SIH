import React from 'react'

const RISK = {
  LOW: 'bg-emerald-500/15 text-emerald-400',
  MEDIUM: 'bg-amber-500/15 text-amber-400',
  HIGH: 'bg-orange-500/15 text-orange-400',
  CRITICAL: 'bg-rose-500/15 text-rose-400',
}

export const Badge = ({ level }) => (
  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${RISK[level] || 'bg-slate-500/15 text-slate-300'}`}>{level}</span>
)

export const Stat = ({ label, value, sub }) => (
  <div className="card">
    <div className="text-xs uppercase text-slate-400">{label}</div>
    <div className="text-2xl font-bold mt-1">{value}</div>
    {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
  </div>
)

export const Loading = () => <div className="text-slate-400 p-6">Loading…</div>

export const ErrorBox = ({ msg }) => (
  <div className="card border-rose-500/40 text-rose-300 text-sm">{msg}</div>
)

export function useFetch(fn, deps = [], intervalMs) {
  const [data, setData] = React.useState(null)
  const [error, setError] = React.useState(null)
  React.useEffect(() => {
    let alive = true
    const run = () =>
      fn()
        .then((r) => alive && (setData(r.data), setError(null)))
        .catch((e) => alive && setError(e.response?.data?.detail || e.message))
    run()
    const id = intervalMs ? setInterval(run, intervalMs) : null
    return () => { alive = false; if (id) clearInterval(id) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { data, error, setData }
}
