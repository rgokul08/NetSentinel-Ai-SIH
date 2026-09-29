import { TrendingDown, TrendingUp } from 'lucide-react'
import { Sparkline } from '../charts/charts'
import { Skeleton } from './states'

const TONES = {
  cyan: { ring: 'border-cyan-500/25', icon: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/30', value: 'text-slate-50' },
  green: { ring: 'border-emerald-500/25', icon: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30', value: 'text-slate-50' },
  amber: { ring: 'border-amber-500/25', icon: 'text-amber-300 bg-amber-500/10 border-amber-500/30', value: 'text-slate-50' },
  red: { ring: 'border-rose-500/30', icon: 'text-rose-300 bg-rose-500/10 border-rose-500/30', value: 'text-slate-50' },
  purple: { ring: 'border-purple-500/25', icon: 'text-purple-300 bg-purple-500/10 border-purple-500/30', value: 'text-slate-50' },
  slate: { ring: 'border-slate-800', icon: 'text-slate-300 bg-slate-800/70 border-slate-700', value: 'text-slate-50' },
}

/**
 * KPI tile. Every value comes from the backend; `hint` is used to disclose the
 * provenance (simulation share, window, model version) so numbers are never
 * presented without context.
 */
export default function StatCard({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'cyan',
  hint,
  trend,
  trendLabel,
  spark,
  sparkKey = 'value',
  sparkColor,
  loading = false,
  onClick,
  footer,
}) {
  const styles = TONES[tone] || TONES.cyan
  const trendUp = Number(trend) > 0
  const trendDown = Number(trend) < 0

  return (
    <div
      className={`card card-hover relative overflow-hidden p-3.5 ${styles.ring} ${onClick ? 'cursor-pointer' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (event) => event.key === 'Enter' && onClick() : undefined}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="panel-title truncate">{label}</p>
        {Icon ? (
          <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${styles.icon}`}>
            <Icon size={13} />
          </span>
        ) : null}
      </div>

      {loading ? (
        <Skeleton className="mt-3" lines={1} />
      ) : (
        <p className={`mt-2 flex items-baseline gap-1 text-[22px] font-bold leading-none tracking-tight ${styles.value}`}>
          {value ?? '—'}
          {unit ? <span className="text-[11px] font-semibold text-slate-500">{unit}</span> : null}
        </p>
      )}

      {trend !== undefined && trend !== null && !Number.isNaN(Number(trend)) ? (
        <p className={`mt-1.5 flex items-center gap-1 text-[10.5px] font-medium ${trendUp ? 'text-rose-300' : trendDown ? 'text-emerald-300' : 'text-slate-400'}`}>
          {trendUp ? <TrendingUp size={11} /> : trendDown ? <TrendingDown size={11} /> : null}
          {trendUp ? '+' : ''}
          {Number(trend).toFixed(1)}% {trendLabel || 'vs previous window'}
        </p>
      ) : null}

      {spark?.length > 1 ? (
        <div className="mt-1.5 -mb-1">
          <Sparkline data={spark} dataKey={sparkKey} color={sparkColor || '#22d3ee'} height={26} />
        </div>
      ) : null}

      {hint ? <p className="muted mt-1.5 truncate" title={hint}>{hint}</p> : null}
      {footer ? <div className="mt-2">{footer}</div> : null}
    </div>
  )
}
