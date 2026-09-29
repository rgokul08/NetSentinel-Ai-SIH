import { ArrowRight, Info, Radar, ShieldAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { ProbabilityGauge } from '../charts/charts'
import { Badge, Progress } from '../ui/primitives'
import { formatPercent, timeAgo } from '../../utils/format'
import { riskColor } from '../../utils/theme'

/**
 * Headline risk panel: current threat level, the 60-minute forecast probability
 * and the per-horizon ramp. All numbers come from `/analytics/dashboard`.
 */
export default function ThreatLevelPanel({ overview, forecast, live, loading }) {
  const threatLevel = overview?.threat_level || live?.threat_level || 'unknown'
  const hex = riskColor(threatLevel)
  const overall = forecast?.overall || {}
  const topThreat = overall?.top_threat || {}
  const horizons = forecast?.horizons || []
  const probability = Number(overall.probability ?? topThreat.probability ?? 0)

  return (
    <div className="card relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0 opacity-[0.07]" style={{ background: `radial-gradient(600px 200px at 20% 0%, ${hex}, transparent)` }} />
      <div className="relative grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_220px]">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="panel-title">Current threat posture</p>
            <Badge tone="slate">window {overview?.window || live?.window || '24h'}</Badge>
            {live?.data_origin ? <Badge tone="purple">source: {live.data_origin}</Badge> : null}
          </div>

          <div className="mt-2 flex flex-wrap items-end gap-3">
            <p className="text-4xl font-bold uppercase leading-none tracking-tight" style={{ color: hex, textShadow: `0 0 26px ${hex}44` }}>
              {threatLevel}
            </p>
            <div className="mb-0.5">
              <p className="muted">
                mean risk {(Number(overview?.kpis?.mean_risk_score ?? 0) * 100).toFixed(1)}% · current{' '}
                {(Number(overview?.kpis?.current_risk_score ?? live?.current_risk_score ?? 0) * 100).toFixed(1)}%
              </p>
              <p className="muted">
                {overview?.kpis?.detected_threats ?? 0} detected threats · {overview?.kpis?.anomalies ?? 0} anomalies ·{' '}
                {overview?.kpis?.critical_alerts ?? 0} critical alerts open
              </p>
            </div>
          </div>

          <div className="mt-3.5 space-y-2.5">
            <div>
              <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                <span>Abnormal traffic share</span>
                <span className="font-mono text-slate-300">{Number(overview?.kpis?.abnormal_percentage ?? live?.abnormal_percentage ?? 0).toFixed(1)}%</span>
              </div>
              <Progress value={overview?.kpis?.abnormal_percentage ?? live?.abnormal_percentage ?? 0} max={100} tone="red" />
            </div>
            <div>
              <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                <span>Attack rate (verdicts / flows)</span>
                <span className="font-mono text-slate-300">{formatPercent(live?.attack_rate ?? 0, 1)}</span>
              </div>
              <Progress value={(live?.attack_rate ?? 0) * 100} max={100} tone="amber" />
            </div>
          </div>

          {horizons.length ? (
            <div className="mt-4">
              <p className="panel-title mb-2 flex items-center gap-1.5">
                <Radar size={11} className="text-cyan-400" /> Forecast ramp
              </p>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {horizons.map((horizon) => {
                  const level = String(horizon.overall_risk_level || '').toLowerCase()
                  const color = riskColor(level)
                  return (
                    <div key={horizon.horizon_minutes} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2">
                      <p className="mono text-[10px] uppercase tracking-wide text-slate-500">next {horizon.horizon_minutes}m</p>
                      <p className="mt-0.5 text-base font-bold leading-none" style={{ color }}>
                        {formatPercent(horizon.overall_probability, 0)}
                      </p>
                      <p className="mt-1 truncate text-[10px] text-slate-400" title={horizon.top_threat?.attack_type}>
                        {horizon.top_threat?.attack_type || '—'}
                      </p>
                      <Progress className="mt-1.5" value={Number(horizon.overall_probability) * 100} max={100} tone={level === 'critical' ? 'red' : level === 'high' ? 'amber' : 'cyan'} />
                    </div>
                  )
                })}
              </div>
            </div>
          ) : null}
        </div>

        <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <ProbabilityGauge value={probability} label={`${overall.horizon_minutes || 60}-min risk`} color={hex} height={150} />
          {topThreat?.attack_type ? (
            <div className="mt-1 w-full space-y-1.5 text-center">
              <p className="text-[11px] font-semibold text-slate-200">Leading threat: {topThreat.attack_type}</p>
              <p className="muted">
                {formatPercent(topThreat.probability, 1)} probability · {topThreat.expected_events ?? 0} expected events
              </p>
              <p className="muted">confidence {formatPercent(topThreat.confidence, 0)} · per-bucket {formatPercent(topThreat.per_bucket_probability, 0)}</p>
              {forecast?.generated_at ? <p className="mono text-[9.5px] text-slate-600">run {timeAgo(forecast.generated_at)}</p> : null}
              <Link to="/forecast" className="btn-secondary btn-sm mt-1 w-full">
                Open forecast <ArrowRight size={11} />
              </Link>
            </div>
          ) : (
            <div className="mt-2 text-center">
              <ShieldAlert size={16} className="mx-auto text-slate-500" />
              <p className="muted mt-1.5">No forecast has been run yet.</p>
              <Link to="/forecast" className="btn-secondary btn-sm mt-2">
                Run forecast
              </Link>
            </div>
          )}
        </div>
      </div>

      <p className="muted flex items-start gap-1.5 border-t border-slate-800/70 px-4 py-2">
        <Info size={11} className="mt-0.5 shrink-0" />
        {forecast?.disclaimer ||
          'Forecasts are probabilistic model estimates derived from historical traffic; they are not guarantees about future events.'}
      </p>
    </div>
  )
}
