import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  BrainCircuit,
  CalendarClock,
  CheckCircle2,
  Info,
  Lightbulb,
  Play,
  Radar,
  RefreshCw,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react'
import { forecastApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Progress,
  RiskBadge,
  Select,
  StatCard,
} from '../components/ui'
import { ProbabilityGauge, TimeSeriesChart } from '../components/charts/charts'
import ForecastRangeChart from '../components/charts/ForecastRangeChart'
import { formatAxisTime, formatDateTime, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { riskColor } from '../utils/theme'
import { FORECAST_HORIZONS } from '../utils/constants'

export default function Forecast() {
  const { can } = useAuth()
  const toast = useToast()
  const [horizons, setHorizons] = useState(FORECAST_HORIZONS)
  const [selectedHorizon, setSelectedHorizon] = useState(60)
  const [historyRows, setHistoryRows] = useState(2000)

  const latest = useApi(() => forecastApi.latest(), [], { keepPrevious: true })
  const trend = useApi(() => forecastApi.trend({ limit: 120 }), [], { keepPrevious: true })
  const history = useApi(() => forecastApi.history({ limit: 12 }), [], { keepPrevious: true })
  const options = useApi(() => forecastApi.options(), [])

  const run = useAction(
    async () => {
      const result = await forecastApi.run({ horizons, history_rows: historyRows })
      toast.success(
        'Forecast updated',
        `${result.run_id ? `Run ${result.run_id}` : 'New run'} · ${result.overall?.risk_level || 'n/a'} risk over ${result.overall?.horizon_minutes || selectedHorizon} min.`,
      )
      latest.refetch()
      trend.refetch()
      history.refetch()
      return result
    },
    { onError: (failure) => toast.error('Forecast failed', failure.message) },
  )

  const forecast = latest.data || {}
  const availableHorizons = forecast.horizons || []
  const horizon = useMemo(
    () => availableHorizons.find((item) => item.horizon_minutes === selectedHorizon) || availableHorizons[availableHorizons.length - 1] || null,
    [availableHorizons, selectedHorizon],
  )
  const categories = (horizon?.categories || []).filter((item) => item.attack_type !== 'Benign')
  const topThreat = horizon?.top_threat || null

  /** `/forecast/trend` returns one row per (run, horizon, category); keep the worst case per run. */
  const trendSeries = useMemo(() => {
    const items = trend.data?.items || []
    const byTime = new Map()
    items.forEach((item) => {
      const key = item.created_at
      if (!byTime.has(key)) byTime.set(key, { time: key })
      const point = byTime.get(key)
      const field = `h${item.horizon_minutes}`
      const value = Number(item.overall_probability) * 100
      point[field] = Math.max(point[field] ?? 0, value)
    })
    return [...byTime.values()].sort((a, b) => new Date(a.time) - new Date(b.time))
  }, [trend.data])

  if (latest.loading && !forecast.available) return <LoadingState label="Loading forecast…" className="py-24" />
  if (latest.error && !forecast.available) return <ErrorState error={latest.error} onRetry={latest.refetch} className="py-16" />

  if (!forecast.available) {
    return (
      <div className="space-y-4">
        <ForecastControls
          horizons={horizons}
          setHorizons={setHorizons}
          historyRows={historyRows}
          setHistoryRows={setHistoryRows}
          run={run}
          can={can}
          latest={latest}
          options={options.data}
        />
        <Card>
          <EmptyState
            icon={Radar}
            title="No forecast has been run yet"
            message="The forecaster fits a ridge lag-regression on historical per-category attack counts and projects the probability of at least one attack in each horizon. Run it now — it takes a couple of seconds."
            action={
              can('forecast.run') ? (
                <Button variant="primary" icon={Play} loading={run.busy} onClick={run.run}>
                  Run first forecast
                </Button>
              ) : (
                <p className="muted">Your role cannot run forecasts; ask an analyst or administrator.</p>
              )
            }
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <ForecastControls
        horizons={horizons}
        setHorizons={setHorizons}
        historyRows={historyRows}
        setHistoryRows={setHistoryRows}
        run={run}
        can={can}
        latest={latest}
        options={options.data}
      />

      {/* run metadata */}
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="cyan"><BrainCircuit size={9} /> {forecast.method || 'ridge-lag-regression'}</Badge>
        <Badge tone="slate">model {forecast.model_version || 'n/a'}</Badge>
        <Badge tone="slate">{formatNumber(forecast.records_used || 0)} historical rows</Badge>
        <Badge tone={forecast.loaded_from === 'database' ? 'slate' : 'green'}>source: {forecast.loaded_from || forecast.source}</Badge>
        <span className="muted">generated {forecast.generated_at ? formatDateTime(forecast.generated_at) : '—'} ({timeAgo(forecast.generated_at)})</span>
        {run.error ? <span className="text-[11px] text-rose-300">{run.error.message}</span> : null}
      </div>

      {/* horizon selector + headline */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {availableHorizons.map((item) => {
              const active = item.horizon_minutes === horizon?.horizon_minutes
              const hex = riskColor(item.overall_risk_level)
              return (
                <button
                  key={item.horizon_minutes}
                  type="button"
                  onClick={() => setSelectedHorizon(item.horizon_minutes)}
                  className={`flex-1 rounded-xl border p-3 text-left transition ${
                    active ? 'border-cyan-500/50 bg-cyan-500/8' : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'
                  }`}
                >
                  <p className="mono text-[10px] uppercase tracking-[0.14em] text-slate-500">next {item.horizon_minutes} minutes</p>
                  <p className="mt-1 text-xl font-bold leading-none" style={{ color: hex }}>
                    {formatPercent(item.overall_probability, 0)}
                  </p>
                  <div className="mt-2 flex items-center justify-between gap-2">
                    <RiskBadge level={item.overall_risk_level} />
                    <span className="mono text-[10px] text-slate-500">{item.expected_attack_events ?? 0} events</span>
                  </div>
                  <Progress className="mt-2" value={Number(item.overall_probability) * 100} max={100} tone={item.overall_risk_level === 'critical' ? 'red' : item.overall_risk_level === 'high' ? 'amber' : 'cyan'} />
                </button>
              )
            })}
          </div>

          <Card
            title={`Per-category probabilities · next ${horizon?.horizon_minutes || 60} minutes`}
            subtitle="Bar = probability of at least one attack of that type; translucent range = 95% interval on expected event counts"
            icon={TrendingUp}
          >
            <ForecastRangeChart data={categories} height={Math.max(220, categories.length * 38)} />
          </Card>

          <Card title="Category detail" subtitle="Expected events, confidence and the dominant historical drivers" icon={Radar} bodyClass="p-0">
            {categories.length === 0 ? (
              <EmptyState title="No attack categories projected" message="The forecaster found no historical attack events to project in this window." />
            ) : (
              <div className="divide-y divide-slate-800/60">
                {categories.map((category) => (
                  <div key={category.id || category.attack_type} className="p-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <AttackBadge type={category.attack_type} />
                        <RiskBadge level={String(category.risk_level || '').toLowerCase()} score={category.probability} />
                        {category.method ? <Badge tone="slate">{category.method}</Badge> : null}
                      </div>
                      <span className="mono text-[10.5px] text-slate-500">
                        {formatNumber(category.historical_events || 0)} historical events · rmse {Number(category.residual_rmse || 0).toFixed(3)}
                      </span>
                    </div>

                    <div className="mt-2.5 grid gap-3 sm:grid-cols-4">
                      <Metric label="Cumulative probability" value={formatPercent(category.probability, 1)} hint="≥1 attack in horizon" />
                      <Metric label="Per-bucket probability" value={formatPercent(category.per_bucket_probability, 1)} hint={`each ${Math.max(1, Math.round((horizon?.horizon_minutes || 60) / 12))} min bucket`} />
                      <Metric label="Peak bucket" value={formatPercent(category.peak_bucket_probability, 1)} hint="busiest interval" />
                      <Metric
                        label="Expected events"
                        value={Number(category.expected_events || 0).toFixed(2)}
                        hint={`95% CI ${category.lower_bound ?? 0}–${category.upper_bound ?? 0}`}
                      />
                    </div>

                    <div className="mt-2.5">
                      <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                        <span>Model confidence</span>
                        <span className="font-mono text-slate-300">{formatPercent(category.confidence, 1)}</span>
                      </div>
                      <Progress value={Number(category.confidence) * 100} max={100} tone="cyan" />
                    </div>

                    {category.contributing_features?.length ? (
                      <div className="mt-2.5">
                        <p className="panel-title mb-1.5">Dominant drivers</p>
                        <ul className="space-y-1">
                          {category.contributing_features.slice(0, 4).map((feature) => (
                            <li key={feature.feature || feature.label} className="flex items-center gap-2">
                              <span className="w-44 shrink-0 truncate text-[11px] text-slate-300">{feature.label || feature.feature}</span>
                              <Progress className="flex-1" value={Math.abs(Number(feature.contribution || feature.weight || 0)) * 100} max={100} tone="purple" />
                              <span className="mono w-16 shrink-0 text-right text-[10.5px] text-slate-400">
                                {formatPercent(feature.contribution ?? feature.weight ?? 0, 1)}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : null}

                    {category.recommendation ? (
                      <div className="mt-2.5 flex items-start gap-2 rounded-lg border border-cyan-500/25 bg-cyan-500/6 p-2.5">
                        <Lightbulb size={13} className="mt-0.5 shrink-0 text-cyan-300" />
                        <p className="text-[11px] leading-relaxed text-cyan-100/90">{category.recommendation}</p>
                      </div>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Headline estimate" icon={ShieldAlert}>
            <ProbabilityGauge
              value={horizon?.overall_probability ?? 0}
              label={`${horizon?.horizon_minutes || 60}-min attack risk`}
              color={riskColor(horizon?.overall_risk_level)}
              height={170}
            />
            <div className="mt-2 space-y-2">
              <KeyValue
                columns={1}
                items={[
                  { label: 'Risk level', value: String(horizon?.overall_risk_level || '—').toUpperCase() },
                  { label: 'Any-attack probability', value: formatPercent(horizon?.overall_probability, 2), mono: true },
                  { label: 'Expected attack events', value: Number(horizon?.expected_attack_events ?? 0).toFixed(2), mono: true },
                  { label: 'Aggregate confidence', value: formatPercent(horizon?.overall_confidence, 1), mono: true },
                  { label: 'Forecast time', value: horizon ? formatDateTime(horizon.created_at) : '—', mono: true },
                ]}
              />
              {topThreat ? (
                <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-2.5">
                  <p className="panel-title mb-1">Leading threat</p>
                  <div className="flex items-center justify-between gap-2">
                    <AttackBadge type={topThreat.attack_type} />
                    <span className="mono text-[11px] text-slate-200">{formatPercent(topThreat.probability, 1)}</span>
                  </div>
                  <p className="muted mt-1.5">
                    {formatNumber(topThreat.expected_events ?? 0)} expected events · confidence {formatPercent(topThreat.confidence, 0)} · per-bucket{' '}
                    {formatPercent(topThreat.per_bucket_probability, 0)}
                  </p>
                </div>
              ) : null}
            </div>
          </Card>

          <Card title="Forecast history" subtitle="Probability estimates from previous runs" icon={CalendarClock}>
            {trendSeries.length > 1 ? (
              <TimeSeriesChart
                data={trendSeries}
                type="line"
                series={[5, 15, 30, 60]
                  .filter((minutes) => trendSeries.some((point) => point[`h${minutes}`] !== undefined))
                  .map((minutes, index) => ({
                    key: `h${minutes}`,
                    label: `${minutes} min`,
                    color: ['#22d3ee', '#a855f7', '#fbbf24', '#fb7185'][index % 4],
                  }))}
                height={200}
                xFormatter={formatAxisTime}
                yFormatter={(value) => `${Number(value).toFixed(0)}%`}
              />
            ) : (
              <p className="muted">Run the forecaster a few times to build a trend line.</p>
            )}
            <Link to="/analytics" className="btn-secondary btn-sm mt-2 w-full">
              Open analytics <TrendingUp size={11} />
            </Link>
          </Card>

          <Card title="How this estimate is produced" icon={Info} dense>
            <ul className="space-y-2 text-[11px] leading-relaxed text-slate-400">
              <li>
                <span className="text-slate-200">1.</span> Historical traffic records are bucketed (12 buckets per horizon) and counted per
                attack category.
              </li>
              <li>
                <span className="text-slate-200">2.</span> A ridge regression on three lagged counts plus exogenous features (traffic volume,
                unique sources, anomaly rate) predicts the next bucket counts.
              </li>
              <li>
                <span className="text-slate-200">3.</span> Counts are mapped through a Poisson link so the reported number is the probability of
                at least one event, with a 95% interval on the expected count.
              </li>
              <li>
                <span className="text-slate-200">4.</span> Confidence is derived from residual error and sample size and is clamped to a
                realistic range.
              </li>
            </ul>
            <p className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-amber-500/25 bg-amber-500/8 p-2 text-[10.5px] leading-relaxed text-amber-200">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              {forecast.disclaimer || 'Forecasts are probabilistic model estimates derived from historical traffic; they are not guarantees about future events.'}
            </p>
          </Card>
        </div>
      </div>

      {/* previous runs */}
      <Card
        title="Previous forecast runs"
        subtitle={`${formatNumber(history.data?.runs_returned ?? 0)} most recent runs of ${formatNumber(history.data?.total ?? 0)} stored category projections`}
        icon={CalendarClock}
        bodyClass="p-0"
        actions={
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={history.refetch} loading={history.loading}>
            Reload
          </Button>
        }
      >
        {history.loading && !history.data ? (
          <LoadingState label="Loading forecast history…" />
        ) : history.error ? (
          <ErrorState error={history.error} onRetry={history.refetch} />
        ) : (history.data?.items || []).length === 0 ? (
          <EmptyState icon={CalendarClock} title="No previous runs stored" message="Each forecast run is persisted so you can compare estimates over time." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Generated</th>
                  <th>Horizon</th>
                  <th>Leading category</th>
                  <th className="text-right">Probability</th>
                  <th className="text-right">Expected events</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {(history.data.items || []).flatMap((run) =>
                  Object.entries(run.horizons || {}).map(([minutes, summary]) => (
                    <tr key={`${run.run_id}-${minutes}`}>
                      <td className="mono text-[10.5px] text-cyan-300">{shortRunId(run.run_id)}</td>
                      <td className="mono text-[10.5px] text-slate-400">{formatDateTime(run.created_at)}</td>
                      <td className="mono">{minutes} min</td>
                      <td>{summary.top_attack ? <AttackBadge type={summary.top_attack} /> : <span className="text-slate-600">—</span>}</td>
                      <td className="mono text-right">{formatPercent(summary.overall_probability, 1)}</td>
                      <td className="mono text-right">{Number(summary.expected_events ?? 0).toFixed(2)}</td>
                      <td>
                        <RiskBadge level={String(summary.risk_level || '').toLowerCase()} />
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

function shortRunId(value) {
  const text = String(value || '')
  return text.length > 12 ? `${text.slice(0, 8)}…` : text
}

function Metric({ label, value, hint }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2">
      <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-base font-bold leading-none text-slate-100">{value}</p>
      {hint ? <p className="muted mt-1 text-[9.5px]">{hint}</p> : null}
    </div>
  )
}

function ForecastControls({ horizons, setHorizons, historyRows, setHistoryRows, run, can, latest, options }) {
  const allowed = options?.horizons || FORECAST_HORIZONS
  const canRun = can('forecast.run')

  return (
    <Card
      title="Run a new forecast"
      subtitle="Choose the projection horizons; the backend refits on the stored traffic history"
      icon={Play}
      actions={
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={latest.refetch} loading={latest.loading}>
            Reload latest
          </Button>
          <Button
            size="sm"
            variant="primary"
            icon={Play}
            loading={run.busy}
            disabled={!canRun || horizons.length === 0}
            onClick={run.run}
            title={canRun ? 'Run forecast now' : 'Your role cannot run forecasts'}
          >
            {canRun ? 'Run forecast' : 'Not permitted'}
          </Button>
        </div>
      }
    >
      <div className="flex flex-wrap items-end gap-4">
        <div>
          <p className="label">Horizons (minutes)</p>
          <div className="flex flex-wrap gap-3">
            {allowed.map((minutes) => (
              <Checkbox
                key={minutes}
                checked={horizons.includes(minutes)}
                label={`${minutes} min`}
                onChange={(checked) =>
                  setHorizons((current) =>
                    checked ? [...current, minutes].sort((a, b) => a - b) : current.filter((value) => value !== minutes),
                  )
                }
              />
            ))}
          </div>
        </div>
        <Select
          label="History rows analysed"
          className="w-auto min-w-[168px]"
          value={historyRows}
          onChange={(event) => setHistoryRows(Number(event.target.value))}
          options={[
            { value: 1000, label: '1,000 recent rows' },
            { value: 2000, label: '2,000 recent rows' },
            { value: 5000, label: '5,000 recent rows' },
            { value: 20000, label: '20,000 recent rows' },
          ]}
          hint="More history improves stability but takes longer"
        />
        {!canRun ? (
          <p className="flex items-center gap-1.5 text-[11px] text-amber-300">
            <AlertTriangle size={12} /> Your role ({can ? 'viewer' : ''}) can read forecasts but not run them.
          </p>
        ) : null}
        {run.result ? (
          <p className="flex items-center gap-1.5 text-[11px] text-emerald-300">
            <CheckCircle2 size={12} /> Last run {timeAgo(run.result.generated_at || new Date().toISOString())}
          </p>
        ) : null}
      </div>
    </Card>
  )
}
