import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  Cpu,
  Database,
  Gauge,
  Layers,
  Lock,
  LogIn,
  Network,
  Radar,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldHalf,
  Siren,
  Users,
  Zap,
} from 'lucide-react'
import { analyticsApi } from '../services/endpoints'
import { useApi } from '../hooks/useApi'
import { useRealtime } from '../context/RealtimeContext'
import { useAuth } from '../context/AuthContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  ErrorState,
  KeyValue,
  LoadingState,
  Progress,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from '../components/ui'
import { CategoryBarChart, DonutChart, TimeSeriesChart } from '../components/charts/charts'
import ForecastRangeChart from '../components/charts/ForecastRangeChart'
import ThreatLevelPanel from '../components/threat/ThreatLevelPanel'
import LiveActivityFeed from '../components/threat/LiveActivityFeed'
import { compactNumber, formatAxisTime, formatBytes, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { attackColor, severityColor } from '../utils/theme'

export default function Dashboard() {
  const { can, isAuthenticated } = useAuth()
  const navigate = useNavigate()
  const { connected, events } = useRealtime()
  const [liveAlerts, setLiveAlerts] = useState([])

  const state = useApi(() => analyticsApi.dashboard(), [], { keepPrevious: true })
  const dashboard = state.data

  /** Top talkers/targets are served by a dedicated analytics endpoint. */
  const entities = useApi(() => analyticsApi.entities({ window: '24h' }), [], { keepPrevious: true })

  useEffect(() => {
    setLiveAlerts(dashboard?.latest_alerts || [])
  }, [dashboard?.latest_alerts])

  const kpis = dashboard?.kpis || {}
  const trends = dashboard?.trends || {}
  const forecast = dashboard?.forecast || {}
  const alertStats = dashboard?.alert_stats || dashboard?.overview?.alerts || {}
  const blockchain = dashboard?.blockchain || dashboard?.overview?.blockchain || {}
  const models = dashboard?.models || dashboard?.overview?.model || {}
  const simulation = dashboard?.simulation || {}
  const health = dashboard?.system_health || {}
  const traffic = dashboard?.traffic_summary || {}

  const trendSeries = useMemo(
    () =>
      (trends.attacks_over_time || []).map((point, index) => ({
        time: point.time,
        attacks: point.attacks,
        flows: point.flows,
        anomalies: trends.anomaly_trend?.[index]?.anomalies ?? 0,
      })),
    [trends],
  )

  const classDistribution = useMemo(
    () => (trends.attack_by_category || []).filter((item) => item.name !== 'Benign'),
    [trends],
  )

  const longestHorizon = useMemo(() => {
    const horizons = forecast?.horizons || []
    return horizons.length ? horizons[horizons.length - 1] : null
  }, [forecast])

  const forecastCategories = useMemo(
    () => (longestHorizon?.categories || forecast?.categories || []).filter((item) => item.attack_type !== 'Benign'),
    [forecast, longestHorizon],
  )

  if (state.loading && !dashboard) return <LoadingState label="Loading command center…" className="py-24" />
  if (state.error && !dashboard) return <ErrorState error={state.error} onRetry={state.refetch} className="py-16" />
  if (!dashboard) return null

  return (
    <div className="space-y-4">
      {/* guest banner - the dashboard is public, signing in is optional */}
      {!isAuthenticated ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/8 px-4 py-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
              <ShieldHalf size={15} className="text-cyan-300" />
            </span>
            <div className="min-w-0">
              <p className="text-xs font-semibold text-slate-100">You&rsquo;re viewing the live Command Center as a guest</p>
              <p className="muted mt-0.5 text-[11px]">Sign in to run detections and forecasts, triage alerts and unlock the full workspace.</p>
            </div>
          </div>
          <Link to="/login" className="shrink-0">
            <Button size="sm" variant="primary" icon={LogIn}>
              Sign in
            </Button>
          </Link>
        </div>
      ) : null}

      {/* provenance + refresh */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="slate">
            <Database size={10} /> window {dashboard.window}
          </Badge>
          <Badge tone={traffic.simulated_percentage > 0 ? 'purple' : 'green'}>
            {traffic.simulated_percentage > 0
              ? `${Number(traffic.simulated_percentage).toFixed(0)}% simulated traffic`
              : 'real dataset traffic'}
          </Badge>
          <Badge tone="cyan">
            <Cpu size={10} /> {models.engine === 'ml' ? models.active_classifier?.algorithm || 'ml engine' : 'heuristic engine'}
          </Badge>
          <span className="muted">refreshed {state.loadedAt ? timeAgo(state.loadedAt) : '—'}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={state.refetch} loading={state.loading}>
            Refresh
          </Button>
          {can('forecast.run') ? (
            <Link to="/forecast">
              <Button size="sm" variant="primary" icon={Radar}>
                Run forecast
              </Button>
            </Link>
          ) : null}
        </div>
      </div>

      <ThreatLevelPanel overview={dashboard.overview} forecast={forecast} live={{ ...traffic, ...kpis, data_origin: simulation.status === 'running' ? 'simulation' : undefined }} loading={state.loading} />

      {/* KPI grid - every figure is computed by the backend from stored records */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-6">
        <StatCard
          label="Flows analysed"
          value={formatNumber(kpis.flows)}
          icon={Network}
          tone="cyan"
          loading={state.loading}
          hint={`${formatNumber(kpis.packets)} packets · ${formatBytes(kpis.traffic_bytes)}`}
          spark={trendSeries}
          sparkKey="flows"
        />
        <StatCard
          label="Detected threats"
          value={formatNumber(kpis.detected_threats)}
          icon={ShieldAlert}
          tone="red"
          loading={state.loading}
          hint={`attack rate ${formatPercent(traffic.attack_rate, 1)} · top ${traffic.top_attack || '—'}`}
          spark={trendSeries}
          sparkKey="attacks"
          sparkColor="#fb7185"
          onClick={() => navigate('/alerts')}
        />
        <StatCard
          label="Critical alerts"
          value={formatNumber(kpis.critical_alerts)}
          unit="open"
          icon={Siren}
          tone="amber"
          loading={state.loading}
          hint={`${formatNumber(alertStats.open ?? alertStats.total ?? 0)} alerts total`}
        />
        <StatCard
          label="Anomalies"
          value={formatNumber(kpis.anomalies)}
          icon={Activity}
          tone="purple"
          loading={state.loading}
          hint={`${Number(kpis.abnormal_percentage ?? 0).toFixed(1)}% of traffic abnormal`}
          spark={trendSeries}
          sparkKey="anomalies"
          sparkColor="#a855f7"
        />
        <StatCard
          label={`Forecast ${longestHorizon?.horizon_minutes || 60} min`}
          value={formatPercent(longestHorizon?.overall_probability ?? forecast?.overall?.probability ?? 0, 0)}
          icon={Radar}
          tone={(longestHorizon?.overall_risk_level || '').toLowerCase() === 'critical' ? 'red' : 'cyan'}
          loading={state.loading}
          hint={`${forecast?.overall?.top_threat?.attack_type || '—'} leading · confidence ${formatPercent(
            longestHorizon?.overall_confidence ?? 0,
            0,
          )}`}
        />
        <StatCard
          label="Throughput"
          value={Number(kpis.traffic_mbps ?? 0).toFixed(2)}
          unit="Mbps"
          icon={Gauge}
          tone="green"
          loading={state.loading}
          hint={`${Number(kpis.packets_per_second ?? 0).toFixed(1)} pps · ${formatBytes(kpis.bytes_per_second)}/s`}
        />
      </div>

      {/* trends + distribution */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Attack and traffic trend"
          subtitle={`Bucketed by the backend · ${dashboard.window} window`}
          icon={Activity}
          actions={
            <Link to="/analytics" className="btn-ghost btn-xs">
              Analytics <ArrowRight size={10} />
            </Link>
          }
        >
          <TimeSeriesChart
            data={trendSeries}
            series={[
              { key: 'flows', label: 'Flows', color: '#38bdf8' },
              { key: 'attacks', label: 'Attacks', color: '#fb7185' },
              { key: 'anomalies', label: 'Anomalies', color: '#a855f7', opacity: 0.25 },
            ]}
            height={250}
            xFormatter={formatAxisTime}
            emptyMessage="No traffic has been recorded in this window yet."
          />
        </Card>

        <Card title="Attack class distribution" subtitle="Model verdicts on analysed flows" icon={Layers}>
          <DonutChart
            data={classDistribution}
            height={250}
            colorBy={(entry) => attackColor(entry.name)}
            centerValue={formatNumber(kpis.detected_threats)}
            centerLabel="threats"
            emptyMessage="No attack verdicts recorded yet."
          />
        </Card>
      </div>

      {/* forecast strip */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title={`Forecast · next ${longestHorizon?.horizon_minutes || 60} minutes`}
          subtitle={forecast?.disclaimer || 'Probabilistic estimates from the ridge lag-regression forecaster'}
          icon={Radar}
          actions={
            <Link to="/forecast" className="btn-ghost btn-xs">
              Details <ArrowRight size={10} />
            </Link>
          }
        >
          <ForecastRangeChart data={forecastCategories} height={230} />
          <p className="muted mt-1">
            Bar length = probability of at least one attack of that type in the horizon; the translucent range is the model's 95% interval on
            expected event counts. Per-bucket rates are shown in the forecast workspace.
          </p>
        </Card>

        <Card title="Detection correctness" subtitle="Verdict vs. ground truth on labelled traffic" icon={Boxes}>
          {trends.correctness ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                {[
                  { label: 'Accuracy', value: trends.correctness.accuracy, tone: 'green' },
                  { label: 'Precision', value: trends.correctness.precision, tone: 'cyan' },
                  { label: 'Recall', value: trends.correctness.recall, tone: 'purple' },
                  { label: 'False-positive rate', value: trends.correctness.false_positive_rate, tone: 'amber' },
                ].map((metric) => (
                  <div key={metric.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
                    <p className="text-[10px] uppercase tracking-wide text-slate-500">{metric.label}</p>
                    <p className="mt-0.5 text-lg font-bold leading-none text-slate-100">{formatPercent(metric.value, 1)}</p>
                    <Progress className="mt-1.5" value={Number(metric.value) * 100} max={100} tone={metric.tone} />
                  </div>
                ))}
              </div>
              <KeyValue
                columns={2}
                items={[
                  { label: 'True positives', value: formatNumber(trends.correctness.true_positives), mono: true },
                  { label: 'True negatives', value: formatNumber(trends.correctness.true_negatives), mono: true },
                  { label: 'False positives', value: formatNumber(trends.correctness.false_positives), mono: true },
                  { label: 'False negatives', value: formatNumber(trends.correctness.false_negatives), mono: true },
                  { label: 'Labelled rows', value: formatNumber(trends.correctness.labeled_rows), mono: true },
                  { label: 'Active model', value: models.active_classifier?.name || '—' },
                ]}
              />
              <Link to="/models" className="btn-secondary btn-sm w-full">
                Model registry <ArrowRight size={11} />
              </Link>
            </div>
          ) : (
            <p className="muted">
              No labelled traffic in this window yet, so detection quality cannot be measured. Upload a labelled dataset or run the
              simulation to populate it.
            </p>
          )}
        </Card>
      </div>

      {/* alerts + live feed + platform status */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Latest threat alerts"
          subtitle={`${formatNumber(alertStats.open ?? 0)} open · ${formatNumber(alertStats.critical_open ?? 0)} critical`}
          icon={Siren}
          actions={
            <Link to="/alerts" className="btn-ghost btn-xs">
              Triage queue <ArrowRight size={10} />
            </Link>
          }
          bodyClass="p-0"
          dense
        >
          {(dashboard.latest_alerts || []).length === 0 ? (
            <div className="px-4 py-6">
              <p className="muted">
                No alerts in this window. Alerts are raised only when the model verdict, risk score and throttling rules agree that an
                analyst should look.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-800/60">
              {(dashboard.latest_alerts || []).slice(0, 6).map((alert) => (
                <li key={alert.id} className="flex items-start gap-3 px-4 py-2.5">
                  <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: severityColor(alert.severity).hex }} />
                  <div className="min-w-0 flex-1">
                    <p className="flex flex-wrap items-center gap-1.5 text-xs font-medium text-slate-100">
                      <span className="truncate">{alert.title}</span>
                      <SeverityBadge severity={alert.severity} />
                      <StatusBadge status={alert.status} />
                    </p>
                    <p className="muted mt-0.5 line-clamp-2">{alert.description}</p>
                    <p className="mono mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-slate-500">
                      <span>{alert.alert_code}</span>
                      <span>·</span>
                      <span>{timeAgo(alert.timestamp)}</span>
                      {alert.source_ip ? (
                        <>
                          <span>·</span>
                          <span>{alert.source_ip} → {alert.destination_ip || '—'}</span>
                        </>
                      ) : null}
                      {alert.blockchain_status ? (
                        <>
                          <span>·</span>
                          <Lock size={9} className="inline text-emerald-400/80" /> {alert.blockchain_status}
                        </>
                      ) : null}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <AttackBadge type={alert.attack_type} />
                    <p className="mono mt-1 text-[10px] text-slate-500">risk {(Number(alert.risk_score) * 100).toFixed(0)}%</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <LiveActivityFeed items={dashboard.live_activity || []} liveEvents={events.filter((event) => event.type === 'prediction')} connected={connected} />
      </div>

      {/* platform status row */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card title="Integrity ledger" icon={Lock} dense>
          <div className="space-y-2.5">
            <div className="flex items-end justify-between">
              <p className="text-2xl font-bold leading-none text-emerald-300">{Number(blockchain.verified_percentage ?? 0).toFixed(1)}%</p>
              <p className="muted">{formatNumber(blockchain.verified ?? 0)} / {formatNumber(blockchain.total_events ?? 0)} verified</p>
            </div>
            <Progress value={blockchain.verified_percentage ?? 0} max={100} tone="green" />
            <KeyValue
              columns={1}
              items={[
                { label: 'Anchor mode', value: blockchain.anchor_mode || 'local-hash-chain', mono: true },
                { label: 'Pending anchors', value: formatNumber(blockchain.pending ?? 0), mono: true },
                { label: 'Failed verification', value: formatNumber(blockchain.failed ?? 0), mono: true },
                { label: 'Tamper demo entries', value: formatNumber(blockchain.tamper_demo_events ?? 0), mono: true },
              ]}
            />
            <Link to="/blockchain" className="btn-secondary btn-sm w-full">
              Verify ledger <ArrowRight size={11} />
            </Link>
          </div>
        </Card>

        <Card title="Active models" icon={Cpu} dense>
          <div className="space-y-2.5">
            {[models.active_classifier, models.active_anomaly_detector].filter(Boolean).map((model) => (
              <div key={model.id} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <p className="truncate text-[11px] font-semibold text-slate-200">{model.name}</p>
                  <Badge tone={model.task === 'classification' ? 'cyan' : 'purple'}>{model.task}</Badge>
                </div>
                <p className="mono mt-1 text-[10px] text-slate-500">
                  {model.algorithm} · v{model.version} · {formatNumber(model.training_rows)} rows
                </p>
                <div className="mt-1.5 flex items-center gap-2">
                  <Progress className="flex-1" value={Number(model.accuracy ?? 0) * 100} max={100} tone={model.task === 'anomaly' ? 'purple' : 'cyan'} />
                  <span className="mono text-[10px] text-slate-300">{formatPercent(model.accuracy, 1)}</span>
                </div>
              </div>
            ))}
            <Link to="/models" className="btn-secondary btn-sm w-full">
              Model registry <ArrowRight size={11} />
            </Link>
          </div>
        </Card>

        <Card title="Simulation engine" icon={Zap} dense>
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <StatusBadge status={simulation.status || 'stopped'} />
              <span className="badge border-purple-500/40 bg-purple-500/10 text-purple-300">{simulation.label || 'Simulation Mode'}</span>
            </div>
            <KeyValue
              columns={1}
              items={[
                { label: 'Scenario', value: simulation.scenario_label || simulation.scenario || '—' },
                { label: 'Generated flows', value: formatNumber(simulation.generated_flows ?? 0), mono: true },
                { label: 'Attacks generated', value: formatNumber(simulation.attacks_generated ?? 0), mono: true },
                { label: 'Alerts created', value: formatNumber(simulation.alerts_created ?? 0), mono: true },
                { label: 'Flow rate', value: `${Number(simulation.flows_per_second ?? 0).toFixed(1)} flows/s`, mono: true },
              ]}
            />
            {simulation.status === 'running' ? <Progress value={Number(simulation.progress ?? 0) * 100} max={100} tone="purple" /> : null}
            <Link to="/simulation" className="btn-secondary btn-sm w-full">
              Simulation console <ArrowRight size={11} />
            </Link>
          </div>
        </Card>

        <Card title="Platform health" icon={Server} dense>
          <div className="space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <StatusBadge status={health.status || 'unknown'} />
              <span className="muted">{health.checked_at ? timeAgo(health.checked_at) : ''}</span>
            </div>
            <ul className="space-y-1.5">
              {Object.entries(health.components || {}).map(([name, component]) => (
                <li key={name} className="flex items-center justify-between gap-2 rounded border border-slate-800/70 bg-slate-950/40 px-2 py-1.5">
                  <span className="mono truncate text-[10.5px] uppercase tracking-wide text-slate-400">{name.replace(/_/g, ' ')}</span>
                  <StatusBadge status={component?.status || (component?.ok ? 'online' : 'offline')} />
                </li>
              ))}
            </ul>
            {health.version ? (
              <p className="mono text-[10px] text-slate-500">
                v{health.version} · storage {health.storage_backend} · {health.blockchain_mode}
              </p>
            ) : null}
            <Link to="/settings" className="btn-secondary btn-sm w-full">
              System settings <ArrowRight size={11} />
            </Link>
          </div>
        </Card>
      </div>

      {/* top entities */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          title="Most active sources"
          subtitle="By analysed flows in the last 24 hours"
          icon={Users}
          dense
          bodyClass="p-0"
        >
          <EntityList items={(entities.data?.sources || []).slice(0, 6)} loading={entities.loading} />
        </Card>
        <Card
          title="Most targeted assets"
          subtitle="Destinations receiving attack verdicts"
          icon={Server}
          dense
          bodyClass="p-0"
        >
          <EntityList items={(entities.data?.targets || []).slice(0, 6)} loading={entities.loading} />
        </Card>
        <Card title="Alert mix" icon={AlertTriangle} dense>
          <CategoryBarChart
            data={Object.entries(alertStats.by_attack_type || {}).map(([name, value]) => ({ name, value }))}
            height={190}
            horizontal
            colorBy={(entry) => attackColor(entry.name)}
            emptyMessage="No alerts recorded in this window."
          />
        </Card>
      </div>
    </div>
  )
}

function EntityList({ items, loading = false }) {
  if (loading && !items?.length) return <LoadingState label="Loading entities…" className="py-6" />
  if (!items?.length) {
    return <p className="muted px-4 py-4">No entities recorded in this window yet.</p>
  }
  const max = Math.max(...items.map((item) => Number(item.flows) || 0), 1)
  return (
    <ul className="divide-y divide-slate-800/60">
      {items.map((item) => (
        <li key={item.ip || item.port} className="px-4 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="mono truncate text-[11px] text-slate-300">{item.ip || `port ${item.port}`}</span>
            <span className="flex shrink-0 items-center gap-2">
              <span className="mono text-[10.5px] text-slate-400">{compactNumber(item.packets || 0)} pkts</span>
              {item.attacks ? <Badge tone="red">{item.attacks} atk</Badge> : null}
            </span>
          </div>
          <Progress
            className="mt-1.5"
            value={item.flows || 0}
            max={max}
            tone={item.risk >= 0.5 ? 'red' : item.risk >= 0.28 ? 'amber' : 'cyan'}
          />
          <p className="muted mt-1">
            {formatNumber(item.flows || 0)} flows · mean risk {formatPercent(item.risk || 0, 1)}
          </p>
        </li>
      ))}
    </ul>
  )
}
