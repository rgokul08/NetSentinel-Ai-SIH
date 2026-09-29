import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Beaker,
  Bolt,
  CircleSlash,
  Clock,
  FlaskConical,
  Gauge,
  Info,
  Layers,
  Pause,
  Play,
  Radar,
  RefreshCw,
  Save,
  ShieldAlert,
  Square,
  Timer,
  TrendingUp,
  Zap,
} from 'lucide-react'
import { simulationApi } from '../services/endpoints'
import { useAction, usePoll } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useRealtime } from '../context/RealtimeContext'
import { useToast } from '../context/ToastContext'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  DataTable,
  EmptyState,
  ErrorState,
  Field,
  Input,
  KeyValue,
  LoadingState,
  Progress,
  Select,
  StatCard,
  StatusBadge,
} from '../components/ui'
import { TimeSeriesChart } from '../components/charts/charts'
import { formatDateTime, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { ATTACK_TYPES } from '../utils/constants'
import { attackColor } from '../utils/theme'

const MAX_TICKS = 90

export default function Simulation() {
  const { can } = useAuth()
  const toast = useToast()
  const { subscribe, status: wsStatus, pausedByPreference } = useRealtime()
  const [ticks, setTicks] = useState([])
  const [form, setForm] = useState({ scenario: 'mixed', intensity: 5, duration_seconds: 600, tick_seconds: 1 })
  const [inject, setInject] = useState({ attack_type: 'DDoS', count: 12, create_alerts: true })

  const status = usePoll(() => simulationApi.status(), 2000, { keepPrevious: true })
  const scenarios = usePoll(() => simulationApi.scenarios(), 120000, { keepPrevious: true })

  const state = status.data || {}
  const running = state.status === 'running'
  const paused = state.status === 'paused'
  const canControl = can('simulation.control')

  // Adopt server-side state into the control form whenever it is idle.
  useEffect(() => {
    if (!state || running || paused) return
    setForm((current) => ({
      scenario: state.scenario || current.scenario,
      intensity: state.intensity ?? current.intensity,
      duration_seconds: state.duration_seconds ?? current.duration_seconds,
      tick_seconds: state.tick_seconds ?? current.tick_seconds,
    }))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.status])

  useEffect(() => {
    const unsubscribe = subscribe('simulation_tick', (message) => {
      setTicks((current) => [
        {
          id: `${message.timestamp}-${current.length}`,
          timestamp: message.timestamp,
          flows: message.flows,
          attacks: message.attacks,
          anomalies: message.anomalies,
          alerts_created: message.alerts_created,
          mean_risk_score: message.mean_risk_score,
          max_risk_score: message.max_risk_score,
          engine: message.engine,
          class_distribution: message.class_distribution || {},
        },
        ...current,
      ].slice(0, MAX_TICKS))
    })
    const unsubscribeStop = subscribe('simulation_stopped', () => {
      status.refetch()
    })
    return () => {
      unsubscribe?.()
      unsubscribeStop?.()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscribe])

  const start = useAction(
    async () => {
      const result = await simulationApi.start({
        scenario: form.scenario,
        intensity: Number(form.intensity),
        duration_seconds: Number(form.duration_seconds),
        tick_seconds: Number(form.tick_seconds),
      })
      setTicks([])
      toast.success('Simulation started', `${result?.scenario_label || form.scenario} · intensity ${form.intensity} · ${form.duration_seconds}s`)
      status.refetch()
      return result
    },
    { onError: (failure) => toast.error('Could not start the simulation', failure.message) },
  )

  const pause = useAction(async () => { const result = await simulationApi.pause(); status.refetch(); toast.info('Simulation paused', 'Generation is frozen; resume to continue the same run.'); return result },
    { onError: (failure) => toast.error('Pause failed', failure.message) })

  const resume = useAction(async () => { const result = await simulationApi.resume(); status.refetch(); toast.success('Simulation resumed', 'Ticks continue from where they stopped.'); return result },
    { onError: (failure) => toast.error('Resume failed', failure.message) })

  const stop = useAction(async () => { const result = await simulationApi.stop(); status.refetch(); toast.info('Simulation stopped', `${formatNumber(state.generated_flows)} synthetic flows were generated during this run.`); return result },
    { onError: (failure) => toast.error('Stop failed', failure.message) })

  const saveDefaults = useAction(
    async () => {
      const result = await simulationApi.update({
        scenario: form.scenario,
        intensity: Number(form.intensity),
        duration_seconds: Number(form.duration_seconds),
      })
      toast.success('Defaults saved', 'These values are used for the next simulation run.')
      return result
    },
    { onError: (failure) => toast.error('Could not save defaults', failure.message) },
  )

  const injectAttack = useAction(
    async () => {
      const result = await simulationApi.inject({
        attack_type: inject.attack_type,
        count: Number(inject.count),
        create_alerts: inject.create_alerts,
      })
      const summary = result?.summary || {}
      toast.success(
        'Attack injected',
        `${formatNumber(summary.rows ?? result?.persisted ?? result?.predictions?.length ?? 0)} synthetic ${inject.attack_type} flows pushed through the live pipeline` +
          ` · ${formatNumber(summary.attacks_detected ?? 0)} detected · ${formatNumber(result?.alerts_created ?? 0)} alerts.`,
      )
      status.refetch()
      return result
    },
    { onError: (failure) => toast.error('Injection failed', failure.message) },
  )

  const chartData = useMemo(
    () =>
      [...ticks]
        .reverse()
        .map((tick) => ({ time: new Date(tick.timestamp).getTime(), flows: tick.flows, attacks: tick.attacks, anomalies: tick.anomalies, alerts: tick.alerts_created })),
    [ticks],
  )

  const totals = useMemo(
    () =>
      ticks.reduce(
        (accumulator, tick) => ({
          flows: accumulator.flows + Number(tick.flows || 0),
          attacks: accumulator.attacks + Number(tick.attacks || 0),
          anomalies: accumulator.anomalies + Number(tick.anomalies || 0),
          alerts: accumulator.alerts + Number(tick.alerts_created || 0),
        }),
        { flows: 0, attacks: 0, anomalies: 0, alerts: 0 },
      ),
    [ticks],
  )

  const activeScenario = (scenarios.data?.items || []).find((item) => item.key === state.scenario) || (scenarios.data?.items || [])[0]

  return (
    <div className="space-y-4">
      {/* Simulation mode banner - synthetic data must never look like real traffic */}
      <div className="flex flex-wrap items-start gap-3 rounded-2xl border border-amber-500/40 bg-amber-500/10 p-3.5">
        <Beaker size={18} className="mt-0.5 shrink-0 text-amber-300" />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-black uppercase tracking-[0.14em] text-amber-300">Simulation mode — synthetic traffic</p>
          <p className="muted mt-1 max-w-4xl">
            {scenarios.data?.label || 'Simulation Mode - synthetic traffic generated for demonstration and defensive training.'}
            Every record produced here is written with <span className="mono text-amber-200">is_simulated = true</span> and is labelled in the UI,
            in exports and in reports. Source addresses are synthetic and region labels are abstracted — they are not real geolocation.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={running ? 'online' : paused ? 'degraded' : 'offline'} label={state.status || 'unknown'} />
          <Badge tone={wsStatus === 'open' ? 'green' : pausedByPreference ? 'slate' : 'amber'}>
            <Activity size={9} /> live feed {wsStatus === 'open' ? 'connected' : pausedByPreference ? 'paused by preference' : wsStatus}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Elapsed / remaining"
          value={`${Math.round(state.elapsed_seconds || 0)}s`}
          unit={`/ ${Math.round(state.remaining_seconds ?? state.duration_seconds ?? 0)}s left`}
          icon={Timer}
          tone={running ? 'cyan' : 'slate'}
          loading={status.loading && !status.data}
          hint={state.ends_at ? `ends ${formatDateTime(state.ends_at)}` : 'not running'}
        />
        <StatCard label="Synthetic flows" value={formatNumber(state.generated_flows || 0)} icon={Layers} tone="green" hint={`${formatNumber(state.analyzed_flows || 0)} analyzed`} />
        <StatCard label="Attacks generated" value={formatNumber(state.attacks_generated || 0)} icon={ShieldAlert} tone="red" hint={`${formatNumber(state.anomalies_generated || 0)} anomalies flagged`} />
        <StatCard label="Alerts created" value={formatNumber(state.alerts_created || 0)} icon={AlertTriangle} tone="amber" hint={`${Number(state.flows_per_second || 0).toFixed(1)} flows/sec`} />
      </div>

      {state.status ? (
        <Card
          title="Run progress"
          subtitle={`${state.scenario_label || state.scenario} · intensity ${state.intensity} · ${state.tick_seconds}s tick`}
          icon={Gauge}
          actions={
            <div className="flex items-center gap-2">
              {state.last_tick_at ? <span className="muted">last tick {timeAgo(state.last_tick_at)}</span> : null}
              <Button size="sm" variant="ghost" icon={RefreshCw} onClick={status.refetch} loading={status.loading}>Refresh</Button>
            </div>
          }
        >
          <Progress value={Number(state.progress || 0) * 100} max={100} tone={running ? 'cyan' : paused ? 'amber' : 'slate'} showLabel label={`${formatPercent(state.progress || 0, 0)} complete`} />
          <KeyValue
            className="mt-3"
            columns={4}
            items={[
              { label: 'Started', value: state.started_at ? formatDateTime(state.started_at) : '—', mono: true },
              { label: 'Duration', value: `${state.duration_seconds ?? '—'} s`, mono: true },
              { label: 'Scenario', value: state.scenario_label || state.scenario || '—' },
              { label: 'Paused at', value: state.paused_at ? formatDateTime(state.paused_at) : 'not paused', mono: true },
            ]}
          />
          {state.last_error ? (
            <p className="mt-2 rounded-lg border border-rose-500/30 bg-rose-500/8 px-3 py-2 text-[11px] text-rose-200">
              Last worker error: {state.last_error}
            </p>
          ) : null}
          {state.scenario_description ? <p className="muted mt-2">{state.scenario_description}</p> : null}
        </Card>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
        <Card title="Run controls" subtitle="Start, pause and stop the synthetic traffic generator" icon={Play}>
          {canControl ? (
            <div className="space-y-3">
              <Select
                label="Scenario"
                value={form.scenario}
                onChange={(event) => setForm({ ...form, scenario: event.target.value })}
                options={(scenarios.data?.items || []).map((item) => ({ value: item.key, label: item.label }))}
                hint={activeScenario?.description}
              />
              <div className="grid gap-3 sm:grid-cols-3">
                <Field label={`Intensity · ${form.intensity}`} hint={`≈ ${Math.round(Number(form.intensity) * 6)} flows per tick (1 – 10)`}>
                  <input
                    type="range"
                    min={1}
                    max={10}
                    step={1}
                    value={form.intensity}
                    onChange={(event) => setForm({ ...form, intensity: event.target.value })}
                    className="w-full accent-cyan-500"
                  />
                </Field>
                <Input
                  label="Duration (seconds)"
                  type="number"
                  min={30}
                  max={7200}
                  value={form.duration_seconds}
                  onChange={(event) => setForm({ ...form, duration_seconds: event.target.value })}
                  hint="30 – 7200"
                />
                <Input
                  label="Tick interval (seconds)"
                  type="number"
                  min={0.25}
                  max={5}
                  step={0.25}
                  value={form.tick_seconds}
                  onChange={(event) => setForm({ ...form, tick_seconds: event.target.value })}
                  hint="0.25 – 5"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {!running && !paused ? (
                  <Button variant="primary" icon={Play} loading={start.busy} onClick={start.run}>Start simulation</Button>
                ) : null}
                {running ? <Button variant="secondary" icon={Pause} loading={pause.busy} onClick={pause.run}>Pause</Button> : null}
                {paused ? <Button variant="primary" icon={Play} loading={resume.busy} onClick={resume.run}>Resume</Button> : null}
                {running || paused ? <Button variant="danger" icon={Square} loading={stop.busy} onClick={stop.run}>Stop &amp; finalize</Button> : null}
                <Button variant="ghost" icon={Save} loading={saveDefaults.busy} onClick={saveDefaults.run}>Save as defaults</Button>
              </div>

              {start.error ? <ErrorState error={start.error} compact /> : null}
              {state.is_simulated === false ? (
                <p className="muted flex items-start gap-1.5">
                  <Info size={11} className="mt-0.5 shrink-0" />
                  The backend reports <span className="mono">is_simulated = false</span> for this run state, which means no synthetic run is active.
                </p>
              ) : null}
            </div>
          ) : (
            <EmptyState
              icon={Play}
              title="Read-only access"
              message="Your role can watch the simulation feed but cannot start, pause or inject traffic. Ask an analyst or administrator."
            />
          )}
        </Card>

        <Card title="Inject a single attack" subtitle="One-shot synthetic burst pushed through the live detection pipeline" icon={Zap}>
          {canControl ? (
            <div className="space-y-3">
              <Select
                label="Attack type"
                value={inject.attack_type}
                onChange={(event) => setInject({ ...inject, attack_type: event.target.value })}
                options={ATTACK_TYPES.map((type) => ({ value: type, label: type }))}
              />
              <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
                <Input
                  label="Flow count"
                  type="number"
                  min={1}
                  max={200}
                  value={inject.count}
                  onChange={(event) => setInject({ ...inject, count: event.target.value })}
                  hint="1 – 200 flows"
                />
                <Button variant="secondary" icon={Bolt} loading={injectAttack.busy} onClick={injectAttack.run}>Inject</Button>
              </div>
              <Checkbox
                checked={inject.create_alerts}
                onChange={(value) => setInject({ ...inject, create_alerts: value })}
                label="Create alerts (subject to normal throttling)"
              />
              {injectAttack.error ? <ErrorState error={injectAttack.error} compact /> : null}
              {injectAttack.result ? (
                <KeyValue
                  columns={2}
                  items={[
                    { label: 'Flows generated', value: formatNumber(injectAttack.result.summary?.rows ?? injectAttack.result.persisted ?? 0), mono: true },
                    { label: 'Detected as attacks', value: formatNumber(injectAttack.result.summary?.attacks_detected ?? 0), mono: true },
                    { label: 'Anomalies flagged', value: formatNumber(injectAttack.result.summary?.anomalies ?? 0), mono: true },
                    { label: 'Alerts created', value: formatNumber(injectAttack.result.alerts_created ?? 0), mono: true },
                    { label: 'Suppressed by throttle', value: formatNumber(injectAttack.result.alerts_suppressed ?? 0), mono: true },
                    { label: 'Mean risk score', value: formatPercent(injectAttack.result.summary?.mean_risk_score ?? 0, 1), mono: true },
                    { label: 'Model', value: injectAttack.result.model?.model_name || '—' },
                    { label: 'Engine', value: String(injectAttack.result.summary?.engine ?? '—'), mono: true },
                  ]}
                />
              ) : null}
              <p className="muted flex items-start gap-1.5">
                <Info size={11} className="mt-0.5 shrink-0" />
                Injection works while the generator is stopped, so you can demonstrate a single deterministic attack without a full run.
              </p>
            </div>
          ) : (
            <EmptyState icon={Zap} title="Not permitted" message="Only analysts and administrators can inject synthetic attacks." />
          )}
        </Card>
      </div>

      <Card
        title="Live tick telemetry"
        subtitle="Frames streamed over the WebSocket as each synthetic batch is analyzed"
        icon={Radar}
        actions={
          <div className="flex items-center gap-2">
            <Badge tone="slate">{ticks.length} frames buffered</Badge>
            <Button size="sm" variant="ghost" icon={CircleSlash} onClick={() => setTicks([])} disabled={!ticks.length}>Clear</Button>
          </div>
        }
      >
        {wsStatus !== 'open' ? (
          <p className="muted mb-3 flex items-center gap-1.5 rounded-lg border border-amber-500/25 bg-amber-500/8 px-3 py-2">
            <AlertTriangle size={12} className="text-amber-300" />
            The live feed is <span className="mono">{wsStatus}</span>
            {pausedByPreference ? ' because live updates are disabled in your interface preferences (Settings page).' : ' — tick frames appear here once it reconnects.'}
          </p>
        ) : null}

        <TimeSeriesChart
          data={chartData}
          series={[
            { key: 'flows', label: 'Flows generated', color: '#22d3ee' },
            { key: 'attacks', label: 'Attacks detected', color: '#fb7185' },
            { key: 'anomalies', label: 'Anomalies', color: '#a855f7' },
            { key: 'alerts', label: 'Alerts', color: '#fbbf24' },
          ]}
          height={220}
          emptyMessage={running ? 'Waiting for the first tick…' : 'Start a simulation to stream tick telemetry'}
        />

        <div className="mt-3 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          {[
            { label: 'Flows this session', value: formatNumber(totals.flows), icon: Layers },
            { label: 'Attacks detected', value: formatNumber(totals.attacks), icon: ShieldAlert },
            { label: 'Anomalies flagged', value: formatNumber(totals.anomalies), icon: Activity },
            { label: 'Alerts raised', value: formatNumber(totals.alerts), icon: AlertTriangle },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
              <item.icon size={14} className="text-cyan-400" />
              <div>
                <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{item.label}</p>
                <p className="mono text-sm font-bold text-slate-100">{item.value}</p>
              </div>
            </div>
          ))}
        </div>

        <DataTable
          className="mt-3"
          columns={[
            { key: 'timestamp', header: 'Tick', width: '132px', render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.timestamp)}>{timeAgo(row.timestamp)}</span> },
            { key: 'flows', header: 'Flows', width: '80px', align: 'right', render: (row) => <span className="mono">{formatNumber(row.flows)}</span> },
            { key: 'attacks', header: 'Attacks', width: '84px', align: 'right', render: (row) => <span className="mono text-rose-300">{formatNumber(row.attacks)}</span> },
            { key: 'anomalies', header: 'Anomalies', width: '92px', align: 'right', render: (row) => <span className="mono text-purple-300">{formatNumber(row.anomalies)}</span> },
            { key: 'alerts_created', header: 'Alerts', width: '80px', align: 'right', render: (row) => <span className="mono text-amber-300">{formatNumber(row.alerts_created)}</span> },
            { key: 'mean_risk_score', header: 'Mean risk', width: '104px', align: 'right', render: (row) => <span className="mono">{formatPercent(row.mean_risk_score, 1)}</span> },
            { key: 'max_risk_score', header: 'Max risk', width: '96px', align: 'right', render: (row) => <span className="mono">{formatPercent(row.max_risk_score, 1)}</span> },
            { key: 'engine', header: 'Engine', width: '86px', render: (row) => <Badge tone={row.engine === 'ml' ? 'green' : 'amber'}>{row.engine || '—'}</Badge> },
            { key: 'class_distribution', header: 'Classes in this tick', render: (row) => (
              <span className="flex flex-wrap gap-1">
                {Object.entries(row.class_distribution || {})
                  .filter(([name]) => name !== 'Benign')
                  .slice(0, 5)
                  .map(([name, value]) => (
                    <span key={name} className="badge" style={{ borderColor: `${attackColor(name)}55`, background: `${attackColor(name)}14`, color: attackColor(name) }}>
                      {name} ×{value}
                    </span>
                  ))}
                {!Object.keys(row.class_distribution || {}).filter((name) => name !== 'Benign').length ? (
                  <span className="muted">benign only</span>
                ) : null}
              </span>
            ) },
          ]}
          rows={ticks}
          rowKey={(row) => row.id}
          maxHeight={300}
          empty={
            <EmptyState
              icon={FlaskConical}
              title="No ticks received yet"
              message={running ? 'Ticks appear here as the generator produces synthetic batches.' : 'Start a run to stream tick telemetry over the WebSocket.'}
            />
          }
        />
      </Card>

      <Card title="Scenario catalogue" subtitle="Attack mixes generated at each phase of a run" icon={TrendingUp}>
        {scenarios.loading && !scenarios.data ? (
          <LoadingState label="Loading scenarios…" />
        ) : scenarios.error ? (
          <ErrorState error={scenarios.error} onRetry={scenarios.refetch} compact />
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {(scenarios.data?.items || []).map((scenario) => (
              <div
                key={scenario.key}
                className={`rounded-xl border p-3 ${scenario.key === state.scenario ? 'border-cyan-500/45 bg-cyan-500/6' : 'border-slate-800 bg-slate-950/40'}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-[11.5px] font-semibold text-slate-100">{scenario.label}</p>
                  <div className="flex items-center gap-1.5">
                    <code className="mono rounded border border-slate-700/70 bg-slate-900/70 px-1.5 py-0.5 text-[10px] text-slate-400">{scenario.key}</code>
                    {scenario.key === state.scenario ? <Badge tone="cyan">current</Badge> : null}
                    {canControl ? (
                      <Button
                        size="xs"
                        variant={scenario.key === state.scenario && running ? 'ghost' : 'secondary'}
                        icon={Play}
                        loading={start.busy}
                        onClick={() => {
                          setForm((current) => ({ ...current, scenario: scenario.key }))
                          simulationApi
                            .start({ scenario: scenario.key, intensity: Number(form.intensity), duration_seconds: Number(form.duration_seconds), tick_seconds: Number(form.tick_seconds) })
                            .then(() => { setTicks([]); status.refetch(); toast.success('Simulation started', scenario.label) })
                            .catch((failure) => toast.error('Could not start', failure.message))
                        }}
                      >
                        Run
                      </Button>
                    ) : null}
                  </div>
                </div>
                <p className="muted mt-1">{scenario.description}</p>

                <div className="mt-2.5 space-y-1.5">
                  {(scenario.phases || []).map((phase, index) => {
                    const entries = Object.entries(phase.mix || {})
                    const attackShare = entries.filter(([name]) => name !== 'Benign').reduce((sum, [, value]) => sum + Number(value), 0)
                    return (
                      <div key={index} className="flex items-center gap-2">
                        <span className="mono w-14 shrink-0 text-[9.5px] text-slate-500">
                          {index === 0 ? '0%' : `${Math.round((scenario.phases[index - 1].until || 0) * 100)}%`}–{Math.round((phase.until || 1) * 100)}%
                        </span>
                        <span className="flex h-3 flex-1 overflow-hidden rounded">
                          {entries.map(([name, share]) => (
                            <span
                              key={name}
                              title={`${name}: ${formatPercent(share, 0)}`}
                              style={{
                                width: `${Number(share) * 100}%`,
                                background: name === 'Benign' ? 'rgba(52,211,153,0.35)' : attackColor(name),
                              }}
                            />
                          ))}
                        </span>
                        <span className="mono w-20 shrink-0 text-right text-[9.5px] text-rose-300">{formatPercent(attackShare, 0)} attack</span>
                      </div>
                    )
                  })}
                </div>

                <div className="mt-2 flex flex-wrap gap-1">
                  {[...new Set((scenario.phases || []).flatMap((phase) => Object.keys(phase.mix || {})))]
                    .filter((name) => name !== 'Benign')
                    .map((name) => (
                      <span key={name} className="badge" style={{ borderColor: `${attackColor(name)}55`, background: `${attackColor(name)}14`, color: attackColor(name) }}>
                        {name}
                      </span>
                    ))}
                </div>
              </div>
            ))}
          </div>
        )}
        <p className="muted mt-3 flex items-start gap-1.5">
          <Clock size={11} className="mt-0.5 shrink-0" />
          Phase percentages show how far through the run duration the mix applies. Green is benign baseline traffic; coloured segments are synthetic attacks.
        </p>
      </Card>
    </div>
  )
}
