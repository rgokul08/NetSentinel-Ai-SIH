import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ArrowUpRight,
  Database,
  Filter,
  Gauge,
  Layers,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Waves,
} from 'lucide-react'
import { trafficApi, predictApi } from '../services/endpoints'
import { useApi } from '../hooks/useApi'
import { useRealtime } from '../context/RealtimeContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  DataTable,
  Drawer,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Progress,
  SearchInput,
  Select,
  StatCard,
  StatusBadge,
} from '../components/ui'
import { CategoryBarChart, DonutChart, TimeSeriesChart } from '../components/charts/charts'
import { compactNumber, formatBytes, formatDateTime, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { attackColor, riskColor } from '../utils/theme'
import { WINDOWS } from '../utils/constants'
import { usePreferences } from '../hooks/usePreferences'

const WINDOW_OPTIONS = WINDOWS.filter((item) => ['5m', '15m', '1h', '6h', '24h', '7d'].includes(item.value))

export default function Traffic() {
  const { connected, metrics, events } = useRealtime()
  const { prefs } = usePreferences()
  const [timeWindow, setTimeWindow] = useState(() => prefs.defaultWindow || '24h')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [search, setSearch] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('')
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [selected, setSelected] = useState(null)

  const live = useApi(() => trafficApi.live({ window: timeWindow }), [timeWindow], { keepPrevious: true })
  const records = useApi(
    () =>
      trafficApi.records({
        limit: page.limit,
        offset: page.offset,
        window: timeWindow,
        search: search || undefined,
        attack_type: verdictFilter || undefined,
      }),
    [timeWindow, page.limit, page.offset, search, verdictFilter],
    { keepPrevious: true },
  )

  /** Poll while auto-refresh is on; the websocket keeps the KPI strip live in between. */
  useEffect(() => {
    if (!autoRefresh) return undefined
    const timer = setInterval(() => {
      live.refetch()
      if (page.offset === 0) records.refetch()
    }, 8000)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoRefresh, timeWindow, page.offset])

  const snapshot = live.data || {}
  const latestMetric = metrics.length ? metrics[metrics.length - 1] : null
  const timeline = useMemo(
    () =>
      (snapshot.timeline || []).map((point) => ({
        time: point.time,
        packets: point.packets,
        flows: point.flows,
        megabits_per_second: point.megabits_per_second,
        anomalies: point.anomalies,
        mean_risk: Number(point.mean_risk || 0) * 100,
      })),
    [snapshot.timeline],
  )

  const rows = records.data?.items || []

  return (
    <div className="space-y-4">
      {/* control strip */}
      <div className="card flex flex-wrap items-center gap-2 p-3">
        <Select
          className="w-auto min-w-[168px]"
          value={timeWindow}
          onChange={(event) => {
            setTimeWindow(event.target.value)
            setPage({ limit: page.limit, offset: 0, page: 1 })
          }}
          options={WINDOW_OPTIONS}
          aria-label="Time window"
        />
        <Button size="sm" variant={autoRefresh ? 'primary' : 'secondary'} icon={autoRefresh ? Pause : Play} onClick={() => setAutoRefresh((v) => !v)}>
          {autoRefresh ? 'Auto-refresh on' : 'Auto-refresh off'}
        </Button>
        <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => { live.refetch(); records.refetch() }} loading={live.loading}>
          Refresh now
        </Button>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <span className={`badge ${connected ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' : 'border-slate-700 bg-slate-800/60 text-slate-400'}`}>
            <Radio size={9} className={connected ? 'animate-pulse' : ''} />
            {connected ? 'websocket live' : 'polling only'}
          </span>
          {snapshot.data_origin ? (
            <Badge tone={snapshot.data_origin === 'simulation' ? 'purple' : 'green'}>
              <Database size={9} /> {snapshot.data_origin}
            </Badge>
          ) : null}
          <span className="muted">
            {snapshot.generated_at ? `snapshot ${timeAgo(snapshot.generated_at)}` : ''} · bucket {snapshot.bucket}
          </span>
        </div>
      </div>

      {live.error && !snapshot.flows ? <ErrorState error={live.error} onRetry={live.refetch} /> : null}

      {snapshot.simulation?.status === 'running' ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-purple-500/30 bg-purple-500/8 px-3.5 py-2 text-[11px] text-purple-200">
          <Radio size={12} className="animate-pulse" />
          <span className="font-semibold uppercase tracking-wide">{snapshot.simulation.label || 'Simulation Mode'}</span>
          <span className="opacity-90">
            {snapshot.simulation.scenario_label} · {formatNumber(snapshot.simulation.generated_flows)} synthetic flows ·{' '}
            {Number(snapshot.simulation.flows_per_second || 0).toFixed(1)} flows/s
          </span>
          <Progress className="min-w-[120px] flex-1" value={Number(snapshot.simulation.progress || 0) * 100} max={100} tone="purple" />
        </div>
      ) : null}

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Flows in window" value={formatNumber(snapshot.flows ?? 0)} icon={Network} tone="cyan" loading={live.loading && !snapshot.flows} hint={`${formatNumber(snapshot.packets)} packets · ${formatBytes(snapshot.bytes)}`} />
        <StatCard label="Packet rate" value={Number(snapshot.packets_per_second ?? 0).toFixed(1)} unit="pps" icon={Waves} tone="green" hint={`${formatBytes(snapshot.bytes_per_second)}/s · ${Number(snapshot.mbps ?? 0).toFixed(3)} Mbps`} />
        <StatCard label="Attacks detected" value={formatNumber(snapshot.attacks ?? 0)} icon={ShieldAlert} tone="red" hint={`${formatNumber(snapshot.anomalies ?? 0)} anomalies flagged`} />
        <StatCard label="Abnormal traffic" value={`${Number(snapshot.abnormal_percentage ?? 0).toFixed(1)}%`} icon={Activity} tone="amber" hint={`mean risk ${formatPercent(snapshot.mean_risk_score ?? 0, 1)} · peak ${formatPercent(snapshot.max_risk_score ?? 0, 1)}`} />
        <StatCard label="Unique sources" value={formatNumber(snapshot.unique_sources ?? 0)} icon={Server} tone="purple" hint={`${formatNumber(snapshot.unique_destinations ?? 0)} destinations`} />
        <StatCard
          label="Threat level"
          value={String(snapshot.threat_level || 'unknown').toUpperCase()}
          icon={Gauge}
          tone={riskColor(snapshot.threat_level) === '#fb7185' ? 'red' : 'slate'}
          hint={`current risk ${formatPercent(snapshot.current_risk_score ?? 0, 1)} · ${formatNumber(snapshot.connection_count ?? 0)} connections`}
        />
      </div>

      {/* realtime metric ticker */}
      {latestMetric ? (
        <div className="card flex flex-wrap items-center gap-x-5 gap-y-1 px-3.5 py-2 text-[11px]">
          <span className="panel-title flex items-center gap-1.5">
            <Radio size={11} className="animate-pulse text-emerald-400" /> live push
          </span>
          <span className="mono text-slate-300">flows {formatNumber(latestMetric.flows ?? 0)}</span>
          <span className="mono text-slate-300">pps {Number(latestMetric.packets_per_second ?? 0).toFixed(1)}</span>
          <span className="mono text-slate-300">attacks {formatNumber(latestMetric.attacks ?? 0)}</span>
          <span className="mono text-slate-300">anomalies {formatNumber(latestMetric.anomalies ?? 0)}</span>
          <span className="mono text-slate-500">{latestMetric.threat_level}</span>
          <span className="muted ml-auto">{timeAgo(latestMetric.generated_at || new Date().toISOString())}</span>
        </div>
      ) : null}

      {/* charts */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Throughput timeline" subtitle={`Bucketed every ${snapshot.bucket || 'interval'} across the ${timeWindow} window`} icon={Activity}>
          <TimeSeriesChart
            data={timeline}
            series={[
              { key: 'packets', label: 'Packets', color: '#38bdf8' },
              { key: 'flows', label: 'Flows', color: '#22d3ee', opacity: 0.22 },
              { key: 'anomalies', label: 'Anomalies', color: '#a855f7', opacity: 0.3 },
            ]}
            height={240}
            emptyMessage="No traffic in this window. Start the simulation or upload a dataset."
          />
        </Card>
        <Card title="Protocol mix" subtitle="Share of analysed flows" icon={Layers}>
          <DonutChart data={snapshot.protocol_distribution || []} height={240} centerValue={formatNumber(snapshot.flows ?? 0)} centerLabel="flows" emptyMessage="No protocol data yet." />
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Verdict distribution" icon={ShieldAlert}>
          <CategoryBarChart
            data={snapshot.attack_distribution || []}
            height={210}
            colorBy={(entry) => attackColor(entry.name)}
            emptyMessage="No verdicts recorded yet."
          />
        </Card>
        <Card title="TCP flag profile" subtitle="Connection behaviour across flows" icon={Filter}>
          <CategoryBarChart data={(snapshot.flag_distribution || []).slice(0, 8)} height={210} horizontal emptyMessage="No flag data yet." />
        </Card>
        <Card title="Top talkers" subtitle="Sources by packet volume" icon={Server} dense bodyClass="p-0">
          {(snapshot.top_sources || []).length === 0 ? (
            <EmptyState title="No sources yet" message="Traffic records will appear here once flows are analysed." />
          ) : (
            <ul className="divide-y divide-slate-800/60">
              {(snapshot.top_sources || []).slice(0, 6).map((source) => (
                <li key={source.ip} className="px-4 py-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono truncate text-[11px] text-slate-200">{source.ip}</span>
                    <span className="mono shrink-0 text-[10.5px] text-slate-400">{compactNumber(source.packets)} pkts</span>
                  </div>
                  <p className="muted mt-0.5">
                    {source.region || 'unmapped region'} · masked as {source.masked}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {/* flow records */}
      <Card
        title="Analysed flow records"
        subtitle={`${formatNumber(records.data?.pagination?.total ?? 0)} records stored by the backend in this window`}
        icon={Database}
        bodyClass="p-0"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={(value) => { setSearch(value); setPage({ ...page, offset: 0, page: 1 }) }} placeholder="Search IP, port, protocol…" className="w-52" />
            <Select
              className="w-auto min-w-[140px] py-1.5 text-[11px]"
              value={verdictFilter}
              placeholder="All verdicts"
              onChange={(event) => { setVerdictFilter(event.target.value); setPage({ ...page, offset: 0, page: 1 }) }}
              options={(snapshot.attack_distribution || []).map((item) => item.name)}
            />
          </div>
        }
      >
        <DataTable
          columns={[
            {
              key: 'timestamp',
              header: 'Time',
              width: '150px',
              sortable: true,
              render: (row) => <span className="mono text-[10.5px] text-slate-400">{formatDateTime(row.timestamp)}</span>,
            },
            {
              key: 'source_ip',
              header: 'Source → Destination',
              render: (row) => (
                <span className="mono flex items-center gap-1 text-[11px] text-slate-200">
                  {row.source_ip || '—'}
                  <ArrowUpRight size={9} className="text-slate-600" />
                  {row.destination_ip || '—'}
                  <span className="text-slate-500">:{row.destination_port ?? '—'}</span>
                </span>
              ),
            },
            { key: 'protocol', header: 'Proto', width: '76px' },
            { key: 'packet_count', header: 'Packets', width: '92px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatNumber(row.packet_count)}</span> },
            { key: 'byte_count', header: 'Bytes', width: '92px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatBytes(row.byte_count, 0)}</span> },
            {
              key: 'predicted_attack_type',
              header: 'Verdict',
              width: '140px',
              render: (row) => (
                <span className="flex items-center gap-1.5">
                  <AttackBadge type={row.predicted_attack_type || row.attack_type} />
                  {row.is_labeled && row.attack_type && row.attack_type !== row.predicted_attack_type ? (
                    <Badge tone="amber" >misclassified</Badge>
                  ) : null}
                </span>
              ),
            },
            {
              key: 'risk_score',
              header: 'Risk',
              width: '120px',
              align: 'right',
              sortable: true,
              render: (row) => (
                <span className="flex items-center justify-end gap-2">
                  <Progress className="w-12" value={Number(row.risk_score) * 100} max={100} tone={Number(row.risk_score) >= 0.5 ? 'red' : Number(row.risk_score) >= 0.28 ? 'amber' : 'cyan'} />
                  <span className="mono text-[10.5px] text-slate-300">{formatPercent(row.risk_score, 0)}</span>
                </span>
              ),
            },
            { key: 'is_anomaly', header: 'Anomaly', width: '78px', align: 'center', render: (row) => (row.is_anomaly ? <Badge tone="purple">yes</Badge> : <span className="text-slate-600">—</span>) },
            { key: 'is_simulated', header: 'Origin', width: '92px', render: (row) => (row.is_simulated ? <Badge tone="purple">simulated</Badge> : <Badge tone="green">{row.source || 'dataset'}</Badge>) },
          ]}
          rows={rows}
          loading={records.loading}
          error={records.error}
          onRetry={records.refetch}
          pagination={records.data?.pagination}
          onPageChange={(next) => setPage(next)}
          onRowClick={setSelected}
          selectedId={selected?.id}
          empty={
            <EmptyState
              icon={Search}
              title="No flow records match this view"
              message="Widen the time window, clear the filters, or generate traffic from the simulation console."
            />
          }
        />
      </Card>

      <FlowDrawer record={selected} onClose={() => setSelected(null)} />

      {/* websocket event log */}
      <Card title="Live stream events" subtitle="Messages pushed over the websocket while this page is open" icon={Radio} dense bodyClass="p-0">
        {events.length === 0 ? (
          <p className="muted px-4 py-4">
            No push messages yet. Start the simulation console and new predictions, alerts and metrics will stream here in real time.
          </p>
        ) : (
          <ul className="max-h-64 divide-y divide-slate-800/60 overflow-y-auto">
            {events.slice(0, 40).map((event, index) => (
              <li key={`${event.received_at}-${index}`} className="flex items-center gap-2 px-4 py-1.5">
                <Badge tone={event.type === 'alert' ? 'red' : event.type === 'forecast' ? 'cyan' : 'slate'}>{event.type}</Badge>
                <span className="mono min-w-0 flex-1 truncate text-[10.5px] text-slate-400">
                  {event.attack_type || event.scenario || event.title || event.source_ip || JSON.stringify(event).slice(0, 90)}
                </span>
                <span className="muted shrink-0">{timeAgo(event.received_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  )
}

/** Record detail with the model verdict, probabilities and XAI attribution. */
function FlowDrawer({ record, onClose }) {
  const [prediction, setPrediction] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    setPrediction(null)
    setError(null)
    if (!record?.prediction_id) return undefined
    setLoading(true)
    predictApi
      .prediction(record.prediction_id)
      .then((result) => {
        if (!cancelled) setPrediction(result)
      })
      .catch((failure) => {
        if (!cancelled) setError(failure)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [record?.prediction_id])

  const probabilities = prediction?.probabilities || {}
  const contributions = prediction?.explanation?.contributions || []

  return (
    <Drawer
      open={Boolean(record)}
      onClose={onClose}
      title={record ? `Flow ${record.source_ip} → ${record.destination_ip}` : ''}
      subtitle={record ? `${formatDateTime(record.timestamp)} · ${record.protocol} · record ${record.id}` : ''}
    >
      {!record ? null : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <AttackBadge type={record.predicted_attack_type || record.attack_type} />
            <StatusBadge status={String(record.risk_level || '').toLowerCase()} />
            {record.is_anomaly ? <Badge tone="purple">anomaly</Badge> : null}
            {record.is_simulated ? <Badge tone="purple">simulation data</Badge> : <Badge tone="green">{record.source || 'dataset'}</Badge>}
            {record.is_labeled ? <Badge tone="slate">ground truth: {record.attack_type}</Badge> : null}
          </div>

          <KeyValue
            columns={2}
            items={[
              { label: 'Source', value: `${record.source_ip || '—'}:${record.source_port ?? '—'}`, mono: true },
              { label: 'Destination', value: `${record.destination_ip || '—'}:${record.destination_port ?? '—'}`, mono: true },
              { label: 'Protocol', value: record.protocol },
              { label: 'TCP flags', value: record.tcp_flags || '—', mono: true },
              { label: 'Packets', value: formatNumber(record.packet_count), mono: true },
              { label: 'Bytes', value: formatBytes(record.byte_count), mono: true },
              { label: 'Duration', value: `${Number(record.flow_duration ?? 0).toFixed(2)} s`, mono: true },
              { label: 'Packet rate', value: `${Number(record.packets_per_second ?? 0).toFixed(1)} pps`, mono: true },
              { label: 'Byte rate', value: `${formatBytes(record.bytes_per_second)}/s`, mono: true },
              { label: 'Failed connections', value: formatNumber(record.failed_connections ?? 0), mono: true },
              { label: 'Risk score', value: formatPercent(record.risk_score, 1), mono: true },
              { label: 'Anomaly score', value: formatPercent(record.anomaly_score, 2), mono: true },
              { label: 'Model version', value: record.model_version || prediction?.model_version || '—', mono: true },
              { label: 'Prediction id', value: record.prediction_id || '—', mono: true },
            ]}
          />

          {loading ? <LoadingState label="Loading model verdict…" /> : null}
          {error ? <ErrorState error={error} compact /> : null}

          {prediction ? (
            <>
              <div>
                <p className="panel-title mb-2">Class probabilities</p>
                <ul className="space-y-1.5">
                  {Object.entries(probabilities)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, value]) => (
                      <li key={name} className="flex items-center gap-2">
                        <span className="w-32 shrink-0 truncate text-[11px] text-slate-300">{name}</span>
                        <Progress className="flex-1" value={Number(value) * 100} max={100} tone={name === 'Benign' ? 'green' : 'red'} />
                        <span className="mono w-12 shrink-0 text-right text-[10.5px] text-slate-400">{formatPercent(value, 1)}</span>
                      </li>
                    ))}
                </ul>
                <p className="muted mt-2">
                  Confidence {formatPercent(prediction.confidence, 1)} · model verdict is an estimate, not a certainty.
                </p>
              </div>

              {contributions.length ? (
                <div>
                  <p className="panel-title mb-2">Why the model decided this</p>
                  <ul className="space-y-1.5">
                    {contributions.map((item) => (
                      <li key={item.feature} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-[11px] font-medium text-slate-200">{item.label}</span>
                          <span className={`mono shrink-0 text-[10.5px] ${item.direction === 'risk_increase' ? 'text-rose-300' : 'text-emerald-300'}`}>
                            {item.impact}
                          </span>
                        </div>
                        <p className="muted mt-0.5">{item.explanation}</p>
                      </li>
                    ))}
                  </ul>
                  <p className="muted mt-2">{prediction.explanation?.disclaimer}</p>
                </div>
              ) : null}
            </>
          ) : null}
        </div>
      )}
    </Drawer>
  )
}
