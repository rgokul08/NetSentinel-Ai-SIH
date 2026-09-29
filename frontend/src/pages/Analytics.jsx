import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  BarChart3,
  Download,
  Gauge,
  Globe2,
  Layers,
  Radar,
  RefreshCw,
  Server,
  ShieldAlert,
  Target,
  TrendingUp,
  Waves,
} from 'lucide-react'
import { analyticsApi } from '../services/endpoints'
import { useApi } from '../hooks/useApi'
import { useToast } from '../context/ToastContext'
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  Progress,
  Select,
  StatCard,
  Tabs,
} from '../components/ui'
import { CategoryBarChart, DonutChart, TimeSeriesChart } from '../components/charts/charts'
import { compactNumber, downloadBlob, formatAxisTime, formatBytes, formatNumber, formatPercent, timeAgo, toCsv } from '../utils/format'
import { attackColor, riskColor, severityColor } from '../utils/theme'
import { WINDOWS } from '../utils/constants'
import { usePreferences } from '../hooks/usePreferences'

const WINDOW_OPTIONS = WINDOWS.filter((item) => ['1h', '6h', '24h', '7d', '30d'].includes(item.value))

export default function Analytics() {
  const toast = useToast()
  const { prefs } = usePreferences()
  const [window_, setWindow] = useState(() => prefs.defaultWindow || '24h')
  const [tab, setTab] = useState('attacks')

  const trends = useApi(() => analyticsApi.trends({ window: window_ }), [window_], { keepPrevious: true })
  const entities = useApi(() => analyticsApi.entities({ window: window_ }), [window_], { keepPrevious: true })

  const data = trends.data
  const correctness = data?.correctness

  const attackSeries = useMemo(
    () =>
      (data?.attacks_over_time || []).map((point, index) => ({
        time: point.time,
        attacks: point.attacks,
        flows: point.flows,
        anomalies: data?.anomaly_trend?.[index]?.anomalies ?? 0,
      })),
    [data],
  )

  const trafficSeries = useMemo(
    () =>
      (data?.traffic_over_time || []).map((point) => ({
        time: point.time,
        packets: point.packets,
        megabits_per_second: point.megabits_per_second,
      })),
    [data],
  )

  const anomalySeries = useMemo(
    () =>
      (data?.anomaly_trend || []).map((point) => ({
        time: point.time,
        anomalies: point.anomalies,
        anomaly_rate: Number(point.anomaly_rate || 0) * 100,
        mean_risk: Number(point.mean_risk || 0) * 100,
      })),
    [data],
  )

  const forecastSeries = useMemo(() => {
    const byRun = new Map()
    ;(data?.forecast_trend || []).forEach((item) => {
      const key = item.created_at
      if (!byRun.has(key)) byRun.set(key, { time: key })
      const point = byRun.get(key)
      const field = `h${item.horizon_minutes}`
      point[field] = Math.max(point[field] ?? 0, Number(item.overall_probability) * 100)
    })
    return [...byRun.values()].sort((a, b) => new Date(a.time) - new Date(b.time))
  }, [data])

  const exportView = () => {
    if (!data) return
    const rows = [
      { section: 'meta', key: 'window', value: data.window },
      { section: 'meta', key: 'bucket', value: data.bucket },
      { section: 'meta', key: 'generated_at', value: data.generated_at },
      ...Object.entries(correctness || {}).map(([key, value]) => ({ section: 'correctness', key, value })),
      ...(data.attack_by_category || []).map((item) => ({ section: 'attack_by_category', key: item.name, value: item.value })),
      ...(data.severity_distribution || []).map((item) => ({ section: 'severity_distribution', key: item.name, value: item.value })),
      ...(data.protocol_distribution || []).map((item) => ({ section: 'protocol_distribution', key: item.name, value: item.value })),
      ...(data.risk_distribution || []).map((item) => ({ section: 'risk_distribution', key: item.name, value: item.value })),
      ...(data.region_distribution || []).map((item) => ({ section: 'region_distribution', key: item.region, value: item.attacks, flows: item.flows })),
      ...(data.attacks_over_time || []).map((item) => ({ section: 'attacks_over_time', key: item.time, value: item.attacks, flows: item.flows })),
    ]
    downloadBlob(toCsv(rows, ['section', 'key', 'value', 'flows']), `cyberforecast-analytics-${window_}.csv`, 'text/csv;charset=utf-8')
    toast.success('Analytics exported', `CSV for the ${window_} window downloaded.`)
  }

  if (trends.loading && !data) return <LoadingState label="Crunching analytics…" className="py-24" />
  if (trends.error && !data) return <ErrorState error={trends.error} onRetry={trends.refetch} className="py-16" />
  if (!data) return null

  if (data.empty) {
    return (
      <div className="space-y-4">
        <Controls window_={window_} setWindow={setWindow} onRefresh={trends.refetch} loading={trends.loading} onExport={exportView} />
        <Card>
          <EmptyState
            icon={BarChart3}
            title="No traffic in this window"
            message="Analytics are computed from persisted traffic records. Widen the window, upload a dataset, or run the simulation console to generate analysed flows."
            action={
              <div className="flex gap-2">
                <Link to="/datasets"><Button variant="secondary" size="sm">Upload dataset</Button></Link>
                <Link to="/simulation"><Button variant="primary" size="sm">Run simulation</Button></Link>
              </div>
            }
          />
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <Controls window_={window_} setWindow={setWindow} onRefresh={() => { trends.refetch(); entities.refetch() }} loading={trends.loading} onExport={exportView} bucket={data.bucket} generatedAt={data.generated_at} />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Attacks detected" value={formatNumber(attackSeries.reduce((total, point) => total + point.attacks, 0))} icon={ShieldAlert} tone="red" hint={`across ${formatNumber(attackSeries.reduce((total, point) => total + point.flows, 0))} flows`} />
        <StatCard label="Anomalies flagged" value={formatNumber(anomalySeries.reduce((total, point) => total + point.anomalies, 0))} icon={Activity} tone="purple" hint={`peak rate ${formatPercent(Math.max(0, ...anomalySeries.map((point) => point.anomaly_rate)) / 100, 1)}`} />
        <StatCard label="Peak throughput" value={Number(Math.max(0, ...trafficSeries.map((point) => point.megabits_per_second))).toFixed(3)} unit="Mbps" icon={Waves} tone="green" hint={`${compactNumber(Math.max(0, ...trafficSeries.map((point) => point.packets)))} packets in busiest bucket`} />
        <StatCard label="Alerts raised" value={formatNumber(data.alerts_total ?? 0)} icon={Target} tone="amber" />
        <StatCard label="Detection accuracy" value={correctness ? formatPercent(correctness.accuracy, 2) : '—'} icon={Gauge} tone="cyan" hint={correctness ? `${formatNumber(correctness.labeled_rows)} labelled rows` : 'no labelled traffic in window'} />
        <StatCard label="False-positive rate" value={correctness ? formatPercent(correctness.false_positive_rate, 2) : '—'} icon={BarChart3} tone={Number(correctness?.false_positive_rate) > 0.05 ? 'red' : 'green'} hint={correctness ? `${formatNumber(correctness.false_positives)} false positives` : 'n/a'} />
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        items={[
          { value: 'attacks', label: 'Attack trend', icon: TrendingUp },
          { value: 'traffic', label: 'Traffic volume', icon: Waves },
          { value: 'anomalies', label: 'Anomaly behaviour', icon: Activity },
          { value: 'distribution', label: 'Distributions', icon: Layers },
          { value: 'correctness', label: 'Detection quality', icon: Gauge },
          { value: 'entities', label: 'Top entities', icon: Server },
          { value: 'forecast', label: 'Forecast trend', icon: Radar },
        ]}
      />

      {tab === 'attacks' ? (
        <div className="grid gap-4 xl:grid-cols-3">
          <Card className="xl:col-span-2" title="Attacks vs analysed flows" subtitle={`Bucket ${data.bucket} · ${window_} window`} icon={TrendingUp}>
            <TimeSeriesChart
              data={attackSeries}
              series={[
                { key: 'flows', label: 'Flows', color: '#38bdf8', opacity: 0.22 },
                { key: 'attacks', label: 'Attack verdicts', color: '#fb7185' },
                { key: 'anomalies', label: 'Anomalies', color: '#a855f7', opacity: 0.25 },
              ]}
              height={280}
              emptyMessage="No flows recorded in this window."
            />
          </Card>
          <Card title="Attack categories" icon={Layers}>
            <DonutChart
              data={(data.attack_by_category || []).filter((item) => item.name !== 'Benign')}
              height={280}
              colorBy={(entry) => attackColor(entry.name)}
              centerValue={formatNumber((data.attack_by_category || []).filter((i) => i.name !== 'Benign').reduce((t, i) => t + i.value, 0))}
              centerLabel="threats"
              emptyMessage="No attacks detected in this window."
            />
          </Card>
        </div>
      ) : null}

      {tab === 'traffic' ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Packet volume" subtitle={`Bucketed every ${data.bucket}`} icon={Waves}>
            <TimeSeriesChart data={trafficSeries} series={[{ key: 'packets', label: 'Packets', color: '#22d3ee' }]} height={260} emptyMessage="No traffic volume recorded." />
          </Card>
          <Card title="Throughput (Mbps)" icon={Gauge}>
            <TimeSeriesChart
              data={trafficSeries}
              type="line"
              series={[{ key: 'megabits_per_second', label: 'Mbps', color: '#34d399' }]}
              height={260}
              yFormatter={(value) => Number(value).toFixed(2)}
              emptyMessage="No throughput recorded."
            />
          </Card>
        </div>
      ) : null}

      {tab === 'anomalies' ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Anomaly count and rate" icon={Activity}>
            <TimeSeriesChart
              data={anomalySeries}
              series={[
                { key: 'anomalies', label: 'Anomalies', color: '#a855f7' },
                { key: 'anomaly_rate', label: 'Anomaly rate %', color: '#fbbf24', opacity: 0.2 },
              ]}
              height={260}
              emptyMessage="No anomaly scoring in this window."
            />
          </Card>
          <Card title="Mean risk score over time" subtitle="Composite risk = 0.72·P(attack) + 0.16·anomaly + 0.12·severity weight" icon={Radar}>
            <TimeSeriesChart data={anomalySeries} type="line" series={[{ key: 'mean_risk', label: 'Mean risk %', color: '#fb7185' }]} height={260} yFormatter={(value) => `${Number(value).toFixed(0)}%`} emptyMessage="No risk history." />
          </Card>
        </div>
      ) : null}

      {tab === 'distribution' ? (
        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
          <Card title="Severity mix" icon={ShieldAlert}>
            <CategoryBarChart data={data.severity_distribution || []} height={220} colorBy={(entry) => severityColor(entry.name).hex} emptyMessage="No alerts raised in this window." />
          </Card>
          <Card title="Protocol mix" icon={Layers}>
            <CategoryBarChart data={data.protocol_distribution || []} height={220} emptyMessage="No protocol data." />
          </Card>
          <Card title="Risk level distribution" icon={Gauge}>
            <CategoryBarChart data={data.risk_distribution || []} height={220} colorBy={(entry) => riskColor(entry.name)} emptyMessage="No risk scoring yet." />
          </Card>
          <Card className="lg:col-span-2 xl:col-span-3" title="Attack volume by abstracted region" subtitle="Regions are a deterministic, privacy-preserving abstraction of source IPs — not real geolocation" icon={Globe2}>
            <CategoryBarChart
              data={(data.region_distribution || []).map((item) => ({ name: item.region, value: item.attacks, flows: item.flows }))}
              height={240}
              colorBy={(entry) => (entry.value > 20 ? '#fb7185' : entry.value > 5 ? '#fbbf24' : '#22d3ee')}
              emptyMessage="No regional data in this window."
            />
          </Card>
        </div>
      ) : null}

      {tab === 'correctness' ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
          <Card title="Detection quality vs ground truth" subtitle={`Computed over ${formatNumber(correctness?.labeled_rows ?? 0)} labelled rows in this window`} icon={Gauge}>
            {correctness ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                  {[
                    { label: 'True positives', value: correctness.true_positives, tone: 'green', hint: 'attacks correctly flagged' },
                    { label: 'True negatives', value: correctness.true_negatives, tone: 'cyan', hint: 'benign flows correctly passed' },
                    { label: 'False positives', value: correctness.false_positives, tone: 'amber', hint: 'benign flagged as attack' },
                    { label: 'False negatives', value: correctness.false_negatives, tone: 'red', hint: 'attacks missed' },
                  ].map((item) => (
                    <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                      <p className="text-[10px] uppercase tracking-wide text-slate-500">{item.label}</p>
                      <p className="mt-1 text-2xl font-bold leading-none text-slate-100">{formatNumber(item.value)}</p>
                      <p className="muted mt-1">{item.hint}</p>
                    </div>
                  ))}
                </div>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {[
                    { label: 'Accuracy', value: correctness.accuracy },
                    { label: 'Precision', value: correctness.precision },
                    { label: 'Recall', value: correctness.recall },
                    { label: 'F1 score', value: correctness.f1 },
                  ].map((metric) => (
                    <div key={metric.label}>
                      <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                        <span>{metric.label}</span>
                        <span className="font-mono text-slate-300">{formatPercent(metric.value, 2)}</span>
                      </div>
                      <Progress value={Number(metric.value) * 100} max={100} tone={Number(metric.value) >= 0.95 ? 'green' : Number(metric.value) >= 0.8 ? 'cyan' : 'amber'} />
                    </div>
                  ))}
                </div>
                <p className="muted">
                  Ground truth comes from the <span className="mono">attack_type</span> label on each traffic record. Unlabelled flows are
                  excluded, so these figures describe measured behaviour rather than an assumption.
                </p>
              </div>
            ) : (
              <EmptyState title="No labelled traffic" message="Upload a labelled dataset to measure detection quality." />
            )}
          </Card>
          <Card title="Confusion breakdown" icon={BarChart3}>
            <CategoryBarChart
              data={[
                { name: 'True positive', value: correctness?.true_positives ?? 0 },
                { name: 'True negative', value: correctness?.true_negatives ?? 0 },
                { name: 'False positive', value: correctness?.false_positives ?? 0 },
                { name: 'False negative', value: correctness?.false_negatives ?? 0 },
              ]}
              height={230}
              horizontal
              colorBy={(entry) => (entry.name.startsWith('True') ? '#34d399' : '#fb7185')}
            />
            <KeyValue
              className="mt-3"
              columns={1}
              items={[
                { label: 'False-positive rate', value: formatPercent(correctness?.false_positive_rate, 3), mono: true },
                { label: 'Labelled rows evaluated', value: formatNumber(correctness?.labeled_rows ?? 0), mono: true },
                { label: 'Window', value: `${data.window} (bucket ${data.bucket})` },
              ]}
            />
          </Card>
        </div>
      ) : null}

      {tab === 'entities' ? (
        <div className="grid gap-4 xl:grid-cols-3">
          <EntityTable title="Top sources" subtitle="By analysed flows" icon={Server} rows={entities.data?.sources || []} loading={entities.loading} column="ip" />
          <EntityTable title="Top targets" subtitle="Destinations receiving attacks" icon={Target} rows={entities.data?.targets || []} loading={entities.loading} column="ip" />
          <EntityTable title="Top ports" subtitle="Destination ports involved in attacks" icon={Layers} rows={entities.data?.ports || []} loading={entities.loading} column="port" />
        </div>
      ) : null}

      {tab === 'forecast' ? (
        <Card title="Forecast probability by run" subtitle="Each point is one stored forecast run; the value is the worst-case category probability for that horizon" icon={Radar}>
          {forecastSeries.length > 1 ? (
            <TimeSeriesChart
              data={forecastSeries}
              type="line"
              series={[5, 15, 30, 60]
                .filter((minutes) => forecastSeries.some((point) => point[`h${minutes}`] !== undefined))
                .map((minutes, index) => ({ key: `h${minutes}`, label: `${minutes} min horizon`, color: ['#22d3ee', '#a855f7', '#fbbf24', '#fb7185'][index % 4] }))}
              height={300}
              yFormatter={(value) => `${Number(value).toFixed(0)}%`}
            />
          ) : (
            <EmptyState
              icon={Radar}
              title="Not enough forecast runs"
              message="Run the forecaster at different times to build a comparable trend."
              action={<Link to="/forecast"><Button variant="primary" size="sm">Open forecast workspace</Button></Link>}
            />
          )}
        </Card>
      ) : null}
    </div>
  )
}

function Controls({ window_, setWindow, onRefresh, loading, onExport, bucket, generatedAt }) {
  return (
    <div className="card flex flex-wrap items-center gap-2 p-3">
      <Select className="w-auto min-w-[176px]" value={window_} onChange={(event) => setWindow(event.target.value)} options={WINDOW_OPTIONS} aria-label="Analytics window" />
      <Button size="sm" variant="ghost" icon={RefreshCw} onClick={onRefresh} loading={loading}>Refresh</Button>
      <Button size="sm" variant="secondary" icon={Download} onClick={onExport}>Export CSV</Button>
      <span className="muted ml-auto">
        {bucket ? `bucket ${bucket}` : ''} {generatedAt ? `· computed ${timeAgo(generatedAt)}` : ''}
      </span>
    </div>
  )
}

function EntityTable({ title, subtitle, icon: Icon, rows, loading, column }) {
  return (
    <Card title={title} subtitle={subtitle} icon={Icon} bodyClass="p-0">
      <DataTable
        columns={[
          { key: column, header: column === 'port' ? 'Port' : 'Address', mono: true, render: (row) => (row[column] ? <span className="mono">{row[column]}</span> : '—') },
          { key: 'flows', header: 'Flows', align: 'right', sortable: true, render: (row) => <span className="mono">{formatNumber(row.flows)}</span> },
          { key: 'attacks', header: 'Attacks', align: 'right', sortable: true, render: (row) => (row.attacks ? <Badge tone="red">{formatNumber(row.attacks)}</Badge> : <span className="text-slate-600">0</span>) },
          { key: 'packets', header: 'Packets', align: 'right', hideBelow: 'lg:table-cell', render: (row) => <span className="mono">{compactNumber(row.packets)}</span> },
          {
            key: 'risk', header: 'Risk', align: 'right', width: '112px',
            render: (row) => (
              <span className="flex items-center justify-end gap-1.5">
                <Progress className="w-10" value={Number(row.risk || 0) * 100} max={100} tone={Number(row.risk) >= 0.5 ? 'red' : 'amber'} />
                <span className="mono text-[10.5px]">{formatPercent(row.risk, 0)}</span>
              </span>
            ),
          },
        ]}
        rows={rows}
        loading={loading}
        rowKey={(row) => String(row[column] ?? row.id ?? Math.random())}
        maxHeight={360}
        empty={<EmptyState title="Nothing recorded" message={`No ${title.toLowerCase()} in this window.`} />}
      />
    </Card>
  )
}
