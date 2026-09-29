import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  ClipboardList,
  Cpu,
  FileJson,
  FlaskConical,
  Info,
  Play,
  Radar,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  Table2,
  Upload,
  Wand2,
} from 'lucide-react'
import { predictApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useToast } from '../context/ToastContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  CopyButton,
  DataTable,
  EmptyState,
  ErrorState,
  Field,
  Input,
  KeyValue,
  LoadingState,
  Modal,
  Progress,
  RiskBadge,
  Select,
  StatCard,
  Tabs,
  Textarea,
} from '../components/ui'
import { CategoryBarChart, ContributionRadar } from '../components/charts/charts'
import { ProbabilityGauge } from '../components/charts/charts'
import { formatDateTime, formatNumber, formatPercent, timeAgo, truncate } from '../utils/format'
import { riskColor } from '../utils/theme'
import { ATTACK_TYPES } from '../utils/constants'

const PRESETS = [
  {
    key: 'ddos',
    label: 'DDoS / SYN flood',
    icon: ShieldAlert,
    flow: {
      source_ip: '203.0.113.9', destination_ip: '10.20.10.5', source_port: 51244, destination_port: 80,
      protocol: 'TCP', tcp_flags: 'SYN', packet_count: 25000, byte_count: 3000000, flow_duration: 12,
      connection_count: 1, failed_connections: 9000, request_frequency: 2083,
    },
  },
  {
    key: 'portscan',
    label: 'Port scan',
    icon: Radar,
    flow: {
      source_ip: '185.220.101.7', destination_ip: '10.20.1.48', source_port: 44120, destination_port: 899,
      protocol: 'TCP', tcp_flags: 'FIN', packet_count: 3, byte_count: 153, flow_duration: 0.02,
      connection_count: 120, failed_connections: 118, request_frequency: 162,
    },
  },
  {
    key: 'bruteforce',
    label: 'Brute force SSH',
    icon: Wand2,
    flow: {
      source_ip: '192.0.2.44', destination_ip: '10.20.5.12', source_port: 55210, destination_port: 22,
      protocol: 'TCP', tcp_flags: 'PSH-ACK', packet_count: 480, byte_count: 39000, flow_duration: 61,
      connection_count: 240, failed_connections: 236, request_frequency: 7.9,
    },
  },
  {
    key: 'botnet',
    label: 'Botnet C2 beacon',
    icon: BrainCircuit,
    flow: {
      source_ip: '10.20.3.77', destination_ip: '45.83.64.12', source_port: 49322, destination_port: 443,
      protocol: 'HTTPS', tcp_flags: 'ACK', packet_count: 26, byte_count: 4300, flow_duration: 2.4,
      connection_count: 1, failed_connections: 0, request_frequency: 0.4,
    },
  },
  {
    key: 'benign',
    label: 'Benign web session',
    icon: CheckCircle2,
    flow: {
      source_ip: '10.20.1.15', destination_ip: '8.8.8.8', source_port: 50122, destination_port: 443,
      protocol: 'HTTPS', tcp_flags: 'ACK', packet_count: 30, byte_count: 42000, flow_duration: 4.1,
      connection_count: 1, failed_connections: 0, request_frequency: 7.3,
    },
  },
]

const EMPTY_FLOW = {
  source_ip: '', destination_ip: '', source_port: '', destination_port: '', protocol: 'TCP', tcp_flags: 'ACK',
  packet_count: '', byte_count: '', flow_duration: '', connection_count: '', failed_connections: '', request_frequency: '',
}

const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SMTP', 'FTP', 'SSH', 'ARP']

export default function Detection() {
  const toast = useToast()
  const [tab, setTab] = useState('single')
  const [flow, setFlow] = useState(EMPTY_FLOW)
  const [batchText, setBatchText] = useState('')
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [selected, setSelected] = useState(null)

  const explain = useApi(() => predictApi.explain(), [], { keepPrevious: true })
  const history = useApi(() => predictApi.predictions({ limit: page.limit, offset: page.offset }), [page.limit, page.offset], { keepPrevious: true })

  const single = useAction(
    async () => {
      const payload = numericFlow(flow)
      const result = await predictApi.predict(payload)
      toast.success('Flow analysed', `${result.attack_type} · risk ${formatPercent(result.risk_score, 0)} · engine ${result.model?.engine}`)
      history.refetch()
      return result
    },
    { onError: (failure) => toast.error('Prediction failed', failure.message) },
  )

  const batch = useAction(
    async () => {
      const flows = parseBatch(batchText)
      if (!flows.length) throw new Error('No parsable flows found. Provide a JSON array of flow objects or CSV lines with a header row.')
      const result = await predictApi.batch(flows)
      toast.success('Batch analysed', `${result.summary?.rows || 0} flows · ${result.summary?.attacks_detected || 0} attack verdicts.`)
      history.refetch()
      return result
    },
    { onError: (failure) => toast.error('Batch prediction failed', failure.message) },
  )

  const setField = (key) => (event) => setFlow((current) => ({ ...current, [key]: event.target.value }))

  const result = single.result
  const batchResult = batch.result

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Tabs
          value={tab}
          onChange={setTab}
          items={[
            { value: 'single', label: 'Single flow', icon: FlaskConical },
            { value: 'batch', label: 'Batch / CSV', icon: Table2 },
            { value: 'history', label: 'Stored predictions', icon: ClipboardList, count: history.data?.pagination?.total },
            { value: 'explain', label: 'Model explainability', icon: BrainCircuit },
          ]}
        />
        <div className="flex items-center gap-2">
          <Badge tone="cyan">
            <Cpu size={9} /> engine: {explain.data?.engine || 'ml'}
          </Badge>
          <Badge tone="slate">{explain.data?.model_name || 'no active model'}</Badge>
          {explain.data?.version ? <Badge tone="slate">v{explain.data.version}</Badge> : null}
        </div>
      </div>

      {tab === 'single' ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
          <div className="space-y-4">
            <Card title="Flow features" subtitle="Values are sent to the backend, engineered into 48 features and scored by the active models" icon={FlaskConical}>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2.5">
                  <Input label="Source IP" value={flow.source_ip} onChange={setField('source_ip')} placeholder="203.0.113.9" />
                  <Input label="Destination IP" value={flow.destination_ip} onChange={setField('destination_ip')} placeholder="10.20.10.5" />
                  <Input label="Source port" type="number" min="0" max="65535" value={flow.source_port} onChange={setField('source_port')} placeholder="51244" />
                  <Input label="Destination port" type="number" min="0" max="65535" value={flow.destination_port} onChange={setField('destination_port')} placeholder="80" />
                </div>
                <div className="grid grid-cols-2 gap-2.5">
                  <Select label="Protocol" value={flow.protocol} onChange={setField('protocol')} options={PROTOCOLS} />
                  <Input label="TCP flags" value={flow.tcp_flags} onChange={setField('tcp_flags')} placeholder="SYN, ACK, PSH-ACK…" />
                </div>
                <div className="grid grid-cols-2 gap-2.5">
                  <Input label="Packet count" type="number" min="0" value={flow.packet_count} onChange={setField('packet_count')} />
                  <Input label="Byte count" type="number" min="0" value={flow.byte_count} onChange={setField('byte_count')} />
                  <Input label="Flow duration (s)" type="number" step="0.001" min="0" value={flow.flow_duration} onChange={setField('flow_duration')} />
                  <Input label="Connection count" type="number" min="0" value={flow.connection_count} onChange={setField('connection_count')} />
                  <Input label="Failed connections" type="number" min="0" value={flow.failed_connections} onChange={setField('failed_connections')} />
                  <Input label="Request frequency" type="number" step="0.01" min="0" value={flow.request_frequency} onChange={setField('request_frequency')} />
                </div>

                <div className="flex flex-wrap gap-2">
                  <Button variant="primary" icon={Play} loading={single.busy} onClick={single.run}>
                    Analyse flow
                  </Button>
                  <Button variant="ghost" icon={RefreshCw} onClick={() => { setFlow(EMPTY_FLOW); single.reset() }}>
                    Clear
                  </Button>
                </div>
                {single.error ? <ErrorState error={single.error} compact /> : null}
              </div>
            </Card>

            <Card title="Load a realistic preset" subtitle="Each preset mirrors the traffic profiles the models were trained on" icon={Wand2} dense>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {PRESETS.map((preset) => (
                  <button
                    key={preset.key}
                    type="button"
                    onClick={() => {
                      setFlow({ ...EMPTY_FLOW, ...Object.fromEntries(Object.entries(preset.flow).map(([key, value]) => [key, String(value)])) })
                      single.reset()
                    }}
                    className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/40 px-2.5 py-2 text-left transition hover:border-cyan-500/40 hover:bg-slate-800/50"
                  >
                    <preset.icon size={13} className="shrink-0 text-cyan-400" />
                    <span className="truncate text-[11px] font-medium text-slate-200">{preset.label}</span>
                  </button>
                ))}
              </div>
            </Card>
          </div>

          {result ? <PredictionResult result={result} /> : (
            <Card title="Verdict" icon={ScanSearch}>
              <EmptyState
                icon={ScanSearch}
                title="No prediction yet"
                message="Fill in a flow (or load a preset) and press Analyse. The backend runs the full feature pipeline, the active classifier and the anomaly detector, then persists the prediction."
              />
            </Card>
          )}
        </div>
      ) : null}

      {tab === 'batch' ? (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Card
            title="Batch input"
            subtitle="Paste a JSON array of flow objects, or CSV lines with a header row"
            icon={FileJson}
            actions={
              <div className="flex items-center gap-2">
                <Button size="sm" variant="ghost" icon={Upload} onClick={() => document.getElementById('batch-file')?.click()}>
                  Load file
                </Button>
                <input
                  id="batch-file"
                  type="file"
                  accept=".csv,.json,.txt"
                  className="hidden"
                  onChange={async (event) => {
                    const file = event.target.files?.[0]
                    if (!file) return
                    setBatchText(await file.text())
                    event.target.value = ''
                  }}
                />
                <Button size="sm" variant="secondary" onClick={() => setBatchText(sampleCsv())}>
                  Insert sample
                </Button>
              </div>
            }
          >
            <Textarea rows={16} value={batchText} onChange={(event) => setBatchText(event.target.value)} placeholder={'source_ip,destination_ip,destination_port,protocol,packet_count,byte_count,flow_duration,tcp_flags,failed_connections\n203.0.113.9,10.20.10.5,80,TCP,25000,3000000,12,SYN,9000\n10.20.1.15,8.8.8.8,443,HTTPS,30,42000,4.1,ACK,0'} />
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button variant="primary" icon={Play} loading={batch.busy} onClick={batch.run}>
                Analyse batch
              </Button>
              <Button variant="ghost" onClick={() => { setBatchText(''); batch.reset() }}>
                Clear
              </Button>
              <span className="muted">{batchText.trim() ? `${batchText.trim().split(/\r?\n/).length} lines pasted` : 'nothing to analyse yet'}</span>
            </div>
            {batch.error ? <ErrorState error={batch.error} compact className="mt-3" /> : null}
          </Card>

          {batchResult ? <BatchResult result={batchResult} /> : (
            <Card title="Batch results" icon={Table2}>
              <EmptyState icon={Table2} title="No batch analysed yet" message="Results include a per-flow verdict, the class distribution and how many alerts the pipeline raised." />
            </Card>
          )}
        </div>
      ) : null}

      {tab === 'history' ? (
        <Card
          title="Stored predictions"
          subtitle="Every prediction the pipeline has persisted, newest first"
          icon={ClipboardList}
          bodyClass="p-0"
          actions={
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={history.refetch} loading={history.loading}>
              Refresh
            </Button>
          }
        >
          <DataTable
            columns={[
              { key: 'timestamp', header: 'When', width: '150px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400">{formatDateTime(row.timestamp)}</span> },
              { key: 'attack_type', header: 'Verdict', width: '140px', render: (row) => <AttackBadge type={row.attack_type} /> },
              { key: 'confidence', header: 'Confidence', width: '104px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatPercent(row.confidence, 1)}</span> },
              {
                key: 'risk_score', header: 'Risk', width: '140px', align: 'right', sortable: true,
                render: (row) => (
                  <span className="flex items-center justify-end gap-2">
                    <Progress className="w-14" value={Number(row.risk_score) * 100} max={100} tone={Number(row.risk_score) >= 0.5 ? 'red' : 'amber'} />
                    <span className="mono text-[10.5px]">{formatPercent(row.risk_score, 0)}</span>
                  </span>
                ),
              },
              { key: 'is_anomaly', header: 'Anomaly', width: '88px', align: 'center', render: (row) => (row.is_anomaly ? <Badge tone="purple">yes</Badge> : <span className="text-slate-600">—</span>) },
              { key: 'true_attack_type', header: 'Ground truth', width: '130px', render: (row) => (row.true_attack_type ? <span className="mono text-[10.5px] text-slate-400">{row.true_attack_type}</span> : <span className="text-slate-600">unlabelled</span>) },
              { key: 'is_correct', header: 'Correct', width: '86px', align: 'center', render: (row) => (row.is_correct === null || row.is_correct === undefined ? <span className="text-slate-600">—</span> : row.is_correct ? <Badge tone="green">yes</Badge> : <Badge tone="red">no</Badge>) },
              { key: 'source', header: 'Origin', width: '104px', render: (row) => (row.is_simulated ? <Badge tone="purple">simulated</Badge> : <Badge tone="slate">{row.source || 'api'}</Badge>) },
              { key: 'model_version', header: 'Model', width: '84px', mono: true },
            ]}
            rows={history.data?.items || []}
            loading={history.loading}
            error={history.error}
            onRetry={history.refetch}
            pagination={history.data?.pagination}
            onPageChange={setPage}
            onRowClick={setSelected}
            selectedId={selected?.id}
            empty={<EmptyState icon={ClipboardList} title="No predictions stored yet" message="Run a single or batch prediction and it will be recorded here." />}
          />
        </Card>
      ) : null}

      {tab === 'explain' ? <ExplainabilityPanel state={explain} /> : null}

      <PredictionModal prediction={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function numericFlow(flow) {
  const numeric = ['source_port', 'destination_port', 'packet_count', 'byte_count', 'flow_duration', 'connection_count', 'failed_connections', 'request_frequency']
  const payload = {}
  Object.entries(flow).forEach(([key, value]) => {
    if (value === '' || value === null || value === undefined) return
    payload[key] = numeric.includes(key) ? Number(value) : String(value).trim()
  })
  return payload
}

function sampleCsv() {
  return [
    'source_ip,destination_ip,destination_port,protocol,packet_count,byte_count,flow_duration,tcp_flags,failed_connections',
    '203.0.113.9,10.20.10.5,80,TCP,25000,3000000,12,SYN,9000',
    '185.220.101.7,10.20.1.48,899,TCP,3,153,0.02,FIN,118',
    '192.0.2.44,10.20.5.12,22,TCP,480,39000,61,PSH-ACK,236',
    '10.20.1.15,8.8.8.8,443,HTTPS,30,42000,4.1,ACK,0',
    '10.20.3.77,45.83.64.12,443,HTTPS,26,4300,2.4,ACK,0',
  ].join('\n')
}

/** Accepts JSON arrays/objects or CSV text with a header row. */
function parseBatch(text) {
  const trimmed = String(text || '').trim()
  if (!trimmed) return []
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed)
      const list = Array.isArray(parsed) ? parsed : parsed.flows || [parsed]
      return list.filter((item) => item && typeof item === 'object')
    } catch {
      /* fall through to CSV parsing */
    }
  }
  const lines = trimmed.split(/\r?\n/).filter((line) => line.trim().length)
  if (lines.length < 2) return []
  const headers = lines[0].split(',').map((header) => header.trim().replace(/^"|"$/g, ''))
  return lines.slice(1).map((line) => {
    const cells = line.split(',').map((cell) => cell.trim().replace(/^"|"$/g, ''))
    const row = {}
    headers.forEach((header, index) => {
      const value = cells[index]
      if (value === undefined || value === '') return
      const numeric = Number(value)
      row[header] = Number.isFinite(numeric) && value !== '' && !Number.isNaN(numeric) && /^-?\d+(\.\d+)?$/.test(value) ? numeric : value
    })
    return row
  })
}

function PredictionResult({ result }) {
  const hex = riskColor(result.risk_level)
  const probabilities = Object.entries(result.probabilities || {}).sort((a, b) => b[1] - a[1])
  const contributions = result.explanation?.contributions || []

  return (
    <div className="space-y-4">
      <Card
        title="Model verdict"
        subtitle={`Analysed ${result.predicted_at ? timeAgo(result.predicted_at) : 'just now'} · engine ${result.model?.engine || 'ml'}`}
        icon={ScanSearch}
        actions={<Badge tone={result.is_attack ? 'red' : 'green'}>{result.is_attack ? 'attack' : 'benign'}</Badge>}
      >
        <div className="grid gap-4 lg:grid-cols-[200px_minmax(0,1fr)]">
          <div className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <ProbabilityGauge value={result.risk_score} label="composite risk" color={hex} height={150} />
            <div className="mt-1 flex flex-wrap items-center justify-center gap-1.5">
              <AttackBadge type={result.attack_type} />
              <RiskBadge level={result.risk_level} />
            </div>
          </div>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <MiniStat label="Attack probability" value={formatPercent(result.attack_probability, 1)} tone="red" />
              <MiniStat label="Model confidence" value={formatPercent(result.confidence, 1)} tone="cyan" />
              <MiniStat label="Anomaly score" value={formatPercent(result.anomaly_score, 2)} tone="purple" />
              <MiniStat label="Severity" value={String(result.severity || '—').toUpperCase()} tone="amber" />
            </div>

            <div>
              <p className="panel-title mb-1.5">Class probabilities</p>
              <ul className="space-y-1">
                {probabilities.map(([name, value]) => (
                  <li key={name} className="flex items-center gap-2">
                    <span className="w-32 shrink-0 truncate text-[11px] text-slate-300">{name}</span>
                    <Progress className="flex-1" value={Number(value) * 100} max={100} tone={name === 'Benign' ? 'green' : 'red'} />
                    <span className="mono w-12 shrink-0 text-right text-[10.5px] text-slate-400">{formatPercent(value, 1)}</span>
                  </li>
                ))}
              </ul>
            </div>

            <KeyValue
              columns={2}
              items={[
                { label: 'Derived packet rate', value: `${formatNumber(Math.round(result.packets_per_second || 0))} pps`, mono: true },
                { label: 'Derived byte rate', value: `${formatNumber(Math.round(result.bytes_per_second || 0))} B/s`, mono: true },
                { label: 'Active classifier', value: result.model?.model_name || '—' },
                { label: 'Model version', value: result.model?.model_version || '—', mono: true },
                { label: 'Anomaly detector', value: result.model?.anomaly_model_id ? truncate(result.model.anomaly_model_id, 14) : 'not registered', mono: true },
                { label: 'Trained at', value: result.model?.trained_at ? formatDateTime(result.model.trained_at) : '—' },
              ]}
            />
            <p className="muted flex items-start gap-1.5">
              <Info size={11} className="mt-0.5 shrink-0" />
              {result.explanation?.disclaimer || 'The verdict is a probabilistic model estimate; it does not claim certainty.'}
            </p>
          </div>
        </div>
      </Card>

      {contributions.length ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Card title="Attribution radar" subtitle={result.explanation?.method || 'importance-weighted deviation attribution'} icon={Radar}>
            <ContributionRadar data={contributions.slice(0, 8).map((item) => ({ label: item.label, impact: Math.abs(Number(item.attribution) || 0) }))} height={250} />
          </Card>
          <Card title="Feature contributions" subtitle="How far each feature deviates from the training baseline" icon={BrainCircuit} bodyClass="p-0">
            <ul className="max-h-[300px] divide-y divide-slate-800/60 overflow-y-auto">
              {contributions.map((item) => (
                <li key={item.feature} className="px-4 py-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[11.5px] font-medium text-slate-200">{item.label}</span>
                    <span className={`mono shrink-0 text-[10.5px] font-semibold ${item.direction === 'risk_increase' ? 'text-rose-300' : 'text-emerald-300'}`}>
                      {item.impact}
                    </span>
                  </div>
                  <Progress
                    className="mt-1.5"
                    value={Math.min(100, Math.abs(Number(item.impact_pct) || 0))}
                    max={100}
                    tone={item.direction === 'risk_increase' ? 'red' : 'green'}
                  />
                  <p className="muted mt-1">{item.explanation}</p>
                  <p className="mono mt-0.5 text-[10px] text-slate-500">
                    observed {formatNumber(item.observed)} · baseline μ {formatNumber(item.baseline_mean)} · p90 {formatNumber(item.baseline_p90)} ·{' '}
                    {Number(item.deviation_sigma).toFixed(1)}σ · model weight {Number(item.weight).toFixed(4)}
                  </p>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      ) : null}

      {result.explanation?.summary ? (
        <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/6 p-3">
          <p className="panel-title mb-1 text-cyan-300">Plain-language explanation</p>
          <p className="text-xs leading-relaxed text-cyan-100/90">{result.explanation.summary}</p>
        </div>
      ) : null}
    </div>
  )
}

function MiniStat({ label, value, tone = 'cyan' }) {
  const tones = { cyan: 'text-cyan-300', red: 'text-rose-300', purple: 'text-purple-300', amber: 'text-amber-300', green: 'text-emerald-300' }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-2">
      <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-0.5 text-base font-bold leading-none ${tones[tone] || tones.cyan}`}>{value}</p>
    </div>
  )
}

function BatchResult({ result }) {
  const summary = result.summary || {}
  const items = result.predictions || result.items || []
  const distribution = summary.class_distribution || {}
  const riskLevels = summary.risk_levels || {}

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Flows analysed" value={formatNumber(summary.rows ?? items.length)} icon={Table2} tone="cyan" />
        <StatCard label="Attack verdicts" value={formatNumber(summary.attacks_detected ?? 0)} icon={ShieldAlert} tone="red" hint={`${formatPercent(summary.attack_rate ?? 0, 1)} of the batch`} />
        <StatCard label="Anomalies" value={formatNumber(summary.anomalies ?? 0)} icon={AlertTriangle} tone="purple" />
        <StatCard
          label="Mean risk"
          value={formatPercent(summary.mean_risk_score ?? 0, 1)}
          icon={Radar}
          tone="amber"
          hint={`peak ${formatPercent(summary.max_risk_score ?? 0, 1)} · confidence ${formatPercent(summary.mean_confidence ?? 0, 0)}`}
        />
      </div>

      <Card title="Verdict distribution" icon={BrainCircuit}>
        <CategoryBarChart
          data={Object.entries(distribution).map(([name, value]) => ({ name, value }))}
          height={190}
          horizontal
          emptyMessage="No verdicts in this batch."
        />
      </Card>

      <Card title="Per-flow results" subtitle="Persisted by the backend and available in the prediction history" icon={ClipboardList} bodyClass="p-0">
        <DataTable
          columns={[
            { key: 'source_ip', header: 'Source', width: '132px', mono: true },
            { key: 'destination_ip', header: 'Destination', width: '132px', mono: true, render: (row) => `${row.destination_ip || '—'}:${row.destination_port ?? ''}` },
            { key: 'attack_type', header: 'Verdict', width: '140px', render: (row) => <AttackBadge type={row.attack_type} /> },
            { key: 'confidence', header: 'Confidence', width: '100px', align: 'right', render: (row) => <span className="mono">{formatPercent(row.confidence, 1)}</span> },
            { key: 'risk_score', header: 'Risk', width: '120px', align: 'right', render: (row) => (
              <span className="flex items-center justify-end gap-2">
                <Progress className="w-12" value={Number(row.risk_score) * 100} max={100} tone={Number(row.risk_score) >= 0.5 ? 'red' : 'amber'} />
                <span className="mono text-[10.5px]">{formatPercent(row.risk_score, 0)}</span>
              </span>
            ) },
            { key: 'is_anomaly', header: 'Anomaly', width: '82px', align: 'center', render: (row) => (row.is_anomaly ? <Badge tone="purple">yes</Badge> : <span className="text-slate-600">—</span>) },
            { key: 'risk_level', header: 'Level', width: '110px', render: (row) => <RiskBadge level={String(row.risk_level || '').toLowerCase()} /> },
          ]}
          rows={items}
          rowKey={(row, index) => `${row.source_ip}-${row.destination_ip}-${index}`}
          maxHeight={360}
          empty={<EmptyState title="No rows returned" message="The batch produced no predictions." />}
        />
      </Card>

      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/50 px-3.5 py-2.5 text-[11px] text-slate-300">
        <Info size={13} className="text-cyan-400" />
        <span>
          Batch engine <span className="mono text-cyan-300">{summary.engine || 'ml'}</span> · source{' '}
          <span className="mono">{summary.source || 'api'}</span> · risk mix{' '}
          {Object.entries(riskLevels)
            .map(([level, count]) => `${level} ${count}`)
            .join(' · ') || 'n/a'}
        </span>
        <span className="muted">
          Predictions are persisted, so any alert raised by the pipeline appears in the triage queue.
        </span>
        <Link to="/alerts" className="btn-secondary btn-xs ml-auto">Open triage queue</Link>
      </div>
    </div>
  )
}

function ExplainabilityPanel({ state }) {
  if (state.loading && !state.data) return <LoadingState label="Loading model explanation…" className="py-16" />
  if (state.error) return <ErrorState error={state.error} onRetry={state.refetch} className="py-16" />
  const data = state.data
  if (!data?.available) {
    return (
      <Card title="Model explainability" icon={BrainCircuit}>
        <EmptyState
          icon={BrainCircuit}
          title="No active model registered"
          message="Train and activate a classifier in the model registry to see global feature importances and per-class performance."
          action={
            <Link to="/models">
              <Button variant="primary" size="sm">Open model registry</Button>
            </Link>
          }
        />
      </Card>
    )
  }

  const importance = data.feature_importance || []
  const classReport = data.metrics?.class_report || []

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard label="Accuracy" value={formatPercent(data.metrics?.accuracy, 2)} icon={CheckCircle2} tone="green" />
        <StatCard label="Precision (weighted)" value={formatPercent(data.metrics?.precision_weighted, 2)} icon={ScanSearch} tone="cyan" />
        <StatCard label="Recall (weighted)" value={formatPercent(data.metrics?.recall_weighted, 2)} icon={Radar} tone="purple" />
        <StatCard label="F1 (macro)" value={formatPercent(data.metrics?.f1_macro, 2)} icon={BrainCircuit} tone="amber" />
        <StatCard label="ROC AUC (OvR)" value={data.metrics?.roc_auc_ovr ? Number(data.metrics.roc_auc_ovr).toFixed(3) : '—'} icon={Cpu} tone="cyan" hint={`log loss ${data.metrics?.log_loss ?? '—'}`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Global feature importance" subtitle={data.method || 'Native tree importances'} icon={BrainCircuit}>
          <CategoryBarChart
            data={importance.slice(0, 14).map((item) => ({ name: item.label, value: Number(item.importance) }))}
            height={Math.max(260, Math.min(importance.length, 14) * 24)}
            horizontal
            formatter={(value) => Number(value).toFixed(2)}
            emptyMessage="The active model exposes no importances."
          />
          <p className="muted mt-2">{data.disclaimer}</p>
        </Card>

        <Card title="Per-class performance" subtitle={`${data.metrics?.n_classes || classReport.length} classes · ${formatNumber(data.metrics?.training_rows || 0)} training rows`} icon={Table2} bodyClass="p-0">
          <DataTable
            columns={[
              { key: 'class', header: 'Class', render: (row) => <AttackBadge type={row.class} /> },
              { key: 'precision', header: 'Precision', align: 'right', render: (row) => <span className="mono">{formatPercent(row.precision, 2)}</span> },
              { key: 'recall', header: 'Recall', align: 'right', render: (row) => <span className="mono">{formatPercent(row.recall, 2)}</span> },
              { key: 'f1', header: 'F1', align: 'right', render: (row) => <span className="mono">{formatPercent(row.f1, 2)}</span> },
              { key: 'support', header: 'Support', align: 'right', render: (row) => <span className="mono">{formatNumber(row.support)}</span> },
            ]}
            rows={classReport}
            rowKey={(row) => row.class}
            maxHeight={340}
            empty={<EmptyState title="No class report available" message="Models trained on a single class have no per-class breakdown." />}
          />
        </Card>
      </div>

      <Card title="Cross-validation and training basis" icon={Info} dense>
        <KeyValue
          columns={3}
          items={[
            { label: 'Algorithm', value: data.metrics?.algorithm_label || data.algorithm },
            { label: 'CV accuracy (mean ± std)', value: `${formatPercent(data.metrics?.cv_accuracy_mean, 2)} ± ${Number(data.metrics?.cv_accuracy_std ?? 0).toFixed(4)}`, mono: true },
            { label: 'Train / test split', value: `${formatNumber(data.metrics?.train_size)} / ${formatNumber(data.metrics?.test_size)}`, mono: true },
            { label: 'Binary attack AUC', value: data.metrics?.roc_auc_binary_attack ? Number(data.metrics.roc_auc_binary_attack).toFixed(3) : '—', mono: true },
            { label: 'Model id', value: data.model_id, mono: true, node: <span className="flex items-center gap-2"><code className="mono">{data.model_id}</code><CopyButton value={data.model_id} label="id" /></span> },
            { label: 'Version', value: data.version, mono: true },
          ]}
        />
        <Link to="/models" className="btn-secondary btn-sm mt-3">Open model registry for confusion matrix</Link>
      </Card>
    </div>
  )
}

function PredictionModal({ prediction, onClose }) {
  const probabilities = useMemo(
    () => Object.entries(prediction?.probabilities || {}).sort((a, b) => b[1] - a[1]),
    [prediction],
  )
  if (!prediction) return null
  return (
    <Modal open onClose={onClose} title={`Prediction ${truncate(prediction.id, 18)}`} subtitle={`${formatDateTime(prediction.timestamp)} · verdict ${prediction.attack_type}`} icon={ScanSearch}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <AttackBadge type={prediction.attack_type} />
          <RiskBadge level={String(prediction.risk_level || '').toLowerCase()} score={prediction.risk_score} />
          {prediction.is_anomaly ? <Badge tone="purple">anomaly</Badge> : null}
          {prediction.is_simulated ? <Badge tone="purple">simulation data</Badge> : null}
          {prediction.is_correct === false ? <Badge tone="red">misclassified vs ground truth</Badge> : null}
        </div>
        <KeyValue
          columns={2}
          items={[
            { label: 'Confidence', value: formatPercent(prediction.confidence, 2), mono: true },
            { label: 'Risk score', value: formatPercent(prediction.risk_score, 2), mono: true },
            { label: 'Anomaly score', value: formatPercent(prediction.anomaly_score, 3), mono: true },
            { label: 'Ground truth', value: prediction.true_attack_type || 'unlabelled' },
            { label: 'Model id', value: prediction.model_id, mono: true },
            { label: 'Model version', value: prediction.model_version, mono: true },
            { label: 'Traffic record', value: prediction.traffic_record_id || '—', mono: true },
            { label: 'Source', value: prediction.source || 'api' },
          ]}
        />
        <div>
          <p className="panel-title mb-1.5">Class probabilities</p>
          <ul className="space-y-1">
            {probabilities.map(([name, value]) => (
              <li key={name} className="flex items-center gap-2">
                <span className="w-32 shrink-0 truncate text-[11px] text-slate-300">{name}</span>
                <Progress className="flex-1" value={Number(value) * 100} max={100} tone={name === 'Benign' ? 'green' : 'red'} />
                <span className="mono w-12 shrink-0 text-right text-[10.5px] text-slate-400">{formatPercent(value, 1)}</span>
              </li>
            ))}
          </ul>
        </div>
        {prediction.explanation?.summary ? <p className="muted">{prediction.explanation.summary}</p> : null}
      </div>
    </Modal>
  )
}
