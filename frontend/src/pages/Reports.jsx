import { useState } from 'react'
import {
  BarChart3,
  CalendarClock,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  FileText,
  Hash,
  Info,
  Play,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Eye,
} from 'lucide-react'
import { reportsApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  DataTable,
  EmptyState,
  ErrorState,
  Field,
  Input,
  KeyValue,
  LoadingState,
  Modal,
  Progress,
  Select,
  StatCard,
} from '../components/ui'
import { formatBytes, formatDateTime, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { riskColor } from '../utils/theme'
import { WINDOWS } from '../utils/constants'

const WINDOW_OPTIONS = WINDOWS.filter((item) => ['1h', '6h', '24h', '7d', '30d'].includes(item.value))

export default function Reports() {
  const { can, user } = useAuth()
  const toast = useToast()
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [form, setForm] = useState({ title: '', window: '24h', format: 'pdf', report_type: 'security_summary' })
  const [detail, setDetail] = useState(null)
  const [pendingDelete, setPendingDelete] = useState(null)

  const list = useApi(() => reportsApi.list({ limit: page.limit, offset: page.offset }), [page.limit, page.offset], { keepPrevious: true })

  const generate = useAction(
    async () => {
      const result = await reportsApi.generate({
        title: form.title.trim() || undefined,
        window: form.window,
        format: form.format,
        report_type: form.report_type,
      })
      toast.success('Report generated', `${result.title} · ${result.format.toUpperCase()} · ${formatBytes(result.size_bytes)}`)
      list.refetch()
      setDetail(result)
      return result
    },
    { onError: (failure) => toast.error('Report generation failed', failure.message) },
  )

  const remove = useAction(
    async (reportId) => {
      await reportsApi.remove(reportId)
      toast.success('Report deleted', 'The stored artifact was removed.')
      setPendingDelete(null)
      list.refetch()
    },
    { onError: (failure) => toast.error('Delete failed', failure.message) },
  )

  const rows = list.data?.items || []
  const canGenerate = can('reports.generate')

  const downloadReport = async (report, format) => {
    try {
      const filename = format === 'csv'
        ? await reportsApi.csv(report.id, `${slug(report.title)}.csv`)
        : await reportsApi.download(report.id, `${slug(report.title)}.${report.format === 'csv' ? 'csv' : 'pdf'}`)
      toast.success('Download started', filename)
    } catch (failure) {
      toast.error('Download failed', failure.message)
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Reports stored" value={formatNumber(list.data?.pagination?.total ?? 0)} icon={FileText} tone="cyan" />
        <StatCard label="PDF reports" value={formatNumber(rows.filter((row) => row.format === 'pdf').length)} unit="on page" icon={FileText} tone="green" />
        <StatCard label="CSV exports" value={formatNumber(rows.filter((row) => row.format === 'csv').length)} unit="on page" icon={FileSpreadsheet} tone="purple" />
        <StatCard label="Total size" value={formatBytes(rows.reduce((total, row) => total + Number(row.size_bytes || 0), 0))} unit="on page" icon={Download} tone="amber" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,380px)_minmax(0,1fr)]">
        <Card title="Generate a report" subtitle="Content is computed from stored records at generation time" icon={Play}>
          {canGenerate ? (
            <div className="space-y-3">
              <Input
                label="Report title"
                value={form.title}
                onChange={(event) => setForm({ ...form, title: event.target.value })}
                placeholder={`Security report - ${form.window} window`}
                hint="Optional; defaults to a window-based title"
              />
              <div className="grid grid-cols-2 gap-3">
                <Select label="Reporting window" value={form.window} onChange={(event) => setForm({ ...form, window: event.target.value })} options={WINDOW_OPTIONS} />
                <Select
                  label="Format"
                  value={form.format}
                  onChange={(event) => setForm({ ...form, format: event.target.value })}
                  options={[
                    { value: 'pdf', label: 'PDF (formatted brief)' },
                    { value: 'csv', label: 'CSV (raw tables)' },
                  ]}
                />
              </div>
              <Select
                label="Report type"
                value={form.report_type}
                onChange={(event) => setForm({ ...form, report_type: event.target.value })}
                options={[
                  { value: 'security_summary', label: 'Security summary (full)' },
                  { value: 'threat_summary', label: 'Threat summary' },
                  { value: 'forecast_brief', label: 'Forecast brief' },
                ]}
                hint="All types include KPIs, attacks, forecast, alerts, models and integrity sections"
              />
              <Button variant="primary" icon={Play} className="w-full" loading={generate.busy} onClick={generate.run}>
                {generate.busy ? 'Computing report…' : 'Generate report'}
              </Button>
              {generate.error ? <ErrorState error={generate.error} compact /> : null}
              {generate.result ? (
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/8 p-3">
                  <p className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                    <CheckCircle2 size={13} /> {generate.result.title}
                  </p>
                  <p className="muted mt-1">
                    {generate.result.format?.toUpperCase()} · {formatBytes(generate.result.size_bytes)} ·{' '}
                    {generate.result.sections?.length || 0} sections · {timeAgo(generate.result.created_at)}
                  </p>
                  <div className="mt-2 flex gap-2">
                    <Button size="xs" variant="secondary" icon={Download} onClick={() => downloadReport(generate.result, generate.result.format)}>
                      Download
                    </Button>
                    <Button size="xs" variant="ghost" icon={Eye} onClick={() => setDetail(generate.result)}>
                      Inspect
                    </Button>
                  </div>
                </div>
              ) : null}
              <p className="muted flex items-start gap-1.5">
                <Info size={11} className="mt-0.5 shrink-0" />
                Generated as <span className="mono text-slate-300">{user?.email}</span>. Each report is anchored in the integrity ledger.
              </p>
            </div>
          ) : (
            <EmptyState
              icon={FileText}
              title="Read-only access"
              message="Your role can download existing reports but cannot generate new ones. Ask an analyst or administrator."
            />
          )}
        </Card>

        <Card
          title="Generated reports"
          subtitle="Stored artifacts available for download"
          icon={FileText}
          bodyClass="p-0"
          actions={
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={list.refetch} loading={list.loading}>
              Refresh
            </Button>
          }
        >
          <DataTable
            columns={[
              { key: 'title', header: 'Title', render: (row) => (
                <span className="block min-w-0">
                  <span className="block truncate text-[11.5px] font-medium text-slate-200">{row.title}</span>
                  <span className="mono block text-[10px] text-slate-500">{row.report_type} · {row.range?.window || '—'}</span>
                </span>
              ) },
              { key: 'format', header: 'Format', width: '86px', render: (row) => <Badge tone={row.format === 'pdf' ? 'green' : 'purple'}>{row.format?.toUpperCase()}</Badge> },
              { key: 'size_bytes', header: 'Size', width: '88px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatBytes(row.size_bytes)}</span> },
              { key: 'threat_level', header: 'Threat level', width: '116px', render: (row) => {
                const level = row.summary?.threat_level
                if (!level) return <span className="text-slate-600">—</span>
                return <span className="badge" style={{ borderColor: `${riskColor(level)}66`, background: `${riskColor(level)}1a`, color: riskColor(level) }}>{level}</span>
              } },
              { key: 'created_by', header: 'Created by', width: '180px', hideBelow: 'lg:table-cell', render: (row) => <span className="mono truncate text-[10.5px] text-slate-400">{row.created_by || '—'}</span> },
              { key: 'created_at', header: 'Generated', width: '132px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.created_at)}>{timeAgo(row.created_at)}</span> },
              { key: 'actions', header: '', width: '150px', align: 'right', render: (row) => (
                <span className="flex items-center justify-end gap-1">
                  <Button size="xs" variant="secondary" icon={Download} onClick={(event) => { event.stopPropagation(); downloadReport(row, row.format) }}>Get</Button>
                  <Button size="xs" variant="ghost" icon={Eye} onClick={(event) => { event.stopPropagation(); setDetail(row) }}>View</Button>
                  {canGenerate ? (
                    <Button size="xs" variant="danger" icon={Trash2} onClick={(event) => { event.stopPropagation(); setPendingDelete(row) }} />
                  ) : null}
                </span>
              ) },
            ]}
            rows={rows}
            loading={list.loading}
            error={list.error}
            onRetry={list.refetch}
            pagination={list.data?.pagination}
            onPageChange={setPage}
            onRowClick={setDetail}
            empty={
              <EmptyState
                icon={FileText}
                title="No reports generated yet"
                message="Generate a PDF or CSV brief from the panel on the left. Reports are computed from live backend data and anchored in the integrity ledger."
              />
            }
          />
        </Card>
      </div>

      <ReportModal report={detail} onClose={() => setDetail(null)} onDownload={downloadReport} />

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => remove.run(pendingDelete.id)}
        busy={remove.busy}
        title="Delete this report?"
        confirmLabel="Delete report"
        message={`"${pendingDelete?.title}" and its stored artifact will be removed. The ledger entry that proves it existed is kept for auditability.`}
      />
    </div>
  )
}

function slug(value) {
  return String(value || 'report')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60)
}

function ReportModal({ report, onClose, onDownload }) {
  if (!report) return null
  const summary = report.summary || {}
  const kpis = summary.kpis || {}

  return (
    <Modal
      open
      onClose={onClose}
      title={report.title}
      subtitle={`${report.report_type} · ${report.range?.window || 'n/a'} window · generated ${formatDateTime(report.created_at)}`}
      icon={FileText}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Close</Button>
          {report.format === 'csv' ? (
            <Button variant="secondary" icon={FileSpreadsheet} onClick={() => onDownload(report, 'csv')}>Download CSV</Button>
          ) : (
            <Button variant="primary" icon={Download} onClick={() => onDownload(report, 'pdf')}>Download PDF</Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={report.format === 'pdf' ? 'green' : 'purple'}>{report.format?.toUpperCase()}</Badge>
          <Badge tone="slate">{formatBytes(report.size_bytes)}</Badge>
          {summary.threat_level ? (
            <span className="badge" style={{ borderColor: `${riskColor(summary.threat_level)}66`, background: `${riskColor(summary.threat_level)}1a`, color: riskColor(summary.threat_level) }}>
              threat level {summary.threat_level}
            </span>
          ) : null}
          {report.blockchain_event_id ? <Badge tone="cyan"><Hash size={9} /> ledger anchored</Badge> : null}
          <span className="muted">created by {report.created_by || '—'}</span>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: 'Flows analysed', value: formatNumber(kpis.flows) },
            { label: 'Detected threats', value: formatNumber(kpis.detected_threats) },
            { label: 'Critical alerts', value: formatNumber(kpis.critical_alerts) },
            { label: 'Anomalies', value: formatNumber(kpis.anomalies) },
            { label: 'Packets', value: formatNumber(kpis.packets) },
            { label: 'Traffic volume', value: formatBytes(kpis.traffic_bytes) },
            { label: 'Mean risk', value: formatPercent(kpis.mean_risk_score, 1) },
            { label: 'Forecast attacks', value: Number(kpis.forecasted_attacks ?? 0).toFixed(2) },
          ].map((item) => (
            <div key={item.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
              <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{item.label}</p>
              <p className="mt-0.5 text-base font-bold leading-none text-slate-100">{item.value}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-3 lg:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2 flex items-center gap-1.5"><ShieldAlert size={11} /> Alert summary</p>
            <KeyValue
              columns={2}
              items={[
                { label: 'Total alerts', value: formatNumber(summary.alerts?.total ?? 0), mono: true },
                { label: 'Critical open', value: formatNumber(summary.alerts?.critical_open ?? 0), mono: true },
                ...Object.entries(summary.alerts?.by_severity || {}).map(([key, value]) => ({ label: key, value: formatNumber(value), mono: true })),
              ]}
            />
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2 flex items-center gap-1.5"><BarChart3 size={11} /> Model &amp; integrity</p>
            <KeyValue
              columns={2}
              items={[
                { label: 'Active classifier', value: summary.model?.active_classifier?.name || summary.model?.name || '—' },
                { label: 'Accuracy', value: summary.model?.accuracy ? formatPercent(summary.model.accuracy, 2) : '—', mono: true },
                { label: 'Ledger entries', value: formatNumber(summary.blockchain?.total_events ?? 0), mono: true },
                { label: 'Verified', value: formatPercent((summary.blockchain?.verified_percentage ?? 0) / 100, 1), mono: true },
              ]}
            />
            {summary.blockchain?.verified_percentage !== undefined ? (
              <Progress className="mt-2" value={summary.blockchain.verified_percentage} max={100} tone="green" />
            ) : null}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <p className="panel-title mb-2 flex items-center gap-1.5"><CalendarClock size={11} /> Sections included ({report.sections?.length || 0})</p>
          <div className="flex flex-wrap gap-1.5">
            {(report.sections || []).map((section) => (
              <code key={section} className="mono rounded border border-slate-700/70 bg-slate-900/70 px-1.5 py-0.5 text-[10.5px] text-cyan-300">
                {String(section).replace(/_/g, ' ')}
              </code>
            ))}
          </div>
        </div>

        {summary.forecast_overall ? (
          <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/6 p-3">
            <p className="panel-title mb-1.5 text-cyan-300">Forecast captured in this report</p>
            <KeyValue
              columns={3}
              items={[
                { label: 'Horizon', value: `${summary.forecast_overall.horizon_minutes} minutes`, mono: true },
                { label: 'Probability', value: formatPercent(summary.forecast_overall.probability, 1), mono: true },
                { label: 'Risk level', value: String(summary.forecast_overall.risk_level || '—').toUpperCase() },
                { label: 'Leading threat', value: summary.forecast_overall.top_threat?.attack_type || '—' },
                { label: 'Confidence', value: formatPercent(summary.forecast_overall.confidence, 1), mono: true },
                { label: 'Expected events', value: Number(summary.forecast_overall.expected_attack_events ?? 0).toFixed(2), mono: true },
              ]}
            />
          </div>
        ) : null}
      </div>
    </Modal>
  )
}
