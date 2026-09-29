import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertOctagon,
  CheckCircle2,
  Download,
  Eye,
  FileWarning,
  Lock,
  MessageSquare,
  RefreshCw,
  UserCheck,
  Search,
  ShieldCheck,
  Siren,
  XCircle,
} from 'lucide-react'
import { alertsApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  CopyButton,
  DataTable,
  Drawer,
  EmptyState,
  ErrorState,
  Field,
  KeyValue,
  LoadingState,
  Progress,
  SearchInput,
  Select,
  SeverityBadge,
  StatCard,
  StatusBadge,
  Textarea,
} from '../components/ui'
import { CategoryBarChart, DonutChart } from '../components/charts/charts'
import { formatDateTime, formatNumber, formatPercent, shortHash, timeAgo } from '../utils/format'
import { attackColor, severityColor } from '../utils/theme'
import { ATTACK_TYPES, SEVERITIES, ALERT_STATUSES, WINDOWS } from '../utils/constants'

const STATUS_LABELS = {
  open: 'Open',
  reviewed: 'Reviewed',
  resolved: 'Resolved',
  false_positive: 'False positive',
}

export default function Alerts() {
  const { can } = useAuth()
  const toast = useToast()
  const [filters, setFilters] = useState({ severity: '', status: '', attack_type: '', origin: '', window: '7d', search: '' })
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [selectedId, setSelectedId] = useState(null)

  const params = useMemo(
    () => ({
      limit: page.limit,
      offset: page.offset,
      severity: filters.severity || undefined,
      status: filters.status || undefined,
      attack_type: filters.attack_type || undefined,
      origin: filters.origin || undefined,
      window: filters.window,
      search: filters.search || undefined,
    }),
    [filters, page.limit, page.offset],
  )

  const list = useApi(() => alertsApi.list(params), [params], { keepPrevious: true })
  const stats = useApi(() => alertsApi.stats({ window: filters.window }), [filters.window], { keepPrevious: true })

  const patch = (key) => (event) => {
    setFilters((current) => ({ ...current, [key]: event.target.value }))
    setPage((current) => ({ ...current, offset: 0, page: 1 }))
  }

  const exportCsv = async () => {
    try {
      const filename = await alertsApi.exportCsv()
      toast.success('Export ready', `${filename} downloaded.`)
    } catch (failure) {
      toast.error('Export failed', failure.message)
    }
  }

  const rows = list.data?.items || []
  const totals = stats.data || {}

  return (
    <div className="space-y-4">
      {/* severity summary */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {SEVERITIES.slice()
          .reverse()
          .map((severity) => (
            <button
              key={severity}
              type="button"
              onClick={() => setFilters((current) => ({ ...current, severity: current.severity === severity ? '' : severity }))}
              className="text-left"
              title={`Filter by ${severity} alerts`}
            >
              <StatCard
                label={`${severity} alerts`}
                value={formatNumber(totals.by_severity?.[severity] ?? 0)}
                icon={severity === 'critical' ? AlertOctagon : Siren}
                tone={severity === 'critical' ? 'red' : severity === 'high' ? 'amber' : severity === 'medium' ? 'amber' : 'slate'}
                loading={stats.loading && !totals.total}
                hint={filters.severity === severity ? 'filter active — click to clear' : 'click to filter'}
              />
            </button>
          ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <Card
          title="Triage queue"
          subtitle={`${formatNumber(list.data?.pagination?.total ?? 0)} alerts match the current filters · ${formatNumber(totals.open ?? 0)} open`}
          icon={Siren}
          bodyClass="p-0"
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => { list.refetch(); stats.refetch() }} loading={list.loading}>
                Refresh
              </Button>
              <Button size="sm" variant="secondary" icon={Download} onClick={exportCsv} disabled={!can('alerts.view')}>
                Export CSV
              </Button>
            </div>
          }
        >
          {/* filter bar */}
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/70 px-3 py-2.5">
            <SearchInput
              value={filters.search}
              onChange={(value) => {
                setFilters((current) => ({ ...current, search: value }))
                setPage((current) => ({ ...current, offset: 0, page: 1 }))
              }}
              placeholder="Search code, IP, title…"
              className="w-56"
            />
            <Select className="w-auto min-w-[128px] py-1.5 text-[11px]" value={filters.severity} placeholder="All severities" onChange={patch('severity')} options={SEVERITIES} />
            <Select
              className="w-auto min-w-[128px] py-1.5 text-[11px]"
              value={filters.status}
              placeholder="All statuses"
              onChange={patch('status')}
              options={ALERT_STATUSES.map((status) => ({ value: status, label: STATUS_LABELS[status] || status }))}
            />
            <Select className="w-auto min-w-[132px] py-1.5 text-[11px]" value={filters.attack_type} placeholder="All attack types" onChange={patch('attack_type')} options={ATTACK_TYPES} />
            <Select
              className="w-auto min-w-[124px] py-1.5 text-[11px]"
              value={filters.origin}
              placeholder="All origins"
              onChange={patch('origin')}
              options={[
                { value: 'detection', label: 'Detection' },
                { value: 'forecast', label: 'Forecast' },
                { value: 'anomaly', label: 'Anomaly' },
                { value: 'manual', label: 'Manual' },
              ]}
            />
            <Select className="w-auto min-w-[128px] py-1.5 text-[11px]" value={filters.window} onChange={patch('window')} options={WINDOWS} />
            {(filters.severity || filters.status || filters.attack_type || filters.origin || filters.search) && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setFilters({ severity: '', status: '', attack_type: '', origin: '', window: filters.window, search: '' })
                  setPage({ limit: page.limit, offset: 0, page: 1 })
                }}
              >
                Clear filters
              </Button>
            )}
          </div>

          <DataTable
            columns={[
              { key: 'alert_code', header: 'Alert', width: '132px', mono: true, render: (row) => <span className="text-cyan-300">{row.alert_code}</span> },
              { key: 'timestamp', header: 'Raised', width: '132px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.timestamp)}>{timeAgo(row.timestamp)}</span> },
              { key: 'severity', header: 'Severity', width: '104px', render: (row) => <SeverityBadge severity={row.severity} /> },
              { key: 'attack_type', header: 'Attack', width: '128px', render: (row) => <AttackBadge type={row.attack_type} /> },
              { key: 'title', header: 'Summary', render: (row) => (
                <span className="block min-w-0">
                  <span className="block truncate text-[11.5px] font-medium text-slate-200">{row.title}</span>
                  <span className="mono block truncate text-[10px] text-slate-500">
                    {row.source_ip ? `${row.source_ip} → ${row.destination_ip || '—'}` : row.origin === 'forecast' ? 'forecast-derived alert' : 'aggregate alert'}
                    {row.is_simulated ? ' · simulated data' : ''}
                  </span>
                </span>
              ) },
              { key: 'risk_score', header: 'Risk', width: '104px', align: 'right', sortable: true, render: (row) => (
                <span className="flex items-center justify-end gap-1.5">
                  <Progress className="w-10" value={Number(row.risk_score) * 100} max={100} tone={Number(row.risk_score) >= 0.5 ? 'red' : 'amber'} />
                  <span className="mono text-[10.5px] text-slate-300">{formatPercent(row.risk_score, 0)}</span>
                </span>
              ) },
              { key: 'confidence', header: 'Conf.', width: '68px', align: 'right', render: (row) => <span className="mono text-[10.5px] text-slate-400">{formatPercent(row.confidence, 0)}</span> },
              { key: 'status', header: 'Status', width: '104px', render: (row) => <StatusBadge status={row.status} /> },
              { key: 'blockchain_status', header: 'Ledger', width: '92px', hideBelow: 'xl:table-cell', render: (row) => (row.blockchain_event_id ? <StatusBadge status={row.blockchain_status || 'pending'} /> : <span className="text-slate-600">—</span>) },
            ]}
            rows={rows}
            loading={list.loading}
            error={list.error}
            onRetry={list.refetch}
            pagination={list.data?.pagination}
            onPageChange={setPage}
            onRowClick={(row) => setSelectedId(row.id)}
            selectedId={selectedId}
            empty={
              <EmptyState
                icon={ShieldCheck}
                title="No alerts match these filters"
                message="Either the window is quiet or the filters are too narrow. Widen the window, clear filters, or generate traffic in the simulation console."
                action={
                  <Link to="/simulation">
                    <Button variant="secondary" size="sm">Open simulation console</Button>
                  </Link>
                }
              />
            }
          />
        </Card>

        <div className="space-y-4">
          <Card title="Alerts by attack type" icon={AlertOctagon}>
            <CategoryBarChart
              data={Object.entries(totals.by_attack_type || {}).map(([name, value]) => ({ name, value }))}
              height={200}
              horizontal
              colorBy={(entry) => attackColor(entry.name)}
              emptyMessage="No alerts recorded yet."
            />
          </Card>
          <Card title="Workflow status" icon={CheckCircle2}>
            <DonutChart
              data={Object.entries(totals.by_status || {})
                .filter(([, value]) => value > 0)
                .map(([name, value]) => ({ name: STATUS_LABELS[name] || name, value }))}
              height={200}
              centerValue={formatNumber(totals.total ?? 0)}
              centerLabel="alerts"
              emptyMessage="No alerts to summarise."
            />
          </Card>
          <Card title="Triage guidance" icon={MessageSquare} dense>
            <ul className="space-y-2 text-[11px] leading-relaxed text-slate-400">
              <li>
                <span className="font-semibold text-slate-200">Open</span> — raised automatically by the detection or forecast pipeline and
                awaiting analyst review.
              </li>
              <li>
                <span className="font-semibold text-slate-200">Reviewed</span> — an analyst has confirmed the alert is worth tracking.
              </li>
              <li>
                <span className="font-semibold text-slate-200">Resolved</span> — mitigated; the action taken is stored in the audit log.
              </li>
              <li>
                <span className="font-semibold text-slate-200">False positive</span> — feedback retained for model review and tuning.
              </li>
              <li className="pt-1 text-slate-500">
                Every status change is written to the audit log and re-anchored in the integrity ledger.
              </li>
            </ul>
          </Card>
        </div>
      </div>

      <AlertDrawer alertId={selectedId} onClose={() => setSelectedId(null)} onChanged={() => { list.refetch(); stats.refetch() }} />
    </div>
  )
}

function AlertDrawer({ alertId, onClose, onChanged }) {
  const { can, user } = useAuth()
  const toast = useToast()
  const [note, setNote] = useState('')
  const detail = useApi(() => (alertId ? alertsApi.get(alertId) : Promise.resolve(null)), [alertId], { enabled: Boolean(alertId) })
  const alert = detail.data

  const triage = useAction(
    async ({ status, notes, assignedTo }) => {
      const result = await alertsApi.update(alertId, {
        status: status || undefined,
        notes: notes || undefined,
        assigned_to: assignedTo || undefined,
      })
      toast.success(
        'Alert updated',
        status ? `${alert?.alert_code || 'Alert'} is now ${status.replace('_', ' ')}.` : 'Analyst note saved to the alert history.',
      )
      setNote('')
      onChanged?.()
      detail.refetch()
      return result
    },
    { onError: (failure) => toast.error('Triage failed', failure.message) },
  )

  useEffect(() => {
    if (!alertId) setNote('')
  }, [alertId])

  if (!alertId) return null
  if (detail.loading && !alert) return <Drawer open onClose={onClose} title="Loading alert…"><LoadingState /></Drawer>
  if (detail.error && !alert) return <Drawer open onClose={onClose} title="Alert unavailable"><ErrorState error={detail.error} onRetry={detail.refetch} /></Drawer>
  if (!alert) return null

  const event = alert.blockchain_event
  const canTriage = can('alerts.triage')

  return (
    <Drawer
      open
      onClose={onClose}
      title={`${alert.alert_code} · ${alert.title}`}
      subtitle={`Raised ${formatDateTime(alert.timestamp)} (${timeAgo(alert.timestamp)}) · origin ${alert.origin}`}
      width="max-w-2xl"
      footer={
        canTriage ? (
          <div className="flex w-full flex-wrap items-center gap-2">
            <Button size="sm" variant="secondary" icon={Eye} loading={triage.busy} onClick={() => triage.run({ status: 'reviewed', notes: note })}>
              Mark reviewed
            </Button>
            <Button size="sm" variant="success" icon={CheckCircle2} loading={triage.busy} onClick={() => triage.run({ status: 'resolved', notes: note })}>
              Resolve
            </Button>
            <Button size="sm" variant="danger" icon={XCircle} loading={triage.busy} onClick={() => triage.run({ status: 'false_positive', notes: note })}>
              False positive
            </Button>
            <Button size="sm" variant="ghost" icon={MessageSquare} loading={triage.busy} disabled={!note.trim()} onClick={() => triage.run({ notes: note })}>
              Save note only
            </Button>
            <span className="muted ml-auto">triaging as {user?.email}</span>
          </div>
        ) : (
          <p className="muted">Your role can view alerts but cannot change their workflow state.</p>
        )
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <AttackBadge type={alert.attack_type} />
          <StatusBadge status={alert.status} />
          {alert.is_simulated ? <Badge tone="purple">simulation data</Badge> : null}
          {alert.blockchain_event_id ? <Badge tone="green"><Lock size={9} /> ledger anchored</Badge> : null}
        </div>

        {triage.error ? <ErrorState error={triage.error} compact /> : null}

        <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <p className="panel-title mb-1.5">Analyst description</p>
          <p className="text-xs leading-relaxed text-slate-300">{alert.description}</p>
        </div>

        {alert.recommendation ? (
          <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/8 p-3">
            <p className="panel-title mb-1.5 flex items-center gap-1.5 text-cyan-300">
              <ShieldCheck size={11} /> Recommended action
            </p>
            <p className="text-xs leading-relaxed text-cyan-100/90">{alert.recommendation}</p>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2">Detection evidence</p>
            <div className="space-y-2">
              <div>
                <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                  <span>Risk score</span>
                  <span className="font-mono text-slate-300">{formatPercent(alert.risk_score, 1)}</span>
                </div>
                <Progress value={Number(alert.risk_score) * 100} max={100} tone="red" />
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-slate-500">
                  <span>Model confidence</span>
                  <span className="font-mono text-slate-300">{formatPercent(alert.confidence, 1)}</span>
                </div>
                <Progress value={Number(alert.confidence) * 100} max={100} tone="cyan" />
              </div>
            </div>
            <p className="muted mt-2">Confidence reflects how certain the model is; it is not a guarantee.</p>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2">Related entities</p>
            <KeyValue
              columns={1}
              items={[
                { label: 'Source', value: alert.source_ip ? `${alert.source_ip}:${alert.source_port || '—'}` : 'not applicable (aggregate alert)', mono: Boolean(alert.source_ip) },
                { label: 'Destination', value: alert.destination_ip ? `${alert.destination_ip}:${alert.destination_port || '—'}` : 'not applicable', mono: Boolean(alert.destination_ip) },
                { label: 'Prediction', value: alert.prediction_id ? shortHash(alert.prediction_id, 8, 4) : '—', mono: true },
                { label: 'Traffic record', value: alert.traffic_record_id ? shortHash(alert.traffic_record_id, 8, 4) : '—', mono: true },
              ]}
            />
          </div>
        </div>

        {event ? (
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/6 p-3">
            <p className="panel-title mb-2 flex items-center gap-1.5 text-emerald-300">
              <Lock size={11} /> Integrity ledger entry #{event.chain_position}
            </p>
            <KeyValue
              columns={1}
              items={[
                { label: 'Event type', value: event.event_type, mono: true },
                { label: 'Event hash', value: event.event_hash, mono: true, node: <span className="flex items-center gap-2"><code className="mono break-all text-emerald-200">{event.event_hash}</code><CopyButton value={event.event_hash} label="hash" /></span> },
                { label: 'Previous hash', value: event.prev_hash, mono: true, node: <code className="mono break-all text-slate-400">{event.prev_hash || 'genesis'}</code> },
                { label: 'Anchor mode', value: event.anchor_mode || 'local', mono: true },
                { label: 'Transaction', value: event.tx_hash || 'not anchored on-chain', mono: true },
              ]}
            />
            <div className="mt-2.5 flex flex-wrap gap-2">
              <Link to={`/blockchain?event=${event.id}`}>
                <Button size="sm" variant="secondary">Open in ledger</Button>
              </Link>
              <StatusBadge status={alert.blockchain_status || event.verification_status} />
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-1 flex items-center gap-1.5"><FileWarning size={11} className="text-amber-300" /> No ledger entry</p>
            <p className="muted">This alert was not anchored. Anchoring happens automatically for detection and forecast alerts.</p>
          </div>
        )}

        <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <p className="panel-title mb-2">Workflow history</p>
          <KeyValue
            columns={2}
            items={[
              { label: 'Reviewed by', value: alert.reviewed_by || '—' },
              { label: 'Reviewed at', value: alert.reviewed_at ? formatDateTime(alert.reviewed_at) : '—' },
              { label: 'Resolved by', value: alert.resolved_by || '—' },
              { label: 'Resolved at', value: alert.resolved_at ? formatDateTime(alert.resolved_at) : '—' },
            ]}
          />
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="panel-title">Ownership</p>
            {canTriage ? (
              <Button
                size="xs"
                variant="secondary"
                icon={UserCheck}
                loading={triage.busy}
                onClick={() => triage.run({ assignedTo: user?.email })}
              >
                Assign to me
              </Button>
            ) : null}
          </div>
          <KeyValue
            className="mt-2"
            columns={2}
            items={[
              { label: 'Assigned to', value: alert.assigned_to || 'unassigned' },
              { label: 'Current status', value: STATUS_LABELS[alert.status] || alert.status },
            ]}
          />
          {alert.notes ? (
            <div className="mt-2.5 rounded-lg border border-slate-800 bg-slate-900/60 p-2.5">
              <p className="text-[10px] uppercase tracking-wide text-slate-500">Latest analyst note</p>
              <p className="mt-1 whitespace-pre-wrap text-[11.5px] leading-relaxed text-slate-200">{alert.notes}</p>
            </div>
          ) : null}
        </div>

        {(alert.history || []).length ? (
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2">Triage trail ({alert.history.length})</p>
            <ol className="space-y-1.5">
              {[...alert.history].reverse().map((entry, index) => (
                <li key={`${entry.at}-${index}`} className="rounded-lg border border-slate-800/70 bg-slate-900/40 px-2.5 py-1.5">
                  <p className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-200">
                    <StatusBadge status={entry.action === 'note' ? 'reviewed' : entry.action} />
                    <span className="mono text-[10px] text-slate-500">{formatDateTime(entry.at)}</span>
                    <span className="text-slate-400">by {entry.actor}</span>
                  </p>
                  {entry.note ? <p className="muted mt-1 whitespace-pre-wrap">{entry.note}</p> : null}
                  {entry.assigned_to ? <p className="muted mt-0.5">assigned to {entry.assigned_to}</p> : null}
                </li>
              ))}
            </ol>
          </div>
        ) : null}

        {canTriage ? (
          <Field label="Analyst note (stored with the status change)" hint="Recorded in the audit log alongside your identity.">
            <Textarea rows={3} value={note} onChange={(event) => setNote(event.target.value)} placeholder="e.g. Confirmed volumetric flood from AS12345; rate limiting applied at edge." />
          </Field>
        ) : null}
      </div>
    </Drawer>
  )
}
