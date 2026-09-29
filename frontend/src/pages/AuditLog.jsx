import { useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  FileSpreadsheet,
  Fingerprint,
  Filter,
  Hash,
  Info,
  Link2,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  UserCog,
  XCircle,
} from 'lucide-react'
import { auditApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useToast } from '../context/ToastContext'
import {
  Badge,
  Button,
  Card,
  DataTable,
  Drawer,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  SearchInput,
  Select,
  StatCard,
} from '../components/ui'
import { DonutChart } from '../components/charts/charts'
import { formatDateTime, formatNumber, timeAgo } from '../utils/format'

const WINDOW_OPTIONS = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'all', label: 'All time' },
]

const OUTCOME_OPTIONS = [
  { value: 'success', label: 'Success only' },
  { value: 'failure', label: 'Failures only' },
]

const CATEGORY_TONES = {
  auth: 'cyan',
  dataset: 'purple',
  model: 'green',
  prediction: 'blue',
  alert: 'amber',
  blockchain: 'pink',
  admin: 'red',
  simulation: 'orange',
  report: 'teal',
  system: 'slate',
}

export default function AuditLog() {
  const toast = useToast()
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [filters, setFilters] = useState({ search: '', category: '', action: '', outcome: '', window: '7d' })
  const [selected, setSelected] = useState(null)

  const params = useMemo(
    () => ({
      limit: page.limit,
      offset: page.offset,
      search: filters.search || undefined,
      category: filters.category || undefined,
      action: filters.action || undefined,
      outcome: filters.outcome || undefined,
      window: filters.window || undefined,
    }),
    [page.limit, page.offset, filters],
  )

  const logs = useApi(() => auditApi.list(params), [params], { keepPrevious: true })
  const categories = useApi(() => auditApi.categories(), [])

  const verify = useAction(
    async () => {
      const result = await auditApi.verify({ limit: 300 })
      if (result.intact) {
        toast.success('Audit chain intact', `${formatNumber(result.checked)} most recent entries recomputed and matched.`)
      } else {
        toast.error('Audit chain broken', `${result.broken_entries?.length || 0} entries failed hash or link verification.`)
      }
      return result
    },
    { onError: (failure) => toast.error('Verification failed', failure.message) },
  )

  const exportCsv = useAction(
    async () => {
      const filename = await auditApi.exportCsv({ window: filters.window || '7d', category: filters.category || undefined, limit: 5000 })
      toast.success('Export started', `${filename} — up to 5,000 entries with the current filters.`)
      return filename
    },
    { onError: (failure) => toast.error('Export failed', failure.message) },
  )

  const rows = logs.data?.items || []
  const stats = logs.data?.stats || categories.data?.stats || {}
  const brokenIds = useMemo(
    () => new Set((verify.result?.broken_entries || []).map((entry) => entry.log_id)),
    [verify.result],
  )

  const update = (key) => (event) => {
    const value = event?.target ? event.target.value : event
    setPage({ limit: page.limit, offset: 0, page: 1 })
    setFilters((current) => ({ ...current, [key]: value }))
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Audit entries (all time)" value={formatNumber(stats.total ?? 0)} icon={ScrollText} tone="cyan" loading={categories.loading && !categories.data} />
        <StatCard label="Matching current filters" value={formatNumber(logs.data?.pagination?.total ?? rows.length)} icon={Filter} tone="green" hint={`${filters.window} window`} />
        <StatCard
          label="Categories seen"
          value={formatNumber(Object.keys(stats.by_category || {}).length)}
          icon={Activity}
          tone="purple"
          hint={Object.keys(stats.by_category || {}).slice(0, 4).join(', ') || undefined}
        />
        <StatCard
          label="Chain integrity"
          value={verify.result ? (verify.result.intact ? 'INTACT' : 'BROKEN') : 'not checked'}
          icon={ShieldCheck}
          tone={verify.result ? (verify.result.intact ? 'green' : 'red') : 'slate'}
          hint={verify.result ? `${formatNumber(verify.result.checked)} entries recomputed · ${timeAgo(verify.result.verified_at)}` : 'Run verification to recompute hashes'}
        />
      </div>

      <Card title="Filters" subtitle="Audit access is restricted to administrators" icon={Filter} dense>
        <div className="grid gap-2.5 lg:grid-cols-5">
          <SearchInput value={filters.search} onChange={(value) => { setPage({ limit: page.limit, offset: 0, page: 1 }); setFilters((c) => ({ ...c, search: value })) }} placeholder="Search email, action, resource…" />
          <Select
            value={filters.category}
            onChange={update('category')}
            placeholder="All categories"
            options={(categories.data?.items || Object.keys(CATEGORY_TONES)).map((category) => ({ value: category, label: category }))}
          />
          <input
            className="input mono"
            placeholder="Exact action, e.g. auth.login"
            value={filters.action}
            onChange={update('action')}
          />
          <Select value={filters.outcome} onChange={update('outcome')} placeholder="Any outcome" options={OUTCOME_OPTIONS} />
          <Select value={filters.window} onChange={update('window')} options={WINDOW_OPTIONS} />
        </div>
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" icon={ShieldCheck} loading={verify.busy} onClick={verify.run}>Verify hash chain</Button>
          <Button size="sm" variant="ghost" icon={FileSpreadsheet} loading={exportCsv.busy} onClick={exportCsv.run}>Export CSV</Button>
          <Button size="sm" variant="ghost" icon={RefreshCw} onClick={logs.refetch} loading={logs.loading}>Refresh</Button>
          {(filters.search || filters.category || filters.action || filters.outcome || filters.window !== '7d') ? (
            <Button
              size="sm"
              variant="ghost"
              icon={XCircle}
              onClick={() => { setPage({ limit: page.limit, offset: 0, page: 1 }); setFilters({ search: '', category: '', action: '', outcome: '', window: '7d' }) }}
            >
              Clear filters
            </Button>
          ) : null}
        </div>
      </Card>

      {verify.result ? (
        <div className={`rounded-2xl border p-3.5 ${verify.result.intact ? 'border-emerald-500/35 bg-emerald-500/8' : 'border-rose-500/40 bg-rose-500/8'}`}>
          <div className="flex flex-wrap items-start gap-3">
            {verify.result.intact ? (
              <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-emerald-300" />
            ) : (
              <AlertTriangle size={18} className="mt-0.5 shrink-0 text-rose-300" />
            )}
            <div className="min-w-0 flex-1">
              <p className={`text-xs font-bold ${verify.result.intact ? 'text-emerald-200' : 'text-rose-200'}`}>
                {verify.result.intact
                  ? `Audit chain intact — ${formatNumber(verify.result.checked)} entries verified`
                  : `Audit chain broken — ${verify.result.broken_entries?.length || 0} entries failed verification`}
              </p>
              <p className="muted mt-1">
                {formatNumber(verify.result.checked)} of {formatNumber(verify.result.total_entries)} stored entries were recomputed at {formatDateTime(verify.result.verified_at)}.
                Each entry's <span className="mono text-slate-300">integrity_hash</span> covers its own content plus the previous entry's hash, so editing or deleting a historical
                record breaks every link after it.
              </p>
              {verify.result.broken_entries?.length ? (
                <div className="mt-2 overflow-x-auto rounded-lg border border-rose-500/25">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Entry</th>
                        <th>Action</th>
                        <th className="text-center">Own hash</th>
                        <th className="text-center">Chain link</th>
                      </tr>
                    </thead>
                    <tbody>
                      {verify.result.broken_entries.map((entry) => (
                        <tr key={entry.log_id}>
                          <td className="mono text-[10.5px] text-slate-400">{entry.log_id}</td>
                          <td className="mono text-[10.5px] text-slate-200">{entry.action}</td>
                          <td className="text-center">{entry.hash_ok ? <CheckCircle2 size={12} className="mx-auto text-emerald-400" /> : <XCircle size={12} className="mx-auto text-rose-400" />}</td>
                          <td className="text-center">{entry.link_ok ? <CheckCircle2 size={12} className="mx-auto text-emerald-400" /> : <XCircle size={12} className="mx-auto text-rose-400" />}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </div>
            <Button size="sm" variant="ghost" onClick={() => verify.setData(null)}>Dismiss</Button>
          </div>
        </div>
      ) : null}
      {verify.error ? <ErrorState error={verify.error} compact /> : null}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,320px)]">
        <Card title="Audit trail" subtitle="Newest entries first" icon={ScrollText} bodyClass="p-0">
          <DataTable
            columns={[
              { key: 'timestamp', header: 'When', width: '136px', sortable: true, render: (row) => (
                <span className="block">
                  <span className="mono block text-[10.5px] text-slate-300">{formatDateTime(row.timestamp)}</span>
                  <span className="muted block">{timeAgo(row.timestamp)}</span>
                </span>
              ) },
              { key: 'user_email', header: 'Actor', width: '190px', render: (row) => (
                <span className="block min-w-0">
                  <span className="block truncate text-[11px] text-slate-200">{row.user_email || 'system'}</span>
                  {row.user_role ? <Badge tone={row.user_role === 'admin' ? 'red' : row.user_role === 'analyst' ? 'cyan' : 'slate'}>{row.user_role}</Badge> : null}
                </span>
              ) },
              { key: 'action', header: 'Action', render: (row) => (
                <span className="block min-w-0">
                  <span className="mono block truncate text-[11px] text-cyan-300">{row.action}</span>
                  <span className="mono block truncate text-[10px] text-slate-500">
                    {row.resource ? `${row.resource}${row.resource_id ? ` · ${row.resource_id}` : ''}` : '—'}
                  </span>
                </span>
              ) },
              { key: 'category', header: 'Category', width: '112px', render: (row) => <Badge tone={CATEGORY_TONES[row.category] || 'slate'}>{row.category || '—'}</Badge> },
              { key: 'outcome', header: 'Outcome', width: '96px', render: (row) => (
                row.outcome === 'failure'
                  ? <Badge tone="red"><XCircle size={9} /> failure</Badge>
                  : <Badge tone="green"><CheckCircle2 size={9} /> success</Badge>
              ) },
              { key: 'ip_address', header: 'Source IP', width: '128px', hideBelow: 'lg:table-cell', render: (row) => <span className="mono text-[10.5px] text-slate-400">{row.ip_address || '—'}</span> },
              { key: 'integrity_hash', header: 'Integrity hash', width: '128px', hideBelow: 'xl:table-cell', render: (row) => (
                <span className="flex items-center gap-1">
                  <Hash size={9} className={brokenIds.has(row.id) ? 'text-rose-400' : 'text-slate-600'} />
                  <code className={`mono truncate text-[10px] ${brokenIds.has(row.id) ? 'text-rose-300' : 'text-slate-500'}`}>{String(row.integrity_hash || '').slice(0, 12)}</code>
                </span>
              ) },
              { key: 'view', header: '', width: '64px', align: 'right', render: () => <Button size="xs" variant="ghost" icon={Eye} /> },
            ]}
            rows={rows}
            loading={logs.loading}
            error={logs.error}
            onRetry={logs.refetch}
            pagination={logs.data?.pagination}
            onPageChange={setPage}
            onRowClick={setSelected}
            selectedId={selected?.id}
            empty={
              <EmptyState
                icon={ScrollText}
                title="No audit entries match these filters"
                message="Widen the time window or clear the filters. Every privileged action on the platform writes an entry here."
              />
            }
          />
        </Card>

        <div className="space-y-4">
          <Card title="Entries by category" subtitle="All-time distribution" icon={Activity} dense>
            {categories.loading && !categories.data ? (
              <LoadingState label="Loading audit statistics…" />
            ) : categories.error ? (
              <ErrorState error={categories.error} onRetry={categories.refetch} compact />
            ) : Object.keys(stats.by_category || {}).length ? (
              <>
                <DonutChart
                  data={Object.entries(stats.by_category).map(([name, value]) => ({ name, value }))}
                  height={200}
                  formatter={(value) => formatNumber(value)}
                />
                <ul className="mt-2 space-y-1">
                  {Object.entries(stats.by_category)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, value]) => (
                      <li key={name}>
                        <button
                          type="button"
                          className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left transition hover:bg-slate-800/60"
                          onClick={() => update('category')({ target: { value: filters.category === name ? '' : name } })}
                        >
                          <Badge tone={CATEGORY_TONES[name] || 'slate'}>{name}</Badge>
                          <span className="mono ml-auto text-[10.5px] text-slate-400">{formatNumber(value)}</span>
                        </button>
                      </li>
                    ))}
                </ul>
              </>
            ) : (
              <EmptyState icon={Activity} title="No audit statistics" message="Entries appear once privileged actions are performed." />
            )}
          </Card>

          <Card title="How integrity works" icon={Fingerprint} dense>
            <ol className="space-y-2">
              {[
                { icon: Hash, text: 'Every entry is hashed with SHA-256 over its timestamp, actor, action, resource, outcome, metadata and the previous entry hash.' },
                { icon: Link2, text: 'Because each hash covers the previous one, the log forms a chain: altering or deleting a historical record invalidates every later link.' },
                { icon: ShieldCheck, text: '"Verify hash chain" recomputes the most recent 300 entries server side and reports hash failures and link failures separately.' },
                { icon: Download, text: 'The CSV export carries the same hashes, so an exported log can be re-verified offline or by a third party.' },
              ].map((item, index) => (
                <li key={index} className="flex gap-2">
                  <item.icon size={12} className="mt-0.5 shrink-0 text-cyan-400" />
                  <p className="muted">{item.text}</p>
                </li>
              ))}
            </ol>
            <p className="muted mt-2 flex items-start gap-1.5">
              <Info size={11} className="mt-0.5 shrink-0" />
              The audit chain is separate from the security-event ledger; anchors for high-value events are written on the Integrity Ledger page.
            </p>
          </Card>
        </div>
      </div>

      <AuditDrawer entry={selected} onClose={() => setSelected(null)} broken={selected ? brokenIds.has(selected.id) : false} />
    </div>
  )
}

function AuditDrawer({ entry, onClose, broken }) {
  const toast = useToast()
  if (!entry) return null

  const copy = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success('Copied', `${label} copied to the clipboard.`)
    } catch {
      toast.error('Copy failed', 'Your browser blocked clipboard access — select the text manually.')
    }
  }

  return (
    <Drawer
      open
      onClose={onClose}
      title={entry.action}
      subtitle={`${entry.category || 'uncategorised'} · ${formatDateTime(entry.timestamp)}`}
      width="max-w-2xl"
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          {entry.outcome === 'failure' ? <Badge tone="red">failure</Badge> : <Badge tone="green">success</Badge>}
          <Badge tone={CATEGORY_TONES[entry.category] || 'slate'}>{entry.category}</Badge>
          {broken ? <Badge tone="red"><AlertTriangle size={9} /> failed chain verification</Badge> : null}
          {entry.resource ? <Badge tone="slate">{entry.resource}{entry.resource_id ? ` · ${entry.resource_id}` : ''}</Badge> : null}
        </div>

        <KeyValue
          columns={2}
          items={[
            { label: 'Entry id', value: entry.id, mono: true },
            { label: 'Timestamp', value: formatDateTime(entry.timestamp), mono: true },
            { label: 'Actor', value: entry.user_email || 'system' },
            { label: 'Role at the time', value: entry.user_role || '—' },
            { label: 'User id', value: entry.user_id || '—', mono: true },
            { label: 'Source IP', value: entry.ip_address || 'not captured', mono: true },
          ]}
        />

        <div>
          <p className="panel-title mb-2 flex items-center gap-1.5"><Fingerprint size={11} /> Integrity chain</p>
          <div className="space-y-2">
            {[
              { label: 'integrity_hash (this entry)', value: entry.integrity_hash },
              { label: 'prev_hash (previous entry)', value: entry.prev_hash },
            ].map((item) => (
              <div key={item.label}>
                <p className="muted mb-1">{item.label}</p>
                <div className="flex items-center gap-2">
                  <code className="input mono flex-1 break-all text-[10.5px] text-cyan-200">{item.value || 'genesis'}</code>
                  <Button size="sm" variant="secondary" icon={Copy} onClick={() => copy(item.value || '', item.label)}>Copy</Button>
                </div>
              </div>
            ))}
          </div>
          <p className="muted mt-2 flex items-start gap-1.5">
            <UserCog size={11} className="mt-0.5 shrink-0" />
            Hashes are computed server side over the canonical entry content. The frontend only displays them — it never decides whether an entry is trustworthy.
          </p>
        </div>

        <div>
          <p className="panel-title mb-2">Metadata captured with this action</p>
          {entry.metadata && Object.keys(entry.metadata).length ? (
            <pre className="mono max-h-72 overflow-auto rounded-lg border border-slate-800 bg-[#050810] p-2.5 text-[10.5px] leading-relaxed text-slate-300">{JSON.stringify(entry.metadata, null, 2)}</pre>
          ) : (
            <p className="muted">No additional metadata was recorded for this action.</p>
          )}
        </div>
      </div>
    </Drawer>
  )
}
