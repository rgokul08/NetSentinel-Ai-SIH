import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  BadgeCheck,
  Boxes,
  Check,
  CheckCircle2,
  ChevronRight,
  FileCode2,
  Fingerprint,
  Hash,
  Info,
  Link2,
  Lock,
  Play,
  Plus,
  RefreshCw,
  Repeat,
  ScanSearch,
  ShieldCheck,
  X,
} from 'lucide-react'
import { blockchainApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import {
  Badge,
  Button,
  Card,
  CopyButton,
  DataTable,
  Drawer,
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
  Switch,
  Textarea,
} from '../components/ui'
import { DonutChart } from '../components/charts/charts'
import { formatDateTime, formatNumber, formatPercent, shortHash, timeAgo } from '../utils/format'

const GENESIS = '0'.repeat(64)

export default function Blockchain() {
  const { can, user } = useAuth()
  const toast = useToast()
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [eventType, setEventType] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedId, setSelectedId] = useState(params.get('event') || null)
  const [chainResult, setChainResult] = useState(null)
  const [recordOpen, setRecordOpen] = useState(false)

  const status = useApi(() => blockchainApi.status(), [], { keepPrevious: true })
  const contract = useApi(() => blockchainApi.contract(), [], { keepPrevious: true })
  const events = useApi(
    () => blockchainApi.events({ limit: page.limit, offset: page.offset, event_type: eventType || undefined, verification_status: statusFilter || undefined }),
    [page.limit, page.offset, eventType, statusFilter],
    { keepPrevious: true },
  )

  const verifyChain = useAction(
    async () => {
      const result = await blockchainApi.verifyChain()
      setChainResult(result)
      status.refetch()
      events.refetch()
      if (result.intact) toast.success('Chain intact', `${formatNumber(result.checked)} entries re-hashed; every link matches.`)
      else toast.warning('Tamper detected', `${result.broken_count} of ${formatNumber(result.checked)} entries failed verification.`)
      return result
    },
    { onError: (failure) => toast.error('Chain verification failed', failure.message) },
  )

  const retry = useAction(
    async () => {
      const result = await blockchainApi.retryPending()
      toast.info('Anchor retry', result.message || `${result.attempted} pending entries processed.`)
      status.refetch()
      return result
    },
    { onError: (failure) => toast.error('Retry failed', failure.message) },
  )

  useEffect(() => {
    const target = params.get('event')
    if (target) setSelectedId(target)
  }, [params])

  const stats = status.data?.ledger || {}
  const anchor = status.data?.anchor || {}
  const typeBreakdown = useMemo(
    () => Object.entries(stats.by_event_type || {}).map(([name, value]) => ({ name, value })),
    [stats.by_event_type],
  )

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Ledger entries" value={formatNumber(stats.total_events ?? 0)} icon={Boxes} tone="cyan" hint={`${formatNumber(events.data?.pagination?.total ?? 0)} shown by filter`} />
        <StatCard label="Verified" value={formatNumber(stats.verified ?? 0)} icon={BadgeCheck} tone="green" hint={`${formatPercent((stats.verified_percentage ?? 0) / 100, 1)} of the ledger`} />
        <StatCard label="Pending" value={formatNumber(stats.pending ?? 0)} icon={Repeat} tone="amber" hint="not verified or awaiting anchor" />
        <StatCard label="Failed verification" value={formatNumber(stats.failed ?? 0)} icon={AlertTriangle} tone={stats.failed ? 'red' : 'slate'} hint={`${formatNumber(stats.tamper_demo_events ?? 0)} tamper-demo entries`} />
        <StatCard label="Anchor mode" value={anchor.mode === 'evm' ? 'On-chain' : 'Local chain'} icon={anchor.connected ? Link2 : Lock} tone={anchor.connected ? 'green' : 'purple'} hint={anchor.configured ? `chain ${anchor.chain_id ?? 'n/a'}` : 'RPC not configured'} />
        <StatCard label="Integrity" value={Number(stats.verified_percentage ?? 0).toFixed(1)} unit="%" icon={ShieldCheck} tone={Number(stats.verified_percentage ?? 0) >= 99.9 ? 'green' : 'amber'} footer={<Progress value={stats.verified_percentage ?? 0} max={100} tone={Number(stats.verified_percentage ?? 0) >= 99.9 ? 'green' : 'amber'} />} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Card
          title="Tamper-evident ledger"
          subtitle="SHA-256 hash chain over security events; payloads stay off-chain, only hashes and verification metadata are anchored"
          icon={Lock}
          bodyClass="p-0"
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => { status.refetch(); events.refetch() }} loading={status.loading}>Refresh</Button>
              <Button size="sm" variant="secondary" icon={ShieldCheck} loading={verifyChain.busy} onClick={verifyChain.run}>Verify entire chain</Button>
              {can('blockchain.record') ? (
                <Button size="sm" variant="primary" icon={Plus} onClick={() => setRecordOpen(true)}>Record event</Button>
              ) : null}
            </div>
          }
        >
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/70 px-3 py-2.5">
            <Select
              className="w-auto min-w-[170px] py-1.5 text-[11px]"
              value={eventType}
              placeholder="All event types"
              onChange={(event) => { setEventType(event.target.value); setPage({ ...page, offset: 0, page: 1 }) }}
              options={Object.keys(stats.by_event_type || {})}
            />
            <Select
              className="w-auto min-w-[150px] py-1.5 text-[11px]"
              value={statusFilter}
              placeholder="All statuses"
              onChange={(event) => { setStatusFilter(event.target.value); setPage({ ...page, offset: 0, page: 1 }) }}
              options={['verified', 'pending', 'failed']}
            />
            <span className="muted ml-auto">
              {status.data?.note ? truncateNote(status.data.note) : ''}
            </span>
          </div>

          <DataTable
            columns={[
              { key: 'chain_position', header: '#', width: '58px', align: 'right', sortable: true, mono: true },
              { key: 'event_type', header: 'Event type', width: '150px', render: (row) => (
                <span className="flex items-center gap-1.5">
                  <Badge tone={row.event_type === 'alert' ? 'red' : row.event_type.startsWith('model') ? 'purple' : row.event_type === 'forecast_run' ? 'cyan' : 'slate'}>
                    {row.event_type.replace(/_/g, ' ')}
                  </Badge>
                  {row.is_tamper_demo ? <Badge tone="amber">tamper demo</Badge> : null}
                </span>
              ) },
              { key: 'event_hash', header: 'Event hash', render: (row) => (
                <span className="flex items-center gap-1.5">
                  <code className="mono truncate text-[10.5px] text-emerald-300/90">{shortHash(row.event_hash, 14, 8)}</code>
                  <CopyButton value={row.event_hash} label="" />
                </span>
              ) },
              { key: 'prev_hash', header: 'Previous hash', width: '150px', hideBelow: 'xl:table-cell', render: (row) => (
                <code className="mono truncate text-[10.5px] text-slate-500">{row.prev_hash === GENESIS ? 'genesis' : shortHash(row.prev_hash, 10, 6)}</code>
              ) },
              { key: 'anchor_mode', header: 'Anchor', width: '86px', render: (row) => <Badge tone={row.anchor_mode === 'evm' ? 'green' : 'slate'}>{row.anchor_mode}</Badge> },
              { key: 'tx_hash', header: 'Tx / block', width: '128px', hideBelow: 'xl:table-cell', render: (row) => (row.tx_hash ? <code className="mono text-[10px] text-cyan-300">{shortHash(row.tx_hash, 8, 6)}</code> : <span className="text-slate-600">—</span>) },
              { key: 'verification_status', header: 'Verification', width: '116px', render: (row) => <StatusBadge status={row.verification_status} /> },
              { key: 'recorded_by', header: 'Recorded by', width: '170px', hideBelow: 'lg:table-cell', render: (row) => <span className="mono truncate text-[10.5px] text-slate-400">{row.recorded_by || '—'}</span> },
              { key: 'created_at', header: 'Recorded', width: '128px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.created_at)}>{timeAgo(row.created_at)}</span> },
            ]}
            rows={events.data?.items || []}
            loading={events.loading}
            error={events.error}
            onRetry={events.refetch}
            pagination={events.data?.pagination}
            onPageChange={setPage}
            onRowClick={(row) => setSelectedId(row.id)}
            selectedId={selectedId}
            empty={<EmptyState icon={Boxes} title="No ledger entries match" message="Adjust the filters, or record a security event manually." />}
          />
        </Card>

        <div className="space-y-4">
          {chainResult ? (
            <Card
              title="Chain verification result"
              subtitle={`${formatNumber(chainResult.checked)} entries re-hashed ${chainResult.verified_at ? timeAgo(chainResult.verified_at) : ''}`}
              icon={chainResult.intact ? CheckCircle2 : AlertTriangle}
              dense
            >
              <div className={`rounded-lg border p-3 ${chainResult.intact ? 'border-emerald-500/35 bg-emerald-500/8' : 'border-rose-500/35 bg-rose-500/8'}`}>
                <p className={`text-sm font-bold ${chainResult.intact ? 'text-emerald-300' : 'text-rose-300'}`}>
                  {chainResult.intact ? 'Chain intact' : `Tamper evidence found (${chainResult.broken_count})`}
                </p>
                <p className={`mt-1 text-[11px] leading-relaxed ${chainResult.intact ? 'text-emerald-200/80' : 'text-rose-200/85'}`}>
                  {chainResult.intact
                    ? 'Every stored hash was recomputed from its payload and matched, and every entry links to the previous hash.'
                    : `${chainResult.hash_failures} hash mismatch(es) and ${chainResult.link_failures} broken link(s). The entries below no longer reproduce their recorded hash.`}
                </p>
              </div>
              {(chainResult.broken_entries || []).length ? (
                <ul className="mt-2.5 space-y-1.5">
                  {chainResult.broken_entries.map((entry) => (
                    <li key={entry.event_id} className="rounded-lg border border-rose-500/25 bg-slate-950/50 p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="mono text-[10.5px] text-rose-300">#{entry.chain_position} · {entry.event_type}</span>
                        {entry.is_tamper_demo ? <Badge tone="amber">tamper demo</Badge> : <Badge tone="red">unexpected</Badge>}
                      </div>
                      <p className="muted mt-1">hash {entry.hash_ok ? 'ok' : 'MISMATCH'} · link {entry.link_ok ? 'ok' : 'BROKEN'}</p>
                      <p className="mono mt-1 break-all text-[9.5px] text-slate-500">stored {entry.stored_hash}</p>
                      <p className="mono break-all text-[9.5px] text-rose-400/80">recomputed {entry.recomputed_hash}</p>
                      <Button size="xs" variant="ghost" className="mt-1.5" onClick={() => setSelectedId(entry.event_id)}>
                        Open entry <ChevronRight size={10} />
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </Card>
          ) : null}

          <Card title="Anchoring configuration" icon={Link2} dense>
            <div className="space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <StatusBadge status={anchor.connected ? 'online' : anchor.configured ? 'pending' : 'unavailable'} />
                <Badge tone={anchor.mode === 'evm' ? 'green' : 'purple'}>{anchor.mode}</Badge>
              </div>
              <KeyValue
                columns={1}
                items={[
                  { label: 'ABI source', value: anchor.abi_source || contract.data?.abi_source || 'embedded', mono: true },
                  { label: 'Contract address', value: anchor.contract_address || contract.data?.contract_address || 'not configured', mono: true },
                  { label: 'Chain id', value: anchor.chain_id ?? contract.data?.chain_id ?? 'n/a', mono: true },
                  { label: 'Recorder address', value: anchor.recorder_address || contract.data?.recorder_address || 'n/a', mono: true },
                  { label: 'On-chain events', value: contract.data?.onchain_event_count ?? 'n/a', mono: true },
                ]}
              />
              {anchor.reason ? (
                <p className="rounded-lg border border-amber-500/25 bg-amber-500/8 p-2 text-[10.5px] leading-relaxed text-amber-200">
                  <AlertTriangle size={11} className="mr-1 inline" />
                  {anchor.reason}
                </p>
              ) : null}
              <p className="muted">
                Without an RPC the platform falls back to the local hash chain, which is still tamper-evident: any payload edit breaks the
                recomputed SHA-256 and the <span className="mono">prev_hash</span> linkage.
              </p>
              {can('blockchain.record') ? (
                <Button size="sm" variant="secondary" icon={Repeat} loading={retry.busy} onClick={retry.run} className="w-full">
                  Retry pending anchors
                </Button>
              ) : null}
            </div>
          </Card>

          <Card title="Event type mix" icon={Fingerprint}>
            <DonutChart data={typeBreakdown} height={210} centerValue={formatNumber(stats.total_events ?? 0)} centerLabel="entries" emptyMessage="No ledger entries yet." />
          </Card>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Smart contract interface" subtitle={contract.data?.source_path || 'blockchain/contracts/SecurityEventRegistry.sol'} icon={FileCode2} dense>
          {contract.loading && !contract.data ? (
            <LoadingState label="Loading contract metadata…" />
          ) : contract.error ? (
            <ErrorState error={contract.error} onRetry={contract.refetch} compact />
          ) : (
            <div className="space-y-3">
              <div>
                <p className="panel-title mb-1.5">Functions ({contract.data?.functions?.length || 0})</p>
                <div className="flex flex-wrap gap-1.5">
                  {(contract.data?.functions || []).map((name) => (
                    <code key={name} className="mono rounded border border-slate-700/70 bg-slate-950/60 px-1.5 py-0.5 text-[10.5px] text-cyan-300">
                      {name}()
                    </code>
                  ))}
                </div>
              </div>
              <div>
                <p className="panel-title mb-1.5">Events ({contract.data?.events?.length || 0})</p>
                <div className="flex flex-wrap gap-1.5">
                  {(contract.data?.events || []).map((name) => (
                    <code key={name} className="mono rounded border border-slate-700/70 bg-slate-950/60 px-1.5 py-0.5 text-[10.5px] text-purple-300">
                      {name}
                    </code>
                  ))}
                </div>
              </div>
              <p className="muted">
                ABI entries: {contract.data?.abi_size ?? 0} · deployed:{' '}
                {contract.data?.contract_address ? <span className="mono text-emerald-300">{contract.data.contract_address}</span> : 'no (local hash-chain mode)'}
              </p>
            </div>
          )}
        </Card>

        <Card title="How integrity is guaranteed" icon={Info} dense>
          <ol className="space-y-2 text-[11px] leading-relaxed text-slate-400">
            <li>
              <span className="text-slate-200">1. Canonical hashing.</span> Each event is serialised to canonical JSON
              (<span className="mono">event_id, event_type, timestamp, prev_hash, payload, hash_version</span>) and hashed with SHA-256.
            </li>
            <li>
              <span className="text-slate-200">2. Hash chaining.</span> Every entry stores the previous entry's hash, so removing or editing
              history breaks every subsequent link.
            </li>
            <li>
              <span className="text-slate-200">3. Optional on-chain anchoring.</span> When an EVM RPC and contract address are configured, the
              hash is written via <span className="mono">recordEventHash(bytes32,bytes32,string)</span>; only hashes and verification metadata
              leave the platform.
            </li>
            <li>
              <span className="text-slate-200">4. Independent verification.</span> Verification recomputes the hash from the stored payload and
              compares it with the recorded value — no trust in the writer required.
            </li>
          </ol>
          <p className="mt-2.5 flex items-start gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/8 p-2 text-[10.5px] leading-relaxed text-emerald-200">
            <Lock size={11} className="mt-0.5 shrink-0" />
            Privacy by design: raw packet captures, passwords, personal identifiers and full alert payloads are never written on-chain.
          </p>
        </Card>
      </div>

      <EventDrawer
        eventId={selectedId}
        onClose={() => {
          setSelectedId(null)
          if (params.get('event')) {
            params.delete('event')
            setParams(params, { replace: true })
          }
        }}
        onChanged={() => { status.refetch(); events.refetch() }}
      />

      <RecordDialog
        open={recordOpen}
        onClose={() => setRecordOpen(false)}
        onRecorded={(event) => {
          setRecordOpen(false)
          events.refetch()
          status.refetch()
          setSelectedId(event.id)
          toast.success('Event recorded', `Chain position ${event.chain_position} · hash ${shortHash(event.event_hash, 10, 6)}`)
        }}
        actor={user?.email}
      />
    </div>
  )
}

function truncateNote(text) {
  const value = String(text || '')
  return value.length > 120 ? `${value.slice(0, 119)}…` : value
}

/** Entry detail with independent verification and the payload that was hashed. */
function EventDrawer({ eventId, onClose, onChanged }) {
  const toast = useToast()
  const detail = useApi(() => (eventId ? blockchainApi.event(eventId) : Promise.resolve(null)), [eventId], { enabled: Boolean(eventId) })
  const verify = useAction(
    async () => {
      const result = await blockchainApi.verify({ event_id: eventId })
      onChanged?.()
      detail.refetch()
      if (result.match) toast.success('Integrity verified', 'The recomputed hash matches the recorded hash.')
      else toast.error('Integrity check failed', result.message)
      return result
    },
    { onError: (failure) => toast.error('Verification error', failure.message) },
  )

  if (!eventId) return null
  const event = detail.data
  const verification = event?.verification || verify.result

  return (
    <Drawer
      open
      onClose={onClose}
      title={`Ledger entry #${event?.chain_position ?? '—'}`}
      subtitle={event ? `${event.event_type} · recorded ${formatDateTime(event.created_at)}` : 'Loading…'}
      width="max-w-2xl"
      footer={
        <div className="flex w-full flex-wrap items-center gap-2">
          <Button size="sm" variant="primary" icon={ScanSearch} loading={verify.busy} onClick={verify.run}>
            Re-verify this entry
          </Button>
          {event?.related_id ? <span className="mono muted">related id {shortHash(event.related_id, 10, 6)}</span> : null}
          <span className="muted ml-auto">verification recomputes the hash server-side</span>
        </div>
      }
    >
      {detail.loading && !event ? (
        <LoadingState label="Loading ledger entry…" />
      ) : detail.error ? (
        <ErrorState error={detail.error} onRetry={detail.refetch} />
      ) : !event ? null : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={event.verification_status} />
            <Badge tone={event.anchor_mode === 'evm' ? 'green' : 'slate'}>anchor: {event.anchor_mode}</Badge>
            {event.is_tamper_demo ? <Badge tone="amber">deliberate tamper demonstration</Badge> : null}
            <Badge tone="purple">position {event.chain_position}</Badge>
          </div>

          {event.is_tamper_demo ? (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/8 p-3 text-[11px] leading-relaxed text-amber-200">
              <AlertTriangle size={12} className="mr-1 inline" />
              This entry was seeded with a payload altered <span className="font-semibold">after</span> hashing, so verification is expected to
              fail. It exists to demonstrate tamper detection end to end.
            </div>
          ) : null}

          {verification ? (
            <div className={`rounded-xl border p-3 ${verification.match ? 'border-emerald-500/30 bg-emerald-500/8' : 'border-rose-500/30 bg-rose-500/8'}`}>
              <p className={`flex items-center gap-1.5 text-xs font-bold ${verification.match ? 'text-emerald-300' : 'text-rose-300'}`}>
                {verification.match ? <Check size={13} /> : <X size={13} />}
                {verification.status?.toUpperCase()} — {verification.message}
              </p>
              <ul className="mt-2 space-y-1.5">
                {(verification.checks || []).map((check) => (
                  <li key={check.name} className="flex items-start gap-2 rounded-lg border border-slate-800/70 bg-slate-950/40 px-2.5 py-1.5">
                    {check.passed ? <CheckCircle2 size={12} className="mt-0.5 shrink-0 text-emerald-400" /> : <X size={12} className="mt-0.5 shrink-0 text-rose-400" />}
                    <span className="min-w-0">
                      <span className="block text-[11px] font-medium text-slate-200">{check.name}</span>
                      <span className="muted block">{check.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
              {verification.onchain ? (
                <p className="muted mt-2">
                  On-chain lookup: {verification.onchain.available ? 'available' : `unavailable — ${verification.onchain.reason}`}
                </p>
              ) : null}
            </div>
          ) : null}

          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <p className="panel-title mb-2 flex items-center gap-1.5"><Hash size={11} /> Hash chain</p>
            <KeyValue
              columns={1}
              items={[
                { label: 'Event hash', node: <span className="flex items-start gap-2"><code className="mono break-all text-emerald-300">{event.event_hash}</code><CopyButton value={event.event_hash} label="copy" /></span> },
                { label: 'Previous hash', node: <code className="mono break-all text-slate-400">{event.prev_hash === GENESIS ? `${GENESIS} (genesis)` : event.prev_hash}</code> },
                { label: 'Recomputed hash', node: verification?.recorded_hash ? <code className="mono break-all text-slate-300">{verification.recorded_hash}</code> : <span className="text-slate-500">run verification</span> },
                { label: 'Recorded by', value: event.recorded_by || '—' },
                { label: 'Recorded at', value: formatDateTime(event.created_at), mono: true },
                { label: 'Verified at', value: event.verified_at ? formatDateTime(event.verified_at) : 'not verified yet' },
              ]}
            />
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <p className="panel-title flex items-center gap-1.5"><FileCode2 size={11} /> Hashed payload</p>
              <CopyButton value={JSON.stringify(event.payload || {}, null, 2)} label="copy JSON" />
            </div>
            <pre className="mono max-h-72 overflow-auto rounded-lg border border-slate-800 bg-[#050810] p-2.5 text-[10.5px] leading-relaxed text-slate-300">
              {JSON.stringify(event.payload || {}, null, 2)}
            </pre>
          </div>

          {event.tx_hash || event.block_number ? (
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/6 p-3">
              <p className="panel-title mb-2 text-emerald-300">On-chain anchor</p>
              <KeyValue
                columns={2}
                items={[
                  { label: 'Transaction', value: event.tx_hash, mono: true },
                  { label: 'Block', value: event.block_number, mono: true },
                  { label: 'Chain id', value: event.chain_id, mono: true },
                  { label: 'Contract', value: event.contract_address, mono: true },
                  { label: 'Recorder', value: event.recorder_address, mono: true },
                ]}
              />
            </div>
          ) : null}
        </div>
      )}
    </Drawer>
  )
}

/** Manual event recording (admin/analyst) with client-side JSON validation. */
function RecordDialog({ open, onClose, onRecorded, actor }) {
  const toast = useToast()
  const [eventType, setEventType] = useState('manual_event')
  const [relatedId, setRelatedId] = useState('')
  const [payloadText, setPayloadText] = useState('{\n  "note": "Manual integrity anchor",\n  "risk_score": 0.42\n}')
  const [anchor, setAnchor] = useState(true)
  const [tamperDemo, setTamperDemo] = useState(false)
  const [jsonError, setJsonError] = useState(null)

  const record = useAction(
    async () => {
      let payload
      try {
        payload = payloadText.trim() ? JSON.parse(payloadText) : {}
        if (typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Payload must be a JSON object')
      } catch (failure) {
        setJsonError(failure.message)
        throw new Error(`Payload is not valid JSON: ${failure.message}`)
      }
      setJsonError(null)
      const event = await blockchainApi.record({
        event_type: eventType,
        payload,
        related_id: relatedId || undefined,
        anchor,
        is_tamper_demo: tamperDemo,
      })
      onRecorded?.(event)
      return event
    },
    { onError: (failure) => toast.error('Could not record event', failure.message) },
  )

  useEffect(() => {
    if (open) setJsonError(null)
  }, [open])

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Record a security event"
      subtitle={`Hashed and appended to the ledger as ${actor || 'the signed-in user'}`}
      width="max-w-xl"
      footer={
        <div className="flex w-full items-center gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={Play} loading={record.busy} onClick={record.run} className="ml-auto">
            Hash &amp; record
          </Button>
        </div>
      }
    >
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label="Event type" value={eventType} onChange={(event) => setEventType(event.target.value)} hint="e.g. manual_event, incident_note" />
          <Input label="Related id (optional)" value={relatedId} onChange={(event) => setRelatedId(event.target.value)} hint="alert, model or report id" />
        </div>
        <Field label="Payload (JSON object)" error={jsonError} hint="Only the hash of this payload is anchored; keep secrets and personal data out of it.">
          <Textarea rows={9} value={payloadText} onChange={(event) => setPayloadText(event.target.value)} />
        </Field>
        <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <Switch checked={anchor} onChange={setAnchor} label="Attempt on-chain anchor" hint="Falls back to the local hash chain when no RPC is configured" />
          <Switch
            checked={tamperDemo}
            onChange={setTamperDemo}
            label="Create as tamper demonstration"
            hint="Alters the stored payload after hashing so verification deliberately fails"
          />
        </div>
        {record.error ? <ErrorState error={record.error} compact /> : null}
        {record.result ? (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/8 p-3">
            <p className="text-xs font-semibold text-emerald-300">Recorded at chain position {record.result.chain_position}</p>
            <code className="mono mt-1.5 block break-all text-[10.5px] text-emerald-200/90">{record.result.event_hash}</code>
          </div>
        ) : null}
      </div>
    </Drawer>
  )
}
