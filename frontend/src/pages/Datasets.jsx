import { useState } from 'react'
import {
  BarChart3,
  CheckCircle2,
  Columns3,
  Database,
  Download,
  Eye,
  FileSpreadsheet,
  FileUp,
  FlaskConical,
  Info,
  Layers,
  Play,
  RefreshCw,
  ScanSearch,
  Sparkles,
  Table2,
  Trash2,
  TrendingUp,
  XCircle,
} from 'lucide-react'
import { datasetsApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import {
  AttackBadge,
  Badge,
  Button,
  Card,
  Checkbox,
  ConfirmDialog,
  DataTable,
  Drawer,
  EmptyState,
  ErrorState,
  Field,
  FileDrop,
  Input,
  KeyValue,
  LoadingState,
  Progress,
  Select,
  StatCard,
  StatusBadge,
} from '../components/ui'
import { CategoryBarChart } from '../components/charts/charts'
import { formatBytes, formatDateTime, formatNumber, formatPercent, timeAgo } from '../utils/format'
import { ATTACK_CLASSES } from '../utils/constants'

const TABS = [
  { key: 'overview', label: 'Quality', icon: BarChart3 },
  { key: 'columns', label: 'Columns', icon: Columns3 },
  { key: 'features', label: 'Features', icon: Sparkles },
  { key: 'preview', label: 'Preview', icon: Table2 },
  { key: 'analyze', label: 'Analyze', icon: ScanSearch },
]

export default function Datasets() {
  const { can } = useAuth()
  const toast = useToast()
  const [page, setPage] = useState({ limit: 25, offset: 0, page: 1 })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [pendingDelete, setPendingDelete] = useState(null)
  const [uploadOptions, setUploadOptions] = useState({ run_analysis: true, analysis_limit: 5000 })
  const [uploadProgress, setUploadProgress] = useState(null)

  const list = useApi(
    () => datasetsApi.list({ limit: page.limit, offset: page.offset, search: search || undefined }),
    [page.limit, page.offset, search],
    { keepPrevious: true },
  )
  const samples = useApi(() => datasetsApi.samples(), [])

  const upload = useAction(
    async (file) => {
      setUploadProgress(0)
      const result = await datasetsApi.upload(
        file,
        { run_analysis: uploadOptions.run_analysis, analysis_limit: uploadOptions.run_analysis ? uploadOptions.analysis_limit : undefined },
        setUploadProgress,
      )
      setUploadProgress(null)
      toast.success(
        'Dataset uploaded',
        `${result.original_filename} · ${formatNumber(result.rows)} rows · ${result.columns} columns` +
          (result.analysis ? ` · ${formatNumber(result.analysis.attacks_detected)} threats detected` : ''),
      )
      list.refetch()
      setSelected(result.id)
      return result
    },
    { onError: (failure) => { setUploadProgress(null); toast.error('Upload failed', failure.message) } },
  )

  const ingestSample = useAction(
    async (name) => {
      const result = await datasetsApi.ingestSample(name, { run_analysis: true })
      toast.success('Sample ingested', `${name} analyzed through the live detection pipeline.`)
      list.refetch()
      return result
    },
    { onError: (failure) => toast.error('Ingest failed', failure.message) },
  )

  const remove = useAction(
    async (datasetId) => {
      await datasetsApi.remove(datasetId)
      toast.success('Dataset deleted', 'The registry entry and stored file were removed.')
      setPendingDelete(null)
      setSelected(null)
      list.refetch()
    },
    { onError: (failure) => toast.error('Delete failed', failure.message) },
  )

  const rows = list.data?.items || []
  const totalRows = rows.reduce((sum, row) => sum + Number(row.rows || 0), 0)
  const totalBytes = rows.reduce((sum, row) => sum + Number(row.size_bytes || 0), 0)
  const canUpload = can('datasets.upload')

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Datasets" value={formatNumber(list.data?.pagination?.total ?? rows.length)} icon={Database} tone="cyan" loading={list.loading && !list.data} />
        <StatCard label="Rows on this page" value={formatNumber(totalRows)} icon={Layers} tone="green" hint="Available for analysis and training" />
        <StatCard label="Stored size" value={formatBytes(totalBytes)} icon={FileSpreadsheet} tone="purple" hint="Raw files kept on the backend" />
        <StatCard
          label="Bundled samples"
          value={formatNumber(samples.data?.items?.length ?? 0)}
          icon={FlaskConical}
          tone="amber"
          hint={samples.data?.limits ? `max upload ${samples.data.limits.max_upload_mb} MB · ${samples.data.limits.allowed.join(' ')}` : undefined}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
        <Card
          title="Dataset library"
          subtitle="Uploaded and bundled traffic files available to the analyzer, trainer and forecaster"
          icon={Database}
          bodyClass="p-0"
          actions={
            <div className="flex items-center gap-2">
              <input
                className="input w-40 py-1 text-[11px]"
                placeholder="Search filename…"
                value={search}
                onChange={(event) => { setPage({ limit: page.limit, offset: 0, page: 1 }); setSearch(event.target.value) }}
              />
              <Button size="sm" variant="ghost" icon={RefreshCw} onClick={list.refetch} loading={list.loading}>Refresh</Button>
            </div>
          }
        >
          <DataTable
            columns={[
              { key: 'original_filename', header: 'Dataset', render: (row) => (
                <span className="block min-w-0">
                  <span className="flex items-center gap-1.5">
                    <span className="truncate text-[11.5px] font-medium text-slate-200">{row.original_filename || row.filename}</span>
                    {row.profile?.labeled === false ? <Badge tone="amber">unlabelled</Badge> : null}
                  </span>
                  <span className="mono block truncate text-[10px] text-slate-500">
                    {row.file_format} · {row.storage_backend} · {row.id}
                  </span>
                </span>
              ) },
              { key: 'rows', header: 'Rows', width: '92px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatNumber(row.rows)}</span> },
              { key: 'columns', header: 'Cols', width: '72px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatNumber(row.columns)}</span> },
              { key: 'size_bytes', header: 'Size', width: '92px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatBytes(row.size_bytes)}</span> },
              { key: 'schema_coverage', header: 'Schema fit', width: '128px', render: (row) => {
                const coverage = row.profile?.schema_coverage ?? row.profile_summary?.schema_coverage
                if (coverage === null || coverage === undefined) return <span className="text-slate-600">not profiled</span>
                return (
                  <span className="flex items-center gap-1.5">
                    <Progress className="w-12" value={coverage * 100} max={100} tone={coverage >= 0.8 ? 'green' : coverage >= 0.5 ? 'amber' : 'red'} />
                    <span className="mono text-[10.5px]">{formatPercent(coverage, 0)}</span>
                  </span>
                )
              } },
              { key: 'status', header: 'Status', width: '104px', render: (row) => <StatusBadge status={row.status === 'processed' ? 'online' : row.status === 'failed' ? 'offline' : 'degraded'} label={row.status} /> },
              { key: 'uploaded_at', header: 'Added', width: '118px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.uploaded_at)}>{timeAgo(row.uploaded_at)}</span> },
              { key: 'actions', header: '', width: '128px', align: 'right', render: (row) => (
                <span className="flex items-center justify-end gap-1" onClick={(event) => event.stopPropagation()}>
                  <Button size="xs" variant="secondary" icon={Eye} onClick={() => setSelected(row.id)}>Inspect</Button>
                  {can('datasets.manage') ? <Button size="xs" variant="danger" icon={Trash2} onClick={() => setPendingDelete(row)} /> : null}
                </span>
              ) },
            ]}
            rows={rows}
            loading={list.loading}
            error={list.error}
            onRetry={list.refetch}
            pagination={list.data?.pagination}
            onPageChange={setPage}
            onRowClick={(row) => setSelected(row.id)}
            selectedId={selected}
            empty={
              <EmptyState
                icon={Database}
                title="No datasets registered"
                message="Upload a CSV/JSON capture or ingest one of the bundled samples to populate the library."
              />
            }
          />
        </Card>

        <div className="space-y-4">
          {canUpload ? (
            <Card title="Upload a capture" subtitle="CSV or JSON network flow data" icon={FileUp}>
              <FileDrop
                onFile={(file) => upload.run(file)}
                accept=".csv,.json"
                busy={upload.busy}
                progress={uploadProgress}
                label="Drag a CSV or JSON flow capture here"
                hint={samples.data?.limits ? `Up to ${samples.data.limits.max_upload_mb} MB · ${samples.data.limits.allowed.join(' / ')}` : undefined}
              />
              <div className="mt-3 space-y-2.5">
                <Checkbox
                  checked={uploadOptions.run_analysis}
                  onChange={(value) => setUploadOptions({ ...uploadOptions, run_analysis: value })}
                  label="Analyze immediately with the active models"
                />
                {uploadOptions.run_analysis ? (
                  <Input
                    label="Rows to analyze"
                    type="number"
                    min={10}
                    max={200000}
                    value={uploadOptions.analysis_limit}
                    onChange={(event) => setUploadOptions({ ...uploadOptions, analysis_limit: event.target.value })}
                    hint="Persisted as live traffic records; alerts follow the normal throttling rules."
                  />
                ) : null}
                {upload.error ? <ErrorState error={upload.error} compact /> : null}
                {upload.result ? (
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/8 p-3">
                    <p className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                      <CheckCircle2 size={13} /> {upload.result.original_filename}
                    </p>
                    <KeyValue
                      className="mt-2"
                      columns={2}
                      items={[
                        { label: 'Rows', value: formatNumber(upload.result.rows), mono: true },
                        { label: 'Columns', value: formatNumber(upload.result.columns), mono: true },
                        { label: 'Schema fit', value: upload.result.profile?.schema_coverage !== undefined ? formatPercent(upload.result.profile.schema_coverage, 0) : '—', mono: true },
                        { label: 'Labelled', value: upload.result.profile?.labeled ? 'yes' : 'no' },
                      ]}
                    />
                    {upload.result.analysis ? (
                      <KeyValue
                        className="mt-2"
                        columns={2}
                        items={[
                          { label: 'Analyzed', value: formatNumber(upload.result.analysis.rows), mono: true },
                          { label: 'Threats found', value: formatNumber(upload.result.analysis.attacks_detected), mono: true },
                          { label: 'Anomalies', value: formatNumber(upload.result.analysis.anomalies), mono: true },
                          { label: 'Alerts created', value: formatNumber(upload.result.analysis.alerts_created), mono: true },
                        ]}
                      />
                    ) : null}
                  </div>
                ) : null}
                <p className="muted flex items-start gap-1.5">
                  <Info size={11} className="mt-0.5 shrink-0" />
                  Column names are mapped to the canonical schema automatically (50+ aliases); unmapped columns are reported, never guessed silently.
                </p>
              </div>
            </Card>
          ) : (
            <Card title="Upload a capture" icon={FileUp}>
              <EmptyState icon={FileUp} title="Read-only access" message="Your role cannot upload datasets. Ask an analyst or administrator." />
            </Card>
          )}

          <Card title="Bundled samples" subtitle={samples.data?.note || 'Synthetic datasets shipped with the platform'} icon={FlaskConical}>
            {samples.loading && !samples.data ? (
              <LoadingState label="Loading samples…" />
            ) : samples.error ? (
              <ErrorState error={samples.error} onRetry={samples.refetch} compact />
            ) : (
              <ul className="space-y-2">
                {(samples.data?.items || []).map((sample) => (
                  <li key={sample.name} className="flex items-center gap-2.5 rounded-xl border border-slate-800 bg-slate-950/40 p-2.5">
                    <FileSpreadsheet size={15} className="shrink-0 text-cyan-400" />
                    <div className="min-w-0 flex-1">
                      <p className="mono truncate text-[11px] text-slate-200">{sample.name}</p>
                      <p className="muted">{sample.format.toUpperCase()} · {formatBytes(sample.size_bytes)}</p>
                    </div>
                    {canUpload ? (
                      <Button size="xs" variant="secondary" icon={Play} loading={ingestSample.busy} onClick={() => ingestSample.run(sample.name)}>
                        Ingest
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      </div>

      <DatasetDrawer
        datasetId={selected}
        onClose={() => setSelected(null)}
        onChanged={list.refetch}
        onDelete={(row) => setPendingDelete(row)}
        canUpload={canUpload}
        canTrain={can('models.train')}
        canForecast={can('forecast.run')}
        canPredict={can('predict.run')}
        canManage={can('datasets.manage')}
      />

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => remove.run(pendingDelete.id)}
        busy={remove.busy}
        title="Delete this dataset?"
        confirmLabel="Delete dataset"
        message={`"${pendingDelete?.original_filename || pendingDelete?.filename}" will be removed from the library. Traffic records and models already derived from it are kept.`}
      />
    </div>
  )
}

function DatasetDrawer({ datasetId, onClose, onChanged, onDelete, canUpload, canTrain, canForecast, canPredict, canManage }) {
  const toast = useToast()
  const [tab, setTab] = useState('overview')
  const detail = useApi(() => (datasetId ? datasetsApi.get(datasetId) : Promise.resolve(null)), [datasetId], { enabled: Boolean(datasetId) })
  const preview = useApi(
    () => (datasetId && tab === 'preview' ? datasetsApi.preview(datasetId, { limit: 50 }) : Promise.resolve(null)),
    [datasetId, tab],
    { enabled: Boolean(datasetId) && tab === 'preview' },
  )
  const [analyzeOptions, setAnalyzeOptions] = useState({ limit: 2000, create_alerts: true })
  const [trainOptions, setTrainOptions] = useState({ algorithm: 'random_forest', activate: false })

  const dataset = detail.data
  const profile = dataset?.profile || {}

  const reprofile = useAction(
    async () => {
      await datasetsApi.reprofile(datasetId)
      toast.success('Profile recomputed', 'Quality metrics were recalculated from the stored file.')
      detail.refetch()
      onChanged?.()
    },
    { onError: (failure) => toast.error('Recompute failed', failure.message) },
  )

  const analyze = useAction(
    async () => {
      const result = await datasetsApi.analyze(datasetId, { limit: analyzeOptions.limit, create_alerts: analyzeOptions.create_alerts })
      toast.success(
        'Analysis complete',
        `${formatNumber(result.summary?.rows || 0)} rows · ${formatNumber(result.summary?.attacks_detected || 0)} threats · ${formatNumber(result.alerts_created || 0)} alerts.`,
      )
      onChanged?.()
      return result
    },
    { onError: (failure) => toast.error('Analysis failed', failure.message) },
  )

  const train = useAction(
    async () => {
      const result = await datasetsApi.train(datasetId, { algorithm: trainOptions.algorithm, activate: trainOptions.activate })
      toast.success('Training complete', `${result?.trained?.length || 0} model(s) trained on ${formatNumber(result?.training_rows || 0)} rows.`)
      onChanged?.()
      return result
    },
    { onError: (failure) => toast.error('Training failed', failure.message) },
  )

  const forecast = useAction(
    async () => {
      const result = await datasetsApi.forecast(datasetId)
      toast.success('Forecast generated', `${result?.forecast?.overall?.risk_level || 'risk'} risk over ${result?.forecast?.overall?.horizon_minutes || '—'} minutes.`)
      return result
    },
    { onError: (failure) => toast.error('Forecast failed', failure.message) },
  )

  const downloadFile = async () => {
    try {
      const filename = await datasetsApi.download(datasetId, dataset?.original_filename || 'dataset.csv')
      toast.success('Download started', filename)
    } catch (failure) {
      toast.error('Download failed', failure.message)
    }
  }

  if (!datasetId) return null

  return (
    <Drawer
      open
      onClose={onClose}
      title={dataset?.original_filename || dataset?.filename || 'Dataset'}
      subtitle={dataset ? `${formatNumber(dataset.rows)} rows · ${dataset.columns} columns · ${formatBytes(dataset.size_bytes)} · ${dataset.file_format}` : 'Loading…'}
      width="max-w-4xl"
      footer={
        dataset ? (
          <div className="flex w-full flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" icon={Download} onClick={downloadFile} disabled={!canManage}>Download</Button>
            {canUpload ? <Button size="sm" variant="secondary" icon={RefreshCw} loading={reprofile.busy} onClick={reprofile.run}>Recompute profile</Button> : null}
            {canForecast ? <Button size="sm" variant="secondary" icon={TrendingUp} loading={forecast.busy} onClick={forecast.run}>Run forecast</Button> : null}
            {canManage ? <Button size="sm" variant="danger" icon={Trash2} onClick={() => onDelete(dataset)}>Delete</Button> : null}
            <span className="muted ml-auto">id {dataset.id}</span>
          </div>
        ) : null
      }
    >
      {detail.loading && !dataset ? (
        <LoadingState label="Loading dataset profile…" />
      ) : detail.error ? (
        <ErrorState error={detail.error} onRetry={detail.refetch} />
      ) : !dataset ? null : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={dataset.status === 'processed' ? 'online' : dataset.status === 'failed' ? 'offline' : 'degraded'} label={dataset.status} />
            <Badge tone="cyan">{dataset.file_format}</Badge>
            <Badge tone="slate">{dataset.storage_backend}</Badge>
            {profile.labeled ? <Badge tone="green">labelled</Badge> : profile.labeled === false ? <Badge tone="amber">unlabelled</Badge> : null}
            {profile.note ? <Badge tone="purple">{profile.note}</Badge> : null}
            <span className="muted">added {formatDateTime(dataset.uploaded_at)}</span>
          </div>

          {dataset.error_message ? (
            <p className="rounded-lg border border-rose-500/30 bg-rose-500/8 px-3 py-2 text-[11px] text-rose-200">{dataset.error_message}</p>
          ) : null}

          {profile.schema_coverage === undefined ? (
            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/8 p-3">
              <Info size={13} className="text-amber-300" />
              <p className="muted flex-1">This record has not been profiled yet — quality metrics are unavailable.</p>
              {canUpload ? <Button size="xs" variant="secondary" loading={reprofile.busy} onClick={reprofile.run}>Compute profile</Button> : null}
            </div>
          ) : null}

          <nav className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-2">
            {TABS.map((item) => (
              <button
                key={item.key}
                type="button"
                onClick={() => setTab(item.key)}
                className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[11.5px] font-medium transition ${
                  tab === item.key ? 'bg-cyan-500/12 text-cyan-300' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                <item.icon size={12} /> {item.label}
              </button>
            ))}
          </nav>

          {tab === 'overview' ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                {[
                  { label: 'Rows', value: formatNumber(profile.rows ?? dataset.rows) },
                  { label: 'Columns', value: formatNumber(profile.columns ?? dataset.columns) },
                  { label: 'Missing cells', value: formatNumber(profile.missing_value_total ?? 0), sub: profile.missing_value_percentage !== undefined ? `${profile.missing_value_percentage}%` : null },
                  { label: 'Duplicate rows', value: formatNumber(profile.duplicate_rows ?? 0), sub: profile.duplicate_percentage !== undefined ? `${profile.duplicate_percentage}%` : null },
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
                    <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{item.label}</p>
                    <p className="mt-0.5 text-base font-bold leading-none text-slate-100">{item.value}</p>
                    {item.sub ? <p className="mono mt-0.5 text-[10px] text-slate-500">{item.sub}</p> : null}
                  </div>
                ))}
              </div>

              <KeyValue
                columns={2}
                items={[
                  { label: 'Schema coverage', value: profile.schema_coverage !== undefined ? formatPercent(profile.schema_coverage, 0) : '—', mono: true },
                  { label: 'Canonical columns detected', value: `${profile.canonical_columns_detected?.length ?? 0} / ${(profile.canonical_columns_detected?.length ?? 0) + (profile.canonical_columns_missing?.length ?? 0)}`, mono: true },
                  { label: 'Labelled', value: profile.labeled ? 'yes — attack_type present' : 'no — detection only' },
                  { label: 'Unmapped columns', value: profile.unmapped_columns?.length ? profile.unmapped_columns.join(', ') : 'none' },
                  { label: 'Profiled at', value: profile.profiled_at ? formatDateTime(profile.profiled_at) : '—', mono: true },
                  { label: 'Stored path', value: dataset.filename, mono: true },
                ]}
              />

              {Object.keys(profile.class_distribution || {}).length ? (
                <div>
                  <p className="panel-title mb-2">Label distribution</p>
                  <CategoryBarChart
                    data={ATTACK_CLASSES.filter((name) => profile.class_distribution[name] !== undefined).map((name) => ({
                      name,
                      value: profile.class_distribution[name],
                    }))}
                    height={Math.max(200, Object.keys(profile.class_distribution).length * 26)}
                    horizontal
                    formatter={(value) => formatNumber(value)}
                  />
                </div>
              ) : null}

              {profile.missing_values && Object.keys(profile.missing_values).length ? (
                <div>
                  <p className="panel-title mb-2">Missing values by column</p>
                  <ul className="space-y-1.5">
                    {Object.entries(profile.missing_values).map(([column, count]) => (
                      <li key={column} className="flex items-center gap-2">
                        <span className="mono w-40 shrink-0 truncate text-[10.5px] text-slate-300">{column}</span>
                        <Progress className="flex-1" value={count} max={profile.rows || 1} tone="amber" />
                        <span className="mono w-16 shrink-0 text-right text-[10.5px] text-slate-400">{formatNumber(count)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {profile.preprocessing ? (
                <div>
                  <p className="panel-title mb-2">Preprocessing applied on ingest</p>
                  <ul className="grid gap-1.5 sm:grid-cols-2">
                    {Object.entries(profile.preprocessing).map(([step, done]) => (
                      <li key={step} className="flex items-center gap-1.5 text-[11px] text-slate-300">
                        {done ? <CheckCircle2 size={11} className="text-emerald-400" /> : <XCircle size={11} className="text-slate-600" />}
                        <span className="mono">{step.replace(/_/g, ' ')}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}

          {tab === 'columns' ? (
            <div className="space-y-4">
              <div>
                <p className="panel-title mb-2">Detected column mapping</p>
                <DataTable
                  columns={[
                    { key: 'canonical', header: 'Canonical field', render: (row) => <span className="mono text-cyan-300">{row.canonical}</span> },
                    { key: 'source', header: 'Source column', render: (row) => <span className="mono text-slate-300">{row.source}</span> },
                    { key: 'dtype', header: 'Raw dtype', width: '120px', render: (row) => <span className="mono text-[10.5px] text-slate-400">{row.dtype || '—'}</span> },
                  ]}
                  rows={Object.entries(profile.column_mapping || {}).map(([canonical, source]) => ({
                    canonical,
                    source,
                    dtype: profile.dtypes?.[source],
                  }))}
                  rowKey={(row) => row.canonical}
                  maxHeight={280}
                  empty={<EmptyState icon={Columns3} title="No mapping available" message="Recompute the profile to detect columns." />}
                />
              </div>
              {profile.canonical_columns_missing?.length ? (
                <div>
                  <p className="panel-title mb-2">Canonical fields not present</p>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.canonical_columns_missing.map((column) => <Badge key={column} tone="amber">{column}</Badge>)}
                  </div>
                  <p className="muted mt-1.5">Missing fields are imputed or derived by the feature pipeline; accuracy may be lower than with a complete capture.</p>
                </div>
              ) : null}
              {profile.unmapped_columns?.length ? (
                <div>
                  <p className="panel-title mb-2">Extra columns kept but unused</p>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.unmapped_columns.map((column) => <Badge key={column} tone="slate">{column}</Badge>)}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          {tab === 'features' ? (
            <DataTable
              columns={[
                { key: 'feature', header: 'Feature', render: (row) => <span className="mono text-[10.5px] text-slate-200">{row.feature}</span> },
                { key: 'mean', header: 'Mean', align: 'right', render: (row) => <span className="mono">{formatMetric(row.mean)}</span> },
                { key: 'std', header: 'Std dev', align: 'right', render: (row) => <span className="mono">{formatMetric(row.std)}</span> },
                { key: 'min', header: 'Min', align: 'right', render: (row) => <span className="mono">{formatMetric(row.min)}</span> },
                { key: 'p50', header: 'Median', align: 'right', render: (row) => <span className="mono">{formatMetric(row.p50)}</span> },
                { key: 'max', header: 'Max', align: 'right', render: (row) => <span className="mono">{formatMetric(row.max)}</span> },
              ]}
              rows={profile.feature_summary || []}
              rowKey={(row) => row.feature}
              loading={detail.loading}
              maxHeight={420}
              empty={<EmptyState icon={Sparkles} title="No numeric features profiled" message="Recompute the profile to summarize numeric columns." />}
            />
          ) : null}

          {tab === 'preview' ? (
            <div className="space-y-3">
              <p className="muted">
                Showing {formatNumber(preview.data?.returned || 0)} of {formatNumber(preview.data?.total_rows || dataset.rows)} normalized rows.
                Values are post-preprocessing (labels mapped to the platform taxonomy, timestamps parsed to UTC).
              </p>
              {preview.loading && !preview.data ? (
                <LoadingState label="Reading stored rows…" />
              ) : preview.error ? (
                <ErrorState error={preview.error} onRetry={preview.refetch} compact />
              ) : (
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="table">
                    <thead>
                      <tr>
                        {(preview.data?.columns || []).map((column) => (
                          <th key={column} className="whitespace-nowrap">{column}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(preview.data?.rows || []).map((row, index) => (
                        <tr key={index}>
                          {(preview.data?.columns || []).map((column) => (
                            <td key={column} className="mono whitespace-nowrap text-[10.5px]">
                              {column === 'attack_type' ? <AttackBadge type={row[column]} /> : formatCell(row[column])}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ) : null}

          {tab === 'analyze' ? (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
                <Input
                  label="Rows to analyze"
                  type="number"
                  min={10}
                  max={200000}
                  value={analyzeOptions.limit}
                  onChange={(event) => setAnalyzeOptions({ ...analyzeOptions, limit: event.target.value })}
                  hint="10 – 200,000"
                />
                <Checkbox
                  checked={analyzeOptions.create_alerts}
                  onChange={(value) => setAnalyzeOptions({ ...analyzeOptions, create_alerts: value })}
                  label="Create alerts for detected threats"
                />
                <Button variant="primary" icon={ScanSearch} loading={analyze.busy} onClick={analyze.run} disabled={!canPredict}>
                  {canPredict ? 'Run detection' : 'Not permitted'}
                </Button>
              </div>

              {canTrain ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                  <p className="panel-title mb-2">Train on this dataset</p>
                  <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
                    <Select
                      label="Algorithm"
                      value={trainOptions.algorithm}
                      onChange={(event) => setTrainOptions({ ...trainOptions, algorithm: event.target.value })}
                      options={[
                        { value: 'random_forest', label: 'Random Forest' },
                        { value: 'gradient_boosting', label: 'Gradient Boosting (hist)' },
                        { value: 'logistic_regression', label: 'Logistic Regression' },
                        { value: 'extra_trees', label: 'Extra Trees' },
                        { value: 'isolation_forest', label: 'Isolation Forest (anomaly)' },
                      ]}
                    />
                    <Checkbox checked={trainOptions.activate} onChange={(value) => setTrainOptions({ ...trainOptions, activate: value })} label="Activate if valid" />
                    <Button variant="secondary" icon={Play} loading={train.busy} onClick={train.run}>Train</Button>
                  </div>
                  {train.result ? (
                    <p className="muted mt-2">
                      Trained {(train.result.trained || []).map((model) => `${model.name} (${formatPercent(model.accuracy, 2)})`).join(', ') || 'no models'} on{' '}
                      {formatNumber(train.result.training_rows || 0)} rows.
                    </p>
                  ) : null}
                  {train.error ? <ErrorState error={train.error} compact className="mt-2" /> : null}
                </div>
              ) : null}

              {analyze.error ? <ErrorState error={analyze.error} compact /> : null}

              {analyze.result ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                    {[
                      { label: 'Rows scored', value: formatNumber(analyze.result.summary?.rows || 0) },
                      { label: 'Threats detected', value: formatNumber(analyze.result.summary?.attacks_detected || 0) },
                      { label: 'Anomalies', value: formatNumber(analyze.result.summary?.anomalies || 0) },
                      { label: 'Attack rate', value: formatPercent(analyze.result.summary?.attack_rate, 1) },
                      { label: 'Mean risk', value: formatPercent(analyze.result.summary?.mean_risk_score, 1) },
                      { label: 'Max risk', value: formatPercent(analyze.result.summary?.max_risk_score, 1) },
                      { label: 'Mean confidence', value: formatPercent(analyze.result.summary?.mean_confidence, 1) },
                      { label: 'Alerts created', value: formatNumber(analyze.result.alerts_created || 0) },
                    ].map((item) => (
                      <div key={item.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
                        <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{item.label}</p>
                        <p className="mt-0.5 text-base font-bold leading-none text-slate-100">{item.value}</p>
                      </div>
                    ))}
                  </div>

                  {analyze.result.summary?.correctness?.labeled_rows ? (
                    <div className="rounded-xl border border-cyan-500/25 bg-cyan-500/6 p-3">
                      <p className="panel-title mb-2 text-cyan-300">Agreement with the dataset labels</p>
                      <KeyValue
                        columns={4}
                        items={[
                          { label: 'Labelled rows', value: formatNumber(analyze.result.summary.correctness.labeled_rows), mono: true },
                          { label: 'Accuracy', value: formatPercent(analyze.result.summary.correctness.accuracy, 2), mono: true },
                          { label: 'True positives', value: formatNumber(analyze.result.summary.correctness.true_positives), mono: true },
                          { label: 'True negatives', value: formatNumber(analyze.result.summary.correctness.true_negatives), mono: true },
                          { label: 'False positives', value: formatNumber(analyze.result.summary.correctness.false_positives), mono: true },
                          { label: 'False negatives', value: formatNumber(analyze.result.summary.correctness.false_negatives), mono: true },
                        ]}
                      />
                      <p className="muted mt-2">
                        Measured against the file's own <span className="mono">attack_type</span> column — an evaluation of the active model on this data, not a guarantee of future accuracy.
                      </p>
                    </div>
                  ) : (
                    <p className="muted">This dataset has no labels, so predictions cannot be scored against ground truth.</p>
                  )}

                  {analyze.result.summary?.class_distribution ? (
                    <div>
                      <p className="panel-title mb-2">Predicted classes</p>
                      <CategoryBarChart
                        data={Object.entries(analyze.result.summary.class_distribution).map(([name, value]) => ({ name, value }))}
                        height={Math.max(180, Object.keys(analyze.result.summary.class_distribution).length * 26)}
                        horizontal
                        formatter={(value) => formatNumber(value)}
                      />
                    </div>
                  ) : null}

                  <p className="muted">
                    Model: {analyze.result.model?.model_name || '—'} v{analyze.result.model?.model_version || '—'} · engine{' '}
                    <span className="mono">{analyze.result.summary?.engine}</span> · {formatNumber(analyze.result.persisted || 0)} traffic records persisted
                    {analyze.result.alerts_suppressed ? ` · ${formatNumber(analyze.result.alerts_suppressed)} alerts suppressed by throttling` : ''}.
                  </p>
                </div>
              ) : null}

              {forecast.result ? (
                <div className="rounded-xl border border-purple-500/25 bg-purple-500/6 p-3">
                  <p className="panel-title mb-2 text-purple-300">Forecast run on this dataset</p>
                  <KeyValue
                    columns={3}
                    items={[
                      { label: 'Run id', value: forecast.result.run_id, mono: true },
                      { label: 'Horizon', value: `${forecast.result.forecast?.overall?.horizon_minutes ?? '—'} min`, mono: true },
                      { label: 'Risk', value: String(forecast.result.forecast?.overall?.risk_level || '—').toUpperCase() },
                      { label: 'Probability', value: forecast.result.forecast?.overall?.probability !== undefined ? formatPercent(forecast.result.forecast.overall.probability, 1) : '—', mono: true },
                      { label: 'Expected events', value: Number(forecast.result.forecast?.overall?.expected_attack_events ?? 0).toFixed(2), mono: true },
                      { label: 'Top threat', value: forecast.result.forecast?.overall?.top_threat?.attack_type || '—' },
                    ]}
                  />
                </div>
              ) : null}
              {forecast.error ? <ErrorState error={forecast.error} compact /> : null}
            </div>
          ) : null}
        </div>
      )}
    </Drawer>
  )
}

function formatMetric(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—'
  const numeric = Number(value)
  if (Math.abs(numeric) >= 10000) return numeric.toExponential(2)
  return numeric.toFixed(Math.abs(numeric) < 10 ? 3 : 2)
}

function formatCell(value) {
  if (value === null || value === undefined || value === '') return <span className="text-slate-600">—</span>
  if (typeof value === 'number') return Number.isInteger(value) ? formatNumber(value) : value.toFixed(3)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return String(value)
}
