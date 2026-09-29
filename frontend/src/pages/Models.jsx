import { useMemo, useState } from 'react'
import {
  Activity,
  Award,
  Boxes,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Database,
  GitCompareArrows,
  Grid3x3,
  Info,
  Play,
  Power,
  PowerOff,
  RefreshCw,
  ScanSearch,
  Trash2,
  Upload,
  XCircle,
} from 'lucide-react'
import { datasetsApi, modelsApi } from '../services/endpoints'
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
  Input,
  KeyValue,
  LoadingState,
  Progress,
  Select,
  StatCard,
  StatusBadge,
} from '../components/ui'
import { CategoryBarChart } from '../components/charts/charts'
import { formatDateTime, formatNumber, formatPercent, timeAgo, truncate } from '../utils/format'

export default function Models() {
  const { can } = useAuth()
  const toast = useToast()
  const [selectedId, setSelectedId] = useState(null)
  const [compareIds, setCompareIds] = useState([])
  const [comparison, setComparison] = useState(null)
  const [pendingDelete, setPendingDelete] = useState(null)

  const registry = useApi(() => modelsApi.registry(), [], { keepPrevious: true })
  const list = useApi(() => modelsApi.list({ limit: 50 }), [], { keepPrevious: true })
  const algorithms = useApi(() => modelsApi.algorithms(), [])
  const datasets = useApi(() => datasetsApi.list({ limit: 50 }), [], { enabled: can('models.train') })

  const refreshAll = () => {
    registry.refetch()
    list.refetch()
  }

  const activate = useAction(
    async (modelId) => {
      const result = await modelsApi.activate(modelId)
      toast.success(
        'Model activated',
        result?.validation?.valid
          ? `Validation accuracy ${formatPercent(result.validation.accuracy, 2)} (minimum ${formatPercent(result.validation.min_required_accuracy, 0)}).`
          : 'Activated with an administrator override.',
      )
      refreshAll()
      return result
    },
    { onError: (failure) => toast.error('Activation refused', failure.message) },
  )

  const deactivate = useAction(
    async (modelId) => {
      await modelsApi.deactivate(modelId)
      toast.info('Model deactivated', 'The registry falls back to the remaining active models.')
      refreshAll()
    },
    { onError: (failure) => toast.error('Deactivation failed', failure.message) },
  )

  const remove = useAction(
    async (modelId) => {
      await modelsApi.remove(modelId)
      toast.success('Model deleted', 'The registry entry and its artifact were removed.')
      setPendingDelete(null)
      setSelectedId(null)
      refreshAll()
    },
    { onError: (failure) => toast.error('Delete failed', failure.message) },
  )

  const compare = useAction(
    async () => {
      if (compareIds.length < 2) throw new Error('Select at least two models to compare.')
      const result = await modelsApi.compare(compareIds)
      setComparison(result)
      return result
    },
    { onError: (failure) => toast.error('Comparison failed', failure.message) },
  )

  const models = list.data?.items || []
  const active = registry.data || {}

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Registered models" value={formatNumber(list.data?.pagination?.total ?? models.length)} icon={Boxes} tone="cyan" hint={`${models.filter((m) => m.is_active).length} active`} />
        <StatCard
          label="Active classifier"
          value={active.active_classifier?.algorithm?.replace(/_/g, ' ') || 'none'}
          icon={Cpu}
          tone="green"
          loading={registry.loading && !active.active_classifier}
          hint={active.active_classifier ? `v${active.active_classifier.version} · accuracy ${formatPercent(active.active_classifier.metrics?.accuracy, 2)}` : 'no classifier activated'}
        />
        <StatCard
          label="Anomaly detector"
          value={active.active_anomaly_detector?.algorithm?.replace(/_/g, ' ') || 'none'}
          icon={Activity}
          tone="purple"
          hint={active.active_anomaly_detector ? `${formatNumber(active.active_anomaly_detector.training_rows)} benign rows` : 'none activated'}
        />
        <StatCard label="Inference engine" value={String(active.inference_engine || 'ml').toUpperCase()} icon={ScanSearch} tone="amber" hint={active.inference_engine === 'ml' ? 'trained scikit-learn artifacts' : 'heuristic fallback'} />
      </div>

      {can('models.train') ? (
        <TrainPanel
          algorithms={algorithms.data?.items || []}
          datasets={datasets.data?.items || []}
          onTrained={(result) => {
            refreshAll()
            toast.success(
              'Training complete',
              `${result?.trained?.length || 0} model(s) trained on ${formatNumber(result?.training_rows || 0)} rows.` +
                (result?.errors?.length ? ` Errors: ${result.errors.join('; ')}` : ''),
            )
          }}
        />
      ) : null}

      <Card
        title="Model registry"
        subtitle="Every trained or uploaded model, with evaluation metrics and activation state"
        icon={Boxes}
        bodyClass="p-0"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" icon={RefreshCw} onClick={refreshAll} loading={list.loading}>Refresh</Button>
            <Button
              size="sm"
              variant={compareIds.length >= 2 ? 'primary' : 'secondary'}
              icon={GitCompareArrows}
              loading={compare.busy}
              disabled={compareIds.length < 2}
              onClick={compare.run}
            >
              Compare ({compareIds.length})
            </Button>
            {can('models.upload') ? <UploadModelButton onUploaded={() => { refreshAll(); toast.success('Model uploaded', 'The artifact was registered and validated.') }} /> : null}
          </div>
        }
      >
        <DataTable
          columns={[
            {
              key: 'select', header: '', width: '40px', align: 'center',
              render: (row) => (
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5 accent-cyan-500"
                  checked={compareIds.includes(row.id)}
                  onClick={(event) => event.stopPropagation()}
                  onChange={(event) =>
                    setCompareIds((current) => (event.target.checked ? [...current, row.id] : current.filter((id) => id !== row.id)))
                  }
                  aria-label={`Select ${row.name} for comparison`}
                />
              ),
            },
            { key: 'name', header: 'Model', render: (row) => (
              <span className="block min-w-0">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-[11.5px] font-medium text-slate-200">{row.name}</span>
                  {row.is_active ? <Badge tone="green">active</Badge> : null}
                </span>
                <span className="mono block truncate text-[10px] text-slate-500">
                  {row.algorithm} · v{row.version} · {row.task} · {truncate(row.id, 14)}
                </span>
              </span>
            ) },
            { key: 'accuracy', header: 'Accuracy', width: '128px', align: 'right', sortable: true, render: (row) => (
              <span className="flex items-center justify-end gap-1.5">
                <Progress className="w-12" value={Number(row.accuracy || 0) * 100} max={100} tone={Number(row.accuracy) >= 0.9 ? 'green' : Number(row.accuracy) >= 0.7 ? 'cyan' : 'amber'} />
                <span className="mono text-[10.5px]">{formatPercent(row.accuracy, 2)}</span>
              </span>
            ) },
            { key: 'precision_score', header: 'Precision', width: '92px', align: 'right', render: (row) => <span className="mono">{row.precision_score ? formatPercent(row.precision_score, 2) : '—'}</span> },
            { key: 'recall_score', header: 'Recall', width: '84px', align: 'right', render: (row) => <span className="mono">{row.recall_score ? formatPercent(row.recall_score, 2) : '—'}</span> },
            { key: 'f1_score', header: 'F1', width: '76px', align: 'right', render: (row) => <span className="mono">{row.f1_score ? formatPercent(row.f1_score, 2) : '—'}</span> },
            { key: 'roc_auc', header: 'AUC', width: '72px', align: 'right', hideBelow: 'lg:table-cell', render: (row) => <span className="mono">{row.roc_auc ? Number(row.roc_auc).toFixed(3) : '—'}</span> },
            { key: 'training_rows', header: 'Rows', width: '88px', align: 'right', sortable: true, render: (row) => <span className="mono">{formatNumber(row.training_rows)}</span> },
            { key: 'dataset_name', header: 'Dataset', width: '180px', hideBelow: 'xl:table-cell', render: (row) => <span className="mono truncate text-[10px] text-slate-400">{row.dataset_name || '—'}</span> },
            { key: 'artifact_status', header: 'Artifact', width: '98px', render: (row) => <StatusBadge status={row.artifact_available ? 'online' : 'offline'} /> },
            { key: 'trained_at', header: 'Trained', width: '116px', sortable: true, render: (row) => <span className="mono text-[10.5px] text-slate-400" title={formatDateTime(row.trained_at)}>{timeAgo(row.trained_at)}</span> },
            { key: 'actions', header: '', width: '132px', align: 'right', render: (row) => (
              <span className="flex items-center justify-end gap-1" onClick={(event) => event.stopPropagation()}>
                {can('models.activate') && !row.is_active ? (
                  <Button size="xs" variant="success" icon={Power} loading={activate.busy} onClick={() => activate.run(row.id)}>Activate</Button>
                ) : null}
                {can('models.activate') && row.is_active ? (
                  <Button size="xs" variant="ghost" icon={PowerOff} loading={deactivate.busy} onClick={() => deactivate.run(row.id)}>Retire</Button>
                ) : null}
                {can('models.activate') ? (
                  <Button size="xs" variant="danger" icon={Trash2} onClick={() => setPendingDelete(row)} disabled={row.is_active} title={row.is_active ? 'Activate another model first' : 'Delete model'} />
                ) : null}
              </span>
            ) },
          ]}
          rows={models}
          loading={list.loading}
          error={list.error}
          onRetry={list.refetch}
          onRowClick={(row) => setSelectedId(row.id)}
          selectedId={selectedId}
          empty={
            <EmptyState
              icon={Boxes}
              title="No models registered"
              message="Train a classifier on an uploaded or bundled dataset to populate the registry."
            />
          }
        />
      </Card>

      {comparison ? <ComparisonPanel result={comparison} onClose={() => setComparison(null)} models={models} /> : null}

      <Card title="Algorithm catalogue" subtitle="Algorithms available to the trainer" icon={BrainCircuit}>
        {algorithms.loading && !algorithms.data ? (
          <LoadingState label="Loading algorithms…" />
        ) : algorithms.error ? (
          <ErrorState error={algorithms.error} onRetry={algorithms.refetch} compact />
        ) : (
          <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
            {(algorithms.data?.items || []).map((algorithm) => (
              <div key={algorithm.key} className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11.5px] font-semibold text-slate-100">{algorithm.label}</p>
                  <Badge tone={algorithm.task === 'classification' ? 'cyan' : 'purple'}>{algorithm.task}</Badge>
                </div>
                <p className="mono mt-0.5 text-[10px] text-slate-500">{algorithm.key}</p>
                <p className="muted mt-1.5 leading-relaxed">{algorithm.description}</p>
                <p className="muted mt-1.5">
                  {algorithm.supports_proba ? <CheckCircle2 size={10} className="mr-1 inline text-emerald-400" /> : <XCircle size={10} className="mr-1 inline text-slate-500" />}
                  probability estimates {algorithm.supports_proba ? 'available' : 'not available'}
                </p>
              </div>
            ))}
          </div>
        )}
      </Card>

      <ModelDrawer
        modelId={selectedId}
        onClose={() => setSelectedId(null)}
        onChanged={refreshAll}
        canActivate={can('models.activate')}
      />

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => remove.run(pendingDelete.id)}
        busy={remove.busy}
        title="Delete this model?"
        confirmLabel="Delete model"
        message={`"${pendingDelete?.name}" and its stored artifact will be removed. Active models cannot be deleted — activate another model first.`}
      />
    </div>
  )
}

function TrainPanel({ algorithms, datasets, onTrained }) {
  const toast = useToast()
  const [form, setForm] = useState({
    algorithm: 'random_forest',
    dataset_id: '',
    rows: 6000,
    contamination: 0.1,
    train_anomaly: true,
    activate: false,
  })

  const train = useAction(
    async () => {
      const result = await modelsApi.train({
        algorithm: form.algorithm,
        dataset_id: form.dataset_id || undefined,
        rows: form.rows ? Number(form.rows) : undefined,
        contamination: form.algorithm === 'isolation_forest' ? Number(form.contamination) : undefined,
        train_anomaly: form.train_anomaly,
        activate: form.activate,
      })
      onTrained?.(result)
      return result
    },
    { onError: (failure) => toast.error('Training failed', failure.message) },
  )

  const task = algorithms.find((item) => item.key === form.algorithm)?.task || 'classification'

  return (
    <Card
      title="Train a model"
      subtitle="Training runs on the backend against a stored dataset and persists a joblib artifact"
      icon={Play}
      actions={train.result ? <Badge tone="green">last run {timeAgo(train.result.trained_at)}</Badge> : null}
    >
      <div className="grid gap-3 lg:grid-cols-4">
        <Select
          label="Algorithm"
          value={form.algorithm}
          onChange={(event) => setForm({ ...form, algorithm: event.target.value })}
          options={algorithms.map((item) => ({ value: item.key, label: `${item.label} (${item.task})` }))}
        />
        <Select
          label="Training dataset"
          value={form.dataset_id}
          placeholder="Latest labelled dataset"
          onChange={(event) => setForm({ ...form, dataset_id: event.target.value })}
          options={(datasets || []).map((item) => ({
            value: item.id,
            label: `${item.original_filename || item.filename} · ${formatNumber(item.rows)} rows`,
          }))}
          hint={task === 'anomaly' ? 'Anomaly models train on the benign subset' : 'Requires a labelled attack_type column'}
        />
        <Input
          label="Rows to train on"
          type="number"
          min={100}
          max={200000}
          value={form.rows}
          onChange={(event) => setForm({ ...form, rows: event.target.value })}
          hint="100 – 200,000"
        />
        {task === 'anomaly' ? (
          <Input
            label="Contamination"
            type="number"
            step="0.01"
            min="0.005"
            max="0.4"
            value={form.contamination}
            onChange={(event) => setForm({ ...form, contamination: event.target.value })}
            hint="Expected anomaly fraction (0.005 – 0.4)"
          />
        ) : (
          <Field label="Expected duration" hint="Random Forest on 6,000 rows trains in a few seconds">
            <p className="input flex items-center text-slate-400">≈ 2–8 seconds</p>
          </Field>
        )}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-4">
        <Checkbox checked={form.train_anomaly} onChange={(value) => setForm({ ...form, train_anomaly: value })} label="Also train the Isolation Forest anomaly detector" />
        <Checkbox checked={form.activate} onChange={(value) => setForm({ ...form, activate: value })} label="Activate immediately if validation passes" />
        <div className="ml-auto flex items-center gap-2">
          <Button variant="primary" icon={Play} loading={train.busy} onClick={train.run}>
            {train.busy ? 'Training…' : 'Start training'}
          </Button>
        </div>
      </div>

      {train.error ? <ErrorState error={train.error} compact className="mt-3" /> : null}

      {train.result ? (
        <div className="mt-3 space-y-2">
          {(train.result.trained || []).map((model) => (
            <div key={model.id} className="rounded-xl border border-emerald-500/25 bg-emerald-500/6 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs font-semibold text-emerald-200">
                  {model.name} · {formatPercent(model.accuracy, 2)} accuracy
                </p>
                <div className="flex items-center gap-1.5">
                  <Badge tone="slate">{formatNumber(model.training_rows)} rows</Badge>
                  {model.activation ? (
                    <Badge tone={model.activation.activated ? 'green' : 'amber'}>
                      {model.activation.activated ? 'activated' : `not activated: ${model.activation.reason || 'validation'}`}
                    </Badge>
                  ) : null}
                </div>
              </div>
              <div className="mt-2 grid gap-2 sm:grid-cols-4">
                {[
                  { label: 'Precision', value: model.precision_score },
                  { label: 'Recall', value: model.recall_score },
                  { label: 'F1', value: model.f1_score },
                  { label: 'ROC AUC', value: model.roc_auc },
                ].map((metric) => (
                  <div key={metric.label} className="rounded-lg border border-slate-800/70 bg-slate-950/40 p-2">
                    <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{metric.label}</p>
                    <p className="mono mt-0.5 text-[11.5px] text-slate-200">
                      {metric.value === null || metric.value === undefined ? '—' : Number(metric.value).toFixed(4)}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {train.result.errors?.length ? (
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/8 px-3 py-2 text-[11px] text-amber-200">
              {train.result.errors.join(' · ')}
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  )
}

function UploadModelButton({ onUploaded }) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [progress, setProgress] = useState(null)

  const upload = useAction(
    async (file) => {
      const result = await modelsApi.upload(file, { name: name || undefined }, setProgress)
      setProgress(null)
      onUploaded?.()
      return result
    },
    { onError: (failure) => { setProgress(null); toast.error('Upload failed', failure.message) } },
  )

  return (
    <span className="flex items-center gap-1.5">
      <input
        className="input w-36 py-1 text-[11px]"
        placeholder="Display name"
        value={name}
        onChange={(event) => setName(event.target.value)}
      />
      <label className="btn-secondary btn-sm cursor-pointer">
        <Upload size={12} /> {upload.busy ? `${progress ?? 0}%` : 'Upload .joblib'}
        <input
          type="file"
          accept=".joblib,.pkl"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) upload.run(file)
            event.target.value = ''
          }}
        />
      </label>
    </span>
  )
}

function ComparisonPanel({ result, onClose, models }) {
  const metricKeys = result.metric_keys || ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc_ovr']
  const bestId = result.best?.id || result.best

  return (
    <Card
      title="Model comparison"
      subtitle={`${result.models?.length || 0} models · best by weighted accuracy: ${models.find((m) => m.id === bestId)?.name || result.best?.name || 'n/a'}`}
      icon={GitCompareArrows}
      actions={<Button size="sm" variant="ghost" onClick={onClose}>Close</Button>}
    >
      <div className="overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>Metric</th>
              {(result.models || []).map((model) => (
                <th key={model.id} className="text-right">
                  <span className="flex items-center justify-end gap-1.5">
                    {model.name}
                    {model.id === bestId ? <Award size={11} className="text-amber-300" /> : null}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {metricKeys.map((key) => {
              const values = (result.models || []).map((model) => Number(model.metrics?.[key] ?? NaN))
              const best = Math.max(...values.filter((value) => Number.isFinite(value)))
              return (
                <tr key={key}>
                  <td className="mono text-[10.5px] text-slate-400">{key.replace(/_/g, ' ')}</td>
                  {values.map((value, index) => (
                    <td key={index} className="text-right">
                      <span className={`mono ${Number.isFinite(value) && value === best ? 'font-bold text-emerald-300' : 'text-slate-300'}`}>
                        {Number.isFinite(value) ? value.toFixed(4) : '—'}
                      </span>
                    </td>
                  ))}
                </tr>
              )
            })}
            <tr>
              <td className="mono text-[10.5px] text-slate-400">training rows</td>
              {(result.models || []).map((model) => (
                <td key={model.id} className="mono text-right">{formatNumber(model.metrics?.training_rows ?? 0)}</td>
              ))}
            </tr>
            <tr>
              <td className="mono text-[10.5px] text-slate-400">task / active</td>
              {(result.models || []).map((model) => (
                <td key={model.id} className="text-right">
                  <Badge tone={model.task === 'classification' ? 'cyan' : 'purple'}>{model.task}</Badge>{' '}
                  {model.is_active ? <Badge tone="green">active</Badge> : null}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ModelDrawer({ modelId, onClose, onChanged, canActivate }) {
  const toast = useToast()
  const detail = useApi(() => (modelId ? modelsApi.get(modelId) : Promise.resolve(null)), [modelId], { enabled: Boolean(modelId) })
  const validation = useApi(() => (modelId ? modelsApi.validate(modelId) : Promise.resolve(null)), [modelId], { enabled: Boolean(modelId) })
  const model = detail.data

  const activate = useAction(
    async () => {
      const result = await modelsApi.activate(modelId)
      toast.success('Model activated', `Validation accuracy ${formatPercent(result?.validation?.accuracy, 2)}.`)
      onChanged?.()
      detail.refetch()
      validation.refetch()
      return result
    },
    { onError: (failure) => toast.error('Activation refused', failure.message) },
  )

  const confusion = model?.confusion_matrix || model?.metrics?.confusion_matrix
  const classReport = model?.class_report || model?.metrics?.class_report || []
  const importance = model?.feature_importance || []

  const maxCell = useMemo(() => {
    if (!confusion?.matrix) return 1
    return Math.max(1, ...confusion.matrix.flat().map((value) => Number(value) || 0))
  }, [confusion])

  if (!modelId) return null

  return (
    <Drawer
      open
      onClose={onClose}
      title={model?.name || 'Model detail'}
      subtitle={model ? `${model.algorithm} · v${model.version} · ${model.task} · trained ${formatDateTime(model.trained_at)}` : 'Loading…'}
      width="max-w-3xl"
      footer={
        canActivate && model ? (
          <div className="flex w-full items-center gap-2">
            {model.is_active ? <Badge tone="green">currently active</Badge> : <Button size="sm" variant="success" icon={Power} loading={activate.busy} onClick={activate.run}>Activate this model</Button>}
            <span className="muted ml-auto">activation re-validates against stored labelled traffic first</span>
          </div>
        ) : null
      }
    >
      {detail.loading && !model ? (
        <LoadingState label="Loading model detail…" />
      ) : detail.error ? (
        <ErrorState error={detail.error} onRetry={detail.refetch} />
      ) : !model ? null : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={model.status} />
            <Badge tone={model.task === 'classification' ? 'cyan' : 'purple'}>{model.task}</Badge>
            {model.is_active ? <Badge tone="green">active</Badge> : null}
            <Badge tone={model.artifact_available ? 'green' : 'red'}>
              artifact {model.artifact_available ? 'available' : 'missing'}
            </Badge>
            {model.error_message ? <Badge tone="red">{model.error_message}</Badge> : null}
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
            {[
              { label: 'Accuracy', value: model.accuracy },
              { label: 'Precision (w)', value: model.metrics?.precision_weighted ?? model.precision_score },
              { label: 'Recall (w)', value: model.metrics?.recall_weighted ?? model.recall_score },
              { label: 'F1 (w)', value: model.metrics?.f1_weighted ?? model.f1_score },
              { label: 'ROC AUC (OvR)', value: model.metrics?.roc_auc_ovr ?? model.roc_auc },
              { label: 'Log loss', value: model.metrics?.log_loss },
              { label: 'CV accuracy', value: model.metrics?.cv_accuracy_mean },
              { label: 'Binary attack AUC', value: model.metrics?.roc_auc_binary_attack },
            ].map((metric) => (
              <div key={metric.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
                <p className="text-[9.5px] uppercase tracking-wide text-slate-500">{metric.label}</p>
                <p className="mt-0.5 text-base font-bold leading-none text-slate-100">
                  {metric.value === null || metric.value === undefined ? '—' : Number(metric.value).toFixed(4)}
                </p>
              </div>
            ))}
          </div>

          <KeyValue
            columns={2}
            items={[
              { label: 'Model id', value: model.id, mono: true },
              { label: 'Dataset', value: model.dataset_name || '—' },
              { label: 'Training rows', value: formatNumber(model.training_rows), mono: true },
              { label: 'Train / test split', value: `${formatNumber(model.metrics?.train_size)} / ${formatNumber(model.metrics?.test_size)}`, mono: true },
              { label: 'CV accuracy std', value: model.metrics?.cv_accuracy_std ? Number(model.metrics.cv_accuracy_std).toFixed(4) : '—', mono: true },
              { label: 'Trained by', value: model.trained_by || '—' },
              { label: 'Artifact path', value: model.artifact_path, mono: true },
              { label: 'Classes', value: `${model.classes?.length || model.metrics?.n_classes || 0}`, mono: true },
            ]}
          />

          {model.notes ? <p className="muted rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">{model.notes}</p> : null}

          {validation.data ? (
            <div className={`rounded-xl border p-3 ${validation.data.valid ? 'border-emerald-500/30 bg-emerald-500/8' : 'border-rose-500/30 bg-rose-500/8'}`}>
              <p className={`flex items-center gap-1.5 text-xs font-bold ${validation.data.valid ? 'text-emerald-300' : 'text-rose-300'}`}>
                {validation.data.valid ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                Live validation {validation.data.valid ? 'passed' : 'failed'} — accuracy {formatPercent(validation.data.accuracy, 2)} (minimum{' '}
                {formatPercent(validation.data.min_required_accuracy, 0)})
              </p>
              <p className="muted mt-1">
                Re-scored against {formatNumber(validation.data.evaluation?.rows)} stored labelled records
                {validation.data.evaluation?.evaluated_at ? ` · ${timeAgo(validation.data.evaluation.evaluated_at)}` : ''}.
              </p>
            </div>
          ) : null}

          {confusion?.matrix?.length ? (
            <div>
              <p className="panel-title mb-2 flex items-center gap-1.5"><Grid3x3 size={11} /> Confusion matrix (test split)</p>
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full border-collapse text-[10px]">
                  <thead>
                    <tr>
                      <th className="border-b border-slate-800 bg-slate-900/70 px-2 py-1.5 text-left font-semibold uppercase tracking-wide text-slate-500">
                        actual ↓ / predicted →
                      </th>
                      {confusion.labels.map((label) => (
                        <th key={label} className="border-b border-slate-800 bg-slate-900/70 px-2 py-1.5 text-center font-semibold text-slate-400">
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {confusion.matrix.map((row, rowIndex) => (
                      <tr key={rowIndex}>
                        <td className="border-b border-slate-800/60 px-2 py-1 font-semibold text-slate-300">{confusion.labels[rowIndex]}</td>
                        {row.map((value, columnIndex) => {
                          const intensity = Number(value) / maxCell
                          const diagonal = rowIndex === columnIndex
                          return (
                            <td
                              key={columnIndex}
                              className="border-b border-slate-800/60 px-2 py-1 text-center font-mono"
                              style={{
                                background: diagonal
                                  ? `rgba(52,211,153,${0.08 + intensity * 0.5})`
                                  : value > 0
                                    ? `rgba(251,113,133,${0.08 + intensity * 0.6})`
                                    : 'transparent',
                                color: diagonal ? '#a7f3d0' : value > 0 ? '#fecdd3' : '#475569',
                              }}
                              title={`${confusion.labels[rowIndex]} predicted as ${confusion.labels[columnIndex]}: ${value}`}
                            >
                              {formatNumber(value)}
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}

          {classReport.length ? (
            <div>
              <p className="panel-title mb-2">Per-class report</p>
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
                maxHeight={260}
              />
            </div>
          ) : null}

          {importance.length ? (
            <Card title="Feature importance" subtitle={model.metrics?.algorithm_label || model.algorithm} icon={BrainCircuit} dense>
              <CategoryBarChart
                data={importance.slice(0, 14).map((item) => ({ name: item.label || item.feature, value: Number(item.importance) }))}
                height={Math.max(240, Math.min(importance.length, 14) * 22)}
                horizontal
                formatter={(value) => Number(value).toFixed(3)}
              />
            </Card>
          ) : null}

          {model.metrics?.class_distribution ? (
            <div>
              <p className="panel-title mb-2 flex items-center gap-1.5"><Database size={11} /> Training class balance</p>
              <ul className="space-y-1.5">
                {Object.entries(model.metrics.class_distribution).map(([name, value]) => (
                  <li key={name} className="flex items-center gap-2">
                    <span className="w-32 shrink-0 truncate text-[11px] text-slate-300">{name}</span>
                    <Progress className="flex-1" value={value} max={Math.max(...Object.values(model.metrics.class_distribution))} tone="cyan" />
                    <span className="mono w-14 shrink-0 text-right text-[10.5px] text-slate-400">{formatNumber(value)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          <p className="muted flex items-start gap-1.5">
            <Info size={11} className="mt-0.5 shrink-0" />
            Metrics are measured on a held-out test split of the training dataset; live validation re-scores the model against stored traffic.
            Neither figure is a guarantee of future performance.
          </p>
        </div>
      )}
    </Drawer>
  )
}
