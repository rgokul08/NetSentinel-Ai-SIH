import React, { useState } from 'react'
import api from '../api.js'
import { ErrorBox, Loading, Stat, useFetch } from '../ui.jsx'

export default function Reports() {
  const { data: rep, error } = useFetch(() => api.get('/reports/summary'), [])
  const { data: model, setData: setModel } = useFetch(() => api.get('/model/metrics'), [])
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const download = async () => {
    const r = await api.get('/reports/download-pdf', { responseType: 'blob' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(r.data); a.download = 'SOC_Attack_Forecast_Report.pdf'; a.click()
  }
  const train = async () => {
    setBusy(true); setMsg('')
    try {
      await api.post('/model/train', {})
      setModel((await api.get('/model/metrics')).data); setMsg('Model retrained successfully.')
    } catch (e) { setMsg(e.response?.data?.detail || e.message) } finally { setBusy(false) }
  }

  if (error) return <ErrorBox msg={error} />
  if (!rep) return <Loading />
  const ex = rep.executive_summary
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Reports & Model</h1>
        <button className="btn" onClick={download}>Download PDF</button>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Threat posture" value={ex.threat_posture} />
        <Stat label="Flows monitored" value={ex.total_monitored_flows} />
        <Stat label="Malicious events" value={ex.detected_malicious_events} />
        <Stat label="24h projection" value={rep.forecast_outlook['24h_projected_attacks']} />
      </div>
      {model && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">{model.name} <span className="text-slate-400 text-sm">v{model.version}</span></div>
            <button className="btn" onClick={train} disabled={busy}>{busy ? 'Training…' : 'Retrain model'}</button>
          </div>
          <div className="grid grid-cols-4 gap-3 text-sm">
            {['accuracy', 'precision_score', 'recall_score', 'f1_score'].map((k) => (
              <div key={k}><div className="text-xs uppercase text-slate-400">{k.replace('_score', '')}</div>{(model[k] * 100).toFixed(1)}%</div>
            ))}
          </div>
          {msg && <div className="text-sm text-slate-300">{msg}</div>}
        </div>
      )}
    </div>
  )
}
