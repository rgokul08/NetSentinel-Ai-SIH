import React, { useState } from 'react'
import api from '../api.js'
import { Badge, ErrorBox } from '../ui.jsx'

const DEFAULTS = { source_ip: '192.168.1.45', destination_ip: '10.0.0.1', source_port: 54321, destination_port: 80, protocol: 'TCP', packet_count: 50, packet_size: 1200, flow_duration: 2.5, tcp_flags: 'SYN' }
const NUM = ['source_port', 'destination_port', 'packet_count', 'packet_size', 'flow_duration']

export default function Detection() {
  const [form, setForm] = useState(DEFAULTS)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setErr('')
    try {
      const body = { ...form }
      NUM.forEach((k) => (body[k] = Number(body[k])))
      setRes((await api.post('/predict', body)).data)
    } catch (ex) {
      setErr(ex.response?.data?.detail ? JSON.stringify(ex.response.data.detail) : ex.message)
    } finally { setBusy(false) }
  }

  const contrib = res?.explanation?.contributions
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Attack Detection</h1>
      <div className="grid lg:grid-cols-2 gap-4">
        <form onSubmit={submit} className="card grid grid-cols-2 gap-3">
          {Object.keys(DEFAULTS).map((k) => (
            <label key={k} className="text-xs text-slate-400">{k}
              <input className="input mt-1" value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} />
            </label>
          ))}
          <button className="btn col-span-2" disabled={busy}>{busy ? 'Analysing…' : 'Analyse flow'}</button>
        </form>
        <div className="card">
          {err && <ErrorBox msg={err} />}
          {!res && !err && <div className="text-slate-400 text-sm">Submit a flow to classify it.</div>}
          {res && (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-2xl font-bold">{res.attack_type}</span><Badge level={res.risk_level} />
              </div>
              <div className="text-sm text-slate-300">Confidence {(res.confidence * 100).toFixed(0)}% · Anomaly score {res.anomaly_score}</div>
              {res.explanation?.summary && <p className="text-sm text-slate-400">{res.explanation.summary}</p>}
              {Array.isArray(contrib) && contrib.slice(0, 6).map((c, i) => (
                <div key={i} className="text-xs border-t border-soc-border pt-2">
                  <div className="flex justify-between"><span className="font-medium">{c.feature} ({c.value})</span>
                    <span className={c.direction === 'risk_increase' ? 'text-rose-400' : 'text-emerald-400'}>{c.impact}</span></div>
                  <div className="text-slate-500">{c.explanation}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
