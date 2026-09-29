import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BrainCircuit,
  KeyRound,
  Lock,
  Mail,
  Radar,
  ShieldCheck,
  ShieldHalf,
  User,
  Users,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { authApi, systemApi } from '../services/endpoints'
import { Button, Field, Spinner } from '../components/ui'
import { Modal } from '../components/ui/overlays'
import { ROLES } from '../utils/constants'

const DEMO_ACCOUNTS = [
  { role: 'admin', email: 'admin@cyberforecast.ai', password: 'Admin@1234', label: 'Administrator', icon: ShieldCheck },
  { role: 'analyst', email: 'analyst@cyberforecast.ai', password: 'Analyst@1234', label: 'Security Analyst', icon: Activity },
  { role: 'viewer', email: 'viewer@cyberforecast.ai', password: 'Viewer@1234', label: 'Viewer (read-only)', icon: Users },
]

const HIGHLIGHTS = [
  { icon: BrainCircuit, title: 'Real machine-learning detection', text: 'Random Forest / Gradient Boosting classifiers plus an Isolation Forest anomaly detector, trained on labelled flows and served from persisted artifacts.' },
  { icon: Radar, title: 'Probabilistic attack forecasting', text: 'Ridge lag-regression over historical attack counts estimates DDoS, port-scan, brute-force and botnet risk across 5, 15, 30 and 60-minute horizons.' },
  { icon: Lock, title: 'Blockchain-assured integrity', text: 'Every alert, model activation and forecast run is hashed into a tamper-evident ledger, optionally anchored to an EVM chain.' },
]

export default function Login() {
  const { login, register, isAuthenticated } = useAuth()
  const toast = useToast()
  const navigate = useNavigate()
  const location = useLocation()
  const from = location.state?.from || '/'
  const reason = location.state?.reason

  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({ email: '', password: '', name: '', role: 'analyst', confirm: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [fieldErrors, setFieldErrors] = useState({})
  const [health, setHealth] = useState(null)
  const [resetOpen, setResetOpen] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetResult, setResetResult] = useState(null)
  const [resetBusy, setResetBusy] = useState(false)
  const [mfa, setMfa] = useState({ required: false, code: '', message: null })

  useEffect(() => {
    if (isAuthenticated) navigate(from, { replace: true })
  }, [isAuthenticated, from, navigate])

  useEffect(() => {
    systemApi
      .health()
      .then(setHealth)
      .catch(() => setHealth(null))
  }, [])

  const set = (key) => (event) => setForm((current) => ({ ...current, [key]: event.target.value }))

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    setFieldErrors({})
    if (!form.email || !form.password) {
      setFieldErrors({ email: !form.email ? 'Email is required' : null, password: !form.password ? 'Password is required' : null })
      return
    }
    if (mode === 'register') {
      if (!form.name) return setFieldErrors({ name: 'Full name is required' })
      if (form.password.length < 8) return setFieldErrors({ password: 'Use at least 8 characters' })
      if (form.password !== form.confirm) return setFieldErrors({ confirm: 'Passwords do not match' })
    }
    setBusy(true)
    try {
      if (mode === 'login') {
        const result = await login(form.email.trim(), form.password, mfa.code.trim() || undefined)
        if (result?.requireMfa) {
          setMfa((current) => ({ ...current, required: true, message: result.message }))
          return
        }
        toast.success('Signed in', `Welcome back, ${result?.name || result?.email}.`)
      } else {
        await register({ name: form.name.trim(), email: form.email.trim(), password: form.password, role: form.role })
        toast.success('Account created', 'You are signed in. Self-service sign-ups are created as analysts; administrators can promote roles.')
      }
      navigate(from, { replace: true })
    } catch (failure) {
      setError(failure)
      if (failure?.fields?.length) {
        const mapped = {}
        failure.fields.forEach((field) => {
          const key = String(field.field).split('.').pop()
          mapped[key] = field.message
        })
        setFieldErrors(mapped)
      }
    } finally {
      setBusy(false)
    }
  }

  const sendReset = async () => {
    setResetBusy(true)
    setResetResult(null)
    try {
      const result = await authApi.forgotPassword(resetEmail.trim())
      setResetResult(result)
    } catch (failure) {
      setResetResult({ error: failure.message })
    } finally {
      setResetBusy(false)
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.05fr_1fr]">
      {/* brand / capability panel */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-slate-800/70 bg-[#070b12] p-10 lg:flex">
        <div className="grid-lines pointer-events-none absolute inset-0 opacity-70" />
        <div className="pointer-events-none absolute -left-24 top-1/3 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="pointer-events-none absolute -right-16 bottom-10 h-72 w-72 rounded-full bg-purple-500/10 blur-3xl" />

        <div className="relative">
          <div className="flex items-center gap-3">
            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-500/10">
              <ShieldHalf size={21} className="text-cyan-300" />
              <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_10px_2px_rgba(52,211,153,0.6)]" />
            </div>
            <div>
              <p className="text-base font-bold tracking-tight text-slate-100">
                CyberForecast <span className="text-cyan-400">AI</span>
              </p>
              <p className="mono text-[10px] uppercase tracking-[0.2em] text-slate-500">Network attack forecasting SOC</p>
            </div>
          </div>

          <h1 className="mt-12 max-w-lg text-3xl font-bold leading-tight tracking-tight text-slate-50">
            AI-based network attack forecasting with
            <span className="text-glow text-cyan-300"> blockchain-assured </span>
            evidence.
          </h1>
          <p className="mt-3 max-w-lg text-sm leading-relaxed text-slate-400">
            Ingest network traffic, classify every flow with trained machine-learning models, forecast which attack types are
            likely next, and keep the whole decision trail verifiable on a tamper-evident ledger.
          </p>

          <div className="mt-9 space-y-4">
            {HIGHLIGHTS.map((item) => (
              <div key={item.title} className="card card-hover flex gap-3 p-3.5">
                <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-700/70 bg-slate-800/60">
                  <item.icon size={15} className="text-cyan-300" />
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-semibold text-slate-100">{item.title}</p>
                  <p className="muted mt-0.5 leading-relaxed">{item.text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative mt-10 flex flex-wrap items-center gap-x-5 gap-y-2 text-[11px] text-slate-500">
          <span className="flex items-center gap-1.5">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: health?.status === 'online' ? '#34d399' : health ? '#fbbf24' : '#64748b' }}
            />
            Backend {health?.status || 'checking'}
            {health?.version ? ` · v${health.version}` : ''}
          </span>
          <span>Smart India Hackathon · Blockchain &amp; Cybersecurity theme</span>
        </div>
      </div>

      {/* auth form */}
      <div className="flex items-center justify-center px-4 py-10 sm:px-8">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center gap-2.5 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
              <ShieldHalf size={17} className="text-cyan-300" />
            </div>
            <p className="text-sm font-bold text-slate-100">
              CyberForecast <span className="text-cyan-400">AI</span>
            </p>
          </div>

          {reason === 'session-expired' ? (
            <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-2.5 text-[11px] text-amber-200">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <span>Your session expired or the stored token is no longer valid. Please sign in again.</span>
            </div>
          ) : null}

          <div className="card overflow-hidden">
            <div className="flex border-b border-slate-800">
              {[
                { key: 'login', label: 'Sign in' },
                { key: 'register', label: 'Create account' },
              ].map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => {
                    setMode(tab.key)
                    setError(null)
                    setFieldErrors({})
                  }}
                  className={`flex-1 px-4 py-3 text-xs font-semibold transition ${
                    mode === tab.key
                      ? 'border-b-2 border-cyan-400 bg-cyan-500/5 text-cyan-300'
                      : 'border-b-2 border-transparent text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <form className="space-y-3.5 p-5" onSubmit={submit} noValidate>
              {mode === 'register' ? (
                <Field label="Full name" required error={fieldErrors.name}>
                  <div className="relative">
                    <User size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                    <input className="input pl-8" value={form.name} onChange={set('name')} placeholder="Analyst name" autoComplete="name" />
                  </div>
                </Field>
              ) : null}

              <Field label="Work email" required error={fieldErrors.email}>
                <div className="relative">
                  <Mail size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    className="input pl-8"
                    type="email"
                    value={form.email}
                    onChange={set('email')}
                    placeholder="you@organisation.in"
                    autoComplete="email"
                  />
                </div>
              </Field>

              <Field label="Password" required error={fieldErrors.password}>
                <div className="relative">
                  <KeyRound size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    className="input pl-8"
                    type="password"
                    value={form.password}
                    onChange={set('password')}
                    placeholder="••••••••"
                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  />
                </div>
              </Field>

              {mode === 'login' && mfa.required ? (
                <div className="rounded-xl border border-cyan-500/35 bg-cyan-500/8 p-3">
                  <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wide text-cyan-300">
                    <ShieldCheck size={13} /> Second factor required
                  </p>
                  <p className="muted mt-1">{mfa.message || 'Enter the six digit code from your authenticator app.'}</p>
                  <Field label="Authenticator code" required className="mt-2.5">
                    <input
                      className="input mono text-center text-base tracking-[0.4em]"
                      value={mfa.code}
                      onChange={(event) => setMfa((current) => ({ ...current, code: event.target.value.replace(/\D/g, '').slice(0, 6) }))}
                      placeholder="000000"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      autoFocus
                    />
                  </Field>
                  <button
                    type="button"
                    className="muted mt-1.5 text-[10.5px] transition hover:text-cyan-300"
                    onClick={() => setMfa({ required: false, code: '', message: null })}
                  >
                    Cancel and sign in without a code
                  </button>
                </div>
              ) : null}

              {mode === 'register' ? (
                <>
                  <Field label="Confirm password" required error={fieldErrors.confirm}>
                    <input className="input" type="password" value={form.confirm} onChange={set('confirm')} placeholder="Repeat password" autoComplete="new-password" />
                  </Field>
                  <Field label="Requested role" hint="Administrators can change any role later from the admin console.">
                    <select className="select" value={form.role} onChange={set('role')}>
                      {ROLES.map((role) => (
                        <option key={role.value} value={role.value}>
                          {role.label} — {role.description}
                        </option>
                      ))}
                    </select>
                  </Field>
                </>
              ) : null}

              {error ? (
                <div className="flex items-start gap-2 rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">
                  <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                  <span>{error.message}</span>
                </div>
              ) : null}

              <Button type="submit" variant="primary" className="w-full py-2.5" loading={busy}>
                {busy ? 'Verifying…' : mode === 'login' ? (mfa.required ? 'Verify code and sign in' : 'Sign in securely') : 'Create account'}
                {!busy ? <ArrowRight size={14} /> : null}
              </Button>

              {mode === 'login' ? (
                <button
                  type="button"
                  className="muted mx-auto block text-center transition hover:text-cyan-300"
                  onClick={() => {
                    setResetOpen(true)
                    setResetResult(null)
                    setResetEmail(form.email)
                  }}
                >
                  Forgot your password?
                </button>
              ) : null}
            </form>
          </div>

          {/* demo credentials - these accounts are seeded by the backend */}
          <div className="card mt-4 p-4">
            <p className="panel-title mb-2.5">Demo accounts (seeded by the backend)</p>
            <div className="space-y-1.5">
              {DEMO_ACCOUNTS.map((account) => (
                <button
                  key={account.role}
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setMode('login')
                    setError(null)
                    setForm((current) => ({ ...current, email: account.email, password: account.password }))
                  }}
                  className="flex w-full items-center gap-2.5 rounded-lg border border-slate-800 bg-slate-900/50 px-2.5 py-2 text-left transition hover:border-cyan-500/40 hover:bg-slate-800/60 disabled:opacity-50"
                >
                  <account.icon size={14} className="shrink-0 text-cyan-400" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[11px] font-semibold text-slate-200">{account.label}</span>
                    <span className="mono block truncate text-[10px] text-slate-500">
                      {account.email} · {account.password}
                    </span>
                  </span>
                  <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wide text-cyan-400/70">use</span>
                </button>
              ))}
            </div>
            <p className="muted mt-2.5">
              Credentials are stored in your browser session only. Change them from <span className="text-slate-300">Settings</span> before
              deploying anywhere public.
            </p>
          </div>

          <p className="muted mt-4 text-center">
            Protected by JWT sessions, bcrypt password hashing and server-side role-based access control.
          </p>
          {busy ? (
            <p className="mt-3 flex items-center justify-center gap-2 text-[11px] text-cyan-300">
              <Spinner size={12} /> Contacting the backend…
            </p>
          ) : null}
          <p className="muted mt-2 text-center">
            Need the API docs? <Link to="/api/docs" className="text-cyan-400 hover:underline">Open Swagger UI</Link>
          </p>
        </div>
      </div>

      <Modal
        open={resetOpen}
        onClose={() => setResetOpen(false)}
        title="Reset your password"
        subtitle="A single-use reset token is issued by the backend."
        size="sm"
        icon={KeyRound}
        footer={
          <>
            <Button variant="ghost" onClick={() => setResetOpen(false)}>
              Close
            </Button>
            <Button variant="primary" onClick={sendReset} loading={resetBusy} disabled={!resetEmail}>
              Send reset link
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Field label="Account email" required>
            <input className="input" type="email" value={resetEmail} onChange={(event) => setResetEmail(event.target.value)} placeholder="you@organisation.in" />
          </Field>
          {resetResult?.error ? (
            <p className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">{resetResult.error}</p>
          ) : null}
          {resetResult && !resetResult.error ? (
            <div className="space-y-2 rounded-lg border border-cyan-500/30 bg-cyan-500/8 p-3">
              <p className="text-[11px] text-cyan-100">{resetResult.message}</p>
              {resetResult.dev_token ? (
                <>
                  <p className="muted">
                    No SMTP provider is configured on this backend, so the token is returned directly (development mode only). It expires in{' '}
                    {resetResult.expires_in_minutes} minutes.
                  </p>
                  <code className="mono block break-all rounded border border-slate-700 bg-slate-950/70 p-2 text-cyan-300">{resetResult.dev_token}</code>
                  <Link to={`/reset-password?token=${encodeURIComponent(resetResult.dev_token)}`} className="btn-primary btn-sm w-full">
                    Continue to reset form
                  </Link>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  )
}
