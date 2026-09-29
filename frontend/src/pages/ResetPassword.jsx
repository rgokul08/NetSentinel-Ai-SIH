import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowLeft, KeyRound, ShieldHalf } from 'lucide-react'
import { authApi } from '../services/endpoints'
import { useToast } from '../context/ToastContext'
import { Button, Field } from '../components/ui'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const [token, setToken] = useState(params.get('token') || '')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  const submit = async (event) => {
    event.preventDefault()
    setError(null)
    if (!token) return setError({ message: 'A reset token is required. Request one from the sign-in page.' })
    if (password.length < 8) return setError({ message: 'The new password must be at least 8 characters long.' })
    if (password !== confirm) return setError({ message: 'The two passwords do not match.' })
    setBusy(true)
    try {
      await authApi.resetPassword(token.trim(), password)
      toast.success('Password updated', 'Sign in with your new password.')
      navigate('/login', { replace: true })
    } catch (failure) {
      setError(failure)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="mb-5 flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
            <ShieldHalf size={17} className="text-cyan-300" />
          </div>
          <p className="text-sm font-bold text-slate-100">
            CyberForecast <span className="text-cyan-400">AI</span>
          </p>
        </div>

        <form className="card space-y-3.5 p-5" onSubmit={submit} noValidate>
          <div>
            <h1 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <KeyRound size={15} className="text-cyan-400" /> Choose a new password
            </h1>
            <p className="muted mt-1">Tokens are single-use and expire after 60 minutes.</p>
          </div>

          <Field label="Reset token" required>
            <textarea className="input resize-y font-mono text-[11px]" rows={3} value={token} onChange={(event) => setToken(event.target.value)} placeholder="paste the token you received" />
          </Field>
          <Field label="New password" required hint="Minimum 8 characters, at least one letter and one digit.">
            <input className="input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" />
          </Field>
          <Field label="Confirm new password" required>
            <input className="input" type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" />
          </Field>

          {error ? <p className="rounded-lg border border-rose-500/35 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">{error.message}</p> : null}

          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Update password
          </Button>
          <Link to="/login" className="muted mx-auto flex items-center justify-center gap-1.5 transition hover:text-cyan-300">
            <ArrowLeft size={12} /> Back to sign in
          </Link>
        </form>
      </div>
    </div>
  )
}
