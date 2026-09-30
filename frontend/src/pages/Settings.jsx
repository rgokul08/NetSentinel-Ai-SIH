import { useEffect, useMemo, useState } from 'react'
import {
  Bell,
  Check,
  CheckCircle2,
  Copy,
  Eye,
  KeyRound,
  Monitor,
  Palette,
  QrCode,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  ShieldOff,
  Sliders,
  UserCog,
  XCircle,
} from 'lucide-react'
import { authApi, systemApi } from '../services/endpoints'
import { useAction, useApi } from '../hooks/useApi'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { PREFERENCE_DEFAULTS, PREFERENCE_META, usePreferences } from '../hooks/usePreferences'
import {
  Badge,
  Button,
  Card,
  Checkbox,
  ErrorState,
  Field,
  Input,
  KeyValue,
  LoadingState,
  Progress,
  Select,
  StatusBadge,
} from '../components/ui'
import { WINDOWS } from '../utils/constants'
import { formatDateTime, timeAgo } from '../utils/format'
import { ROLE_TONES } from '../utils/theme'

const AVATAR_COLORS = ['#22d3ee', '#818cf8', '#34d399', '#f472b6', '#fbbf24', '#60a5fa', '#f87171', '#a3e635']

export default function Settings() {
  const { user, updateUser } = useAuth()
  const toast = useToast()
  const { prefs, setPreference, resetPreferences } = usePreferences()

  const [profile, setProfile] = useState({ name: user?.name || '', color: user?.avatar_color || AVATAR_COLORS[0] })
  const [password, setPassword] = useState({ current: '', next: '', confirm: '' })
  const [showPassword, setShowPassword] = useState(false)

  const me = useApi(() => authApi.me(), [])
  const roles = useApi(() => authApi.roles(), [])
  const config = useApi(() => systemApi.config(), [])
  const health = useApi(() => systemApi.detailedHealth(), [])

  const current = me.data || user || {}

  useEffect(() => {
    if (current?.name) setProfile((p) => ({ ...p, name: current.name }))
    if (current?.avatar_color) setProfile((p) => ({ ...p, color: current.avatar_color }))
  }, [current?.name, current?.avatar_color])

  const saveProfile = useAction(
    async () => {
      const result = await authApi.updateProfile({ name: profile.name.trim(), avatar_color: profile.color })
      updateUser(result)
      toast.success('Profile updated', 'Your display name and avatar colour were saved.')
      me.refetch()
      return result
    },
    { onError: (failure) => toast.error('Could not save profile', failure.message) },
  )

  const changePassword = useAction(
    async () => {
      if (password.next !== password.confirm) throw new Error('The new passwords do not match.')
      const result = await authApi.changePassword({ current_password: password.current, new_password: password.next })
      setPassword({ current: '', next: '', confirm: '' })
      toast.success('Password changed', result?.message || 'Use the new password at your next sign-in.')
      return result
    },
    { onError: (failure) => toast.error('Password change failed', failure.message) },
  )

  const passwordScore = useMemo(() => scorePassword(password.next), [password.next])
  const myRole = roles.data?.roles?.find((role) => role.key === current.role)

  return (
    <div className="space-y-4">
      <Card bodyClass="p-4">
        <div className="flex flex-wrap items-center gap-4">
          <span
            className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl text-lg font-black text-slate-950"
            style={{ background: profile.color || '#22d3ee' }}
          >
            {initials(profile.name || current.email)}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-lg font-bold text-slate-100">{profile.name || 'Unnamed user'}</p>
            <p className="mono truncate text-[11.5px] text-slate-400">{current.email}</p>
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              <Badge tone={ROLE_TONES[current.role] || 'slate'}>{current.role}</Badge>
              <Badge tone={current.auth_provider === 'appwrite' ? 'purple' : 'cyan'}>
                {current.auth_provider === 'appwrite' ? 'Appwrite identity' : 'local identity'}
              </Badge>
              <Badge tone={current.mfa_enabled ? 'green' : 'slate'}>
                <ShieldCheck size={9} /> MFA {current.mfa_enabled ? 'enabled' : 'off'}
              </Badge>
              <Badge tone={current.is_active === false ? 'red' : 'green'}>{current.is_active === false ? 'disabled' : 'active'}</Badge>
            </div>
          </div>
          <div className="text-right">
            <p className="muted">Last sign-in</p>
            <p className="mono text-[11.5px] text-slate-300">{current.last_login ? formatDateTime(current.last_login) : 'this session'}</p>
            <p className="muted mt-1">Member since</p>
            <p className="mono text-[11.5px] text-slate-300">{current.created_at ? formatDateTime(current.created_at) : '—'}</p>
          </div>
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Profile" subtitle="Shown across the console and in audit records" icon={UserCog}>
          <div className="space-y-3">
            <Input
              label="Display name"
              value={profile.name}
              onChange={(event) => setProfile({ ...profile, name: event.target.value })}
              placeholder="Your full name"
              maxLength={120}
              error={profile.name.trim().length === 1 ? 'Use at least 2 characters' : null}
            />
            <Field label="Avatar colour" hint="Used for the initials badge in the top bar, tables and audit views.">
              <div className="flex flex-wrap gap-2">
                {AVATAR_COLORS.map((color) => (
                  <button
                    key={color}
                    type="button"
                    onClick={() => setProfile({ ...profile, color })}
                    className="flex h-8 w-8 items-center justify-center rounded-lg border-2 transition"
                    style={{ background: color, borderColor: profile.color === color ? '#e2e8f0' : 'transparent' }}
                    aria-label={`Use colour ${color}`}
                  >
                    {profile.color === color ? <Check size={14} className="text-slate-950" /> : null}
                  </button>
                ))}
              </div>
            </Field>
            <Field label="Email address" hint="Contact an administrator to change the sign-in email; it is the account identity used by audit logs.">
              <p className="input mono flex items-center text-slate-400">{current.email}</p>
            </Field>
            <div className="flex items-center gap-2">
              <Button variant="primary" loading={saveProfile.busy} onClick={saveProfile.run} disabled={!profile.name.trim()}>
                Save profile
              </Button>
              <Button variant="ghost" onClick={() => setProfile({ name: current.name || '', color: current.avatar_color || AVATAR_COLORS[0] })}>
                Reset
              </Button>
            </div>
            {saveProfile.error ? <ErrorState error={saveProfile.error} compact /> : null}
          </div>
        </Card>

        <Card title="Password" subtitle="Minimum 8 characters; verified against the stored bcrypt hash" icon={KeyRound}>
          <div className="space-y-3">
            <Field label="Current password" required>
              <div className="relative">
                <input
                  className="input pr-9"
                  type={showPassword ? 'text' : 'password'}
                  value={password.current}
                  onChange={(event) => setPassword({ ...password, current: event.target.value })}
                  autoComplete="current-password"
                  placeholder="••••••••"
                />
                <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-300" onClick={() => setShowPassword((v) => !v)}>
                  <Eye size={13} />
                </button>
              </div>
            </Field>
            <Field label="New password" required error={password.next && passwordScore.length < 8 ? 'Use at least 8 characters' : null}>
              <input
                className="input"
                type={showPassword ? 'text' : 'password'}
                value={password.next}
                onChange={(event) => setPassword({ ...password, next: event.target.value })}
                autoComplete="new-password"
                placeholder="At least 8 characters"
              />
            </Field>
            {password.next ? (
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <span className="muted">Strength</span>
                  <span className="mono text-[10.5px] text-slate-400">{passwordScore.label}</span>
                </div>
                <Progress value={passwordScore.score} max={4} tone={passwordScore.score >= 3 ? 'green' : passwordScore.score === 2 ? 'amber' : 'red'} />
                <ul className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
                  {passwordScore.checks.map((check) => (
                    <li key={check.label} className={`flex items-center gap-1 text-[10px] ${check.ok ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {check.ok ? <CheckCircle2 size={9} /> : <XCircle size={9} />} {check.label}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <Field label="Confirm new password" required error={password.confirm && password.next !== password.confirm ? 'Passwords do not match' : null}>
              <input
                className="input"
                type={showPassword ? 'text' : 'password'}
                value={password.confirm}
                onChange={(event) => setPassword({ ...password, confirm: event.target.value })}
                autoComplete="new-password"
                placeholder="Repeat the new password"
              />
            </Field>
            <Button
              variant="primary"
              icon={KeyRound}
              loading={changePassword.busy}
              onClick={changePassword.run}
              disabled={!password.current || passwordScore.length < 8 || password.next !== password.confirm}
            >
              Change password
            </Button>
            {changePassword.error ? <ErrorState error={changePassword.error} compact /> : null}
            {changePassword.result ? (
              <p className="flex items-center gap-1.5 text-[11px] text-emerald-300">
                <CheckCircle2 size={12} /> {changePassword.result.message || 'Password updated successfully.'}
              </p>
            ) : null}
          </div>
        </Card>
      </div>

      <MfaPanel me={me} onChanged={() => { me.refetch(); updateUser({ mfa_enabled: undefined }) }} />

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Interface preferences" subtitle="Stored in this browser only — they never affect other analysts" icon={Sliders}>
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/40 p-3">
              <div className="min-w-0">
                <p className="flex items-center gap-1.5 text-[11.5px] font-semibold text-slate-200"><Bell size={11} /> {PREFERENCE_META.liveUpdates.label}</p>
                <p className="muted mt-0.5">{PREFERENCE_META.liveUpdates.description}</p>
              </div>
              <Checkbox checked={prefs.liveUpdates} onChange={(value) => setPreference('liveUpdates', value)} label="" />
            </div>

            <Select
              label={PREFERENCE_META.defaultWindow.label}
              value={prefs.defaultWindow}
              onChange={(event) => setPreference('defaultWindow', event.target.value)}
              options={WINDOWS.filter((item) => ['1h', '6h', '24h', '7d', '30d'].includes(item.value))}
              hint={`${PREFERENCE_META.defaultWindow.description} Applies the next time those pages load.`}
            />

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <p className="flex items-center gap-1.5 text-[11.5px] font-semibold text-slate-200"><Monitor size={11} /> {PREFERENCE_META.reduceMotion.label}</p>
                <p className="muted mt-0.5">{PREFERENCE_META.reduceMotion.description}</p>
                <Checkbox className="mt-2" checked={prefs.reduceMotion} onChange={(value) => setPreference('reduceMotion', value)} label={prefs.reduceMotion ? 'Motion reduced' : 'Animations enabled'} />
              </div>
              <Select
                label={PREFERENCE_META.tableDensity.label}
                value={prefs.tableDensity}
                onChange={(event) => setPreference('tableDensity', event.target.value)}
                options={[
                  { value: 'comfortable', label: 'Comfortable' },
                  { value: 'compact', label: 'Compact (more rows)' },
                ]}
                hint={PREFERENCE_META.tableDensity.description}
              />
            </div>

            <div className="flex items-center gap-2">
              <Button variant="ghost" icon={RefreshCw} onClick={() => { resetPreferences(); toast.info('Preferences reset', 'Interface settings are back to their defaults.') }}>
                Reset to defaults
              </Button>
              <span className="muted">
                {Object.keys(PREFERENCE_DEFAULTS).filter((key) => prefs[key] !== PREFERENCE_DEFAULTS[key]).length} customised
              </span>
            </div>
          </div>
        </Card>

        <Card
          title="Platform"
          subtitle="Backend configuration as reported by /config and /health/detailed"
          icon={ServerCog}
          actions={<Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => { config.refetch(); health.refetch() }} loading={config.loading}>Refresh</Button>}
        >
          {config.loading && !config.data ? (
            <LoadingState label="Loading platform configuration…" />
          ) : config.error ? (
            <ErrorState error={config.error} onRetry={config.refetch} compact />
          ) : (
            <div className="space-y-3">
              <KeyValue
                columns={2}
                items={[
                  { label: 'Application', value: config.data?.app_name },
                  { label: 'Version', value: config.data?.version, mono: true },
                  { label: 'Environment', value: config.data?.environment },
                  { label: 'Storage backend', value: String(config.data?.storage_backend).toUpperCase() },
                  { label: 'Appwrite', value: config.data?.appwrite_enabled ? 'connected' : 'disabled (local store)' },
                  { label: 'Blockchain mode', value: config.data?.blockchain_mode },
                  { label: 'Simulation', value: config.data?.simulation_enabled ? 'enabled' : 'disabled' },
                  { label: 'Upload limit', value: `${config.data?.max_upload_mb} MB · ${(config.data?.allowed_upload_extensions || []).join(', ')}` },
                ]}
              />

              <div>
                <p className="panel-title mb-2">Component health</p>
                <div className="space-y-1.5">
                  {Object.entries(health.data?.components || {}).map(([name, component]) => (
                    <div key={name} className="flex items-center gap-2 rounded-lg border border-slate-800/70 bg-slate-950/40 px-2.5 py-1.5">
                      <StatusBadge status={component.status || (component.ok ? 'online' : 'degraded')} />
                      <span className="mono flex-1 truncate text-[10.5px] text-slate-300">{name.replace(/_/g, ' ')}</span>
                      {component.latency_ms !== undefined ? <span className="mono text-[10px] text-slate-500">{Number(component.latency_ms).toFixed(0)} ms</span> : null}
                      {component.model_name ? <span className="mono hidden truncate text-[10px] text-slate-500 sm:block">{component.model_name}</span> : null}
                    </div>
                  ))}
                  {!health.data ? <p className="muted">Health details unavailable.</p> : null}
                </div>
              </div>

              <div>
                <p className="panel-title mb-2 flex items-center gap-1.5"><Palette size={11} /> Seed status</p>
                <ul className="space-y-1">
                  {(config.data?.seed_status?.steps || []).map((step) => (
                    <li key={step.step} className="flex items-center gap-2 text-[11px]">
                      {step.ok ? <CheckCircle2 size={11} className="text-emerald-400" /> : <XCircle size={11} className="text-rose-400" />}
                      <span className="mono text-slate-300">{step.step}</span>
                      <span className="muted truncate">{step.detail}</span>
                      <span className="mono ml-auto text-slate-500">{Number(step.seconds || 0).toFixed(2)}s</span>
                    </li>
                  ))}
                </ul>
                {config.data?.seed_status?.status ? (
                  <p className="muted mt-1.5">
                    Overall: <span className={config.data.seed_status.status === 'complete' ? 'text-emerald-300' : 'text-amber-300'}>{config.data.seed_status.status}</span>
                    {config.data.seed_status.finished_at ? ` · ${timeAgo(config.data.seed_status.finished_at)}` : ''}
                  </p>
                ) : null}
              </div>
            </div>
          )}
        </Card>
      </div>

      <Card title="My role & capabilities" subtitle="Enforced by the backend on every request, not just hidden in the UI" icon={ShieldCheck}>
        {roles.loading && !roles.data ? (
          <LoadingState label="Loading role matrix…" />
        ) : roles.error ? (
          <ErrorState error={roles.error} onRetry={roles.refetch} compact />
        ) : (
          <div className="space-y-3">
            {myRole ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
                <p className="text-[11.5px] font-semibold text-slate-200">{myRole.label}</p>
                <p className="muted mt-0.5">{myRole.description}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {(myRole.capabilities || []).map((capability) => (
                    <code key={capability} className="mono rounded border border-cyan-500/25 bg-cyan-500/8 px-1.5 py-0.5 text-[10px] text-cyan-300">
                      {capability}
                    </code>
                  ))}
                </div>
              </div>
            ) : null}
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Capability</th>
                    {(roles.data?.roles || []).map((role) => <th key={role.key} className="text-center">{role.label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {capabilityRows(roles.data?.permission_matrix || {}, roles.data?.roles || []).map((row) => (
                    <tr key={row.capability} className={row.capability === 'mfa' ? '' : undefined}>
                      <td className={`mono text-[10.5px] ${current.capabilities?.includes(row.capability) ? 'text-cyan-300' : 'text-slate-500'}`}>
                        {row.capability}
                      </td>
                      {(roles.data?.roles || []).map((role) => (
                        <td key={role.key} className="text-center">
                          {row.roles.includes(role.key) ? (
                            <CheckCircle2 size={12} className={role.key === current.role ? 'mx-auto text-emerald-400' : 'mx-auto text-slate-500'} />
                          ) : (
                            <span className="text-slate-700">—</span>
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}

function MfaPanel({ onChanged }) {
  const toast = useToast()
  const status = useApi(() => authApi.mfaStatus(), [])
  const [enrolment, setEnrolment] = useState(null)
  const [code, setCode] = useState('')
  const [secondsLeft, setSecondsLeft] = useState(30)

  useEffect(() => {
    const timer = setInterval(() => setSecondsLeft(30 - Math.floor(Date.now() / 1000) % 30), 1000)
    return () => clearInterval(timer)
  }, [])

  const enroll = useAction(
    async () => {
      const result = await authApi.mfaEnable()
      setEnrolment(result)
      setCode('')
      return result
    },
    { onError: (failure) => toast.error('Could not start enrolment', failure.message) },
  )

  const confirm = useAction(
    async () => {
      const result = await authApi.mfaConfirm(code.trim())
      toast.success('MFA enabled', 'Sign-in now requires a code from your authenticator app.')
      setEnrolment(null)
      setCode('')
      status.refetch()
      onChanged?.()
      return result
    },
    { onError: (failure) => toast.error('Confirmation failed', failure.message) },
  )

  const disable = useAction(
    async () => {
      const result = await authApi.mfaDisable(code.trim())
      toast.info('MFA disabled', 'Sign-in no longer requires a second factor.')
      setCode('')
      status.refetch()
      onChanged?.()
      return result
    },
    { onError: (failure) => toast.error('Could not disable MFA', failure.message) },
  )

  const copy = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value)
      toast.success('Copied', `${label} copied to the clipboard.`)
    } catch {
      toast.error('Copy failed', 'Your browser blocked clipboard access — select the text manually.')
    }
  }

  const enabled = Boolean(status.data?.enabled)

  return (
    <Card
      title="Multi-factor authentication"
      subtitle="Time-based one-time passwords (RFC 6238 · SHA-1 · 6 digits · 30 second period)"
      icon={ShieldCheck}
      actions={
        status.data ? (
          <Badge tone={enabled ? 'green' : status.data.pending_enrolment ? 'amber' : 'slate'}>
            {enabled ? 'active' : status.data.pending_enrolment ? 'awaiting confirmation' : 'not enrolled'}
          </Badge>
        ) : null
      }
    >
      {status.loading && !status.data ? (
        <LoadingState label="Loading MFA status…" />
      ) : status.error ? (
        <ErrorState error={status.error} onRetry={status.refetch} compact />
      ) : enabled ? (
        <div className="space-y-3">
          <div className="flex items-start gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/8 p-3">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-emerald-300" />
            <div className="min-w-0">
              <p className="text-xs font-semibold text-emerald-200">Multi-factor authentication is active</p>
              <p className="muted mt-0.5">
                Every sign-in requires your password plus a six digit code.
                {status.data.confirmed_at ? ` Enrolled ${formatDateTime(status.data.confirmed_at)}.` : ''}
              </p>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,220px)_minmax(0,1fr)]">
            <Field label="Current code window" hint="Codes rotate every 30 seconds.">
              <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3 text-center">
                <p className="mono text-3xl font-black tracking-[0.2em] text-cyan-300">{String(secondsLeft).padStart(2, '0')}s</p>
                <Progress className="mt-2" value={secondsLeft} max={30} tone="cyan" />
                <p className="muted mt-1.5">until the next code</p>
              </div>
            </Field>
            <div className="space-y-2.5">
              <Field label="Authenticator code" hint="Enter a current code to turn multi-factor authentication off.">
                <input
                  className="input mono tracking-[0.3em]"
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                />
              </Field>
              <div className="flex items-center gap-2">
                <Button variant="danger" icon={ShieldOff} loading={disable.busy} disabled={code.length !== 6} onClick={disable.run}>
                  Disable MFA
                </Button>
                <span className="muted">Disabling lowers account security and is written to the audit log.</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="muted">
            Protect this account with a second factor. Enrolment generates a fresh TOTP secret that is stored server side only —
            it is never written to the blockchain ledger or exposed by any read endpoint.
          </p>

          {!enrolment ? (
            <Button variant="primary" icon={QrCode} loading={enroll.busy} onClick={enroll.run}>
              {status.data?.pending_enrolment ? 'Regenerate enrolment key' : 'Start enrolment'}
            </Button>
          ) : (
            <div className="grid gap-3 lg:grid-cols-[minmax(0,220px)_minmax(0,1fr)]">
              <div className="rounded-xl border border-slate-800 bg-white p-3">
                {enrolment.qr_png_base64 ? (
                  <img src={`data:image/png;base64,${enrolment.qr_png_base64}`} alt="Authenticator provisioning QR code" className="mx-auto h-auto w-full" />
                ) : (
                  <div className="flex h-40 items-center justify-center text-center">
                    <p className="text-[11px] text-slate-600">
                      QR unavailable — add the key manually with the details on the right.
                    </p>
                  </div>
                )}
              </div>

              <div className="space-y-2.5">
                <Field label="Manual entry key" hint="Use this if your authenticator app cannot scan the QR code.">
                  <div className="flex items-center gap-2">
                    <code className="input mono flex-1 text-[11.5px] tracking-[0.12em] text-cyan-200">{enrolment.secret_formatted}</code>
                    <Button size="sm" variant="secondary" icon={Copy} onClick={() => copy(enrolment.secret, 'Secret key')}>Copy</Button>
                  </div>
                </Field>
                <Field label="otpauth:// URI">
                  <div className="flex items-center gap-2">
                    <code className="input mono flex-1 truncate text-[10.5px] text-slate-400" title={enrolment.otpauth_uri}>{enrolment.otpauth_uri}</code>
                    <Button size="sm" variant="secondary" icon={Copy} onClick={() => copy(enrolment.otpauth_uri, 'Provisioning URI')}>Copy</Button>
                  </div>
                </Field>
                <KeyValue
                  columns={3}
                  items={[
                    { label: 'Account', value: enrolment.account, mono: true },
                    { label: 'Issuer', value: enrolment.issuer },
                    { label: 'Algorithm', value: `${enrolment.algorithm} · ${enrolment.digits} digits · ${enrolment.period}s`, mono: true },
                  ]}
                />
                <p className="muted">{enrolment.instructions}</p>
                <div className="flex flex-wrap items-end gap-2">
                  <Field label="Verification code" className="w-36">
                    <input
                      className="input mono tracking-[0.3em]"
                      value={code}
                      onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                    />
                  </Field>
                  <Button variant="primary" icon={Check} loading={confirm.busy} disabled={code.length !== 6} onClick={confirm.run}>
                    Confirm and enable
                  </Button>
                  <Button variant="ghost" onClick={() => { setEnrolment(null); setCode('') }}>Cancel</Button>
                </div>
                {confirm.error ? <ErrorState error={confirm.error} compact /> : null}
                <p className="muted flex items-start gap-1.5">
                  <XCircle size={11} className="mt-0.5 shrink-0 text-amber-400" />
                  If you lose the device, an administrator must reset the account — there is no self-service recovery code path.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

function initials(value) {
  const parts = String(value || '')
    .split(/[\s@._-]+/)
    .filter(Boolean)
  if (!parts.length) return '?'
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
  return (parts[0][0] + parts[1][0]).toUpperCase()
}

function scorePassword(value) {
  const checks = [
    { label: '8+ characters', ok: value.length >= 8 },
    { label: 'upper & lower case', ok: /[a-z]/.test(value) && /[A-Z]/.test(value) },
    { label: 'a number', ok: /\d/.test(value) },
    { label: 'a symbol', ok: /[^A-Za-z0-9]/.test(value) },
  ]
  const score = checks.filter((check) => check.ok).length
  return { checks, score, length: value.length, label: ['too short', 'weak', 'fair', 'good', 'strong'][score] || 'weak' }
}

function capabilityRows(matrix, roles) {
  const capabilities = new Set()
  roles.forEach((role) => (role.capabilities || []).forEach((capability) => capabilities.add(capability)))
  Object.keys(matrix || {}).forEach((key) => {
    // matrix keys are `resource.action` audit permissions; capabilities are the same vocabulary
    capabilities.add(key)
  })
  return [...capabilities]
    .sort()
    .map((capability) => ({
      capability,
      roles: roles.filter((role) => (role.capabilities || []).includes(capability)).map((role) => role.key),
    }))
}
