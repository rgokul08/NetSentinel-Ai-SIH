import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { AuthProvider, useAuth } from './context/AuthContext'
import { RealtimeProvider } from './context/RealtimeContext'
import { ToastProvider } from './context/ToastContext'
import AppLayout from './components/layout/AppLayout'
import { Button, LoadingState } from './components/ui'

/* Pages are code-split so the initial bundle stays small. */
const Login = lazy(() => import('./pages/Login'))
const ResetPassword = lazy(() => import('./pages/ResetPassword'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Timeline = lazy(() => import('./pages/Timeline'))
const ThreatMap = lazy(() => import('./pages/ThreatMap'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Detection = lazy(() => import('./pages/Detection'))
const Forecast = lazy(() => import('./pages/Forecast'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Reports = lazy(() => import('./pages/Reports'))
const Models = lazy(() => import('./pages/Models'))
const Datasets = lazy(() => import('./pages/Datasets'))
const Blockchain = lazy(() => import('./pages/Blockchain'))
const Simulation = lazy(() => import('./pages/Simulation'))
const AuditLog = lazy(() => import('./pages/AuditLog'))
const Admin = lazy(() => import('./pages/Admin'))
const Settings = lazy(() => import('./pages/Settings'))
const NotFound = lazy(() => import('./pages/NotFound'))

function PageFallback() {
  return <LoadingState label="Loading workspace…" className="py-24" />
}

/** Redirects unauthenticated visitors to /login, remembering where they came from. */
function RequireAuth({ children }) {
  const { isAuthenticated, initializing } = useAuth()
  const location = useLocation()

  if (initializing) return <LoadingState label="Restoring session…" className="py-24" />
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return children
}

/**
 * Capability gate. Rather than silently hiding a page (which looks broken), it
 * renders an explicit "not permitted" panel - the API enforces the same rule.
 */
function RequireCapability({ capability, title, children }) {
  const { can, role } = useAuth()
  if (!capability || can(capability)) return children
  return (
    <div className="card mx-auto max-w-lg p-8 text-center">
      <div className="mx-auto mb-3 w-fit rounded-full border border-amber-500/40 bg-amber-500/10 p-3">
        <ShieldAlert size={20} className="text-amber-300" />
      </div>
      <h2 className="text-sm font-semibold text-slate-100">{title || 'Insufficient permissions'}</h2>
      <p className="muted mx-auto mt-2 max-w-sm">
        Your role (<span className="font-mono text-amber-300">{role}</span>) does not include the{' '}
        <span className="font-mono text-slate-300">{capability}</span> capability, so this workspace is not available.
        The backend enforces the same rule on every request.
      </p>
      <div className="mt-4 flex justify-center">
        <Button variant="secondary" onClick={() => window.history.back()}>
          Go back
        </Button>
      </div>
    </div>
  )
}

function Workspace() {
  return (
    <RealtimeProvider>
      <Routes>
        <Route element={<AppLayout />}>
          {/* Public landing page: the Command Center dashboard is readable by
              guests with no session. Every other workspace page requires auth
              and redirects to /login, remembering where the visitor was headed. */}
          <Route index element={<Dashboard />} />
          <Route path="analytics" element={<RequireAuth><Analytics /></RequireAuth>} />
          <Route path="timeline" element={<RequireAuth><Timeline /></RequireAuth>} />
          <Route path="threat-map" element={<RequireAuth><ThreatMap /></RequireAuth>} />
          <Route path="traffic" element={<RequireAuth><Traffic /></RequireAuth>} />
          <Route
            path="detection"
            element={
              <RequireAuth>
                <RequireCapability capability="predict.run" title="Detection Lab requires analyst access">
                  <Detection />
                </RequireCapability>
              </RequireAuth>
            }
          />
          <Route path="forecast" element={<RequireAuth><Forecast /></RequireAuth>} />
          <Route path="alerts" element={<RequireAuth><Alerts /></RequireAuth>} />
          <Route path="reports" element={<RequireAuth><Reports /></RequireAuth>} />
          <Route path="models" element={<RequireAuth><Models /></RequireAuth>} />
          <Route path="datasets" element={<RequireAuth><Datasets /></RequireAuth>} />
          <Route path="blockchain" element={<RequireAuth><Blockchain /></RequireAuth>} />
          <Route path="simulation" element={<RequireAuth><Simulation /></RequireAuth>} />
          <Route
            path="audit"
            element={
              <RequireAuth>
                <RequireCapability capability="audit.view" title="Audit logs are restricted to administrators">
                  <AuditLog />
                </RequireCapability>
              </RequireAuth>
            }
          />
          <Route
            path="admin"
            element={
              <RequireAuth>
                <RequireCapability capability="users.manage" title="The admin console is restricted to administrators">
                  <Admin />
                </RequireCapability>
              </RequireAuth>
            }
          />
          <Route path="settings" element={<RequireAuth><Settings /></RequireAuth>} />
          <Route path="*" element={<RequireAuth><NotFound /></RequireAuth>} />
        </Route>
      </Routes>
    </RealtimeProvider>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            {/* The workspace shell (and its public Command Center landing page)
                renders for everyone; individual pages opt into auth themselves. */}
            <Route path="/*" element={<Workspace />} />
          </Routes>
        </Suspense>
      </AuthProvider>
    </ToastProvider>
  )
}
