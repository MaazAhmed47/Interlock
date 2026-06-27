import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ScanLine, Server, Activity, ShieldCheck } from 'lucide-react'
import { AuditEvent, ScanHistoryEvent, ScanStats, ShadowStats, DEMO_PROMPTS } from '../api'
import { useDashboardData } from '../components/DashLayout'
import MetricCard from '../components/MetricCard'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

const LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']

type ActivityRow = {
  key: string
  timestamp: string
  source: string
  target: string
  action: string
  severity: string
  reason: string
}

function PromptLibrary() {
  return (
    <>
      <div className="dash-section-title">Demo Prompt Library</div>
      <div className="prompt-grid">
        {DEMO_PROMPTS.map(item => (
          <Link
            key={item.label}
            to="/dashboard/scan"
            state={{ prompt: item.prompt, target: item.target }}
            className={`prompt-card ${item.tone}`}
          >
            <div className="prompt-card-meta">{item.target === 'output' ? 'Output scan' : 'Prompt scan'}</div>
            <div className="prompt-card-title">{item.label}</div>
            <p>{item.intent}</p>
            <code>{item.prompt}</code>
          </Link>
        ))}
      </div>
    </>
  )
}

function eventTimestamp(event: AuditEvent) {
  return event.timestamp || event.ts || ''
}

function getShadowMetric(shadow: ShadowStats | null) {
  if (!shadow) {
    return { label: 'Shadow Findings', value: '-', sub: 'No shadow stats yet' }
  }

  const total = Number.isFinite(shadow.total) ? shadow.total : 0
  const threatRate = shadow.threat_rate
  const hasThreatRate = typeof threatRate === 'number' && Number.isFinite(threatRate)

  if (hasThreatRate) {
    return {
      label: 'Shadow Threat Rate',
      value: Math.round(threatRate * 100) + '%',
      sub: `${total} shadow scan${total === 1 ? '' : 's'}`,
    }
  }

  const avgRisk = typeof shadow.avg_risk_score === 'number' && Number.isFinite(shadow.avg_risk_score)
    ? Math.round(shadow.avg_risk_score)
    : 0

  return {
    label: 'Shadow Findings',
    value: total,
    sub: 'Avg risk ' + avgRisk + '/100',
  }
}

function scanToActivity(event: ScanHistoryEvent, index: number): ActivityRow {
  return {
    key: 'scan-' + index + '-' + event.timestamp,
    timestamp: event.timestamp,
    source: event.endpoint || '/scan',
    target: event.prompt_preview || 'Scan event',
    action: event.is_threat ? 'block' : 'allow',
    severity: event.threat_level || 'SAFE',
    reason: event.reason || event.threat_type || '-',
  }
}

function mcpToActivity(event: AuditEvent, index: number): ActivityRow {
  return {
    key: 'mcp-' + (event.id ?? index),
    timestamp: eventTimestamp(event),
    source: event.server_id || 'mcp',
    target: event.tool_name || '-',
    action: event.action || '-',
    severity: event.drift_severity || '-',
    reason: event.reason || event.matched_rule || '-',
  }
}

function ExecutiveDemoBrief({
  demoMode,
  driftedCount,
  auditCount,
  scanCount,
}: {
  demoMode: boolean
  driftedCount: number
  auditCount: number
  scanCount: number
}) {
  const environmentLabel = demoMode ? 'Demo evidence' : 'Live environment'
  const auditLabel = auditCount > 0 ? `${auditCount} evidence event${auditCount === 1 ? '' : 's'}` : 'No evidence yet'
  const driftLabel = driftedCount > 0 ? `${driftedCount} ${driftedCount === 1 ? 'tool needs' : 'tools need'} review` : 'No drift pending'
  const scanLabel = scanCount > 0 ? `${scanCount} scan event${scanCount === 1 ? '' : 's'}` : 'Ready for scans'

  return (
    <div className="exec-demo-panel glow-card">
      <div className="exec-demo-copy">
        <div className="exec-demo-kicker">Enterprise demo brief</div>
        <h2>Runtime control for agent tool access, with evidence a security team can inspect.</h2>
        <p>Evaluate one agent workflow through Interlock: policy enforcement before execution, MCP drift review, response scanning, and a unified decision timeline.</p>
      </div>
      <div className="exec-demo-grid">
        <div className="exec-demo-item"><span>Environment</span><strong>{environmentLabel}</strong></div>
        <div className="exec-demo-item"><span>Prompt / output scans</span><strong>{scanLabel}</strong></div>
        <div className="exec-demo-item"><span>MCP review queue</span><strong>{driftLabel}</strong></div>
        <div className="exec-demo-item"><span>Audit readiness</span><strong>{auditLabel}</strong></div>
      </div>
      <div className="pilot-readiness">
        <div><span>Integration</span><strong>base_url swap</strong></div>
        <div><span>Policy</span><strong>RBAC + fail modes</strong></div>
        <div><span>MCP</span><strong>baseline + drift</strong></div>
        <div><span>Evidence</span><strong>audit + SIEM-ready</strong></div>
      </div>
    </div>
  )
}

function SecurityPosture({ scanStats }: { scanStats: ScanStats | null }) {
  const total = scanStats?.total ?? 0
  const blocked = scanStats?.threats ?? 0
  const safe = scanStats?.safe ?? 0
  const blockRate = scanStats?.block_rate ?? 0
  const avgRisk = Math.round(scanStats?.avg_risk_score ?? 0)
  const byLevel = scanStats?.by_level ?? {}
  const pieStyle = { '--blocked': String(Math.max(0, Math.min(100, blockRate))) } as CSSProperties

  return (
    <>
      <div className="dash-section-title">Security Posture</div>
      <div className="posture-grid">
        <div className="posture-card">
          <div className="posture-label">Average Risk</div>
          <div className="risk-meter">
            <div className="risk-meter-top"><strong>{avgRisk}/100</strong><span>{total} scan{total === 1 ? '' : 's'}</span></div>
            <div className="risk-bar"><span style={{ width: Math.max(0, Math.min(100, avgRisk)) + '%' }} /></div>
          </div>
        </div>
        <div className="posture-card posture-pie-card">
          <div className="posture-label">Decision Split</div>
          <div className="decision-pie" style={pieStyle}><span>{Math.round(blockRate)}%</span></div>
          <div className="posture-sub">{blocked} blocked / {safe} allowed</div>
        </div>
        <div className="posture-card">
          <div className="posture-label">Threat Levels</div>
          <div className="level-bars">
            {LEVELS.map(level => {
              const count = byLevel[level] ?? 0
              const width = total > 0 ? Math.max(4, Math.round((count / total) * 100)) : 0
              return (
                <div className="level-row" key={level}>
                  <span>{level}</span>
                  <div className="level-track"><i className={'level-fill ' + level.toLowerCase()} style={{ width: width + '%' }} /></div>
                  <b>{count}</b>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </>
  )
}

export default function Dashboard() {
  const {
    configured,
    demoMode,
    loaded,
    loading,
    health,
    usage,
    servers,
    drifted,
    audit,
    scanHistory,
    scanStats,
    shadow,
    errors,
    refreshAll,
  } = useDashboardData()

  const isOk = health?.status === 'ok'
  const hasLiveData = Boolean(usage || servers.length > 0 || shadow || drifted.length > 0 || audit.length > 0 || scanHistory.length > 0)
  const backendOnline = isOk || hasLiveData
  const demoBackendError = demoMode && Boolean(errors.health)
  const backendError = Boolean(errors.health && !hasLiveData && !demoMode)
  const backendLabel = demoMode
    ? demoBackendError ? 'Demo mode - backend unreachable' : isOk ? 'Demo mode - backend online' : 'Demo mode'
    : backendError ? 'Backend unreachable' : backendOnline ? 'Backend online' : 'Checking...'
  const shadowMetric = getShadowMetric(shadow)
  const driftUnavailable = Boolean(errors.drifted && drifted.length === 0)
  const recentActivity = [
    ...scanHistory.map(scanToActivity),
    ...audit.map(mcpToActivity),
  ].sort((a, b) => new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime())

  return (
    <div className="dash-main">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className={'status-dot ' + (backendError || demoBackendError ? 'err' : backendOnline || demoMode ? 'ok' : 'loading')} />
          <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
            {backendLabel}
          </span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={refreshAll} disabled={loading}>
          <RefreshCw size={12} />{loading ? 'Loading' : 'Refresh'}
        </button>
      </div>

      {!configured && !demoMode ? (
        <>
          <EmptyState message="Add an API key to run live scans. The demo prompts below show what Interlock is built to catch." />
          <PromptLibrary />
        </>
      ) : (
        <>
          {demoMode && (
            <div style={{
              width: '100%',
              background: 'rgba(255, 193, 7, 0.12)',
              border: '1px solid rgba(255, 193, 7, 0.4)',
              borderRadius: 4,
              padding: '10px 16px',
              marginBottom: 20,
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              fontSize: 13,
              fontFamily: 'var(--font-mono)',
              color: '#ffc107',
              letterSpacing: '0.3px',
            }}>
              <span style={{ fontWeight: 700 }}>DEMO MODE</span>
              <span style={{ color: 'rgba(255,193,7,0.7)' }}>—</span>
              <span>Connect your API key in Settings to see live data</span>
            </div>
          )}
          <ExecutiveDemoBrief
            demoMode={demoMode}
            driftedCount={drifted.length}
            auditCount={audit.length + scanHistory.length}
            scanCount={scanHistory.length}
          />
          <div className="dash-section-title">Overview</div>
          <div className="metrics-grid">
            {errors.usage && !usage
              ? <ErrorCard message={errors.usage} />
              : <MetricCard
                  label="Usage This Month"
                  value={usage ? usage.used_this_month : loaded ? '-' : '...'}
                  sub={usage ? 'of ' + (usage.monthly_limit || 'infinity') + ' - ' + usage.plan : 'Loading...'}
                />
            }
            <MetricCard
              label="MCP Servers"
              value={errors.servers && servers.length === 0 ? '-' : servers.length}
              sub={errors.servers && servers.length === 0 ? 'Server registry unavailable' : 'Registered servers'}
            />
            <MetricCard
              label="Drifted / Quarantined"
              value={driftUnavailable ? '-' : drifted.length}
              sub={driftUnavailable ? 'Drift status unavailable' : 'Tools needing review'}
              accent={drifted.length > 0 ? 'red' : undefined}
            />
            <MetricCard
              label={shadowMetric.label}
              value={shadowMetric.value}
              sub={errors.shadow && !shadow ? 'Shadow stats unavailable' : shadowMetric.sub}
            />
          </div>

          <SecurityPosture scanStats={scanStats} />

          <div className="dash-section-title">Quick Actions</div>
          <div className="quick-actions">
            <Link to="/dashboard/scan" className="btn btn-ghost"><ScanLine size={13} />Run Prompt Scan</Link>
            <Link to="/dashboard/mcp" className="btn btn-ghost"><Server size={13} />View MCP Gateway</Link>
            <Link to="/dashboard/audit" className="btn btn-ghost"><Activity size={13} />View Audit Log</Link>
            <Link to="/dashboard/login" className="btn btn-cyan"><ShieldCheck size={13} />Admin Login</Link>
          </div>

          <PromptLibrary />

          <div className="dash-section-title">Recent Activity</div>
          <div className="card glow-card" style={{ padding: 0 }}>
            {(errors.audit || errors.scanHistory) && recentActivity.length === 0
              ? <div style={{ padding: 16 }}><EmptyState message={`Runtime activity could not load. ${errors.audit ? `MCP audit: ${errors.audit}. ` : ''}${errors.scanHistory ? `Scan history: ${errors.scanHistory}. ` : ''}Check Settings for the active API URL/key.`} showSettingsLink /></div>
              : recentActivity.length === 0
                ? <div style={{ padding: 16 }}><EmptyState message="No scan or MCP events yet." showSettingsLink={false} /></div>
                : <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Time</th><th>Source</th><th>Target</th><th>Action</th><th>Severity</th><th>Reason</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentActivity.slice(0, 10).map(row => (
                          <tr key={row.key}>
                            <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>
                              {row.timestamp
                                ? new Date(row.timestamp).toLocaleString('en-US', { timeZone: 'UTC', dateStyle: 'short', timeStyle: 'medium' }) + ' UTC'
                                : '-'}
                            </td>
                            <td className="mono">{row.source}</td>
                            <td className="mono dim" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.target}</td>
                            <td><StatusBadge value={row.action} /></td>
                            <td>{row.severity !== '-' ? <StatusBadge value={row.severity} /> : <span className="dim">-</span>}</td>
                            <td className="dim" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
            }
          </div>
        </>
      )}
    </div>
  )
}
