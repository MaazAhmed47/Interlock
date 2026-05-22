# Interlock Web App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Vite+React+TypeScript SPA with a landing page (ported from reference HTML) and a 5-page authenticated dashboard backed by the Interlock FastAPI backend.

**Architecture:** React Router v6 SPA. Global CSS design tokens from the landing reference. API client in `api.ts` reads key/URL from localStorage. Each dashboard page fetches independently with manual refresh and graceful empty/error states.

**Tech Stack:** Vite 5, React 18, TypeScript 5, react-router-dom 6, lucide-react

---

### Task 1: Project scaffold

**Files:**
- Create: `interlock-web/package.json`
- Create: `interlock-web/vite.config.ts`
- Create: `interlock-web/tsconfig.json`
- Create: `interlock-web/index.html`
- Create: `interlock-web/vercel.json`

- [ ] Create `interlock-web/package.json`:

```json
{
  "name": "interlock-web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "lucide-react": "^0.441.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2"
  },
  "devDependencies": {
    "@types/react": "^18.3.5",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "typescript": "^5.5.4",
    "vite": "^5.4.2"
  }
}
```

- [ ] Create `interlock-web/vite.config.ts`:

```ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/',
})
```

- [ ] Create `interlock-web/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
```

- [ ] Create `interlock-web/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Interlock — Runtime Security Gateway for AI Agents</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800&family=DM+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
```

- [ ] Create `interlock-web/vercel.json`:

```json
{
  "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
```

- [ ] Run `npm install` in `interlock-web/` and verify it succeeds.

- [ ] Commit: `git add interlock-web && git commit -m "feat: scaffold Interlock web app"`

---

### Task 2: API client

**Files:**
- Create: `interlock-web/src/api.ts`

- [ ] Create `interlock-web/src/api.ts`:

```ts
export const API_URL_KEY = 'interlock_api_url';
export const API_KEY_KEY = 'interlock_api_key';
export const DEFAULT_API_URL =
  (import.meta.env.VITE_INTERLOCK_API_URL as string) || 'https://interlock.onrender.com';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function getBaseUrl(): string {
  return localStorage.getItem(API_URL_KEY) || DEFAULT_API_URL;
}

function getApiKey(): string | null {
  return localStorage.getItem(API_KEY_KEY);
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  requireKey = true,
): Promise<T> {
  const baseUrl = getBaseUrl();
  const apiKey = getApiKey();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (requireKey && apiKey) headers['x-api-key'] = apiKey;
  if (requireKey && !apiKey) throw new ApiError(401, 'No API key configured.');

  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const data = await res.json() as { detail?: string; message?: string };
      message = data.detail || data.message || message;
    } catch { /* ignore */ }
    throw new ApiError(res.status, message);
  }
  return res.json() as Promise<T>;
}

// ── Response types ──────────────────────────────────────────────────────────

export interface HealthResponse { status: string; service: string; version?: string }

export interface UsageResponse {
  plan: string;
  used_this_month: number;
  monthly_limit: number;
  remaining: number | null;
}

export interface ScanResult {
  is_threat: boolean;
  threat_level: string;
  threat_type: string | null;
  reason: string;
  original_prompt: string;
  safe_to_proceed: boolean;
  confidence: number | null;
  layer_caught: string | null;
  scan_time_ms: number | null;
  risk_score: number | null;
  sanitized_output?: string | null;
  redactions?: string[] | null;
}

export interface MCPServer {
  server_id: string;
  url?: string;
  trust_level?: string;
  tool_count?: number;
  registered?: string;
  [key: string]: unknown;
}

export interface MCPTool {
  server_id: string;
  tool_name: string;
  status?: string;
  description?: string;
  drift_severity?: string;
  drift_action?: string;
  effects?: string;
  side_effect?: string;
  data_classes?: string;
  last_seen?: string;
  [key: string]: unknown;
}

export interface AuditEvent {
  id?: number;
  timestamp: string;
  server_id: string;
  tool_name: string;
  role?: string;
  action: string;
  matched_rule?: string;
  reason?: string;
  blocked_by?: string;
  drift_severity?: string;
  [key: string]: unknown;
}

export interface ShadowStats {
  total: number;
  threats: number;
  threat_rate: number;
  top_threat_type?: string;
  [key: string]: unknown;
}

// ── API methods ─────────────────────────────────────────────────────────────

export const api = {
  health: () => request<HealthResponse>('GET', '/health', undefined, false),
  usage: () => request<UsageResponse>('GET', '/usage'),
  scan: (prompt: string) => request<ScanResult>('POST', '/scan', { prompt }),
  scanOutput: (prompt: string) => request<ScanResult>('POST', '/scan/output', { prompt }),
  shadowStats: () => request<ShadowStats>('GET', '/shadow/stats'),
  mcpServers: () => request<{ servers: MCPServer[] }>('GET', '/mcp/servers'),
  mcpTools: (server_id?: string) =>
    request<{ tools: MCPTool[] }>('GET', `/mcp/tools${server_id ? `?server_id=${encodeURIComponent(server_id)}` : ''}`),
  mcpDrifted: (server_id?: string) =>
    request<{ tools: MCPTool[] }>('GET', `/mcp/tools/drifted${server_id ? `?server_id=${encodeURIComponent(server_id)}` : ''}`),
  approveTool: (server_id: string, tool_name: string, payload: { reviewer?: string; reason?: string }) =>
    request<{ ok: boolean }>('POST', `/mcp/tools/${encodeURIComponent(server_id)}/${encodeURIComponent(tool_name)}/approve`, payload),
  quarantineTool: (server_id: string, tool_name: string, payload: { reviewer?: string; reason?: string }) =>
    request<{ ok: boolean }>('POST', `/mcp/tools/${encodeURIComponent(server_id)}/${encodeURIComponent(tool_name)}/quarantine`, payload),
  mcpAudit: (limit = 100) => request<{ events: AuditEvent[] }>('GET', `/mcp/audit?limit=${limit}`),
  siemProviders: () =>
    request<{ providers: string[]; config_examples: Record<string, unknown> }>('GET', '/siem/providers'),
  roles: () => request<{ roles: Record<string, unknown> }>('GET', '/roles'),
};
```

- [ ] Commit: `git add interlock-web/src && git commit -m "feat: add API client"`

---

### Task 3: Global CSS

**Files:**
- Create: `interlock-web/src/styles.css`

- [ ] Create `interlock-web/src/styles.css` with design tokens, reset, dashboard layout, tables, badges, buttons, forms, and responsive rules. Full content:

```css
/* ── TOKENS ──────────────────────────────────────────────────────────────── */
:root {
  --black: #060608;
  --white: #f5f0e8;
  --red: #e8182c;
  --cyan: #00e5c8;
  --lime: #c8f000;
  --orange: #ff6b35;
  --purple: #7c3aed;
  --dim: rgba(245,240,232,.55);
  --border: rgba(245,240,232,.10);
  --card-bg: rgba(245,240,232,.04);
  --font-body: 'Geist', 'Inter', ui-sans-serif, system-ui, -apple-system, sans-serif;
  --font-mono: 'DM Mono', monospace;
}

/* ── RESET ───────────────────────────────────────────────────────────────── */
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  background: var(--black);
  color: var(--white);
  font-family: var(--font-body);
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
}
a { color: inherit; text-decoration: none; }
button { cursor: pointer; font-family: var(--font-body); }
input, textarea, select {
  font-family: var(--font-body);
  color: var(--white);
  background: transparent;
}

/* ── DASHBOARD LAYOUT ────────────────────────────────────────────────────── */
.dash-shell {
  display: flex;
  min-height: 100vh;
}
.dash-sidebar {
  width: 220px;
  flex-shrink: 0;
  background: var(--black);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  position: fixed;
  top: 0; left: 0; bottom: 0;
  z-index: 100;
  overflow-y: auto;
}
.dash-logo {
  padding: 20px 20px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 18px; font-weight: 700; letter-spacing: -.4px;
  color: var(--white);
}
.dash-logo-sub {
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--dim);
  margin-top: 2px;
}
.dash-nav { padding: 12px 0; flex: 1; }
.dash-nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 20px;
  font-size: 13px; font-weight: 500; letter-spacing: .3px;
  color: rgba(245,240,232,.55);
  transition: color .15s, background .15s;
  border-left: 2px solid transparent;
}
.dash-nav-item:hover { color: var(--white); background: rgba(245,240,232,.03); }
.dash-nav-item.active {
  color: var(--white);
  border-left-color: var(--cyan);
  background: rgba(0,229,200,.05);
}
.dash-nav-item svg { flex-shrink: 0; opacity: .7; }
.dash-nav-item.active svg { opacity: 1; }
.dash-nav-divider {
  height: 1px; background: var(--border);
  margin: 8px 0;
}
.dash-nav-section {
  padding: 8px 20px 4px;
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 2.5px;
  text-transform: uppercase;
  color: rgba(245,240,232,.28);
}
.dash-content {
  margin-left: 220px;
  flex: 1;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.dash-topbar {
  height: 52px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 28px;
  background: var(--black);
  position: sticky; top: 0; z-index: 50;
}
.dash-topbar-title {
  font-size: 14px; font-weight: 600;
  color: var(--white);
}
.dash-topbar-actions { display: flex; gap: 8px; align-items: center; }
.dash-main { padding: 28px; flex: 1; }
.dash-section-title {
  font-size: 11px; font-weight: 600;
  letter-spacing: 2.5px; text-transform: uppercase;
  color: rgba(245,240,232,.35);
  font-family: var(--font-mono);
  margin-bottom: 14px;
}
.dash-page-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  margin-bottom: 24px;
  gap: 16px;
}
.dash-page-header h1 {
  font-size: 22px; font-weight: 700; letter-spacing: -.4px;
}
.dash-page-header p {
  font-size: 13px; color: var(--dim); margin-top: 4px;
}

/* ── STATUS STRIP ────────────────────────────────────────────────────────── */
.status-strip {
  display: flex; align-items: center; gap: 10px;
  padding: 7px 12px;
  border: 1px solid var(--border);
  background: var(--card-bg);
  font-family: var(--font-mono);
  font-size: 12px; letter-spacing: .5px;
}
.status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--dim);
  flex-shrink: 0;
}
.status-dot.ok { background: var(--cyan); box-shadow: 0 0 8px rgba(0,229,200,.5); }
.status-dot.err { background: var(--red); box-shadow: 0 0 8px rgba(232,24,44,.5); }
.status-dot.loading { background: var(--orange); }

/* ── METRIC CARDS ────────────────────────────────────────────────────────── */
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}
.metric-card {
  border: 1px solid var(--border);
  background: var(--card-bg);
  padding: 18px 20px;
}
.metric-card-label {
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 2px;
  text-transform: uppercase;
  color: rgba(245,240,232,.45);
  margin-bottom: 10px;
}
.metric-card-value {
  font-size: 32px; font-weight: 800;
  letter-spacing: -1.5px; line-height: 1;
  color: var(--white);
}
.metric-card-value.accent-red { color: var(--red); }
.metric-card-value.accent-cyan { color: var(--cyan); }
.metric-card-sub {
  font-size: 12px; color: var(--dim);
  margin-top: 6px;
}

/* ── CARDS ───────────────────────────────────────────────────────────────── */
.card {
  border: 1px solid var(--border);
  background: var(--card-bg);
  padding: 20px;
}
.card + .card { margin-top: 12px; }
.card-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 16px;
}
.card-title {
  font-size: 13px; font-weight: 600;
  letter-spacing: .3px;
}

/* ── TABLES ──────────────────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; }
table.data-table {
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}
.data-table th {
  text-align: left;
  padding: 8px 12px;
  font-family: var(--font-mono);
  font-size: 10px; letter-spacing: 2px;
  text-transform: uppercase;
  color: rgba(245,240,232,.35);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.data-table td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(245,240,232,.05);
  color: rgba(245,240,232,.82);
  vertical-align: middle;
}
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: rgba(245,240,232,.02); }
.mono { font-family: var(--font-mono); font-size: 12px; }
.dim { color: var(--dim); }

/* ── BADGES ──────────────────────────────────────────────────────────────── */
.badge {
  display: inline-flex; align-items: center;
  padding: 2px 8px;
  font-family: var(--font-mono);
  font-size: 11px; font-weight: 700; letter-spacing: 1px;
  border-radius: 2px;
  white-space: nowrap;
}
.badge-allow   { color: #00e5c8; border: 1px solid rgba(0,229,200,.3); background: rgba(0,229,200,.12); }
.badge-block   { color: #ff4455; border: 1px solid rgba(232,24,44,.3); background: rgba(232,24,44,.12); }
.badge-monitor { color: #ffcc00; border: 1px solid rgba(255,204,0,.3); background: rgba(255,204,0,.10); }
.badge-quarantine { color: #ff6b35; border: 1px solid rgba(255,107,53,.3); background: rgba(255,107,53,.10); }
.badge-safe    { color: #00e5c8; border: 1px solid rgba(0,229,200,.3); background: rgba(0,229,200,.12); }
.badge-high    { color: #ff6b35; border: 1px solid rgba(255,107,53,.3); background: rgba(255,107,53,.10); }
.badge-critical{ color: #ff4455; border: 1px solid rgba(232,24,44,.3); background: rgba(232,24,44,.12); }
.badge-medium  { color: #ffcc00; border: 1px solid rgba(255,204,0,.3); background: rgba(255,204,0,.10); }
.badge-low     { color: var(--dim); border: 1px solid var(--border); background: var(--card-bg); }

/* ── BUTTONS ─────────────────────────────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 16px;
  font-size: 12px; font-weight: 600; letter-spacing: 1px;
  text-transform: uppercase; border: none;
  transition: all .2s; white-space: nowrap;
}
.btn-primary {
  background: var(--red); color: #fff;
}
.btn-primary:hover { background: #ff2a3e; }
.btn-primary:disabled { background: rgba(232,24,44,.35); cursor: not-allowed; }
.btn-ghost {
  background: transparent; color: rgba(245,240,232,.6);
  border: 1px solid var(--border);
}
.btn-ghost:hover { color: var(--white); border-color: rgba(245,240,232,.3); }
.btn-cyan {
  background: rgba(0,229,200,.12); color: var(--cyan);
  border: 1px solid rgba(0,229,200,.3);
}
.btn-cyan:hover { background: rgba(0,229,200,.18); }
.btn-orange {
  background: rgba(255,107,53,.12); color: var(--orange);
  border: 1px solid rgba(255,107,53,.3);
}
.btn-orange:hover { background: rgba(255,107,53,.18); }
.btn-sm { padding: 5px 10px; font-size: 11px; }
.btn-icon { padding: 6px; }

/* ── FORMS ───────────────────────────────────────────────────────────────── */
.form-group { margin-bottom: 16px; }
.form-label {
  display: block;
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 2px;
  text-transform: uppercase;
  color: rgba(245,240,232,.45);
  margin-bottom: 8px;
}
.form-input {
  width: 100%; padding: 10px 12px;
  background: rgba(245,240,232,.05);
  border: 1px solid var(--border);
  color: var(--white);
  font-size: 13px;
  outline: none;
  transition: border-color .2s;
}
.form-input:focus { border-color: rgba(0,229,200,.4); }
.form-input::placeholder { color: rgba(245,240,232,.25); }
textarea.form-input { resize: vertical; min-height: 100px; font-family: var(--font-mono); font-size: 12px; }
.form-hint { font-size: 12px; color: var(--dim); margin-top: 6px; }

/* ── SCAN RESULT ─────────────────────────────────────────────────────────── */
.scan-result {
  border: 1px solid var(--border);
  background: var(--card-bg);
  padding: 18px;
  margin-top: 16px;
}
.scan-result.threat-safe     { border-color: rgba(0,229,200,.3); }
.scan-result.threat-medium   { border-color: rgba(255,204,0,.3); }
.scan-result.threat-high     { border-color: rgba(255,107,53,.3); }
.scan-result.threat-critical { border-color: rgba(232,24,44,.3); }
.scan-result-header {
  display: flex; align-items: center; gap: 10px;
  margin-bottom: 14px;
}
.scan-result-row {
  display: flex; gap: 8px;
  padding: 7px 0;
  border-bottom: 1px solid rgba(245,240,232,.05);
  font-size: 13px;
}
.scan-result-row:last-child { border-bottom: none; }
.scan-result-key {
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 1.5px;
  text-transform: uppercase;
  color: rgba(245,240,232,.4);
  width: 120px; flex-shrink: 0; padding-top: 1px;
}
.scan-result-val { color: rgba(245,240,232,.88); }

/* ── EMPTY / ERROR STATES ────────────────────────────────────────────────── */
.empty-state {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 12px;
  padding: 48px 24px; text-align: center;
  border: 1px dashed rgba(245,240,232,.12);
  color: var(--dim);
}
.empty-state svg { opacity: .35; }
.empty-state p { font-size: 13px; }
.error-card {
  border: 1px solid rgba(232,24,44,.2);
  background: rgba(232,24,44,.05);
  padding: 14px 16px;
  display: flex; align-items: center; gap: 10px;
  font-size: 13px; color: rgba(245,240,232,.75);
}

/* ── QUICK ACTIONS ───────────────────────────────────────────────────────── */
.quick-actions {
  display: flex; gap: 10px; flex-wrap: wrap;
  margin-bottom: 24px;
}

/* ── FILTERS ─────────────────────────────────────────────────────────────── */
.filters-row {
  display: flex; gap: 8px; align-items: center;
  margin-bottom: 14px; flex-wrap: wrap;
}
.filter-select {
  background: rgba(245,240,232,.05);
  border: 1px solid var(--border);
  color: var(--white);
  padding: 6px 10px; font-size: 12px;
  outline: none;
}
.filter-select:focus { border-color: rgba(0,229,200,.3); }

/* ── DRIFT CARDS ─────────────────────────────────────────────────────────── */
.drift-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
}
.drift-card {
  border: 1px solid rgba(255,107,53,.25);
  background: rgba(255,107,53,.04);
  padding: 16px;
}
.drift-card.quarantined {
  border-color: rgba(232,24,44,.3);
  background: rgba(232,24,44,.04);
}
.drift-card-header {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 8px; margin-bottom: 10px;
}
.drift-card-name { font-size: 14px; font-weight: 600; }
.drift-card-server { font-family: var(--font-mono); font-size: 11px; color: var(--dim); margin-top: 2px; }
.drift-card-field { font-size: 12px; color: var(--dim); margin-top: 6px; line-height: 1.5; }
.drift-card-field strong { color: rgba(245,240,232,.7); font-weight: 500; }
.drift-card-actions { display: flex; gap: 8px; margin-top: 12px; }

/* ── SETTINGS ────────────────────────────────────────────────────────────── */
.settings-section {
  border: 1px solid var(--border);
  background: var(--card-bg);
  padding: 24px;
  margin-bottom: 16px;
  max-width: 560px;
}
.settings-section-title {
  font-size: 14px; font-weight: 600;
  margin-bottom: 18px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.key-fingerprint {
  font-family: var(--font-mono);
  font-size: 12px; color: var(--cyan);
  margin-top: 8px;
}
.siem-providers-list {
  display: flex; flex-wrap: wrap; gap: 8px;
  margin-top: 8px;
}
.siem-chip {
  font-family: var(--font-mono);
  font-size: 11px; letter-spacing: 1.5px;
  padding: 4px 10px;
  border: 1px solid var(--border);
  color: var(--dim);
}

/* ── RESPONSIVE ──────────────────────────────────────────────────────────── */
@media (max-width: 768px) {
  .dash-sidebar { display: none; }
  .dash-content { margin-left: 0; }
  .dash-mobile-nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 16px; height: 52px;
    border-bottom: 1px solid var(--border);
    background: var(--black);
    position: sticky; top: 0; z-index: 100;
  }
  .dash-main { padding: 16px; }
  .metrics-grid { grid-template-columns: repeat(2, 1fr); }
  .drift-grid { grid-template-columns: 1fr; }
}
@media (min-width: 769px) {
  .dash-mobile-nav { display: none; }
}
```

- [ ] Commit: `git add interlock-web/src/styles.css && git commit -m "feat: add global design system CSS"`

---

### Task 4: Shared components

**Files:**
- Create: `interlock-web/src/components/StatusBadge.tsx`
- Create: `interlock-web/src/components/MetricCard.tsx`
- Create: `interlock-web/src/components/ErrorCard.tsx`
- Create: `interlock-web/src/components/EmptyState.tsx`

- [ ] Create `interlock-web/src/components/StatusBadge.tsx`:

```tsx
interface Props { value: string }

const MAP: Record<string, string> = {
  allow: 'badge-allow',
  allowed: 'badge-allow',
  block: 'badge-block',
  blocked: 'badge-block',
  deny: 'badge-block',
  denied: 'badge-block',
  monitor: 'badge-monitor',
  monitored: 'badge-monitor',
  quarantine: 'badge-quarantine',
  quarantined: 'badge-quarantine',
  safe: 'badge-safe',
  high: 'badge-high',
  critical: 'badge-critical',
  medium: 'badge-medium',
  low: 'badge-low',
};

export default function StatusBadge({ value }: Props) {
  const cls = MAP[value.toLowerCase()] || 'badge-low';
  return <span className={`badge ${cls}`}>{value.toUpperCase()}</span>;
}
```

- [ ] Create `interlock-web/src/components/MetricCard.tsx`:

```tsx
interface Props {
  label: string;
  value: string | number;
  sub?: string;
  accent?: 'red' | 'cyan';
}

export default function MetricCard({ label, value, sub, accent }: Props) {
  const cls = accent ? `metric-card-value accent-${accent}` : 'metric-card-value';
  return (
    <div className="metric-card">
      <div className="metric-card-label">{label}</div>
      <div className={cls}>{value}</div>
      {sub && <div className="metric-card-sub">{sub}</div>}
    </div>
  );
}
```

- [ ] Create `interlock-web/src/components/ErrorCard.tsx`:

```tsx
import { AlertCircle, RefreshCw } from 'lucide-react';

interface Props {
  message: string;
  onRetry?: () => void;
}

export default function ErrorCard({ message, onRetry }: Props) {
  return (
    <div className="error-card">
      <AlertCircle size={15} style={{ color: 'var(--red)', flexShrink: 0 }} />
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry && (
        <button className="btn btn-ghost btn-sm" onClick={onRetry} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <RefreshCw size={12} /> Retry
        </button>
      )}
    </div>
  );
}
```

- [ ] Create `interlock-web/src/components/EmptyState.tsx`:

```tsx
import { Link } from 'react-router-dom';
import { KeyRound } from 'lucide-react';

interface Props {
  message?: string;
  showSettingsLink?: boolean;
}

export default function EmptyState({
  message = 'No API key configured.',
  showSettingsLink = true,
}: Props) {
  return (
    <div className="empty-state">
      <KeyRound size={28} />
      <p>{message}</p>
      {showSettingsLink && (
        <Link to="/dashboard/settings" className="btn btn-ghost btn-sm">
          Go to Settings →
        </Link>
      )}
    </div>
  );
}
```

- [ ] Commit: `git add interlock-web/src/components && git commit -m "feat: add shared dashboard components"`

---

### Task 5: main.tsx + App.tsx

**Files:**
- Create: `interlock-web/src/main.tsx`
- Create: `interlock-web/src/App.tsx`

- [ ] Create `interlock-web/src/main.tsx`:

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
```

- [ ] Create `interlock-web/src/App.tsx`:

```tsx
import { Routes, Route, Navigate } from 'react-router-dom'
import Landing from './pages/Landing'
import DashLayout from './components/DashLayout'
import Dashboard from './pages/Dashboard'
import Scan from './pages/Scan'
import MCPGateway from './pages/MCPGateway'
import Audit from './pages/Audit'
import Settings from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/dashboard" element={<DashLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="scan" element={<Scan />} />
        <Route path="mcp" element={<MCPGateway />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
```

- [ ] Commit: `git add interlock-web/src/main.tsx interlock-web/src/App.tsx && git commit -m "feat: add root entry and route tree"`

---

### Task 6: DashLayout

**Files:**
- Create: `interlock-web/src/components/DashLayout.tsx`

- [ ] Create `interlock-web/src/components/DashLayout.tsx`:

```tsx
import { Outlet, NavLink, Link } from 'react-router-dom'
import { LayoutDashboard, ScanLine, Server, BookOpen, Settings, ArrowLeft, Menu } from 'lucide-react'
import { useState } from 'react'

const NAV = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/dashboard/scan', label: 'Scan', icon: ScanLine },
  { to: '/dashboard/mcp', label: 'MCP Gateway', icon: Server },
  { to: '/dashboard/audit', label: 'Audit Log', icon: BookOpen },
  { to: '/dashboard/settings', label: 'Settings', icon: Settings },
]

export default function DashLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="dash-shell">
      {/* Sidebar */}
      <aside className="dash-sidebar">
        <div className="dash-logo">
          Interlock
          <div className="dash-logo-sub">Security Gateway</div>
        </div>
        <nav className="dash-nav">
          <div className="dash-nav-section">Dashboard</div>
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `dash-nav-item${isActive ? ' active' : ''}`}
            >
              <Icon size={15} />
              {label}
            </NavLink>
          ))}
          <div className="dash-nav-divider" />
          <Link to="/" className="dash-nav-item" style={{ fontSize: 12 }}>
            <ArrowLeft size={13} /> Back to site
          </Link>
        </nav>
      </aside>

      {/* Mobile top bar */}
      <div className="dash-mobile-nav">
        <span style={{ fontWeight: 700, fontSize: 16 }}>Interlock</span>
        <button className="btn btn-ghost btn-icon" onClick={() => setMobileOpen(!mobileOpen)}>
          <Menu size={18} />
        </button>
      </div>

      {/* Mobile nav overlay */}
      {mobileOpen && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 200,
            background: 'rgba(6,6,8,.96)',
            display: 'flex', flexDirection: 'column',
            paddingTop: 52,
          }}
          onClick={() => setMobileOpen(false)}
        >
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `dash-nav-item${isActive ? ' active' : ''}`}
              style={{ fontSize: 16, padding: '14px 24px' }}
              onClick={() => setMobileOpen(false)}
            >
              <Icon size={16} /> {label}
            </NavLink>
          ))}
          <Link to="/" className="dash-nav-item" style={{ fontSize: 14, padding: '14px 24px' }}>
            <ArrowLeft size={14} /> Back to site
          </Link>
        </div>
      )}

      {/* Main content */}
      <div className="dash-content">
        <Outlet />
      </div>
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/components/DashLayout.tsx && git commit -m "feat: add dashboard layout shell"`

---

### Task 7: Settings page

**Files:**
- Create: `interlock-web/src/pages/Settings.tsx`

- [ ] Create `interlock-web/src/pages/Settings.tsx`:

```tsx
import { useState, useEffect } from 'react'
import { Save } from 'lucide-react'
import { API_URL_KEY, API_KEY_KEY, DEFAULT_API_URL, api } from '../api'
import ErrorCard from '../components/ErrorCard'

export default function Settings() {
  const [url, setUrl] = useState(localStorage.getItem(API_URL_KEY) || DEFAULT_API_URL)
  const [key, setKey] = useState(localStorage.getItem(API_KEY_KEY) || '')
  const [saved, setSaved] = useState(false)
  const [siemProviders, setSiemProviders] = useState<string[]>([])
  const [siemError, setSiemError] = useState('')

  function save() {
    localStorage.setItem(API_URL_KEY, url.trim() || DEFAULT_API_URL)
    if (key.trim()) {
      localStorage.setItem(API_KEY_KEY, key.trim())
    } else {
      localStorage.removeItem(API_KEY_KEY)
    }
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  useEffect(() => {
    if (!localStorage.getItem(API_KEY_KEY)) return
    api.siemProviders()
      .then(d => setSiemProviders(d.providers))
      .catch(e => setSiemError((e as Error).message))
  }, [])

  const storedKey = localStorage.getItem(API_KEY_KEY) || ''
  const fingerprint = storedKey ? `…${storedKey.slice(-6)}` : null

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div>
          <h1>Settings</h1>
          <p>API connection and key configuration</p>
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-title">Connection</div>

        <div className="form-group">
          <label className="form-label">API Base URL</label>
          <input
            className="form-input"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder={DEFAULT_API_URL}
          />
          <div className="form-hint">Default: {DEFAULT_API_URL}</div>
        </div>

        <div className="form-group">
          <label className="form-label">API Key</label>
          <input
            className="form-input"
            type="password"
            value={key}
            onChange={e => setKey(e.target.value)}
            placeholder="sk-…"
            autoComplete="off"
          />
          {fingerprint && (
            <div className="key-fingerprint">Active key: {fingerprint}</div>
          )}
          <div className="form-hint">Stored in browser localStorage only. Never sent to any third party.</div>
        </div>

        <button className="btn btn-primary" onClick={save}>
          <Save size={13} />
          {saved ? 'Saved!' : 'Save Settings'}
        </button>
      </div>

      {storedKey && (
        <div className="settings-section">
          <div className="settings-section-title">SIEM Integrations</div>
          {siemError ? (
            <ErrorCard message={siemError} onRetry={() => {
              setSiemError('')
              api.siemProviders()
                .then(d => setSiemProviders(d.providers))
                .catch(e => setSiemError((e as Error).message))
            }} />
          ) : (
            <>
              <p style={{ fontSize: 13, color: 'var(--dim)', marginBottom: 12 }}>
                Supported export destinations. Configure per-key via the admin API.
              </p>
              <div className="siem-providers-list">
                {siemProviders.map(p => (
                  <span key={p} className="siem-chip">{p}</span>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/pages/Settings.tsx && git commit -m "feat: add settings page"`

---

### Task 8: Dashboard overview

**Files:**
- Create: `interlock-web/src/pages/Dashboard.tsx`

- [ ] Create `interlock-web/src/pages/Dashboard.tsx`:

```tsx
import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ScanLine, Server, Activity } from 'lucide-react'
import { api, hasApiKey, ApiError, HealthResponse, UsageResponse, MCPTool, AuditEvent, ShadowStats } from '../api'
import MetricCard from '../components/MetricCard'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

export default function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthErr, setHealthErr] = useState('')
  const [usage, setUsage] = useState<UsageResponse | null>(null)
  const [usageErr, setUsageErr] = useState('')
  const [serverCount, setServerCount] = useState<number | null>(null)
  const [drifted, setDrifted] = useState<MCPTool[]>([])
  const [mcpErr, setMcpErr] = useState('')
  const [audit, setAudit] = useState<AuditEvent[]>([])
  const [auditErr, setAuditErr] = useState('')
  const [shadow, setShadow] = useState<ShadowStats | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)

    api.health()
      .then(setHealth)
      .catch(e => setHealthErr((e as Error).message))

    if (!hasApiKey()) {
      setLoading(false)
      return
    }

    Promise.all([
      api.usage().then(setUsage).catch(e => setUsageErr((e as Error).message)),
      api.mcpServers()
        .then(d => setServerCount(d.servers.length))
        .catch(() => {}),
      api.mcpDrifted()
        .then(d => setDrifted(d.tools))
        .catch(e => setMcpErr((e as Error).message)),
      api.mcpAudit(10)
        .then(d => setAudit(d.events))
        .catch(e => setAuditErr((e as Error).message)),
      api.shadowStats()
        .then(setShadow)
        .catch(() => {}),
    ]).finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const isOk = health?.status === 'ok'

  return (
    <div className="dash-main">
      {/* Topbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className={`status-dot ${healthErr ? 'err' : isOk ? 'ok' : 'loading'}`} />
          <span style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--dim)' }}>
            {healthErr ? 'Backend unreachable' : isOk ? 'Backend online' : 'Checking…'}
          </span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {!hasApiKey() ? (
        <EmptyState />
      ) : (
        <>
          {/* Metrics */}
          <div className="dash-section-title">Overview</div>
          <div className="metrics-grid">
            {usageErr ? (
              <ErrorCard message={usageErr} />
            ) : (
              <MetricCard
                label="Usage This Month"
                value={usage ? usage.used_this_month : '—'}
                sub={usage ? `of ${usage.monthly_limit || '∞'} · ${usage.plan}` : 'Loading…'}
              />
            )}
            <MetricCard
              label="MCP Servers"
              value={serverCount ?? '—'}
              sub="Registered servers"
            />
            <MetricCard
              label="Drifted / Quarantined"
              value={mcpErr ? '!' : drifted.length}
              sub="Tools needing review"
              accent={drifted.length > 0 ? 'red' : undefined}
            />
            {shadow && (
              <MetricCard
                label="Shadow Threat Rate"
                value={`${Math.round(shadow.threat_rate * 100)}%`}
                sub={`${shadow.total} shadow scans`}
              />
            )}
          </div>

          {/* Quick actions */}
          <div className="dash-section-title">Quick Actions</div>
          <div className="quick-actions" style={{ marginBottom: 24 }}>
            <Link to="/dashboard/scan" className="btn btn-ghost">
              <ScanLine size={13} /> Run Prompt Scan
            </Link>
            <Link to="/dashboard/mcp" className="btn btn-ghost">
              <Server size={13} /> View MCP Gateway
            </Link>
            <Link to="/dashboard/audit" className="btn btn-ghost">
              <Activity size={13} /> View Audit Log
            </Link>
          </div>

          {/* Recent audit */}
          <div className="dash-section-title">Recent Audit Decisions</div>
          <div className="card">
            {auditErr ? (
              <ErrorCard message={auditErr} onRetry={load} />
            ) : audit.length === 0 ? (
              <EmptyState message="No audit events yet." showSettingsLink={false} />
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Server</th>
                      <th>Tool</th>
                      <th>Role</th>
                      <th>Action</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.slice(0, 10).map((e, i) => (
                      <tr key={e.id ?? i}>
                        <td className="mono dim">{new Date(e.timestamp).toLocaleTimeString()}</td>
                        <td className="mono">{e.server_id}</td>
                        <td className="mono">{e.tool_name}</td>
                        <td className="dim">{e.role || '—'}</td>
                        <td><StatusBadge value={e.action} /></td>
                        <td>{e.drift_severity ? <StatusBadge value={e.drift_severity} /> : <span className="dim">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/pages/Dashboard.tsx && git commit -m "feat: add dashboard overview page"`

---

### Task 9: Scan page

**Files:**
- Create: `interlock-web/src/pages/Scan.tsx`

- [ ] Create `interlock-web/src/pages/Scan.tsx`:

```tsx
import { useState } from 'react'
import { ScanLine } from 'lucide-react'
import { api, hasApiKey, ScanResult } from '../api'
import StatusBadge from '../components/StatusBadge'
import EmptyState from '../components/EmptyState'
import ErrorCard from '../components/ErrorCard'

function threatClass(level: string) {
  const l = level.toLowerCase()
  if (l === 'safe') return 'threat-safe'
  if (l === 'medium') return 'threat-medium'
  if (l === 'high') return 'threat-high'
  if (l === 'critical') return 'threat-critical'
  return ''
}

function ScanForm({ title, action }: { title: string; action: (p: string) => Promise<ScanResult> }) {
  const [prompt, setPrompt] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function run() {
    if (!prompt.trim()) return
    setLoading(true); setResult(null); setError('')
    try {
      setResult(await action(prompt))
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card" style={{ flex: 1 }}>
      <div className="card-header">
        <div className="card-title">{title}</div>
      </div>
      <div className="form-group">
        <textarea
          className="form-input"
          style={{ minHeight: 120 }}
          placeholder="Paste text to scan…"
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
        />
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading || !prompt.trim()}>
        <ScanLine size={13} /> {loading ? 'Scanning…' : 'Scan'}
      </button>

      {error && <ErrorCard message={error} />}

      {result && (
        <div className={`scan-result ${threatClass(result.threat_level)}`}>
          <div className="scan-result-header">
            <StatusBadge value={result.threat_level} />
            <span style={{ fontSize: 13, color: result.is_threat ? 'var(--red)' : 'var(--cyan)' }}>
              {result.is_threat ? 'Threat detected' : 'Clean'}
            </span>
          </div>
          {[
            ['Reason', result.reason],
            ['Threat Type', result.threat_type],
            ['Layer Caught', result.layer_caught],
            ['Confidence', result.confidence != null ? `${Math.round(result.confidence * 100)}%` : null],
            ['Risk Score', result.risk_score != null ? String(result.risk_score) : null],
            ['Scan Time', result.scan_time_ms != null ? `${result.scan_time_ms}ms` : null],
          ].filter(([, v]) => v).map(([k, v]) => (
            <div key={k as string} className="scan-result-row">
              <div className="scan-result-key">{k}</div>
              <div className="scan-result-val">{v}</div>
            </div>
          ))}
          {result.sanitized_output && (
            <div className="scan-result-row">
              <div className="scan-result-key">Sanitized</div>
              <div className="scan-result-val" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                {result.sanitized_output}
              </div>
            </div>
          )}
          {result.redactions && result.redactions.length > 0 && (
            <div className="scan-result-row">
              <div className="scan-result-key">Redactions</div>
              <div className="scan-result-val">{result.redactions.join(', ')}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Scan() {
  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Scan</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div>
          <h1>Scan</h1>
          <p>Run prompt and output scans against the Interlock pipeline</p>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <ScanForm title="Prompt Scan" action={api.scan} />
        <ScanForm title="Output Scan" action={api.scanOutput} />
      </div>
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/pages/Scan.tsx && git commit -m "feat: add scan page"`

---

### Task 10: MCP Gateway page

**Files:**
- Create: `interlock-web/src/pages/MCPGateway.tsx`

- [ ] Create `interlock-web/src/pages/MCPGateway.tsx`:

```tsx
import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, CheckCircle, AlertOctagon } from 'lucide-react'
import { api, hasApiKey, MCPServer, MCPTool } from '../api'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

export default function MCPGateway() {
  const [servers, setServers] = useState<MCPServer[]>([])
  const [tools, setTools] = useState<MCPTool[]>([])
  const [drifted, setDrifted] = useState<MCPTool[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({})

  const load = useCallback(async () => {
    if (!hasApiKey()) return
    setLoading(true); setErr('')
    try {
      const [s, t, d] = await Promise.all([
        api.mcpServers(), api.mcpTools(), api.mcpDrifted(),
      ])
      setServers(s.servers)
      setTools(t.tools)
      setDrifted(d.tools)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function approve(tool: MCPTool) {
    const k = `${tool.server_id}/${tool.tool_name}`
    try {
      await api.approveTool(tool.server_id, tool.tool_name, { reviewer: 'operator', reason: 'Approved via dashboard' })
      setActionMsg(m => ({ ...m, [k]: 'Approved' }))
      setTimeout(() => load(), 800)
    } catch (e) {
      setActionMsg(m => ({ ...m, [k]: `Error: ${(e as Error).message}` }))
    }
  }

  async function quarantine(tool: MCPTool) {
    const k = `${tool.server_id}/${tool.tool_name}`
    try {
      await api.quarantineTool(tool.server_id, tool.tool_name, { reviewer: 'operator', reason: 'Quarantined via dashboard' })
      setActionMsg(m => ({ ...m, [k]: 'Quarantined' }))
      setTimeout(() => load(), 800)
    } catch (e) {
      setActionMsg(m => ({ ...m, [k]: `Error: ${(e as Error).message}` }))
    }
  }

  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>MCP Gateway</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div>
          <h1>MCP Gateway</h1>
          <p>Registered servers, tool inventory, and drift review</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {err && <ErrorCard message={err} onRetry={load} />}

      {/* Drifted tools — show first if any */}
      {drifted.length > 0 && (
        <>
          <div className="dash-section-title" style={{ color: 'var(--orange)' }}>
            Drifted / Quarantined — {drifted.length} tool{drifted.length !== 1 ? 's' : ''} need review
          </div>
          <div className="drift-grid" style={{ marginBottom: 28 }}>
            {drifted.map(tool => {
              const k = `${tool.server_id}/${tool.tool_name}`
              const isQ = tool.status === 'quarantined'
              return (
                <div key={k} className={`drift-card${isQ ? ' quarantined' : ''}`}>
                  <div className="drift-card-header">
                    <div>
                      <div className="drift-card-name">{tool.tool_name}</div>
                      <div className="drift-card-server">{tool.server_id}</div>
                    </div>
                    {tool.drift_severity && <StatusBadge value={tool.drift_severity} />}
                  </div>
                  {tool.description && (
                    <div className="drift-card-field" style={{ color: 'rgba(245,240,232,.65)' }}>
                      {tool.description}
                    </div>
                  )}
                  {tool.effects && <div className="drift-card-field"><strong>Effects:</strong> {tool.effects}</div>}
                  {tool.side_effect && <div className="drift-card-field"><strong>Side effect:</strong> {tool.side_effect}</div>}
                  {tool.data_classes && <div className="drift-card-field"><strong>Data classes:</strong> {tool.data_classes}</div>}
                  {tool.drift_action && <div className="drift-card-field"><strong>Drift action:</strong> {tool.drift_action}</div>}
                  {actionMsg[k] ? (
                    <div style={{ marginTop: 12, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>
                      {actionMsg[k]}
                    </div>
                  ) : (
                    <div className="drift-card-actions">
                      <button className="btn btn-cyan btn-sm" onClick={() => approve(tool)}>
                        <CheckCircle size={11} /> Approve
                      </button>
                      <button className="btn btn-orange btn-sm" onClick={() => quarantine(tool)}>
                        <AlertOctagon size={11} /> Quarantine
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* Servers */}
      <div className="dash-section-title">Registered Servers</div>
      <div className="card" style={{ marginBottom: 20 }}>
        {servers.length === 0 ? (
          <EmptyState message="No MCP servers registered." showSettingsLink={false} />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Server ID</th><th>URL</th><th>Trust</th></tr></thead>
              <tbody>
                {servers.map(s => (
                  <tr key={s.server_id}>
                    <td className="mono">{s.server_id}</td>
                    <td className="mono dim">{(s.url as string) || '—'}</td>
                    <td>{s.trust_level ? <StatusBadge value={String(s.trust_level)} /> : <span className="dim">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* All tools */}
      <div className="dash-section-title">All Tools — {tools.length}</div>
      <div className="card">
        {tools.length === 0 ? (
          <EmptyState message="No tools discovered yet." showSettingsLink={false} />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Server</th><th>Tool</th><th>Status</th><th>Description</th></tr></thead>
              <tbody>
                {tools.map(t => (
                  <tr key={`${t.server_id}/${t.tool_name}`}>
                    <td className="mono">{t.server_id}</td>
                    <td className="mono">{t.tool_name}</td>
                    <td>{t.status ? <StatusBadge value={t.status} /> : <span className="dim">—</span>}</td>
                    <td className="dim" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/pages/MCPGateway.tsx && git commit -m "feat: add MCP gateway page"`

---

### Task 11: Audit page

**Files:**
- Create: `interlock-web/src/pages/Audit.tsx`

- [ ] Create `interlock-web/src/pages/Audit.tsx`:

```tsx
import { useEffect, useState, useCallback } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, hasApiKey, AuditEvent } from '../api'
import StatusBadge from '../components/StatusBadge'
import ErrorCard from '../components/ErrorCard'
import EmptyState from '../components/EmptyState'

const ACTIONS = ['all', 'allow', 'block', 'monitor', 'quarantine', 'deny']
const SEVERITIES = ['all', 'low', 'medium', 'high', 'critical']

export default function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [action, setAction] = useState('all')
  const [severity, setSeverity] = useState('all')

  const load = useCallback(async () => {
    if (!hasApiKey()) return
    setLoading(true); setErr('')
    try {
      const d = await api.mcpAudit(200)
      setEvents(d.events)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = events.filter(e => {
    if (action !== 'all' && e.action.toLowerCase() !== action) return false
    if (severity !== 'all' && (e.drift_severity || '').toLowerCase() !== severity) return false
    return true
  })

  if (!hasApiKey()) return (
    <div className="dash-main">
      <div className="dash-page-header"><div><h1>Audit Log</h1></div></div>
      <EmptyState />
    </div>
  )

  return (
    <div className="dash-main">
      <div className="dash-page-header">
        <div>
          <h1>Audit Log</h1>
          <p>Every MCP gateway decision — allow, block, monitor, quarantine</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      <div className="filters-row">
        <span style={{ fontSize: 12, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>Action:</span>
        <select className="filter-select" value={action} onChange={e => setAction(e.target.value)}>
          {ACTIONS.map(a => <option key={a} value={a}>{a === 'all' ? 'All actions' : a.toUpperCase()}</option>)}
        </select>
        <span style={{ fontSize: 12, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>Severity:</span>
        <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s === 'all' ? 'All severities' : s.toUpperCase()}</option>)}
        </select>
        <span style={{ fontSize: 12, color: 'var(--dim)' }}>{filtered.length} events</span>
      </div>

      {err && <ErrorCard message={err} onRetry={load} />}

      <div className="card" style={{ padding: 0 }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 20 }}>
            <EmptyState message="No audit events match the current filter." showSettingsLink={false} />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Server</th>
                  <th>Tool</th>
                  <th>Role</th>
                  <th>Action</th>
                  <th>Severity</th>
                  <th>Blocked By</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, i) => (
                  <tr key={e.id ?? i}>
                    <td className="mono dim" style={{ whiteSpace: 'nowrap' }}>
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="mono">{e.server_id}</td>
                    <td className="mono">{e.tool_name}</td>
                    <td className="dim">{e.role || '—'}</td>
                    <td><StatusBadge value={e.action} /></td>
                    <td>{e.drift_severity ? <StatusBadge value={e.drift_severity} /> : <span className="dim">—</span>}</td>
                    <td className="mono dim">{e.blocked_by || '—'}</td>
                    <td className="dim" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {e.reason || e.matched_rule || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] Commit: `git add interlock-web/src/pages/Audit.tsx && git commit -m "feat: add audit log page"`

---

### Task 12: Landing page

**Files:**
- Create: `interlock-web/src/pages/Landing.tsx`

The landing page is a direct JSX port of `interlock-web/interlock-landing-reference.html`. Key transformation rules:
- `class=` → `className=`
- SVG attributes: `viewBox` OK, `stroke-width` → `strokeWidth`, `stroke-dasharray` → `strokeDasharray`, `stroke-dashoffset` → `strokeDashoffset`, `fill-opacity` → `fillOpacity`, `stroke-opacity` → `strokeOpacity`, `text-anchor` → `textAnchor`, `font-family` → `fontFamily`, `font-size` → `fontSize`, `font-weight` → `fontWeight`, `marker-end` → `markerEnd`, `refX` OK, `refY` OK
- `<animate>` → `<animate>` (SVG native, valid JSX)
- `<animateMotion>` → same
- All CSS stays inline in `<style>` tags inside the component or as className references
- JS from the reference HTML's `<script>` block becomes `useEffect` hooks

The landing CSS is self-contained in a `<style>` tag at the top of the component so it doesn't leak into the dashboard.

- [ ] Create `interlock-web/src/pages/Landing.tsx` — see implementation note below.

The file ports the full reference HTML as a React component. All sections map directly:
- Nav: `<nav>` with exact links and CTAs
- Hero: h1 "Runtime Security for MCP Agents", sub, buttons, trusted strip
- Arch split: orb div + cyan/purple panels with exact text
- Flow section: SVG (preserve all animateMotion, animate, defs) + status panel. Status rotation useEffect with `setInterval(fn, 3600)`.
- Layers: 5 pipeline steps with exact copy
- Split sections: policy enforcement (code block with tab switching via useState) + audit terminal (animated rows)
- Color split: 4 feature cards with exact copy
- Metrics strip: 4 blocks with exact numbers
- Pricing: 3 tiers with exact copy
- Final CTA: lime left + purple right panels
- Footer: 5-column grid

All external links (Calendly, Notion docs, GitHub) are preserved exactly from the reference.

The inline `<style>` block contains all the CSS from the reference HTML's `<style>` section, scoped under a `.landing` wrapper class to prevent leakage.

- [ ] Commit: `git add interlock-web/src/pages/Landing.tsx && git commit -m "feat: port landing page to React"`

---

### Task 13: Build verification

- [ ] Run from `interlock-web/`:

```
npm run build
```

Expected: TypeScript compile succeeds, Vite bundles to `dist/`. No errors.

- [ ] If TypeScript errors appear: fix unused imports/variables flagged by `noUnusedLocals` and `noUnusedParameters`. Common fixes:
  - Remove unused imports
  - Add `_` prefix to unused parameters: `_e` instead of `e`

- [ ] Verify `dist/index.html` exists and `dist/assets/` contains JS/CSS bundles.

- [ ] Final commit: `git add interlock-web && git commit -m "feat: complete Interlock web app build"`

---

## Deployment

**Vercel:** Import `interlock-web/` as the project root. Set env var `VITE_INTERLOCK_API_URL=https://interlock.onrender.com`. Build command: `npm run build`. Output dir: `dist`.

**Local dev:** `cd interlock-web && npm run dev` → http://localhost:5173

## Known backend gaps

- No `GET /scan/history` endpoint — no history page in v1.
- Shadow stats only available if backend has `SHADOW_SCAN_ENABLED=true`.
- `/ws` WebSocket not used — polling/manual refresh only.
