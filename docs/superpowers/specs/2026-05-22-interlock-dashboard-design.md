# Interlock Web App — Design Spec
**Date:** 2026-05-22  
**Stack:** Vite + React 18 + TypeScript + React Router v6 + lucide-react  
**Deployment:** Vercel (SPA rewrite)  
**Backend:** https://interlock.onrender.com

---

## Scope

A single Vite SPA with two major zones:

1. **Landing page** (`/`) — faithful port of `interlock-web/interlock-landing-reference.html` into React components. Exact copy, exact links, all CSS animations preserved.
2. **Dashboard** (`/dashboard/*`) — operator product view. Real API data, graceful empty/error states, manual refresh pattern.

---

## Project Layout

```
interlock-web/
  package.json
  vite.config.ts
  tsconfig.json
  index.html
  vercel.json              # SPA rewrite: /* → /index.html
  src/
    main.tsx               # ReactDOM.createRoot + BrowserRouter
    App.tsx                # Route tree
    api.ts                 # API client — reads key/url from localStorage
    styles.css             # Design tokens + shared CSS primitives
    components/
      Nav.tsx              # Landing top nav
      DashLayout.tsx       # Dashboard shell (sidebar + outlet)
      StatusBadge.tsx      # ALLOW/BLOCK/MONITOR/QUARANTINE chip
      MetricCard.tsx       # Metric stat box
      ErrorCard.tsx        # Per-section fetch error
      EmptyState.tsx       # No-key or empty-data placeholder
    pages/
      Landing.tsx          # / — full landing
      Dashboard.tsx        # /dashboard
      Scan.tsx             # /dashboard/scan
      MCPGateway.tsx       # /dashboard/mcp
      Audit.tsx            # /dashboard/audit
      Settings.tsx         # /dashboard/settings
```

---

## Routing

| Path | Component | Chrome |
|---|---|---|
| `/` | `Landing.tsx` | None |
| `/dashboard` | `Dashboard.tsx` | `DashLayout` |
| `/dashboard/scan` | `Scan.tsx` | `DashLayout` |
| `/dashboard/mcp` | `MCPGateway.tsx` | `DashLayout` |
| `/dashboard/audit` | `Audit.tsx` | `DashLayout` |
| `/dashboard/settings` | `Settings.tsx` | `DashLayout` |

`DashLayout`: 220px fixed sidebar + top status strip + `<Outlet>`. Collapses to top nav on mobile ≤768px.

---

## API Client (`src/api.ts`)

Reads `interlock_api_url` (default `https://interlock.onrender.com`) and `interlock_api_key` from `localStorage` at each call. Throws `ApiError(status: number, message: string)` on non-2xx.

**Methods:**

| Method | Endpoint |
|---|---|
| `health()` | `GET /health` |
| `usage()` | `GET /usage` |
| `scan(prompt)` | `POST /scan` |
| `scanOutput(prompt)` | `POST /scan/output` |
| `shadowStats()` | `GET /shadow/stats` |
| `mcpServers()` | `GET /mcp/servers` |
| `mcpTools(server_id?)` | `GET /mcp/tools` |
| `mcpDrifted(server_id?)` | `GET /mcp/tools/drifted` |
| `approveTool(server_id, tool, payload)` | `POST /mcp/tools/{server_id}/{tool_name}/approve` |
| `quarantineTool(server_id, tool, payload)` | `POST /mcp/tools/{server_id}/{tool_name}/quarantine` |
| `mcpAudit(limit?)` | `GET /mcp/audit` |
| `siemProviders()` | `GET /siem/providers` |
| `roles()` | `GET /roles` |

---

## Page Designs

### `/` — Landing

Sections (all verbatim from reference HTML):
1. Nav — Interlock wordmark, HOW IT WORKS / DESIGN PARTNER / ARCHITECTURE / DOCS / LIVE DEMO links, REQUEST ACCESS CTA
2. Hero — "Runtime Security for MCP Agents" h1, sub, REQUEST ACCESS + DOCS buttons, trusted strip
3. Arch split — cyan/green left panel "What is Interlock?", orb, right text panel
4. Flow section — SVG animated architecture diagram + JS status rotation panel. Status states: allow/monitor/quarantine cycle every 3.6s.
5. 5-Layer pipeline — L0 Learned Memory, L1 Rule Engine, L2 Pattern Matcher, L3 LLM Judge, CP Custom Policy
6. Split sections — Policy Enforcement (code block with Python/JS/API tabs) + Observability (audit terminal with animated rows)
7. Color split — Tool Drift Detection (cyan), Deployment Flexibility (lime), Response Scanning (red), Configurable Fail Mode (purple)
8. Metrics strip — <1s, 6 stages, 80+, 0 changes
9. Pricing — Builder (Free), Design Partner (Apply), Enterprise (Custom)
10. Final CTA — left lime panel (early access), right purple panel (rhetorical question)
11. Footer — 5-column grid, copyright

All external links preserved (Calendly, Notion docs, GitHub).

### `/dashboard` — Overview

Top strip: health dot (green/red) + `Interlock` wordmark + status text.

Three metric cards: Usage (used/limit), MCP Servers (count), Drifted Tools (count, red accent if >0).

Quick actions row: "Run Prompt Scan", "Validate MCP Tool", "View Shadow Stats" — lucide icons, link or local modal.

Recent audit table: last 10 rows from `GET /mcp/audit`. Columns: time, server, tool, role, action badge, drift severity.

Shadow stats block: total shadow scans, threat rate, top threat type (if available).

Empty state: if no key → `EmptyState` with link to Settings.

### `/dashboard/scan`

Two side-by-side forms: **Prompt Scan** and **Output Scan**.

Prompt Scan: textarea + "Scan Prompt" button → `POST /scan`. Show result card: threat level badge, reason, confidence %, layer caught, risk score, scan time.

Output Scan: textarea + "Scan Output" button → `POST /scan/output`. Same result card shape.

Result state colors:
- `SAFE` → cyan border
- `MEDIUM` → yellow
- `HIGH` → orange
- `CRITICAL` → red

### `/dashboard/mcp`

Three sections with manual refresh:

1. **Servers** — table from `GET /mcp/servers`. Columns: server_id, url, trust level, tool count, registered.
2. **All Tools** — table from `GET /mcp/tools`. Columns: server, tool name, status badge, description truncated.
3. **Drifted / Quarantined** — cards from `GET /mcp/tools/drifted`. Each card shows drift severity, drift action, effects, data classes, and two action buttons: Approve + Quarantine. Approve calls `POST /mcp/tools/{server_id}/{tool_name}/approve`, Quarantine calls the quarantine endpoint. Shows confirmation inline after action.

### `/dashboard/audit`

Table from `GET /mcp/audit`. Columns: timestamp, server, tool, role, action badge, matched rule, blocked_by, drift severity, reason.

Filters: Action (all / allow / block / monitor / quarantine), Drift Severity (all / low / medium / high / critical). Client-side filter on fetched data.

Refresh button top-right.

### `/dashboard/settings`

Two sections:
1. **Connection** — API Base URL input (default shown), API Key input (password type), Save button. Key saved to `localStorage`. Shows key fingerprint (last 6 chars) after save, never full key.
2. **SIEM Providers** — if key exists, fetches `GET /siem/providers` and displays list of supported integrations in a code-style card. No SIEM configuration UI in v1 (shown as reference only).

---

## Visual Design

### Tokens (exact from reference)

```css
:root {
  --black: #060608;
  --white: #f5f0e8;
  --red: #e8182c;
  --cyan: #00e5c8;
  --lime: #c8f000;
  --orange: #ff6b35;
  --purple: #7c3aed;
}
```

### Typography
- Body: `Geist, Inter, ui-sans-serif, system-ui`
- Code/labels: `DM Mono, monospace`
- Loaded from Google Fonts CDN

### Dashboard UI rules
- Cards: `border: 1px solid rgba(245,240,232,.10)`, `background: rgba(245,240,232,.04)`, radius ≤4px
- Tables: border-bottom rows only, no zebra
- Status badges: exact background/border/color from reference
- Border radius: never exceeds 6px in dashboard, 0px in most landing sections
- Sidebar: `background: #060608`, `border-right: 1px solid rgba(245,240,232,.08)`

### Status badge colors
| State | Text | Border | Background |
|---|---|---|---|
| ALLOW | `#00e5c8` | `rgba(0,229,200,.3)` | `rgba(0,229,200,.15)` |
| BLOCK | `#ff4455` | `rgba(232,24,44,.3)` | `rgba(232,24,44,.15)` |
| MONITOR | `#ffcc00` | `rgba(255,204,0,.3)` | `rgba(255,204,0,.12)` |
| QUARANTINE | `#ff6b35` | `rgba(255,107,53,.3)` | `rgba(255,107,53,.12)` |

---

## Empty & Error States

- **No key**: `EmptyState` → icon + "No API key configured." + "Go to Settings →" button
- **API error**: `ErrorCard` → icon + error message + "Retry" button
- **401/403**: inline badge "Invalid or missing API key."
- Each dashboard section is independently failable

---

## Deployment

### `vercel.json`
```json
{
  "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
```

### `vite.config.ts`
```ts
base: '/'
```

### Env var
`VITE_INTERLOCK_API_URL` — set in Vercel dashboard. Fallback: `https://interlock.onrender.com`.

---

## Known Backend Gaps (discovered during design)

- No `GET /scan/history` endpoint — no scan history page possible in v1.
- No `GET /mcp/tools/{server_id}/{tool_name}` detail endpoint — tool cards show only list fields.
- `/ws` WebSocket available but not used in v1 (polling / manual refresh instead).
- Shadow stats (`GET /shadow/stats`) requires `SHADOW_SCAN_ENABLED=true` on backend — will show gracefully if unavailable.
