# Interlock Frontend Design Spec

**Date:** 2026-05-19  
**Product:** Interlock — Runtime security gateway and control plane for MCP agents  
**Scope:** Full rebuild of `interlock-web/` from scratch

---

## 1. Product Positioning

Interlock is the **control plane and system of record for MCP tool security**. It discovers MCP tools, remembers their trusted baseline, detects risky drift, blocks or quarantines unsafe changes, lets operators approve legitimate updates, and records an audit trail for every allow/deny/monitor/quarantine decision.

**Audience:** CTOs, Heads of AI, Staff Security Engineers, platform teams, founders at AI agent companies.

**Tagline:** Runtime security gateway for AI agents.

---

## 2. Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| Framework | React 19 + TypeScript | Retained from prior setup |
| Build | Vite | `@vitejs/plugin-react` |
| Styling | Tailwind v4 via `@tailwindcss/vite` | CSS-first config, `@theme inline` |
| Animation | framer-motion | Restrained, professional |
| Icons | lucide-react | No emoji in production UI |
| Routing | react-router-dom v7 | Sub-routes for dashboard sections |
| HTTP | Fetch API via `interlockApi.ts` | No axios, no Supabase |
| Charts | None initially | Tables are primary data display |

---

## 3. Directory Structure

```
interlock-web/
  src/
    pages/
      Landing.tsx              ← landing page shell
      Dashboard.tsx            ← dashboard shell (sidebar + <Outlet>)
    features/
      overview/Overview.tsx
      drift/DriftReview.tsx
      audit/AuditLog.tsx
      tools/Tools.tsx
      servers/Servers.tsx
      policies/Policies.tsx
      quarantine/Quarantine.tsx
      settings/Settings.tsx
    components/
      landing/
        Nav.tsx
        Hero.tsx
        Problem.tsx
        HowItWorks.tsx
        Capabilities.tsx
        WorkflowExample.tsx
        BuyerProof.tsx
        LandingCTA.tsx
        Footer.tsx
      dashboard/
        Sidebar.tsx            ← fixed left sidebar, 220px
        TopBar.tsx             ← breadcrumb, demo pill, refresh
        StatCards.tsx
        StatusBadge.tsx
        MetadataInspector.tsx
      ui/
        Button.tsx
        Badge.tsx
        EmptyState.tsx
        LoadingState.tsx
    lib/
      interlockApi.ts          ← API calls + demo fallback
      demoData.ts              ← seeded realistic demo state
    styles/
      globals.css              ← CSS tokens, Tailwind @theme, resets, fonts
    App.tsx
    main.tsx
```

---

## 4. Routing

```
/                         → Landing page
/dashboard                → redirect to /dashboard/drift
/dashboard/drift          → DriftReview (default, demo story starts here)
/dashboard/overview       → Overview metrics
/dashboard/audit          → Audit log
/dashboard/tools          → Tool metadata inspector
/dashboard/servers        → MCP server registry
/dashboard/policies       → Policy rules panel
/dashboard/quarantine     → Quarantine queue
/dashboard/settings       → Settings (API key, URL)
```

Both primary CTA "Launch Security Console" and secondary CTA "Review Drift" navigate to `/dashboard/drift`.

---

## 5. Design System

### Color Tokens

```css
--bg:         #080A09    /* page background */
--surface:    #101412    /* card / panel */
--elevated:   #161B18    /* raised surface */
--border:     #27302B    /* default border */
--ac:         #10B981    /* primary emerald */
--ac-muted:   #059669    /* muted emerald */
--ac-sub:     rgba(16,185,129,0.10)
--ac-border:  rgba(16,185,129,0.20)
--warn:       #D6A23A    /* warning amber */
--danger:     #D86A4A    /* danger/deny */
--info:       #7AA2F7    /* info — use sparingly */
--quarantine: #A78BFA    /* quarantine violet — use sparingly */
--tx:         #F4F7F5    /* primary text */
--t2:         #9CA8A2    /* secondary text */
--t3:         #6B7670    /* muted text */
```

### Typography
- Sans: Inter (Google Fonts)
- Mono: JetBrains Mono (timestamps, code, badges, numbers)

### Semantic Action Colors
- allow → emerald
- monitor → amber
- deny → danger
- quarantine → violet

### Layout Dimensions
- Sidebar: 220px fixed
- Section padding: 24px
- Table row height: 48px min
- Card gap: 16px

---

## 6. Landing Page Sections

1. **Nav** — logo, nav links, "Launch Security Console" CTA
2. **Hero** — large headline, subheading, two CTAs, architecture diagram
   - Headline: "Control plane for MCP tool security"
   - Subheading: "Interlock baselines every MCP tool, detects risky drift, enforces role-aware policy before execution, and records an audit trail for every agent decision."
   - Primary CTA: "Launch Security Console" → `/dashboard/drift`
   - Secondary CTA: "Review Drift" → `/dashboard/drift`
3. **Problem** — Fragmented MCP security policy across tools, servers, teams
4. **How Interlock Works** — Discover → Baseline → Enforce → Review → Audit
5. **Core Capabilities** — 6-item grid
6. **Workflow Example** — drift detection narrative
7. **Architecture** — Agent → Interlock Gateway → MCP Servers (SVG diagram)
8. **Buyer Proof** — "Know what every agent was allowed to do before it does it."
9. **Final CTA**
10. **Footer**

---

## 7. Dashboard Sections

### Layout
Fixed left sidebar (220px) + TopBar + section content via `<Outlet>`.  
`/dashboard` redirects to `/dashboard/drift`.

### Sidebar Nav Items
Overview · Drift Review · Audit Log · Tools · Servers · Policies · Quarantine · Settings

### Drift Review Queue — Visual Hero
Primary demo story: tool drifted → detected → classified → quarantined → operator decides.

Table columns: `Server | Tool | Severity | Status | What Changed | Confidence | Action`

Row actions: "Approve Baseline" (emerald ghost) + "Keep Quarantined" (violet ghost)  
Optimistic update: badge changes in-place, new audit event appended.

Filters: server, severity, action type, tool name search.

### Audit Log
Table: `Timestamp | Server | Tool | Action | Role | Matched Rule | Reason`  
Action badge colors: allow=emerald, monitor=amber, deny=danger, quarantine=violet.

### Tools
Full tool table with expandable MetadataInspector panel.

### Servers
MCP server registry: name, URL, trust status, tool count, last seen.

### Policies
Readable rule list (not a table — human-readable format).

### Quarantine
Filtered drift table showing only status=quarantined. Approve/Release actions.

### Overview
6 stat cards + summary of recent drift with link to Drift Review.

---

## 8. Demo Data

### MCP Servers
- `slack-mcp` — Slack MCP Server (trusted, 3 tools)
- `nextcloud-mcp` — Nextcloud File Server (trusted, 2 tools)
- `finance-db-mcp` — Finance Database Server (trusted, 1 tool)

### Drifted Tools

**slack-mcp / export_channel — CRITICAL / quarantined**
- Gained external_sharing effect, PII + financial data classes added
- Confidence: 94%

**nextcloud-mcp / read_file — HIGH / deny**
- side_effect changed none→write, effects gained file_modification
- Confidence: 87%

**finance-db-mcp / query_transactions — CRITICAL / quarantined**
- data_classes expanded to financial_records, pii, account_numbers; export capability added
- Confidence: 96%

### Audit Events (5)
allow, monitor, deny, quarantine — mix of roles and rules, timestamps within last hour.

---

## 9. API Layer

All calls via `interlockApi.ts`. On any error → return demo data from `demoData.ts` + set `isDemoMode = true`. TopBar shows "Demo data" pill when active.

API base from `VITE_INTERLOCK_API_URL` → fallback `http://localhost:8001`.  
API key from localStorage → `VITE_INTERLOCK_API_KEY` → `'lf-free-demo-key-123'`.

---

## 10. Animation (framer-motion)

- Landing section scroll-in: opacity 0→1, y 24→0, 500ms ease-out
- Dashboard section mount: opacity 0→1, y 16→0, 350ms ease-out
- Drift table rows: stagger 60ms per row
- Action badge transition: 200ms
- No looping, no bounce, no spring physics

---

## 11. Quality Gate

- `tsc -b && vite build` passes, zero errors
- ESLint passes, zero errors
- No text overflow in any table or badge
- Responsive: sidebar icon-only ≤ 768px, landing readable on mobile
- Keyboard-accessible buttons
- Dashboard works with backend unavailable (demo mode automatic)
- Optimistic approve/quarantine updates
- Empty, loading, and error states for all data tables
- No lorem ipsum
- No vague copy

---

## 12. What This Is Not

- Not a marketing toy or generic SaaS starter
- Not dependent on a live backend to look correct
- Not using nested cards, oversized empty cards, or purple gradient blobs
- Not using Supabase
- Not using vague copy ("leverage AI-powered insights")
