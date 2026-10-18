# Blindspot Security Console (frontend)

React + TypeScript + Vite + Tailwind CSS dashboard for the Blindspot Android APK
security assessment platform. Tagline: *Find what others miss.*

## Run

```bash
npm install
npm run dev      # http://localhost:5173, /api proxied to http://localhost:8000
npm run build    # production build -> dist/
```

The backend API must be running at `http://localhost:8000`. Every number on every
screen comes from the API - there is no mock data. Missing fields render as "-".

## Routes

| Route | Screen |
|---|---|
| `/` | Upload: drag-and-drop APK, scan config (AI review toggle, model name, disabled rules), dependency readiness, privacy notice |
| `/scans/:scanId/live` | Live scan: stage, progress bar (indeterminate when percent is null), stages list, checks run, findings so far, elapsed, errors, cancel; auto-navigates to overview on SSE `done` |
| `/scans/:scanId` | Overview: metadata, severity counts, OWASP M1–M10 distribution, AI status, limitations, errors, HTML/PDF/JSON exports |
| `/scans/:scanId/findings` | Findings explorer: search, severity/OWASP/engine/confidence/review-status filters, severity/confidence sort, expandable rows with code viewer, copy evidence/remediation, assessor review (confirmed / rejected / accepted risk / needs review + note) |
| `/history` | Scan history table: reopen, export, delete |
| `/rules` | Searchable rule library table |
| `/system` | Tool status cards, resource limits, local Ollama model setup hints |

## Notes

- Dark mode is class-based, toggled in the header, persisted in `localStorage`.
- Live scan progress uses `EventSource` against `GET /api/scans/:id/events`
  (`progress` / `done` / `error` named events); stage details refresh via
  `GET /api/scans/:id`.
- Severity colors: critical red, high orange, medium amber, low blue,
  informational gray.
- Code snippets render in escaped `<pre>` blocks with line numbers - never
  interpreted as HTML.
