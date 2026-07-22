# AntiFlock Third-Eye web dashboard

The independently runnable TypeScript dashboard for AntiFlock Core. It presents protection posture, topology, path evidence, activity, findings, devices, policies, Secure Action decisions, field intelligence, verified footprint assets, and Scrambler simulation.

## Run locally

Requirements: Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

The dashboard uses the current origin for Core by default. Set `NEXT_PUBLIC_ANTIFLOCK_API_URL` or save a Core URL in Settings when the API is hosted elsewhere.

```bash
npm run build
npm test
npm run lint
```

## Data behavior

- REST projections come from `/v1/overview`, `/v1/nodes`, `/v1/topology`, `/v1/paths`, `/v1/events`, `/v1/findings`, `/v1/posture`, `/v1/field/reports`, `/v1/footprint`, and `/v1/scrambler/state`.
- Durable live projection events come from `/v1/stream`, with topic filters and cursor resume.
- Canonical snake_case fields are accepted. Partial projection failures remain visible.
- When no Core endpoint is reachable, a deterministic coffee-shop incident is shown only if demo fallback is enabled. It is labeled as fixture data throughout the shell.
- The UI never treats nearby reported infrastructure as evidence of interception.

The web app does not collect packet payloads, upload exact field location, or independently infer a live protection state.
