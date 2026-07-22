# AntiFlock Third-Eye web dashboard

The independently runnable TypeScript dashboard for AntiFlock Core. It presents protection posture, topology, path evidence, activity, findings, devices, policies, Secure Action decisions, field intelligence, verified footprint assets, and Scrambler simulation.

## Run locally

Requirements: Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

In the local stack, the dashboard reaches Core only through its authenticated
same-origin server proxy. The proxy holds the scoped Core credential
server-side; browser JavaScript cannot configure or receive it. When that proxy
is unavailable, the standalone build can show the deterministic coffee-shop
fixture only when demo fallback was enabled at build time, and labels the data
as a simulation throughout the interface.

```bash
npm run build
npm test
npm run lint
```

## Data behavior

- REST projections come from `/v1/overview`, `/v1/nodes`, `/v1/topology`, `/v1/paths`, `/v1/events`, `/v1/findings`, `/v1/posture`, `/v1/field/reports`, `/v1/footprint`, and `/v1/scrambler/state`.
- Durable live projection events come from `/v1/stream`, with topic filters and cursor resume.
- Canonical snake_case fields are accepted. Partial projection failures remain visible.
- When the server proxy cannot reach Core, a deterministic coffee-shop incident is shown only if demo fallback is enabled. It is labeled as fixture data throughout the shell.
- The UI never treats nearby reported infrastructure as evidence of interception.

The web app does not collect packet payloads, upload exact field location, or independently infer a live protection state.
