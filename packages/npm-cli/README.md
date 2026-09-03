# antiflock

Bootstrap and run [AntiFl0ck](https://github.com/AetherAI3/AntiFlock) — open-source
counter-surveillance for the networks you control — with one command. No manual
`git clone`, no hand-editing compose files.

Pre-alpha: this installs and runs the local, fully-simulated demo stack (Core,
policy engine, signed audit log, Third-Eye dashboard). Host-level enforcement is
still under active development — see the
[release status](https://github.com/AetherAI3/AntiFlock/blob/main/docs/release-status.md).

## Requirements

- [Docker](https://docs.docker.com/get-docker/)
- [git](https://git-scm.com/)
- Node.js 20+

## Quick start

```bash
npx antiflock init
npx antiflock dev
```

`init` clones the repo into `./antiflock` (skipped if you're already inside a
checkout) and generates a private, locally-scoped config at
`.antiflock/dev.env` — operator/SDK/agent/dashboard tokens, never committed.

`dev` builds and starts the full stack. Once it's up, open
<http://127.0.0.1:4173> — username `operator`, token from that config file.

Run the scripted coffee-shop simulation against a running stack:

```bash
npx antiflock lab
```

Stop everything:

```bash
npx antiflock down
```

## Commands

| Command | Does |
| --- | --- |
| `antiflock init` | Clone (if needed) and generate local config |
| `antiflock dev` | Build and start the full local stack |
| `antiflock lab` | Run the one-shot coffee-shop simulation |
| `antiflock build` | Build images without starting them |
| `antiflock down` | Stop the local stack |
| `antiflock clean` | Stop and remove local stack volumes |

Flags: `--dir <path>` (checkout location, default `./antiflock`), `--ref <git-ref>`
(branch or tag to clone, default `main`).

## Feature configuration

- `.antiflock/dev.env` — generated secrets and node/application identifiers
  (permissions locked down automatically; regenerate by deleting the file and
  re-running `init`).
- `configs/demo.yaml` and `docker-compose.yml` in the checkout — service ports,
  demo-mode flags, and the `lab` profile.
- Full walkthrough: [docs/operator-runbook.md](https://github.com/AetherAI3/AntiFlock/blob/main/docs/operator-runbook.md).

## Already have a checkout?

Run any command from inside it and the CLI uses that directory directly instead
of cloning a new one — it's just a thin wrapper around
`node scripts/compose.mjs`.

## License

Apache-2.0, see [LICENSE](LICENSE). AntiFl0ck is an independent open-source
project; see [TRADEMARKS.md](https://github.com/AetherAI3/AntiFlock/blob/main/TRADEMARKS.md).
