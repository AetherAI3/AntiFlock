# AntiFl0ck Relaunch Runbook

Companion to [launch-report.md](launch-report.md) (the article) and
[distribution-kit.md](distribution-kit.md) (the copy blocks). This file is the
sequencing: what to do, in what order, and what only a human can do.

Every boundary from the distribution kit still applies — independent project,
pre-alpha, simulation works today, no anonymity claims, no interference with
third-party infrastructure, AI never makes the enforcement decision.

---

## The actual diagnosis

The repo went public on 2026-07-22 and tagged `v0.1.0-alpha` on 2026-07-27.
Traffic over that window:

| Metric | Value |
| --- | --- |
| Views | 39 |
| **Unique visitors** | **3** |
| Clones | 117 (19 unique — mostly CI and mirrors) |
| Referrers | `github.com` (26), `l.threads.com` (2) |
| Stars | 2 |

Three unique visitors is not an algorithm problem. It is the absence of
distribution. Nothing was posted anywhere with reach, so nothing arrived.

**There is no "re-post" mechanic for a GitHub repository.** A repo is not a feed
item; it has no publish event to repeat. The things people call "the GitHub
algorithm" are narrower than they sound:

- **Trending** ranks by *star velocity inside a short window*. Charting in a
  niche category realistically takes tens of stars in a day. It is a
  consequence of outside traffic, never a source of it.
- **Search** ranks on repo name, description, topics, README, and stars. This is
  the part that is genuinely tunable, and it has now been tuned — but at 2 stars
  the repo loses every ranked query to incumbents with 70–90.
- **Topic pages** (`/topics/homelab`, `/topics/privacy`) sort by stars. Same
  ceiling.
- **Explore / recommendations** run off the social graph — who you follow, who
  stars adjacent repos. Not addressable from inside the repository.

Every one of those is downstream of stars, and stars come from outside GitHub.
So the in-repo work below is real but bounded; the channel work is the actual
lever.

### The competitive read

The high-traffic repos in this niche are Flock **camera detectors** — WiFi
recon, Flipper Zero sniffers, plate-reader mapping:

| Stars | Repo |
| --- | --- |
| 89 | `DeflockYourCity/flock-alpr-toolkit` |
| 83 | `GainSec/Flock-Safety-Trap-Shooter-Sniffer-Alarm` |
| 79 | `JakeSwiz/flock-you-wifi-recon` |
| 72 | `f1yaw4y/FlockSquawk` |
| 71 | `zmattmanz/flock-detection` |

AntiFl0ck is not that product, and the name draws that audience anyway. Readers
arriving from a "flock" query expect hardware detection and bounce when they
find a policy engine. That mismatch is now addressed head-on in the README
rather than left to disappoint, and the `alpr` / `license-plate-reader` topics
were dropped — the tool does not read plates, and squatting that intent is
exactly what a privacy audience punishes.

The audience that *does* fit is self-hosted / homelab / mesh-VPN operators.
Target them.

---

## Done in-repo (2026-07-28)

Already applied — no action needed.

- Description rewritten to front-load searchable terms
- Topics rebuilt: dropped `alpr`, `license-plate-reader`, `digital-privacy`,
  `metadata`, `open-source`; added `golang`, `homelab`, `opsec`, `audit-log`,
  `security`, `selfhosted`
- Discussions enabled
- Secret scanning + push protection enabled
- Dependabot vulnerability alerts + automated security fixes enabled
- `CITATION.cff` added — GitHub now renders the "Cite this repository" widget
- README states who it is for and what it is not, above the fold
- Stale `DBarr3` remote corrected to `AetherAI3`

CodeQL had been failing on `main`. Root cause was `Code scanning is not enabled
for this repository` — an Advanced Security limit from when the repo was
private, not a workflow bug. It resolved on its own when the repo went public.

---

## Only a human can do these

### 1. Upload the social preview — highest single lever

`assets/social-preview.png` (1280×640) exists and is correct. It has **never
been uploaded**, so every link to this repo currently renders GitHub's generic
grey card.

GitHub exposes **no REST API for social preview**. It is web UI only:

> Settings → General → Social preview → Edit → Upload an image

Do this **before** posting anywhere. Every share on HN, Reddit, Lobsters,
Threads, Discord, and Slack unfurls that card, and a branded card versus a grey
default is a large, permanent difference in click-through on identical copy.

### 2. Post to channels

Drafts below. Read the gates before posting — most of these auto-filter new
accounts, and a removed post is worse than no post because it burns the title.

---

## Channel drafts

### Show HN

**Gate:** brand-new accounts get filtered. Use an aged account with prior
comment history. Post Tue–Thu, ~08:00 ET. One shot — a flop burns the title.

**Title** (from the kit, unchanged — it leads with the mechanic, not the brand):

```
Show HN: AntiFl0ck – open-source tool that holds sensitive actions when your trusted route disappears
```

**First comment** — on HN the author's own comment carries the honesty, which is
what that audience rewards:

> I built this after the Flock Safety debate made an asymmetry obvious to me:
> surveillance operates as a correlated network, while defensive tooling is a
> junk drawer of single-purpose products. A VPN carries traffic but can't tell
> your applications the trusted path just vanished.
>
> The demo is fully simulated and runs locally — `make dev && make lab`, Docker
> plus Node 24, no account and no real data. A laptop joins an untrusted
> network, an app requests a sensitive upload, the action is **held** with a
> recorded reason, the route recovers and is **verified**, the action is
> **allowed**. Five signed events in a hash-chained local log.
>
> Being blunt about the state: this is pre-alpha. The simulated slice and the
> dashboard work. Production enforcement, real packet-path integration, mobile,
> and independent review are all open. It does not provide anonymity, does not
> prove surveillance is occurring, does not replace a VPN, and does not detect
> or interfere with anyone's cameras.
>
> The design rule I care most about: every finding carries an evidence label —
> detected, verified, reported, inferred, suspected, unknown — so a guess never
> quietly becomes an accusation. An AI may explain a finding; it never makes the
> allow-or-block decision.
>
> Apache-2.0. Happy to answer anything about the threat model or the policy
> engine.

**Expect** to be challenged on: what enforcement actually means at pre-alpha,
why this isn't just a firewall, and the name-versus-scope question. Answer
plainly; do not defend scope you haven't built.

### r/selfhosted

**Gate:** read the current self-promo rule before posting; several privacy and
selfhosted subs require a set account age plus karma, and some want a flair or a
weekly thread instead of a top-level post.

**Title:**

```
I built an open-source tool that holds sensitive actions when your trusted mesh route drops — pre-alpha, demo runs locally
```

**Body:**

> **What it does:** maps your devices, routes, and mesh peers, then gates
> sensitive actions against deterministic policy *you* write. If your trusted
> route through Tailscale/Headscale/WireGuard is gone, the action is held with a
> recorded reason instead of silently going out over coffee-shop WiFi. When the
> route is verified back, it's allowed. Every decision is signed into a local
> hash-chained audit log on your machine.
>
> **Runs today:** `make dev && make lab` — Docker + Node 24, fully simulated
> coffee-shop scenario, no VPN account or real data needed. Third-Eye dashboard
> at `127.0.0.1:4173`.
>
> **Honest state:** pre-alpha. The simulation, policy engine, signed audit log,
> secure-action gate, TypeScript SDK, Linux route observation, and read-only
> Tailscale/Headscale probes work. Production enforcement, macOS/Windows
> collectors, and mobile are open work — that's where contributors would have
> the most impact.
>
> **Not what it is:** no anonymity, no VPN replacement, no camera detection, no
> interference with anyone's infrastructure. Defensive layer for networks you
> already control.
>
> Apache-2.0, built in public. Ten scoped issues are labelled good-first-issue /
> help-wanted if anyone wants a way in.

### r/privacy

Same body, but lead with the **evidence taxonomy** — that sub is sharp on
overclaiming, and the six-level labelling is the thing that survives scrutiny:

> Security tooling should distinguish what it observed from what it inferred.
> Every finding here is labelled DETECTED, VERIFIED, REPORTED, INFERRED,
> SUSPECTED, or UNKNOWN, so a guess never quietly becomes an accusation. An AI
> may explain a finding; it never makes the allow-or-block decision.

### Lobste.rs

**Gate:** invite-only. Only post if you already have an account — do not solicit
an invite in order to self-promote, that gets accounts banned.

Tag `security` + `privacy`. Same framing as HN but shorter; that audience reads
the code before the pitch, so link the threat model directly.

### Tailscale / Headscale communities

Highest signal-to-noise available and the most precise audience fit — the
read-only Tailscale and Headscale probes are already built, so this is on-topic
rather than self-promo. Lead with the integration, not the project.

Do not cross-post the same text everywhere on the same day.

---

## Awesome-list submissions — hold

Recommend **not** submitting yet, despite the durable long-tail traffic:

- `awesome-selfhosted` rejects early-alpha software outright
- `awesome-go` expects tests plus real traction
- Most curated lists want a working, non-simulated release

At pre-alpha with 2 stars these are likely rejections, and a rejected entry is
hard to re-apply against later. Revisit once a non-simulated slice ships — the
same submission then lands instead of burning the opportunity.

---

## Sequencing

1. Upload the social preview. Nothing else ships until this is done.
2. Merge the open discoverability PR so the README and citation widget are live.
3. Pick **one** channel and post. Not all of them at once — a single thread you
   answer well beats four you abandon.
4. Answer every comment within the first two hours. Response rate drives
   ranking on HN and Reddit far more than the post body does.
5. Wait for that thread to settle before opening the next channel.

## What to measure

Check `Insights → Traffic` 24h after each post. The number that matters is
**unique visitors**, not views, and **referrers** — that tells you which channel
actually moved and which did nothing. Star count is the lagging indicator;
referrer diversity is the leading one.

If a channel returns fewer than ~50 uniques, the problem is the post, not the
project. Rewrite the hook before trying the next channel.
