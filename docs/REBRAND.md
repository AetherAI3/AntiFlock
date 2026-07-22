# Rebrand checklist — AntiFlock → AntiFl0ck

The public name is **AntiFl0ck** (chosen to avoid a documented collision with an
existing project). The README, logo, and public prose already use it. This
checklist migrates the remaining **in-tree identifiers** and re-proves the build.
Run it on a workstation that has the full toolchain — **Go, Buf, Node 24+, and
Docker** — because the wire package and generated code must be regenerated and the
ten-gate release must pass. It cannot be verified without them.

## What changes, what is preserved

- **Changes:** Go string identifiers, `ANTIFLOCK_*` env vars, binary and directory
  names (`antiflock-core` → `antifl0ck-core`, `api/proto/antiflock` →
  `api/proto/antifl0ck`), the protobuf package `antiflock.v1` → `antifl0ck.v1`,
  npm package names, config profiles, compose, scripts, and docs prose.
- **Preserved:** the Go module path and repository URL
  `github.com/DBarr3/AntiFlock` (the GitHub repo keeps its name), so import paths
  never break.
- **Regenerated, not string-edited:** `api/gen/**` (`*.pb.go`),
  `package-lock.json`, and `go.sum`.

## Steps

1. **Branch.** `git switch -c rebrand/antifl0ck`
2. **Dry run and review.** `node scripts/rebrand-antifl0ck.mjs` — inspect the list
   of files and directory renames. Nothing is written.
3. **Apply.** `node scripts/rebrand-antifl0ck.mjs --apply` — rewrites text and
   renames `antiflock`-named directories.
4. **Regenerate protobuf.** `npx buf generate` (from the repo root or `api/proto`
   per `buf.gen.yaml`). Then remove any stale generated package:
   `rm -rf api/gen/go/antiflock`.
5. **Compile and test Go.** `go mod tidy && go build ./... && go test ./... && go vet ./...`
6. **Reinstall and re-lock JS.** `npm install` (regenerates `package-lock.json`
   with the new package names).
7. **Run the locked release gate.** `npm run verify` — must reach `10 / 10` strict
   acceptance gates.
8. **Spot-check the running stack.** `npm run dev`, confirm the dashboard loads and
   the env file is now `.antifl0ck/dev.env` with `ANTIFL0CK_*` variables, then
   `npm run lab`.
9. **Grep for leftovers.** `git grep -in antiflock` — the only expected matches are
   inside `github.com/DBarr3/AntiFlock` paths, this file, and historical CHANGELOG
   entries.
10. **Commit.** Focused commit: `refactor: rebrand internal identifiers antiflock → antifl0ck`.

## Rollback

The change is isolated to a branch and fully reversible: `git checkout -- .` before
committing, or `git switch main` and delete the branch. `--apply` never touches
`.git`.

## Follow-ups (separate, gated)

- Publishing npm packages requires flipping `"private": true` — still gated by the
  acceptance **contracts** gate and the release process.
- Bumping the protobuf package to a public `v1` namespace is a wire decision; keep
  it `antifl0ck.v1` unless a compatibility break is intended (see
  [open-questions.md](open-questions.md)).
