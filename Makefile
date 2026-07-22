.PHONY: dev dev-env down lab sdk-live test verify fmt lint build clean

dev:
	node scripts/compose.mjs dev

dev-env:
	node scripts/dev-env.mjs

down:
	node scripts/compose.mjs down

lab:
	node scripts/compose.mjs lab

sdk-live:
	node scripts/sdk-live-e2e.mjs

test:
	node scripts/test-all.mjs

verify:
	node scripts/verify.mjs

fmt:
	node scripts/format.mjs

lint:
	node scripts/verify.mjs --lint-only

build:
	node scripts/compose.mjs build

clean:
	node scripts/compose.mjs clean
	node scripts/clean.mjs
