SHELL := /bin/sh

.PHONY: dev down lab test verify fmt lint build clean

dev:
	docker compose up --build

down:
	docker compose down --remove-orphans

lab:
	docker compose --profile lab up --build --abort-on-container-exit lab

test:
	node scripts/test-all.mjs

verify:
	node scripts/verify.mjs

fmt:
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace golang:1.26.5-bookworm gofmt -w $$(find . -name '*.go' -not -path './apps/*')

lint:
	docker run --rm -e CGO_ENABLED=0 -v "$(CURDIR):/workspace" -w /workspace golang:1.26.5-bookworm go vet ./...

build:
	docker compose build

clean:
	docker compose down --remove-orphans --volumes
	rm -rf bin coverage apps/web/dist sdk/typescript/dist

