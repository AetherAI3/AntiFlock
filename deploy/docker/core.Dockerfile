# syntax=docker/dockerfile:1.7
FROM golang:1.26.5-bookworm AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/antiflock-core ./cmd/antiflock-core && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/antiflock-agent ./cmd/antiflock-agent && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/antiflock-sim ./cmd/antiflock-sim && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/antiflockctl ./cmd/antiflockctl && \
    install -d -m 0700 -o 65532 -g 65532 /image-data/var/lib/antiflock && \
    test "$(stat -c '%u:%g:%a' /image-data/var/lib/antiflock)" = "65532:65532:700"

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build --chown=65532:65532 /out/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /image-data/var/lib/antiflock/ /var/lib/antiflock/
USER nonroot:nonroot
EXPOSE 8787
ENTRYPOINT []
CMD ["antiflock-core", "serve"]
