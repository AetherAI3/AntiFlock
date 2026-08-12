# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

COPY --from=build --chown=65532:65532 /out/ /usr/local/bin/
COPY --from=build --chown=65532:65532 /image-data/var/lib/antiflock/ /var/lib/antiflock/
USER nonroot:nonroot
EXPOSE 8787
ENTRYPOINT []
CMD ["antiflock-core", "serve"]
