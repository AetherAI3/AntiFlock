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
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/antiflockctl ./cmd/antiflockctl

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8787
ENTRYPOINT []
CMD ["antiflock-core", "serve"]

