#!/usr/bin/env node

import http from "node:http";

const maximumRequestBytes = 1 << 20;
const maximumResponseBytes = 8 << 20;
const hopByHopHeaders = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function endpoint(value, fallback) {
  const parsed = new URL(value ?? fallback);
  if (parsed.protocol !== "http:" || parsed.username !== "" || parsed.password !== "") {
    throw new Error("SDK loopback bridge endpoints must use credential-free HTTP URLs.");
  }
  return parsed;
}

const target = endpoint(process.env.ANTIFLOCK_PROXY_TARGET, "http://172.30.0.10:8787");
const listen = endpoint(`http://${process.env.ANTIFLOCK_PROXY_LISTEN ?? "0.0.0.0:18787"}`);

function filteredHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers).filter(([name, value]) =>
      value !== undefined && name.toLowerCase() !== "host" && !hopByHopHeaders.has(name.toLowerCase()),
    ),
  );
}

function safeFailure(response, status) {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    connection: "close",
  });
  response.end(JSON.stringify({ error: status === 413 ? "request_too_large" : "core_unavailable" }));
}

const server = http.createServer((request, response) => {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > maximumRequestBytes) {
    safeFailure(response, 413);
    request.resume();
    return;
  }

  const upstream = http.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: request.method,
    path: request.url,
    headers: filteredHeaders(request.headers),
  });
  upstream.setTimeout(130_000, () => upstream.destroy(new Error("upstream timeout")));

  let requestBytes = 0;
  request.on("data", (chunk) => {
    requestBytes += chunk.length;
    if (requestBytes > maximumRequestBytes) {
      upstream.destroy();
      safeFailure(response, 413);
      return;
    }
    upstream.write(chunk);
  });
  request.on("end", () => upstream.end());
  request.on("aborted", () => upstream.destroy());
  request.on("error", () => upstream.destroy());

  upstream.on("response", (incoming) => {
    response.writeHead(incoming.statusCode ?? 502, filteredHeaders(incoming.headers));
    let responseBytes = 0;
    incoming.on("data", (chunk) => {
      responseBytes += chunk.length;
      if (responseBytes > maximumResponseBytes) {
        incoming.destroy();
        response.destroy();
        return;
      }
      response.write(chunk);
    });
    incoming.on("end", () => response.end());
    incoming.on("error", () => response.destroy());
  });
  upstream.on("error", () => safeFailure(response, 502));
});

server.headersTimeout = 10_000;
server.requestTimeout = 135_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;
server.listen(Number(listen.port), listen.hostname);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
