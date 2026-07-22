const maximumProxyRequestBytes = 1 << 20;

export interface CoreProxyEnv {
  ANTIFLOCK_API_ORIGIN?: string;
  ANTIFLOCK_OPERATOR_TOKEN?: string;
}

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

function configured(env: CoreProxyEnv, name: keyof CoreProxyEnv): string {
  const binding = env[name]?.trim();
  if (binding) return binding;
  if (typeof process !== "undefined") return process.env[name]?.trim() ?? "";
  return "";
}

function privateHTTPHost(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (normalized === "localhost" || normalized === "core" || normalized === "::1") return true;
  const octets = normalized.split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false;
  return octets[0] === 10 || octets[0] === 127 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127);
}

function parseCoreOrigin(raw: string): URL | null {
  try {
    const value = new URL(raw);
    const cleanRoot = (value.pathname === "" || value.pathname === "/") && !value.search && !value.hash && !value.username && !value.password;
    const secure = value.protocol === "https:";
    const localHTTP = value.protocol === "http:" && privateHTTPHost(value.hostname);
    return cleanRoot && (secure || localHTTP) ? value : null;
  } catch {
    return null;
  }
}

function jsonError(status: number, code: string, message: string): Response {
  return Response.json({ code, message }, { status, headers: { "Cache-Control": "no-store" } });
}

export function withSecurityHeaders(response: Response, requestURL: string): Response {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", headers.get("Cache-Control") ?? "no-store");
  headers.set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; worker-src 'self'; manifest-src 'self'");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  if (new URL(requestURL).protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  headers.delete("Set-Cookie");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export async function proxyCoreRequest(
  request: Request,
  env: CoreProxyEnv,
  fetcher: Fetcher = fetch,
): Promise<Response | null> {
  const incomingURL = new URL(request.url);
  if (!incomingURL.pathname.startsWith("/v1/")) return null;

  const rawOrigin = configured(env, "ANTIFLOCK_API_ORIGIN");
  const token = configured(env, "ANTIFLOCK_OPERATOR_TOKEN");
  if (!rawOrigin && !token) return null;
  if (!rawOrigin || token.length < 32) {
    return withSecurityHeaders(jsonError(503, "CORE_PROXY_MISCONFIGURED", "The private Core proxy is not fully configured."), request.url);
  }
  const coreOrigin = parseCoreOrigin(rawOrigin);
  if (!coreOrigin) {
    return withSecurityHeaders(jsonError(503, "CORE_PROXY_ORIGIN_INVALID", "The configured Core origin is not allowed."), request.url);
  }
  if (!["GET", "POST", "PATCH"].includes(request.method)) {
    return withSecurityHeaders(jsonError(405, "METHOD_NOT_ALLOWED", "This Core proxy method is not allowed."), request.url);
  }
  if (request.method !== "GET") {
    const origin = request.headers.get("Origin");
    const fetchSite = request.headers.get("Sec-Fetch-Site");
    if (origin !== incomingURL.origin || (fetchSite !== null && fetchSite !== "same-origin")) {
      return withSecurityHeaders(jsonError(403, "CROSS_ORIGIN_DENIED", "Cross-origin Core mutations are not allowed."), request.url);
    }
  }

  const declaredLength = Number(request.headers.get("Content-Length") ?? "0");
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > maximumProxyRequestBytes) {
    return withSecurityHeaders(jsonError(413, "REQUEST_TOO_LARGE", "The Core proxy request is too large."), request.url);
  }
  let body: ArrayBuffer | undefined;
  if (request.method !== "GET") {
    const contentType = request.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") {
      return withSecurityHeaders(jsonError(415, "UNSUPPORTED_MEDIA_TYPE", "Core mutations require application/json."), request.url);
    }
    body = await request.arrayBuffer();
    if (body.byteLength > maximumProxyRequestBytes) {
      return withSecurityHeaders(jsonError(413, "REQUEST_TOO_LARGE", "The Core proxy request is too large."), request.url);
    }
  }

  const upstream = new URL(`${incomingURL.pathname}${incomingURL.search}`, coreOrigin);
  const headers = new Headers({ Accept: request.headers.get("Accept") ?? "application/json", Authorization: `Bearer ${token}` });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const lastEventID = request.headers.get("Last-Event-ID");
  if (lastEventID && lastEventID.length <= 256 && !/[\r\n]/.test(lastEventID)) headers.set("Last-Event-ID", lastEventID);

  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetcher(upstream, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
    });
  } catch {
    return withSecurityHeaders(jsonError(502, "CORE_UNREACHABLE", "The private Core service could not be reached."), request.url);
  }

  const responseHeaders = new Headers();
  for (const name of ["cache-control", "content-type", "etag", "last-modified", "retry-after"]) {
    const value = upstreamResponse.headers.get(name);
    if (value !== null) responseHeaders.set(name, value);
  }
  return withSecurityHeaders(new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  }), request.url);
}
