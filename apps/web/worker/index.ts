/** Cloudflare Worker entry point for the AntiFlock Third-Eye dashboard. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { dashboardAccessResponse, proxyCoreRequest, withSecurityHeaders, type CoreProxyEnv } from "./proxy";

interface Env extends CoreProxyEnv {
  ASSETS: {
    fetch(request: Request): Promise<Response>;
  };
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env | undefined, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    const accessResponse = await dashboardAccessResponse(request, env);
    if (accessResponse) return withSecurityHeaders(accessResponse, request.url);

    const coreResponse = await proxyCoreRequest(request, env);
    if (coreResponse) return coreResponse;

    if (url.pathname === "/_vinext/image") {
      if (!env?.ASSETS || !env.IMAGES) {
        return withSecurityHeaders(new Response("Image optimization is unavailable.", { status: 503 }), request.url);
      }
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const response = await handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return withSecurityHeaders(response, request.url);
    }

    return withSecurityHeaders(await handler.fetch(request, env, ctx), request.url);
  },
};

export default worker;
