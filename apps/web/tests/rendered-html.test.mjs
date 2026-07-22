import assert from "node:assert/strict";
import test from "node:test";

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${path}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the AntiFlock command shell with honest source state", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Overview · AntiFlock<\/title>/i);
  assert.match(html, /AntiFlock/);
  assert.match(html, /Third-Eye Console/);
  assert.match(html, /CHECKING CORE/);
  assert.match(html, /Awaiting current Core evidence/);
  assert.doesNotMatch(html, /Protection interrupted/);
  assert.doesNotMatch(html, /held Aether Code action was released/);
  assert.match(html, /aria-label="Primary navigation"/);
  assert.match(html, /Skip to dashboard content/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/i);
});

test("server-renders every required route", async () => {
  const routes = [
    "/overview",
    "/network",
    "/path",
    "/activity",
    "/findings",
    "/devices",
    "/policies",
    "/actions",
    "/field",
    "/intelligence",
    "/footprint",
    "/scrambler",
    "/settings",
  ];
  for (const route of routes) {
    const response = await render(route);
    assert.equal(response.status, 200, route);
    const html = await response.text();
    assert.match(html, /AntiFlock/, route);
  }
});

test("rejects unknown dashboard routes", async () => {
  const response = await render("/not-a-real-view");
  assert.equal(response.status, 404);
  assert.match(await response.text(), /This Third-Eye view does not exist/);
});
