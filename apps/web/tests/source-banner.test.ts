import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SourceBannerView } from "../src/app/dashboard-frame";

function renderBanner({
  mode = "live",
  simulation = null,
  evidenceProvenance = "UNKNOWN",
  failedEndpoints = [],
}: {
  mode?: "checking" | "live" | "partial" | "demo" | "error";
  simulation?: boolean | null;
  evidenceProvenance?: "LIVE" | "SIMULATION" | "UNKNOWN";
  failedEndpoints?: string[];
} = {}): string {
  return renderToStaticMarkup(createElement(SourceBannerView, {
    mode,
    simulation,
    evidenceProvenance,
    failedEndpoints,
    error: null,
    streamStatus: "connected",
  }));
}

test("renders persistent provenance when live Core data is simulated", () => {
  const html = renderBanner({ simulation: true });
  assert.match(html, /LIVE SIMULATION - NOT HOST PROTECTION/);
  assert.match(html, /Values do not represent protection on this host/);
  assert.match(html, /aria-label="Simulation provenance warning"/);
  assert.doesNotMatch(html, /LIVE CORE/);
});

test("keeps simulation provenance when live projections are partial", () => {
  const html = renderBanner({ mode: "partial", simulation: true, failedEndpoints: ["/v1/paths", "/v1/findings"] });
  assert.match(html, /2 projections are unavailable/);
  assert.match(html, /not represent protection on this host/);
  assert.doesNotMatch(html, /PARTIAL LIVE/);
});

test("does not infer simulation provenance when Core omits it", () => {
  assert.match(renderBanner({ simulation: null }), /UNVERIFIED EVIDENCE SOURCE/);
  assert.match(renderBanner({ simulation: false, evidenceProvenance: "LIVE" }), /LIVE CORE/);
  assert.match(renderBanner({ simulation: false, evidenceProvenance: "SIMULATION" }), /LIVE SIMULATION/);
  assert.doesNotMatch(renderBanner({ mode: "demo", simulation: true }), /LIVE SIMULATION/);
});
