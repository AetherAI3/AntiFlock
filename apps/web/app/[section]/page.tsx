import type { Metadata } from "next";
import { notFound } from "next/navigation";
import type { DashboardSection } from "../../src/api/contracts";
import { SectionView } from "../../src/features/section-view";

const SECTIONS: DashboardSection[] = [
  "overview",
  "network",
  "path",
  "activity",
  "findings",
  "devices",
  "policies",
  "actions",
  "field",
  "intelligence",
  "footprint",
  "scrambler",
  "settings",
];

const TITLES: Record<DashboardSection, string> = {
  overview: "Overview",
  network: "Network",
  path: "Path",
  activity: "Activity",
  findings: "Findings",
  devices: "Devices",
  policies: "Policies",
  actions: "Actions",
  field: "Field Intelligence",
  intelligence: "Field Intelligence",
  footprint: "Footprint",
  scrambler: "Scrambler",
  settings: "Settings",
};

function isSection(value: string): value is DashboardSection {
  return SECTIONS.includes(value as DashboardSection);
}

export async function generateMetadata({ params }: { params: Promise<{ section: string }> }): Promise<Metadata> {
  const { section } = await params;
  return isSection(section) ? { title: TITLES[section] } : {};
}

export default async function DashboardSectionPage({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  if (!isSection(section)) notFound();
  return <SectionView section={section} />;
}
