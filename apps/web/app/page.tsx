import type { Metadata } from "next";
import { SectionView } from "../src/features/section-view";

export const metadata: Metadata = {
  title: "Overview",
};

export default function OverviewPage() {
  return <SectionView section="overview" />;
}
