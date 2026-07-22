import type { Metadata, Viewport } from "next";
import "./globals.css";
import { DashboardFrame } from "../src/app/dashboard-frame";
import { DashboardProvider } from "../src/state/dashboard-context";

export const metadata: Metadata = {
  title: {
    default: "AntiFlock Third-Eye",
    template: "%s · AntiFlock",
  },
  description: "A private-security command layer for protection posture, paths, evidence, devices, policy, field intelligence, footprint, and Scrambler state.",
  applicationName: "AntiFlock Third-Eye",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark",
  themeColor: "#070b0f",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <DashboardProvider>
          <DashboardFrame>{children}</DashboardFrame>
        </DashboardProvider>
      </body>
    </html>
  );
}
