import type { Metadata } from "next";
import { headers } from "next/headers";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mungard",
  description: "Local-first AI security testing agent. Guard every agent action.",
  robots: { index: false, follow: false },
  icons: { icon: "/logo.jpeg" },
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Reading request headers makes every page dynamically rendered, which the
  // per-request CSP nonce set in proxy.ts requires.
  await headers();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
