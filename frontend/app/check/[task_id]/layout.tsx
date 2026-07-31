/**
 * Check page layout — sets noindex, nofollow for all check result pages.
 *
 * Report pages must never be indexed by search engines.
 */

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VibeCheck — 检测结果",
  description: "项目上线体检结果",
  robots: {
    index: false,
    follow: false,
  },
};

export default function CheckLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
