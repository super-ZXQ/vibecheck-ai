import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VibeCheck",
  description: "项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN">
      <body style={{ margin: 0, fontFamily: "system-ui, -apple-system, sans-serif" }}>
        {children}
      </body>
    </html>
  );
}
