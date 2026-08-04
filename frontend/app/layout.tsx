import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeCheck",
  description: "项目上线体检工具 — 面向 Vibe Coding 与 AI 编程初学者",
};

function BrandLogo() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 3l7 4v5c0 4.5-3 8.5-7 9.5-4-1-7-5-7-9.5V7l7-4z"
        fill="currentColor"
        opacity="0.95"
      />
      <path
        d="M9.2 12.4l2 2 3.6-3.8"
        stroke="#fff"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

function BackgroundScene() {
  return (
    <div className="bg-scene" aria-hidden="true">
      <div className="bg-blob bg-blob-1" />
      <div className="bg-blob bg-blob-2" />
      <div className="bg-blob bg-blob-3" />
    </div>
  );
}

function TopBar() {
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand">
          <span className="brand-logo">
            <BrandLogo />
          </span>
          <span className="brand-name">VibeCheck</span>
          <span className="brand-tag">项目上线体检工具</span>
        </Link>
        <div className="topbar-right">
          <span className="topbar-chip">
            <span className="dot" />
            公开仓库 · 零安装
          </span>
        </div>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="app-footer">
      <div className="footer-inner">
        <div>
          <span className="brand-name">VibeCheck</span> · 面向 Vibe Coding 与 AI
          编程初学者的上线体检工具
        </div>
        <div className="footer-dots">· · ·</div>
        <div>代码仅本地规则 + 脱敏分析，敏感信息不离开服务端隔离目录</div>
      </div>
    </footer>
  );
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN">
      <body>
        <BackgroundScene />
        <TopBar />
        {children}
        <Footer />
      </body>
    </html>
  );
}
