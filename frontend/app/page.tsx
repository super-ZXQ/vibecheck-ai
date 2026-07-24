export default function Home() {
  return (
    <main style={{ maxWidth: 640, margin: "80px auto", padding: "0 24px" }}>
      <h1 style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>VibeCheck</h1>
      <p style={{ color: "#666", marginBottom: "2rem" }}>
        项目上线体检工具 — 输入公开 GitHub 仓库地址，检查项目是否适合上线。
      </p>
      <div style={{ display: "flex", gap: "8px" }}>
        <input
          type="text"
          placeholder="https://github.com/owner/repo"
          style={{
            flex: 1,
            padding: "12px 16px",
            borderRadius: 8,
            border: "1px solid #ddd",
            fontSize: "1rem",
          }}
        />
        <button
          style={{
            padding: "12px 24px",
            borderRadius: 8,
            border: "none",
            background: "#6366f1",
            color: "#fff",
            fontSize: "1rem",
            cursor: "pointer",
          }}
        >
          开始检测
        </button>
      </div>
    </main>
  );
}
