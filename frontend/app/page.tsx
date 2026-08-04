/**
 * Home page — URL submission form + recent check history.
 *
 * On submit: calls submitCheck, redirects to /check/{task_id}.
 * Errors are displayed via ErrorState with fixed safe messages.
 * History is read from localStorage (non-sensitive metadata only).
 */

"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { ErrorState } from "@/components/ErrorState";
import {
  ApiConfigError,
  ApiHttpError,
  ApiNetworkError,
  ApiRequestTimeoutError,
  submitCheck,
  submitUpload,
  type UploadMode,
} from "@/lib/api";
import {
  CONFIG_ERROR_MESSAGE,
  getErrorMessage,
  NETWORK_ERROR_MESSAGE,
} from "@/lib/error-messages";
import { clearHistory, getHistory, type HistoryEntry } from "@/lib/history";
import { normalizeGitHubRepoUrl } from "@/lib/repository-url.mjs";

// Upload convenience pre-check (the backend enforces authoritative caps).
const UPLOAD_SINGLE_FILE_LIMIT = 25 * 1024 * 1024;
const UPLOAD_TOTAL_LIMIT = 200 * 1024 * 1024;
const UPLOAD_FILE_COUNT_LIMIT = 2000;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function scoreClass(score: number | null): string {
  if (score === null) return "history-score history-score-none";
  if (score >= 75) return "history-score history-score-pass";
  if (score >= 50) return "history-score history-score-warning";
  return "history-score history-score-blocked";
}

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const diffMs = Date.now() - date.getTime();
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} 天前`;
  return date.toLocaleDateString("zh-CN");
}

function avatarText(owner: string, repoName: string): string {
  if (owner) return owner.slice(0, 1).toUpperCase();
  return repoName.slice(0, 1).toUpperCase() || "R";
}

function FeaturePill({ children }: { children: React.ReactNode }) {
  return (
    <span className="feature-pill">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2.4" />
        <path
          d="M8.5 12.2l2.4 2.4 4.6-5"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
      </svg>
      {children}
    </span>
  );
}

const EXAMPLE_REPOS = [
  { owner: "super-ZXQ", repo: "vibecheck-ai", url: "https://github.com/super-ZXQ/vibecheck-ai" },
  { owner: "expressjs", repo: "express", url: "https://github.com/expressjs/express" },
  { owner: "pallets", repo: "flask", url: "https://github.com/pallets/flask" },
];

function HistoryList({
  entries,
  onClear,
}: {
  entries: HistoryEntry[];
  onClear: () => void;
}) {
  if (entries.length === 0) return null;
  return (
    <section className="history-section">
      <div className="history-header">
        <h2 className="history-title">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M12 8v4l2.5 2.5M12 3a9 9 0 100 18 9 9 0 000-18z"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          最近检测
        </h2>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onClear}>
          清空历史
        </button>
      </div>
      <ul className="history-list">
        {entries.map((entry) => (
          <li key={entry.task_id}>
            <Link href={`/check/${entry.task_id}`} className="history-item">
              <span className="history-avatar">
                {avatarText(entry.owner, entry.repo_name)}
              </span>
              <span className="history-repo">
                <span className="history-repo-name">
                  {entry.owner}/{entry.repo_name}
                </span>
                <span className="history-repo-url">{entry.repo_url}</span>
              </span>
              {entry.status === "failed" ? (
                <span className="history-status-chip history-status-failed">
                  检测失败
                </span>
              ) : (
                <span className={scoreClass(entry.security_score)}>
                  {entry.security_score !== null ? entry.security_score : "—"}
                </span>
              )}
              <span className="history-time">{formatTime(entry.created_at)}</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function Home() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
  const [folderFiles, setFolderFiles] = useState<File[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  useEffect(() => {
    setHistory(getHistory());
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const normalized = normalizeGitHubRepoUrl(repoUrl);
    if (!normalized || loading) return;

    setLoading(true);
    setError(null);
    setRepoUrl(normalized);

    try {
      const response = await submitCheck(normalized);
      // Redirect to check page — polling happens there
      router.push(`/check/${response.task_id}`);
    } catch (err) {
      if (err instanceof ApiConfigError) {
        setError(CONFIG_ERROR_MESSAGE);
      } else if (err instanceof ApiHttpError) {
        setError(getErrorMessage(err.errorCode));
      } else if (
        err instanceof ApiNetworkError ||
        err instanceof ApiRequestTimeoutError
      ) {
        setError(NETWORK_ERROR_MESSAGE);
      } else {
        setError(getErrorMessage(null));
      }
      setLoading(false);
    }
  };

  const handleArchivePick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files?.[0] ?? null;
    setArchiveFile(picked);
    setFolderFiles([]);
    setUploadError(null);
  };

  const handleFolderPick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = e.target.files ? Array.from(e.target.files) : [];
    setFolderFiles(picked);
    setArchiveFile(null);
    setUploadError(null);
  };

  const handleUpload = async () => {
    const mode: UploadMode = archiveFile ? "archive" : "folder";
    const files = archiveFile ? [archiveFile] : folderFiles;
    if (!files.length || uploading) return;

    // Convenience pre-checks — the backend caps are authoritative.
    const total = files.reduce((sum, f) => sum + f.size, 0);
    if (files.some((f) => f.size > UPLOAD_SINGLE_FILE_LIMIT)) {
      setUploadError("单个文件不能超过 25MB，请压缩或拆分后重试。");
      return;
    }
    if (total > UPLOAD_TOTAL_LIMIT) {
      setUploadError("上传内容总量不能超过 200MB，请精简后重试。");
      return;
    }
    if (files.length > UPLOAD_FILE_COUNT_LIMIT) {
      setUploadError("文件数量不能超过 2000 个，请精简后重试。");
      return;
    }

    setUploading(true);
    setUploadError(null);

    try {
      const response = await submitUpload(mode, files);
      router.push(`/check/${response.task_id}`);
    } catch (err) {
      if (err instanceof ApiConfigError) {
        setUploadError(CONFIG_ERROR_MESSAGE);
      } else if (err instanceof ApiHttpError) {
        setUploadError(getErrorMessage(err.errorCode));
      } else if (
        err instanceof ApiNetworkError ||
        err instanceof ApiRequestTimeoutError
      ) {
        setUploadError(NETWORK_ERROR_MESSAGE);
      } else {
        setUploadError(getErrorMessage(null));
      }
      setUploading(false);
    }
  };

  const handleClearHistory = () => {
    clearHistory();
    setHistory([]);
  };

  const applyExample = (url: string) => {
    setRepoUrl(url);
    setError(null);
  };

  return (
    <main className="container">
      <section className="hero">
        <h1 className="page-title">VibeCheck</h1>
        <p className="page-subtitle">
          项目上线体检工具 — 输入公开 GitHub 仓库地址，检查项目是否适合上线。
        </p>

        <div className="hero-badge-row">
          <FeaturePill>安全下载</FeaturePill>
          <FeaturePill>敏感信息扫描</FeaturePill>
          <FeaturePill>上线评分</FeaturePill>
          <FeaturePill>AI 分析</FeaturePill>
        </div>

        <div className="hero-form-card">
          <form onSubmit={handleSubmit}>
            <div className="input-group">
              <input
                type="text"
                className="input-field"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                disabled={loading}
                aria-label="GitHub 仓库地址"
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading || !repoUrl.trim()}
              >
                {loading ? <span className="spinner" /> : "开始检测"}
              </button>
            </div>
          </form>
        </div>

        <div className="upload-card">
          <div className="upload-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 16V4m0 0l-4 4m4-4l4 4M4 20h16"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            或上传本地文件检测
          </div>
          <p className="upload-hint">
            支持 .zip / .tar.gz 压缩包或本地文件夹（单文件 ≤25MB，总量 ≤200MB，最多 2000 个文件）
          </p>
          <div className="upload-options">
            <label className="upload-option">
              <span className="upload-option-label">压缩包</span>
              <input
                type="file"
                accept=".zip,.tar.gz,.tgz"
                onChange={handleArchivePick}
                disabled={uploading}
                aria-label="上传压缩包"
              />
            </label>
            <label className="upload-option">
              <span className="upload-option-label">文件夹</span>
              <input
                type="file"
                {...({ webkitdirectory: "", multiple: true } as React.InputHTMLAttributes<HTMLInputElement>)}
                onChange={handleFolderPick}
                disabled={uploading}
                aria-label="上传文件夹"
              />
            </label>
          </div>
          <div className="upload-selection" aria-live="polite">
            {archiveFile
              ? `已选择压缩包：${archiveFile.name}（${formatBytes(archiveFile.size)}）`
              : folderFiles.length > 0
                ? `已选择文件夹：${folderFiles.length} 个文件（${formatBytes(
                    folderFiles.reduce((sum, f) => sum + f.size, 0),
                  )}）`
                : ""}
          </div>
          <div className="upload-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={
                uploading || (!archiveFile && folderFiles.length === 0)
              }
              onClick={handleUpload}
            >
              {uploading ? <span className="spinner" /> : "上传检测"}
            </button>
          </div>
          {uploadError && <ErrorState message={uploadError} />}
        </div>

        <div className="example-chips" aria-label="示例仓库">
          <span className="example-chips-label">试试：</span>
          {EXAMPLE_REPOS.map((repo) => (
            <button
              key={repo.url}
              type="button"
              className="example-chip"
              onClick={() => applyExample(repo.url)}
              disabled={loading}
            >
              {repo.owner}/{repo.repo}
            </button>
          ))}
        </div>
      </section>

      {error && <ErrorState message={error} />}

      <HistoryList entries={history} onClear={handleClearHistory} />
    </main>
  );
}
