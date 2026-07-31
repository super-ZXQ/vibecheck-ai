/**
 * Home page — URL submission form.
 *
 * On submit: calls submitCheck, redirects to /check/{task_id}.
 * Errors are displayed via ErrorState with fixed safe messages.
 */

"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { ErrorState } from "@/components/ErrorState";
import {
  ApiConfigError,
  ApiHttpError,
  ApiNetworkError,
  submitCheck,
} from "@/lib/api";
import {
  CONFIG_ERROR_MESSAGE,
  getErrorMessage,
  NETWORK_ERROR_MESSAGE,
} from "@/lib/error-messages";

export default function Home() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = repoUrl.trim();
    if (!trimmed || loading) return;

    setLoading(true);
    setError(null);

    try {
      const response = await submitCheck(trimmed);
      // Redirect to check page — polling happens there
      router.push(`/check/${response.task_id}`);
    } catch (err) {
      if (err instanceof ApiConfigError) {
        setError(CONFIG_ERROR_MESSAGE);
      } else if (err instanceof ApiHttpError) {
        setError(getErrorMessage(err.errorCode));
      } else if (err instanceof ApiNetworkError) {
        setError(NETWORK_ERROR_MESSAGE);
      } else {
        setError(getErrorMessage(null));
      }
      setLoading(false);
    }
  };

  return (
    <main className="container">
      <h1 className="page-title">VibeCheck</h1>
      <p className="page-subtitle">
        项目上线体检工具 — 输入公开 GitHub 仓库地址，检查项目是否适合上线。
      </p>

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

      {error && <ErrorState message={error} />}
    </main>
  );
}
