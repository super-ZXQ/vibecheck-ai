/**
 * LLM settings — per-user LLM configuration for AI analysis.
 *
 * Credentials are stored in this browser's localStorage ONLY and sent to
 * the backend as X-LLM-* headers on detection submission. The backend
 * uses them in process memory for the LLM analysis stage and never
 * persists, logs, or returns them.
 */

"use client";

import { useEffect, useRef, useState } from "react";

import {
  clearLLMConfig,
  getLLMConfig,
  hasLLMConfig,
  saveLLMConfig,
  type LLMConfig,
} from "@/lib/llm-config";

export function LLMSettings() {
  const [open, setOpen] = useState(false);
  const [configured, setConfigured] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const config = getLLMConfig();
    setConfigured(hasLLMConfig(config));
  }, []);

  const openDialog = () => {
    const config = getLLMConfig();
    setApiKey(config.apiKey);
    setBaseUrl(config.baseUrl);
    setModel(config.model);
    setOpen(true);
  };

  const closeDialog = () => {
    setOpen(false);
  };

  const handleSave = () => {
    const config: LLMConfig = {
      apiKey: apiKey.trim(),
      baseUrl: baseUrl.trim(),
      model: model.trim(),
    };
    saveLLMConfig(config);
    setConfigured(hasLLMConfig(config));
    setOpen(false);
  };

  const handleClear = () => {
    clearLLMConfig();
    setApiKey("");
    setBaseUrl("");
    setModel("");
    setConfigured(false);
    setOpen(false);
  };

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeDialog();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <>
      <button
        type="button"
        className={`llm-settings-button${configured ? " llm-settings-button-configured" : ""}`}
        onClick={openDialog}
        aria-label="LLM 设置"
      >
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M12 15.5a3.5 3.5 0 100-7 3.5 3.5 0 000 7z"
            stroke="currentColor"
            strokeWidth="1.8"
          />
          <path
            d="M19.4 15a1.7 1.7 0 00.34 1.87l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.7 1.7 0 00-1.87-.34 1.7 1.7 0 00-1.03 1.56V21a2 2 0 11-4 0v-.09a1.7 1.7 0 00-1.11-1.56 1.7 1.7 0 00-1.87.34l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.7 1.7 0 004.6 15a1.7 1.7 0 00-1.56-1.03H3a2 2 0 110-4h.09A1.7 1.7 0 004.6 8.89a1.7 1.7 0 00-.34-1.87l-.06-.06a2 2 0 112.83-2.83l.06.06a1.7 1.7 0 001.87.34h.01A1.7 1.7 0 0010 2.97V3a2 2 0 114 0v.09a1.7 1.7 0 001.03 1.56 1.7 1.7 0 001.87-.34l.06-.06a2 2 0 112.83 2.83l-.06.06a1.7 1.7 0 00-.34 1.87v.01a1.7 1.7 0 001.56 1.03H21a2 2 0 110 4h-.09a1.7 1.7 0 00-1.56 1.03z"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
        设置
      </button>

      {open && (
        <div className="modal-backdrop" onClick={closeDialog}>
          <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-label="LLM 设置"
            className="modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-title">LLM 设置</div>
            <p className="modal-hint">
              使用你自己的 LLM 凭据生成 AI 分析。凭据仅保存在当前浏览器本地，随检测请求以
              X-LLM-* 请求头发送给 VibeCheck 后端，仅在内存中用于本次检测，不会落库、不会记录日志。
              未填写完整（Key + 地址 + 模型）时将使用服务端默认配置或模板。
            </p>
            <label className="modal-field">
              <span>API Key</span>
              <input
                type="password"
                className="input-field"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-..."
                autoComplete="off"
                aria-label="API Key"
              />
            </label>
            <label className="modal-field">
              <span>Base URL</span>
              <input
                type="text"
                className="input-field"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://api.openai.com/v1/chat/completions"
                autoComplete="off"
                aria-label="Base URL"
              />
            </label>
            <label className="modal-field">
              <span>模型</span>
              <input
                type="text"
                className="input-field"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="gpt-4o-mini"
                autoComplete="off"
                aria-label="模型"
              />
            </label>
            <div className="modal-actions">
              {configured && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleClear}
                >
                  清除
                </button>
              )}
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={closeDialog}
              >
                取消
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={handleSave}
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
