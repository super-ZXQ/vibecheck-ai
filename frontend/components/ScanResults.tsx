/**
 * ScanResults — findings table with pagination + collapsible sections.
 *
 * Pagination:
 * - Default 25 items per page, switchable to 50.
 * - Client-side pagination (no virtual scrolling dependency).
 *
 * Collapsible sections:
 * - notices, skipped_files, scan_errors
 * - Each shows count; empty arrays show empty state.
 *
 * All data is already desensitized by the backend.
 */

"use client";

import { useState } from "react";

import type { ScanResult } from "@/lib/types";

interface ScanResultsProps {
  scanResult: ScanResult;
}

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
  info: "severity-info",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
  info: "信息",
};

export function ScanResults({ scanResult }: ScanResultsProps) {
  const [pageSize, setPageSize] = useState<number>(25);
  const [currentPage, setCurrentPage] = useState<number>(0);

  const findings = scanResult.findings;
  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const safePage = Math.min(currentPage, totalPages - 1);
  const startIndex = safePage * pageSize;
  const endIndex = Math.min(startIndex + pageSize, findings.length);
  const pageFindings = findings.slice(startIndex, endIndex);

  return (
    <div>
      {/* --- Findings --- */}
      <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
        发现问题 ({findings.length})
      </h3>

      {findings.length === 0 ? (
        <div className="empty-state">未发现敏感信息问题。</div>
      ) : (
        <>
          <table className="findings-table">
            <thead>
              <tr>
                <th>严重程度</th>
                <th>规则</th>
                <th>文件</th>
                <th>行号</th>
                <th>代码片段</th>
                <th>阻断</th>
              </tr>
            </thead>
            <tbody>
              {pageFindings.map((f, i) => (
                <tr key={`${f.rule_id}-${startIndex + i}`}>
                  <td>
                    <span
                      className={`severity-badge ${
                        SEVERITY_CLASSES[f.severity] ?? "severity-info"
                      }`}
                    >
                      {SEVERITY_LABELS[f.severity] ?? f.severity}
                    </span>
                  </td>
                  <td>{f.rule_name}</td>
                  <td
                    style={{
                      maxWidth: "200px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={f.file_path}
                  >
                    {f.file_path}
                  </td>
                  <td>
                    {f.line_start}
                    {f.line_end !== f.line_start ? `-${f.line_end}` : ""}
                  </td>
                  <td
                    style={{
                      maxWidth: "300px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      fontFamily: "monospace",
                      fontSize: "0.8rem",
                    }}
                    title={f.snippet_masked}
                  >
                    {f.snippet_masked}
                  </td>
                  <td>
                    {f.is_blocking ? (
                      <span className="severity-badge severity-critical">
                        是
                      </span>
                    ) : (
                      <span style={{ color: "#94a3b8" }}>否</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="pagination">
            <div>
              <span style={{ fontSize: "0.85rem", color: "#64748b" }}>
                第 {startIndex + 1}-{endIndex} 条 / 共 {findings.length} 条
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <select
                className="page-size-select"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setCurrentPage(0);
                }}
              >
                <option value={25}>25 条/页</option>
                <option value={50}>50 条/页</option>
              </select>
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 12px", fontSize: "0.85rem" }}
                disabled={safePage === 0}
                onClick={() => setCurrentPage(safePage - 1)}
              >
                上一页
              </button>
              <span style={{ fontSize: "0.85rem", color: "#64748b" }}>
                {safePage + 1} / {totalPages}
              </span>
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 12px", fontSize: "0.85rem" }}
                disabled={safePage >= totalPages - 1}
                onClick={() => setCurrentPage(safePage + 1)}
              >
                下一页
              </button>
            </div>
          </div>
        </>
      )}

      {/* --- Collapsible: Notices --- */}
      <CollapsibleSection
        title="扫描提示"
        items={scanResult.notices}
        renderItem={(n, i) => (
          <div key={i} style={{ marginBottom: "0.5rem", fontSize: "0.875rem" }}>
            <strong>{n.rule_id}</strong>
            {n.file_path && <span style={{ color: "#64748b" }}> ({n.file_path})</span>}
            : {n.message}
          </div>
        )}
        emptyMessage="无扫描提示。"
      />

      {/* --- Collapsible: Skipped Files --- */}
      <CollapsibleSection
        title="跳过文件"
        items={scanResult.skipped_files}
        renderItem={(s, i) => (
          <div key={i} style={{ marginBottom: "0.25rem", fontSize: "0.875rem" }}>
            <code>{s.file_path}</code>
            <span style={{ color: "#64748b" }}> — {s.reason}</span>
          </div>
        )}
        emptyMessage="无跳过文件。"
      />

      {/* --- Collapsible: Scan Errors --- */}
      <CollapsibleSection
        title="扫描错误"
        items={scanResult.scan_errors}
        renderItem={(e, i) => (
          <div key={i} style={{ marginBottom: "0.25rem", fontSize: "0.875rem" }}>
            <code>{e.file_path}</code>
            <span style={{ color: "#991b1b" }}> — {e.error_type}: {e.error_message}</span>
          </div>
        )}
        emptyMessage="无扫描错误。"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collapsible section helper
// ---------------------------------------------------------------------------

interface CollapsibleSectionProps<T> {
  title: string;
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
  emptyMessage: string;
}

function CollapsibleSection<T>({
  title,
  items,
  renderItem,
  emptyMessage,
}: CollapsibleSectionProps<T>) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{ marginTop: "1.5rem" }}>
      <div
        className="collapsible-trigger"
        onClick={() => setExpanded(!expanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
      >
        <span>{expanded ? "▼" : "▶"}</span>
        <span>{title} ({items.length})</span>
      </div>
      {expanded && (
        <div className="collapsible-content">
          {items.length === 0 ? (
            <div className="empty-state">{emptyMessage}</div>
          ) : (
            items.map(renderItem)
          )}
        </div>
      )}
    </div>
  );
}
