/**
 * ScanResults — dimension summary, filtered findings, and collapsible details.
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

import { Fragment, useState } from "react";

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

const SENSITIVE_DIMENSION = "sensitive_data_security";
const INCOMPLETE_DIMENSION = "incomplete_content";
const DEPLOYABILITY_DIMENSION = "deployability_production";
const BASIC_SECURITY_DIMENSION = "basic_security";
const DOCUMENTATION_DIMENSION = "documentation_consistency";

type FindingFilter =
  | "all"
  | typeof SENSITIVE_DIMENSION
  | typeof INCOMPLETE_DIMENSION
  | typeof DEPLOYABILITY_DIMENSION
  | typeof BASIC_SECURITY_DIMENSION
  | typeof DOCUMENTATION_DIMENSION;

function findingDimension(dimension: string | undefined) {
  return dimension ?? SENSITIVE_DIMENSION;
}

function dimensionLabel(dimension: string) {
  if (dimension === INCOMPLETE_DIMENSION) return "未完成内容";
  if (dimension === DEPLOYABILITY_DIMENSION) return "可部署性";
  if (dimension === BASIC_SECURITY_DIMENSION) return "基础安全";
  if (dimension === DOCUMENTATION_DIMENSION) return "文档一致性";
  return "敏感信息";
}

export function ScanResults({ scanResult }: ScanResultsProps) {
  const [pageSize, setPageSize] = useState<number>(25);
  const [currentPage, setCurrentPage] = useState<number>(0);
  const [filter, setFilter] = useState<FindingFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const findings = scanResult.findings;
  const counts = scanResult.summary.dimension_counts;
  const sensitiveCount = counts?.sensitive_data_security
    ?? findings.filter((finding) => findingDimension(finding.dimension) === SENSITIVE_DIMENSION).length;
  const incompleteCount = counts?.incomplete_content
    ?? findings.filter((finding) => findingDimension(finding.dimension) === INCOMPLETE_DIMENSION).length;
  const deployabilityCount = counts?.deployability_production
    ?? findings.filter((finding) => findingDimension(finding.dimension) === DEPLOYABILITY_DIMENSION).length;
  const basicSecurityCount = counts?.basic_security
    ?? findings.filter((finding) => findingDimension(finding.dimension) === BASIC_SECURITY_DIMENSION).length;
  const documentationCount = counts?.documentation_consistency
    ?? findings.filter((finding) => findingDimension(finding.dimension) === DOCUMENTATION_DIMENSION).length;

  const query = searchQuery.trim().toLowerCase();
  const filteredFindings = findings.filter((finding) => {
    if (filter !== "all" && findingDimension(finding.dimension) !== filter) {
      return false;
    }
    if (severityFilter !== "all" && finding.severity !== severityFilter) {
      return false;
    }
    if (
      query !== "" &&
      !finding.file_path.toLowerCase().includes(query) &&
      !finding.rule_name.toLowerCase().includes(query)
    ) {
      return false;
    }
    return true;
  });
  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
  const safePage = Math.min(currentPage, totalPages - 1);
  const startIndex = safePage * pageSize;
  const endIndex = Math.min(startIndex + pageSize, filteredFindings.length);
  const pageFindings = filteredFindings.slice(startIndex, endIndex);

  const resetView = () => {
    setCurrentPage(0);
    setExpandedFinding(null);
  };

  const selectFilter = (nextFilter: FindingFilter) => {
    setFilter(nextFilter);
    resetView();
  };

  const selectSeverity = (nextSeverity: string) => {
    setSeverityFilter(nextSeverity);
    resetView();
  };

  const updateSearch = (nextQuery: string) => {
    setSearchQuery(nextQuery);
    resetView();
  };

  return (
    <div>
      <div className="dimension-summary" aria-label="扫描维度摘要">
        <div className="dimension-card" data-testid="sensitive-dimension-count">
          <span>敏感信息安全</span>
          <strong>{sensitiveCount}</strong>
        </div>
        <div className="dimension-card" data-testid="incomplete-dimension-count">
          <span>未完成内容</span>
          <strong>{incompleteCount}</strong>
        </div>
        <div className="dimension-card" data-testid="deployability-dimension-count">
          <span>可部署性与生产配置</span>
          <strong>{deployabilityCount}</strong>
        </div>
        <div className="dimension-card" data-testid="basic-security-dimension-count">
          <span>基础安全</span>
          <strong>{basicSecurityCount}</strong>
        </div>
        <div className="dimension-card" data-testid="documentation-dimension-count">
          <span>文档一致性</span>
          <strong>{documentationCount}</strong>
        </div>
      </div>
      <p className="dimension-score-notice">
        未完成内容、可部署性、基础安全和文档一致性暂不计入安全评分。
      </p>

      {/* --- Findings --- */}
      <h3 style={{ fontSize: "1.1rem", marginBottom: "0.75rem" }}>
        发现问题 ({findings.length})
      </h3>

      <div className="dimension-filters" aria-label="按扫描维度筛选">
        {([
          ["all", "全部"],
          [SENSITIVE_DIMENSION, "敏感信息"],
          [INCOMPLETE_DIMENSION, "未完成内容"],
          [DEPLOYABILITY_DIMENSION, "可部署性"],
          [BASIC_SECURITY_DIMENSION, "基础安全"],
          [DOCUMENTATION_DIMENSION, "文档一致性"],
        ] as const).map(([value, label]) => (
          <button
            key={value}
            type="button"
            className={`dimension-filter${filter === value ? " dimension-filter-active" : ""}`}
            aria-pressed={filter === value}
            onClick={() => selectFilter(value)}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <select
          className="filter-select"
          value={severityFilter}
          onChange={(e) => selectSeverity(e.target.value)}
          aria-label="按严重级别筛选"
        >
          <option value="all">全部级别</option>
          <option value="critical">严重</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
          <option value="info">信息</option>
        </select>
        <input
          type="search"
          className="filter-search"
          placeholder="按文件路径或规则名搜索..."
          value={searchQuery}
          onChange={(e) => updateSearch(e.target.value)}
          aria-label="搜索发现"
        />
        {(severityFilter !== "all" || query !== "") && (
          <span className="filter-count">
            匹配 {filteredFindings.length} / {findings.length} 条
          </span>
        )}
      </div>

      {filteredFindings.length === 0 ? (
        <div className="empty-state">
          {findings.length === 0
            ? "未发现扫描问题。"
            : "当前维度没有发现问题。"}
        </div>
      ) : (
        <>
          <table className="findings-table">
            <thead>
              <tr>
                <th>严重程度</th>
                <th>维度</th>
                <th>规则</th>
                <th>文件</th>
                <th>行号</th>
                <th>代码片段</th>
                <th>阻断</th>
                <th>建议</th>
              </tr>
            </thead>
            <tbody>
              {pageFindings.map((f, i) => {
                const findingKey = `${f.rule_id}-${f.file_path}-${f.line_start}-${startIndex + i}`;
                const isExpanded = expandedFinding === findingKey;
                const dimension = findingDimension(f.dimension);
                return (
                <Fragment key={findingKey}>
                <tr>
                  <td>
                    <span
                      className={`severity-badge ${
                        SEVERITY_CLASSES[f.severity] ?? "severity-info"
                      }`}
                    >
                      {SEVERITY_LABELS[f.severity] ?? f.severity}
                    </span>
                  </td>
                  <td>
                    <span className={`dimension-badge dimension-${dimension}`}>
                      {dimensionLabel(dimension)}
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
                    {f.line_start ?? "-"}
                    {f.line_start !== null && f.line_end !== f.line_start ? `-${f.line_end}` : ""}
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
                  <td>
                    <button
                      type="button"
                      className="finding-detail-button"
                      aria-expanded={isExpanded}
                      onClick={() => setExpandedFinding(isExpanded ? null : findingKey)}
                    >
                      {isExpanded ? "收起建议" : "查看建议"}
                    </button>
                  </td>
                </tr>
                {isExpanded && (
                  <tr className="finding-detail-row">
                    <td colSpan={8}>
                      <strong>说明：</strong>{f.description}
                      <br />
                      <strong>处理建议：</strong>{f.message}
                    </td>
                  </tr>
                )}
                </Fragment>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="pagination">
            <div>
              <span style={{ fontSize: "0.85rem", color: "#64748b" }}>
                第 {startIndex + 1}-{endIndex} 条 / 共 {filteredFindings.length} 条
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
