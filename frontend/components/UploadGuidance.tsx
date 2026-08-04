/**
 * Upload guidance — shown on the failure page when a repository was
 * rejected because it exceeded the download/extraction size limits.
 *
 * Points the user to the local upload channel, which lifts the GitHub
 * download limits (50 MB archive / 200 MB extracted) and supports the
 * same five-dimension check.
 */

"use client";

import Link from "next/link";

const UPLOAD_GUIDANCE_CODES = new Set([
  "DOWNLOAD_TOO_LARGE",
  "EXTRACTION_LIMIT_EXCEEDED",
]);

export function isUploadGuidanceCode(errorCode: string | null | undefined) {
  return errorCode !== null && errorCode !== undefined
    ? UPLOAD_GUIDANCE_CODES.has(errorCode)
    : false;
}

export function UploadGuidance() {
  return (
    <div className="upload-guidance" role="note">
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M12 16V4m0 0l-4 4m4-4l4 4M4 20h16"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <div className="upload-guidance-body">
        <div className="upload-guidance-title">
          该仓库超出下载大小限制
        </div>
        <p className="upload-guidance-text">
          可以改用本地上传：压缩包或文件夹同样支持完整检测，单文件上限 25MB、
          压缩包 50MB、总量 200MB、最多 2000 个文件，且不经过 GitHub 下载。
        </p>
        <Link href="/?upload=1" className="btn btn-primary btn-sm">
          改用本地上传
        </Link>
      </div>
    </div>
  );
}
