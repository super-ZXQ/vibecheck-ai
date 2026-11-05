import type { QualityBlock, QualityItem } from "./types";

export interface QualityStatusMeta {
  label: string;
  className: string;
}

export interface QualityItemGroups {
  fixable: QualityItem[];
  manual: QualityItem[];
  other: QualityItem[];
}

export interface QualityCountsView {
  scalars: Array<[string, string]>;
  nested: Array<[string, Array<[string, string]>]>;
}

export declare function splitQualityItems(
  block: Pick<
    QualityBlock,
    "items" | "fixable_item_ids" | "manual_confirm_item_ids"
  >,
): QualityItemGroups;

export declare function formatQualityCounts(
  counts?: Record<string, number | Record<string, number>>,
): QualityCountsView;

export declare function qualityStatusMeta(status: string): QualityStatusMeta;
