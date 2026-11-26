export interface SigmaLogsource {
  category: string;
  product: string;
  service?: string | null;
}

export interface ExtractedCTI {
  threat_title: string;
  summary: string;
  mitre_attack_tags: string[];
  logsource: SigmaLogsource;
  suspicious_behaviors: string[];
  iocs: string[];
}

export interface ValidationResult {
  is_valid: boolean;
  splunk_spl?: string | null;
  sentinel_kql?: string | null;
  splunk_queries: string[];
  sentinel_queries: string[];
  error?: string | null;
}

export interface RetrievedRuleReference {
  title: string;
  logsource: Record<string, unknown>;
  detection_fields: string[];
  raw_yaml: string;
  score?: number | null;
}

export interface GenerateRequestPayload {
  url?: string;
  raw_text?: string;
  max_retries?: number;
}

export interface GenerateResponsePayload {
  status: "success" | "failed";
  extracted_cti?: ExtractedCTI | null;
  retrieved_rules: RetrievedRuleReference[];
  sigma_yaml?: string | null;
  splunk_spl?: string | null;
  sentinel_kql?: string | null;
  validation?: ValidationResult | null;
  attempts: number;
  error?: string | null;
}

export type WorkflowNodeName =
  | "extract_cti"
  | "rag_grounding"
  | "generate_sigma"
  | "validate_sigma";

export interface StreamProgressEvent {
  node: WorkflowNodeName;
  attempts: number;
  extracted_cti?: ExtractedCTI;
  retrieved_count?: number;
  retrieved_titles?: string[];
  sigma_yaml?: string;
  validation?: ValidationResult;
}
