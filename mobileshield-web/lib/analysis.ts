/** Schema v1 mirrors app/message_models.py. None of these objects are persisted. */
export type Assessment = 'phishing' | 'suspicious' | 'no_clear_signs' | 'unknown';
export type AnalysisStatus = 'complete' | 'partial' | 'unavailable';
export type ActionCode = 'avoid_interaction' | 'verify_independently' | 'do_not_share_secrets' | 'consider_link_inspection' | 'retry_later';
export type InspectionStatus = 'not_requested' | 'completed' | 'blocked' | 'failed' | 'skipped';
export type ReasonCode = 'credential_request' | 'payment_request' | 'urgency' | 'brand_destination_mismatch' | 'lookalike_host' | 'suspicious_obfuscation' | 'credential_form' | 'payment_form' | 'local_blocklist_hit' | 'certificate_mismatch' | 'unsupported_text' | 'invalid_link' | 'inspection_disabled' | 'inspection_failed' | 'destination_blocked' | 'body_limit' | 'deadline_exceeded' | 'shortened_link' | 'high_abuse_domain_ending' | 'scam_scenario';
export interface MessageRequest { text: string; inspect_links: boolean }
export interface Reason {
  code: string;
  strength: 'info' | 'medium' | 'strong';
  source: 'message' | 'url' | 'inspection';
  link_id: string | null;
  params: Record<string, string>;
}
export interface LinkCandidate { link_id: string; raw: string; canonical_url: string | null; display_host: string | null; parse_error: string | null }
export interface ParsedMessage { text: string; normalized_text: string; links: LinkCandidate[]; supported_text: boolean }
export interface LinkTechnical { normalized_url: string | null; final_url: string | null }
export interface LinkResult {
  link_id: string;
  assessment: Assessment;
  inspection_status: InspectionStatus;
  display_host: string | null;
  reasons: Reason[];
  limitations: string[];
  technical: LinkTechnical | null;
}
export interface AssessmentSummary {
  assessment: Assessment;
  analysis_status: AnalysisStatus;
  reasons: Reason[];
  recommended_actions: ActionCode[];
  limitations: string[];
}
export interface MessageResponse extends AssessmentSummary { schema_version: 1; links: LinkResult[]; request_id: string }
export type AnalysisErrorCode = 'invalid_request' | 'invalid_response' | 'analysis_unavailable' | 'rate_limit_exceeded' | 'request_failed' | 'network_error' | 'timeout' | 'cancelled';

/** Codes are translation keys. Never retain arbitrary response/exception text. */
export class AnalysisError extends Error {
  constructor(public readonly code: AnalysisErrorCode) {
    super(code);
    this.name = 'AnalysisError';
  }
}

export const MAX_TEXT_CODEPOINTS = 10_000;
/** Long enough for a sleeping host to wake up and still finish the 20 s link-inspection budget. */
export const CLIENT_REQUEST_TIMEOUT_MS = 60_000;
const assessments = ['phishing', 'suspicious', 'no_clear_signs', 'unknown'] as const;
const statuses = ['complete', 'partial', 'unavailable'] as const;
const actions = ['avoid_interaction', 'verify_independently', 'do_not_share_secrets', 'consider_link_inspection', 'retry_later'] as const;
const reasonCodes: readonly ReasonCode[] = ['credential_request', 'payment_request', 'urgency', 'brand_destination_mismatch', 'lookalike_host', 'suspicious_obfuscation', 'credential_form', 'payment_form', 'local_blocklist_hit', 'certificate_mismatch', 'unsupported_text', 'invalid_link', 'inspection_disabled', 'inspection_failed', 'destination_blocked', 'body_limit', 'deadline_exceeded', 'shortened_link', 'high_abuse_domain_ending', 'scam_scenario'];
const hostFactCodes = ['suspicious_obfuscation', 'credential_form', 'payment_form', 'local_blocklist_hit', 'certificate_mismatch', 'invalid_link', 'destination_blocked', 'shortened_link', 'high_abuse_domain_ending'];
const brandFactCodes = ['brand_destination_mismatch', 'lookalike_host'];
/** Mirrors app/brand.py KNOWN_BRAND_IDS (checked by tests/test_brand_registry.py). */
const brands = ['amazon', 'amex', 'apple', 'appleid', 'bank', 'bankofamerica', 'beinleumi', 'bezeq', 'binance', 'bit', 'bituachleumi', 'cal', 'capitalone', 'cashapp', 'cellcom', 'chase', 'citibank', 'coinbase', 'dhl', 'discount', 'facebook', 'fedex', 'google', 'hapoalim', 'hot', 'hsbc', 'icloud', 'iec', 'instagram', 'isracard', 'israelpost', 'kvish', 'leumi', 'mastercard', 'max', 'meta', 'microsoft', 'mizrahi', 'netflix', 'office', 'onezero', 'outlook', 'partner', 'paybox', 'paypal', 'pelephone', 'pepper', 'stripe', 'taxauthority', 'telegram', 'usps', 'venmo', 'visa', 'wellsfargo', 'whatsapp'];

function invalid(): never { throw new AnalysisError('invalid_response'); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const result = value as Record<string, unknown>;
  if (Object.keys(result).some(key => !keys.includes(key))) return invalid();
  return result;
}
function boundedString(value: unknown, limit: number): string {
  if (typeof value !== 'string' || !value.length || Array.from(value).length > limit) return invalid();
  return value;
}
function nullableString(value: unknown, limit: number): string | null {
  return value === null || value === undefined ? null : boundedString(value, limit);
}
function enumValue<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) return invalid();
  return value as T;
}
function array<T>(value: unknown, limit: number, parse: (entry: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > limit) return invalid();
  return value.map(parse);
}
function code(value: unknown): string {
  const parsed = boundedString(value, 64);
  return reasonCodes.includes(parsed as ReasonCode) ? parsed : 'unknown_reason';
}
function safeHost(value: string): boolean {
  if (value !== value.toLowerCase() || /[\p{C}\s/@?#%\\\[\]]/u.test(value) || value.endsWith('.')) return false;
  // IPv6 facts have no brackets or zone identifier; URL validates the literal.
  if (value.includes(':')) {
    try { return new URL(`http://[${value}]`).hostname === `[${value}]`; } catch { return false; }
  }
  if (!/^[\p{L}\p{M}\p{N}.-]+$/u.test(value)) return false;
  if (value.split('.').some(label => !label || label.startsWith('-') || label.endsWith('-'))) return false;
  try { return Boolean(new URL(`http://${value}`).hostname); } catch { return false; }
}
function reason(value: unknown): Reason {
  const item = record(value, ['code', 'strength', 'source', 'link_id', 'params']);
  const reasonCode = code(item.code);
  const params = item.params === undefined ? {} : item.params;
  if (!params || typeof params !== 'object' || Array.isArray(params) || Object.keys(params).length > 4) return invalid();
  const allowed = brandFactCodes.includes(reasonCode) ? ['display_host', 'expected_host', 'brand'] : hostFactCodes.includes(reasonCode) ? ['display_host'] : [];
  const facts: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    const fact = boundedString(value, 256);
    if (reasonCode === 'unknown_reason') continue;
    if (!allowed.includes(key) || (key === 'brand' ? !brands.includes(fact) : !safeHost(fact))) return invalid();
    facts[key] = fact;
  }
  return {
    code: reasonCode, strength: enumValue(item.strength, ['info', 'medium', 'strong']),
    source: enumValue(item.source, ['message', 'url', 'inspection']),
    link_id: nullableString(item.link_id, 64), params: facts,
  };
}
function technical(value: unknown): LinkTechnical | null {
  if (value === null || value === undefined) return null;
  const item = record(value, ['normalized_url', 'final_url']);
  // Percent encoding can expand a 10,000-code-point submitted URL by up to 12x.
  return { normalized_url: nullableString(item.normalized_url, 120_000), final_url: nullableString(item.final_url, 120_000) };
}
function link(value: unknown): LinkResult {
  const item = record(value, ['link_id', 'assessment', 'inspection_status', 'display_host', 'reasons', 'limitations', 'technical']);
  const displayHost = nullableString(item.display_host, 256);
  if (displayHost !== null && !safeHost(displayHost)) return invalid();
  return {
    link_id: boundedString(item.link_id, 64), assessment: enumValue(item.assessment, assessments),
    inspection_status: enumValue(item.inspection_status, ['not_requested', 'completed', 'blocked', 'failed', 'skipped']),
    display_host: displayHost, reasons: array(item.reasons, 32, reason),
    limitations: array(item.limitations, 32, code), technical: technical(item.technical),
  };
}

export function parseAnalysisResponse(value: unknown): MessageResponse {
  const item = record(value, ['schema_version', 'assessment', 'analysis_status', 'reasons', 'recommended_actions', 'limitations', 'links', 'request_id']);
  if (item.schema_version !== 1) return invalid();
  const links = array(item.links, 10, link);
  const reasons = array(item.reasons, 32, reason);
  const linkIds = new Set(links.map(item => item.link_id));
  if (linkIds.size !== links.length) return invalid();
  for (const entry of [...reasons, ...links.flatMap(item => item.reasons)]) {
    if (entry.link_id !== null && !linkIds.has(entry.link_id)) return invalid();
  }
  return {
    schema_version: 1, assessment: enumValue(item.assessment, assessments),
    analysis_status: enumValue(item.analysis_status, statuses), reasons,
    recommended_actions: array(item.recommended_actions, actions.length, value => enumValue(value, actions)),
    limitations: array(item.limitations, 32, code), links, request_id: boundedString(item.request_id, 128),
  };
}

export function normalizeLegacyVerdict(value: unknown, analysisStatus: AnalysisStatus): Assessment {
  enumValue(analysisStatus, statuses);
  if (value === 'phishing' || value === 'malicious') return 'phishing';
  if (value === 'suspicious' || value === 'unknown') return value;
  if (value === 'legitimate' || value === 'safe' || value === 'no_clear_signs') {
    return analysisStatus === 'complete' ? 'no_clear_signs' : 'unknown';
  }
  return invalid();
}

export function validateMessageRequest(value: unknown): MessageRequest {
  try {
    const input = record(value, ['text', 'inspect_links']);
    const text = boundedString(input.text, MAX_TEXT_CODEPOINTS);
    // Python str.strip includes NEL/information separators and excludes BOM.
    if (/^[\p{White_Space}\u001c-\u001f]*$/u.test(text) || typeof input.inspect_links !== 'boolean') {
      throw new AnalysisError('invalid_request');
    }
    return { text, inspect_links: input.inspect_links };
  } catch { throw new AnalysisError('invalid_request'); }
}
