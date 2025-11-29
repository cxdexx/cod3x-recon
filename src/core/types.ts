// src/core/types.ts
/**
 * Type definitions for COD3X:RECON
 */

/**
 * Application configuration
 */
export interface AppConfig {
  domain: string;
  concurrency: number;
  timeout: number;
  format: 'text' | 'json' | 'sarif';
  export?: string;
  runNuclei: boolean;
  plugins: string[];
  quiet: boolean;
}

/**
 * Subdomain enumeration result
 */
export interface SubdomainResult {
  hostname: string;
  source: 'crt.sh' | 'dns' | 'wordlist';
  resolvedIPs: string[];
  timestamp: Date;
}

/**
 * HTTP probe result
 *
 * NOTE: headers may be single string or an array of strings (multiple header occurrences).
 * Mark as optional entries to avoid unsafe indexing issues.
 */
export interface ProbeResult {
  hostname: string;
  ip: string;
  protocol: 'http' | 'https';
  port: number;
  statusCode: number;
  statusText: string;
  headers: Record<string, string | string[] | undefined>;
  contentLength: number;
  title?: string;
  redirectChain: string[];
  tls?: TLSInfo;
  endpoints: EndpointCheck[];
  responseTime: number;
  timestamp: Date;
}

/**
 * TLS certificate information
 */
export interface TLSInfo {
  validationError?: string; // Now optional to accommodate error handling flow
  version?: string; // Now optional (resolves 'undefined is not assignable to string')
  cipher?: string; // Now optional (resolves 'undefined is not assignable to string')
  cipherVersion?: string;
  validFrom?: Date; // Now optional (resolves 'undefined is not assignable to Date')
  validTo?: Date; // Now optional (resolves 'undefined is not assignable to Date')
  issuer?: string;
  subject?: string;
  altNames: string[];
  ja3Lite?: string;
}

/**
 * Endpoint check result
 */
export interface EndpointCheck {
  path: string;
  statusCode: number;
  exists: boolean;
  notes?: string;
}

export interface Cod3xPlugin {
  name: string;
  version?: string; // FIX: Reverted to optional as the mandatory fix did not resolve external assignment issue.
  description?: string;
  // FIX: Replaced 'any' with 'unknown' for type safety when the exact context shape is not guaranteed.
  run: (context: unknown) => Promise<void>;
  // FIX: Replaced the unsafe generic 'Function' type with a more specific function signature.
  hooks?: Record<string, (data: unknown) => Promise<void> | void>;
}

/**
 * Classification result
 */
export interface ClassifiedResult extends ProbeResult {
  categories: string[];
  riskScore: number;
  notes: string;
}

/**
 * Plugin interface
 */
export interface Plugin {
  name: string;
  version: string;
  hooks: PluginHooks;
}

/**
 * Plugin lifecycle hooks
 */
export interface PluginHooks {
  onSubdomainFound?: (subdomain: SubdomainResult) => Promise<void> | void;
  onProbeResult?: (result: ProbeResult) => Promise<void> | void;
  onClassify?: (result: ProbeResult) => ClassificationHint | null;
  onComplete?: (results: ScanResults) => Promise<void> | void;
}

/**
 * Classification hint from plugins
 */
export interface ClassificationHint {
  categories: string[];
  riskScore: number;
  notes: string;
}

/**
 * Complete scan results
 */
export interface ScanResults {
  domain: string;
  subdomains: SubdomainResult[];
  probeResults: ProbeResult[];
  classifiedResults: ClassifiedResult[];
  nucleiResults?: NucleiResult[];
  metadata: ScanMetadata;
}

/**
 * Scan metadata
 */
export interface ScanMetadata {
  startTime: Date;
  endTime: Date;
  duration: number;
  subdomainsFound: number;
  liveHosts: number;
  highRiskFindings: number;
}

/**
 * Nuclei scan result
 */
export interface NucleiResult {
  templateId: string;
  templateName: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  host: string;
  matchedAt: string;
  extractedResults: string[];
  timestamp: Date;
}

/**
 * Cache entry
 */
export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

/**
 * Logger levels
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
