/**
 * src/core/probe.ts
 *
 * HTTP/HTTPS host probing engine — improved:
 * - robust timeouts via AbortController
 * - explicit redirect chain extraction
 * - safer TLS handling (no rejectUnauthorized:false)
 * - best-effort JA3-lite fingerprint (derived from observable TLS properties)
 * - endpoint discovery: common paths + robots.txt + sitemap.xml + trailing slash variants + .php/.asp
 * - endpoint probing parallelized and rate-limited
 * - cache keys include IP to support VHOSTs
 * - no unsafe calls (we don't disable cert validation)
 */

import { request, type Dispatcher } from 'undici';
import pLimit from 'p-limit';
import { connect as tlsConnect } from 'tls';
import { CacheManager } from './cache.js';
import { logger } from '../utils/logger.js';
import type { SubdomainResult, ProbeResult, EndpointCheck, TLSInfo } from './types.js';

const DEFAULT_COMMON_ENDPOINTS = [
  '/',
  '/login',
  '/admin',
  '/api',
  '/status',
  '/health',
  '/.git',
  '/robots.txt',
  '/sitemap.xml',
];

export class HostProber {
  private timeout: number;
  private concurrency: number;
  private endpointConcurrency: number;
  private cache: CacheManager<ProbeResult>;
  private commonEndpoints: string[];

  constructor(
    timeout = 3000,
    concurrency = 10,
    endpointConcurrency = 6,
    commonEndpoints: string[] | undefined = undefined
  ) {
    this.timeout = timeout;
    this.concurrency = concurrency;
    this.endpointConcurrency = endpointConcurrency;
    this.cache = new CacheManager<ProbeResult>(2000, 10 * 60 * 1000); // 10 min TTL
    this.commonEndpoints = commonEndpoints ?? DEFAULT_COMMON_ENDPOINTS;
  }

  /**
   * Probe all hosts (hostname + per-resolved-IP)
   */
  async probeHosts(subdomains: SubdomainResult[]): Promise<ProbeResult[]> {
    logger.info(`Probing ${subdomains.length} hostnames (per-IP)...`);

    const limit = pLimit(this.concurrency);
    const tasks: Promise<ProbeResult | null>[] = [];

    for (const sub of subdomains) {
      for (const ip of sub.resolvedIPs) {
        // Launch HTTPS then HTTP probes (order doesn't matter; both attempted)
        tasks.push(limit(() => this.probeHost(sub.hostname, ip, 'https', 443)));
        tasks.push(limit(() => this.probeHost(sub.hostname, ip, 'http', 80)));
      }
    }

    const settled = await Promise.allSettled(tasks);
    const results: ProbeResult[] = [];

    for (const res of settled) {
      if (res.status === 'fulfilled' && res.value) results.push(res.value);
    }

    logger.info(`Probing finished — successful probes: ${results.length}`);
    return results;
  }

  /**
   * Probe a single host: builds result object, caches, and returns.
   */
  private async probeHost(
    hostname: string,
    ip: string,
    protocol: 'http' | 'https',
    port: number
  ): Promise<ProbeResult | null> {
    const cacheKey = `probe:${protocol}:${hostname}:${ip}:${port}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const start = Date.now();
    try {
      // Perform request while capturing redirect chain (manual follow)
      const maxRedirects = 5;
      const { finalResponse, redirectChain } = await this.fetchWithRedirects({
        hostname,
        ip,
        protocol,
        port,
        maxRedirects,
        timeout: this.timeout,
      });

      if (!finalResponse) {
        // unreachable or timed out
        return null;
      }

      const body = await finalResponse.body.text();
      const responseTime = Date.now() - start;
      const title = this.extractTitle(body);

      let tls: TLSInfo | undefined;
      if (protocol === 'https') {
        tls = await this.extractTLSInfoSafe(hostname, port);
      }

      // Probe endpoints (parallel, rate-limited)
      const endpoints = await this.probeEndpoints(hostname, protocol, port);

      const result: ProbeResult = {
        hostname,
        ip,
        protocol,
        port,
        statusCode: finalResponse.statusCode,
        statusText: String(finalResponse.statusCode),
        headers: this.normalizeHeaders(finalResponse.headers as Record<string, string | string[]>),
        contentLength: Number(finalResponse.headers['content-length'] || Buffer.byteLength(body)),
        title,
        redirectChain,
        tls,
        endpoints,
        responseTime,
        timestamp: new Date(),
      };

      this.cache.set(cacheKey, result);
      return result;
    } catch (err) {
      // if anything unexpected happens, fail gracefully
      logger.debug(`probeHost error ${hostname}:${port} -> ${(err as Error).message}`);
      return null;
    }
  }

  /**
   * Normalize undici headers to string map
   */
  private normalizeHeaders(headers: Record<string, string | string[]>) {
    return Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v])
    );
  }

  /**
   * Fetch with manual redirect following so we can capture redirect chain
   */
  private async fetchWithRedirects(opts: {
    hostname: string;
    ip: string;
    protocol: 'http' | 'https';
    port: number;
    maxRedirects: number;
    timeout: number;
  }): Promise<{ finalResponse: Dispatcher.ResponseData | null; redirectChain: string[] }> {
    const { hostname, ip, protocol, port, maxRedirects, timeout } = opts;
    let url = `${protocol}://${ip}:${port}/`; // start with IP but use Host header for vhosts
    const hostHeader = hostname;
    const redirectChain: string[] = [];
    let redirects = 0;

    while (redirects <= maxRedirects) {
      // AbortController for timeout
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      try {
        const resp = await request(url, {
          method: 'GET',
          maxRedirections: 0, // manual handling
          headers: {
            host: hostHeader,
            accept: 'text/html,application/xml,application/xhtml+xml,*/*;q=0.8',
            'user-agent': 'codex-prober/1.0',
          },
          bodyTimeout: timeout,
          headersTimeout: timeout,
          signal: controller.signal,
          throwOnError: false,
        });

        clearTimeout(timer);

        const status = resp.statusCode;
        const rawLocation = (resp.headers && (resp.headers.location as string)) || undefined;
        // If 3xx + location -> follow
        if (status >= 300 && status < 400 && rawLocation) {
          const location = this.resolveLocation(url, rawLocation);
          redirectChain.push(location);
          url = location;
          redirects += 1;
          // consume body before next iteration to free socket
          try {
            await resp.body.text();
          } catch {
            // ignore
          }
          continue;
        }

        // final response (non-redirect or no location)
        return { finalResponse: resp, redirectChain };
      } catch (err) {
        clearTimeout(timer);
        // Request aborted/timed out or other network error
        logger.debug(`fetchWithRedirects ${hostname}:${port} -> ${(err as Error).message}`);
        return { finalResponse: null, redirectChain };
      }
    }

    // too many redirects
    return { finalResponse: null, redirectChain };
  }

  /**
   * Resolve relative Location headers against the current URL
   */
  private resolveLocation(currentUrl: string, locationHeader: string): string {
    try {
      return new URL(locationHeader, currentUrl).toString();
    } catch {
      // fallback: attempt simple join
      if (locationHeader.startsWith('//')) {
        return `${new URL(currentUrl).protocol}${locationHeader}`;
      }
      return locationHeader;
    }
  }

  /**
   * Extract page title
   */
  private extractTitle(html: string): string | undefined {
    const m = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return m ? m[1].trim() : undefined;
  }

  /**
   * Safer TLS info extraction:
   * - we do NOT disable certificate verification
   * - if validation fails, we report validationError in TLS info
   * - we compute a lightweight "JA3-lite" fingerprint from observable TLS socket properties
   */
  private async extractTLSInfoSafe(hostname: string, port: number): Promise<TLSInfo | undefined> {
    // Attempt TLS connect with default validation (rejectUnauthorized: true)
    // If the handshake fails (e.g., cert validation), return info indicating validation error.
    return new Promise<TLSInfo | undefined>((resolve) => {
      let settled = false;
      const finalize = (v?: TLSInfo) => {
        if (!settled) {
          settled = true;
          resolve(v);
        }
      };

      // Create socket with SNI (servername) and default validation
      const socket = tlsConnect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: true, // do not bypass validation
          timeout: this.timeout,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate(true);
            const protocol = socket.getProtocol() || 'unknown';
            const cipher = socket.getCipher()?.name || 'unknown';
            const cipherVersion = socket.getCipher()?.version || undefined;

            // Node's TLS API does NOT expose signatureAlgorithm.
            const sigAlg: string | undefined = undefined;

            const ja3Lite = this.computeJA3Lite(protocol, cipher, sigAlg);

            socket.end();
            finalize({
              // Set to undefined if they are 'unknown', respecting TLSInfo optionality
              version: protocol === 'unknown' ? undefined : protocol,
              cipher: cipher === 'unknown' ? undefined : cipher,
              cipherVersion: cipherVersion,
              validFrom: cert.valid_from ? new Date(cert.valid_from) : undefined,
              validTo: cert.valid_to ? new Date(cert.valid_to) : undefined,
              issuer: cert.issuer?.CN,
              subject: cert.subject?.CN,
              altNames: cert.subjectaltname
                ? cert.subjectaltname.split(',').map((n: string) => n.replace(/DNS:/i, '').trim())
                : [],
              ja3Lite,
            });
          } catch (err) {
            socket.end();
            finalize(undefined);
          }
        }
      );

      // handle validation errors & other errors
      // FIX: Using NodeJS.ErrnoException resolves the 'any' and unsafe member access warnings.
      socket.on('error', (err: NodeJS.ErrnoException) => {
        // If the error is a cert validation error, we surface it rather than ignoring
        // Common Node messages include "SELF_SIGNED_CERT_IN_CHAIN", etc.
        const validationErrorCodes = new Set([
          'ERR_TLS_CERT_ALTNAME_INVALID',
          'CERT_HAS_EXPIRED',
          'SELF_SIGNED_CERT_IN_CHAIN',
          'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        ]);
        // Access to 'err.code' is now type-safe
        const code = err && err.code ? String(err.code) : undefined;
        if (code && validationErrorCodes.has(code)) {
          // This object literal is correct because validationError is optional in TLSInfo.
          finalize({
            validationError: code,
            altNames: [],
          });
        } else {
          // network-level or other error -> resolve undefined
          finalize(undefined);
        }
        try {
          socket.destroy();
        } catch {
          // ignore
        }
      });

      socket.setTimeout(this.timeout, () => {
        try {
          socket.destroy();
        } catch {
          // ignore
        }
        finalize(undefined);
      });
    });
  }

  /**
   * Compute a best-effort JA3-lite fingerprint from observable TLS properties.
   * Note: this is NOT a full JA3 (which needs raw ClientHello).
   * We produce a short fingerprint string that helps group similar stacks.
   */
  private computeJA3Lite(
    protocol: string | undefined,
    cipher: string | undefined,
    sigAlg?: string
  ) {
    // normalize values and hash them simply
    const p = protocol ?? 'unknown';
    const c = cipher ?? 'unknown';
    const s = sigAlg ?? 'unknown';
    // simple stable fingerprint (sha-like hex) without bringing crypto libs: use built-in string hash -> hex
    let h = 2166136261 >>> 0; // FNV offset basis
    const str = `${p}|${c}|${s}`;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return `ja3lite-${h.toString(16)}`;
  }

  /**
   * Probe common endpoints in parallel with rate-limiting.
   * Extended to try common suffixes and variations: trailing slash, .php, .asp
   */
  private async probeEndpoints(
    hostname: string,
    protocol: 'http' | 'https',
    port: number
  ): Promise<EndpointCheck[]> {
    const paths = new Set<string>();

    // base endpoints
    for (const p of this.commonEndpoints) paths.add(p);

    // generate variations
    for (const p of Array.from(paths)) {
      if (!p.endsWith('/')) {
        paths.add(p + '/');
      }
      // common extensions
      if (!p.includes('.')) {
        paths.add(p + '.php');
        paths.add(p + '.asp');
      }
    }

    // ensure root included
    paths.add('/');

    const limit = pLimit(this.endpointConcurrency);
    const tasks = Array.from(paths).map((p) =>
      limit(async () => {
        const url = `${protocol}://${hostname}:${port}${p}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), Math.min(2000, this.timeout));

        try {
          // Use hostname in Host header to support vhosts even when requesting via IP earlier
          const resp = await request(url, {
            method: 'GET',
            maxRedirections: 0,
            headers: { host: hostname, 'user-agent': 'codex-prober/1.0' },
            headersTimeout: Math.min(2000, this.timeout),
            bodyTimeout: Math.min(2000, this.timeout),
            throwOnError: false,
            signal: controller.signal,
          });

          clearTimeout(timer);
          const exists = resp.statusCode < 400;
          let notes: string | undefined;

          // quick directory listing detection
          if (exists) {
            try {
              const txt = await resp.body.text();
              if (/Index of \//i.test(txt) || /Parent Directory/i.test(txt)) {
                notes = 'Directory listing suspected';
              } else if (p === '/robots.txt' && txt) {
                notes = 'robots.txt present';
              } else if (p === '/sitemap.xml' && txt) {
                notes = 'sitemap.xml present';
              }
            } catch {
              // ignore body read errors
            }
          }

          // consume body in case not yet read (some code reads it)
          try {
            await resp.body.text();
          } catch {
            // ignore
          }

          return {
            path: p,
            statusCode: resp.statusCode,
            exists,
            notes,
          } as EndpointCheck;
        } catch {
          clearTimeout(timer);
          return {
            path: p,
            statusCode: 0,
            exists: false,
          } as EndpointCheck;
        }
      })
    );

    const resolved = await Promise.all(tasks);
    // sort endpoints: exists first
    return resolved.sort((a, b) => Number(b.exists) - Number(a.exists));
  }
}
