/**
 * Subdomain enumeration engine
 */

import { promises as dns } from 'dns';
import { readFile } from 'fs/promises';
import { join } from 'path';
import pLimit from 'p-limit';
import { CacheManager } from './cache.js';
import { logger } from '../utils/logger.js';
import type { SubdomainResult } from './types.js';

/**
 * Multi-source subdomain enumerator
 */
export class SubdomainEnumerator {
  private domain: string;
  private concurrency: number;
  private dnsCache: CacheManager<string[]>;
  private seenSubdomains = new Set<string>();

  constructor(domain: string, concurrency = 10) {
    this.domain = domain;
    this.concurrency = concurrency;
    this.dnsCache = new CacheManager<string[]>(5000, 3600000); // 1 hour TTL
  }

  /**
   * Enumerate subdomains from all sources
   */
  async enumerate(): Promise<SubdomainResult[]> {
    const results: SubdomainResult[] = [];

    // Gather from all sources concurrently
    const [crtshResults, wordlistResults] = await Promise.all([
      this.enumerateFromCrtSh(),
      this.enumerateFromWordlist(),
    ]);

    results.push(...crtshResults, ...wordlistResults);

    // Verify DNS resolution for all candidates
    const verifiedResults = await this.verifyDNS(results);

    logger.info(`Total unique subdomains after verification: ${verifiedResults.length}`);

    return verifiedResults;
  }

  /**
   * Enumerate subdomains from crt.sh (Certificate Transparency)
   */
  private async enumerateFromCrtSh(): Promise<SubdomainResult[]> {
    const results: SubdomainResult[] = [];

    try {
      logger.info('Querying crt.sh...');
      const url = `https://crt.sh/?q=%.${this.domain}&output=json`;

      const response = await fetch(url, {
        headers: { 'User-Agent': 'COD3X:RECON/1.0' },
        signal: AbortSignal.timeout(30000),
      });

      if (!response.ok) {
        throw new Error(`crt.sh returned ${response.status}`);
      }

      // Fix: Cast through unknown to avoid 'unsafe assignment of any' error
      const json = (await response.json()) as unknown;
      const data = json as Array<{
        name_value: string;
        common_name?: string;
      }>;

      const subdomains = new Set<string>();

      // Safe type definition for crt.sh entries
      type CrtShEntry = {
        name_value: string;
      };

      if (Array.isArray(data)) {
        for (const entryRaw of data) {
          // Runtime + type guard to avoid unsafe-any
          if (
            entryRaw &&
            typeof entryRaw === 'object' &&
            'name_value' in entryRaw &&
            typeof (entryRaw as { name_value: unknown }).name_value === 'string'
          ) {
            const entry = entryRaw as CrtShEntry;

            const names = entry.name_value.split('\n');
            for (const name of names) {
              const cleaned = name.trim().toLowerCase();

              if (cleaned.endsWith(this.domain) && !cleaned.includes('*')) {
                subdomains.add(cleaned);
              }
            }
          }
        }
      }

      logger.info(`Found ${subdomains.size} subdomains from crt.sh`);

      for (const sub of subdomains) {
        const subdomain = String(sub); // explicit safe cast

        if (!this.seenSubdomains.has(subdomain)) {
          this.seenSubdomains.add(subdomain);
          results.push({
            hostname: subdomain,
            source: 'crt.sh',
            resolvedIPs: [],
            timestamp: new Date(),
          });
        }
      }
    } catch (error) {
      logger.error('crt.sh enumeration failed:', error);
    }

    return results;
  }

  /**
   * Enumerate subdomains using wordlist
   */
  private async enumerateFromWordlist(): Promise<SubdomainResult[]> {
    const results: SubdomainResult[] = [];

    try {
      logger.info('Enumerating from wordlist...');
      const wordlistPath = join(process.cwd(), 'templates', 'wordlists', 'common-subdomains.txt');

      const content = await readFile(wordlistPath, 'utf-8');
      const words = content
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'));

      logger.info(`Loaded ${words.length} words from wordlist`);

      for (const word of words) {
        const subdomain = `${word}.${this.domain}`;
        if (!this.seenSubdomains.has(subdomain)) {
          this.seenSubdomains.add(subdomain);
          results.push({
            hostname: subdomain,
            source: 'wordlist',
            resolvedIPs: [],
            timestamp: new Date(),
          });
        }
      }
    } catch (error) {
      logger.warn('Wordlist enumeration skipped:', error);
    }

    return results;
  }

  /**
   * Verify DNS resolution for subdomains
   */
  private async verifyDNS(candidates: SubdomainResult[]): Promise<SubdomainResult[]> {
    logger.info(`Verifying DNS for ${candidates.length} candidates...`);

    const limit = pLimit(this.concurrency);
    const verified: SubdomainResult[] = [];

    const tasks = candidates.map((candidate) =>
      limit(async () => {
        try {
          const ips = await this.resolveDNS(candidate.hostname);
          if (ips.length > 0) {
            candidate.resolvedIPs = ips;
            verified.push(candidate);
          }
        } catch {
          // DNS resolution failed, skip this subdomain
        }
      })
    );

    await Promise.all(tasks);

    logger.info(`${verified.length} subdomains resolved successfully`);
    return verified;
  }

  /**
   * Resolve DNS with caching
   */
  private async resolveDNS(hostname: string): Promise<string[]> {
    return await this.dnsCache.getOrSet(
      `dns:${hostname}`,
      async () => {
        try {
          const resolver = new dns.Resolver();
          resolver.setServers(['8.8.8.8', '1.1.1.1']); // Use public DNS

          // Try A records
          try {
            const addresses = await resolver.resolve4(hostname);
            return addresses;
          } catch {
            // Try AAAA records if A fails
            const addresses = await resolver.resolve6(hostname);
            return addresses;
          }
        } catch {
          return [];
        }
      },
      3600000 // 1 hour TTL
    );
  }
}
