/**
 * Intelligent classification and risk scoring engine
 */

import { logger } from '../utils/logger.js';
import type { ProbeResult, ClassifiedResult, Plugin, ClassificationHint } from './types.js';

export class Classifier {
  async classify(
    probeResults: readonly ProbeResult[],
    plugins: readonly Plugin[] = []
  ): Promise<ClassifiedResult[]> {
    logger.info('Classifying probe results...');

    await Promise.resolve();

    const classified: ClassifiedResult[] = [];

    for (const result of probeResults) {
      const categories: string[] = [];
      let riskScore = 0;
      const notes: string[] = [];

      // ----------------------------
      // Built-in rules
      // ----------------------------
      const builtIn = this.applyBuiltInRules(result);

      categories.push(...builtIn.categories);
      riskScore = Math.max(riskScore, builtIn.riskScore);
      if (builtIn.notes) notes.push(builtIn.notes);

      // ----------------------------
      // Plugin rules
      // ----------------------------
      for (const plugin of plugins) {
        const onClassify = plugin.hooks?.onClassify;

        if (typeof onClassify === 'function') {
          try {
            // Safe casting: onClassify can return unknown
            const rawHint: unknown = onClassify(result);

            // Narrow to ClassificationHint | null
            const hint =
              rawHint && typeof rawHint === 'object' ? (rawHint as ClassificationHint) : null;

            if (
              hint &&
              Array.isArray(hint.categories) &&
              hint.categories.every((v) => typeof v === 'string')
            ) {
              categories.push(...hint.categories);
              riskScore = Math.max(riskScore, hint.riskScore ?? 0);

              if (hint.notes) notes.push(hint.notes);
            }
          } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            logger.error(`Plugin ${plugin.name} classification failed: ${errorMessage}`);
          }
        }
      }

      // Completely safe dedupe
      const dedupedCategories: string[] = Array.from(new Set<string>(categories));

      classified.push({
        ...result,
        categories: dedupedCategories,
        riskScore: Math.min(riskScore, 100),
        notes: notes.length ? notes.join('; ') : 'No significant findings',
      });
    }

    return classified;
  }

  private applyBuiltInRules(result: ProbeResult): ClassificationHint {
    const categories: string[] = [];
    let riskScore = 0;
    const notes: string[] = [];

    // Hostname patterns
    const hostnamePatterns: Record<string, { category: string; risk: number }> = {
      'staging|stg|stage|dev|development': { category: 'staging', risk: 60 },
      api: { category: 'api', risk: 40 },
      'admin|administrator|management': { category: 'admin-panel', risk: 85 },
      'test|testing|qa': { category: 'testing', risk: 55 },
      'mail|smtp|imap|pop': { category: 'mail', risk: 30 },
      'vpn|remote': { category: 'remote-access', risk: 50 },
      'jenkins|gitlab|ci|cd': { category: 'ci-cd', risk: 70 },
      'static|cdn|assets': { category: 'static', risk: 10 },
    };

    for (const [pattern, info] of Object.entries(hostnamePatterns)) {
      const regex = new RegExp(pattern, 'i');
      if (regex.test(result.hostname)) {
        categories.push(info.category);
        riskScore = Math.max(riskScore, info.risk);
        notes.push(`${info.category} detected in hostname`);
      }
    }

    // Status codes
    if (result.statusCode === 200 && categories.includes('admin-panel')) {
      riskScore = Math.max(riskScore, 85);
      notes.push('Admin panel accessible');
    } else if (result.statusCode === 401 || result.statusCode === 403) {
      riskScore = Math.max(riskScore, 40);
      notes.push('Authentication required');
    } else if (result.statusCode >= 500) {
      riskScore = Math.max(riskScore, 30);
      notes.push('Server error detected');
    }

    // Header analysis
    const headers = result.headers;

    const rawServer = headers['server'];
    const serverHeader = typeof rawServer === 'string' ? rawServer.toLowerCase() : '';

    const outdatedPatterns = [
      /apache\/1\./i,
      /apache\/2\.[0-2]/i,
      /nginx\/1\.[0-9]\./i,
      /iis\/[6-7]\./i,
    ];

    if (outdatedPatterns.some((p) => p.test(serverHeader))) {
      categories.push('outdated-server');
      riskScore = Math.max(riskScore, 60);
      notes.push('Outdated server software detected');
    }

    // CORS misconfig
    const allowOrigin = headers['access-control-allow-origin'];
    const allowCred = headers['access-control-allow-credentials'];

    if (allowOrigin === '*' && allowCred === 'true') {
      categories.push('cors-unsafe');
      riskScore = Math.max(riskScore, 75);
      notes.push('Unsafe CORS policy');
    }

    // Missing security headers
    const securityHeaders = [
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'content-security-policy',
    ] as const;

    const missing = securityHeaders.filter((h) => !headers[h]);

    if (missing.length >= 3) {
      categories.push('weak-headers');
      riskScore = Math.max(riskScore, 45);
      notes.push(`Missing ${missing.length} security headers`);
    }

    // Sensitive endpoints
    const sensitive = result.endpoints.filter(
      (e) => e.exists && (e.path.includes('admin') || e.path.includes('.git'))
    );

    if (sensitive.length > 0) {
      categories.push('exposed-endpoints');
      riskScore = Math.max(riskScore, 80);
      notes.push(`Sensitive endpoints exposed: ${sensitive.map((e) => e.path).join(', ')}`);
    }

    // Directory listing
    const directoryListing = result.endpoints.find((e) => {
      if (!e.notes) return false;
      const n = e.notes.toLowerCase();
      return n.includes('directory listing') || n.includes('index of');
    });

    if (directoryListing) {
      categories.push('directory-listing');
      riskScore = Math.max(riskScore, 80);
      notes.push('Directory listing enabled — sensitive files may be exposed');
    }

    // TLS checks
    if (result.tls) {
      const now = Date.now();
      // Destructure potentially optional properties from result.tls
      const { validTo, cipher } = result.tls;

      // Check validTo before calling .getTime()
      if (validTo) {
        if (validTo.getTime() < now) {
          categories.push('expired-certificate');
          riskScore = Math.max(riskScore, 65);
          notes.push('TLS certificate expired');
        }

        const oneWeek = 7 * 24 * 60 * 60 * 1000;

        if (validTo.getTime() - now < oneWeek) {
          categories.push('expiring-certificate');
          riskScore = Math.max(riskScore, 40);
          notes.push('TLS certificate expiring soon');
        }
      }

      const weakCiphers = ['RC4', 'DES', 'MD5', '3DES'];

      // Check cipher before calling .includes()
      if (cipher && weakCiphers.some((c) => cipher.includes(c))) {
        categories.push('weak-cipher');
        riskScore = Math.max(riskScore, 70);
        notes.push('Weak TLS cipher detected');
      }
    }

    // No TLS
    if (!result.tls && result.protocol === 'http') {
      categories.push('no-tls');
      riskScore = Math.max(riskScore, 50);
      notes.push('No TLS encryption');
    }

    // Slow response
    if (result.responseTime > 5000) {
      categories.push('slow-response');
      riskScore = Math.max(riskScore, 20);
      notes.push('Slow response time');
    }

    return {
      categories: categories.length ? categories : ['standard'],
      riskScore,
      notes: notes.join('; '),
    };
  }
}
