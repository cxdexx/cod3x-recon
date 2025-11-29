/**
 * Sample built-in plugin demonstrating the plugin API
 */

import type { Plugin, SubdomainResult, ProbeResult, ClassificationHint } from '../core/types.js';

/**
 * Sample plugin that demonstrates all available hooks
 */
export const samplePlugin: Plugin = {
  name: 'sample-plugin',
  version: '1.0.0',

  hooks: {
    /**
     * Called when a subdomain is discovered
     */
    onSubdomainFound: (subdomain: SubdomainResult) => {
      console.log(`[Sample Plugin] Found subdomain: ${subdomain.hostname}`);

      // Example: Log subdomains from specific sources
      if (subdomain.source === 'crt.sh') {
        console.log(`[Sample Plugin] Certificate Transparency entry detected`);
      }
    },

    /**
     * Called when a host is probed
     */
    onProbeResult: (result: ProbeResult) => {
      // Example: Detect specific technologies
      // Get the 'server' header
      const rawServer = result.headers['server'];

      // Normalize to string
      const serverHeader = Array.isArray(rawServer)
        ? rawServer.join(', ') // If multiple headers, join them
        : rawServer;

      // Only call toLowerCase if it's a string
      if (typeof serverHeader === 'string' && serverHeader.includes('apache')) {
        console.log(`[Sample Plugin] Apache server detected on ${result.hostname}`);
      }

      // Example: Check for x-powered-by header
      const rawXPoweredBy = result.headers['x-powered-by'];
      const xPoweredBy = Array.isArray(rawXPoweredBy) ? rawXPoweredBy.join(', ') : rawXPoweredBy;

      if (typeof xPoweredBy === 'string') {
        console.log(`[Sample Plugin] Technology fingerprint: ${xPoweredBy}`);
      }

      // Example: Analyze response time
      if (result.responseTime > 3000) {
        console.log(
          `[Sample Plugin] Slow response detected: ${result.responseTime}ms on ${result.hostname}`
        );
      }
    },

    /**
     * Called during classification to add custom rules
     */
    onClassify: (result: ProbeResult): ClassificationHint | null => {
      // Example: Custom classification for GraphQL endpoints
      if (result.title?.toLowerCase().includes('graphql')) {
        return {
          categories: ['graphql-endpoint'],
          riskScore: 50,
          notes: 'GraphQL endpoint detected',
        };
      }

      // Example: Detect WordPress installations
      if (
        result.headers['x-powered-by']?.includes('WordPress') ||
        result.title?.includes('WordPress')
      ) {
        return {
          categories: ['wordpress'],
          riskScore: 40,
          notes: 'WordPress installation detected',
        };
      }

      // Example: Flag potential honeypots
      if (
        result.endpoints.every((e) => e.exists && e.statusCode === 200) &&
        result.endpoints.length > 5
      ) {
        return {
          categories: ['possible-honeypot'],
          riskScore: 30,
          notes: 'All endpoints return 200 - possible honeypot',
        };
      }

      // Return null if no custom classification applies
      return null;
    },

    /**
     * Called when the scan is complete
     */
    onComplete: (results) => {
      console.log(`\n[Sample Plugin] Scan Summary:`);
      console.log(`  Total subdomains: ${results.subdomains.length}`);
      console.log(`  Live hosts: ${results.probeResults.length}`);
      console.log(`  High-risk findings: ${results.metadata.highRiskFindings}`);
      console.log(`  Scan duration: ${(results.metadata.duration / 1000).toFixed(2)}s`);

      // Example: Generate custom report
      const categoryCounts = new Map<string, number>();
      for (const result of results.classifiedResults) {
        for (const category of result.categories) {
          categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
        }
      }

      console.log(`\n[Sample Plugin] Category Distribution:`);
      for (const [category, count] of categoryCounts.entries()) {
        console.log(`  ${category}: ${count}`);
      }
    },
  },
};
