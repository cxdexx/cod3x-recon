/**
 * Tests for Classifier
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Classifier } from '../src/core/classifier.js';
import type { ProbeResult } from '../src/core/types.js';

describe('Classifier', () => {
  let classifier: Classifier;

  beforeEach(() => {
    classifier = new Classifier();
  });

  const createMockProbeResult = (overrides: Partial<ProbeResult> = {}): ProbeResult => ({
    hostname: 'example.com',
    ip: '192.168.1.1',
    protocol: 'https',
    port: 443,
    statusCode: 200,
    statusText: 'OK',
    headers: {},
    contentLength: 1024,
    redirectChain: [],
    endpoints: [],
    responseTime: 100,
    timestamp: new Date(),
    ...overrides,
  });

  describe('classify', () => {
    it('should classify admin panels with high risk', async () => {
      const probeResult = createMockProbeResult({
        hostname: 'admin.example.com',
        statusCode: 200,
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('admin-panel');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(70);
    });

    it('should classify staging environments', async () => {
      const probeResult = createMockProbeResult({
        hostname: 'staging.example.com',
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('staging');
      expect(results[0].riskScore).toBeGreaterThan(50);
    });

    it('should detect CORS misconfigurations', async () => {
      const probeResult = createMockProbeResult({
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
        },
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('cors-unsafe');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(70);
    });

    it('should detect missing security headers', async () => {
      const probeResult = createMockProbeResult({
        headers: {
          server: 'nginx',
          // Missing: strict-transport-security, x-frame-options, etc.
        },
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('weak-headers');
    });

    it('should detect outdated server software', async () => {
      const probeResult = createMockProbeResult({
        headers: {
          server: 'Apache/2.2.15',
        },
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('outdated-server');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(60);
    });

    it('should detect exposed sensitive endpoints', async () => {
      const probeResult = createMockProbeResult({
        endpoints: [
          { path: '/admin', statusCode: 200, exists: true },
          { path: '/.git', statusCode: 200, exists: true },
        ],
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('exposed-endpoints');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(80);
    });

    it('should detect directory listing', async () => {
      const probeResult = createMockProbeResult({
        hostname: 'test.example.com',
        endpoints: [
          {
            path: '/',
            statusCode: 200,
            exists: true,
            notes: 'Directory listing detected',
          },
        ],
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('directory-listing');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(70);
    });

    it('should detect expired TLS certificates', async () => {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const probeResult = createMockProbeResult({
        tls: {
          version: 'TLSv1.2',
          cipher: 'AES256-SHA',
          validFrom: new Date('2020-01-01'),
          validTo: yesterday,
          issuer: 'Test CA',
          subject: 'test.example.com',
          altNames: ['test.example.com'],
        },
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('expired-certificate');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(65);
    });

    it('should apply plugin classification rules', async () => {
      const mockPlugin = {
        name: 'test-plugin',
        version: '1.0.0',
        hooks: {
          onClassify: () => ({
            categories: ['custom-category'],
            riskScore: 90,
            notes: 'Custom plugin detection',
          }),
        },
      };

      const probeResult = createMockProbeResult();
      const results = await classifier.classify([probeResult], [mockPlugin]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('custom-category');
      expect(results[0].riskScore).toBeGreaterThanOrEqual(90);
    });

    it('should handle classification errors gracefully', async () => {
      const faultyPlugin = {
        name: 'faulty-plugin',
        version: '1.0.0',
        hooks: {
          onClassify: () => {
            throw new Error('Plugin error');
          },
        },
      };

      const probeResult = createMockProbeResult();

      // Should not throw
      await expect(classifier.classify([probeResult], [faultyPlugin])).resolves.toBeDefined();
    });

    it('should assign standard category when no rules match', async () => {
      const probeResult = createMockProbeResult({
        hostname: 'normal-site.example.com',
        headers: {
          'strict-transport-security': 'max-age=31536000',
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'content-security-policy': "default-src 'self'",
        },
      });

      const results = await classifier.classify([probeResult]);

      expect(results).toHaveLength(1);
      expect(results[0].categories).toContain('standard');
      expect(results[0].riskScore).toBeLessThan(50);
    });
  });
});
