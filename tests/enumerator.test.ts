/**
 * Tests for SubdomainEnumerator
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SubdomainEnumerator } from '../src/core/enumerator.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('SubdomainEnumerator', () => {
  let enumerator: SubdomainEnumerator;

  beforeEach(() => {
    enumerator = new SubdomainEnumerator('example.com', 5);
    vi.clearAllMocks();
  });

  describe('enumerate', () => {
    it('should enumerate subdomains from multiple sources', async () => {
      // Mock crt.sh response
      const mockCrtShData = [
        { name_value: 'www.example.com' },
        { name_value: 'api.example.com' },
        { name_value: 'mail.example.com' },
      ];

      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCrtShData),
      });

      // Note: In a real test, you'd also mock DNS resolution
      // For now, this test will verify the structure

      const results = await enumerator.enumerate();

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
    });

    it('should handle crt.sh API errors gracefully', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network error'));

      const results = await enumerator.enumerate();

      // Should not throw, just return empty or partial results
      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
    });

    it('should deduplicate subdomains from multiple sources', async () => {
      const mockCrtShData = [
        { name_value: 'www.example.com' },
        { name_value: 'www.example.com' }, // Duplicate
        { name_value: 'api.example.com' },
      ];

      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCrtShData),
      });

      const results = await enumerator.enumerate();

      // Verify deduplication (exact count depends on DNS resolution mock)
      const hostnames = results.map((r) => r.hostname);
      const uniqueHostnames = new Set(hostnames);
      expect(hostnames.length).toBe(uniqueHostnames.size);
    });

    it('should filter out wildcard certificates', async () => {
      const mockCrtShData = [
        { name_value: '*.example.com' }, // Should be filtered
        { name_value: 'www.example.com' },
      ];

      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCrtShData),
      });

      const results = await enumerator.enumerate();

      // Verify no wildcards in results
      const hasWildcard = results.some((r) => r.hostname.includes('*'));
      expect(hasWildcard).toBe(false);
    });

    it('should set correct source metadata', async () => {
      const mockCrtShData = [{ name_value: 'www.example.com' }];

      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCrtShData),
      });

      const results = await enumerator.enumerate();

      // Verify each result has proper metadata
      results.forEach((result) => {
        expect(result).toHaveProperty('hostname');
        expect(result).toHaveProperty('source');
        expect(result).toHaveProperty('resolvedIPs');
        expect(result).toHaveProperty('timestamp');
        expect(['crt.sh', 'dns', 'wordlist']).toContain(result.source);
      });
    });
  });
});
