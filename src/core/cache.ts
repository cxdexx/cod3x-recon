/**
 * LRU Cache implementation with TTL support
 */

import { LRUCache } from 'lru-cache';
import type { CacheEntry } from './types.js';

/**
 * Cache manager for DNS and HTTP results
 */
export class CacheManager<T = unknown> {
  private cache: LRUCache<string, CacheEntry<T>>;
  private defaultTTL: number;

  /**
   * Create a new cache manager
   * @param maxSize Maximum number of entries
   * @param ttl Time-to-live in milliseconds
   */
  constructor(maxSize = 1000, ttl = 300000) {
    this.defaultTTL = ttl;
    this.cache = new LRUCache<string, CacheEntry<T>>({
      max: maxSize,
      ttl: ttl,
      updateAgeOnGet: true,
      updateAgeOnHas: false,
    });
  }

  /**
   * Get a value from cache
   * @param key Cache key
   * @returns Cached value or undefined if not found or expired
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      return undefined;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  /**
   * Set a value in cache
   * @param key Cache key
   * @param value Value to cache
   * @param ttl Optional custom TTL in milliseconds
   */
  set(key: string, value: T, ttl?: number): void {
    const expiresAt = Date.now() + (ttl ?? this.defaultTTL);
    const entry: CacheEntry<T> = {
      value,
      expiresAt,
    };
    this.cache.set(key, entry);
  }

  /**
   * Check if a key exists and is not expired
   * @param key Cache key
   * @returns True if key exists and is valid
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Delete a key from cache
   * @param key Cache key
   */
  delete(key: string): void {
    this.cache.delete(key);
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getStats() {
    return {
      size: this.cache.size,
      maxSize: this.cache.max,
      ttl: this.defaultTTL,
    };
  }

  /**
   * Get or set pattern: get from cache or compute and cache
   * @param key Cache key
   * @param factory Function to compute value if not cached
   * @param ttl Optional custom TTL
   */
  async getOrSet(key: string, factory: () => Promise<T>, ttl?: number): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const value = await factory();
    this.set(key, value, ttl);
    return value;
  }
}
