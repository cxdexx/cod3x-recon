/**
 * HTTP utilities with connection pooling
 */

import { request, Agent } from 'undici';

/**
 * Create a persistent HTTP agent with connection pooling
 */
export function createHttpAgent() {
  return new Agent({
    connections: 100,
    pipelining: 10,
    keepAliveTimeout: 10000,
    keepAliveMaxTimeout: 60000,
  });
}

/**
 * HTTP client with timeout and retries
 */
export class HttpClient {
  private agent: Agent;
  private timeout: number;

  constructor(timeout = 5000) {
    this.agent = createHttpAgent();
    this.timeout = timeout;
  }

  /**
   * Make an HTTP GET request
   */
  async get(
    url: string,
    options: {
      headers?: Record<string, string>;
      maxRedirections?: number;
    } = {}
  ) {
    try {
      const response = await request(url, {
        method: 'GET',
        headers: options.headers,
        maxRedirections: options.maxRedirections ?? 5,
        headersTimeout: this.timeout,
        bodyTimeout: this.timeout,
        dispatcher: this.agent,
        throwOnError: false,
      });

      const body = await response.body.text();

      return {
        statusCode: response.statusCode,
        headers: response.headers,
        body,
      };
    } catch (error) {
      throw new Error(
        `HTTP GET failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Make an HTTP HEAD request
   */
  async head(
    url: string,
    options: {
      headers?: Record<string, string>;
    } = {}
  ) {
    try {
      const response = await request(url, {
        method: 'HEAD',
        headers: options.headers,
        headersTimeout: this.timeout,
        dispatcher: this.agent,
        throwOnError: false,
      });

      // Consume body (should be empty for HEAD)
      await response.body.text();

      return {
        statusCode: response.statusCode,
        headers: response.headers,
      };
    } catch (error) {
      throw new Error(
        `HTTP HEAD failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Close the agent and cleanup connections
   */
  async close() {
    await this.agent.close();
  }

  /**
   * Set timeout for requests
   */
  setTimeout(timeout: number) {
    this.timeout = timeout;
  }
}

/**
 * Parse URL safely
 */
export function parseUrl(urlString: string): URL | null {
  try {
    return new URL(urlString);
  } catch {
    return null;
  }
}

/**
 * Validate URL format
 */
export function isValidUrl(urlString: string): boolean {
  return parseUrl(urlString) !== null;
}

/**
 * Extract domain from URL
 */
export function extractDomain(urlString: string): string | null {
  const url = parseUrl(urlString);
  return url ? url.hostname : null;
}
