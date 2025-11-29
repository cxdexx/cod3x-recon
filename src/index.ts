/**
 * COD3X:RECON - Context-Aware Subdomain Enumerator
 * Main entry point for programmatic usage
 */

export { App } from './core/app.js';
export { SubdomainEnumerator } from './core/enumerator.js';
export { HostProber } from './core/probe.js';
export { Classifier } from './core/classifier.js';
export { NucleiRunner } from './nuclei/runner.js';
export * from './core/types.js';

/**
 * Version information
 */
export const VERSION = '1.0.0';

/**
 * Quick scan interface for programmatic usage
 * @example
 * ```typescript
 * import { quickScan } from 'cod3x-recon';
 *
 * const results = await quickScan('example.com', {
 *   concurrency: 20,
 *   timeout: 5000,
 * });
 * ```
 */
export async function quickScan(
  domain: string,
  options: {
    concurrency?: number;
    timeout?: number;
    runNuclei?: boolean;
    quiet?: boolean;
  } = {}
) {
  const { App } = await import('./core/app.js');
  const app = new App({
    domain,
    concurrency: options.concurrency ?? 10,
    timeout: options.timeout ?? 3000,
    runNuclei: options.runNuclei ?? false,
    quiet: options.quiet ?? false,
    format: 'json',
    plugins: [],
  });

  return await app.run();
}
