/**
 * Nuclei integration and runner
 */

import { spawn } from 'child_process';
import { access, constants } from 'fs/promises';
import { join } from 'path';
import { logger } from '../utils/logger.js';
import type { NucleiResult } from '../core/types.js';

/**
 * Nuclei scanner wrapper
 */
export class NucleiRunner {
  private nucleiPath = 'nuclei';
  private templatesPath: string;

  constructor() {
    this.templatesPath = join(process.cwd(), 'src', 'nuclei', 'templates');
  }

  /**
   * Check if Nuclei is available
   */
  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn(this.nucleiPath, ['-version'], {
        stdio: 'ignore',
      });

      proc.on('close', (code) => {
        resolve(code === 0);
      });

      proc.on('error', () => {
        resolve(false);
      });
    });
  }

  /**
   * Run Nuclei scans against target hosts
   */
  async runScans(hosts: string[]): Promise<NucleiResult[]> {
    // Check availability
    const available = await this.isAvailable();
    if (!available) {
      logger.warn(
        'Nuclei not found in PATH. Install from: https://github.com/projectdiscovery/nuclei'
      );
      return [];
    }

    // Check if custom templates exist
    const hasCustomTemplates = await this.hasCustomTemplates();

    logger.info(`Running Nuclei scans on ${hosts.length} hosts...`);

    const results: NucleiResult[] = [];

    try {
      const args = [
        '-l',
        '-', // Read targets from stdin
        '-json', // JSON output
        '-silent', // Silent mode
        '-stats', // Show stats
      ];

      // Add custom templates if available
      if (hasCustomTemplates) {
        args.push('-t', this.templatesPath);
        logger.info(`Using custom templates from: ${this.templatesPath}`);
      } else {
        logger.info('Using default Nuclei templates');
      }

      const proc = spawn(this.nucleiPath, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      // Send hosts to stdin
      proc.stdin.write(hosts.join('\n'));
      proc.stdin.end();

      // Collect output
      let output = '';
      proc.stdout.on('data', (data: Buffer) => {
        output += data.toString();
      });

      let errors = '';
      proc.stderr.on('data', (data: Buffer) => {
        errors += data.toString();
      });

      // Wait for completion
      await new Promise<void>((resolve, reject) => {
        proc.on('close', (code) => {
          if (code === 0 || code === null) {
            resolve();
          } else {
            reject(new Error(`Nuclei exited with code ${code}: ${errors}`));
          }
        });

        proc.on('error', (error) => {
          reject(error);
        });
      });

      // Parse results
      const lines = output.split('\n').filter((line) => line.trim());
      for (const line of lines) {
        try {
          const result = JSON.parse(line) as {
            'template-id': string;
            info: { name: string; severity: string };
            host: string;
            'matched-at': string;
            'extracted-results'?: string[];
          };

          results.push({
            templateId: result['template-id'],
            templateName: result.info.name,
            severity: result.info.severity as NucleiResult['severity'],
            host: result.host,
            matchedAt: result['matched-at'],
            extractedResults: result['extracted-results'] || [],
            timestamp: new Date(),
          });
        } catch (parseError) {
          // Skip invalid JSON lines
        }
      }

      logger.info(`Nuclei scan complete: ${results.length} findings`);
    } catch (error) {
      logger.error('Nuclei scan failed:', error);
    }

    return results;
  }

  /**
   * Check if custom templates directory exists and has templates
   */
  private async hasCustomTemplates(): Promise<boolean> {
    try {
      await access(this.templatesPath, constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Set custom Nuclei binary path
   */
  setNucleiPath(path: string): void {
    this.nucleiPath = path;
  }

  /**
   * Set custom templates path
   */
  setTemplatesPath(path: string): void {
    this.templatesPath = path;
  }
}
