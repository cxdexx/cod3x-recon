/**
 * Main application orchestrator
 */
import { writeFile } from 'fs/promises';
import chalk from 'chalk';
import { SubdomainEnumerator } from './enumerator.js';
import { HostProber } from './probe.js';
import { Classifier } from './classifier.js';
import { NucleiRunner } from '../nuclei/runner.js';
import type { Cod3xPlugin } from '../core/types.js';
import { logger } from '../utils/logger.js';
import type { AppConfig, ScanResults, Plugin, SubdomainResult, ProbeResult } from './types.js';

/**
 * Nuclei result shapes — treated as unknown-ish but normalized before assigning.
 */
// UNUSED: type NucleiFinding = {
//   templateId?: string;
//   severity?: string;
//   matchedAt?: string;
//   description?: string;
//   [key: string]: unknown;
// };

type NucleiSafe = Record<string, unknown>[] | Record<string, unknown>;

/**
 * Main application class that orchestrates the scan
 */
export class App {
  private config: AppConfig;
  private plugins: Plugin[] = [];
  private enumerator: SubdomainEnumerator;
  private prober: HostProber;
  private classifier: Classifier;
  private nucleiRunner?: NucleiRunner;

  constructor(config: AppConfig) {
    this.config = config;
    this.enumerator = new SubdomainEnumerator(config.domain, config.concurrency);
    this.prober = new HostProber(config.timeout, config.concurrency);
    this.classifier = new Classifier();

    if (config.runNuclei) {
      this.nucleiRunner = new NucleiRunner();
    }

    // Configure logger
    logger.setQuiet(config.quiet);
  }

  /**
   * Load plugins from specified paths
   */
  private async loadPlugins(): Promise<void> {
    for (const pluginPath of this.config.plugins) {
      try {
        // Fully type the expected import shape
        const pluginModule = (await import(`file://${process.cwd()}/${pluginPath}/index.js`)) as {
          default: unknown;
        };

        const mod = pluginModule.default;

        // Runtime validation: is it even an object?
        if (typeof mod !== 'object' || mod === null) {
          logger.warn(`Invalid plugin export: ${pluginPath}`);
          continue;
        }

        // Minimal structural check
        const candidate = mod as Partial<Cod3xPlugin>;

        if (typeof candidate.name === 'string' && typeof candidate.run === 'function') {
          const finalPlugin = {
            ...candidate, // Spread existing properties (name, run, description, hooks, etc.)
            version: candidate.version || '0.0.0', // This guarantees 'version' is a string
          };
          // Safe to accept as Cod3xPlugin
          this.plugins.push(finalPlugin as Plugin);
          logger.info(`Loaded plugin: ${finalPlugin.name}`);
        } else {
          logger.warn(`Plugin structure invalid: ${pluginPath}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`Failed to load plugin ${pluginPath}: ${errorMessage}`);
      }
    }
  }

  /**
   * Execute plugin hooks
   */
  private async executePluginHook<T>(hookName: keyof Plugin['hooks'], data: T): Promise<void> {
    for (const plugin of this.plugins) {
      const hook = plugin.hooks[hookName];
      if (hook && typeof hook === 'function') {
        try {
          // Temporarily cast the hook for execution, assuming external type safety
          await (hook as (data: T) => Promise<void> | void)(data);
        } catch (error) {
          logger.error(`Plugin ${plugin.name} hook ${hookName} failed:`, error);
        }
      }
    }
  }

  /**
   * Convert unknown nuclei output into a safe structure.
   * Returns either an array of safe records or a single safe record (or an empty array).
   */
  private toNucleiSafe(input: unknown): NucleiSafe {
    if (Array.isArray(input)) {
      return input.map((item) =>
        typeof item === 'object' && item !== null ? (item as Record<string, unknown>) : {}
      );
    }

    if (typeof input === 'object' && input !== null) {
      return input as Record<string, unknown>;
    }

    return [];
  }

  /**
   * Run the complete scan workflow
   */
  async run(): Promise<ScanResults> {
    const startTime = new Date();

    try {
      // Load plugins
      await this.loadPlugins();

      // Step 1: Enumerate subdomains
      logger.info(chalk.cyan.bold('\nStep 1/4') + chalk.cyan('  Enumerating subdomains...'));
      const subdomains = await this.enumerator.enumerate();
      logger.info(`Found ${subdomains.length} unique subdomains`);

      // Execute plugin hooks for each subdomain
      for (const subdomain of subdomains) {
        await this.executePluginHook<SubdomainResult>('onSubdomainFound', subdomain);
      }

      // Step 2: Probe live hosts
      logger.info(chalk.cyan.bold('\nStep 2/4') + chalk.cyan('  Probing live hosts...'));
      const probeResults = await this.prober.probeHosts(subdomains);
      logger.info(`Probed ${probeResults.length} live hosts`);

      // Execute plugin hooks for probe results
      for (const result of probeResults) {
        await this.executePluginHook<ProbeResult>('onProbeResult', result);
      }

      // Step 3: Classify results
      logger.info(chalk.cyan.bold('Step 3/4') + chalk.cyan('  Classifying results...'));
      const classifiedResults = await this.classifier.classify(probeResults, this.plugins);
      const highRisk = classifiedResults.filter((r) => r.riskScore >= 70);
      logger.info(`Classified ${classifiedResults.length} results (${highRisk.length} high-risk)`);

      // Step 4: Run Nuclei (optional)
      let nucleiRaw: unknown = [];

      if (this.config.runNuclei && this.nucleiRunner) {
        logger.info(
          chalk.red.bold('\nStep 4/4') + chalk.red('  Running Nuclei vulnerability scan...')
        );
        const liveHosts = probeResults.map((r) => `${r.protocol}://${r.hostname}:${r.port}`);

        // Keep raw as unknown; sanitize before assigning into ScanResults
        const scanResult = await this.nucleiRunner.runScans(liveHosts);
        nucleiRaw = scanResult;
        if (Array.isArray(nucleiRaw)) {
          logger.info(`Nuclei found ${nucleiRaw.length} findings`);
        } else {
          logger.info('Nuclei returned non-array output (normalized later)');
        }
      } else {
        logger.info(chalk.gray('\nStep 4/4: Nuclei scanning skipped'));
      }

      // Compile results
      const endTime = new Date();

      // Sanitize nuclei results into a stable, safe shape
      const nucleiSafe = this.toNucleiSafe(nucleiRaw);

      const results: ScanResults = {
        domain: this.config.domain,
        subdomains,
        probeResults,
        classifiedResults,
        // Narrowed safe data assigned to ScanResults field via an intermediate safe variable.
        // If your ScanResults type declares a specific nucleiResults shape, consider updating that type
        // to accept Record<string, unknown>[] | Record<string, unknown>.
        // We cast through unknown to avoid `any` and to keep ESLint happy.
        nucleiResults: nucleiSafe as unknown as ScanResults['nucleiResults'],
        metadata: {
          startTime,
          endTime,
          duration: endTime.getTime() - startTime.getTime(),
          subdomainsFound: subdomains.length,
          liveHosts: probeResults.length,
          highRiskFindings: highRisk.length,
        },
      };

      // Execute completion hooks
      await this.executePluginHook('onComplete', results);

      // Output results
      await this.outputResults(results);

      return results;
    } catch (error) {
      logger.error('Scan failed:', error);
      throw error;
    }
  }

  /**
   * Output results in the specified format
   */
  private async outputResults(results: ScanResults): Promise<void> {
    let output: string;

    switch (this.config.format) {
      case 'json':
        output = this.formatJSON(results);
        break;
      case 'sarif':
        output = this.formatSARIF(results);
        break;
      default:
        output = this.formatText(results);
    }

    // Print to console
    if (!this.config.quiet) {
      if (!this.config.quiet) {
        if (!this.config.quiet) {
          console.log(output);
        }
      }
    }

    // Export to file
    if (this.config.export) {
      await writeFile(this.config.export, output, 'utf-8');
      logger.info(`Results exported to: ${this.config.export}`);
    }
  }

  /**
   * Format results as plain text
   */
  private formatText(results: ScanResults): string {
    const lines: string[] = [];

    // ────────────────────── Gorgeous Header ──────────────────────
    lines.push(chalk.cyan.bold('\n╔════════════════════════════════════════════════════════════╗'));
    lines.push(chalk.cyan.bold('║                     COD3X:RECON RESULTS                   ║'));
    lines.push(chalk.cyan.bold('╚════════════════════════════════════════════════════════════╝\n'));

    // ────────────────────── Summary Block ──────────────────────
    const duration = (results.metadata.duration / 1000).toFixed(2);

    lines.push(chalk.bold('   Summary'));
    lines.push(chalk.gray('   ┌────────────────────────────────────────────────────────┐'));
    lines.push(`   │ Target Domain        : ${chalk.cyan.bold(results.domain.padEnd(32))}${'│'}`);
    lines.push(`   │ Scan Duration        : ${chalk.white.bold(duration + 's').padEnd(32)}${'│'}`);
    lines.push(
      `   │ Subdomains Found     : ${chalk.cyan.bold(results.metadata.subdomainsFound.toString().padEnd(32))}${'│'}`
    );
    lines.push(
      `   │ Live Hosts           : ${chalk.green.bold(results.metadata.liveHosts.toString().padEnd(32))}${'│'}`
    );
    lines.push(
      `   │ High-Risk Findings   : ${
        results.metadata.highRiskFindings > 0
          ? chalk.red.bold(results.metadata.highRiskFindings.toString() + ' 🔥').padEnd(32)
          : chalk.green('0 (Clean)').padEnd(32)
      }${'│'}`
    );
    lines.push(chalk.gray('   └────────────────────────────────────────────────────────┘\n'));

    // ────────────────────── High-Risk Section ──────────────────────
    const highRisk = results.classifiedResults.filter((r) => r.riskScore >= 70);

    if (highRisk.length > 0) {
      lines.push(
        chalk.red.bold('   High Risk Findings') +
          chalk.red('  ⚠️  ') +
          chalk.red.bold(`(${highRisk.length})`)
      );
      lines.push(chalk.gray('   ┌────────────────────────────────────────────────────────┐'));

      highRisk.forEach((result, idx) => {
        const isLast = idx === highRisk.length - 1;
        const prefix = isLast ? '   └─ ' : '   ├─ ';

        lines.push(chalk.gray(prefix) + chalk.yellow.bold(result.hostname));
        lines.push(chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ IP        : `) + chalk.dim(result.ip));
        lines.push(
          chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ Port      : `) +
            chalk.cyan(`${result.port} (${result.protocol})`)
        );
        lines.push(
          chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ Status    : `) +
            (result.statusCode >= 200 && result.statusCode < 300
              ? chalk.green(result.statusCode + ' OK')
              : chalk.red(result.statusCode + ' Error'))
        );
        lines.push(
          chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ Risk Score: `) +
            chalk.red.bold(`${result.riskScore}/100`) +
            chalk.red('  Critical')
        );
        lines.push(
          chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ Categories: `) +
            chalk.magenta(result.categories.join(', '))
        );

        const notes = result.notes.trim();
        if (notes) {
          const noteLines = notes.split('\n');
          noteLines.forEach((line, i) => {
            const notePrefix =
              i === 0
                ? chalk.gray(`   ${isLast ? ' ' : '│'}  ├─ Note      : `)
                : chalk.gray(`   ${isLast ? ' ' : '│'}  │              `);
            lines.push(notePrefix + chalk.white(line));
          });
        }

        if (!isLast) lines.push('');
      });

      lines.push(chalk.gray('   └────────────────────────────────────────────────────────┘\n'));
    } else {
      lines.push(chalk.green.bold('   No high-risk findings detected. Target appears clean.\n'));
    }

    // ────────────────────── Final Touch ──────────────────────
    lines.push(
      chalk.dim('   Scan completed at ') +
        chalk.white(new Date(results.metadata.endTime).toLocaleString())
    );
    lines.push(chalk.dim('   Powered by COD3X:RECON — Advanced Subdomain Intelligence\n'));

    return lines.join('\n');
  }

  /**
   * Format results as JSON
   */
  private formatJSON(results: ScanResults): string {
    return JSON.stringify(results, null, 2);
  }

  /**
   * Format results as SARIF (Static Analysis Results Interchange Format)
   */
  private formatSARIF(results: ScanResults): string {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'COD3X:RECON',
              version: '1.0.0',
              informationUri: 'https://github.com/cxdexx/cod3x-recon',
            },
          },
          results: results.classifiedResults
            .filter((r) => r.riskScore >= 50)
            .map((result) => ({
              ruleId: 'subdomain-risk',
              level: result.riskScore >= 70 ? 'error' : 'warning',
              message: {
                text: result.notes,
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: `${result.protocol}://${result.hostname}:${result.port}`,
                    },
                  },
                },
              ],
              properties: {
                categories: result.categories,
                riskScore: result.riskScore,
                ip: result.ip,
                statusCode: result.statusCode,
              },
            })),
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }
}
