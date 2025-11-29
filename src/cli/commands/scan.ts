/**
 * Scan command implementation
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { App } from '../../core/app.js';
import type { AppConfig } from '../../core/types.js';

export const scanCommand = new Command('scan')
  .description('Scan a domain for subdomains and classify them')
  .requiredOption('-d, --domain <domain>', 'Target domain to scan')
  .option('-c, --concurrency <number>', 'Concurrent requests', parseInt, 10)
  .option('-t, --timeout <ms>', 'Request timeout in milliseconds', parseInt, 3000)
  .option('-f, --format <type>', 'Output format: text|json|sarif', 'text')
  .option('-e, --export <file>', 'Export results to file')
  .option('--run-nuclei', 'Run Nuclei scans on discovered hosts', false)
  .option('--plugins <paths...>', 'Load custom plugins (space-separated paths)', [])
  .option('-q, --quiet', 'Suppress output', false)
  .action(
    async (options: {
      domain: string;
      concurrency: number;
      timeout: number;
      format: string;
      export?: string;
      runNuclei: boolean;
      plugins: string[];
      quiet: boolean;
    }) => {
      try {
        // ────────────────────────────── Validation (unchanged) ──────────────────────────────
        if (!isValidDomain(options.domain)) {
          throw new Error(`Invalid domain: ${options.domain}`);
        }
        if (!['text', 'json', 'sarif'].includes(options.format)) {
          throw new Error(`Invalid format: ${options.format}. Use text, json, or sarif.`);
        }

        const config: AppConfig = {
          domain: options.domain,
          concurrency: options.concurrency,
          timeout: options.timeout,
          format: options.format as 'text' | 'json' | 'sarif',
          export: options.export,
          runNuclei: options.runNuclei,
          plugins: options.plugins,
          quiet: options.quiet,
        };

        // ────────────────────────────── Start Banner (Beautiful!) ──────────────────────────────
        if (!config.quiet) {
          console.log(
            chalk.cyan.bold('\n╔════════════════════════════════════════════════════════════╗\n') +
              chalk.cyan.bold('║                     🔍 COD3X:RECON                        ║\n') +
              chalk.cyan.bold('╚════════════════════════════════════════════════════════════╝\n')
          );

          console.log(
            chalk.bold('   Target') +
              chalk.gray(' ──▶ ') +
              chalk.cyan.bold(config.domain) +
              chalk.gray(' (primary)\n')
          );

          console.log(chalk.dim('   Configuration'));
          console.log(
            chalk.gray('   ├─ Concurrency      : ') +
              chalk.white.bold(config.concurrency.toString())
          );
          console.log(chalk.gray('   ├─ Timeout          : ') + chalk.white(`${config.timeout}ms`));
          console.log(
            chalk.gray('   ├─ Output Format    : ') +
              chalk.magenta.bold(config.format.toUpperCase())
          );
          if (config.export) {
            console.log(chalk.gray('   ├─ Export File      : ') + chalk.blue(config.export));
          }
          if (config.runNuclei) {
            console.log(chalk.gray('   ├─ Nuclei Scanner   : ') + chalk.red.bold('Enabled'));
          }
          if (config.plugins.length > 0) {
            console.log(
              chalk.gray('   └─ Custom Plugins   : ') +
                chalk.green(config.plugins.join(chalk.gray(', ')))
            );
          } else {
            console.log(chalk.gray('   └─ Custom Plugins   : ') + chalk.dim('None'));
          }
          console.log(
            chalk.dim('\n   ┌─ Starting reconnaissance scan... ─────────────────────────────┐')
          );
          console.log(
            chalk.dim('   └──────────────────────────────────────────────────────────────┘\n')
          );
        }

        // ────────────────────────────── Run Scan (unchanged) ──────────────────────────────
        const app = new App(config);
        const results = await app.run();

        // ────────────────────────────── Success Summary (Gorgeous!) ──────────────────────────────
        if (!config.quiet) {
          console.log(
            chalk.green.bold('\n   ✔ Scan completed successfully!\n') +
              chalk.green.bold(
                '   ──────────────────────────────────────────────────────────────\n'
              )
          );

          console.log(chalk.bold('   Results Summary'));
          console.log(
            chalk.gray('   ├─ Subdomains discovered   : ') +
              chalk.cyan.bold(results.subdomains.length.toString())
          );
          console.log(
            chalk.gray('   ├─ Live hosts confirmed    : ') +
              chalk.green.bold(results.probeResults.length.toString())
          );

          const highRisk = results.classifiedResults.filter((r) => r.riskScore >= 70);
          const mediumRisk = results.classifiedResults.filter(
            (r) => r.riskScore >= 40 && r.riskScore < 70
          );

          if (highRisk.length > 0) {
            console.log(
              chalk.gray('   ├─ ') +
                chalk.red.bold(`High-risk findings      : ${highRisk.length}`) +
                chalk.red(' 🔥')
            );
          }
          if (mediumRisk.length > 0) {
            console.log(
              chalk.gray('   ├─ Medium-risk findings   : ') +
                chalk.yellow.bold(mediumRisk.length.toString())
            );
          }
          if (highRisk.length === 0 && mediumRisk.length === 0) {
            console.log(
              chalk.gray('   ├─ Risk findings           : ') + chalk.green('None detected')
            );
          }

          if (config.export) {
            console.log(
              chalk.gray('   └─ Exported to             : ') + chalk.blue.underline(config.export)
            );
          } else {
            console.log(chalk.gray('   └─ Export                  : ') + chalk.dim('Disabled'));
          }

          console.log(
            chalk.dim('\n   ┌─ Scan finished. Review output above or exported file. ────────┐')
          );
          console.log(
            chalk.dim('   └──────────────────────────────────────────────────────────────┘\n')
          );
        }

        process.exit(0);
      } catch (error) {
        if (error instanceof Error) {
          console.log(
            chalk.red.bold('\n   ✘ Scan failed\n') +
              chalk.red.bold('   ──────────────────────────────────────────────────────────────\n')
          );
          console.log(chalk.red(`   Error: `) + chalk.white(error.message));
          console.log(chalk.dim('\n   Check your input arguments or network connectivity.\n'));
        }
        process.exit(1);
      }
    }
  );
/**
 * Validate domain format
 */
function isValidDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}
