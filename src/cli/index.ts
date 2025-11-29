#!/usr/bin/env node

/**
 * COD3X:RECON CLI Entry Point
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { scanCommand } from './commands/scan.js';
import { pluginCommand } from './commands/plugin.js';

const program = new Command();

program
  .name('cod3x')
  .description('Context-Aware Subdomain Enumerator with intelligent classification')
  .version('1.0.0');

// ASCII Art Banner
const banner = `
${chalk.cyan('╔═══════════════════════════════════════════════════════════╗')}
${chalk.cyan('║')}  ${chalk.bold.white('COD3X:RECON')} ${chalk.gray('v1.0.0')}                                  ${chalk.cyan('║')}
${chalk.cyan('║')}  ${chalk.gray('Context-Aware Subdomain Enumerator')}                ${chalk.cyan('║')}
${chalk.cyan('╚═══════════════════════════════════════════════════════════╝')}
`;

program.addHelpText('beforeAll', banner);

// Register commands
program.addCommand(scanCommand);
program.addCommand(pluginCommand);

// Error handling
program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  if (error instanceof Error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}\n`));
    process.exit(1);
  }
  throw error;
}
