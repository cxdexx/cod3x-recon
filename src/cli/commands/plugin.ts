import { Command } from 'commander';
import chalk from 'chalk';
import { readdir, stat } from 'fs/promises';
import { join } from 'path';
import { error } from 'console';

// Define the expected structure of the plugin export
interface PluginInfo {
  name: string;
  version?: string;
  // Add other required plugin fields here if necessary
}

// Define the shape of the imported module
interface PluginModule {
  plugin?: PluginInfo;
}
export const pluginCommand = new Command('plugin')
  .description('Manage COD3X plugins')
  .action(async () => {
    // Header - bold, branded, with subtle separator
    console.log(
      chalk.cyan.bold('\n╔════════════════════════════════════╗\n') +
        chalk.cyan.bold('║    🔌 COD3X Plugin System          ║\n') +
        chalk.cyan.bold('╚════════════════════════════════════╝\n')
    );

    await listPlugins();

    // Usage hint section - clean and prominent
    console.log(chalk.dim('┌─ Usage Example'));
    console.log(chalk.dim('│'));
    console.log(
      `   ${chalk.bold('cod3x')} scan -d example.com ${chalk.cyan('--plugins')} ${chalk.gray('./path/to/plugins')}`
    );
    console.log(chalk.dim('└──────────────────────────────────────────────\n'));

    // Footer guidance
    console.log(
      chalk.gray('💡 Tip: Place your plugins in ') +
        chalk.bold('./plugins/') +
        chalk.gray(' directory')
    );
    console.log(
      chalk.gray('📖 Plugin Development → ') +
        chalk.underline('README.md') +
        chalk.gray(' for full API docs\n')
    );
  });

/**
 * List available plugins in the plugins directory
 */
async function listPlugins() {
  try {
    const pluginsDir = join(process.cwd(), 'plugins');

    try {
      const entries = await readdir(pluginsDir);

      if (entries.length === 0) {
        console.log(chalk.yellow('No plugins found in ./plugins/\n'));
        return;
      }

      console.log(chalk.white('Available plugins:\n'));

      for (const entry of entries) {
        const entryPath = join(pluginsDir, entry);
        const stats = await stat(entryPath);

        if (stats.isDirectory()) {
          try {
            // Try to load plugin info
            const pluginPath = join(entryPath, 'index.js');

            // FIX: Assert the imported module type to PluginModule to resolve 'any' warnings
            const pluginModule = (await import(pluginPath)) as PluginModule;

            if (pluginModule.plugin) {
              // Access is now type-safe
              console.log(chalk.green(`  ✓ ${pluginModule.plugin.name}`));
              console.log(chalk.gray(`    Version: ${pluginModule.plugin.version || 'unknown'}`));
              console.log(chalk.gray(`    Path: ./plugins/${entry}`));
              console.log();
            }
          } catch (error) {
            console.log(chalk.red(`  ✗ ${entry} (failed to load)`));
            if (error instanceof Error) {
              console.log(chalk.gray(`    Error: ${error.message}`));
            }
            console.log();
          }
        }
      }
    } catch (error) {
      console.log(
        chalk.yellow('No plugins directory found. Create ./plugins/ to add custom plugins.\n')
      );
    }
    if (error instanceof Error && !error.message.includes('outputHelp')) {
      console.error(error.message);
    }

    console.log(chalk.gray('Plugin Development Guide:'));
    console.log(chalk.white('  See README.md for plugin API documentation\n'));
  } catch (error) {
    console.error(chalk.red('Error listing plugins:'), error);
  }
}
