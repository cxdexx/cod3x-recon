/**
 * Logging utility with levels and colors
 */

import chalk from 'chalk';
import type { LogLevel } from '../core/types.js';

/**
 * Logger class with configurable levels
 */
class Logger {
  private level: LogLevel = 'info';
  private quiet = false;

  /**
   * Set log level
   */
  setLevel(level: LogLevel) {
    this.level = level;
  }

  /**
   * Set quiet mode
   */
  setQuiet(quiet: boolean) {
    this.quiet = quiet;
  }

  /**
   * Check if level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    if (this.quiet) {
      return false;
    }

    const levels: Record<LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
    };

    return levels[level] >= levels[this.level];
  }

  /**
   * Debug log
   */
  debug(message: string, ...args: unknown[]) {
    if (this.shouldLog('debug')) {
      console.log(chalk.gray(`[DEBUG] ${message}`), ...args);
    }
  }

  /**
   * Info log
   */
  info(message: string, ...args: unknown[]) {
    if (this.shouldLog('info')) {
      console.log(chalk.blue(`[INFO] ${message}`), ...args);
    }
  }

  /**
   * Warning log
   */
  warn(message: string, ...args: unknown[]) {
    if (this.shouldLog('warn')) {
      console.warn(chalk.yellow(`[WARN] ${message}`), ...args);
    }
  }

  /**
   * Error log
   */
  error(message: string, ...args: unknown[]) {
    if (this.shouldLog('error')) {
      console.error(chalk.red(`[ERROR] ${message}`), ...args);
    }
  }

  /**
   * Success log (always info level)
   */
  success(message: string, ...args: unknown[]) {
    if (this.shouldLog('info')) {
      console.log(chalk.green(`[✓] ${message}`), ...args);
    }
  }

  /**
   * Progress log (always info level)
   */
  progress(message: string, current: number, total: number) {
    if (this.shouldLog('info')) {
      const percentage = Math.round((current / total) * 100);
      console.log(chalk.cyan(`[${percentage}%] ${message} (${current}/${total})`));
    }
  }
}

/**
 * Global logger instance
 */
export const logger = new Logger();
