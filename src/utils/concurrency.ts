/**
 * Concurrency control utilities
 */

import pLimit from 'p-limit';

/**
 * Execute tasks with controlled concurrency
 * @param tasks Array of async tasks
 * @param concurrency Maximum concurrent tasks
 * @returns Array of results
 */
export async function executeConcurrent<T>(
  tasks: Array<() => Promise<T>>,
  concurrency = 10
): Promise<T[]> {
  const limit = pLimit(concurrency);
  const wrappedTasks = tasks.map((task) => limit(task));
  return await Promise.all(wrappedTasks);
}

/**
 * Execute tasks with concurrency and error handling
 * @param tasks Array of async tasks
 * @param concurrency Maximum concurrent tasks
 * @returns Array of settled results
 */
export async function executeConcurrentSettled<T>(
  tasks: Array<() => Promise<T>>,
  concurrency = 10
): Promise<PromiseSettledResult<T>[]> {
  const limit = pLimit(concurrency);
  const wrappedTasks = tasks.map((task) => limit(task));
  return await Promise.allSettled(wrappedTasks);
}

/**
 * Batch process items with concurrency control
 * @param items Array of items to process
 * @param processor Function to process each item
 * @param concurrency Maximum concurrent tasks
 * @returns Array of results
 */
export async function batchProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  concurrency = 10
): Promise<R[]> {
  const limit = pLimit(concurrency);
  const tasks = items.map((item) => limit(() => processor(item)));
  return await Promise.all(tasks);
}

/**
 * Retry a task with exponential backoff
 * @param task Task to retry
 * @param maxRetries Maximum number of retries
 * @param delayMs Initial delay in milliseconds
 * @returns Task result
 */
export async function retryWithBackoff<T>(
  task: () => Promise<T>,
  maxRetries = 3,
  delayMs = 1000
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await task();
    } catch (error) {
      lastError = error as Error;

      if (attempt < maxRetries) {
        const delay = delayMs * Math.pow(2, attempt);
        await sleep(delay);
      }
    }
  }

  throw lastError;
}

/**
 * Sleep for specified milliseconds
 * @param ms Milliseconds to sleep
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create a rate limiter
 * @param maxRequests Maximum requests per interval
 * @param intervalMs Interval in milliseconds
 */
export function createRateLimiter(maxRequests: number, intervalMs: number) {
  const queue: Array<() => void> = [];
  let currentRequests = 0;

  const processQueue = () => {
    if (queue.length === 0 || currentRequests >= maxRequests) {
      return;
    }

    // Safely shift from the queue
    const resolve = queue.shift();

    // Explicit check instead of non-null assertion (!)
    if (resolve) {
      currentRequests++;
      resolve();

      setTimeout(() => {
        currentRequests--;
        processQueue();
      }, intervalMs / maxRequests);
    }
  };

  return async () => {
    return new Promise<void>((resolve) => {
      queue.push(resolve);
      processQueue();
    });
  };
}
