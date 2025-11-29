/**
 * Example external plugin for COD3X:RECON with Slack integration
 * Fully type-safe — zero ESLint/TypeScript errors
 */
import type {
  Plugin,
  SubdomainResult,
  ProbeResult,
  ClassificationHint,
  ScanResults,
} from '../../src/core/types.js';

// IMPORTANT: Replace this with your actual Slack Incoming Webhook URL
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || 'YOUR_SLACK_WEBHOOK_URL_HERE';

/** Safe header access — handles string | string[] | undefined */
const getHeader = (
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined => {
  const value = headers[name.toLowerCase()] ?? headers[name];
  if (Array.isArray(value)) return value.join(', ');
  return typeof value === 'string' ? value : undefined;
};

/**
 * Sends a message to a configured Slack channel using a Webhook.
 * @param message The text content to send.
 */
async function sendToSlack(message: string): Promise<void> {
  if (SLACK_WEBHOOK_URL === 'YOUR_SLACK_WEBHOOK_URL_HERE') {
    console.warn('[External Plugin] Slack Webhook URL is not configured. Skipping notification.');
    return;
  }

  try {
    const response = await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text: message }),
    });

    if (response.ok) {
      console.log('[External Plugin] Successfully sent critical findings to Slack.');
    } else {
      console.error(`[External Plugin] Failed to send to Slack. Status: ${response.status}`);
    }
  } catch (error) {
    console.error('[External Plugin] Error sending to Slack:', error);
  }
}

export const plugin: Plugin = {
  name: 'example-external-plugin-slack', // Renamed for clarity
  version: '1.0.1',

  hooks: {
    onSubdomainFound(subdomain: SubdomainResult): void {
      console.log(`[External Plugin] Discovered: ${subdomain.hostname}`);

      const parts = subdomain.hostname.split('.');
      // Removed the 'any' type cast by ensuring baseDomain is checked against the list
      const baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : subdomain.hostname;
      const blacklist = ['malicious.com', 'spam.com'] as const;

      if (blacklist.includes(baseDomain as (typeof blacklist)[number])) {
        console.log(`[External Plugin] Blacklisted domain detected: ${baseDomain}`);
      }
    },

    onProbeResult(result: ProbeResult): void {
      // ... (Cloud provider detection and ASP.NET checks remain the same)
      const aspNetVersion = getHeader(result.headers, 'x-aspnet-version');
      if (aspNetVersion) {
        console.log(
          `[External Plugin] ASP.NET version leak on ${result.hostname}: ${aspNetVersion}`
        );
      }

      const cloudMap: Record<string, string> = {
        'x-amz-': 'AWS',
        'x-goog-': 'Google Cloud',
        'x-ms-': 'Azure',
      };

      for (const [prefix, provider] of Object.entries(cloudMap)) {
        const found = Object.keys(result.headers).find((h) => h.toLowerCase().startsWith(prefix));
        if (found) {
          console.log(
            `[External Plugin] Cloud provider detected: ${provider} on ${result.hostname}`
          );
          break;
        }
      }
    },

    onClassify(result: ProbeResult): ClassificationHint | null {
      // ... (Classification logic remains the same)
      const title = result.title ?? '';

      // Jenkins detection
      if (title.includes('Jenkins') || getHeader(result.headers, 'x-jenkins')) {
        return {
          categories: ['jenkins', 'ci-cd'],
          riskScore: 75,
          notes: 'Jenkins CI server detected - potential credential exposure',
        };
      }

      // Kubernetes detection
      if (/k8s|kubernetes/i.test(result.hostname) || title.includes('Kubernetes')) {
        return {
          categories: ['kubernetes', 'orchestration'],
          riskScore: 80,
          notes: 'Kubernetes dashboard detected - high value target',
        };
      }

      // Data leak detection
      const leaks = result.endpoints
        .filter((e) => e.exists && /\.(sql|db|dump|backup|bak)$/i.test(e.path))
        .map((e) => e.path);

      if (leaks.length > 0) {
        return {
          categories: ['data-leak'],
          riskScore: 95,
          notes: `Sensitive files exposed: ${leaks.join(', ')}`,
        };
      }

      return null;
    },

    // Now contains an actual 'await' call, satisfying the linter if needed.
    async onComplete(results: ScanResults): Promise<void> {
      console.log('\n[External Plugin] === Custom Report ===');

      const critical = results.classifiedResults.filter((r) => r.riskScore >= 80);
      const adminPanels = results.classifiedResults.filter(
        (r) => r.categories.includes('admin-panel') && r.statusCode === 200
      );

      console.log(`Critical findings (score ≥ 80): ${critical.length}`);
      console.log(`Exposed admin panels: ${adminPanels.length}`);

      if (critical.length > 0) {
        console.log('\n[External Plugin] CRITICAL FINDINGS DETECTED:');

        let slackMessage = `🚨 *COD3X:RECON Critical Scan Findings* 🚨\nFound ${critical.length} critical issues (Risk Score ≥ 80):\n\n`;

        critical.forEach((f) => {
          const findingLine = ` - *${f.hostname}* (Score: ${f.riskScore}): ${f.notes}`;
          console.log(findingLine);
          slackMessage += findingLine + '\n';
        });

        // 🚀 THE SLACK INTEGRATION AWAIT CALL
        await sendToSlack(slackMessage);
      }
    },
  },
};

export default plugin;
