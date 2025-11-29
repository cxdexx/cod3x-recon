# COD3X:RECON 🔍

**Context-Aware Subdomain Enumerator** with intelligent classification, risk scoring, and Nuclei integration.

## Features

- 🌐 **Multi-Source Enumeration**: Certificate Transparency (crt.sh), DNS bruteforce, wordlist-based discovery
- 🎯 **Smart Probing**: HTTP/HTTPS fingerprinting, TLS inspection, endpoint discovery
- 🧠 **Intelligent Classification**: Pattern-based risk scoring with extensible rules engine
- 🔌 **Plugin System**: Extensible architecture for custom integrations
- ⚡ **Performance Optimized**: Connection pooling, caching, bounded concurrency
- 🛡️ **Nuclei Integration**: Automated vulnerability scanning on discovered assets
- 📊 **Multiple Output Formats**: Text, JSON, SARIF for CI/CD integration

## Installation

```bash
npm install -g cod3x-recon
```

Or from source:

```bash
git clone https://github.com/cxdexx/cod3x-recon.git
cd cod3x-recon
npm install
npm run build
npm link
```

## Usage

### Basic Scan

```bash
cod3x scan -d example.com
```

### Advanced Options

```bash
cod3x scan -d example.com \
  --concurrency 20 \
  --timeout 5000 \
  --format json \
  --export results.json \
  --run-nuclei \
  --plugins ./plugins/custom-plugin
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain <domain>` | Target domain (required) | - |
| `-c, --concurrency <num>` | Concurrent requests | 10 |
| `-t, --timeout <ms>` | Request timeout | 3000 |
| `-f, --format <type>` | Output format (text\|json\|sarif) | text |
| `-e, --export <file>` | Export results to file | - |
| `--run-nuclei` | Run Nuclei scans on live hosts | false |
| `--plugins <paths...>` | Load custom plugins | [] |
| `-q, --quiet` | Suppress output | false |

## Output Example

```
[+] Enumerating subdomains for example.com...
[+] Found 127 subdomains from crt.sh
[+] DNS verification: 89 live hosts
[+] Probing hosts...

┌─────────────────────────────────────────────────────────┐
│ HIGH RISK FINDINGS                                       │
├─────────────────────────────────────────────────────────┤
│ admin.example.com [192.168.1.10]                        │
│   Status: 200 OK                                        │
│   Risk Score: 85/100                                    │
│   Categories: admin-panel, directory-listing            │
│   Notes: Exposed admin panel with directory listing    │
│                                                          │
│ api-staging.example.com [10.0.0.5]                     │
│   Status: 200 OK                                        │
│   Risk Score: 75/100                                    │
│   Categories: staging, api, cors-unsafe                 │
│   Notes: CORS wildcard (*) policy detected             │
└─────────────────────────────────────────────────────────┘

[+] Scan complete: 89 hosts, 12 high-risk findings
```

## Plugin Development

Create custom plugins to extend COD3X:RECON functionality:

```typescript
// plugins/my-plugin/index.ts
import { Plugin, SubdomainResult, ProbeResult } from 'cod3x-recon';

export const plugin: Plugin = {
  name: 'my-custom-plugin',
  version: '1.0.0',
  
  hooks: {
    onSubdomainFound: async (subdomain: SubdomainResult) => {
      console.log(`[Plugin] Found: ${subdomain.hostname}`);
    },
    
    onProbeResult: async (result: ProbeResult) => {
      if (result.statusCode === 200) {
        // Custom logic here
      }
    },
    
    onClassify: (result: ProbeResult) => {
      // Add custom classification rules
      if (result.headers['x-custom-header']) {
        return {
          categories: ['custom-category'],
          riskScore: 50,
          notes: 'Custom header detected',
        };
      }
      return null;
    },
  },
};
```

Load your plugin:

```bash
cod3x scan -d example.com --plugins ./plugins/my-plugin
```

## Architecture

```
src/
├── cli/          # CLI interface (Commander.js)
├── core/         # Core enumeration engine
│   ├── enumerator.ts    # Multi-source subdomain discovery
│   ├── probe.ts         # HTTP/HTTPS probing
│   ├── classifier.ts    # Risk scoring and classification
│   └── cache.ts         # LRU caching layer
├── plugins/      # Plugin system
├── nuclei/       # Nuclei integration
└── utils/        # Shared utilities
```

## Development

### Setup

```bash
npm install
npm run dev
```

### Testing

```bash
npm test              # Run tests
npm run test:watch   # Watch mode
```

### Linting & Formatting

```bash
npm run lint         # ESLint
npm run format       # Prettier
```

### Building

```bash
npm run build        # Compile TypeScript
```

## Configuration

### Wordlists

Place custom wordlists in `templates/wordlists/`:

```
templates/wordlists/
├── common-subdomains.txt
├── api-endpoints.txt
└── admin-paths.txt
```

### Nuclei Templates

Add custom Nuclei templates in `src/nuclei/templates/`:

```yaml
id: custom-check
info:
  name: Custom Security Check
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
```

## Performance Tips

1. **Adjust Concurrency**: Increase for faster scans, decrease for rate-limited targets
2. **Enable Caching**: Reduces redundant DNS/HTTP requests
3. **Use Wordlist Filtering**: Smaller wordlists = faster enumeration
4. **Skip Nuclei**: Disable for quick reconnaissance

## Security Best Practices

- Always obtain authorization before scanning
- Respect rate limits and robots.txt
- Use VPN/proxy for sensitive assessments
- Sanitize outputs before sharing

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Credits

Built with ❤️ by the CODEX Security Team

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Users are responsible for complying with applicable laws.