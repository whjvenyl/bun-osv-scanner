<!--
Copyright (c) 2025 maloma7. All rights reserved.
SPDX-License-Identifier: MIT
-->

<img src="docs/icons/logo.svg" width="100%" alt="Bun OSV Scanner" />

# Bun OSV Scanner

A production-grade security scanner for [Bun](https://bun.sh/) that integrates with [OSV.dev](https://osv.dev/) (Open Source Vulnerabilities) to detect known vulnerabilities in npm packages during installation.

[![npm version](https://img.shields.io/npm/v/bun-osv-scanner?color=dc2626)](https://npmjs.com/package/bun-osv-scanner)
[![npm downloads](https://img.shields.io/npm/dm/bun-osv-scanner?color=dc2626)](https://npmjs.com/package/bun-osv-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626)](LICENSE)
[![Built with Claude](https://img.shields.io/badge/Built_with-Claude-dc2626?style=flat&logo=claude&logoColor=dc2626)](https://anthropic.com/claude-code)
[![Checked with Biome](https://img.shields.io/badge/Checked_with-Biome-dc2626?style=flat&logo=biome&logoColor=dc2626)](https://biomejs.dev)
[![Secured with Lefthook](https://img.shields.io/badge/Secured_with-Lefthook-dc2626?style=flat&logo=lefthook&logoColor=dc2626)](https://lefthook.dev/)

## What is OSV.dev?

[OSV.dev](https://osv.dev/) is Google's open source vulnerability database that aggregates and distributes vulnerability information for open source projects. It provides:

- **Comprehensive Coverage**: Vulnerabilities from multiple sources (npm, PyPI, Go, Rust, etc.)
- **Structured Data**: Machine-readable vulnerability information with precise version ranges
- **Real-time Updates**: Continuously updated with the latest security advisories
- **Authoritative Source**: Maintained by Google and the open source community

## Features

- **Real-time Scanning**: Checks packages against OSV.dev during installation
- **High Performance**: Efficient batch queries with smart deduplication
- **Fail-safe**: Never blocks installations due to scanner errors
- **Structured Logging**: Configurable logging levels with contextual information
- **Precise Matching**: Accurate vulnerability-to-package version matching
- **Configurable**: Environment variable configuration for all settings
- **Allowlist (Ignore Rules)**: Ignore by advisory ID (CVE/GHSA/OSV) or package (optionally with version range); ignored issues are demoted to warnings and annotated with bold red “[ignored]”
- **Well Tested**: Comprehensive test suite with edge case coverage

## Installation

**No API keys or registration required** - completely free to use with zero setup beyond installation.

```bash
# Install as a dev dependency
bun add -d bun-osv-scanner
```

## Configuration

### 1. Enable the Scanner

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "bun-osv-scanner"
```

### 2. Optional: Configuration Options

The scanner can be configured via environment variables:

```bash
# Core scanner config
export OSV_LOG_LEVEL=info
export OSV_API_BASE_URL=https://api.osv.dev/v1
export OSV_TIMEOUT_MS=30000
export OSV_DISABLE_BATCH=false

# Ignore / allowlist config
# Ignore by package (name or name@range)
export BUN_OSV_IGNORE_PKG="ip@* lodash@<4.17.21"
# Ignore by advisory id(s)
export BUN_OSV_IGNORE_ADVISORY="CVE-2024-29415 GHSA-xxxx-xxxx-xxxx"
# Load extra rules from a file (JSON with { "ignore": [...] } or an array)
export BUN_OSV_IGNORE_FILE="$PWD/security/ignore.json"
# Show ignored advisories as warnings (1/true to show, 0/false to hide). Default: 1
export BUN_OSV_SHOW_IGNORED=1
```

### 3. Ignore Rules (Allowlist)

You can allow specific vulnerabilities or packages while still seeing them in the output.

- Matches advisories by ID (CVE/GHSA/OSV) or by package name (optionally with a semver range).
- Ignored advisories won’t block installs. By default they’re shown as warnings, annotated with a bold red “[ignored]”.
- Expiring rules are supported via an ISO date (rules past `expires` are ignored).
- Rules are merged from (in order): `.bun-osv.json`, `package.json` → `bunOsv.ignore`, `BUN_OSV_IGNORE_FILE`, and environment variables.

Project-level file (`.bun-osv.json`):

```json
{
  "ignore": [
    { "advisory": "CVE-2024-29415", "reason": "accepted risk", "expires": "2026-01-01" },
    { "package": "ip", "range": "*", "reason": "legacy env" },
    { "package": "lodash", "range": "<4.17.21", "reason": "pending upgrade" }
  ]
}
```

`package.json` alternative:

```json
{
  "name": "your-project",
  "bunOsv": {
    "ignore": [
      { "package": "left-pad", "range": "*" }
    ]
  }
}
```

Notes on matching:
- Advisory IDs are matched across known fields and within URLs/references (e.g., an NVD link containing “CVE-2024-29415”).
- Package names are case-insensitive; if version information isn’t available, name-only rules still apply.
- Coloring respects `NO_COLOR`. Without it, “[ignored]” is bold red.

## How It Works

### Security Scanning Process

1. **Package Detection**: Bun provides package information during installation
2. **Smart Deduplication**: Eliminates duplicate package@version queries
3. **Batch Querying**: Uses OSV.dev's efficient `/querybatch` endpoint
4. **Vulnerability Matching**: Precisely matches vulnerabilities to installed versions
5. **Severity Assessment**: Analyzes CVSS scores and database-specific severity
6. **Advisory Generation**: Creates actionable security advisories
7. **Ignore Rule Application**: Filters advisories using allowlist rules; ignored ones are demoted to warning level and annotated “[ignored]” (if `BUN_OSV_SHOW_IGNORED=1`)

### Advisory Levels

The scanner generates two types of security advisories:

#### Fatal (Installation Blocked)
- **CVSS Score**: ≥ 7.0 (High/Critical)
- **Database Severity**: CRITICAL or HIGH
- **Action**: Installation is immediately blocked
- **Examples**: Remote code execution, privilege escalation, data exposure

#### Warning (User Prompted)
- **CVSS Score**: < 7.0 (Medium/Low)
- **Database Severity**: MEDIUM, LOW, or unspecified
- **Action**: User is prompted to continue or cancel
- **TTY**: Interactive choice presented
- **Non-TTY**: Installation automatically cancelled
- **Examples**: Denial of service, information disclosure, deprecation warnings

Ignored advisories
- When a rule matches, the advisory is treated as a warning and annotated “[ignored]” so it remains visible without blocking the install (behavior controlled by `BUN_OSV_SHOW_IGNORED`).

### Error Handling Philosophy

The scanner follows a **fail-safe** approach:
- Network errors don't block installations
- Malformed responses are logged but don't halt the process
- Scanner crashes return empty advisory arrays (allows installation)
- Only genuine security threats should prevent package installation

## Usage Examples

### Basic Usage

```bash
# Scanner runs automatically during installation
bun install express
# -> Checks express and all dependencies for vulnerabilities

bun add lodash@4.17.20
# -> May warn about known lodash vulnerabilities in older versions
```

### Development Usage

```bash
# Enable debug logging to see detailed scanning information
OSV_LOG_LEVEL=debug bun install

# Test with a known vulnerable package
bun add event-stream@3.3.6
# -> Should trigger security advisory
```

### Ignore Examples

```bash
# Ignore a specific advisory (CVE)
export BUN_OSV_IGNORE_ADVISORY="CVE-2024-29415"
bun install

# Ignore a package regardless of version
export BUN_OSV_IGNORE_PKG="ip@*"
bun install

# Hide ignored advisories completely (instead of showing as warnings)
export BUN_OSV_SHOW_IGNORED=0
bun install
```

### Configuration Examples

```bash
# Increase timeout for slow networks
OSV_TIMEOUT_MS=60000 bun install

# Use custom OSV instance (advanced)
OSV_API_BASE_URL=https://api.custom-osv.dev/v1 bun install
```

## Architecture

The scanner is built with a modular, production-ready architecture:

```
src/
├── api/
│   └── client.ts           # OSV.dev API client with batch support
├── scanner/
│   └── processor.ts        # Vulnerability processing and advisory generation
├── utils/
│   ├── retry.ts           # Robust retry logic with exponential backoff
│   ├── semver.ts          # OSV semver range matching
│   └── severity.ts        # CVSS and severity assessment
├── constants.ts           # Centralized configuration management
├── logger.ts             # Structured logging with configurable levels
├── schema.ts             # Zod schemas for OSV API responses
├── types.ts              # TypeScript type definitions
└── index.ts              # Main scanner implementation
```

### Key Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Error Isolation**: Failures in one component don't cascade to others
3. **Performance Optimization**: Batch processing, deduplication, and concurrent requests
4. **Observability**: Comprehensive logging for debugging and monitoring
5. **Type Safety**: Full TypeScript coverage with runtime validation

## Testing

```bash
# Run the test suite
bun test

# Run with coverage
bun test --coverage

# Type checking
bun run typecheck

# Linting
bun run lint
```

### Test Coverage

- Known vulnerable packages detection
- Safe package verification  
- Multiple package scenarios
- Version-specific vulnerability matching
- Network failure handling
- Edge cases and error conditions

## Development

### Building from Source

```bash
git clone https://github.com/maloma7/bun-osv-scanner.git
cd bun-osv-scanner
bun install
bun run build
```

### Contributing

We do not accept pull requests as this package is actively maintained. However, we appreciate if developers report bugs or suggest features by [opening an issue](https://github.com/maloma7/bun-osv-scanner/issues/new).

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## API Reference

### OSV.dev Integration

This scanner integrates with the following OSV.dev endpoints:

- **POST /v1/querybatch**: Batch vulnerability queries for multiple packages
- **POST /v1/query**: Individual package queries with pagination support

For complete OSV.dev API documentation, visit: https://google.github.io/osv.dev/api/

### Configuration Reference

| Environment Variable         | Default                 | Description                                                                 |
|-----------------------------|-------------------------|-----------------------------------------------------------------------------|
| `OSV_LOG_LEVEL`             | `info`                  | Logging level: debug, info, warn, error                                     |
| `OSV_API_BASE_URL`          | `https://api.osv.dev/v1`| OSV API base URL                                                            |
| `OSV_TIMEOUT_MS`            | `30000`                 | Request timeout in milliseconds                                             |
| `OSV_DISABLE_BATCH`         | `false`                 | Disable batch queries (use individual queries)                              |
| `BUN_OSV_IGNORE_PKG`        | —                       | Space/comma-separated package tokens to ignore (e.g., `ip@* lodash@<4.17.21`) |
| `BUN_OSV_IGNORE_ADVISORY`   | —                       | Space/comma-separated advisory IDs to ignore (CVE-/GHSA-/OSV-)              |
| `BUN_OSV_IGNORE_FILE`       | —                       | Path to JSON file containing ignore rules                                   |
| `BUN_OSV_SHOW_IGNORED`      | `1`                     | If `1/true`, show ignored advisories as warnings; if `0/false`, hide them   |

## Troubleshooting

### Common Issues

**Scanner not running during installation?**
- Verify `bunfig.toml` configuration
- Check that the package is installed as a dev dependency
- Enable debug logging: `OSV_LOG_LEVEL=debug bun install`

**Ignore rule doesn’t apply?**
- Ensure the rule file is in the project being installed (or set `BUN_OSV_IGNORE_FILE`).
- Enable debug logs to see “Loaded N ignore rules”.
- Match by CVE/GHSA if the advisory uses a URL (e.g., NVD link). Example: `{ "advisory": "CVE-2024-29415" }`.
- Package rules are case-insensitive; `"range": "*"` ignores all versions.
- Check `expires` hasn’t passed.

**Network timeouts?**
- Increase timeout: `OSV_TIMEOUT_MS=60000`
- Check internet connectivity to osv.dev
- Consider corporate firewall restrictions

**Too many false positives?**
- OSV.dev data is authoritative - verify vulnerabilities manually
- Check if you're using an outdated package version
- Report false positives to the OSV.dev project

### Debug Mode

Enable comprehensive debug output:

```bash
OSV_LOG_LEVEL=debug bun install your-package
```

This shows:
- Package deduplication statistics
- API request/response details  
- Vulnerability matching decisions (including ignore-rule matches)
- Performance timing information

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **OSV.dev Team**: For maintaining the comprehensive vulnerability database
- **Bun Team**: For the innovative Security Scanner API

## Related Projects

- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [OSV.dev](https://osv.dev/) - Open Source Vulnerabilities database

---

**Last Updated**: September 12, 2025  
**Version**: 1.0.0

*This documentation is a living document and will be updated as the project evolves and new features are added.*