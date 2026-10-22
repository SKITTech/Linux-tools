# Changelog

All notable updates and fixes to System Admin Tools are documented here.

## [Unreleased] — 2026-10-22

### Changed
- **Database Comparator**: "Load Sample" now loads the latest Virtualizor structure export (`public/samples/latest_virtualizor.sql`, 76 tables).

## 2026-10-21

### Added
- **Docker Workspace** (`/#/docker`): four sub-tabs — Ask Docker (AI Q&A with Beginner/Advanced modes), Learn (structured curriculum with progress tracking), Terminal (KodeKloud-style lab layout with live environment launch), Quiz (MCQ with spaced repetition, topic filters, and missed-question review).
- **Git Workspace** (`/#/git`): four sub-tabs — Ask Git (AI Q&A with undo guidance), Learn (curriculum), Terminal (safe command simulator with allowlist + destructive-command confirmation, plus an interactive Learn Git Branching tutor), Quiz (84 questions with spaced repetition).

### Fixed
- Docker terminal simulator: support for `docker container` subcommands, `--help`/`-h` flags, and image alias handling.

## 2026-10-20

### Added
- **Error Solver**: AI model selector (Gemini Flash/Pro/3 Flash, GPT-5/5 Mini) and senior-support-agent mode with a copyable "Customer Reply" and validated reference links.

### Changed
- **Error Solver**: switched to a faster model with a trusted-host allowlist and a 2s URL validation timeout.
- **Command Library**: switched to a faster model with JSON response format for quicker command search.
- **Writing Tools**: consolidated AI requests into a single JSON call for speed; added Cmd/Ctrl+Enter shortcut, live analysis timer, and Clear button.

### Fixed
- **Bridge Generator**: IPv6 DNS servers no longer leak into IPv4 DNS commands; IPv6 addresses only appear when IPv6 is explicitly enabled in Advanced options.

## 2026-10-19

### Added
- SEO: per-route titles/descriptions/OG tags, `public/sitemap.xml`, `robots.txt` with Sitemap directive, and `public/llms.txt` for AI crawlers.

### Fixed
- Sitewide meta description length; added WebSite/Organization JSON-LD.

## 2026-10-18

### Security
- **check-port function**: DNS-based SSRF protection (connects to resolved IPs after validating against private ranges), rightmost `x-forwarded-for` entry for rate limiting, and broader IPv6 private-range detection.
- Updated `@supabase/supabase-js`, `react-router-dom`, and `recharts` to clear flagged dependency vulnerabilities.
