# driftwatch

**Catch browser extensions that turn risky between releases.**

Most extension scanners judge one single version in isolation. But the classic attack is a
clean extension that gets sold or hijacked and then ships a "routine" update with a
new permission, broader site access or a loader for remote code. `driftwatch` diffs
two releases and scores what changed, so the dangerous update stands out...

zero dependencies (yay) and works offline on files you already have.

```
$ driftwatch diff testdata/demo/v1.0.0 testdata/demo/v1.1.0

driftwatch  Sample Notes  1.0.0 -> 1.1.0
risk 100/100  CRITICAL

[CRITICAL +60] PERM_ADDED  New permissions granted
      - cookies
      - scripting
      - webRequest
[CRITICAL +50] CSP_WEAKENED  Content-Security-Policy now allows riskier script sources
      - extension_pages: script-src allows unsafe-eval
      - extension_pages: script-src loads remote code from https://cdn.stats-collector.invalid
[CRITICAL +40] HOST_BROADENED  Access to every website
      - <all_urls>
[CRITICAL +30] CONTENT_SCRIPT_BROADENED  Content scripts now run on every website
[HIGH +25] OBFUSCATION_SPIKE  Obfuscated-looking code: 1 file(s), 81% of script bytes (was 0, 0%)
      - loader.js
[HIGH +20] DYNAMIC_CODE_INTRODUCED  eval/new Function appeared for the first time (1 call sites)
...
```

## Install

```
go install github.com/radnyxx/driftwatch@latest
# or
git clone https://github.com/radnyxx/driftwatch && cd driftwatch && go build -o driftwatch .
```

## Usage

```
driftwatch diff [flags] <old> <new>         compare two releases
driftwatch timeline [flags] <v1> <v2> ...   risk trend across many releases (oldest first)
driftwatch inspect <path>                   dump extracted facts as JSON
```

`<old>` / `<new>` can be a `.crx` (CRX2 and CRX3), `.xpi`, `.zip`, or an unpacked directory.

| flag | meaning |
|---|---|
| `-json` | machine-readable output |
| `-fail-on N` | exit code 2 when a risk score is `>= N` (use it as a CI gate) |
| `-ignore-domain HOST` | don't report `HOST` or its subdomains as new endpoints (repeatable) |

```
$ driftwatch timeline v1.0.0.crx v1.1.0.crx v1.2.0.crx
VERSION  PERMS  HOSTS  REMOTE  OBFUSC  RISK  VERDICT
1.0.0    2      1      0       0       -     -
1.1.0    5      1      2       1       100   critical
```

## What it checks

| code | what triggers it | points |
|---|---|---|
| `PERM_ADDED` | new API permission (weighted: `debugger` 35 ... `storage` 1; optional = half) | up to 60 |
| `HOST_BROADENED` | newly gained all-sites access (`<all_urls>`, `*://*/*`) | 40 |
| `HOST_ADDED` | new specific or wildcard-subdomain host patterns | up to 20 |
| `CONTENT_SCRIPT_BROADENED` / `_ADDED` | content scripts on all sites / more sites | 30 / up to 18 |
| `CONTENT_SCRIPT_MAIN_WORLD` | a content script now runs in the page's JS world | 10 |
| `CSP_WEAKENED` | new `unsafe-eval`, `unsafe-inline`, wildcard or remote `script-src` | 25 each, max 50 |
| `UPDATE_URL_CHANGED` | self-hosted update URL (outside the stores) | 35 |
| `EXTERNALLY_CONNECTABLE_ADDED` | websites can message the extension | 10 |
| `NAME_CHANGED` | extension renamed (typical of transferred listings) | 10 |
| `NEW_REMOTE_DOMAIN` / `NEW_REMOTE_IP` | new hosts / raw IPs referenced in code | up to 24 / 30 |
| `DYNAMIC_CODE_INTRODUCED` / `_INCREASED` | `eval` / `new Function` first appears, or jumps by 5+ | 20 / 8 |
| `LOADER_INCREASED` | more `importScripts` / injected `<script>` | 4 |
| `OBFUSCATION_SPIKE` | more files that look obfuscated, or a big jump in their share | 25 (12 if already present) |

Scores add up and cap at 100. Verdicts: `low` < 15, `medium` < 40, `high` < 70, `critical` >= 70.
Re-adding something that already existed (for example a second `<all_urls>` variant) costs nothing.

## Limitations

- **scoring** A high score means 'a human should read this diff', not
  'this is malware'. Plenty of legitimate updates add permissions.
- **Obfuscation detection** needs at least two independent signals (many `_0x...` names,
  heavy `\xNN` escapes, `eval` next to `atob`/big encoded blobs). Plain minified code is
  deliberately not flagged. Bundlers that rename files can still shift the file lists.
- **Remote hosts** are matched by full hostname (no public-suffix list), so CDN subdomain
  churn can be noisy. Use `-ignore-domain`.
- It reads files you give it. It does not download from stores and does not run any code.
- Only JS and HTML are scanned. WASM and other payloads are not.

## Roadmap

- [ ] Android: `AndroidManifest.xml` permission/component drift + tracker SDK signatures
- [ ] `driftwatch watch`: scheduled snapshots of a watchlist (GitHub Action) to build history
- [ ] SARIF output for GitHub code scanning
- [ ] HTML report with a permissions-over-time chart

## Development

```
go vet ./... && go test -race ./...
```

`testdata/demo` holds two tiny benign extensions. v1.1.0 is deliberately written to trip
the rules (its "suspicious" hosts use the reserved `.invalid` TLD and an RFC 5737 documentation
IP, and its "obfuscated" loader just decodes `console.log('demo')`).

## License

MIT
