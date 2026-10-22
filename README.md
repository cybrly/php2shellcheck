# PHP2SHELL CHECK (`php2shellcheck.py`)

Asynchronous HTTP/HTTPS header inspection that fingerprints PHP and compares the version against the PHP2Shell fixed releases.

## 1. Overview

**PHP2SHELL CHECK** probes ports **80**, **443**, **8080**, and **8443** and looks for PHP in three places:

- `X-Powered-By` containing `PHP` (for example `PHP/8.2.12` or `ASP.NET, PHP/8.2.12`)
- `Server` containing a `PHP/x.y.z` token (for example `Apache/2.4.58 (Ubuntu) PHP/8.1.2`)
- A `PHPSESSID` cookie (PHP is present, but no version is shown)

It requests `/`, follows redirects that stay on the same host, port, and scheme (up to 3), and tries `/index.php` when a port answers without any PHP signal.

The CVEs are:

- **CVE-2026-109618** — RCE via OOM corruption ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)).
- **CVE-2026-109619** — RCE via stale global state ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)).

Each PHP signal is given a status:

| Status | Meaning |
| --- | --- |
| `VULNERABLE` | 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, or 8.5 < 8.5.12 |
| `END OF LIFE` | 8.1 or older. These branches are not covered by the advisories and get no fix. Upgrade the branch. |
| `VERSION UNKNOWN` | PHP is present but the version, branch, or patch level is not shown, or the branch is not listed in the advisories |
| `PATCHED` | At or above the fixed release for its branch |

A host takes the worst status seen on any port. `VERSION UNKNOWN` is used only when no signal on the host shows a version.

Versions with a distro suffix such as `8.3.6-0ubuntu0.24.04.5` are flagged in the note. Debian, Ubuntu, RHEL, and similar vendors backport fixes without changing the upstream version, so confirm those against the package changelog.

A status is not confirmation that either CVE is exploitable. A host with no PHP signal is not written to the results file, and that is not proof the host is safe.

## 2. Prerequisites and installation

- Python 3.8 or newer
- `pip3`

```bash
pip3 install -r requirements.txt
```

`requirements.txt` contains one third-party package:

- `aiohttp` — asynchronous HTTP client

`asyncio` is part of the Python standard library. The progress bar does not need an extra package.

## 3. Usage

```bash
python php2shellcheck.py -h
```

| Parameter | Short | Long | Description | Required |
| --- | --- | --- | --- | --- |
| Target file | `-t` | `--target` | Text file of IP addresses, hostnames, or CIDR blocks, one per line | Yes, unless `-u` is given |
| URL | `-u` | `--url` | One URL or hostname to scan, such as `https://www.example.com/` or `example.com`. Repeat to add more. | Yes, unless `-t` is given |
| Output file | `-o` | `--output` | Where to write the results. Default: `scan_results.txt` | No |
| Quiet mode | `-q` | `--quiet` | Print a host only when it is `VULNERABLE`, `END OF LIFE`, or `VERSION UNKNOWN` | No |

Blank lines and `#` comments are ignored. CIDR blocks such as `10.0.4.0/24` are expanded to their host addresses. Blocks larger than 65,536 addresses are skipped so a typo like `/8` is not scanned. URLs, ports, and other non-host tokens are skipped and counted in the summary. Duplicate hosts are scanned once. Up to 50 requests run at once. Each request allows 5 seconds to connect and 10 seconds overall. One retry is attempted after a timeout.

The scan reads response headers only. It does not download the body. Redirects to another host, port, or scheme are not followed. TLS certificate verification is disabled so a self-signed target can still be fingerprinted. TLS 1.0/1.1, low-security ciphers, and legacy renegotiation are allowed, because older PHP hosts often support nothing newer and would otherwise be missed. Do not point the tool at hosts you are not allowed to test.

While a normal scan runs, a progress bar is drawn on stderr:

```text
[##############--------------] 12/40  30.0%  hits=1  00:04 ETA 00:09
[+] 192.168.1.10 [END OF LIFE]
  [Port 80/HTTP] X-Powered-By: PHP/7.4.33 -> END OF LIFE (branch is end of life, no fix released)
```

**Scan a target list. Results go to `scan_results.txt`:**

```bash
python php2shellcheck.py -t targets.txt
```

**Scan one site without a target file.** A full URL or a bare hostname both work. Only the host is kept; the scheme, port, and path are ignored, and all four ports are still probed. `-u` can be repeated and combined with `-t`.

```bash
python php2shellcheck.py -u https://www.example.com/
python php2shellcheck.py -u example.com -u www.example.com
```

`example.com` and `www.example.com` are separate hosts. A redirect from one to the other is not followed, so list both when both are in scope.

**Choose the results path:**

```bash
python php2shellcheck.py -t targets.txt -o audit.txt
```

**Quiet mode.** The terminal shows only hosts with an indicator. Patched hosts are left out of the terminal but still listed in the results file.

```bash
python php2shellcheck.py -t targets.txt -o audit.txt -q
```

The output path cannot be the same file as the target list. The results file is created with mode `0600` because it describes the hosts you scanned. If the scan is interrupted, the file is still written from the hosts that finished. Saving partial results on Ctrl-C was verified on Python 3.11 and newer.

Example `targets.txt`:

```text
# production web
192.168.1.10
10.0.4.0/28
app.example.com
```

## 4. Interpreting results

The file lists hosts that showed PHP, worst status first, then a summary. The summary separates targets that never answered on a probed port from targets that did, so "0 indicators" on a mostly unreachable list is not mistaken for a clean result. Header text is taken from the server, with control characters removed so a response cannot add extra lines to the report.

```text
PHP2SHELLCHECK SCAN RESULTS
Timestamp: 2026-10-21 16:40:22 EDT
CVEs: CVE-2026-109618, CVE-2026-109619
Fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 8.1 and older is end of life.
Note: Status comes from version banners. It is an indicator only, not confirmation that the CVE is exploitable.

Host: 192.168.1.10 [VULNERABLE]
  [Port 80/HTTP] X-Powered-By: PHP/8.2.12 -> VULNERABLE (fixed in 8.2.35)

Host: app.example.com [PATCHED]
  [Port 443/HTTPS] X-Powered-By: PHP/8.5.12 -> PATCHED

Summary
Targets scanned: 18
Responded on at least one probed port: 6
No HTTP response on any probed port: 12
Hosts showing PHP: 2
  Vulnerable (unpatched supported branch): 1
  End of life (8.1 or older): 0
  Version unknown: 0
  Patched: 1
Hosts with vulnerability indicators: 1 of 6 responding
```

If nothing showed PHP, the host list is empty and the summary reports `0 of N responding`.

## 5. Security disclaimer

The absence of a PHP signal, or a `PATCHED` status, must not be treated as a clean bill of health.

1. **Header suppression.** `expose_php = Off`, or a proxy that strips the headers, hides the signature. The host can still be running PHP.
2. **Other ports and paths.** Only 80, 443, 8080, and 8443 are probed, and only `/` (plus same-host redirects) and `/index.php` are requested.
3. **Virtual hosts.** Scanning an IP address sees only the default site. List hostnames as well when name-based virtual hosts are in scope.
4. **Banners can be wrong.** Distro backports, version-spoofing proxies, and a load balancer in front of mixed back ends all make the banner differ from the runtime.
5. **Unpatched runtimes.** Hosts that hide their version, or that listen elsewhere, can still be vulnerable to **CVE-2026-109618** and **CVE-2026-109619**.

TLS verification is intentionally off for fingerprinting. A network attacker could present a fake header. Treat the file as a lead list, then confirm versions from an inventory you trust.

## 6. Tests

```bash
python -m unittest discover -s tests
```

The tests cover version classification, header parsing, target loading, the report summary, and live checks against local test servers. They make no outside network calls.

## 7. License

This project is released under the [MIT License](LICENSE).

Copyright (c) 2026 Josh Gatka

You can use, copy, modify, and distribute this software, including for commercial purposes. Include the copyright notice and the license text with any substantial copy. The software is provided as is, without warranty.
