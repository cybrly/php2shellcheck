# PHP2SHELL CHECK (`php2shellcheck.py`)

Asynchronous HTTP/HTTPS header inspection for PHP fingerprinting.

## 1. Overview

**PHP2SHELL CHECK** probes ports **80**, **443**, **8080**, and **8443**. A host is reported when the `X-Powered-By` header value starts with `PHP`, which covers:

- `PHP/7.4.33`
- `PHP/7.4`
- `PHP/8.1`
- `PHP/8.` (any PHP 8 release)
- `PHP`

That match is a reconnaissance indicator for:

- **CVE-2026-109618** — remote code execution / memory corruption in PHP web handling.
- **CVE-2026-109619** — argument injection / CGI wrapper processing in PHP environments.

It is not confirmation that either CVE is exploitable. A host with no matching header is not written to the results file, and that is not proof the host is safe.

```text
    ___  _  _ ___  ___  ____ _  _ ____ _    _    ____ _  _ ____ ____ _  _
   |__] |__| |__]  __] [__  |__| |___ |    |    |    |__| |___ |    |_/
   |    |  | |    |__  ___] |  | |___ |___ |___ |___ |  | |___ |___ | \
============================ PHP2SHELLCHECK =============================
```

The banner prints in green when stdout is a terminal. Quiet mode (`-q`) skips it.

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
| Target file | `-t` | `--target` | Text file of IP addresses or hostnames, one per line | Yes |
| Output file | `-o` | `--output` | Where to write the results. Default: `scan_results.txt` | No |
| Quiet mode | `-q` | `--quiet` | Print a host only when it has a vulnerability indicator | No |

Blank lines and `#` comments are ignored. URLs, ports, and other non-host tokens are skipped and counted in the summary. Duplicate hosts are scanned once. Up to 50 requests run at once. Each request allows 5 seconds to connect and 10 seconds overall. One retry is attempted after a timeout.

The scan reads response headers only. It does not download the body, and it does not follow redirects. TLS certificate verification is disabled so a self-signed target can still be fingerprinted. Do not point the tool at hosts you are not allowed to test.

While a normal scan runs, a progress bar is drawn on stderr:

```text
[##############--------------] 12/40  30.0%  hits=1  00:04 ETA 00:09
[+] 192.168.1.10
  [Port 80/HTTP] X-Powered-By: PHP/7.4.33
```

**Scan a target list. Results go to `scan_results.txt`:**

```bash
python php2shellcheck.py -t targets.txt
```

**Choose the results path:**

```bash
python php2shellcheck.py -t targets.txt -o audit.txt
```

**Quiet mode.** The terminal shows only hosts that matched. The results file is still written.

```bash
python php2shellcheck.py -t targets.txt -o audit.txt -q
```

The output path cannot be the same file as the target list. If the scan is interrupted, the file is still written from the hosts that finished.

Example `targets.txt`:

```text
# production web
192.168.1.10
10.0.4.15
app.example.com
```

## 4. Interpreting results

The file lists only hosts with a matching `X-Powered-By` header, then a summary. The summary states how many hosts were scanned and how many of that total showed an indicator. Header text is taken from the server, with control characters removed so a response cannot add extra lines to the report.

```text
PHP2SHELLCHECK SCAN RESULTS
Timestamp: 2026-10-21 16:40:22 EDT
CVEs: CVE-2026-109618, CVE-2026-109619
Note: A matching X-Powered-By header is an indicator only, not confirmation that the CVE is exploitable.

Host: 192.168.1.10
  [Port 80/HTTP] X-Powered-By: PHP/7.4.33

Summary
Total hosts scanned: 3
Hosts with vulnerability indicators: 1 of 3
```

If nothing matched, the host list is empty and the summary reports `0 of N`.

## 5. Security disclaimer

The absence of `X-Powered-By: PHP` must not be treated as a clean bill of health.

1. **Header suppression.** `expose_php = Off`, or a proxy that strips `X-Powered-By`, hides the signature. The host can still be running PHP.
2. **Other ports.** Only 80, 443, 8080, and 8443 are probed.
3. **Unpatched runtimes.** Hosts that hide this header, or that listen elsewhere, can still be vulnerable to **CVE-2026-109618** and **CVE-2026-109619** if the runtime is unpatched.

TLS verification is intentionally off for fingerprinting. A network attacker could present a fake header. Treat the file as a lead list, then confirm versions from an inventory you trust.

## 6. License

This project is released under the [MIT License](LICENSE).

Copyright (c) 2026 Josh Gatka

You can use, copy, modify, and distribute this software, including for commercial purposes. Include the copyright notice and the license text with any substantial copy. The software is provided as is, without warranty.
