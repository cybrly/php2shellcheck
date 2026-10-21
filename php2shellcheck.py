# SPDX-License-Identifier: MIT
# Copyright (c) 2026 the php2shellcheck authors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import asyncio
import ipaddress
import os
import re
import ssl
import sys
import tempfile
import threading
import time

import aiohttp

ASCII_ART = r"""
    ___  _  _ ___  ___  ____ _  _ ____ _    _    ____ _  _ ____ ____ _  _
   |__] |__| |__]  __] [__  |__| |___ |    |    |    |__| |___ |    |_/
   |    |  | |    |__  ___] |  | |___ |___ |___ |___ |  | |___ |___ | \
============================ PHP2SHELLCHECK =============================
"""

DEFAULT_OUTPUT = "scan_results.txt"
MAX_TARGET_LINE = 512
MAX_HEADER_VALUE = 300
CONCURRENCY = 50

PHP_VALUE = re.compile(r"(?i)^php")
HOSTNAME = re.compile(
    r"(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
    re.IGNORECASE,
)

TARGET_PORTS = (
    (80, "http"),
    (443, "https"),
    (8080, "http"),
    (8443, "https"),
)

# Certificate checks are off so a self-signed target can still be fingerprinted.
# Redirects are not followed, so a response cannot steer the scan at another host.
SSL_CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def show_banner():
    """Print the banner. Green on a terminal, plain text when piped."""
    if sys.stdout.isatty():
        print("\033[1;32m" + ASCII_ART + "\033[0m")
    else:
        print(ASCII_ART)


def format_duration(seconds):
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class ProgressBar:
    """Scan progress on stderr. One updating line on a terminal."""

    def __init__(self, total, stream=None):
        self.total = total
        self.done = 0
        self.hits = 0
        self.start = time.monotonic()
        self.stream = stream if stream is not None else sys.stderr
        self.tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_report = 0
        self._lock = threading.Lock()
        self._closed = False

    def _bar(self):
        width = 28
        if self.total <= 0:
            return "#" * width
        filled = int(width * (self.done / self.total))
        if self.done and not filled:
            filled = 1
        if self.done >= self.total:
            filled = width
        return "#" * filled + "-" * (width - filled)

    def _eta(self):
        if self.done <= 0:
            return "--:--"
        if self.done >= self.total:
            return "00:00"
        elapsed = time.monotonic() - self.start
        if elapsed <= 0:
            return "--:--"
        remain = (self.total - self.done) * (elapsed / self.done)
        return format_duration(remain)

    def render(self):
        percent = (100.0 * self.done / self.total) if self.total else 100.0
        elapsed = format_duration(time.monotonic() - self.start)
        return (
            f"[{self._bar()}] {self.done}/{self.total} "
            f"{percent:5.1f}%  hits={self.hits}  "
            f"{elapsed} ETA {self._eta()}"
        )

    def tick(self, hit=False, message=None):
        with self._lock:
            if self._closed:
                return
            self.done += 1
            if hit:
                self.hits += 1
            line = self.render()
            if message:
                if self.tty:
                    self.stream.write("\r\033[2K" + message + "\n")
                else:
                    self.stream.write(message + "\n")
            if self.tty:
                self.stream.write("\r\033[2K" + line)
                self.stream.flush()
                return
            step = 1 if self.total <= 20 else max(1, self.total // 20)
            if (
                self.done == 1
                or self.done == self.total
                or self.done - self._last_report >= step
            ):
                self.stream.write(line + "\n")
                self.stream.flush()
                self._last_report = self.done

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self.tty:
                self.stream.write("\n")
                self.stream.flush()


def sanitize(value, limit=MAX_HEADER_VALUE):
    """Drop control characters so a header cannot forge extra report lines."""
    cleaned = []
    for char in value:
        if char in "\r\n\t" or not char.isprintable():
            cleaned.append(" ")
        else:
            cleaned.append(char)
    text = " ".join("".join(cleaned).split())
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def normalize_target(token):
    """Return a canonical host, or None when the token is not a host."""
    token = token.strip()
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if not token or any(char.isspace() for char in token):
        return None
    if any(char in token for char in "/\\?#@"):
        return None
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        pass
    if ":" in token:
        return None
    host = token[:-1] if token.endswith(".") else token
    if HOSTNAME.fullmatch(host):
        return host
    return None


def host_for_url(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 6:
        return f"[{address}]"
    return str(address)


def load_targets(path):
    hosts = []
    seen = set()
    skipped = 0
    duplicates = 0
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if len(line) > MAX_TARGET_LINE:
                skipped += 1
                continue
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            host = normalize_target(raw)
            if host is None:
                skipped += 1
                continue
            key = host.lower()
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            hosts.append(host)
    return hosts, skipped, duplicates


def matching_headers(header_items, port, scheme):
    """Return X-Powered-By lines whose value starts with PHP."""
    found = []
    seen = set()
    label = f"[Port {port}/{scheme.upper()}]"
    for key, value in header_items:
        if str(key).lower() != "x-powered-by":
            continue
        cleaned = sanitize(str(value))
        if not PHP_VALUE.match(cleaned):
            continue
        rendered = f"{label} X-Powered-By: {cleaned}"
        if rendered not in seen:
            seen.add(rendered)
            found.append(rendered)
    return found


def format_hit(host, indicators):
    lines = [f"[+] {host}"]
    lines.extend(f"  {indicator}" for indicator in indicators)
    return "\n".join(lines)


def paths_same(left, right):
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.abspath(left) == os.path.abspath(right)


def parse_arguments():
    description_text = (
        f"{ASCII_ART}\n"
        "Description:\n"
        "  This script checks for indicators of vulnerability to CVE-2026-109618 "
        "and CVE-2026-109619.\n"
        "  It probes ports 80, 443, 8080, and 8443 and reads the X-Powered-By "
        "header.\n"
        "  A match means the header names PHP. It does not prove the CVE is "
        "exploitable.\n"
        "\n"
        "  Only hosts with a matching header are listed. The file ends with a\n"
        "  summary of hosts scanned and hosts with indicators.\n"
        "  Use -q to print those hosts and nothing else."
    )

    parser = argparse.ArgumentParser(
        prog="php2shellcheck.py",
        description=description_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument(
        "-t",
        "--target",
        dest="target_file",
        metavar="TARGET_FILE",
        help="Text file of IP addresses or hostnames, one per line.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        default=DEFAULT_OUTPUT,
        metavar="OUTPUT_FILE",
        help=f"Results file to write (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode. Print a host only when it shows a vulnerability indicator.",
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show this help message and exit.",
    )

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    if not args.target_file:
        show_banner()
        print("Error: Target file parameter (-t) is required.\n")
        parser.print_help()
        sys.exit(1)

    parent = os.path.dirname(os.path.abspath(args.output_file))
    if parent and not os.path.isdir(parent):
        print(f"Error: Output directory '{parent}' does not exist.")
        sys.exit(1)

    if paths_same(args.target_file, args.output_file):
        print("Error: Output file must not be the same as the target file.")
        sys.exit(1)

    return args


async def check_target(session, host, port, scheme, semaphore):
    url = f"{scheme}://{host_for_url(host)}:{port}/"
    request_kwargs = {
        "allow_redirects": False,
        "timeout": aiohttp.ClientTimeout(total=10, connect=5, sock_read=5),
    }
    if scheme == "https":
        request_kwargs["ssl"] = SSL_CONTEXT

    async with semaphore:
        for attempt in (1, 2):
            try:
                async with session.get(url, **request_kwargs) as response:
                    headers = list(response.headers.items())
                    response.release()
                    return matching_headers(headers, port, scheme)
            except asyncio.TimeoutError:
                if attempt == 1:
                    continue
                return []
            except (aiohttp.ClientError, OSError):
                return []
    return []


async def process_host(session, host, semaphore):
    results = await asyncio.gather(
        *(
            check_target(session, host, port, scheme, semaphore)
            for port, scheme in TARGET_PORTS
        )
    )
    indicators = []
    for match_list in results:
        indicators.extend(match_list)
    return indicators


def write_report(path, findings, scanned, unfinished, skipped, duplicates):
    """Write findings, then the summary. Replace the file only when complete."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    indicated = len(findings)
    lines = [
        "PHP2SHELLCHECK SCAN RESULTS",
        f"Timestamp: {timestamp}",
        "CVEs: CVE-2026-109618, CVE-2026-109619",
        "Note: A matching X-Powered-By header is an indicator only, not confirmation that the CVE is exploitable.",
        "",
    ]
    if not findings:
        lines.append("No hosts with vulnerability indicators were found.")
        lines.append("")
    else:
        for host, indicators in findings:
            lines.append(f"Host: {sanitize(host, limit=253)}")
            for indicator in indicators:
                lines.append(f"  {indicator}")
            lines.append("")

    lines.extend(
        [
            "Summary",
            f"Total hosts scanned: {scanned}",
            f"Hosts with vulnerability indicators: {indicated} of {scanned}",
        ]
    )
    if unfinished:
        lines.append(f"Scan interrupted: {unfinished} host(s) not finished.")
    if skipped:
        lines.append(f"Invalid target lines skipped: {skipped}")
    if duplicates:
        lines.append(f"Duplicate targets skipped: {duplicates}")
    lines.append("")

    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".php2shellcheck-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def main():
    args = parse_arguments()

    if not args.quiet:
        show_banner()

    try:
        hosts, skipped, duplicates = load_targets(args.target_file)
    except FileNotFoundError:
        print(f"Error: Target file '{args.target_file}' not found.")
        sys.exit(1)
    except OSError as exc:
        print(f"Error: Could not read '{args.target_file}': {exc}")
        sys.exit(1)

    if not hosts:
        print(f"Error: No valid targets in '{args.target_file}'.")
        if skipped:
            print(f"Skipped {skipped} invalid line(s).")
        sys.exit(1)

    if not args.quiet:
        print(
            f"Starting scan of {len(hosts)} host(s) on ports 80, 443, 8080, and 8443."
        )
        if skipped:
            print(f"Skipped {skipped} invalid target line(s).")
        print()

    progress = None if args.quiet else ProgressBar(len(hosts))
    findings = [None] * len(hosts)
    semaphore = asyncio.Semaphore(CONCURRENCY)
    interrupted = False
    write_failed = False
    workers = []

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        limit_per_host=4,
        force_close=True,
        ttl_dns_cache=60,
        ssl=SSL_CONTEXT,
    )
    timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=5)
    session = aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        trust_env=False,
        headers={"User-Agent": "php2shellcheck"},
    )

    try:
        queue = asyncio.Queue()
        for index, host in enumerate(hosts):
            queue.put_nowait((index, host))

        async def worker():
            while True:
                index, host = await queue.get()
                try:
                    try:
                        indicators = await process_host(session, host, semaphore)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        indicators = []
                    findings[index] = (host, indicators)
                    if indicators:
                        message = format_hit(host, indicators)
                        if args.quiet:
                            print(message, flush=True)
                        elif progress is not None:
                            progress.tick(hit=True, message=message)
                    elif progress is not None:
                        progress.tick(hit=False)
                finally:
                    queue.task_done()

        worker_count = min(CONCURRENCY, len(hosts))
        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        await queue.join()
    except asyncio.CancelledError:
        interrupted = True
    finally:
        for task in workers:
            task.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        try:
            await session.close()
        except (asyncio.CancelledError, Exception):
            pass
        if progress is not None:
            progress.close()
        finished = [item for item in findings if item is not None]
        suspected = [(host, indicators) for host, indicators in finished if indicators]
        unfinished = len(hosts) - len(finished)
        try:
            write_report(
                args.output_file,
                suspected,
                len(finished),
                unfinished if interrupted else 0,
                skipped,
                duplicates,
            )
        except OSError as exc:
            write_failed = True
            print(f"Error: Could not write '{args.output_file}': {exc}", file=sys.stderr)

    if write_failed:
        return 1
    if interrupted:
        return 130

    if not args.quiet:
        print(
            f"Scan complete. {len(suspected)} host(s) with indicators written to {args.output_file}."
        )
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except KeyboardInterrupt:
        exit_code = 130
    if exit_code == 130:
        print(
            "\nScan interrupted. Partial results were saved when possible.",
            file=sys.stderr,
        )
    sys.exit(exit_code)
