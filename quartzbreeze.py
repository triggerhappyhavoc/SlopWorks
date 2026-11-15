#!/usr/bin/env python3
"""
QuartzBreeze - coordinate port scans against a single target from multiple
vantage points (scanner hosts) over SSH. For authorised penetration tests /
security assessments only.

CLI invocation syntax:
    quartzbreeze.py [-sT] [-sU] [-p <port-range>] <target> --scanners </path/to/scanner/list.txt>
                    [--max-concurrent <int>]

    -sT                 Perform TCP scan. Default if neither -sT nor -sU is passed.
    -sU                 Perform UDP scan. If passed with -sT, both TCP and UDP scans are performed.
    -p                  Ports to scan: 22 | 22,80,443 | 1-1024 | any mix | - (all).
                        (default: 1-1024)
    <target>            IPv4 address or hostname that the scanners will port scan.
    --scanners          Path to text file listing the scanner hosts.
    --max-concurrent    Number of scanner hosts scanning concurrently (default: 5).

Scanner list format (one per line, '#' comments and blank lines ignored):
    user@host[:port] [/path/to/private/key]
    IPv6 hosts with a port use brackets: user@[fe80::1]:2222
    If no key path is given, ssh falls back to ssh-agent / default keys.
    Authentication is SSH-key only; password auth is not supported.

Execution order:
    1. Parse input
    2. Scanner smoke test (SSH login + remote dependency check)
    3. Target smoke test (ICMP ping from each scanner; failure is a warning only)
    4. Show smoke test results, prompt user to continue (mandatory, unskippable gate)
    5. Deploy dropper (portscan.sh) to each scanner, run it against the target,
       collect results, delete the dropper once that scanner is finished
    6. Print report to CLI and write quartzbreeze-<target>-<ports>.txt

Scanner requirements (all checked by the smoke test): bash 4+, mktemp,
timeout, awk, xargs, sort; plus dd and od for UDP. nc is optional -
portscan.sh falls back to bash's /dev/tcp without it.

See README.md for design decisions.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

log = logging.getLogger("quartzbreeze")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DROPPER_NAME = "portscan.sh"               # must exist in the CWD (see brief)
# protocol -> dropper scan-type flag. TCP is portscan.sh's default and it
# rejects -sT ("unknown option -s"), so TCP passes no flag.
PROTO_FLAGS: dict[str, list[str]] = {"tcp": [], "udp": ["-sU"]}
# Always ask for the REASON column and the "Not shown: N closed (why)" summary:
# conn-refused vs no-response is the firewall signal this tool exists for.
DROPPER_OPTIONS = ["--reason"]
DEFAULT_SSH_PORT = 22
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_PORT_SPEC = "1-1024"
SSH_CONNECT_TIMEOUT = 10                   # seconds, ssh/scp connection setup
SSH_COMMAND_TIMEOUT = 30                   # seconds, short housekeeping commands
SCP_TIMEOUT = 60                           # seconds, dropper upload
PING_TIMEOUT = 2                           # seconds
# What portscan.sh needs on a scanner (its header, plus mktemp for deployment).
REMOTE_DEPENDENCIES = ("bash", "mktemp", "timeout", "awk", "xargs", "sort")
REMOTE_UDP_DEPENDENCIES = ("dd", "od")     # only needed for -sU
REMOTE_MIN_BASH = 4                        # portscan.sh exits under bash < 4
LOCAL_DEPENDENCIES = ("ssh", "scp")        # checked on the C2 host

TABLE_COLUMNS = ("PORT", "STATE", "SERVICE", "REASON", "BANNER")
PORT_FIELD_RE = re.compile(r"(\d{1,5})/(tcp|udp)")
REPORT_WIDTH = 72
REPORT_RULE = "=" * REPORT_WIDTH           # opens and closes the report
SECTION_RULE = "-" * REPORT_WIDTH          # divides one scanner's results from the next
INDENT = "  "                              # results sit under their TCP / UDP heading
COLUMN_GAP = "  "                          # between port-table columns
# Target forms portscan.sh accepts that are also a single host (it also takes
# CIDRs, ranges and lists, which this tool deliberately does not pass through).
IPV4_RE = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
HOSTNAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9.])?")
# Only paths shaped like our own mktemp -d output are ever rm -rf'd remotely.
REMOTE_DIR_RE = re.compile(r"/[A-Za-z0-9._/-]*/quartzbreeze\.[A-Za-z0-9]{6,}")

# Set on Ctrl-C so in-flight scanner jobs stop starting new scans (cleanup
# of already-deployed droppers still runs).
ABORT = threading.Event()

# ssh stderr fragments -> friendlier explanations (checked in order)
SSH_FAILURE_HINTS = (
    ("REMOTE HOST IDENTIFICATION HAS CHANGED", "host key has CHANGED since last connection - investigate before trusting it"),
    ("Host key verification failed", "host key not trusted - connect once manually to add it to known_hosts"),
    ("Permission denied", "authentication failed (key rejected)"),
    ("Connection refused", "connection refused"),
    ("Connection timed out", "connection timed out"),
    ("No route to host", "no route to host"),
    ("Could not resolve hostname", "scanner hostname could not be resolved"),
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class QuartzError(Exception):
    """An error with a message fit to show the user."""


class RemoteError(QuartzError):
    """A remote command or file transfer failed."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScannerHost:
    """A vantage point. Frozen so it can be used as a dict key."""
    username: str
    host: str
    port: int = DEFAULT_SSH_PORT
    key_path: str | None = None   # None -> ssh-agent / default identity

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host   # IPv6
        return f"{self.username}@{host}:{self.port}"


@dataclass(frozen=True)
class Target:
    raw: str                      # as given on the CLI
    ip: str | None = None         # None if it couldn't be resolved locally
    fqdn: str | None = None

    @property
    def address(self) -> str:
        """What the scanners are told to scan: the IP if known, else the name."""
        return self.ip or self.raw

    @property
    def label(self) -> str:
        """'<fqdn> (<ip>)' where both are known, as in the report example."""
        if self.fqdn and self.ip and self.fqdn != self.ip:
            return f"{self.fqdn} ({self.ip})"
        return self.ip or self.fqdn or self.raw


@dataclass
class ScanConfig:
    """Everything the run needs, built once from the CLI."""
    target: Target
    scanners: list[ScannerHost]
    protocols: list[str]          # ordered subset of ["tcp", "udp"]
    port_spec: str                # validated -p string; passed to the dropper and
                                  # used in the output filename
    max_concurrent: int


@dataclass
class RemoteResult:
    returncode: int               # -1 if the command timed out locally
    stdout: str
    stderr: str


@dataclass
class SmokeReport:
    ssh_ok: dict[ScannerHost, bool] = field(default_factory=dict)
    ssh_errors: dict[ScannerHost, str] = field(default_factory=dict)
    target_reachable: dict[ScannerHost, bool] = field(default_factory=dict)
    notes: dict[ScannerHost, list[str]] = field(default_factory=dict)  # non-fatal findings

    @property
    def healthy_scanners(self) -> list[ScannerHost]:
        """Scanners that passed SSH. Ping failures do NOT exclude a scanner."""
        return [s for s, ok in self.ssh_ok.items() if ok]


@dataclass
class PortResult:
    """One row of portscan.sh's port table. All fields come from the dropper."""
    port: int                     # '22/tcp' -> 22
    proto: str                    # '22/tcp' -> 'tcp'
    state: str                    # open | open|filtered | filtered
    service: str                  # conventional service for the port, or 'unknown'
    reason: str                   # one token: syn-ack, udp-response, no-response, ...
    banner: str                   # grabbed banner (may contain spaces, may be empty)


@dataclass
class ScanResult:
    scanner: ScannerHost
    proto: str
    ports: list[PortResult] = field(default_factory=list)
    # The dropper's summary lines ("Not shown: 1021 closed (1021 conn-refused)",
    # "No open ports found.") and its stderr log ("... using /usr/bin/nc",
    # "scan incomplete ...") - they carry the closed/filtered picture.
    notes: list[str] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# 1. Input parsing
# ---------------------------------------------------------------------------

def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer")
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Define and parse the CLI (see module docstring)."""
    parser = argparse.ArgumentParser(
        prog="quartzbreeze.py",
        description="Port scan a single target from multiple SSH-reachable "
                    "vantage points. For authorised testing only.",
    )
    parser.add_argument("-sT", dest="tcp", action="store_true",
                        help="TCP scan (default if neither -sT nor -sU is given)")
    parser.add_argument("-sU", dest="udp", action="store_true",
                        help="UDP scan (combine with -sT to run both)")
    parser.add_argument("-p", dest="ports", default=DEFAULT_PORT_SPEC, metavar="PORTS",
                        help=f"ports, e.g. 22,80,8000-8100, or - for all "
                             f"(default: {DEFAULT_PORT_SPEC})")
    parser.add_argument("target", help="IPv4 address or hostname to scan")
    parser.add_argument("--scanners", required=True, metavar="FILE",
                        help="file listing scanner hosts: user@host[:port] [/path/to/key]")
    parser.add_argument("--max-concurrent", type=_positive_int, default=DEFAULT_MAX_CONCURRENT,
                        metavar="N",
                        help=f"scanners working at once (default: {DEFAULT_MAX_CONCURRENT})")
    return parser.parse_args(argv)


def resolve_protocols(args: argparse.Namespace) -> list[str]:
    """
    Apply the -sT / -sU rules:
      neither  -> ["tcp"]
      -sT      -> ["tcp"]
      -sU      -> ["udp"]
      both     -> ["tcp", "udp"]
    """
    protocols = []
    if args.tcp or not args.udp:
        protocols.append("tcp")
    if args.udp:
        protocols.append("udp")
    return protocols


PORT_ENTRY_RE = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")


def validate_port_spec(spec: str) -> str:
    """
    Validate a port spec locally, using exactly the rules portscan.sh's
    expand_list applies, so a typo fails fast here rather than once per
    scanner. Accepted: '22', '22,80,443', '1-1024', any comma-separated mix,
    or '-' (all ports). Open-ended ranges ('-1024', '1024-') are NOT
    accepted, because portscan.sh rejects them.
    Returns the spec (whitespace stripped) to pass verbatim to the dropper.
    Raises ValueError on out-of-range or malformed input.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("port specification is empty")
    if spec == "-":
        return spec
    for entry in spec.split(","):
        match = PORT_ENTRY_RE.fullmatch(entry)
        if not match:
            raise ValueError(f"invalid port entry '{entry}' "
                             "(use N or N-M, comma-separated, or - for all ports)")
        lo = int(match.group(1))
        hi = int(match.group(2) or lo)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValueError(f"'{entry}' is out of range (1-65535)")
        if lo > hi:
            raise ValueError(f"range '{entry}' starts after it ends")
    return spec


def resolve_target(raw: str) -> Target:
    """
    Check the target is a single host portscan.sh can scan, then resolve it.
      - IPv4 literal: reverse lookup for the FQDN (failure is silent).
      - Hostname: forward lookup for its first IPv4 address, which is what
        the scanners are given so every vantage point scans the same address.
        If it doesn't resolve locally that's a warning, not fatal: scanners
        may see DNS the C2 host can't, so the name is passed through for
        them to resolve.
    Raises QuartzError for IPv6 (portscan.sh is IPv4-only) and for CIDRs,
    ranges and lists (portscan.sh accepts them, but this tool scans one host).
    """
    raw = raw.strip()
    if IPV4_RE.fullmatch(raw):
        try:
            ip = str(ipaddress.IPv4Address(raw))
        except ValueError:
            raise QuartzError(f"Invalid IPv4 address: '{raw}'")
        try:
            fqdn = socket.gethostbyaddr(ip)[0]
        except OSError:
            fqdn = None
        return Target(raw=raw, ip=ip, fqdn=fqdn)

    try:
        ipaddress.IPv6Address(raw)
        raise QuartzError(f"'{raw}' is IPv6; {DROPPER_NAME} only scans IPv4")
    except ValueError:
        pass
    if not HOSTNAME_RE.fullmatch(raw) or not re.search(r"[A-Za-z]", raw):
        raise QuartzError(f"Invalid target '{raw}': expected one IPv4 address or hostname "
                          "(CIDRs, ranges and lists are not supported)")

    try:
        infos = socket.getaddrinfo(raw, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        log.warning("Could not resolve %s to IPv4 locally (%s); scanners will resolve it "
                    "themselves and may reach different addresses.", raw, exc.strerror)
        return Target(raw=raw, ip=None, fqdn=raw)

    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if len(addresses) > 1:
        log.info("%s resolves to %s; scanning %s.", raw, ", ".join(addresses), addresses[0])
    return Target(raw=raw, ip=addresses[0], fqdn=raw)


def _split_host_port(hostport: str) -> tuple[str, int]:
    """'host', 'host:2222', '[v6addr]:2222' or a bare IPv6 address."""
    port_text: str | None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise ValueError(f"unclosed '[' in '{hostport}'")
        host, rest = hostport[1:end], hostport[end + 1:]
        if rest and not rest.startswith(":"):
            raise ValueError(f"unexpected text after ']' in '{hostport}'")
        port_text = rest[1:] if rest else None
    elif hostport.count(":") == 1:
        host, port_text = hostport.split(":")
    else:
        host, port_text = hostport, None   # hostname, IPv4 or bare IPv6

    if not host:
        raise ValueError(f"missing host in '{hostport}'")
    if port_text is None:
        return host, DEFAULT_SSH_PORT
    if not (port_text.isascii() and port_text.isdigit()) or not 1 <= int(port_text) <= 65535:
        raise ValueError(f"invalid SSH port '{port_text}'")
    return host, int(port_text)


def _check_key_file(path: str) -> None:
    if not os.path.isfile(path):
        raise ValueError(f"key file not found: {path}")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        log.warning("Key file %s has mode %o; ssh ignores keys other users can read. "
                    "Fix with: chmod 600 %s", path, mode, path)


def parse_scanner_line(line: str) -> ScannerHost:
    """
    Parse 'user@host[:port] [/path/to/key]'.
    Validates the key file exists and warns if its permissions are too open.
    Raises ValueError on malformed lines.
    """
    parts = line.split()
    if len(parts) not in (1, 2):
        raise ValueError("expected 'user@host[:port] [/path/to/key]'")

    user, at, hostport = parts[0].rpartition("@")
    if not at or not user:
        raise ValueError(f"'{parts[0]}' needs a username (user@host)")
    host, port = _split_host_port(hostport)

    key_path = None
    if len(parts) == 2:
        key_path = os.path.abspath(os.path.expanduser(parts[1]))
        _check_key_file(key_path)
    return ScannerHost(username=user, host=host, port=port, key_path=key_path)


def load_scanners(path: str) -> list[ScannerHost]:
    """
    Read the scanner list, skipping blanks and '#' comments (whole-line or
    trailing). Every bad line is reported at once, with line numbers, via
    QuartzError. Duplicate entries are dropped with a warning.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise QuartzError(f"Cannot read scanner list {path}: {exc.strerror}")

    scanners: list[ScannerHost] = []
    errors: list[str] = []
    for lineno, line in enumerate(lines, start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            scanner = parse_scanner_line(line)
        except ValueError as exc:
            errors.append(f"  line {lineno}: {exc}")
            continue
        if scanner in scanners:
            log.warning("%s line %d: duplicate scanner %s ignored", path, lineno, scanner.label)
            continue
        scanners.append(scanner)

    if errors:
        raise QuartzError(f"Invalid entries in scanner list {path}:\n" + "\n".join(errors))
    if not scanners:
        raise QuartzError(f"No scanners listed in {path}")
    return scanners


def check_local_dependencies() -> None:
    """
    Verify LOCAL_DEPENDENCIES are on PATH and DROPPER_NAME exists in the CWD.
    Raises QuartzError naming everything that's missing.
    """
    problems = []
    missing = [tool for tool in LOCAL_DEPENDENCIES if shutil.which(tool) is None]
    if missing:
        problems.append(f"required tools not installed: {', '.join(missing)}")
    if not os.path.isfile(DROPPER_NAME):
        problems.append(f"dropper '{DROPPER_NAME}' not found in {os.getcwd()}")
    if problems:
        raise QuartzError("; ".join(problems))


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Combine the parsing helpers above into a single ScanConfig."""
    try:
        port_spec = validate_port_spec(args.ports)
    except ValueError as exc:
        raise QuartzError(f"Invalid -p value: {exc}")
    return ScanConfig(
        target=resolve_target(args.target),
        scanners=load_scanners(args.scanners),
        protocols=resolve_protocols(args),
        port_spec=port_spec,
        max_concurrent=args.max_concurrent,
    )


# ---------------------------------------------------------------------------
# 2. SSH transport (key-based only; the only layer that touches the network)
# ---------------------------------------------------------------------------

def ssh_common_options(scanner: ScannerHost) -> list[str]:
    """
    Options shared by ssh and scp:
      BatchMode=yes          never prompt for a password - key auth only
      ConnectTimeout         don't hang on unreachable scanners
      ServerAlive*           detect connections that die mid-scan
      -i + IdentitiesOnly    use exactly the listed key, if one is given
    Port is NOT included because ssh uses -p and scp uses -P.
    """
    options = [
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "LogLevel=ERROR",
    ]
    if scanner.key_path:
        options += ["-i", scanner.key_path, "-o", "IdentitiesOnly=yes"]
    return options


def describe_ssh_failure(result: RemoteResult) -> str:
    """Turn a failed RemoteResult into a one-line explanation."""
    stderr = result.stderr.strip()
    for needle, explanation in SSH_FAILURE_HINTS:
        if needle in stderr:
            return explanation
    if stderr:
        return stderr.splitlines()[-1]
    return f"exited with status {result.returncode}"


def run_remote(
    scanner: ScannerHost,
    command: str,
    timeout: int | None = SSH_COMMAND_TIMEOUT,
) -> RemoteResult:
    """
    Run a command on the scanner over ssh and capture rc/stdout/stderr.
    stdin is /dev/null so worker threads never read from the terminal.
    A local timeout returns returncode -1 instead of raising.
    """
    argv = ["ssh", *ssh_common_options(scanner), "-p", str(scanner.port),
            f"{scanner.username}@{scanner.host}", command]
    log.debug("[%s] $ %s", scanner.label, command)
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return RemoteResult(-1, "", f"timed out after {timeout}s")
    return RemoteResult(proc.returncode, proc.stdout, proc.stderr)


def copy_to_remote(scanner: ScannerHost, local_path: str, remote_path: str) -> None:
    """scp a local file to the scanner. Raises RemoteError on failure."""
    host = f"[{scanner.host}]" if ":" in scanner.host else scanner.host
    argv = ["scp", "-q", *ssh_common_options(scanner), "-P", str(scanner.port),
            local_path, f"{scanner.username}@{host}:{remote_path}"]
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=SCP_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise RemoteError(f"upload timed out after {SCP_TIMEOUT}s")
    if proc.returncode != 0:
        failure = describe_ssh_failure(RemoteResult(proc.returncode, proc.stdout, proc.stderr))
        raise RemoteError(f"upload failed: {failure}")


def remove_remote_dir(scanner: ScannerHost, remote_dir: str) -> None:
    """
    Best-effort delete of the dropper's temp directory; logs but never
    raises. Refuses any path not shaped like our own mktemp output, so a
    bad value can never turn into an rm -rf of something else.
    """
    if not REMOTE_DIR_RE.fullmatch(remote_dir):
        log.warning("Refusing to delete unexpected path %r on %s - check it manually.",
                    remote_dir, scanner.label)
        return
    result = run_remote(scanner, f"rm -rf -- {shlex.quote(remote_dir)}")
    if result.returncode != 0:
        log.warning("Could not remove %s from %s (%s) - remove it manually.",
                    remote_dir, scanner.label, describe_ssh_failure(result))


# ---------------------------------------------------------------------------
# 3. Smoke tests
# ---------------------------------------------------------------------------

def smoke_test_scanner(scanner: ScannerHost, protocols: list[str]) -> tuple[bool, str, list[str]]:
    """
    SSH in and check what portscan.sh needs: REMOTE_DEPENDENCIES (plus
    REMOTE_UDP_DEPENDENCIES if UDP is requested) and bash >= REMOTE_MIN_BASH.
    nc is only checked for a note: portscan.sh uses ./nc (in the SSH login
    directory, which is where it runs) or nc/ncat/netcat on PATH, and falls
    back to bash's /dev/tcp without one.
    Returns (ok, error_message, notes). Distinguishes auth failure, timeout,
    missing tools and old bash in the message.
    """
    required = list(REMOTE_DEPENDENCIES)
    if "udp" in protocols:
        required += REMOTE_UDP_DEPENDENCIES
    # Results are tagged so stray shell-profile output can't be mistaken for them.
    script = (
        f"for t in {' '.join(required)}; do "
        f'command -v "$t" >/dev/null 2>&1 || echo "MISSING:$t"; done; '
        "command -v bash >/dev/null 2>&1 && "
        "echo \"BASHVER:$(bash -c 'echo ${BASH_VERSINFO[0]}')\"; "
        "if [ -x ./nc ]; then echo NC:./nc; "
        "else echo \"NC:$(command -v nc || command -v ncat || command -v netcat)\"; fi"
    )
    result = run_remote(scanner, f"sh -c {shlex.quote(script)}")
    if result.returncode != 0:
        return False, describe_ssh_failure(result), []

    tagged = {}
    missing = []
    for line in result.stdout.splitlines():
        tag, sep, value = line.partition(":")
        if not sep:
            continue
        if tag == "MISSING":
            missing.append(value)
        elif tag in ("BASHVER", "NC"):
            tagged[tag] = value.strip()
    if missing:
        return False, f"missing on scanner: {', '.join(missing)}", []
    bash_major = tagged.get("BASHVER", "")
    if not bash_major.isdigit() or int(bash_major) < REMOTE_MIN_BASH:
        return False, f"{DROPPER_NAME} needs bash {REMOTE_MIN_BASH}+ (found: {bash_major or 'unknown'})", []

    notes = []
    if "tcp" in protocols and not tagged.get("NC"):
        notes.append(f"no nc found; {DROPPER_NAME} will fall back to bash /dev/tcp for TCP")
    return True, "", notes


def smoke_test_target(scanner: ScannerHost, target: Target) -> bool:
    """ICMP ping the target from the scanner (ping -c1 -W PING_TIMEOUT)."""
    command = f"ping -c 1 -W {PING_TIMEOUT} {shlex.quote(target.address)} >/dev/null 2>&1"
    result = run_remote(scanner, command, timeout=SSH_COMMAND_TIMEOUT + PING_TIMEOUT)
    return result.returncode == 0


def _smoke_one(scanner: ScannerHost, config: ScanConfig) -> tuple[bool, str, list[str], bool | None]:
    ok, error, notes = smoke_test_scanner(scanner, config.protocols)
    reachable = smoke_test_target(scanner, config.target) if ok else None
    return ok, error, notes, reachable


def run_smoke_tests(config: ScanConfig) -> SmokeReport:
    """
    Smoke test every scanner in parallel (bounded by max_concurrent): SSH +
    dependency check first, then the target ping from scanners that passed.
    """
    print(f"Smoke testing {len(config.scanners)} scanner(s)...")
    with ThreadPoolExecutor(max_workers=config.max_concurrent) as pool:
        outcomes = list(pool.map(lambda s: _smoke_one(s, config), config.scanners))

    report = SmokeReport()
    for scanner, (ok, error, notes, reachable) in zip(config.scanners, outcomes):
        report.ssh_ok[scanner] = ok
        if ok:
            report.target_reachable[scanner] = bool(reachable)
            report.notes[scanner] = notes
        else:
            report.ssh_errors[scanner] = error
    return report


def print_smoke_report(report: SmokeReport, target: Target) -> None:
    """
    Per-scanner summary: SSH status (+ error) and ping status.
    Ping failures are flagged as warnings ("ICMP may be filtered"), not errors.
    """
    print(f"\nSmoke test results (target: {target.label})")
    width = max(len(s.label) for s in report.ssh_ok)
    for scanner, ok in report.ssh_ok.items():
        if not ok:
            status, detail = "FAIL", f"SSH: {report.ssh_errors[scanner]}"
        elif report.target_reachable.get(scanner):
            status, detail = " OK ", "SSH ok, target replied to ping"
        else:
            status, detail = "WARN", "SSH ok, no ping reply (ICMP may be filtered; scanner will still be used)"
        print(f"  [{status}] {scanner.label:<{width}}  {detail}")
        for note in report.notes.get(scanner, []):
            print(f"         {'':<{width}}  note: {note}")
    print(f"\n{len(report.healthy_scanners)} of {len(report.ssh_ok)} scanner(s) ready.")


def prompt_continue(report: SmokeReport) -> bool:
    """
    Mandatory gate - there is deliberately no flag to bypass it.
    Return False immediately if no scanners are healthy; otherwise ask y/N
    (default N). Requires an interactive terminal, so the gate can't be
    satisfied by piping input in; EOF counts as "no".
    """
    healthy = report.healthy_scanners
    if not healthy:
        print("No usable scanners - aborting.")
        return False
    if not sys.stdin.isatty():
        print("Confirmation requires an interactive terminal - aborting.")
        return False
    try:
        answer = input(f"Proceed with scanning from {len(healthy)} scanner(s)? [y/N] ")
    except EOFError:
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


# ---------------------------------------------------------------------------
# 4. Scan orchestration
# ---------------------------------------------------------------------------

def deploy_dropper(scanner: ScannerHost) -> str:
    """
    Create a temp directory on the scanner (mktemp -d), scp DROPPER_NAME into
    it under its own name, and return the directory. Keeping the real name
    matters: portscan.sh prefixes its messages with its own filename, which
    is how dropper_log() picks them out of stderr.
    The dropper is run as 'bash <path>', so it needs no execute bit and works
    even if the temp dir is mounted noexec.
    """
    result = run_remote(scanner, "mktemp -d -t quartzbreeze.XXXXXX")
    output = result.stdout.strip().splitlines()
    if result.returncode != 0:
        raise RemoteError(f"could not create temp dir: {describe_ssh_failure(result)}")
    if not output or not REMOTE_DIR_RE.fullmatch(output[-1]):
        raise RemoteError(f"unexpected mktemp output: {result.stdout.strip()!r}")
    remote_dir = output[-1]
    try:
        copy_to_remote(scanner, DROPPER_NAME, f"{remote_dir}/{DROPPER_NAME}")
    except RemoteError:
        remove_remote_dir(scanner, remote_dir)
        raise
    return remote_dir


def run_dropper(
    scanner: ScannerHost,
    remote_dir: str,
    target: Target,
    proto: str,
    port_spec: str,
) -> RemoteResult:
    """
    Invoke: bash <remote_dir>/portscan.sh --reason [-sU] -p<port_spec> <target>
    It runs from the SSH login directory (not the temp dir), so a static nc
    the operator placed there is picked up as portscan.sh intends.
    Arguments are shell-quoted since they travel through the remote shell.
    No timeout: scan duration depends on the port range.
    Returns the RemoteResult (stdout = report, stderr = dropper log).
    Raises RemoteError on non-zero exit, quoting the dropper's own messages.
    """
    argv = ["bash", f"{remote_dir}/{DROPPER_NAME}", *DROPPER_OPTIONS, *PROTO_FLAGS[proto],
            f"-p{port_spec}", target.address]
    result = run_remote(scanner, " ".join(shlex.quote(a) for a in argv), timeout=None)
    if result.returncode == 255:
        raise RemoteError(f"ssh failed during scan: {describe_ssh_failure(result)}")
    if result.returncode != 0:
        messages = dropper_log(result.stderr) or result.stderr.strip().splitlines()[-1:]
        raise RemoteError(f"{DROPPER_NAME} exited with status {result.returncode}: "
                          f"{'; '.join(messages) or 'no error output'}")
    return result


def scan_from_scanner(scanner: ScannerHost, config: ScanConfig) -> list[ScanResult]:
    """
    One scanner's whole job: deploy the dropper once, run it once per
    protocol, parse output, then delete the dropper after all of this
    scanner's scans are done (finally: remove_remote_dir, so it also runs on
    error). Errors are captured into ScanResult.error rather than raised, so
    one bad scanner never aborts the run.
    """
    try:
        remote_dir = deploy_dropper(scanner)
    except QuartzError as exc:
        return [ScanResult(scanner, proto, error=f"deploy failed: {exc}")
                for proto in config.protocols]

    results = []
    try:
        for proto in config.protocols:
            if ABORT.is_set():
                results.append(ScanResult(scanner, proto, error="cancelled"))
                continue
            try:
                result = run_dropper(scanner, remote_dir, config.target, proto, config.port_spec)
            except QuartzError as exc:
                results.append(ScanResult(scanner, proto, error=str(exc)))
                continue
            ports, notes = parse_dropper_output(result.stdout)
            results.append(ScanResult(scanner, proto, ports=ports,
                                      notes=notes + dropper_log(result.stderr)))
    finally:
        remove_remote_dir(scanner, remote_dir)
    return results


def run_scans(config: ScanConfig, report: SmokeReport) -> list[ScanResult]:
    """
    ThreadPoolExecutor(max_workers=config.max_concurrent) over
    report.healthy_scanners, each running scan_from_scanner.
    Prints progress as each scanner completes. On Ctrl-C, queued scanners are
    cancelled and running ones finish cleanup before the interrupt propagates.
    Results are returned in scanner-list order.
    """
    scanners = report.healthy_scanners
    protocols = "+".join(p.upper() for p in config.protocols)
    print(f"\nScanning {config.target.label} ({protocols}, ports {config.port_spec}) "
          f"from {len(scanners)} scanner(s), up to {config.max_concurrent} at once...")

    by_scanner: dict[ScannerHost, list[ScanResult]] = {}
    pool = ThreadPoolExecutor(max_workers=config.max_concurrent)
    try:
        futures = {pool.submit(scan_from_scanner, s, config): s for s in scanners}
        for done, future in enumerate(as_completed(futures), start=1):
            scanner = futures[future]
            try:
                results = future.result()
            except Exception as exc:   # bug guard: one scanner must not sink the run
                log.debug("Unexpected error on %s", scanner.label, exc_info=True)
                results = [ScanResult(scanner, p, error=f"unexpected error: {exc}")
                           for p in config.protocols]
            by_scanner[scanner] = results
            failed = [r.proto.upper() for r in results if r.error]
            status = "done" if not failed else f"{'/'.join(failed)} scan failed"
            print(f"  [{done}/{len(scanners)}] {scanner.label}: {status}")
    except KeyboardInterrupt:
        ABORT.set()
        print("\nInterrupted - cleaning up droppers on scanners...", file=sys.stderr)
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    finally:
        pool.shutdown(wait=True)

    return [r for s in scanners for r in by_scanner[s]]


# ---------------------------------------------------------------------------
# 5. Parsing & reporting
# ---------------------------------------------------------------------------

def parse_dropper_output(stdout: str) -> tuple[list[PortResult], list[str]]:
    """
    Parse portscan.sh's stdout (run with --reason). Real output looks like:
        Scan report for 10.0.0.5
        PORT        STATE  SERVICE             REASON            BANNER
        22/tcp      open   ssh                 syn-ack           SSH-2.0-OpenSSH_9.2p1
        Not shown: 1021 closed (1021 conn-refused)
    or, with nothing open, no table at all:
        Scan report for 10.0.0.5
        All 1024 scanned TCP port(s) are closed (1024 conn-refused)
        No open ports found.
    Returns (ports, notes): port rows become PortResults; every other
    non-blank line except the 'Scan report for' and table header lines is
    kept verbatim as a note, since those lines describe the closed/filtered
    ports. A port-shaped row that fails to parse is logged and kept as a note.
    """
    ports: list[PortResult] = []
    notes: list[str] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text or text.startswith("Scan report for ") or is_table_header(text):
            continue
        if PORT_FIELD_RE.fullmatch(text.split(maxsplit=1)[0]):
            try:
                ports.append(parse_port_row(text))
                continue
            except ValueError as exc:
                log.warning("Unparseable dropper row %r: %s", text, exc)
        notes.append(text)
    return ports, notes


def is_table_header(line: str) -> bool:
    """True for portscan.sh's 'PORT STATE SERVICE [REASON] BANNER' line."""
    return line.split()[:3] == list(TABLE_COLUMNS[:3])


def parse_port_row(line: str) -> PortResult:
    """
    Split one port row. PORT, STATE, SERVICE and REASON are always single
    tokens in portscan.sh output (SERVICE is 'unknown' when it has no name;
    REASON is never empty), so the first four whitespace-separated fields are
    taken as-is and everything after them is the BANNER, which may contain
    spaces or be empty.
    Raises ValueError if the row has fewer than four fields or the PORT field
    isn't '<1-65535>/<tcp|udp>'.
    """
    fields = line.split(maxsplit=4)
    if len(fields) < 4:
        raise ValueError("expected PORT STATE SERVICE REASON [BANNER]")
    port_match = PORT_FIELD_RE.fullmatch(fields[0])
    if not port_match:
        raise ValueError(f"bad PORT field {fields[0]!r}")
    port = int(port_match.group(1))
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} out of range")
    return PortResult(port=port, proto=port_match.group(2), state=fields[1],
                      service=fields[2], reason=fields[3],
                      banner=fields[4] if len(fields) > 4 else "")


def dropper_log(stderr: str) -> list[str]:
    """
    portscan.sh's own messages from stderr: lines prefixed 'portscan.sh: '
    (prefix removed), plus the indented continuation lines its warn() adds.
    Anything else on stderr (shell-profile noise and so on) is dropped.
    These say which probe method was used and whether the scan completed.
    """
    prefix = f"{DROPPER_NAME}: "
    messages: list[str] = []
    for line in stderr.splitlines():
        if line.startswith(prefix):
            messages.append(line[len(prefix):].strip())
        elif messages and line.startswith("  ") and line.strip():
            messages[-1] += " " + line.strip()
    return messages


def format_port_table(ports: list[PortResult]) -> str:
    """
    Render the 'PORT STATE SERVICE REASON BANNER' block for one scan, with
    each column sized to its widest value, sorted by port.
    """
    rows = [[f"{p.port}/{p.proto}", p.state, p.service, p.reason, p.banner]
            for p in sorted(ports, key=lambda p: (p.proto, p.port))]
    table = [list(TABLE_COLUMNS), *rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(TABLE_COLUMNS))]
    return "\n".join(COLUMN_GAP.join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip()
                     for row in table)


def _format_scan_section(result: ScanResult) -> list[str]:
    """
    One protocol's results under one scanner: a 'TCP' / 'UDP' heading, then,
    indented, the port table, a blank line, and the dropper's notes. A failed
    scan shows 'Scan failed: <error>' in place of the table.
    """
    lines = [result.proto.upper()]
    if result.error:
        return lines + [f"{INDENT}Scan failed: {result.error}"]
    if result.ports:
        lines += [INDENT + row for row in format_port_table(result.ports).splitlines()]
        if result.notes:
            lines.append("")
    lines += [INDENT + note for note in result.notes]
    if not result.ports and not result.notes:
        lines.append(f"{INDENT}No ports reported.")
    return lines


def format_report(
    config: ScanConfig,
    results: list[ScanResult],
    skipped: dict[ScannerHost, str] | None = None,
) -> str:
    """
    Render the full report:
        ========================================================
        QuartzBreeze scan report for <fqdn> (<ip>)
        ========================================================
        Ports:      <port spec>
        Protocols:  TCP, UDP
        Scanners:   <n> scanned, <n> not used (failed smoke test)

        --------------------------------------------------------
        Scan from <host> (<user>@<host>:<port>)
        --------------------------------------------------------

        TCP
          <port table>

          <dropper notes, e.g. "Not shown: 1021 closed (1021 conn-refused)">

        UDP
          <port table | "Scan failed: <error>">
          ...
        --------------------------------------------------------
        Scanners not used (failed smoke test)
        --------------------------------------------------------
          <user>@<host>:<port>  <reason>

        ========================================================
    A full-width rule divides each scanner's results from the next. Under
    each scanner, TCP and UDP are separate sections (TCP first), each with its
    own table. A section's notes are the dropper's lines about the ports not
    in its table (closed vs no-response is the firewall signal). Failed scans
    are stated explicitly, and scanners that failed the smoke test (skipped)
    get their own section, so gaps in coverage are visible rather than silent.
    """
    grouped: dict[ScannerHost, list[ScanResult]] = {}
    for result in results:
        grouped.setdefault(result.scanner, []).append(result)
    skipped = skipped or {}

    ports = "all (1-65535)" if config.port_spec == "-" else config.port_spec
    scanners = f"{len(grouped)} scanned"
    if skipped:
        scanners += f", {len(skipped)} not used (failed smoke test)"
    lines = [
        REPORT_RULE,
        f"QuartzBreeze scan report for {config.target.label}",
        REPORT_RULE,
        f"Ports:      {ports}",
        f"Protocols:  {', '.join(p.upper() for p in config.protocols)}",
        f"Scanners:   {scanners}",
        "",
    ]

    proto_order = list(PROTO_FLAGS)
    for scanner, scanner_results in grouped.items():
        lines += [SECTION_RULE, f"Scan from {scanner.host} ({scanner.label})", SECTION_RULE, ""]
        for result in sorted(scanner_results, key=lambda r: proto_order.index(r.proto)):
            lines += _format_scan_section(result) + [""]

    if skipped:
        width = max(len(s.label) for s in skipped)
        lines += [SECTION_RULE, "Scanners not used (failed smoke test)", SECTION_RULE, ""]
        lines += [f"{INDENT}{s.label.ljust(width)}  {reason}" for s, reason in skipped.items()]
        lines.append("")

    lines.append(REPORT_RULE)
    return "\n".join(lines) + "\n"


def build_output_filename(config: ScanConfig) -> str:
    """
    quartzbreeze-<target>-<ports>.txt, with characters unsafe for filenames
    (',', '/', ':') replaced by '_'. A bare '-' port spec becomes 'all';
    the port part is truncated if excessively long.
    """
    def safe(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9.-]+", "_", text)

    ports = "all" if config.port_spec == "-" else config.port_spec
    return f"quartzbreeze-{safe(config.target.raw)}-{safe(ports)[:60]}.txt"


def write_report(text: str, path: str) -> None:
    """Write the report to disk. Raises QuartzError on failure."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        raise QuartzError(f"Could not write report to {path}: {exc.strerror}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        check_local_dependencies()
        config = build_config(args)

        report = run_smoke_tests(config)
        print_smoke_report(report, config.target)
        if not prompt_continue(report):
            return 1

        results = run_scans(config, report)

        text = format_report(config, results, report.ssh_errors)
        print("\n" + text)
        path = build_output_filename(config)
        write_report(text, path)
        print(f"Report saved to {path}")
    except QuartzError as exc:
        log.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
