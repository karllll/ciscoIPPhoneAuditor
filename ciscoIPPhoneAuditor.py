#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cisco_phone_config_audit.py - audit Cisco IP phone TFTP configuration files.

For each phone IP supplied, the script will:

  1. Fetch  /CGI/Java/Serviceability?adapter=device.statistics.configuration
     over HTTP (port 80) and fall back to HTTPS (port 443, certificate
     validation disabled, because phones ship self-signed MIC/LSC certs).
  2. Scrape "Host name" and "TFTP server 1" (plus MAC address as a fallback)
     from the Network Setup table.
  3. Pull the device's configuration file from that TFTP server, trying the
     encrypted, signed and plaintext variants so that the *availability* of
     each one becomes evidence in its own right.
  4. Run a best-practice analysis over the configuration and print every
     defect as it is detected.

Only the Python standard library is used - the TFTP client (RFC 1350 + the
RFC 2348 blksize option) is implemented inline.

Usage
-----
    ./cisco_phone_config_audit.py -i phones.txt
    ./cisco_phone_config_audit.py 10.1.2.3 10.1.2.4 --workers 16
    ./cisco_phone_config_audit.py -i phones.txt \
        --expected-tftp 192.168.46.89,192.168.46.90 \
        --json audit.json --csv audit.csv --save-configs ./configs \
        --fail-on HIGH

Input file format: one IP (or hostname) per line; blank lines and anything
after a '#' are ignored.  Use "-" to read the list from stdin.

Notes
-----
* Secret values are never printed in full unless --show-secrets is given;
  by default only a length and a SHA-256 prefix are shown so the output can
  safely be pasted into a ticket.
* Cisco's boolean enums are not consistent (webAccess/sshAccess use
  0=Enabled/1=Disabled, while settingsAccess uses 0=Disabled/1=Enabled/
  2=Restricted).  Every finding therefore prints the raw "tag=value" it was
  derived from so you can sanity-check it against your firmware release.
* Run this only against equipment you are authorised to assess.  It is a
  read-only audit: nothing is written to the phones or the TFTP servers.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cfutures
import csv
import hashlib
import html as html_mod
import json
import os
import re
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

STATS_PATH = "/CGI/Java/Serviceability?adapter=device.statistics.configuration"
USER_AGENT = "cisco-phone-config-audit/%s" % __version__
MAX_HTTP_BYTES = 4 * 1024 * 1024
MAX_TFTP_BYTES = 8 * 1024 * 1024

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_COLOR = {
    "CRITICAL": "\033[1;35m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
}
RESET = "\033[0m"


class AuditError(Exception):
    """Fatal problem while auditing a single target."""


# --------------------------------------------------------------------------
# Findings and reporting
# --------------------------------------------------------------------------


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
        }


class Reporter:
    """Thread-safe streaming console output."""

    def __init__(self, color: bool, min_severity: str, quiet: bool = False):
        self.color = color
        self.min_rank = SEV_RANK[min_severity]
        self.quiet = quiet
        self._lock = threading.Lock()
        self.counts = {s: 0 for s in SEVERITIES}

    def _emit(self, text: str) -> None:
        with self._lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def info(self, target: str, text: str) -> None:
        if not self.quiet:
            self._emit("[%s] %s" % (target, text))

    def error(self, target: str, text: str) -> None:
        tag = "\033[1;31mERROR\033[0m" if self.color else "ERROR"
        self._emit("[%s] %s %s" % (target, tag, text))

    def finding(self, target: str, f: Finding) -> None:
        with self._lock:
            self.counts[f.severity] += 1
        if SEV_RANK[f.severity] > self.min_rank:
            return
        sev = f.severity
        if self.color:
            sev = "%s%-8s%s" % (SEV_COLOR[f.severity], f.severity, RESET)
        else:
            sev = "%-8s" % f.severity
        line = "[%s]   %s %-22s %s" % (target, sev, f.code, f.title)
        if f.detail:
            line += "\n[%s]            -> %s" % (target, f.detail)
        self._emit(line)


# --------------------------------------------------------------------------
# HTTP: retrieve and parse the phone's Network Setup page
# --------------------------------------------------------------------------


def _url_host(host: str) -> str:
    return "[%s]" % host if ":" in host and not host.startswith("[") else host


def fetch_stats_page(host: str, timeout: float) -> Tuple[str, str]:
    """Return (url, html).  HTTP/80 is tried first, then HTTPS/443."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Old phone firmware only speaks TLS 1.0/1.1 with legacy ciphers.
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except (AttributeError, ssl.SSLError, ValueError):
            pass

    # Phones are on the local voice VLAN: never send these requests through a
    # corporate proxy picked up from http_proxy/https_proxy in the environment.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )

    problems = []
    for scheme, port in (("http", 80), ("https", 443)):
        url = "%s://%s:%d%s" % (scheme, _url_host(host), port, STATS_PATH)
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                raw = resp.read(MAX_HTTP_BYTES)
            return url, raw.decode(charset, "replace")
        except urllib.error.HTTPError as exc:
            # A 401/403 is a real answer - the web server is up but locked down.
            problems.append("%s -> HTTP %s %s" % (scheme, exc.code, exc.reason))
        except Exception as exc:  # URLError, socket.timeout, ssl errors, ...
            problems.append("%s -> %s" % (scheme, _short_exc(exc)))
    raise AuditError("web interface unreachable (%s)" % "; ".join(problems))


_TAG_RE = re.compile(r"<[^>]+>")
_ROW_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.I | re.S)
_CELL_RE = re.compile(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", re.I | re.S)
_BOLD_RE = re.compile(r"<b\b[^>]*>(.*?)</b>", re.I | re.S)


def _plain(fragment: str) -> str:
    text = re.sub(r"<br\s*/?>", " ", fragment, flags=re.I)
    text = _TAG_RE.sub("", text)
    text = html_mod.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _norm_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", label.lower()).strip()


def parse_stats_page(doc: str) -> Dict[str, str]:
    """Return {normalised label: value} for every row of the status table."""
    fields: Dict[str, str] = {}

    for row in _ROW_RE.findall(doc):
        cells = [_plain(c) for c in _CELL_RE.findall(row)]
        cells = [c for c in cells if c]
        if not cells:
            continue
        label = _norm_label(cells[0])
        value = cells[-1] if len(cells) > 1 else ""
        if label and label not in fields:
            fields[label] = value

    if not fields:
        # Fallback for firmware that does not use a table layout: pair up
        # consecutive <b> elements (label, value, label, value, ...).
        bolds = [_plain(b) for b in _BOLD_RE.findall(doc)]
        for i in range(0, len(bolds) - 1, 2):
            label = _norm_label(bolds[i])
            if label and label not in fields:
                fields[label] = bolds[i + 1]
    return fields


def pick_field(fields: Dict[str, str], *labels: str) -> Optional[str]:
    for label in labels:
        value = fields.get(label)
        if value:
            return value
    # loose match: the page may render "TFTP Server 1 :" etc.
    for label in labels:
        for key, value in fields.items():
            if value and key.startswith(label):
                return value
    return None


HOSTNAME_LABELS = ("host name", "hostname", "device name")
TFTP1_LABELS = ("tftp server 1", "tftp server1", "tftp server")
TFTP2_LABELS = ("tftp server 2", "tftp server2")
MAC_LABELS = ("mac address", "mac addr")


# --------------------------------------------------------------------------
# Minimal TFTP read client (RFC 1350, RFC 2348 blksize option)
# --------------------------------------------------------------------------


TFTP_ERRORS = {
    0: "not defined",
    1: "file not found",
    2: "access violation",
    3: "disk full",
    4: "illegal TFTP operation",
    5: "unknown transfer ID",
    6: "file already exists",
    7: "no such user",
    8: "option negotiation failed",
}


class TftpError(Exception):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code

    @property
    def not_found(self) -> bool:
        return self.code == 1


def tftp_read(
    server: str,
    filename: str,
    port: int = 69,
    timeout: float = 5.0,
    retries: int = 3,
    blksize: int = 1428,
    max_bytes: int = MAX_TFTP_BYTES,
) -> bytes:
    """Download `filename` from `server` and return its bytes."""
    try:
        infos = socket.getaddrinfo(server, port, 0, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise TftpError("cannot resolve %s: %s" % (server, exc))
    family, socktype, proto, _canon, addr = infos[0]

    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        request = (
            b"\x00\x01"
            + filename.encode("ascii", "strict")
            + b"\x00octet\x00blksize\x00"
            + str(blksize).encode()
            + b"\x00tsize\x000\x00"
        )
        sock.sendto(request, addr)

        data = bytearray()
        last_sent = request
        peer = None
        expected = 1
        current_blksize = 512
        attempts = 0

        while True:
            try:
                packet, raddr = sock.recvfrom(65536)
            except socket.timeout:
                attempts += 1
                if attempts > retries:
                    raise TftpError("timed out waiting for %s" % filename)
                sock.sendto(last_sent, peer or addr)
                continue

            if peer is None:
                peer = raddr          # server replies from an ephemeral TID
            elif raddr != peer:
                continue              # stray packet from somewhere else
            attempts = 0

            if len(packet) < 4:
                continue
            opcode = int.from_bytes(packet[:2], "big")

            if opcode == 5:  # ERROR
                code = int.from_bytes(packet[2:4], "big")
                msg = packet[4:].split(b"\x00", 1)[0].decode("ascii", "replace")
                raise TftpError(
                    "%s (%s)" % (msg or TFTP_ERRORS.get(code, "error"), code), code
                )

            if opcode == 6:  # OACK
                parts = packet[2:].split(b"\x00")
                options = {
                    parts[i].decode("ascii", "replace").lower():
                    parts[i + 1].decode("ascii", "replace")
                    for i in range(0, len(parts) - 1, 2)
                    if parts[i]
                }
                if "blksize" in options:
                    try:
                        current_blksize = max(8, min(65464, int(options["blksize"])))
                    except ValueError:
                        pass
                last_sent = b"\x00\x04\x00\x00"
                sock.sendto(last_sent, peer)
                continue

            if opcode == 3:  # DATA
                block = int.from_bytes(packet[2:4], "big")
                payload = packet[4:]
                if block == expected:
                    data += payload
                    if len(data) > max_bytes:
                        raise TftpError("file larger than %d bytes" % max_bytes)
                    last_sent = b"\x00\x04" + packet[2:4]
                    sock.sendto(last_sent, peer)
                    expected = (expected + 1) & 0xFFFF
                    if len(payload) < current_blksize:
                        return bytes(data)
                else:
                    sock.sendto(last_sent, peer)  # duplicate: re-ACK
                continue

            raise TftpError("unexpected TFTP opcode %d" % opcode)
    finally:
        sock.close()


# --------------------------------------------------------------------------
# Configuration file retrieval
# --------------------------------------------------------------------------


@dataclass
class ConfigFile:
    name: str
    data: bytes
    kind: str          # encrypted | signed | plain | binary
    xml: Optional[bytes] = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def extract_xml(data: bytes, filename: str) -> Tuple[Optional[bytes], str]:
    """Strip a Cisco .sgn signature header and return (xml_bytes, kind)."""
    start = data.find(b"<?xml")
    if start < 0:
        start = data.find(b"<device")
    if start < 0:
        kind = "encrypted" if filename.endswith(".enc.sgn") else "binary"
        return None, kind

    body = data[start:]
    end = body.rfind(b"</device>")
    if end >= 0:
        body = body[: end + len(b"</device>")]
    if filename.endswith(".sgn") or start > 0:
        kind = "signed"
    else:
        kind = "plain"
    return body, kind


def config_candidates(hostname: str) -> List[str]:
    base = hostname.strip()
    return [
        "%s.cnf.xml.enc.sgn" % base,
        "%s.cnf.xml.sgn" % base,
        "%s.cnf.xml" % base,
    ]


def retrieve_configs(
    tftp_server: str, hostname: str, port: int, timeout: float, retries: int
) -> Tuple[Dict[str, ConfigFile], List[str]]:
    """Try every config-file variant; return what was downloadable."""
    found: Dict[str, ConfigFile] = {}
    notes: List[str] = []
    for name in config_candidates(hostname):
        try:
            raw = tftp_read(
                tftp_server, name, port=port, timeout=timeout, retries=retries
            )
        except TftpError as exc:
            if not exc.not_found:
                notes.append("%s: %s" % (name, exc))
            continue
        xml, kind = extract_xml(raw, name)
        found[name] = ConfigFile(name=name, data=raw, kind=kind, xml=xml)
    return found, notes


# --------------------------------------------------------------------------
# Best-practice analysis
# --------------------------------------------------------------------------


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def walk(root: ET.Element, path: str = "") -> Iterable[Tuple[str, ET.Element]]:
    for child in root:
        child_path = "%s/%s" % (path, local_name(child.tag))
        yield child_path, child
        yield from walk(child, child_path)


def find_values(root: ET.Element, tag: str) -> List[Tuple[str, str]]:
    """All (path, text) pairs for `tag` anywhere in the tree."""
    out = []
    for path, el in walk(root, "/" + local_name(root.tag)):
        if local_name(el.tag) == tag and el.text is not None:
            text = el.text.strip()
            if text:
                out.append((path, text))
    return out


@dataclass
class EnumCheck:
    tags: Tuple[str, ...]
    code: str
    label: str
    values: Dict[str, str]
    bad: Dict[str, Tuple[str, str]]
    missing: Optional[Tuple[str, str]] = None


# NOTE: Cisco's enumerations are not uniform across settings or firmware
# releases.  Each finding below prints the raw tag=value so the result can be
# verified against the "Phone Features and Product Specific Configuration"
# documentation for the model in question.
ENUM_CHECKS: List[EnumCheck] = [
    EnumCheck(
        tags=("deviceSecurityMode",),
        code="SEC-MODE",
        label="Device security mode",
        values={"0": "Non-Secure", "1": "Authenticated", "2": "Encrypted"},
        bad={
            "0": ("HIGH", "Device security mode is Non-Secure: signalling and "
                          "media are sent in the clear and the phone will "
                          "accept an unauthenticated call manager."),
            "1": ("MEDIUM", "Device security mode is Authenticated: signalling "
                            "is protected by TLS but RTP media is not "
                            "encrypted (no SRTP)."),
        },
        missing=("MEDIUM", "No deviceSecurityMode element in the configuration "
                           "- the device is almost certainly running "
                           "non-secure."),
    ),
    EnumCheck(
        tags=("transportLayerProtocol",),
        code="SEC-SIP-TRANSPORT",
        label="SIP transport",
        values={"1": "TCP", "2": "UDP", "3": "TCP+UDP", "4": "TLS"},
        bad={
            "1": ("HIGH", "SIP signalling uses cleartext TCP; use a secure "
                          "phone security profile (TLS/5061)."),
            "2": ("HIGH", "SIP signalling uses cleartext UDP; use a secure "
                          "phone security profile (TLS/5061)."),
            "3": ("HIGH", "SIP signalling uses cleartext TCP/UDP; use a secure "
                          "phone security profile (TLS/5061)."),
        },
    ),
    EnumCheck(
        tags=("encrConfig",),
        code="SEC-ENCR-CONFIG",
        label="Encrypted configuration",
        values={"true": "Enabled", "false": "Disabled",
                "1": "Enabled", "0": "Disabled"},
        bad={
            "false": ("MEDIUM", "TFTP configuration encryption is disabled; "
                                "anything in this file is readable by anyone "
                                "who can reach the TFTP server."),
            "0": ("MEDIUM", "TFTP configuration encryption is disabled; "
                            "anything in this file is readable by anyone who "
                            "can reach the TFTP server."),
        },
    ),
    EnumCheck(
        tags=("sshAccess",),
        code="SVC-SSH",
        label="SSH access",
        values={"0": "Enabled", "1": "Disabled"},
        bad={"0": ("HIGH", "SSH is enabled on the handset. Disable it unless "
                           "it is actively needed for troubleshooting.")},
    ),
    EnumCheck(
        tags=("webAccess",),
        code="SVC-WEB",
        label="Web access",
        values={"0": "Enabled", "1": "Disabled", "2": "Read-Only"},
        bad={"0": ("MEDIUM", "The phone web server is enabled and exposes "
                             "device, network and call statistics without "
                             "authentication on most firmware.")},
    ),
    EnumCheck(
        tags=("webProtocol",),
        code="SVC-WEB-PROTO",
        label="Web protocol",
        values={"0": "HTTP", "1": "HTTPS"},
        bad={"0": ("MEDIUM", "The phone web interface is served over plain "
                             "HTTP; set Web Protocol to HTTPS.")},
    ),
    EnumCheck(
        tags=("settingsAccess",),
        code="SVC-SETTINGS",
        label="Settings access",
        values={"0": "Disabled", "1": "Enabled", "2": "Restricted"},
        bad={"1": ("LOW", "Full settings access from the handset keypad is "
                          "enabled; consider Restricted so users cannot alter "
                          "network settings.")},
    ),
    EnumCheck(
        tags=("spanToPCPort",),
        code="NET-SPAN-PC",
        label="Span to PC port",
        values={"0": "Enabled", "1": "Disabled"},
        bad={"0": ("HIGH", "Span to PC Port is enabled: voice VLAN traffic, "
                           "including this phone's signalling and RTP, is "
                           "mirrored to the daisy-chained PC port.")},
    ),
    EnumCheck(
        tags=("voiceVlanAccess", "pcVoiceVlanAccess"),
        code="NET-VOICE-VLAN",
        label="PC port voice VLAN access",
        values={"0": "Enabled", "1": "Disabled"},
        bad={"0": ("HIGH", "A device on the PC port can reach the voice VLAN "
                           "directly (VLAN hopping). Disable PC Voice VLAN "
                           "Access.")},
    ),
    EnumCheck(
        tags=("garp", "gratuitousArp"),
        code="NET-GARP",
        label="Gratuitous ARP",
        values={"0": "Enabled", "1": "Disabled"},
        bad={"0": ("MEDIUM", "Gratuitous ARP is accepted, which makes ARP "
                             "spoofing / man-in-the-middle against the handset "
                             "easier.")},
    ),
    EnumCheck(
        tags=("pcPort",),
        code="NET-PC-PORT",
        label="PC port",
        values={"0": "Enabled", "1": "Disabled"},
        bad={"0": ("LOW", "The PC passthrough port is enabled. Disable it on "
                          "phones in public areas (lobby, conference room) "
                          "where no workstation is attached.")},
    ),
    EnumCheck(
        tags=("capfAuthMode",),
        code="SEC-CAPF",
        label="CAPF authentication mode",
        values={
            "0": "By Authentication String",
            "1": "By Null String",
            "2": "By Existing Certificate (precedence to LSC)",
            "3": "By Existing Certificate (precedence to MIC)",
            "4": "By Authentication String or Existing Certificate",
        },
        bad={"1": ("HIGH", "CAPF is set to 'By Null String': any device that "
                           "can present this device name can enrol and obtain "
                           "an LSC. Use an authentication string or existing "
                           "certificate.")},
    ),
    EnumCheck(
        tags=("webAdmin",),
        code="SVC-WEB-ADMIN",
        label="Phone web admin",
        values={"0": "Disabled", "1": "Enabled"},
        bad={"1": ("MEDIUM", "The phone's local web administration interface "
                             "is enabled; it allows configuration changes "
                             "directly on the handset.")},
    ),
    EnumCheck(
        tags=("enableHostIdCheck",),
        code="VPN-HOSTID",
        label="VPN host ID check",
        values={"0": "Disabled", "1": "Enabled"},
        bad={"0": ("MEDIUM", "The VPN profile does not verify the gateway "
                             "hostname against its certificate.")},
    ),
]


# Elements that are known to carry credentials in a phone configuration file.
SECRET_TAGS = {
    "sshpassword": "SSH password",
    "adminpassword": "Phone web-admin password",
    "phonepassword": "Phone settings (unlock) password",
    "authpassword": "SIP digest authentication password",
    "password": "Password",
    "passwd": "Password",
    "userpassword": "User password",
    "vpnpassword": "VPN password",
    "eappassword": "802.1X / EAP password",
    "wepkey": "WEP key",
    "presharedkey": "Wi-Fi pre-shared key",
    "pskkey": "Wi-Fi pre-shared key",
    "passphrase": "Wi-Fi passphrase",
    "wifipassword": "Wi-Fi password",
    "sharedsecret": "Shared secret",
    "secret": "Secret",
    "capfauthstring": "CAPF authentication string",
    "authenticationstring": "CAPF authentication string",
}

# Generic fallback pattern, with an allow-list for tags that merely *look*
# like secrets (public keys, hashes, key sizes, soft keys, ...).
SECRET_TAG_RE = re.compile(
    r"(password|passwd|pwd|secret|passphrase|credential|psk|privatekey)", re.I
)
SECRET_TAG_ALLOW = {
    "publickey", "certhash", "keysize", "keepalive", "keypad", "softkey",
    "softkeyfile", "hotkey", "keyorder", "passwordprompt", "secretprompt",
}
PLACEHOLDER_VALUES = {"", "null", "none", "n/a", "unprovisioned", "<null>"}

URL_WITH_CREDS_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/<>@]+:[^\s/<>@]+@", re.I)
URL_TAG_RE = re.compile(r"url$", re.I)
INLINE_SECRET_RE = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|passphrase)\b\s*[:=]\s*\S{3,}"
)


def _fingerprint(value: str, show: bool) -> str:
    if show:
        return "value=%r" % value
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return "length=%d sha256:%s (use --show-secrets to reveal)" % (
        len(value),
        digest,
    )


def analyse_config(
    xml_bytes: bytes,
    show_secrets: bool = False,
) -> Tuple[List[Finding], Dict[str, str]]:
    """Run every best-practice check over a phone configuration file."""
    findings: List[Finding] = []
    facts: Dict[str, str] = {}

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        return (
            [Finding("INFO", "CFG-PARSE", "Configuration file is not valid XML",
                     str(exc))],
            facts,
        )

    elements = [(path, el) for path, el in walk(root, "/" + local_name(root.tag))]

    # ---- informational facts -------------------------------------------
    for tag, key in (
        ("loadInformation", "firmware_load"),
        ("deviceProtocol", "protocol"),
        ("mlppDomainId", "mlpp_domain"),
        ("phonePersonalization", "phone_personalization"),
    ):
        values = find_values(root, tag)
        if values:
            facts[key] = values[0][1]

    tftp_in_config = [v for _p, v in find_values(root, "processNodeName")]
    if tftp_in_config:
        facts["call_managers"] = ",".join(dict.fromkeys(tftp_in_config))

    # ---- 1. stored secrets ---------------------------------------------
    for path, el in elements:
        tag = local_name(el.tag)
        tag_l = tag.lower()
        text = (el.text or "").strip()

        is_secret_tag = tag_l in SECRET_TAGS or (
            SECRET_TAG_RE.search(tag_l) and tag_l not in SECRET_TAG_ALLOW
        )
        if is_secret_tag and text.lower() not in PLACEHOLDER_VALUES:
            label = SECRET_TAGS.get(tag_l, "Credential-bearing element")
            findings.append(
                Finding(
                    "CRITICAL",
                    "SECRET-STORED",
                    "%s stored in the configuration file (<%s>)" % (label, tag),
                    "%s  %s - anyone who can read this file from TFTP has the "
                    "credential. Clear it in CUCM, or enable encrypted "
                    "configuration files for this device."
                    % (path, _fingerprint(text, show_secrets)),
                )
            )

        if text and URL_WITH_CREDS_RE.search(text):
            findings.append(
                Finding(
                    "CRITICAL",
                    "SECRET-URL-CREDS",
                    "Credentials embedded in a URL (<%s>)" % tag,
                    "%s  %s" % (path, _fingerprint(text, show_secrets)),
                )
            )
        elif text and len(text) < 512 and INLINE_SECRET_RE.search(text):
            findings.append(
                Finding(
                    "HIGH",
                    "SECRET-INLINE",
                    "Password-like string inside <%s>" % tag,
                    "%s  %s" % (path, _fingerprint(text, show_secrets)),
                )
            )

        for attr, attr_val in el.attrib.items():
            if SECRET_TAG_RE.search(attr) and attr_val.strip():
                findings.append(
                    Finding(
                        "HIGH",
                        "SECRET-ATTR",
                        "Credential in attribute %s of <%s>" % (attr, tag),
                        "%s  %s" % (path, _fingerprint(attr_val, show_secrets)),
                    )
                )

    for path, value in find_values(root, "sshUserId"):
        findings.append(
            Finding(
                "LOW",
                "SEC-SSH-USER",
                "SSH username published in the configuration file",
                "%s = %s - half of a credential pair is handed out over TFTP."
                % (path, value),
            )
        )

    for path, value in find_values(root, "authName"):
        findings.append(
            Finding(
                "LOW",
                "SEC-SIP-AUTHNAME",
                "SIP digest username published in the configuration file",
                "%s = %s" % (path, value),
            )
        )

    # ---- 2. enumerated security settings --------------------------------
    for check in ENUM_CHECKS:
        hits: List[Tuple[str, str]] = []
        for tag in check.tags:
            hits.extend(find_values(root, tag))
        if not hits:
            if check.missing:
                severity, message = check.missing
                findings.append(
                    Finding(severity, check.code,
                            "%s not set" % check.label, message)
                )
            continue

        seen = set()
        for path, raw in hits:
            key = (path, raw)
            if key in seen:
                continue
            seen.add(key)
            normalised = raw.strip().lower()
            pretty = check.values.get(normalised, check.values.get(raw, raw))
            facts.setdefault(check.code.lower(), "%s (%s)" % (raw, pretty))
            rule = check.bad.get(normalised) or check.bad.get(raw)
            if rule:
                severity, message = rule
                findings.append(
                    Finding(
                        severity,
                        check.code,
                        "%s = %s" % (check.label, pretty),
                        "%s=%s at %s. %s"
                        % (local_name(path.rsplit("/", 1)[-1]), raw, path, message),
                    )
                )

    # ---- 3. service URLs over cleartext ---------------------------------
    for path, el in elements:
        tag = local_name(el.tag)
        if not URL_TAG_RE.search(tag):
            continue
        value = (el.text or "").strip()
        if not value or value.lower() in PLACEHOLDER_VALUES:
            continue
        if value.lower().startswith("http://"):
            sensitive = tag.lower() in {
                "authenticationurl", "secureauthenticationurl", "directoryurl",
                "proxyserverurl",
            }
            findings.append(
                Finding(
                    "HIGH" if sensitive else "MEDIUM",
                    "URL-CLEARTEXT",
                    "%s points at cleartext HTTP" % tag,
                    "%s = %s - phone service traffic%s travels unencrypted and "
                    "can be modified in transit."
                    % (path, value,
                       " (including the user's PIN/credentials)" if sensitive else ""),
                )
            )

    auth_url = find_values(root, "authenticationURL")
    secure_auth_url = find_values(root, "secureAuthenticationURL")
    if auth_url and not secure_auth_url:
        findings.append(
            Finding(
                "MEDIUM",
                "URL-NO-SECURE-AUTH",
                "No secureAuthenticationURL configured",
                "Phone services will authenticate over the non-secure URL.",
            )
        )

    # ---- 4. consistency checks ------------------------------------------
    dsm = find_values(root, "deviceSecurityMode")
    certs = find_values(root, "certHash") + find_values(root, "certificate")
    if dsm and dsm[0][1] in {"1", "2"} and not certs:
        findings.append(
            Finding(
                "MEDIUM",
                "SEC-NO-CERT",
                "Secure device security mode without a certificate reference",
                "deviceSecurityMode=%s but the configuration carries no "
                "certHash/certificate element; the device may not actually "
                "have an LSC installed." % dsm[0][1],
            )
        )

    return findings, facts


def analyse_retrieval(
    configs: Dict[str, ConfigFile], hostname: str
) -> List[Finding]:
    """Findings derived from *which* config variants the TFTP server served."""
    findings: List[Finding] = []
    plain_names = [n for n, c in configs.items() if c.kind in {"plain", "signed"}]
    encrypted = [n for n, c in configs.items() if c.kind == "encrypted"]

    if encrypted and not plain_names:
        findings.append(
            Finding(
                "INFO",
                "CFG-ENCRYPTED",
                "Encrypted configuration file in use",
                "%s was served and is not readable without the device key - "
                "this is the desired state." % encrypted[0],
            )
        )
    if plain_names:
        findings.append(
            Finding(
                "MEDIUM",
                "CFG-READABLE",
                "Configuration is readable over anonymous TFTP",
                "%s downloaded without authentication. Enable TFTP encrypted "
                "configuration files for this device and restrict UDP/69 to "
                "the voice VLAN." % ", ".join(sorted(plain_names)),
            )
        )
    if encrypted and plain_names:
        findings.append(
            Finding(
                "HIGH",
                "CFG-ENC-BYPASS",
                "Encrypted and unencrypted copies of the configuration coexist",
                "The encrypted file %s is available, but %s can still be "
                "fetched in the clear, which defeats configuration encryption."
                % (encrypted[0], ", ".join(sorted(plain_names))),
            )
        )
    unsigned = [n for n, c in configs.items() if c.kind == "plain"]
    if unsigned:
        findings.append(
            Finding(
                "MEDIUM",
                "CFG-UNSIGNED",
                "Unsigned configuration file available",
                "%s carries no signature header. Without Security by Default "
                "(ITL) the phone cannot detect a spoofed TFTP server."
                % ", ".join(sorted(unsigned)),
            )
        )
    if not configs:
        findings.append(
            Finding(
                "INFO",
                "CFG-NONE",
                "No configuration file could be downloaded",
                "Tried: %s" % ", ".join(config_candidates(hostname)),
            )
        )
    return findings


# --------------------------------------------------------------------------
# Per-TFTP-server checks (performed once per server, then cached)
# --------------------------------------------------------------------------


class ServerChecker:
    def __init__(self, port: int, timeout: float, retries: int, enabled: bool):
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.enabled = enabled
        self._cache: Dict[str, List[Finding]] = {}
        self._lock = threading.Lock()

    def check(self, server: str) -> List[Finding]:
        if not self.enabled:
            return []
        with self._lock:
            if server in self._cache:
                return []  # already reported for this server
            self._cache[server] = []

        findings: List[Finding] = []

        def grab(name: str) -> Optional[bytes]:
            try:
                return tftp_read(
                    server, name, port=self.port,
                    timeout=self.timeout, retries=self.retries,
                )
            except TftpError:
                return None

        itl = grab("ITLFile.tlv")
        if itl:
            findings.append(
                Finding("INFO", "SRV-ITL",
                        "TFTP %s publishes ITLFile.tlv" % server,
                        "Security by Default is in use (%d bytes)." % len(itl)))
        else:
            findings.append(
                Finding("MEDIUM", "SRV-NO-ITL",
                        "TFTP %s does not publish ITLFile.tlv" % server,
                        "Without an Initial Trust List the phones cannot "
                        "verify that configuration files come from the real "
                        "cluster."))

        ctl = grab("CTLFile.tlv")
        if ctl:
            findings.append(
                Finding("INFO", "SRV-CTL",
                        "TFTP %s publishes CTLFile.tlv" % server,
                        "Cluster appears to be in mixed (secure) mode."))
        else:
            findings.append(
                Finding("LOW", "SRV-NO-CTL",
                        "TFTP %s does not publish CTLFile.tlv" % server,
                        "No CTL means the cluster is not in mixed mode, so "
                        "encrypted device security mode is unavailable."))

        default_cfg = grab("XMLDefault.cnf.xml")
        if default_cfg:
            findings.append(
                Finding("LOW", "SRV-DEFAULT-CFG",
                        "TFTP %s serves XMLDefault.cnf.xml anonymously" % server,
                        "The default configuration discloses call manager "
                        "names and firmware loads to anyone on the network. "
                        "Restrict UDP/69 to the voice VLAN."))
        return findings


# --------------------------------------------------------------------------
# Per-target driver
# --------------------------------------------------------------------------


@dataclass
class TargetResult:
    target: str
    ok: bool = False
    url: Optional[str] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    tftp1: Optional[str] = None
    tftp2: Optional[str] = None
    configs: Dict[str, str] = field(default_factory=dict)
    facts: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def as_dict(self) -> dict:
        data = {
            "target": self.target,
            "ok": self.ok,
            "url": self.url,
            "hostname": self.hostname,
            "mac": self.mac,
            "tftp_server_1": self.tftp1,
            "tftp_server_2": self.tftp2,
            "config_files": self.configs,
            "facts": self.facts,
            "error": self.error,
            "findings": [f.as_dict() for f in self.findings],
        }
        return data


def _short_exc(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    return "%s: %s" % (type(exc).__name__, reason if reason else exc)


def audit_target(
    target: str,
    args: argparse.Namespace,
    reporter: Reporter,
    server_checker: ServerChecker,
) -> TargetResult:
    result = TargetResult(target=target)

    def record(f: Finding) -> None:
        result.findings.append(f)
        reporter.finding(target, f)

    # 1. web page -------------------------------------------------------
    try:
        url, doc = fetch_stats_page(target, args.timeout)
    except AuditError as exc:
        result.error = str(exc)
        reporter.error(target, str(exc))
        return result
    result.url = url

    fields = parse_stats_page(doc)
    result.hostname = pick_field(fields, *HOSTNAME_LABELS)
    result.mac = pick_field(fields, *MAC_LABELS)
    result.tftp1 = pick_field(fields, *TFTP1_LABELS)
    result.tftp2 = pick_field(fields, *TFTP2_LABELS)

    if url.startswith("http://"):
        record(
            Finding(
                "MEDIUM",
                "SVC-WEB-HTTP",
                "Phone status pages are served over cleartext HTTP",
                "%s responded on port 80 without authentication." % url,
            )
        )

    if not result.hostname and result.mac:
        mac = re.sub(r"[^0-9A-Fa-f]", "", result.mac).upper()
        if len(mac) == 12:
            result.hostname = "SEP" + mac
    if not result.hostname:
        result.error = "could not scrape a host name from %s" % url
        reporter.error(target, result.error)
        return result

    tftp_server = args.tftp_override or result.tftp1
    reporter.info(
        target,
        "host=%s  tftp1=%s%s"
        % (result.hostname, result.tftp1 or "<none>",
           "  (overridden -> %s)" % tftp_server if args.tftp_override else ""),
    )
    if not tftp_server or tftp_server in {"0.0.0.0", "::"}:
        result.error = "no TFTP server advertised by the phone"
        reporter.error(target, result.error)
        return result

    if args.expected_tftp and tftp_server not in args.expected_tftp:
        record(
            Finding(
                "HIGH",
                "NET-ROGUE-TFTP",
                "Phone is pointed at an unexpected TFTP server",
                "Phone reports %s, which is not in the approved list (%s). "
                "Investigate DHCP option 150 and the handset's manual "
                "settings." % (tftp_server, ", ".join(sorted(args.expected_tftp))),
            )
        )

    # 2. per-server checks (once per TFTP server) ------------------------
    for f in server_checker.check(tftp_server):
        record(f)

    # 3. config files ----------------------------------------------------
    configs, notes = retrieve_configs(
        tftp_server, result.hostname, args.tftp_port, args.timeout, args.retries
    )
    for note in notes:
        reporter.info(target, "tftp: %s" % note)

    for name, cfg in configs.items():
        result.configs[name] = "%s, %d bytes, sha256=%s" % (
            cfg.kind, len(cfg.data), cfg.sha256[:16]
        )
        reporter.info(target, "fetched %s (%s, %d bytes)"
                      % (name, cfg.kind, len(cfg.data)))
        if args.save_configs:
            os.makedirs(args.save_configs, exist_ok=True)
            with open(os.path.join(args.save_configs, name), "wb") as fh:
                fh.write(cfg.data)

    for f in analyse_retrieval(configs, result.hostname):
        record(f)

    # 4. analyse the most informative readable variant --------------------
    readable = None
    for name in sorted(configs, key=lambda n: (configs[n].kind != "signed", n)):
        if configs[name].xml:
            readable = configs[name]
            break

    if readable is not None:
        findings, facts = analyse_config(readable.xml, args.show_secrets)
        result.facts.update(facts)
        if facts.get("firmware_load"):
            reporter.info(target, "firmware load: %s" % facts["firmware_load"])
        for f in findings:
            record(f)

    result.ok = True
    if not result.findings:
        reporter.info(target, "no defects detected")
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def read_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = list(args.targets)
    if args.input:
        stream = sys.stdin if args.input == "-" else open(args.input, "r",
                                                          encoding="utf-8")
        try:
            for line in stream:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.append(line.split(",")[0].strip())
        finally:
            if stream is not sys.stdin:
                stream.close()
    seen, unique = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def write_json(path: str, results: Sequence[TargetResult]) -> None:
    payload = {
        "tool": "cisco_phone_config_audit",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "results": [r.as_dict() for r in results],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_csv(path: str, results: Sequence[TargetResult]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "hostname", "tftp_server", "severity", "code",
                         "title", "detail"])
        for r in results:
            if r.error and not r.findings:
                writer.writerow([r.target, r.hostname or "", r.tftp1 or "",
                                 "INFO", "AUDIT-ERROR", r.error, ""])
            for f in r.findings:
                writer.writerow([r.target, r.hostname or "", r.tftp1 or "",
                                 f.severity, f.code, f.title, f.detail])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit Cisco IP phone TFTP configuration files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run only against equipment you are authorised to assess.",
    )
    p.add_argument("targets", nargs="*", help="phone IP addresses")
    p.add_argument("-i", "--input", help="file with one phone IP per line "
                                         "('-' for stdin)")
    p.add_argument("-w", "--workers", type=int, default=8,
                   help="parallel phones (default 8; use 1 for strictly "
                        "sequential output)")
    p.add_argument("-t", "--timeout", type=float, default=5.0,
                   help="HTTP/TFTP timeout in seconds (default 5)")
    p.add_argument("--retries", type=int, default=3,
                   help="TFTP retransmissions per packet (default 3)")
    p.add_argument("--tftp-port", type=int, default=69,
                   help="TFTP server port (default 69)")
    p.add_argument("--tftp-override",
                   help="ignore the advertised TFTP server and use this one")
    p.add_argument("--expected-tftp", default="",
                   help="comma-separated list of approved TFTP servers; "
                        "anything else is reported as a rogue")
    p.add_argument("--save-configs", metavar="DIR",
                   help="write every downloaded configuration file to DIR")
    p.add_argument("--show-secrets", action="store_true",
                   help="print discovered credentials in full (default: show "
                        "length + hash only)")
    p.add_argument("--no-server-checks", action="store_true",
                   help="skip the per-TFTP-server ITL/CTL/default-config checks")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="only print findings at or above this severity")
    p.add_argument("--fail-on", choices=SEVERITIES + ["NEVER"], default="NEVER",
                   help="exit non-zero if a finding at or above this severity "
                        "was raised")
    p.add_argument("--json", help="write full results to this JSON file")
    p.add_argument("--csv", help="write findings to this CSV file")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress lines, print findings only")
    p.add_argument("-V", "--version", action="version",
                   version="%(prog)s " + __version__)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    args.expected_tftp = {
        s.strip() for s in args.expected_tftp.split(",") if s.strip()
    }

    targets = read_targets(args)
    if not targets:
        print("No targets supplied. Use -i FILE or list IPs on the command "
              "line.", file=sys.stderr)
        return 2

    use_color = args.color == "always" or (
        args.color == "auto" and sys.stdout.isatty()
    )
    reporter = Reporter(use_color, args.min_severity, args.quiet)
    server_checker = ServerChecker(
        args.tftp_port, args.timeout, args.retries, not args.no_server_checks
    )

    if not args.quiet:
        print("Auditing %d phone(s) with %d worker(s)\n"
              % (len(targets), max(1, args.workers)))

    results: List[TargetResult] = []
    workers = max(1, min(args.workers, len(targets)))
    with cfutures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(audit_target, t, args, reporter, server_checker): t
            for t in targets
        }
        for future in cfutures.as_completed(future_map):
            target = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:  # defensive: never lose the whole run
                reporter.error(target, "unhandled error: %s" % _short_exc(exc))
                results.append(TargetResult(target=target,
                                            error=_short_exc(exc)))

    results.sort(key=lambda r: targets.index(r.target))

    if args.json:
        write_json(args.json, results)
    if args.csv:
        write_csv(args.csv, results)

    reachable = sum(1 for r in results if r.ok)
    failed = [r for r in results if not r.ok]
    print("\n--- summary -------------------------------------------------")
    print("phones audited : %d  (reachable %d, failed %d)"
          % (len(results), reachable, len(failed)))
    print("findings       : " + ", ".join(
        "%s=%d" % (s, reporter.counts[s]) for s in SEVERITIES))
    if failed:
        print("unreachable    : " + ", ".join(r.target for r in failed))
    if args.json:
        print("json report    : %s" % args.json)
    if args.csv:
        print("csv report     : %s" % args.csv)

    if args.fail_on != "NEVER":
        threshold = SEV_RANK[args.fail_on]
        if any(reporter.counts[s] for s in SEVERITIES
               if SEV_RANK[s] <= threshold):
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
