"""Passive web-security configuration scanner."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from http.cookies import SimpleCookie
from typing import Dict, List
from urllib.parse import urlparse

import requests


USER_AGENT = "WebSecurityScannerDemo/1.0 (authorized defensive testing)"
TIMEOUT = 10


SECURITY_HEADERS = {
    "Content-Security-Policy": "Restricts executable content sources.",
    "Strict-Transport-Security": "Requests HTTPS for future connections.",
    "X-Content-Type-Options": "Reduces MIME-sniffing risks.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "Referrer-Policy": "Controls referrer information.",
    "Permissions-Policy": "Restricts browser features.",
}


@dataclass
class HeaderFinding:
    """Represents the result of a security-header check."""

    header: str
    present: bool
    value: str
    purpose: str


@dataclass
class CookieFinding:
    """Represents security attributes of a cookie."""

    name: str
    secure: bool
    httponly: bool
    samesite: str


def validate_target(url: str) -> str:
    """Validate a user-supplied HTTP(S) URL."""

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(
            "Target must be a valid http:// or https:// URL."
        )

    return url


def inspect_cookies(
    response: requests.Response,
) -> List[CookieFinding]:
    """Inspect Set-Cookie headers without modifying them."""

    findings: List[CookieFinding] = []

    if hasattr(response.raw.headers, "getlist"):
        raw_headers = response.raw.headers.getlist("Set-Cookie")
    else:
        raw_headers = []

    for raw in raw_headers:
        cookie = SimpleCookie()
        cookie.load(raw)

        for name, morsel in cookie.items():
            findings.append(
                CookieFinding(
                    name=name,
                    secure=bool(morsel["secure"]),
                    httponly=bool(morsel["httponly"]),
                    samesite=morsel["samesite"] or "not-set",
                )
            )

    return findings


def scan(url: str) -> Dict:
    """Perform passive security configuration checks."""

    target = validate_target(url)

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": USER_AGENT,
        }
    )

    response = session.get(
        target,
        timeout=TIMEOUT,
        allow_redirects=True,
    )

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    header_findings = [
        HeaderFinding(
            header=name,
            present=name.lower() in headers,
            value=headers.get(name.lower(), ""),
            purpose=purpose,
        )
        for name, purpose in SECURITY_HEADERS.items()
    ]

    redirect_chain = []

    for redirect in response.history:
        redirect_chain.append(
            {
                "status_code": redirect.status_code,
                "url": redirect.url,
                "location": redirect.headers.get(
                    "Location",
                    "",
                ),
            }
        )

    return {
        "target": target,
        "final_url": response.url,
        "status_code": response.status_code,
        "https": urlparse(response.url).scheme == "https",
        "redirect_chain": redirect_chain,
        "server": response.headers.get(
            "Server",
            "",
        ),
        "powered_by": response.headers.get(
            "X-Powered-By",
            "",
        ),
        "security_headers": [
            asdict(item)
            for item in header_findings
        ],
        "cookies": [
            asdict(item)
            for item in inspect_cookies(response)
        ],
    }


def print_report(report: Dict) -> None:
    """Print a human-readable scan summary."""

    print(f"Target: {report['target']}")
    print(f"Final URL: {report['final_url']}")
    print(f"Status: {report['status_code']}")

    https_status = (
        "PASS"
        if report["https"]
        else "FAIL"
    )

    print(f"HTTPS: {https_status}")

    print("\nSecurity Headers:")

    for item in report["security_headers"]:
        status = (
            "PASS"
            if item["present"]
            else "MISSING"
        )

        print(
            f"  {item['header']}: {status}"
        )

    print(
        f"\nCookies: {len(report['cookies'])}"
    )

    for cookie in report["cookies"]:
        print(
            f"  {cookie['name']}: "
            f"Secure="
            f"{'yes' if cookie['secure'] else 'no'}, "
            f"HttpOnly="
            f"{'yes' if cookie['httponly'] else 'no'}, "
            f"SameSite="
            f"{cookie['samesite']}"
        )

    if report["server"]:
        print(
            f"\nServer: {report['server']}"
        )

    if report["powered_by"]:
        print(
            f"X-Powered-By: "
            f"{report['powered_by']}"
        )


def main() -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "Passive web-security "
            "configuration scanner"
        )
    )

    parser.add_argument(
        "url",
        help="Authorized HTTP(S) target URL",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        help="Write results to a JSON file",
    )

    args = parser.parse_args()

    try:
        report = scan(args.url)

    except (
        requests.RequestException,
        ValueError,
    ) as exc:
        print(
            f"Scan failed: {exc}",
            file=sys.stderr,
        )

        return 1

    print_report(report)

    if args.json_path:
        with open(
            args.json_path,
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                report,
                handle,
                indent=2,
            )

        print(
            f"\nJSON report saved to "
            f"{args.json_path}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
