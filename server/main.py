#!/usr/bin/env python3
# pyright: reportMissingImports=false
from __future__ import annotations

import json
import os
import re
import time
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib import error, request
from urllib.parse import urlencode

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cf-domain-availability")

DEFAULT_TLDS = ["com", "ai"]
MAX_LABELS = int(os.getenv("MAX_BATCH_LABELS", "100"))
MAX_TLDS = int(os.getenv("MAX_BATCH_TLDS", "20"))
GD_MAX_BULK_DOMAINS = 500
GD_API_BASE_BY_ENV = {
    "ote": "https://api.ote-godaddy.com",
    "production": "https://api.godaddy.com",
}

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TLD_RE = re.compile(r"^[a-z0-9-]{2,63}$")


class GoDaddyApiError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int | None = None,
        retryable: bool = False,
        retry_after_sec: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable
        self.retry_after_sec = retry_after_sec


def _normalize_label(label: str) -> str:
    candidate = label.strip().lower()
    if not candidate:
        raise ValueError("Each label must be a non-empty string.")
    if "." in candidate:
        raise ValueError("Labels must be base labels only (no dots/TLDs).")
    if not LABEL_RE.fullmatch(candidate):
        raise ValueError(
            "Invalid label. Use 1-63 chars with [a-z0-9-], and no leading/trailing hyphen."
        )
    return candidate


def _normalize_tld(tld: str) -> str:
    candidate = tld.strip().lower()
    if candidate.startswith("."):
        candidate = candidate[1:]
    if not TLD_RE.fullmatch(candidate):
        raise ValueError(f"Invalid TLD: {tld}")
    return candidate


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _micro_to_decimal_price(value: Any) -> float | None:
    if value is None:
        return None
    try:
        micro = Decimal(str(value))
        return float(micro / Decimal("1000000"))
    except (InvalidOperation, ValueError, TypeError):
        return None


class GoDaddyDomainsClient:
    def __init__(self) -> None:
        self.api_key = os.getenv("GD_API_KEY", "").strip()
        self.api_secret = os.getenv("GD_API_SECRET", "").strip()
        self.environment = os.getenv("GD_ENVIRONMENT", "ote").strip().lower()
        self.api_base = GD_API_BASE_BY_ENV.get(self.environment)

        if not self.api_key:
            raise GoDaddyApiError(
                code="AUTH_ERROR",
                message="Missing GD_API_KEY in environment.",
                retryable=False,
            )
        if not self.api_secret:
            raise GoDaddyApiError(
                code="AUTH_ERROR",
                message="Missing GD_API_SECRET in environment.",
                retryable=False,
            )
        if self.api_base is None:
            raise GoDaddyApiError(
                code="INVALID_ENVIRONMENT",
                message="Invalid GD_ENVIRONMENT. Allowed values: ote, production.",
                retryable=False,
            )

    def _request_json(
        self,
        url: str,
        method: str = "GET",
        body: Any = None,
        retries: int = 3,
        timeout_s: int = 15,
    ) -> dict[str, Any]:
        wait_s = 0.5
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        for attempt in range(retries + 1):
            req = request.Request(
                url,
                headers={
                    "Authorization": f"sso-key {self.api_key}:{self.api_secret}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                data=data,
                method=method,
            )

            try:
                with request.urlopen(req, timeout=timeout_s) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    return payload
            except error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                retry_after_sec = None
                try:
                    parsed = json.loads(body) if body else {}
                except Exception:  # noqa: BLE001
                    parsed = {}
                if isinstance(parsed, dict) and parsed.get("retryAfterSec") is not None:
                    try:
                        retry_after_sec = int(parsed.get("retryAfterSec"))
                    except (TypeError, ValueError):
                        retry_after_sec = None

                retryable = exc.code == 429 or 500 <= exc.code < 600
                if retryable and attempt < retries:
                    sleep_seconds = retry_after_sec if retry_after_sec is not None else wait_s * (2**attempt)
                    time.sleep(min(sleep_seconds, 8.0))
                    continue

                err_code = parsed.get("code") if isinstance(parsed, dict) else None
                err_message = parsed.get("message") if isinstance(parsed, dict) else None
                raise GoDaddyApiError(
                    code="RATE_LIMITED" if exc.code == 429 else "UPSTREAM_ERROR",
                    message=f"GoDaddy API HTTP {exc.code}: {err_message or body or exc.reason}",
                    status_code=exc.code,
                    retryable=retryable,
                    retry_after_sec=retry_after_sec,
                )
            except Exception as exc:  # noqa: BLE001
                if attempt < retries:
                    time.sleep(wait_s * (2**attempt))
                    continue
                raise GoDaddyApiError(
                    code="NETWORK_ERROR",
                    message=f"Network error calling GoDaddy API: {exc}",
                    retryable=True,
                ) from exc

        raise GoDaddyApiError(
            code="UPSTREAM_ERROR",
            message="Exhausted retries calling GoDaddy API.",
            retryable=True,
        )

    def available_bulk(
        self,
        domains: list[str],
        check_type: str = "FAST",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        all_domains: list[dict[str, Any]] = []
        all_errors: list[dict[str, Any]] = []

        for i in range(0, len(domains), GD_MAX_BULK_DOMAINS):
            chunk = domains[i : i + GD_MAX_BULK_DOMAINS]
            query = urlencode({"checkType": check_type})
            url = f"{self.api_base}/v1/domains/available?{query}"
            payload = self._request_json(url=url, method="POST", body=chunk)

            if not isinstance(payload, dict):
                raise GoDaddyApiError(
                    code="UPSTREAM_ERROR",
                    message="Unexpected GoDaddy response shape for bulk availability.",
                    retryable=False,
                )

            checks = payload.get("domains") or []
            errs = payload.get("errors") or []
            if isinstance(checks, list):
                all_domains.extend(check for check in checks if isinstance(check, dict))
            if isinstance(errs, list):
                all_errors.extend(err for err in errs if isinstance(err, dict))

        return all_domains, all_errors


def _build_error(
    code: str,
    message: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
    }


@mcp.tool()
def check_domain_availability_batch(
    labels: list[str],
    tlds: list[str] | None = None,
) -> dict[str, Any]:
    """Check .com/.ai (or custom TLDs) availability for a batch of domain base labels via GoDaddy API."""
    started = time.time()

    if not labels:
        raise ValueError("labels is required and must contain at least one label.")

    normalized_labels = _dedupe_preserve_order([_normalize_label(value) for value in labels])
    if len(normalized_labels) > MAX_LABELS:
        raise ValueError(f"Too many labels. Maximum allowed is {MAX_LABELS}.")

    input_tlds = tlds if tlds is not None and len(tlds) > 0 else DEFAULT_TLDS
    normalized_tlds = _dedupe_preserve_order([_normalize_tld(value) for value in input_tlds])
    if len(normalized_tlds) > MAX_TLDS:
        raise ValueError(f"Too many TLDs. Maximum allowed is {MAX_TLDS}.")

    results_by_label: dict[str, dict[str, Any]] = {
        label: {"label": label, "checks": [], "errors": []} for label in normalized_labels
    }

    try:
        client = GoDaddyDomainsClient()
    except GoDaddyApiError as exc:
        for label in normalized_labels:
            results_by_label[label]["errors"].append(_build_error(code=exc.code, message=exc.message))
        duration_ms = int((time.time() - started) * 1000)
        return {
            "status": "failed",
            "summary": {
                "total_labels": len(normalized_labels),
                "total_checks": len(normalized_labels) * len(normalized_tlds),
                "succeeded": 0,
                "failed": len(normalized_labels) * len(normalized_tlds),
                "duration_ms": duration_ms,
            },
            "results": [results_by_label[label] for label in normalized_labels],
        }

    domains_to_check = [f"{label}.{tld}" for label in normalized_labels for tld in normalized_tlds]
    domain_to_label = {domain: domain.rsplit(".", 1)[0] for domain in domains_to_check}

    try:
        checks, api_errors = client.available_bulk(domains_to_check, check_type="FAST")
    except GoDaddyApiError as exc:
        for label in normalized_labels:
            results_by_label[label]["errors"].append(_build_error(code=exc.code, message=exc.message))
        duration_ms = int((time.time() - started) * 1000)
        return {
            "status": "failed",
            "summary": {
                "total_labels": len(normalized_labels),
                "total_checks": len(domains_to_check),
                "succeeded": 0,
                "failed": len(domains_to_check),
                "duration_ms": duration_ms,
            },
            "results": [results_by_label[label] for label in normalized_labels],
        }

    succeeded = 0
    mapped_domains: set[str] = set()

    for check in checks:
        domain = check.get("domain")
        if not isinstance(domain, str):
            continue
        label = domain_to_label.get(domain)
        if label is None:
            continue

        item: dict[str, Any] = {
            "domain": domain,
            "available": check.get("available"),
            "definitive": check.get("definitive"),
        }

        if "price" in check:
            item["price"] = _micro_to_decimal_price(check.get("price"))
        if "currency" in check:
            item["currency"] = check.get("currency")
        if "period" in check:
            item["period"] = check.get("period")

        results_by_label[label]["checks"].append(item)
        mapped_domains.add(domain)
        succeeded += 1

    for api_error in api_errors:
        domain = api_error.get("domain")
        if isinstance(domain, str):
            label = domain_to_label.get(domain)
            if label is not None:
                filtered = {
                    key: api_error.get(key)
                    for key in ("code", "domain", "message", "path", "status")
                    if key in api_error
                }
                if not filtered:
                    filtered = _build_error(code="UPSTREAM_ERROR", message="GoDaddy availability error.")
                results_by_label[label]["errors"].append(filtered)

    for domain in domains_to_check:
        if domain not in mapped_domains:
            label = domain_to_label[domain]
            already_has_domain_error = any(
                err.get("domain") == domain for err in results_by_label[label]["errors"] if isinstance(err, dict)
            )
            if not already_has_domain_error:
                results_by_label[label]["errors"].append(
                    {
                        "code": "NO_RESULT",
                        "domain": domain,
                        "message": "No availability result returned by GoDaddy for this domain.",
                    }
                )

    for label in normalized_labels:
        results_by_label[label]["checks"].sort(key=lambda item: item["domain"])

    failed = len(domains_to_check) - succeeded
    duration_ms = int((time.time() - started) * 1000)
    status = "ok" if failed == 0 else ("failed" if succeeded == 0 else "partial")

    return {
        "status": status,
        "summary": {
            "total_labels": len(normalized_labels),
            "total_checks": len(domains_to_check),
            "succeeded": succeeded,
            "failed": failed,
            "duration_ms": duration_ms,
        },
        "results": [results_by_label[label] for label in normalized_labels],
    }


if __name__ == "__main__":
    mcp.run()
