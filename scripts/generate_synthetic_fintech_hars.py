#!/usr/bin/env python3
"""Generate deterministic offline HAR fixtures for the SyntheticPay validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

BASE_TIME = "2026-01-15T10:{minute:02d}:00.000Z"


def entry(
    index: int,
    method: str,
    url: str,
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
    token: str | None = None,
    cookie: str | None = None,
    content_type: str = "application/json",
    status: int = 200,
) -> dict[str, Any]:
    """Build one deterministic HAR entry containing only synthetic data."""

    request_headers: list[dict[str, str]] = []
    if token:
        request_headers.append({"name": "Authorization", "value": f"Bearer {token}"})
    if cookie:
        request_headers.append({"name": "Cookie", "value": f"session={cookie}"})
    request_document: dict[str, Any] = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": request_headers,
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": -1,
    }
    if request is not None:
        request_headers.append({"name": "Content-Type", "value": "application/json"})
        request_document["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(request, sort_keys=True, separators=(",", ":")),
        }
    response_headers = [{"name": "Content-Type", "value": content_type}]
    if cookie:
        response_headers.append({"name": "Set-Cookie", "value": f"session={cookie}; Secure"})
    return {
        "startedDateTime": BASE_TIME.format(minute=index),
        "time": 1,
        "request": request_document,
        "response": {
            "status": status,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": response_headers,
            "cookies": [],
            "content": {
                "size": 0,
                "mimeType": content_type,
                "text": (
                    json.dumps(response, sort_keys=True, separators=(",", ":"))
                    if content_type == "application/json"
                    else "SYNTHETIC_ASSET_CONTENT"
                ),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 0},
    }


def har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "FinSec Hunt SyntheticPay", "version": "1"},
            "entries": entries,
        }
    }


def fixtures() -> dict[str, dict[str, Any]]:
    """Return every deterministic SyntheticPay capture."""

    api = "https://api.syntheticpay.test"
    app = "https://app.syntheticpay.test"
    static = "https://static.syntheticpay.test"
    telemetry = "https://telemetry.syntheticpay.test"
    a_token = "SYNTHETIC_ACCOUNT_A_TOKEN"
    b_token = "SYNTHETIC_ACCOUNT_B_TOKEN"
    files: dict[str, list[dict[str, Any]]] = {
        "01-account-a-private-resources.har": [
            entry(
                1,
                "GET",
                f"{api}/api/v2/profile",
                {"userId": "USER-A", "verificationLevel": "basic"},
                token=a_token,
                cookie="SYNTHETIC_COOKIE_A",
            ),
            entry(
                2,
                "GET",
                f"{api}/api/v2/payments/PAY-A-1001",
                {
                    "paymentId": "PAY-A-1001",
                    "ownerId": "USER-A",
                    "walletId": "WALLET-A",
                    "amount": 12500,
                    "currency": "IRR",
                    "status": "completed",
                },
                token=a_token,
            ),
            entry(
                3,
                "GET",
                f"{api}/api/v2/payments/PAY-A-1001/receipt",
                {
                    "receiptId": "RECEIPT-A-1001",
                    "paymentId": "PAY-A-1001",
                    "ownerId": "USER-A",
                },
                token=a_token,
            ),
        ],
        "02-account-b-private-resources.har": [
            entry(
                4,
                "GET",
                f"{api}/api/v2/profile",
                {"userId": "USER-B", "verificationLevel": "basic"},
                token=b_token,
                cookie="SYNTHETIC_COOKIE_B",
            ),
            entry(
                5,
                "GET",
                f"{api}/api/v2/payments/PAY-B-2001",
                {
                    "paymentId": "PAY-B-2001",
                    "ownerId": "USER-B",
                    "walletId": "WALLET-B",
                    "amount": 8500,
                    "currency": "IRR",
                    "status": "completed",
                },
                token=b_token,
            ),
            entry(
                6,
                "GET",
                f"{api}/api/v2/payments/PAY-B-2001/receipt",
                {
                    "receiptId": "RECEIPT-B-2001",
                    "paymentId": "PAY-B-2001",
                    "ownerId": "USER-B",
                },
                token=b_token,
            ),
            entry(
                7,
                "POST",
                f"{api}/api/v2/wallet/payment-history",
                {
                    "walletId": "WALLET-B",
                    "ownerId": "USER-B",
                    "items": [{"paymentId": "PAY-B-2001", "amount": 8500, "status": "completed"}],
                },
                request={"walletId": "WALLET-B", "cursor": "CURSOR-2", "pageSize": 20},
                token=b_token,
            ),
        ],
        "03-body-identifier-wallet.har": [
            entry(
                8,
                "POST",
                f"{api}/api/v2/wallet/payment-history",
                {
                    "walletId": "WALLET-A",
                    "ownerId": "USER-A",
                    "items": [{"paymentId": "PAY-A-1001", "amount": 12500, "status": "completed"}],
                },
                request={"walletId": "WALLET-A", "cursor": "CURSOR-1", "pageSize": 20},
                token=a_token,
            )
        ],
        "04-state-transitions.har": [
            entry(
                9,
                "GET",
                f"{api}/api/v2/payments/PAY-A-PENDING",
                {"paymentId": "PAY-A-PENDING", "ownerId": "USER-A", "status": "pending"},
                token=a_token,
            ),
            entry(
                10,
                "POST",
                f"{api}/api/v2/payments/PAY-A-PENDING/cancel",
                {"paymentId": "PAY-A-PENDING", "status": "cancelled"},
                request={"reason": "synthetic-user-request"},
                token=a_token,
            ),
            entry(
                11,
                "POST",
                f"{api}/api/v2/payments/PAY-A-CONFIRM/confirm",
                {"paymentId": "PAY-A-CONFIRM", "status": "confirmed"},
                request={"confirmationReference": "SYNTHETIC-CONFIRM-1"},
                token=a_token,
            ),
        ],
        "05-auth-code-replay.har": [
            entry(
                12,
                "POST",
                f"{api}/api/v2/auth/challenge/initiate",
                {"challengeId": "CHALLENGE-A-1", "purpose": "signin", "status": "code_sent"},
                request={
                    "accountReference": "SYNTHETIC-ACCOUNT-A",
                    "email": "account-a@syntheticpay.test",
                },
            ),
            entry(
                13,
                "POST",
                f"{api}/api/v2/auth/code/consume",
                {
                    "challengeId": "CHALLENGE-A-1",
                    "status": "consumed",
                    "sessionReference": "SESSION-A-1",
                },
                request={"challengeId": "CHALLENGE-A-1", "code": "111111"},
            ),
            entry(
                14,
                "POST",
                f"{api}/api/v2/auth/challenge/initiate",
                {"challengeId": "CHALLENGE-B-1", "purpose": "signin", "status": "code_sent"},
                request={
                    "accountReference": "SYNTHETIC-ACCOUNT-B",
                    "email": "account-b@syntheticpay.test",
                },
            ),
            entry(
                15,
                "POST",
                f"{api}/api/v2/auth/code/consume",
                {
                    "challengeId": "CHALLENGE-B-1",
                    "status": "consumed",
                    "sessionReference": "SESSION-B-1",
                },
                request={"challengeId": "CHALLENGE-B-1", "code": "222222"},
            ),
        ],
        "06-static-and-versioned-assets.har": [
            entry(
                16,
                "GET",
                f"{static}/static/photo/user/webp_thumbnail/100/a1b2c3d4-e5f6-4789-8abc-def012345678.webp",
                {},
                content_type="image/webp",
            ),
            entry(
                17,
                "GET",
                f"{static}/static/photo/user/webp_thumbnail/100/fedcba98-7654-4321-8fed-cba987654321.webp",
                {},
                content_type="image/webp",
            ),
            entry(
                18,
                "GET",
                f"{static}/static/photo/user/post/100/33333333-3333-4333-8333-333333333333.jpg",
                {},
                content_type="image/jpeg",
            ),
            entry(
                19,
                "GET",
                f"{app}/web/v3/loader_v3.12.3.js",
                {},
                content_type="application/javascript",
            ),
            entry(20, "GET", f"{app}/assets/app-v2.css", {}, content_type="text/css"),
        ],
        "07-telemetry-and-third-party.har": [
            entry(21, "POST", f"{telemetry}/api/5/envelope/", {}, request={"eventId": "EVENT-1"}),
            entry(22, "POST", f"{telemetry}/gen_204", {}, request={"eventId": "EVENT-2"}),
            entry(
                23,
                "POST",
                f"{telemetry}/client-exporter/send-report",
                {},
                request={"reportId": "REPORT-1"},
            ),
            entry(24, "POST", f"{app}/v8/actionlog/send", {}, request={"action": "page_view"}),
            entry(
                25, "POST", "https://thirdparty.invalid/collect", {}, request={"event": "synthetic"}
            ),
        ],
        "08-post-read-endpoints.har": [
            entry(
                26,
                "POST",
                f"{api}/api/v2/search",
                {"items": []},
                request={"query": "synthetic", "page": 1},
            ),
            entry(
                27,
                "POST",
                f"{api}/api/v2/payments/list",
                {"items": []},
                request={"status": "completed", "pageSize": 20},
            ),
            entry(28, "POST", f"{api}/api/v2/menu", {"items": []}, request={"section": "wallet"}),
            entry(
                29,
                "POST",
                f"{api}/api/v2/map/viewport",
                {"items": []},
                request={"zoom": 12, "bounds": "synthetic"},
            ),
            entry(
                30,
                "POST",
                f"{api}/api/v2/payment-methods/lookup",
                {"items": []},
                request={"currency": "IRR"},
            ),
        ],
        "09-duplicate-route-instances.har": [
            *[
                entry(
                    31 + index,
                    "GET",
                    f"{api}/api/v2/payments/{payment_id}",
                    {"paymentId": payment_id, "ownerId": owner},
                    token=a_token if owner == "USER-A" else b_token,
                )
                for index, (payment_id, owner) in enumerate(
                    [
                        ("PAY-A-1001", "USER-A"),
                        ("PAY-A-1002", "USER-A"),
                        ("PAY-A-1003", "USER-A"),
                        ("PAY-B-2001", "USER-B"),
                        ("PAY-B-2002", "USER-B"),
                    ]
                )
            ]
        ],
        "10-incomplete-evidence.har": [
            entry(
                36,
                "POST",
                f"{api}/api/v2/wallet/change-wallet/FAST_PAYMENT",
                {"mode": "FAST_PAYMENT", "page": {"title": "Payment Method"}},
                request={"mode": "FAST_PAYMENT"},
                token=a_token,
            ),
            entry(
                37,
                "POST",
                f"{api}/api/v2/user/verification",
                {"message": "verification page initialized"},
                request={"step": "start", "phone": "+00000000000"},
                token=a_token,
            ),
        ],
    }
    return {name: har(entries) for name, entries in files.items()}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path, help="Directory that will receive deterministic HARs")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, document in fixtures().items():
        path = args.output / name
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        print(path)


if __name__ == "__main__":
    main()
