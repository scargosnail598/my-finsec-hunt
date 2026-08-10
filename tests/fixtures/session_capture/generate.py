"""Generate the deterministic, credential-free session-capture acceptance corpus."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).resolve().parent
API_HOST = "api.example.test"
TELEMETRY_HOST = "telemetry.example.test"
STARTED_AT = datetime(2026, 1, 2, 10, 0, tzinfo=UTC)


def _entry(
    offset: int,
    actor: str,
    method: str,
    path: str,
    *,
    status: int = 200,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | list[Any] | None = None,
    host: str = API_HOST,
) -> dict[str, Any]:
    request_headers = [
        {"name": "Accept", "value": "application/json"},
        {"name": "X-Synthetic-Actor", "value": actor},
    ]
    request_document: dict[str, Any] = {
        "method": method,
        "url": f"https://{host}{path}",
        "headers": request_headers,
        "cookies": [],
    }
    if request is not None:
        request_headers.append({"name": "Content-Type", "value": "application/json"})
        request_document["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(request, sort_keys=True),
        }
    response_document = response if response is not None else {"ok": True}
    return {
        "startedDateTime": (STARTED_AT + timedelta(seconds=offset))
        .isoformat()
        .replace("+00:00", "Z"),
        "request": request_document,
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "cookies": [],
            "content": {
                "mimeType": "application/json",
                "text": json.dumps(response_document, sort_keys=True),
            },
        },
    }


def _write(name: str, entries: list[dict[str, Any]]) -> None:
    document = {
        "log": {
            "version": "1.2",
            "creator": {"name": "finsec-session-capture-corpus", "version": "1"},
            "entries": entries,
        }
    }
    (FIXTURE_ROOT / name).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _order_create(actor: str, order_id: str, owner_id: str, offset: int) -> list[dict[str, Any]]:
    return [
        _entry(
            offset,
            actor,
            "POST",
            "/api/orders",
            status=201,
            request={"quantity": 1},
            response={"id": order_id, "ownerId": owner_id, "status": "created"},
        ),
        _entry(
            offset + 1,
            actor,
            "GET",
            f"/api/orders/{order_id}",
            response={"id": order_id, "ownerId": owner_id, "status": "created"},
        ),
    ]


def _order_return(actor: str, order_id: str, owner_id: str, offset: int) -> list[dict[str, Any]]:
    return [
        _entry(
            offset,
            actor,
            "GET",
            f"/api/orders/{order_id}",
            response={"id": order_id, "ownerId": owner_id, "status": "created"},
        ),
        _entry(
            offset + 1,
            actor,
            "POST",
            f"/api/orders/{order_id}/return",
            request={"reason": "synthetic_fixture"},
            response={
                "id": order_id,
                "ownerId": owner_id,
                "status": "return_requested",
            },
        ),
        _entry(
            offset + 2,
            actor,
            "GET",
            f"/api/orders/{order_id}",
            response={
                "id": order_id,
                "ownerId": owner_id,
                "status": "return_requested",
            },
        ),
    ]


def _dns_journey(
    actor: str,
    domain_id: str,
    record_id: str,
    address: str,
    offset: int,
) -> list[dict[str, Any]]:
    return [
        _entry(
            offset,
            actor,
            "GET",
            f"/api/domains/{domain_id}",
            response={"id": domain_id, "name": f"{actor.lower()}.example.test"},
        ),
        _entry(
            offset + 1,
            actor,
            "GET",
            f"/api/domains/{domain_id}/dns-records",
            response=[],
        ),
        _entry(
            offset + 2,
            actor,
            "POST",
            f"/api/domains/{domain_id}/dns-records",
            status=201,
            request={"name": "www", "type": "A", "value": address},
            response={"id": record_id, "type": "A", "value": address},
        ),
        _entry(
            offset + 3,
            actor,
            "GET",
            f"/api/domains/{domain_id}/dns-records/{record_id}",
            response={"id": record_id, "type": "A", "value": address},
        ),
        _entry(offset + 4, actor, "GET", "/api/profile", response={"actor": actor}),
        _entry(offset + 5, actor, "GET", "/api/notifications", response=[]),
        _entry(offset + 6, actor, "GET", "/api/billing/summary", response={"due": 0}),
        _entry(
            offset + 7,
            actor,
            "POST",
            "/events",
            request={"event": "dns_record_created"},
            host=TELEMETRY_HOST,
        ),
    ]


def main() -> None:
    fixtures = {
        "order-a1-create.har": _order_create("ACCOUNT_A", "1001", "7001", 0),
        "order-a2-return.har": _order_return("ACCOUNT_A", "1001", "7001", 100),
        "order-b1-create.har": _order_create("ACCOUNT_B", "3001", "8001", 200),
        "order-b2-return.har": _order_return("ACCOUNT_B", "3001", "8001", 300),
        "order-b-probe-a.har": [
            _entry(
                400,
                "ACCOUNT_B",
                "GET",
                "/api/orders/1001",
                response={"id": "1001", "ownerId": "7001", "status": "created"},
            )
        ],
        "arvan-a-create-dns.har": _dns_journey("ACCOUNT_A", "101", "501", "192.0.2.10", 500),
        "arvan-b-create-dns.har": _dns_journey("ACCOUNT_B", "202", "602", "192.0.2.20", 600),
    }
    for name, entries in fixtures.items():
        _write(name, entries)


if __name__ == "__main__":
    main()
