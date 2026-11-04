"""RFC 7807 problem responses with safe messages and request IDs.

Raw exception text, SQL detail, tokens and URLs never reach a client response.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("skb.api")

PROBLEM_CONTENT_TYPE = "application/problem+json"

# Stable mapping from condition to HTTP status + machine code (docs/06).
CODE_STATUS = {
    "invalid": 400,
    "unauthenticated": 401,
    "forbidden": 403,
    "not_found": 404,
    "conflict": 409,
    "precondition_failed": 412,
    "too_large": 413,
    "unsupported_media": 415,
    "invalid_semantic": 422,
    "quota": 429,
    "unavailable": 503,
    "mode_disabled": 503,
}

CODE_TITLE = {
    "invalid": "Invalid request",
    "unauthenticated": "Authentication required",
    "forbidden": "Forbidden",
    "not_found": "Not found",
    "conflict": "Conflict",
    "precondition_failed": "Precondition failed",
    "too_large": "Payload too large",
    "unsupported_media": "Unsupported media type",
    "invalid_semantic": "Unprocessable request",
    "quota": "Quota exceeded",
    "unavailable": "Temporarily unavailable",
    "mode_disabled": "Capability disabled",
}


class Problem(Exception):
    """A safe, contract-shaped error. `detail` must never contain secrets."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        status_code: Optional[int] = None,
        field_errors: Optional[Iterable[dict[str, str]]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        if code not in CODE_STATUS:
            raise ValueError(f"unknown problem code: {code}")
        self.code = code
        self.status_code = status_code or CODE_STATUS[code]
        self.detail = detail[:1000]
        self.field_errors = list(field_errors or [])[:50]
        self.headers = headers or {}
        super().__init__(self.detail)


def problem_body(problem: Problem, request_id: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": f"https://baseline.invalid/problems/{problem.code}",
        "title": CODE_TITLE[problem.code],
        "status": problem.status_code,
        "code": problem.code,
        "detail": problem.detail,
        "request_id": request_id,
    }
    if problem.field_errors:
        body["field_errors"] = problem.field_errors
    return body


def request_id_of(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    if not rid:
        rid = str(uuid.uuid4())
        request.state.request_id = rid
    return rid


def problem_response(request: Request, problem: Problem) -> JSONResponse:
    rid = request_id_of(request)
    headers = {"X-Request-ID": rid, "Cache-Control": "no-store", **problem.headers}
    return JSONResponse(
        status_code=problem.status_code,
        content=problem_body(problem, rid),
        media_type=PROBLEM_CONTENT_TYPE,
        headers=headers,
    )


async def problem_exception_handler(request: Request, exc: Problem) -> JSONResponse:
    return problem_response(request, exc)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = request_id_of(request)
    logger.error("unhandled_error request_id=%s type=%s", rid, type(exc).__name__)
    return problem_response(
        request,
        Problem("unavailable", "An unexpected internal error occurred. See request_id."),
    )
