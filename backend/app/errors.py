"""Custom API exception and shared error response model."""

from __future__ import annotations

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Returned for every non-2xx response."""

    code: str
    detail: str


class ApiError(Exception):
    """Raise this anywhere in the pipeline to return a structured error."""

    def __init__(self, status_code: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail

