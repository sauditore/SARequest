from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ActionResult:
    error_code: int
    is_success: bool
    message: str

    @classmethod
    def not_found(cls, message: str) -> ActionResult:
        return cls(404, False, message)

    @classmethod
    def internal_error(cls, message: str) -> ActionResult:
        return cls(500, False, message)

    @classmethod
    def success(cls, message: str = "") -> ActionResult:
        return cls(0, True, message)
