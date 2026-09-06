from __future__ import annotations

from dataclasses import dataclass, field


class ValidationError(Exception):
    """Raised when a value fails a hard validation rule."""

    def __init__(self, field_name: str, message: str, code: str = "INVALID"):
        super().__init__(f"{field_name}: {message}")
        self.field_name = field_name
        self.message = message
        self.code = code

    def to_dict(self) -> dict:
        return {"field": self.field_name, "message": self.message, "code": self.code}


@dataclass
class ValidationResult:
    """Accumulates the outcome of validating a record."""

    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def add_error(self, field_name: str, message: str, code: str = "INVALID") -> None:
        self.errors.append(ValidationError(field_name, message, code))

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def merge(self, other: "ValidationResult") -> "ValidationResult":
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        return self

    def error_fields(self) -> set[str]:
        return {e.field_name for e in self.errors}

    def to_dict(self) -> dict:
        return {
            "valid": self.is_valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": list(self.warnings),
        }

    def raise_if_invalid(self) -> None:
        if self.errors:
            raise self.errors[0]
