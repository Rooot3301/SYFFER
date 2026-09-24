"""Prompts questionary avec validation."""

from __future__ import annotations

import questionary

from syffer.utils.validation import (
    safe_filename,
    validate_bpf,
    validate_cidr,
    validate_ip,
)


def _validate_or_error(func):
    def inner(value: str) -> bool | str:
        try:
            func(value)
        except ValueError as exc:
            return str(exc)
        return True
    return inner


def ask_cidr() -> str:
    answer = questionary.text(
        "Plage CIDR a scanner (ex: 192.168.1.0/24)",
        validate=_validate_or_error(validate_cidr),
    ).ask()
    if answer is None:
        raise KeyboardInterrupt
    return validate_cidr(answer)


def ask_ip() -> str:
    answer = questionary.text(
        "Adresse IP publique",
        validate=_validate_or_error(validate_ip),
    ).ask()
    if answer is None:
        raise KeyboardInterrupt
    return validate_ip(answer)


def ask_bpf() -> str | None:
    if not questionary.confirm("Utiliser un filtre BPF ?", default=False).ask():
        return None
    answer = questionary.text(
        "Expression BPF (ex: tcp port 443)",
        validate=_validate_or_error(validate_bpf),
    ).ask()
    if answer is None:
        raise KeyboardInterrupt
    return validate_bpf(answer)


def ask_int(message: str, default: int) -> int:
    def _validate(value: str) -> bool | str:
        try:
            n = int(value)
            if n <= 0:
                return "doit etre > 0"
        except ValueError:
            return "entier requis"
        return True

    answer = questionary.text(message, default=str(default), validate=_validate).ask()
    if answer is None:
        raise KeyboardInterrupt
    return int(answer)


def ask_export() -> tuple[str, str] | None:
    fmt = questionary.select(
        "Exporter le rapport ?",
        choices=["Aucun", "txt", "json", "csv"],
        default="Aucun",
    ).ask()
    if fmt is None:
        raise KeyboardInterrupt
    if fmt == "Aucun":
        return None
    name = questionary.text(
        "Nom du fichier (sans extension)",
        validate=_validate_or_error(safe_filename),
    ).ask()
    if name is None:
        raise KeyboardInterrupt
    return fmt, safe_filename(name)
