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


from syffer.utils.validation import validate_ports, validate_target  # noqa: E402


def ask_target() -> str:
    answer = questionary.text(
        "Cible (IP, CIDR ou hostname, ex: scanme.nmap.org)",
        validate=_validate_or_error(validate_target),
    ).ask()
    if answer is None:
        raise KeyboardInterrupt
    return validate_target(answer)


def ask_ports() -> str:
    answer = questionary.text(
        "Ports a scanner (ex: 22,80,1000-2000)",
        default="1-1024",
        validate=_validate_or_error(validate_ports),
    ).ask()
    if answer is None:
        raise KeyboardInterrupt
    return validate_ports(answer)


def ask_custom_toggles() -> tuple[bool, bool, bool, bool]:
    choices = questionary.checkbox(
        "Options nmap a activer",
        choices=[
            questionary.Choice("Service + version (-sV)", checked=True),
            questionary.Choice("Scripts NSE par defaut (-sC)"),
            questionary.Choice("OS detection (-O, requiert admin)"),
            questionary.Choice("Skip host discovery (-Pn)"),
        ],
    ).ask()
    if choices is None:
        raise KeyboardInterrupt
    return (
        "Service + version (-sV)" in choices,
        "Scripts NSE par defaut (-sC)" in choices,
        "OS detection (-O, requiert admin)" in choices,
        "Skip host discovery (-Pn)" in choices,
    )
