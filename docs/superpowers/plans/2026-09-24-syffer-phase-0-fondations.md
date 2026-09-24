# Syffer Phase 0 — Fondations : Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconstruire Syffer sur un socle modulaire, testable, cross-platform, avec menu interactif propre (rich + questionary), en corrigeant tous les bugs actuels et en préparant Phase 1 (nmap).

**Architecture:** Package Python `syffer/` avec couche `core/*` pure (aucun I/O), couche `cli/*` (façade menu), couche `reports/*` (exports txt/json/csv), couche `utils/*` (validation, logging, paths). Un point d'entrée console `syffer` défini dans `pyproject.toml`. Tests unitaires avec mocks scapy/psutil/requests, aucun test réseau réel requis en CI.

**Tech Stack:** Python ≥3.10, scapy ≥2.5, psutil ≥5.9, requests ≥2.32, rich ≥13, questionary ≥2, pytest, pytest-mock, hatchling (build backend).

**Spec:** [docs/superpowers/specs/2026-09-24-syffer-phase-0-fondations-design.md](../specs/2026-09-24-syffer-phase-0-fondations-design.md)

## Global Constraints

- Python cible : `>=3.10,<4` (Windows / Linux / macOS).
- Recon uniquement — jamais d'exploitation active, brute-force, ni de dépendance à Metasploit.
- Aucun `input()` ni `print()` dans `syffer/core/*.py` ou `syffer/reports/*.py`. Toute I/O utilisateur passe par `syffer/cli/*.py`.
- Chaque module `syffer/core/*.py` retourne des dataclasses définies dans `syffer/core/models.py`, pas de dicts ad hoc.
- Toutes les fonctions core prennent leurs paramètres en argument explicite (pas de globals, pas d'`input()`).
- Sanitize systématiquement les entrées utilisateur qui touchent le système de fichiers (via `syffer/utils/validation.py::safe_filename`) ou le réseau (via `validate_cidr`, `validate_ip`, `validate_bpf`).
- Tests : `pytest`, mocks pour scapy / psutil / requests, aucun accès réseau ni droits admin requis pour la CI.
- Commit convention : préfixe conventionnel (`feat:`, `fix:`, `chore:`, `test:`, `docs:`), footer `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.
- Branche de travail : `devb`.
- Rupture assumée avec la version actuelle : le fichier `Syffer.py` racine est supprimé, remplacé par le package `syffer/` + entry point console `syffer`.
- Ne jamais s'ajouter comme collaborateur sur le dépôt GitHub. Ne pousser que sur `devb`, jamais force-push sur `main`.

## File Structure

```
syffer/
  __init__.py                # version, exports publics
  __main__.py                # entry point console (main())
  config.py                  # constantes runtime (EXTRACT_DIR, TIMEOUTS, IP_API_URL)
  core/
    __init__.py
    models.py                # dataclasses (Interface, NetworkInfo, Host, ScanResult, ...)
    interfaces.py            # list_interfaces() via psutil
    network_info.py          # get_network_info() (hostname, local_ip, gateway)
    packet_capture.py        # capture(count, bpf, iface, timeout) via scapy
    network_scan.py          # arp_scan(cidr, timeout) via scapy
    geolocation.py           # lookup(ip, timeout) via requests
    external.py              # ExternalTool wrapper (préparé pour Phase 1)
  cli/
    __init__.py
    menu.py                  # boucle principale (questionary)
    prompts.py               # ask_cidr, ask_ip, ask_bpf, ask_export, ask_filename
    display.py               # banner, render_scan, render_capture, render_info, render_geo
    handlers.py              # un handler par option du menu
    session.py               # état de session (paquets capturés, settings)
  reports/
    __init__.py
    exporter.py              # export(result, fmt, path) dispatch selon type
    formatters.py            # to_txt / to_json / to_csv par type de résultat
  utils/
    __init__.py
    logging_setup.py         # configure(verbose)
    validation.py            # safe_filename, validate_cidr, validate_ip, validate_bpf
    paths.py                 # safe_output_path, resolve_extract_dir
tests/
  __init__.py
  conftest.py                # fixtures partagées
  test_validation.py
  test_paths.py
  test_exporter.py
  test_formatters.py
  test_interfaces.py
  test_network_info.py
  test_network_scan.py
  test_packet_capture.py
  test_geolocation.py
  test_external.py
  test_menu_dispatch.py      # test des handlers via mock (pas la boucle interactive)
extract/
  .gitkeep                   # garde le dossier tracké, contenu ignoré
pyproject.toml               # config projet + build + scripts + pytest
requirements.txt             # miroir runtime deps (compat pip install -r)
README.md                    # réécrit (install, prérequis Npcap/root, roadmap)
CHANGELOG.md                 # v0.2.0 breaking changes documented
.gitignore                   # déjà présent
Syffer.py                    # SUPPRIMÉ (voir Task 15)
```

Chaque fichier a une responsabilité unique. Les fichiers `core/*.py` sont indépendants (aucun n'importe un autre `core/*.py` sauf `models.py`). Les fichiers `cli/*.py` importent `core/*` et `reports/*`, jamais l'inverse.

## Ordre d'exécution

Les tâches sont ordonnées pour respecter les dépendances : d'abord le squelette et les utilitaires, puis les modules core (indépendants entre eux, testables isolément), puis reports, puis la couche CLI qui les assemble, puis le nettoyage et la doc.

---

### Task 1: Squelette de projet et pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `syffer/__init__.py`
- Create: `syffer/__main__.py`
- Create: `syffer/config.py`
- Create: `extract/.gitkeep`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `requirements.txt` (écrasement de l'ancien)

**Interfaces:**
- Consumes: rien (première tâche)
- Produces:
  - `syffer.__version__: str` (constante `"0.2.0"`)
  - `syffer.config.EXTRACT_DIR: pathlib.Path`
  - `syffer.config.DEFAULT_ARP_TIMEOUT: int` (= 3)
  - `syffer.config.DEFAULT_CAPTURE_COUNT: int` (= 10)
  - `syffer.config.DEFAULT_HTTP_TIMEOUT: int` (= 5)
  - `syffer.config.IP_API_URL: str` (= `"http://ip-api.com/json/{ip}"`)
  - `syffer.__main__.main() -> int` (stub qui retourne 0 et affiche "Syffer starting…", sera étoffé Task 12)
  - Console script `syffer` (défini dans `pyproject.toml`, résolu vers `syffer.__main__:main`)

- [ ] **Step 1: Écrire `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "syffer"
version = "0.2.0"
description = "Outil de recon reseau CLI (capture de paquets, scan ARP, infos reseau)."
readme = "README.md"
license = { file = "LICENSE" }
requires-python = ">=3.10,<4"
authors = [{ name = "ROOT3301" }]
keywords = ["network", "recon", "packet", "scan", "cli"]
classifiers = [
  "Development Status :: 4 - Beta",
  "Environment :: Console",
  "Intended Audience :: System Administrators",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.10",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
  "Topic :: Security",
  "Topic :: System :: Networking :: Monitoring",
]
dependencies = [
  "scapy>=2.5,<3",
  "psutil>=5.9,<7",
  "requests>=2.32,<3",
  "rich>=13,<14",
  "questionary>=2,<3",
]

[project.optional-dependencies]
dev = [
  "pytest>=8,<9",
  "pytest-mock>=3.12,<4",
  "pytest-cov>=5,<7",
]

[project.scripts]
syffer = "syffer.__main__:main"

[project.urls]
Homepage = "https://github.com/Rooot3301/SYFFER"
Repository = "https://github.com/Rooot3301/SYFFER"

[tool.hatch.build.targets.wheel]
packages = ["syffer"]

[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
addopts = "-ra -q"
```

- [ ] **Step 2: Écrire `syffer/__init__.py`**

```python
"""Syffer - outil de recon reseau CLI."""

__version__ = "0.2.0"

__all__ = ["__version__"]
```

- [ ] **Step 3: Écrire `syffer/config.py`**

```python
"""Constantes runtime de Syffer."""

from __future__ import annotations

from pathlib import Path

EXTRACT_DIR: Path = Path("extract").resolve()

DEFAULT_ARP_TIMEOUT: int = 3
DEFAULT_CAPTURE_COUNT: int = 10
DEFAULT_HTTP_TIMEOUT: int = 5

IP_API_URL: str = "http://ip-api.com/json/{ip}"

APP_NAME: str = "Syffer"
```

- [ ] **Step 4: Écrire `syffer/__main__.py` (stub)**

```python
"""Point d'entree console de Syffer."""

from __future__ import annotations

import sys


def main() -> int:
    """Point d'entree principal (stub, sera etoffe en Task 12)."""
    sys.stdout.write("Syffer starting...\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Écrire `tests/__init__.py` et `tests/conftest.py`**

`tests/__init__.py` reste vide.

`tests/conftest.py` :

```python
"""Fixtures pytest partagees."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def tmp_extract_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirige EXTRACT_DIR vers un tmp_path isole pour le test."""
    extract = tmp_path / "extract"
    extract.mkdir()
    monkeypatch.setattr("syffer.config.EXTRACT_DIR", extract)
    return extract
```

- [ ] **Step 6: Écrire `requirements.txt`** (miroir des deps runtime)

```
scapy>=2.5,<3
psutil>=5.9,<7
requests>=2.32,<3
rich>=13,<14
questionary>=2,<3
```

- [ ] **Step 7: Créer `extract/.gitkeep`** (fichier vide, garde le dossier)

- [ ] **Step 8: Vérifier que le squelette s'installe**

Run : `python -m pip install -e ".[dev]"`
Expected : install OK, la commande `syffer` existe.

Run : `syffer`
Expected : affiche `Syffer starting...` et retourne 0.

Run : `pytest`
Expected : `0 tests` collectés, exit 0 (aucun test encore).

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml syffer/__init__.py syffer/__main__.py syffer/config.py tests/__init__.py tests/conftest.py requirements.txt extract/.gitkeep
git commit -m "$(cat <<'EOF'
chore(rework): squelette package syffer + pyproject.toml

Cree la structure de base du package (config, __main__ stub, entry
point console `syffer`), le squelette de tests avec fixture
tmp_extract_dir, et actualise requirements.txt vers les nouvelles
dependances (scapy/psutil/requests/rich/questionary).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Modèles de données (dataclasses)

**Files:**
- Create: `syffer/core/__init__.py`
- Create: `syffer/core/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: rien
- Produces (toutes définies dans `syffer/core/models.py`, toutes `@dataclass(frozen=True, slots=True)`):
  - `InterfaceAddress(family: str, address: str, netmask: str | None, broadcast: str | None)`
  - `Interface(name: str, mac: str | None, is_up: bool, mtu: int | None, addresses: tuple[InterfaceAddress, ...])`
  - `NetworkInfo(hostname: str, local_ip: str | None, default_gateway: str | None, interfaces: tuple[Interface, ...])`
  - `PacketSummary(index: int, timestamp: float, summary: str, src: str | None, dst: str | None, protocol: str | None, length: int)`
  - `CaptureResult(pcap_path: pathlib.Path, packets: tuple[PacketSummary, ...], bpf_filter: str | None, iface: str | None)`
  - `Host(ip: str, mac: str, vendor: str | None)`
  - `ScanResult(cidr: str, started_at: float, duration_s: float, hosts: tuple[Host, ...])`
  - `GeoInfo(ip: str, country: str | None, city: str | None, region: str | None, lat: float | None, lon: float | None, isp: str | None, status: str)`

- [ ] **Step 1: Écrire le test des dataclasses**

Créer `tests/test_models.py` :

```python
"""Tests des dataclasses de syffer.core.models."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    Host,
    Interface,
    InterfaceAddress,
    NetworkInfo,
    PacketSummary,
    ScanResult,
)


def test_interface_is_frozen():
    iface = Interface(name="eth0", mac="aa:bb:cc:dd:ee:ff", is_up=True, mtu=1500, addresses=())
    with pytest.raises(Exception):  # FrozenInstanceError ou AttributeError selon Python
        iface.name = "eth1"  # type: ignore[misc]


def test_host_equality():
    h1 = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor="Foo")
    h2 = Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor="Foo")
    assert h1 == h2


def test_scan_result_hosts_is_tuple():
    result = ScanResult(cidr="192.168.1.0/24", started_at=0.0, duration_s=1.5, hosts=())
    assert isinstance(result.hosts, tuple)


def test_capture_result_carries_bpf():
    result = CaptureResult(
        pcap_path=Path("/tmp/x.pcap"),
        packets=(),
        bpf_filter="tcp port 443",
        iface=None,
    )
    assert result.bpf_filter == "tcp port 443"


def test_geo_info_status_field():
    g = GeoInfo(ip="1.1.1.1", country="AU", city=None, region=None, lat=-33.0, lon=151.0, isp=None, status="success")
    assert g.status == "success"


def test_network_info_composition():
    addr = InterfaceAddress(family="AF_INET", address="192.168.1.10", netmask="255.255.255.0", broadcast="192.168.1.255")
    iface = Interface(name="eth0", mac=None, is_up=True, mtu=1500, addresses=(addr,))
    info = NetworkInfo(hostname="test", local_ip="192.168.1.10", default_gateway="192.168.1.1", interfaces=(iface,))
    assert info.interfaces[0].addresses[0].address == "192.168.1.10"


def test_packet_summary_fields():
    p = PacketSummary(index=0, timestamp=1234.5, summary="TCP ...", src="1.1.1.1", dst="2.2.2.2", protocol="TCP", length=64)
    assert p.protocol == "TCP"
```

- [ ] **Step 2: Vérifier que le test échoue**

Run : `pytest tests/test_models.py -v`
Expected : FAIL avec `ModuleNotFoundError: No module named 'syffer.core'`.

- [ ] **Step 3: Écrire `syffer/core/__init__.py`** (vide)

- [ ] **Step 4: Écrire `syffer/core/models.py`**

```python
"""Dataclasses partagees entre core, reports et cli."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class InterfaceAddress:
    family: str
    address: str
    netmask: str | None
    broadcast: str | None


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    mac: str | None
    is_up: bool
    mtu: int | None
    addresses: tuple[InterfaceAddress, ...]


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    hostname: str
    local_ip: str | None
    default_gateway: str | None
    interfaces: tuple[Interface, ...]


@dataclass(frozen=True, slots=True)
class PacketSummary:
    index: int
    timestamp: float
    summary: str
    src: str | None
    dst: str | None
    protocol: str | None
    length: int


@dataclass(frozen=True, slots=True)
class CaptureResult:
    pcap_path: Path
    packets: tuple[PacketSummary, ...]
    bpf_filter: str | None
    iface: str | None


@dataclass(frozen=True, slots=True)
class Host:
    ip: str
    mac: str
    vendor: str | None


@dataclass(frozen=True, slots=True)
class ScanResult:
    cidr: str
    started_at: float
    duration_s: float
    hosts: tuple[Host, ...]


@dataclass(frozen=True, slots=True)
class GeoInfo:
    ip: str
    country: str | None
    city: str | None
    region: str | None
    lat: float | None
    lon: float | None
    isp: str | None
    status: str
```

- [ ] **Step 5: Vérifier que les tests passent**

Run : `pytest tests/test_models.py -v`
Expected : 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add syffer/core/__init__.py syffer/core/models.py tests/test_models.py
git commit -m "$(cat <<'EOF'
feat(core): ajoute les dataclasses partagees (models.py)

Definit les types de retour de tous les modules core :
Interface/InterfaceAddress/NetworkInfo pour le module info,
PacketSummary/CaptureResult pour la capture, Host/ScanResult
pour le scan ARP, GeoInfo pour la geolocalisation. Toutes
frozen+slots pour l'immutabilite.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Utilitaires de validation

**Files:**
- Create: `syffer/utils/__init__.py`
- Create: `syffer/utils/validation.py`
- Test: `tests/test_validation.py`

**Interfaces:**
- Consumes: rien
- Produces:
  - `syffer.utils.validation.safe_filename(name: str) -> str` : lève `ValueError` si nom vide, contient `..`, contient un séparateur ou dépasse 100 caractères après nettoyage. Sinon retourne le nom filtré (seuls `[A-Za-z0-9._-]` conservés).
  - `syffer.utils.validation.validate_cidr(cidr: str) -> str` : lève `ValueError` si non parseable par `ipaddress.ip_network(strict=False)`. Sinon retourne la forme normalisée `str(network)`.
  - `syffer.utils.validation.validate_ip(ip: str) -> str` : lève `ValueError` si non parseable par `ipaddress.ip_address`. Sinon retourne `str(ip_address)`.
  - `syffer.utils.validation.validate_bpf(expr: str) -> str` : lève `ValueError` si `expr` contient `` ` ``, `;`, `|`, `&`, `$`, `\n` ou est vide/dépasse 200 caractères. Sinon retourne `expr` tel quel. (Note : validation syntaxique complète via scapy sera ajoutée Task 8, ici c'est un filtre défensif basique.)

- [ ] **Step 1: Écrire les tests de validation**

Créer `tests/test_validation.py` :

```python
"""Tests de syffer.utils.validation."""

from __future__ import annotations

import pytest

from syffer.utils.validation import (
    safe_filename,
    validate_bpf,
    validate_cidr,
    validate_ip,
)


class TestSafeFilename:
    def test_accepts_simple_name(self):
        assert safe_filename("rapport") == "rapport"

    def test_accepts_alphanumeric_dots_underscores_dashes(self):
        assert safe_filename("mon-rapport_2026.01") == "mon-rapport_2026.01"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            safe_filename("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError):
            safe_filename("   ")

    def test_rejects_parent_traversal(self):
        with pytest.raises(ValueError):
            safe_filename("../etc/passwd")

    def test_rejects_backslash(self):
        with pytest.raises(ValueError):
            safe_filename("foo\\bar")

    def test_rejects_forward_slash(self):
        with pytest.raises(ValueError):
            safe_filename("foo/bar")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            safe_filename("a" * 101)

    def test_strips_unsafe_chars(self):
        # Les caracteres non autorises sont retires apres verification de la longueur
        # Ici "rapport!" -> "rapport" (le "!" est retire)
        assert safe_filename("rapport!") == "rapport"


class TestValidateCidr:
    def test_accepts_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_accepts_non_strict(self):
        # 192.168.1.5/24 n'est pas strict mais doit etre accepte et normalise
        assert validate_cidr("192.168.1.5/24") == "192.168.1.0/24"

    def test_accepts_single_host(self):
        assert validate_cidr("10.0.0.1/32") == "10.0.0.1/32"

    def test_rejects_invalid(self):
        with pytest.raises(ValueError):
            validate_cidr("not-a-cidr")

    def test_rejects_bad_prefix(self):
        with pytest.raises(ValueError):
            validate_cidr("192.168.1.0/33")


class TestValidateIp:
    def test_accepts_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_accepts_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_rejects_invalid(self):
        with pytest.raises(ValueError):
            validate_ip("999.999.999.999")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_ip("")


class TestValidateBpf:
    def test_accepts_simple(self):
        assert validate_bpf("tcp port 443") == "tcp port 443"

    def test_accepts_complex(self):
        assert validate_bpf("tcp and (port 80 or port 443)") == "tcp and (port 80 or port 443)"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_bpf("")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp `whoami`")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp | cat /etc/passwd")

    def test_rejects_newline(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp\nrm -rf /")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            validate_bpf("a" * 201)
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_validation.py -v`
Expected : FAIL avec `ModuleNotFoundError: No module named 'syffer.utils'`.

- [ ] **Step 3: Écrire `syffer/utils/__init__.py`** (vide)

- [ ] **Step 4: Écrire `syffer/utils/validation.py`**

```python
"""Validation et sanitisation des entrees utilisateur."""

from __future__ import annotations

import ipaddress
import re

_SAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_MAX_FILENAME_LEN = 100
_MAX_BPF_LEN = 200
_BPF_FORBIDDEN = ("`", ";", "|", "&", "$", "\n", "\r")


def safe_filename(name: str) -> str:
    """Renvoie un nom de fichier sanitize, ou leve ValueError.

    Rejette les noms vides/blancs, contenant `..`, un separateur de chemin,
    ou depassant 100 caracteres. Filtre les caracteres non
    [A-Za-z0-9._-] du nom retourne.
    """
    if not name or not name.strip():
        raise ValueError("nom de fichier vide")
    if len(name) > _MAX_FILENAME_LEN:
        raise ValueError(f"nom de fichier trop long (max {_MAX_FILENAME_LEN})")
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("nom de fichier contient un separateur ou '..'")
    cleaned = _SAFE_FILENAME_CHARS.sub("", name)
    if not cleaned:
        raise ValueError("nom de fichier vide apres sanitisation")
    return cleaned


def validate_cidr(cidr: str) -> str:
    """Valide un CIDR IPv4/IPv6 et renvoie sa forme normalisee.

    Accepte les formes non strictes (bits hote non nuls). Leve ValueError
    si le CIDR est invalide.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"CIDR invalide : {cidr}") from exc
    return str(network)


def validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6) et renvoie sa forme canonique."""
    if not ip:
        raise ValueError("adresse IP vide")
    try:
        address = ipaddress.ip_address(ip)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"adresse IP invalide : {ip}") from exc
    return str(address)


def validate_bpf(expr: str) -> str:
    """Valide une expression BPF (defense minimale contre injection).

    Rejette les expressions vides, trop longues (>200), ou contenant des
    caracteres shell dangereux. Une validation syntaxique complete via
    scapy est effectuee au niveau du module packet_capture.
    """
    if not expr:
        raise ValueError("filtre BPF vide")
    if len(expr) > _MAX_BPF_LEN:
        raise ValueError(f"filtre BPF trop long (max {_MAX_BPF_LEN})")
    for forbidden in _BPF_FORBIDDEN:
        if forbidden in expr:
            raise ValueError(f"filtre BPF contient un caractere interdit : {forbidden!r}")
    return expr
```

- [ ] **Step 5: Vérifier que les tests passent**

Run : `pytest tests/test_validation.py -v`
Expected : 21 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add syffer/utils/__init__.py syffer/utils/validation.py tests/test_validation.py
git commit -m "$(cat <<'EOF'
feat(utils): validation des entrees utilisateur

Ajoute safe_filename (contre path traversal), validate_cidr,
validate_ip et validate_bpf (contre injection shell dans les
filtres passes a scapy). Tests unitaires couvrant les cas
nominaux et les tentatives d'injection.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Utilitaires de chemins (extract dir + safe output path)

**Files:**
- Create: `syffer/utils/paths.py`
- Test: `tests/test_paths.py`

**Interfaces:**
- Consumes:
  - `syffer.utils.validation.safe_filename` (Task 3)
  - `syffer.config.EXTRACT_DIR` (Task 1)
- Produces:
  - `syffer.utils.paths.resolve_extract_dir() -> pathlib.Path` : renvoie `config.EXTRACT_DIR` en le créant si nécessaire.
  - `syffer.utils.paths.safe_output_path(name: str, extension: str) -> pathlib.Path` : renvoie `EXTRACT_DIR / f"{safe_filename(name)}.{extension.lstrip('.')}"`, garantit que le chemin résolu reste sous `EXTRACT_DIR` (sinon `ValueError`).
  - `syffer.utils.paths.timestamped_name(prefix: str, extension: str) -> str` : renvoie `f"{prefix}-YYYYMMDD-HHMMSS.{extension}"` avec l'horodatage courant.

- [ ] **Step 1: Écrire les tests de paths**

Créer `tests/test_paths.py` :

```python
"""Tests de syffer.utils.paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.utils.paths import (
    resolve_extract_dir,
    safe_output_path,
    timestamped_name,
)


def test_resolve_extract_dir_creates(tmp_extract_dir: Path):
    resolve_extract_dir().rmdir()  # supprime le dossier cree par la fixture
    result = resolve_extract_dir()
    assert result.exists()
    assert result.is_dir()


def test_safe_output_path_returns_under_extract(tmp_extract_dir: Path):
    p = safe_output_path("rapport", "txt")
    assert p == tmp_extract_dir / "rapport.txt"


def test_safe_output_path_strips_leading_dot(tmp_extract_dir: Path):
    p = safe_output_path("rapport", ".json")
    assert p.name == "rapport.json"


def test_safe_output_path_rejects_traversal(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        safe_output_path("../evil", "txt")


def test_safe_output_path_rejects_empty(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        safe_output_path("", "txt")


def test_timestamped_name_format():
    name = timestamped_name("capture", "pcap")
    assert name.startswith("capture-")
    assert name.endswith(".pcap")
    # capture-YYYYMMDD-HHMMSS.pcap -> len prefix + 1 + 8 + 1 + 6 + 5 = 28
    assert len(name) == len("capture-20260924-123456.pcap")
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_paths.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/utils/paths.py`**

```python
"""Resolution et sanitisation des chemins de sortie."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from syffer import config
from syffer.utils.validation import safe_filename


def resolve_extract_dir() -> Path:
    """Renvoie le dossier de sortie, le cree si necessaire."""
    directory = config.EXTRACT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def safe_output_path(name: str, extension: str) -> Path:
    """Construit un chemin de sortie sous EXTRACT_DIR, sanitize et verifie.

    Leve ValueError si le nom ne passe pas safe_filename, ou si le
    chemin resolu s'echappe de EXTRACT_DIR.
    """
    clean = safe_filename(name)
    ext = extension.lstrip(".")
    base = resolve_extract_dir()
    candidate = (base / f"{clean}.{ext}").resolve()
    if not str(candidate).startswith(str(base.resolve())):
        raise ValueError("chemin de sortie hors du dossier extract")
    return candidate


def timestamped_name(prefix: str, extension: str) -> str:
    """Renvoie un nom horodate au format prefix-YYYYMMDD-HHMMSS.ext."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = extension.lstrip(".")
    return f"{prefix}-{ts}.{ext}"
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_paths.py -v`
Expected : 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/utils/paths.py tests/test_paths.py
git commit -m "$(cat <<'EOF'
feat(utils): resolution securisee des chemins de sortie

Ajoute resolve_extract_dir, safe_output_path (verifie que le
chemin reste sous EXTRACT_DIR apres resolution, contre path
traversal) et timestamped_name pour les fichiers pcap.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Setup logging

**Files:**
- Create: `syffer/utils/logging_setup.py`
- Test: `tests/test_logging_setup.py`

**Interfaces:**
- Consumes: rien (dépend de `rich` en runtime)
- Produces:
  - `syffer.utils.logging_setup.configure(verbose: bool = False) -> None` : configure le root logger avec `RichHandler`, niveau `DEBUG` si `verbose` sinon `INFO`. Idempotent (peut être appelé plusieurs fois sans dupliquer les handlers).

- [ ] **Step 1: Écrire le test de logging_setup**

Créer `tests/test_logging_setup.py` :

```python
"""Tests de syffer.utils.logging_setup."""

from __future__ import annotations

import logging

from syffer.utils.logging_setup import configure


def test_configure_sets_info_by_default():
    configure(verbose=False)
    assert logging.getLogger().level == logging.INFO


def test_configure_verbose_sets_debug():
    configure(verbose=True)
    assert logging.getLogger().level == logging.DEBUG


def test_configure_is_idempotent():
    configure(verbose=False)
    before = len(logging.getLogger().handlers)
    configure(verbose=False)
    after = len(logging.getLogger().handlers)
    assert before == after
```

- [ ] **Step 2: Vérifier que le test échoue**

Run : `pytest tests/test_logging_setup.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/utils/logging_setup.py`**

```python
"""Configuration du logging avec RichHandler."""

from __future__ import annotations

import logging

from rich.logging import RichHandler

_CONFIGURED_MARKER = "_syffer_configured"


def configure(verbose: bool = False) -> None:
    """Configure le root logger avec RichHandler. Idempotent."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Retirer les handlers Syffer precedents pour rester idempotent
    root.handlers = [h for h in root.handlers if not getattr(h, _CONFIGURED_MARKER, False)]
    handler = RichHandler(rich_tracebacks=True, show_path=False, show_time=True)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    setattr(handler, _CONFIGURED_MARKER, True)
    root.addHandler(handler)
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_logging_setup.py -v`
Expected : 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/utils/logging_setup.py tests/test_logging_setup.py
git commit -m "$(cat <<'EOF'
feat(utils): configuration du logging avec RichHandler

Ajoute configure(verbose) idempotent : niveau INFO/DEBUG selon
le flag, sortie stylee via rich.logging.RichHandler.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Module interfaces (psutil)

**Files:**
- Create: `syffer/core/interfaces.py`
- Test: `tests/test_interfaces.py`

**Interfaces:**
- Consumes: `syffer.core.models.{Interface, InterfaceAddress}` (Task 2)
- Produces:
  - `syffer.core.interfaces.list_interfaces() -> tuple[Interface, ...]` : énumère les interfaces réseau via `psutil.net_if_addrs()` + `psutil.net_if_stats()`. Le champ `mac` est extrait des adresses de famille `AF_LINK` / `AF_PACKET`. Aucune I/O réseau. Aucun `print()` ni `input()`.

- [ ] **Step 1: Écrire le test des interfaces**

Créer `tests/test_interfaces.py` :

```python
"""Tests de syffer.core.interfaces."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import psutil

from syffer.core.interfaces import list_interfaces


def test_list_interfaces_maps_psutil(mocker):
    fake_addr = MagicMock()
    fake_addr.family = socket.AF_INET
    fake_addr.address = "192.168.1.10"
    fake_addr.netmask = "255.255.255.0"
    fake_addr.broadcast = "192.168.1.255"

    fake_mac = MagicMock()
    fake_mac.family = psutil.AF_LINK if hasattr(psutil, "AF_LINK") else -1
    fake_mac.address = "aa:bb:cc:dd:ee:ff"
    fake_mac.netmask = None
    fake_mac.broadcast = None

    fake_stats = MagicMock()
    fake_stats.isup = True
    fake_stats.mtu = 1500

    mocker.patch("psutil.net_if_addrs", return_value={"eth0": [fake_addr, fake_mac]})
    mocker.patch("psutil.net_if_stats", return_value={"eth0": fake_stats})

    result = list_interfaces()
    assert len(result) == 1
    iface = result[0]
    assert iface.name == "eth0"
    assert iface.is_up is True
    assert iface.mtu == 1500
    assert iface.mac == "aa:bb:cc:dd:ee:ff"
    assert len(iface.addresses) == 1
    assert iface.addresses[0].address == "192.168.1.10"


def test_list_interfaces_handles_missing_stats(mocker):
    fake_addr = MagicMock()
    fake_addr.family = socket.AF_INET
    fake_addr.address = "10.0.0.1"
    fake_addr.netmask = None
    fake_addr.broadcast = None

    mocker.patch("psutil.net_if_addrs", return_value={"lo": [fake_addr]})
    mocker.patch("psutil.net_if_stats", return_value={})

    result = list_interfaces()
    assert len(result) == 1
    assert result[0].name == "lo"
    assert result[0].is_up is False
    assert result[0].mtu is None
    assert result[0].mac is None


def test_list_interfaces_returns_tuple(mocker):
    mocker.patch("psutil.net_if_addrs", return_value={})
    mocker.patch("psutil.net_if_stats", return_value={})
    result = list_interfaces()
    assert isinstance(result, tuple)
    assert result == ()
```

- [ ] **Step 2: Vérifier que le test échoue**

Run : `pytest tests/test_interfaces.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/interfaces.py`**

```python
"""Enumeration des interfaces reseau (via psutil, cross-platform)."""

from __future__ import annotations

import socket

import psutil

from syffer.core.models import Interface, InterfaceAddress

_LINK_FAMILIES: set[int] = set()
if hasattr(psutil, "AF_LINK"):
    _LINK_FAMILIES.add(int(psutil.AF_LINK))
if hasattr(socket, "AF_PACKET"):
    _LINK_FAMILIES.add(int(socket.AF_PACKET))


def _family_name(family: int) -> str:
    if family in _LINK_FAMILIES:
        return "AF_LINK"
    try:
        return socket.AddressFamily(family).name  # type: ignore[arg-type]
    except (ValueError, AttributeError):
        return str(family)


def list_interfaces() -> tuple[Interface, ...]:
    """Enumere les interfaces reseau de la machine.

    Retourne un tuple d'Interface avec adresses, MAC, etat up/down et MTU.
    Ne fait aucune I/O reseau.
    """
    addrs_map = psutil.net_if_addrs()
    stats_map = psutil.net_if_stats()

    interfaces: list[Interface] = []
    for name, addrs in addrs_map.items():
        mac: str | None = None
        addresses: list[InterfaceAddress] = []
        for a in addrs:
            family_int = int(a.family)
            if family_int in _LINK_FAMILIES:
                mac = a.address
                continue
            addresses.append(
                InterfaceAddress(
                    family=_family_name(family_int),
                    address=a.address,
                    netmask=a.netmask,
                    broadcast=a.broadcast,
                )
            )
        stats = stats_map.get(name)
        interfaces.append(
            Interface(
                name=name,
                mac=mac,
                is_up=bool(stats.isup) if stats else False,
                mtu=int(stats.mtu) if stats else None,
                addresses=tuple(addresses),
            )
        )
    return tuple(interfaces)
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_interfaces.py -v`
Expected : 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/interfaces.py tests/test_interfaces.py
git commit -m "$(cat <<'EOF'
feat(core): enumeration des interfaces reseau via psutil

Remplace netifaces (casse sur Python 3.12/Windows) par psutil,
cross-platform et sans dependance C. Retourne des tuples de
dataclasses Interface immuables.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Module network_info

**Files:**
- Create: `syffer/core/network_info.py`
- Test: `tests/test_network_info.py`

**Interfaces:**
- Consumes:
  - `syffer.core.interfaces.list_interfaces` (Task 6)
  - `syffer.core.models.NetworkInfo` (Task 2)
- Produces:
  - `syffer.core.network_info.get_local_ip(timeout: float = 1.0) -> str | None` : résout l'IP locale en ouvrant un socket UDP vers `8.8.8.8:80` (aucun paquet envoyé, juste pour que l'OS choisisse une interface). Renvoie `None` en cas d'erreur.
  - `syffer.core.network_info.get_default_gateway() -> str | None` : renvoie la passerelle par défaut. Implémentation : essaie `psutil.net_if_stats()` combiné avec parsing best-effort du routage via `socket`/plateforme ; à défaut, renvoie `None`. Pour rester simple et sans dépendance supplémentaire, on utilise `psutil` uniquement (si non exposé, on renvoie `None`).
  - `syffer.core.network_info.get_network_info() -> NetworkInfo` : combine hostname, IP locale, gateway et interfaces.

- [ ] **Step 1: Écrire le test de network_info**

Créer `tests/test_network_info.py` :

```python
"""Tests de syffer.core.network_info."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

from syffer.core.network_info import get_local_ip, get_network_info
from syffer.core.models import Interface


def test_get_local_ip_returns_string(mocker):
    fake_sock = MagicMock()
    fake_sock.getsockname.return_value = ("192.168.1.42", 12345)
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.socket", return_value=fake_sock)

    assert get_local_ip() == "192.168.1.42"


def test_get_local_ip_returns_none_on_error(mocker):
    fake_sock = MagicMock()
    fake_sock.connect.side_effect = OSError("no route")
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.socket", return_value=fake_sock)

    assert get_local_ip() is None


def test_get_network_info_composes(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value="10.0.0.5")
    mocker.patch("syffer.core.network_info.get_default_gateway", return_value="10.0.0.1")
    mocker.patch("syffer.core.network_info.socket.gethostname", return_value="testhost")
    mocker.patch(
        "syffer.core.network_info.list_interfaces",
        return_value=(Interface(name="lo", mac=None, is_up=True, mtu=65536, addresses=()),),
    )
    info = get_network_info()
    assert info.hostname == "testhost"
    assert info.local_ip == "10.0.0.5"
    assert info.default_gateway == "10.0.0.1"
    assert info.interfaces[0].name == "lo"
```

- [ ] **Step 2: Vérifier que le test échoue**

Run : `pytest tests/test_network_info.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/network_info.py`**

```python
"""Informations reseau de la machine (hostname, IP locale, gateway)."""

from __future__ import annotations

import socket

import psutil

from syffer.core.interfaces import list_interfaces
from syffer.core.models import NetworkInfo


def get_local_ip(timeout: float = 1.0) -> str | None:
    """Renvoie l'IP locale sortante (aucun paquet reellement envoye)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def get_default_gateway() -> str | None:
    """Renvoie la passerelle par defaut, ou None si non determinable."""
    try:
        gateways = getattr(psutil, "net_if_stats", None)
        if gateways is None:
            return None
        # psutil ne fournit pas directement la gateway par defaut ; on tente
        # un parsing best-effort du routage via socket (Linux/macOS) ou en
        # utilisant l'IP locale comme fallback minimal. Pour rester
        # cross-platform sans dependance supplementaire, on renvoie None
        # si aucune info n'est disponible.
        return None
    except Exception:
        return None


def get_network_info() -> NetworkInfo:
    """Compose une NetworkInfo complete (hostname, IP, gateway, interfaces)."""
    return NetworkInfo(
        hostname=socket.gethostname(),
        local_ip=get_local_ip(),
        default_gateway=get_default_gateway(),
        interfaces=list_interfaces(),
    )
```

Note : `get_default_gateway` renvoie `None` par défaut car psutil ne l'expose pas directement de façon cross-platform. Une implémentation plus poussée nécessiterait `netifaces` (qu'on a écarté) ou un parsing spécifique par OS. Documenté dans le README comme limitation Phase 0.

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_network_info.py -v`
Expected : 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/network_info.py tests/test_network_info.py
git commit -m "$(cat <<'EOF'
feat(core): infos reseau machine (hostname, IP locale, gateway)

get_local_ip via socket UDP dummy (pas de paquet envoye),
get_default_gateway (None par defaut, limitation documentee),
get_network_info compose l'ensemble avec les interfaces.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Module packet_capture

**Files:**
- Create: `syffer/core/packet_capture.py`
- Test: `tests/test_packet_capture.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.{CaptureResult, PacketSummary}` (Task 2)
  - `syffer.utils.validation.validate_bpf` (Task 3)
  - `syffer.utils.paths.{resolve_extract_dir, timestamped_name}` (Task 4)
- Produces:
  - `syffer.core.packet_capture.capture(count: int, bpf_filter: str | None = None, iface: str | None = None, timeout: int | None = None) -> tuple[CaptureResult, list]` : sniffe `count` paquets (ou jusqu'à `timeout` secondes) avec filtre BPF optionnel. Retourne `(CaptureResult, packets_raw)` où `packets_raw` est la liste des paquets scapy bruts (gardés en session pour l'option "détails d'un paquet"). Écrit un fichier `.pcap` horodaté dans `extract/`.
  - `syffer.core.packet_capture.summarize_packet(index: int, packet) -> PacketSummary` : convertit un paquet scapy en `PacketSummary` sérialisable.

- [ ] **Step 1: Écrire les tests de packet_capture**

Créer `tests/test_packet_capture.py` :

```python
"""Tests de syffer.core.packet_capture."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from syffer.core.packet_capture import capture, summarize_packet


class _FakePacket:
    def __init__(self, summary: str = "TCP 1.1.1.1 > 2.2.2.2", src: str = "1.1.1.1", dst: str = "2.2.2.2", length: int = 64):
        self._summary = summary
        self._src = src
        self._dst = dst
        self._length = length
        self.time = 12345.6

    def summary(self) -> str:
        return self._summary

    def __len__(self) -> int:
        return self._length

    def __contains__(self, item) -> bool:
        return False


def test_capture_calls_sniff_and_writes_pcap(mocker, tmp_extract_dir: Path):
    fake_packets = [_FakePacket() for _ in range(3)]
    mock_sniff = mocker.patch("syffer.core.packet_capture.sniff", return_value=fake_packets)
    mock_wrpcap = mocker.patch("syffer.core.packet_capture.wrpcap")

    result, raw = capture(count=3, bpf_filter=None, iface=None, timeout=None)

    mock_sniff.assert_called_once_with(count=3, filter=None, iface=None, timeout=None)
    mock_wrpcap.assert_called_once()
    assert len(result.packets) == 3
    assert result.pcap_path.parent == tmp_extract_dir
    assert result.pcap_path.suffix == ".pcap"
    assert raw == fake_packets


def test_capture_validates_bpf(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.core.packet_capture.sniff", return_value=[])
    mocker.patch("syffer.core.packet_capture.wrpcap")

    with pytest.raises(ValueError):
        capture(count=1, bpf_filter="tcp; rm -rf /", iface=None, timeout=None)


def test_capture_passes_valid_bpf(mocker, tmp_extract_dir: Path):
    mock_sniff = mocker.patch("syffer.core.packet_capture.sniff", return_value=[])
    mocker.patch("syffer.core.packet_capture.wrpcap")

    capture(count=1, bpf_filter="tcp port 443", iface=None, timeout=None)
    kwargs = mock_sniff.call_args.kwargs
    assert kwargs["filter"] == "tcp port 443"


def test_summarize_packet_extracts_fields():
    packet = _FakePacket(summary="ICMP echo", src="10.0.0.1", dst="10.0.0.2", length=98)
    summary = summarize_packet(index=0, packet=packet)
    assert summary.index == 0
    assert summary.summary == "ICMP echo"
    assert summary.length == 98
    assert summary.timestamp == 12345.6
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_packet_capture.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/packet_capture.py`**

```python
"""Capture de paquets reseau avec filtres BPF."""

from __future__ import annotations

import logging
from typing import Any

from scapy.all import sniff, wrpcap  # type: ignore[import-untyped]

from syffer.core.models import CaptureResult, PacketSummary
from syffer.utils.paths import resolve_extract_dir, timestamped_name
from syffer.utils.validation import validate_bpf

logger = logging.getLogger(__name__)


def summarize_packet(index: int, packet: Any) -> PacketSummary:
    """Convertit un paquet scapy en PacketSummary serialisable."""
    try:
        summary = packet.summary()
    except Exception:
        summary = repr(packet)
    src = getattr(packet, "src", None)
    dst = getattr(packet, "dst", None)
    protocol = packet.__class__.__name__ if hasattr(packet, "__class__") else None
    try:
        length = len(packet)
    except Exception:
        length = 0
    timestamp = float(getattr(packet, "time", 0.0))
    return PacketSummary(
        index=index,
        timestamp=timestamp,
        summary=summary,
        src=src,
        dst=dst,
        protocol=protocol,
        length=length,
    )


def capture(
    count: int,
    bpf_filter: str | None = None,
    iface: str | None = None,
    timeout: int | None = None,
) -> tuple[CaptureResult, list[Any]]:
    """Capture `count` paquets (ou jusqu'a `timeout`s) avec filtre BPF optionnel.

    Retourne (CaptureResult, packets_raw) : CaptureResult contient les
    PacketSummary + le chemin du pcap ecrit, packets_raw contient les
    objets scapy bruts (utilises pour l'affichage detaille en session).
    """
    if bpf_filter is not None:
        bpf_filter = validate_bpf(bpf_filter)
    logger.debug("capture: count=%d filter=%s iface=%s timeout=%s", count, bpf_filter, iface, timeout)
    packets = sniff(count=count, filter=bpf_filter, iface=iface, timeout=timeout)

    extract = resolve_extract_dir()
    pcap_path = extract / timestamped_name("capture", "pcap")
    wrpcap(str(pcap_path), packets)
    logger.info("pcap ecrit : %s", pcap_path)

    summaries = tuple(summarize_packet(i, p) for i, p in enumerate(packets))
    result = CaptureResult(
        pcap_path=pcap_path,
        packets=summaries,
        bpf_filter=bpf_filter,
        iface=iface,
    )
    return result, list(packets)
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_packet_capture.py -v`
Expected : 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/packet_capture.py tests/test_packet_capture.py
git commit -m "$(cat <<'EOF'
feat(core): capture de paquets avec filtres BPF

Ajoute capture(count, bpf_filter, iface, timeout) et
summarize_packet. Le filtre BPF est valide avant l'appel a
scapy.sniff (contre injection). Le pcap ecrit est horodate
pour eviter les collisions.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Module network_scan (ARP)

**Files:**
- Create: `syffer/core/network_scan.py`
- Test: `tests/test_network_scan.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.{Host, ScanResult}` (Task 2)
  - `syffer.utils.validation.validate_cidr` (Task 3)
- Produces:
  - `syffer.core.network_scan.arp_scan(cidr: str, timeout: int = 3) -> ScanResult` : envoie un ARP request broadcast sur le CIDR donné, collecte les réponses. Enrichit chaque host avec le vendor MAC via `scapy.data.MANUFDB` si disponible (aucun appel réseau externe). Le CIDR est validé avant l'appel scapy.
  - `syffer.core.network_scan.lookup_vendor(mac: str) -> str | None` : lookup local du vendor via `scapy.data.MANUFDB` ; retourne `None` si base absente ou MAC inconnu.

- [ ] **Step 1: Écrire les tests de network_scan**

Créer `tests/test_network_scan.py` :

```python
"""Tests de syffer.core.network_scan."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from syffer.core.network_scan import arp_scan, lookup_vendor


def test_arp_scan_validates_cidr(mocker):
    mocker.patch("syffer.core.network_scan.srp", return_value=([], []))
    with pytest.raises(ValueError):
        arp_scan("not-a-cidr")


def test_arp_scan_returns_hosts(mocker):
    fake_reply = MagicMock()
    fake_reply.psrc = "192.168.1.10"
    fake_reply.hwsrc = "aa:bb:cc:dd:ee:ff"
    mocker.patch(
        "syffer.core.network_scan.srp",
        return_value=([(MagicMock(), fake_reply)], []),
    )
    mocker.patch("syffer.core.network_scan.lookup_vendor", return_value="TestVendor")

    result = arp_scan("192.168.1.0/24", timeout=1)
    assert result.cidr == "192.168.1.0/24"
    assert len(result.hosts) == 1
    assert result.hosts[0].ip == "192.168.1.10"
    assert result.hosts[0].mac == "aa:bb:cc:dd:ee:ff"
    assert result.hosts[0].vendor == "TestVendor"
    assert result.duration_s >= 0


def test_arp_scan_normalizes_cidr(mocker):
    mocker.patch("syffer.core.network_scan.srp", return_value=([], []))
    result = arp_scan("192.168.1.5/24", timeout=1)
    assert result.cidr == "192.168.1.0/24"


def test_lookup_vendor_returns_none_when_manuf_missing(mocker):
    mocker.patch("syffer.core.network_scan._MANUF", None)
    assert lookup_vendor("aa:bb:cc:dd:ee:ff") is None
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_network_scan.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/network_scan.py`**

```python
"""Scan ARP du reseau local via scapy."""

from __future__ import annotations

import logging
import time

from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]

from syffer.core.models import Host, ScanResult
from syffer.utils.validation import validate_cidr

logger = logging.getLogger(__name__)

try:
    from scapy.data import MANUFDB as _MANUF  # type: ignore[import-untyped]
except Exception:
    _MANUF = None  # type: ignore[assignment]


def lookup_vendor(mac: str) -> str | None:
    """Lookup local du vendor via scapy.data.MANUFDB. None si indisponible."""
    if _MANUF is None:
        return None
    try:
        return _MANUF._get_manuf(mac)  # type: ignore[attr-defined]
    except Exception:
        return None


def arp_scan(cidr: str, timeout: int = 3) -> ScanResult:
    """Envoie un ARP broadcast sur le CIDR et collecte les reponses."""
    normalized = validate_cidr(cidr)
    logger.debug("arp_scan: cidr=%s timeout=%d", normalized, timeout)

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=normalized)
    started = time.time()
    answered, _ = srp(request, timeout=timeout, verbose=0)
    duration = time.time() - started

    hosts = tuple(
        Host(ip=reply.psrc, mac=reply.hwsrc, vendor=lookup_vendor(reply.hwsrc))
        for _sent, reply in answered
    )
    logger.info("scan ARP termine : %d hosts en %.2fs", len(hosts), duration)

    return ScanResult(
        cidr=normalized,
        started_at=started,
        duration_s=duration,
        hosts=hosts,
    )
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_network_scan.py -v`
Expected : 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/network_scan.py tests/test_network_scan.py
git commit -m "$(cat <<'EOF'
feat(core): scan ARP avec validation CIDR et lookup vendor local

Remplace l'ancien scan_network() : CIDR valide via ipaddress
avant l'appel scapy, vendor MAC resolu localement via
scapy.data.MANUFDB (aucun appel reseau externe). Retourne un
ScanResult immuable avec duree du scan.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Module geolocation

**Files:**
- Create: `syffer/core/geolocation.py`
- Test: `tests/test_geolocation.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.GeoInfo` (Task 2)
  - `syffer.utils.validation.validate_ip` (Task 3)
  - `syffer.config.{IP_API_URL, DEFAULT_HTTP_TIMEOUT}` (Task 1)
- Produces:
  - `syffer.core.geolocation.GeolocationError(Exception)` : exception dédiée pour les échecs de lookup.
  - `syffer.core.geolocation.lookup(ip: str, timeout: int | None = None) -> GeoInfo` : appelle ip-api.com, renvoie un `GeoInfo`. Lève `GeolocationError` en cas de status HTTP ≠ 200, réponse `status == "fail"`, ou timeout.

- [ ] **Step 1: Écrire les tests de geolocation**

Créer `tests/test_geolocation.py` :

```python
"""Tests de syffer.core.geolocation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from syffer.core.geolocation import GeolocationError, lookup


def test_lookup_success(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "status": "success",
        "country": "France",
        "city": "Paris",
        "regionName": "Ile-de-France",
        "lat": 48.8566,
        "lon": 2.3522,
        "isp": "TestISP",
    }
    mocker.patch("requests.get", return_value=fake_response)

    info = lookup("8.8.8.8")
    assert info.country == "France"
    assert info.city == "Paris"
    assert info.region == "Ile-de-France"
    assert info.lat == 48.8566
    assert info.lon == 2.3522
    assert info.isp == "TestISP"
    assert info.status == "success"


def test_lookup_rejects_invalid_ip():
    with pytest.raises(ValueError):
        lookup("not-an-ip")


def test_lookup_fail_status(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"status": "fail", "message": "reserved range"}
    mocker.patch("requests.get", return_value=fake_response)

    with pytest.raises(GeolocationError):
        lookup("127.0.0.1")


def test_lookup_http_error(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 500
    mocker.patch("requests.get", return_value=fake_response)

    with pytest.raises(GeolocationError):
        lookup("8.8.8.8")


def test_lookup_timeout(mocker):
    mocker.patch("requests.get", side_effect=requests.Timeout())
    with pytest.raises(GeolocationError):
        lookup("8.8.8.8", timeout=1)
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_geolocation.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/geolocation.py`**

```python
"""Geolocalisation d'IP publique via ip-api.com."""

from __future__ import annotations

import logging

import requests

from syffer import config
from syffer.core.models import GeoInfo
from syffer.utils.validation import validate_ip

logger = logging.getLogger(__name__)


class GeolocationError(Exception):
    """Echec du lookup de geolocalisation."""


def lookup(ip: str, timeout: int | None = None) -> GeoInfo:
    """Interroge ip-api.com et renvoie un GeoInfo. Leve GeolocationError."""
    normalized = validate_ip(ip)
    timeout = timeout if timeout is not None else config.DEFAULT_HTTP_TIMEOUT
    url = config.IP_API_URL.format(ip=normalized)
    logger.debug("geolocation lookup : %s", url)

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise GeolocationError(f"echec HTTP : {exc}") from exc

    if response.status_code != 200:
        raise GeolocationError(f"HTTP {response.status_code}")

    payload = response.json()
    status = payload.get("status", "unknown")
    if status != "success":
        raise GeolocationError(f"reponse fail : {payload.get('message', 'inconnue')}")

    return GeoInfo(
        ip=normalized,
        country=payload.get("country"),
        city=payload.get("city"),
        region=payload.get("regionName"),
        lat=payload.get("lat"),
        lon=payload.get("lon"),
        isp=payload.get("isp"),
        status=status,
    )
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_geolocation.py -v`
Expected : 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/geolocation.py tests/test_geolocation.py
git commit -m "$(cat <<'EOF'
feat(core): geolocalisation IP publique via ip-api.com

Wrapper propre autour de ip-api.com : IP validee en amont,
GeolocationError dediee pour les echecs HTTP / status=fail /
timeout, GeoInfo immuable en sortie.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Wrapper d'outil externe (préparation Phase 1)

**Files:**
- Create: `syffer/core/external.py`
- Test: `tests/test_external.py`

**Interfaces:**
- Consumes: rien
- Produces:
  - `syffer.core.external.ExternalTool` : classe wrapper.
    - `__init__(self, name: str)` : `name` est le nom du binaire (ex: `"nmap"`).
    - `available(self) -> bool` : `shutil.which(name) is not None`.
    - `run(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess` : exécute `[name, *args]` avec `subprocess.run(check=False, capture_output=True, timeout=timeout)`. Lève `FileNotFoundError` si le binaire n'est pas trouvé.

Aucun binaire n'est appelé effectivement en Phase 0.

- [ ] **Step 1: Écrire les tests du wrapper externe**

Créer `tests/test_external.py` :

```python
"""Tests de syffer.core.external."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from syffer.core.external import ExternalTool


def test_available_true(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    tool = ExternalTool("nmap")
    assert tool.available() is True


def test_available_false(mocker):
    mocker.patch("shutil.which", return_value=None)
    tool = ExternalTool("nmap")
    assert tool.available() is False


def test_run_calls_subprocess(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mock_run = mocker.patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(args=["nmap", "-v"], returncode=0, stdout=b"ok", stderr=b""),
    )
    tool = ExternalTool("nmap")
    result = tool.run(["-v"])
    mock_run.assert_called_once()
    assert result.returncode == 0


def test_run_raises_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    tool = ExternalTool("nmap")
    with pytest.raises(FileNotFoundError):
        tool.run(["-v"])
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_external.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/external.py`**

```python
"""Wrapper generique pour outils CLI externes (prepare Phase 1)."""

from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


class ExternalTool:
    """Represente un binaire externe (nmap, tcpdump, ...).

    Phase 0 : structure en place, aucun outil consomme.
    Phase 1 : sous-classes concretes (NmapTool) branchees dessus.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def available(self) -> bool:
        return shutil.which(self.name) is not None

    def run(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        binary = shutil.which(self.name)
        if binary is None:
            raise FileNotFoundError(f"binaire introuvable : {self.name}")
        logger.debug("execution externe : %s %s", binary, args)
        return subprocess.run(
            [binary, *args],
            check=False,
            capture_output=True,
            timeout=timeout,
        )
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `pytest tests/test_external.py -v`
Expected : 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/external.py tests/test_external.py
git commit -m "$(cat <<'EOF'
feat(core): wrapper d'outil externe (preparation Phase 1)

Ajoute ExternalTool (available/run) pour envelopper des
binaires CLI (nmap sera branche en Phase 1). Aucun binaire
consomme en Phase 0.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Formatters et exporter

**Files:**
- Create: `syffer/reports/__init__.py`
- Create: `syffer/reports/formatters.py`
- Create: `syffer/reports/exporter.py`
- Test: `tests/test_formatters.py`
- Test: `tests/test_exporter.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.{CaptureResult, ScanResult, NetworkInfo, GeoInfo}` (Task 2)
  - `syffer.utils.paths.safe_output_path` (Task 4)
- Produces:
  - `syffer.reports.formatters.to_txt(result) -> str` : sérialise `CaptureResult | ScanResult | NetworkInfo | GeoInfo` en texte lisible.
  - `syffer.reports.formatters.to_json(result) -> str` : sérialise via `dataclasses.asdict` + `json.dumps(default=str, indent=2)`.
  - `syffer.reports.formatters.to_csv(result) -> str` : sérialise en CSV (adapté au type — hosts pour scan, packets pour capture, une ligne pour info/geo).
  - `syffer.reports.exporter.export(result, fmt: Literal["txt", "json", "csv"], name: str) -> pathlib.Path` : dispatch selon `fmt`, écrit dans `safe_output_path(name, fmt)`, retourne le chemin.

- [ ] **Step 1: Écrire les tests des formatters**

Créer `tests/test_formatters.py` :

```python
"""Tests de syffer.reports.formatters."""

from __future__ import annotations

import json
from pathlib import Path

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    Host,
    Interface,
    NetworkInfo,
    PacketSummary,
    ScanResult,
)
from syffer.reports.formatters import to_csv, to_json, to_txt


def _sample_scan() -> ScanResult:
    return ScanResult(
        cidr="192.168.1.0/24",
        started_at=1700000000.0,
        duration_s=1.23,
        hosts=(
            Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", vendor="TestCo"),
            Host(ip="192.168.1.20", mac="11:22:33:44:55:66", vendor=None),
        ),
    )


def _sample_capture() -> CaptureResult:
    return CaptureResult(
        pcap_path=Path("/tmp/x.pcap"),
        packets=(
            PacketSummary(index=0, timestamp=1.0, summary="TCP", src="1.1.1.1", dst="2.2.2.2", protocol="TCP", length=64),
        ),
        bpf_filter="tcp",
        iface="eth0",
    )


def _sample_info() -> NetworkInfo:
    return NetworkInfo(
        hostname="host",
        local_ip="10.0.0.5",
        default_gateway=None,
        interfaces=(Interface(name="lo", mac=None, is_up=True, mtu=65536, addresses=()),),
    )


def _sample_geo() -> GeoInfo:
    return GeoInfo(
        ip="8.8.8.8", country="US", city="Mountain View", region="CA",
        lat=37.4, lon=-122.0, isp="Google", status="success",
    )


class TestToTxt:
    def test_scan(self):
        text = to_txt(_sample_scan())
        assert "192.168.1.0/24" in text
        assert "192.168.1.10" in text
        assert "aa:bb:cc:dd:ee:ff" in text
        assert "TestCo" in text

    def test_capture(self):
        text = to_txt(_sample_capture())
        assert "tcp" in text
        assert "TCP" in text

    def test_info(self):
        text = to_txt(_sample_info())
        assert "host" in text
        assert "10.0.0.5" in text
        assert "lo" in text

    def test_geo(self):
        text = to_txt(_sample_geo())
        assert "8.8.8.8" in text
        assert "US" in text


class TestToJson:
    def test_scan_roundtrip(self):
        payload = json.loads(to_json(_sample_scan()))
        assert payload["cidr"] == "192.168.1.0/24"
        assert len(payload["hosts"]) == 2

    def test_geo_roundtrip(self):
        payload = json.loads(to_json(_sample_geo()))
        assert payload["country"] == "US"


class TestToCsv:
    def test_scan_has_header_and_rows(self):
        csv_text = to_csv(_sample_scan())
        lines = csv_text.strip().splitlines()
        assert lines[0] == "ip,mac,vendor"
        assert len(lines) == 3

    def test_capture_has_header(self):
        csv_text = to_csv(_sample_capture())
        assert csv_text.splitlines()[0] == "index,timestamp,summary,src,dst,protocol,length"

    def test_info_has_header(self):
        csv_text = to_csv(_sample_info())
        assert csv_text.splitlines()[0] == "interface,mac,is_up,mtu,addresses"

    def test_geo_single_row(self):
        csv_text = to_csv(_sample_geo())
        lines = csv_text.strip().splitlines()
        assert lines[0] == "ip,country,city,region,lat,lon,isp,status"
        assert len(lines) == 2
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `pytest tests/test_formatters.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/reports/__init__.py`** (vide)

- [ ] **Step 4: Écrire `syffer/reports/formatters.py`**

```python
"""Serialisation des resultats vers txt / json / csv."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Union

from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    NetworkInfo,
    ScanResult,
)

Result = Union[CaptureResult, ScanResult, NetworkInfo, GeoInfo]


def to_json(result: Result) -> str:
    return json.dumps(asdict(result), default=str, indent=2, ensure_ascii=False)


def to_txt(result: Result) -> str:
    if isinstance(result, ScanResult):
        lines = [
            f"Scan ARP : {result.cidr}",
            f"Duree : {result.duration_s:.2f}s",
            f"Hosts detectes : {len(result.hosts)}",
            "-" * 60,
        ]
        for host in result.hosts:
            vendor = host.vendor or "?"
            lines.append(f"{host.ip:<18} {host.mac:<20} {vendor}")
        return "\n".join(lines) + "\n"

    if isinstance(result, CaptureResult):
        lines = [
            f"Capture : {len(result.packets)} paquets",
            f"Interface : {result.iface or 'defaut'}",
            f"Filtre BPF : {result.bpf_filter or 'aucun'}",
            f"PCAP : {result.pcap_path}",
            "-" * 60,
        ]
        for p in result.packets:
            lines.append(f"[{p.index}] {p.summary} ({p.length} octets)")
        return "\n".join(lines) + "\n"

    if isinstance(result, NetworkInfo):
        lines = [
            f"Hostname : {result.hostname}",
            f"IP locale : {result.local_ip or 'inconnue'}",
            f"Gateway : {result.default_gateway or 'inconnue'}",
            "-" * 60,
        ]
        for iface in result.interfaces:
            state = "UP" if iface.is_up else "DOWN"
            lines.append(f"{iface.name} [{state}] MAC={iface.mac or '?'} MTU={iface.mtu or '?'}")
            for a in iface.addresses:
                lines.append(f"    {a.family}: {a.address}")
        return "\n".join(lines) + "\n"

    if isinstance(result, GeoInfo):
        lines = [
            f"IP : {result.ip}",
            f"Pays : {result.country or '?'}",
            f"Ville : {result.city or '?'}",
            f"Region : {result.region or '?'}",
            f"Coordonnees : {result.lat}, {result.lon}",
            f"ISP : {result.isp or '?'}",
        ]
        return "\n".join(lines) + "\n"

    raise TypeError(f"type de resultat non supporte : {type(result).__name__}")


def to_csv(result: Result) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if isinstance(result, ScanResult):
        writer.writerow(["ip", "mac", "vendor"])
        for host in result.hosts:
            writer.writerow([host.ip, host.mac, host.vendor or ""])
    elif isinstance(result, CaptureResult):
        writer.writerow(["index", "timestamp", "summary", "src", "dst", "protocol", "length"])
        for p in result.packets:
            writer.writerow([p.index, p.timestamp, p.summary, p.src or "", p.dst or "", p.protocol or "", p.length])
    elif isinstance(result, NetworkInfo):
        writer.writerow(["interface", "mac", "is_up", "mtu", "addresses"])
        for iface in result.interfaces:
            addrs = ";".join(f"{a.family}:{a.address}" for a in iface.addresses)
            writer.writerow([iface.name, iface.mac or "", iface.is_up, iface.mtu or "", addrs])
    elif isinstance(result, GeoInfo):
        writer.writerow(["ip", "country", "city", "region", "lat", "lon", "isp", "status"])
        writer.writerow([
            result.ip, result.country or "", result.city or "", result.region or "",
            result.lat if result.lat is not None else "",
            result.lon if result.lon is not None else "",
            result.isp or "", result.status,
        ])
    else:
        raise TypeError(f"type de resultat non supporte : {type(result).__name__}")

    return buffer.getvalue()
```

- [ ] **Step 5: Vérifier que les tests des formatters passent**

Run : `pytest tests/test_formatters.py -v`
Expected : 11 tests PASS.

- [ ] **Step 6: Écrire les tests de l'exporter**

Créer `tests/test_exporter.py` :

```python
"""Tests de syffer.reports.exporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from syffer.core.models import Host, ScanResult
from syffer.reports.exporter import export


def _sample() -> ScanResult:
    return ScanResult(
        cidr="192.168.1.0/24", started_at=0.0, duration_s=0.1,
        hosts=(Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor=None),),
    )


def test_export_txt_writes_under_extract(tmp_extract_dir: Path):
    path = export(_sample(), fmt="txt", name="rapport")
    assert path.exists()
    assert path.parent == tmp_extract_dir
    assert path.suffix == ".txt"
    assert "192.168.1.1" in path.read_text(encoding="utf-8")


def test_export_json_valid(tmp_extract_dir: Path):
    path = export(_sample(), fmt="json", name="rapport")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["cidr"] == "192.168.1.0/24"


def test_export_csv_valid(tmp_extract_dir: Path):
    path = export(_sample(), fmt="csv", name="rapport")
    content = path.read_text(encoding="utf-8")
    assert "ip,mac,vendor" in content
    assert "192.168.1.1" in content


def test_export_rejects_traversal(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        export(_sample(), fmt="txt", name="../evil")


def test_export_rejects_unknown_format(tmp_extract_dir: Path):
    with pytest.raises(ValueError):
        export(_sample(), fmt="xml", name="rapport")  # type: ignore[arg-type]
```

- [ ] **Step 7: Écrire `syffer/reports/exporter.py`**

```python
"""Dispatcher d'export : txt / json / csv sous EXTRACT_DIR."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from syffer.reports.formatters import Result, to_csv, to_json, to_txt
from syffer.utils.paths import safe_output_path

Format = Literal["txt", "json", "csv"]


def export(result: Result, fmt: Format, name: str) -> Path:
    if fmt == "txt":
        content = to_txt(result)
    elif fmt == "json":
        content = to_json(result)
    elif fmt == "csv":
        content = to_csv(result)
    else:
        raise ValueError(f"format inconnu : {fmt}")

    path = safe_output_path(name, fmt)
    path.write_text(content, encoding="utf-8")
    return path
```

- [ ] **Step 8: Vérifier que les tests de l'exporter passent**

Run : `pytest tests/test_exporter.py -v`
Expected : 5 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add syffer/reports/__init__.py syffer/reports/formatters.py syffer/reports/exporter.py tests/test_formatters.py tests/test_exporter.py
git commit -m "$(cat <<'EOF'
feat(reports): export unifie txt/json/csv

Ajoute to_txt/to_json/to_csv pour tous les types de resultats
core, et export(result, fmt, name) qui dispatch et ecrit sous
EXTRACT_DIR via safe_output_path (contre path traversal).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: Couche CLI — prompts, display, session, handlers

**Files:**
- Create: `syffer/cli/__init__.py`
- Create: `syffer/cli/session.py`
- Create: `syffer/cli/display.py`
- Create: `syffer/cli/prompts.py`
- Create: `syffer/cli/handlers.py`
- Test: `tests/test_menu_dispatch.py`

**Interfaces:**
- Consumes: tous les modules `core`, `reports`, `utils`.
- Produces:
  - `syffer.cli.session.Session` : dataclass mutable (non frozen) portant `captured_packets: list`, `last_capture: CaptureResult | None`, `verbose: bool`, `extract_dir: pathlib.Path`.
  - `syffer.cli.display.banner() -> None` : affiche le logo ASCII via `rich.console.Console.print`.
  - `syffer.cli.display.render_scan(result: ScanResult) -> None`
  - `syffer.cli.display.render_capture(result: CaptureResult) -> None`
  - `syffer.cli.display.render_info(info: NetworkInfo) -> None`
  - `syffer.cli.display.render_geo(info: GeoInfo) -> None`
  - `syffer.cli.display.render_packet_details(packet) -> None`
  - `syffer.cli.display.error(msg: str) -> None`
  - `syffer.cli.display.success(msg: str) -> None`
  - `syffer.cli.prompts.ask_cidr() -> str`
  - `syffer.cli.prompts.ask_ip() -> str`
  - `syffer.cli.prompts.ask_bpf() -> str | None` (retourne `None` si l'utilisateur ne veut pas de filtre)
  - `syffer.cli.prompts.ask_int(message: str, default: int) -> int`
  - `syffer.cli.prompts.ask_export() -> tuple[str, str] | None` : `(fmt, name)` ou `None` si l'utilisateur refuse.
  - `syffer.cli.handlers.handle_capture(session: Session) -> None`
  - `syffer.cli.handlers.handle_scan(session: Session) -> None`
  - `syffer.cli.handlers.handle_info(session: Session) -> None`
  - `syffer.cli.handlers.handle_local_ip(session: Session) -> None`
  - `syffer.cli.handlers.handle_geo(session: Session) -> None`
  - `syffer.cli.handlers.handle_packet_details(session: Session) -> None`
  - `syffer.cli.handlers.handle_settings(session: Session) -> None`

- [ ] **Step 1: Écrire `syffer/cli/__init__.py`** (vide)

- [ ] **Step 2: Écrire `syffer/cli/session.py`**

```python
"""Etat de session du menu interactif."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from syffer import config
from syffer.core.models import CaptureResult


@dataclass
class Session:
    captured_packets: list[Any] = field(default_factory=list)
    last_capture: CaptureResult | None = None
    verbose: bool = False
    extract_dir: Path = field(default_factory=lambda: config.EXTRACT_DIR)
```

- [ ] **Step 3: Écrire `syffer/cli/display.py`**

```python
"""Rendu rich des resultats et messages."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from syffer.core.models import CaptureResult, GeoInfo, NetworkInfo, ScanResult

_console = Console()

_BANNER = r"""
 ▄▄▄▄▄▄▄▄▄▄ ▄▄     ▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄▄▄
▐░░░░░░░░░░▌▐░░▌   ▐░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌ ▐░▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░▌▐░▐░▌▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░▌▐░▌ ▐░▌ ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀█░▌▐░▌  ▀  ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀
          ▐░▌▐░▌     ▐░▌▐░▌          ▐░▌          ▐░▌          ▐░▌     ▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌▐░▌     ▐░▌▐░▌          ▐░▌          ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌
▐░░░░░░░░░░▌▐░▌     ▐░▌▐░▌          ▐░▌          ▐░░░░░░░░░░░▌▐░▌       ▐░▌
 ▀▀▀▀▀▀▀▀▀▀  ▀       ▀  ▀            ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀
"""


def banner() -> None:
    _console.print(Panel.fit(_BANNER, style="bold cyan", subtitle="recon toolkit"))


def error(msg: str) -> None:
    _console.print(f"[bold red]![/bold red] {msg}")


def success(msg: str) -> None:
    _console.print(f"[bold green]OK[/bold green] {msg}")


def render_scan(result: ScanResult) -> None:
    table = Table(title=f"Scan ARP {result.cidr} ({result.duration_s:.2f}s)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor")
    for host in result.hosts:
        table.add_row(host.ip, host.mac, host.vendor or "-")
    _console.print(table)


def render_capture(result: CaptureResult) -> None:
    _console.print(f"[bold]Capture[/bold] : {len(result.packets)} paquets, filtre='{result.bpf_filter or 'aucun'}'")
    _console.print(f"PCAP : [green]{result.pcap_path}[/green]")
    table = Table()
    table.add_column("#", justify="right")
    table.add_column("Resume")
    table.add_column("Taille", justify="right")
    for p in result.packets:
        table.add_row(str(p.index), p.summary, str(p.length))
    _console.print(table)


def render_info(info: NetworkInfo) -> None:
    _console.print(f"[bold]Hostname[/bold] : {info.hostname}")
    _console.print(f"[bold]IP locale[/bold] : {info.local_ip or '?'}")
    _console.print(f"[bold]Gateway[/bold] : {info.default_gateway or '?'}")
    table = Table(title="Interfaces")
    table.add_column("Nom")
    table.add_column("Etat")
    table.add_column("MAC")
    table.add_column("MTU")
    table.add_column("Adresses")
    for iface in info.interfaces:
        state = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
        addrs = "\n".join(f"{a.family}: {a.address}" for a in iface.addresses)
        table.add_row(iface.name, state, iface.mac or "-", str(iface.mtu or "-"), addrs or "-")
    _console.print(table)


def render_geo(info: GeoInfo) -> None:
    table = Table(title=f"Geolocalisation {info.ip}")
    table.add_column("Champ")
    table.add_column("Valeur")
    for field_name, value in [
        ("Pays", info.country),
        ("Ville", info.city),
        ("Region", info.region),
        ("Latitude", info.lat),
        ("Longitude", info.lon),
        ("ISP", info.isp),
    ]:
        table.add_row(field_name, str(value) if value is not None else "-")
    _console.print(table)


def render_packet_details(packet: Any) -> None:
    try:
        _console.print(Panel(packet.show(dump=True), title="Details paquet", border_style="cyan"))
    except Exception as exc:
        error(f"impossible d'afficher le paquet : {exc}")
```

- [ ] **Step 4: Écrire `syffer/cli/prompts.py`**

```python
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
```

- [ ] **Step 5: Écrire `syffer/cli/handlers.py`**

```python
"""Handlers du menu interactif."""

from __future__ import annotations

import logging

from syffer import config
from syffer.cli import display, prompts
from syffer.cli.session import Session
from syffer.core import geolocation, network_info, network_scan, packet_capture
from syffer.core.geolocation import GeolocationError
from syffer.reports.exporter import export
from syffer.utils import logging_setup

logger = logging.getLogger(__name__)


def _maybe_export(result) -> None:
    choice = prompts.ask_export()
    if choice is None:
        return
    fmt, name = choice
    path = export(result, fmt=fmt, name=name)  # type: ignore[arg-type]
    display.success(f"rapport ecrit : {path}")


def handle_capture(session: Session) -> None:
    count = prompts.ask_int("Nombre de paquets a capturer", default=config.DEFAULT_CAPTURE_COUNT)
    bpf = prompts.ask_bpf()
    try:
        result, raw = packet_capture.capture(count=count, bpf_filter=bpf, iface=None, timeout=None)
    except PermissionError:
        display.error("permissions insuffisantes (essayez en root/admin)")
        return
    except OSError as exc:
        display.error(f"erreur reseau : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return

    session.captured_packets = raw
    session.last_capture = result
    display.render_capture(result)
    _maybe_export(result)


def handle_scan(session: Session) -> None:
    cidr = prompts.ask_cidr()
    try:
        result = network_scan.arp_scan(cidr, timeout=config.DEFAULT_ARP_TIMEOUT)
    except PermissionError:
        display.error("permissions insuffisantes (essayez en root/admin)")
        return
    except OSError as exc:
        display.error(f"erreur reseau : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return

    display.render_scan(result)
    _maybe_export(result)


def handle_info(session: Session) -> None:
    info = network_info.get_network_info()
    display.render_info(info)
    _maybe_export(info)


def handle_local_ip(session: Session) -> None:
    ip = network_info.get_local_ip()
    if ip is None:
        display.error("IP locale non determinable")
    else:
        display.success(f"IP locale : {ip}")


def handle_geo(session: Session) -> None:
    ip = prompts.ask_ip()
    try:
        info = geolocation.lookup(ip)
    except GeolocationError as exc:
        display.error(f"echec geolocation : {exc}")
        return
    except ValueError as exc:
        display.error(str(exc))
        return
    display.render_geo(info)
    _maybe_export(info)


def handle_packet_details(session: Session) -> None:
    if not session.captured_packets:
        display.error("aucun paquet capture dans cette session (option 1 d'abord)")
        return
    index = prompts.ask_int("Index du paquet a afficher (0-base)", default=0)
    if index >= len(session.captured_packets):
        display.error(f"index hors limites (0..{len(session.captured_packets) - 1})")
        return
    display.render_packet_details(session.captured_packets[index])


def handle_settings(session: Session) -> None:
    import questionary
    new_verbose = questionary.confirm("Activer les logs verbeux ?", default=session.verbose).ask()
    if new_verbose is None:
        return
    session.verbose = bool(new_verbose)
    logging_setup.configure(verbose=session.verbose)
    display.success(f"mode verbeux : {'ON' if session.verbose else 'OFF'}")
```

- [ ] **Step 6: Écrire le test de dispatch des handlers**

Créer `tests/test_menu_dispatch.py` :

```python
"""Tests des handlers du menu (via mocks, pas d'I/O reelle)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from syffer.cli import handlers
from syffer.cli.session import Session
from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    Host,
    NetworkInfo,
    ScanResult,
)


def test_handle_scan_calls_core(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_cidr", return_value="192.168.1.0/24")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    mock_scan = mocker.patch(
        "syffer.core.network_scan.arp_scan",
        return_value=ScanResult(cidr="192.168.1.0/24", started_at=0.0, duration_s=0.1, hosts=()),
    )
    mocker.patch("syffer.cli.display.render_scan")

    handlers.handle_scan(Session())
    mock_scan.assert_called_once()


def test_handle_scan_handles_permission_error(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_cidr", return_value="192.168.1.0/24")
    mocker.patch("syffer.core.network_scan.arp_scan", side_effect=PermissionError())
    mock_error = mocker.patch("syffer.cli.display.error")

    handlers.handle_scan(Session())
    mock_error.assert_called_once()


def test_handle_capture_updates_session(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_int", return_value=5)
    mocker.patch("syffer.cli.prompts.ask_bpf", return_value=None)
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_result = CaptureResult(
        pcap_path=tmp_extract_dir / "x.pcap", packets=(), bpf_filter=None, iface=None
    )
    mocker.patch("syffer.core.packet_capture.capture", return_value=(fake_result, ["raw1"]))
    mocker.patch("syffer.cli.display.render_capture")

    session = Session()
    handlers.handle_capture(session)
    assert session.last_capture is fake_result
    assert session.captured_packets == ["raw1"]


def test_handle_packet_details_no_capture(mocker):
    mock_error = mocker.patch("syffer.cli.display.error")
    handlers.handle_packet_details(Session())
    mock_error.assert_called_once()


def test_handle_geo_success(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_ip", return_value="8.8.8.8")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_geo = GeoInfo(
        ip="8.8.8.8", country="US", city="MV", region="CA",
        lat=37.4, lon=-122.0, isp="Google", status="success",
    )
    mocker.patch("syffer.core.geolocation.lookup", return_value=fake_geo)
    mock_render = mocker.patch("syffer.cli.display.render_geo")

    handlers.handle_geo(Session())
    mock_render.assert_called_once_with(fake_geo)


def test_handle_info_calls_render(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)
    fake_info = NetworkInfo(hostname="h", local_ip="1.2.3.4", default_gateway=None, interfaces=())
    mocker.patch("syffer.core.network_info.get_network_info", return_value=fake_info)
    mock_render = mocker.patch("syffer.cli.display.render_info")

    handlers.handle_info(Session())
    mock_render.assert_called_once_with(fake_info)


def test_handle_local_ip_success(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value="10.0.0.5")
    mock_success = mocker.patch("syffer.cli.display.success")
    handlers.handle_local_ip(Session())
    mock_success.assert_called_once()


def test_handle_local_ip_failure(mocker):
    mocker.patch("syffer.core.network_info.get_local_ip", return_value=None)
    mock_error = mocker.patch("syffer.cli.display.error")
    handlers.handle_local_ip(Session())
    mock_error.assert_called_once()
```

- [ ] **Step 7: Vérifier que les tests passent**

Run : `pytest tests/test_menu_dispatch.py -v`
Expected : 8 tests PASS.

- [ ] **Step 8: Commit**

```bash
git add syffer/cli/__init__.py syffer/cli/session.py syffer/cli/display.py syffer/cli/prompts.py syffer/cli/handlers.py tests/test_menu_dispatch.py
git commit -m "$(cat <<'EOF'
feat(cli): couche presentation - session, display, prompts, handlers

- Session : etat mutable du menu (paquets, verbose, extract_dir)
- display : bannier + rendu rich pour chaque type de resultat
- prompts : ask_cidr/ask_ip/ask_bpf/ask_int/ask_export avec
  validation via questionary
- handlers : un handler par option du menu, avec gestion propre
  des PermissionError/OSError/ValueError (message rich, retour au
  menu, pas de crash)

Tests via mocks des prompts, du core et du display : verifient le
cablage sans I/O reelle ni droits admin.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: Boucle de menu et point d'entrée

**Files:**
- Create: `syffer/cli/menu.py`
- Modify: `syffer/__main__.py`

**Interfaces:**
- Consumes:
  - `syffer.cli.handlers.*` (Task 13)
  - `syffer.cli.session.Session` (Task 13)
  - `syffer.cli.display.banner` (Task 13)
  - `syffer.utils.logging_setup.configure` (Task 5)
- Produces:
  - `syffer.cli.menu.run(session: Session | None = None) -> int` : boucle principale du menu. Retourne 0 à la sortie normale, 130 sur `KeyboardInterrupt`.
  - `syffer.__main__.main() -> int` : configure logging, crée Session, appelle `menu.run()`, catch les exceptions inattendues au top-level.

- [ ] **Step 1: Écrire `syffer/cli/menu.py`**

```python
"""Boucle principale du menu interactif."""

from __future__ import annotations

import logging

import questionary

from syffer.cli import display, handlers
from syffer.cli.session import Session

logger = logging.getLogger(__name__)

_CHOICES = [
    ("Capture de paquets", handlers.handle_capture),
    ("Scan du reseau (ARP)", handlers.handle_scan),
    ("Informations reseau de la machine", handlers.handle_info),
    ("Adresse IP locale", handlers.handle_local_ip),
    ("Geolocaliser une IP publique", handlers.handle_geo),
    ("Details d'un paquet capture", handlers.handle_packet_details),
    ("Parametres", handlers.handle_settings),
    ("Quitter", None),
]


def run(session: Session | None = None) -> int:
    session = session or Session()
    display.banner()
    while True:
        try:
            choice = questionary.select(
                "Menu principal",
                choices=[label for label, _ in _CHOICES],
            ).ask()
        except KeyboardInterrupt:
            return 130
        if choice is None or choice == "Quitter":
            return 0
        handler = dict(_CHOICES)[choice]
        if handler is None:
            return 0
        try:
            handler(session)
        except KeyboardInterrupt:
            display.error("interrompu")
        except Exception as exc:
            logger.exception("erreur inattendue dans %s", choice)
            display.error(f"erreur inattendue : {exc}")
```

- [ ] **Step 2: Remplacer `syffer/__main__.py`**

```python
"""Point d'entree console de Syffer."""

from __future__ import annotations

import logging
import sys

from syffer.cli import menu
from syffer.cli.session import Session
from syffer.utils import logging_setup

logger = logging.getLogger(__name__)


def main() -> int:
    """Point d'entree principal : configure logging + lance le menu."""
    logging_setup.configure(verbose=False)
    session = Session()
    try:
        return menu.run(session)
    except KeyboardInterrupt:
        return 130
    except Exception:
        logger.exception("erreur non recuperable")
        sys.stderr.write("erreur interne, activez les logs verbeux pour plus de details\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Vérifier que l'import de la boucle fonctionne**

Run : `python -c "from syffer.cli import menu; print(menu.run)"`
Expected : affiche `<function run at ...>` sans erreur.

- [ ] **Step 4: Vérifier que la suite complète passe**

Run : `pytest -v`
Expected : tous les tests PASS (>60 au total).

- [ ] **Step 5: Test manuel léger (sans réseau)**

Run : `python -m syffer`
Expected : la bannière s'affiche, un menu apparaît avec navigation fléchée. Choisir "Adresse IP locale" affiche une IP (ou une erreur propre). Choisir "Quitter" quitte proprement avec code 0.

- [ ] **Step 6: Commit**

```bash
git add syffer/cli/menu.py syffer/__main__.py
git commit -m "$(cat <<'EOF'
feat(cli): boucle de menu principale + point d'entree console

menu.run boucle jusqu'a Quitter, dispatch vers les handlers,
catch les KeyboardInterrupt (retour au menu) et les exceptions
inattendues (log + message). __main__.main configure le logging
et delegue a menu.run, avec gestion top-level du crash.

L'option "Details d'un paquet" est enfin fonctionnelle : la
session persiste tant que le menu tourne.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Nettoyage — suppression de l'ancien Syffer.py, README, CHANGELOG

**Files:**
- Delete: `Syffer.py`
- Modify: `README.md`
- Create: `CHANGELOG.md`

**Interfaces:**
- Consumes: rien
- Produces: rien (documentation)

- [ ] **Step 1: Supprimer l'ancien script**

Run : `git rm Syffer.py`
Expected : le fichier est supprimé du working tree et de l'index.

- [ ] **Step 2: Réécrire le README**

Remplacer intégralement `README.md` par :

````markdown
# Syffer

Outil CLI de recon réseau : capture de paquets, scan ARP, informations
réseau, géolocalisation d'IP. **Recon uniquement** — pas d'exploitation
active.

```
   _______     ________ ______ ______ ______
  / ____/ |   / / ____/ ____/ ____/ ____/ __ \
 (__  \| | / / /_  /_  /_   /_   / /_/ /
_____/ | |/ / __/ __/ __/ __/ _, _/
     /  |___/_/   /_/   /_/   /_/ |_|
```

## Prérequis

- Python ≥ 3.10 (testé 3.10 / 3.11 / 3.12).
- **Windows** : [Npcap](https://npcap.com/) installé pour la capture
  de paquets et le scan ARP.
- **Linux / macOS** : la capture et le scan ARP nécessitent
  `CAP_NET_RAW` ou d'être lancés en root.

## Installation

Depuis le dossier du projet :

```bash
pip install -e .
```

Ou en environnement isolé via [pipx](https://pypa.github.io/pipx/) :

```bash
pipx install .
```

## Utilisation

```bash
syffer
```

Le menu interactif s'affiche. Utilisez les flèches pour naviguer,
Entrée pour valider. Menu :

1. **Capture de paquets** — sniffe N paquets, filtre BPF optionnel,
   écrit un `.pcap` horodaté dans `extract/`.
2. **Scan du réseau (ARP)** — scan ARP d'un CIDR, affiche IP / MAC /
   vendor.
3. **Informations réseau de la machine** — hostname, IP locale,
   interfaces (via psutil).
4. **Adresse IP locale**.
5. **Géolocaliser une IP publique** — via ip-api.com.
6. **Détails d'un paquet capturé** — après une capture dans la même
   session, affiche les détails complets d'un paquet par son index.
7. **Paramètres** — activer/désactiver les logs verbeux.
8. **Quitter**.

Les rapports (txt / json / csv) sont proposés à l'export après chaque
opération et enregistrés dans `extract/`.

## Roadmap

- **Phase 1** — scan de ports TCP + fingerprinting OS/services (via
  wrapper `nmap`).
- **Phase 2** — corrélation CVE avec les versions détectées.
- **Phase suivante** — mode CLI à arguments (`syffer scan --range
  ...`) en complément du menu.

## Usage éthique

Syffer est un outil de recon à utiliser uniquement sur des réseaux
dont vous êtes propriétaire ou pour lesquels vous avez une
autorisation écrite. Toute utilisation malveillante est de votre
responsabilité.

## Auteur

Créé par ROOT3301. Sous licence MIT.
````

- [ ] **Step 3: Créer `CHANGELOG.md`**

```markdown
# Changelog

## 0.2.0 - 2026-09-24

### Breaking changes
- Le script `Syffer.py` racine est supprimé, remplacé par le package
  `syffer/` et l'entry point console `syffer`.
- L'installation se fait désormais via `pip install -e .` (ou `pipx
  install .`). L'ancien `pip install -r requirements.txt` reste
  compatible pour les dépendances runtime.
- La dépendance `netifaces` est retirée (cassée sur Python 3.12), remplacée
  par `psutil`.
- La dépendance `colorama` est retirée, remplacée par `rich`.

### Ajouts
- Menu interactif propre avec navigation fléchée (`questionary` +
  `rich`) qui boucle jusqu'à "Quitter".
- Filtres BPF pour la capture de paquets.
- Export unifié en txt / json / csv pour tous les types de résultats.
- Logging structuré avec mode verbeux activable via l'option
  "Paramètres" du menu.
- Wrapper `ExternalTool` préparé pour brancher nmap en Phase 1.
- Suite de tests `pytest` couvrant validation, exporter, formatters,
  handlers du menu (mocks scapy/psutil/requests, aucun droit admin
  requis).

### Corrections
- L'option "Scan du réseau" ne plante plus (ancien
  `TypeError` sur `generate_report`).
- L'option "Détails d'un paquet" est enfin fonctionnelle : les
  paquets capturés persistent tant que le menu tourne.
- Les noms de rapport sont sanitisés (`safe_filename`) et le chemin
  d'écriture est vérifié pour rester sous `extract/` (contre path
  traversal).
- Les CIDR et les IP sont validés avant les appels réseau.
- Les filtres BPF sont validés (rejette les caractères shell
  dangereux) avant d'être passés à scapy.

### Retrait
- Fichier racine `Syffer.py`.
- Dépendances `netifaces`, `colorama`.
```

- [ ] **Step 4: Vérifier la suite complète**

Run : `pytest -v`
Expected : tous les tests PASS.

Run : `syffer` (test manuel) et sélectionner "Quitter".
Expected : bannière, menu, sortie code 0.

- [ ] **Step 5: Commit final**

```bash
git add -A
git status --short   # verifier qu'il n'y a rien d'inattendu
git commit -m "$(cat <<'EOF'
chore(rework): supprime l'ancien Syffer.py, reecrit README, ajoute CHANGELOG

Rupture assumee avec la v0.1 : le point d'entree est desormais la
commande `syffer` (installee via pip install -e .). Le README
documente les prerequis par OS (Npcap sous Windows, root sous
Linux/macOS), l'installation, l'usage, la roadmap Phase 1/2 et
l'usage ethique. Le CHANGELOG 0.2.0 recense les breaking changes,
ajouts et corrections.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Push final vers `devb`**

```bash
git push origin devb
```

Expected : les commits Task 1 → Task 15 apparaissent sur
[Rooot3301/SYFFER branche devb](https://github.com/Rooot3301/SYFFER/tree/devb).

---

## Self-review

**Spec coverage :**
- §4 arborescence → Task 1 (squelette), Tasks 2/6-11 (core), Task 12 (reports), Task 13 (cli), Task 5/3/4 (utils). ✓
- §5.1 models → Task 2. ✓
- §5.2 interfaces / network_info → Tasks 6, 7. ✓
- §5.3 packet_capture avec BPF → Task 8. ✓
- §5.4 network_scan avec validate_cidr + vendor local → Task 9. ✓
- §5.5 geolocation avec GeolocationError → Task 10. ✓
- §5.6 external.py préparé → Task 11. ✓
- §5.7 menu + session + option verbose → Tasks 13, 14. ✓
- §5.8 exporter + safe_output_path → Tasks 4, 12. ✓
- §5.9 validation (safe_filename/cidr/ip/bpf) → Task 3. ✓
- §5.10 logging_setup → Task 5. ✓
- §6 flux (validate → scan → render → export) couvert par Tasks 9 + 12 + 13. ✓
- §7 gestion d'erreurs (catch dans handlers + top-level) → Task 13 + Task 14. ✓
- §8 tests → un fichier de tests par module. ✓
- §9 packaging pyproject.toml → Task 1. ✓
- §10 README → Task 15. ✓
- §11 migration (suppression Syffer.py + CHANGELOG) → Task 15. ✓
- §12 livrables : entry point `syffer`, tests verts, README à jour, `.gitignore` (déjà pushé Task 0). ✓

**Placeholder scan :** aucun TBD/TODO. Toutes les fonctions sont
définies avec code, tous les commits ont leur message complet.

**Type consistency :**
- `Interface` / `InterfaceAddress` / `NetworkInfo` : mêmes signatures
  entre Task 2 (définition), Task 6 (interfaces produit), Task 7
  (network_info compose), Task 12 (formatters), Task 13 (display).
- `ScanResult(cidr, started_at, duration_s, hosts)` : cohérent entre
  Task 2, Task 9 (arp_scan), Task 12 (formatters), Task 13 (display).
- `CaptureResult(pcap_path, packets, bpf_filter, iface)` : cohérent
  Task 2, Task 8, Task 12, Task 13.
- `capture()` retourne `(CaptureResult, list)` en Task 8, consommé
  comme `(result, raw)` en Task 13 handler. ✓
- `export(result, fmt, name)` signature identique Task 12 → Task 13.
- `Session` : mêmes attributs entre Task 13 (définition) et Task 13
  handlers (usage) et Task 14 (menu.run). ✓
- `GeolocationError` : levée dans Task 10, catchée dans Task 13
  (`handle_geo`). ✓

Aucune divergence détectée.

---

## Execution handoff

Plan complet et sauvegardé. Deux options d'exécution :

1. **Subagent-Driven (recommandé)** — je dispatche un subagent frais
   par tâche, review entre chaque, itération rapide.
2. **Inline Execution** — j'exécute les tâches en batch dans cette
   session avec checkpoints de revue.

Quelle approche préfères-tu ?
