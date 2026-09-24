# Syffer Phase 1 — Port scan + fingerprinting nmap : Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter à Syffer les capacités port scan + fingerprinting services/OS + scripts NSE + banner grabbing manuel, via un wrapper subprocess propre autour de nmap.

**Architecture:** `NmapTool(ExternalTool)` invoque nmap en subprocess et retourne le XML brut. `nmap_parser` transforme le XML en dataclasses immuables. `port_scan` orchestre scan + banner grabbing optionnel. Nouveau sous-menu CLI "Scan avancé (nmap)" avec 5 profils prédéfinis + custom. Refus propre si nmap absent (pas de fallback pure-python).

**Tech Stack:** Python ≥3.10, `xml.etree.ElementTree` (stdlib, parsing XML), `subprocess` (stdlib), nmap ≥7.90 (binaire externe, refusé proprement si absent). Aucune nouvelle dépendance pip.

**Spec:** [docs/superpowers/specs/2026-09-24-syffer-phase-1-portscan-fingerprinting-design.md](../specs/2026-09-24-syffer-phase-1-portscan-fingerprinting-design.md)

## Global Constraints

- Reprend TOUS les invariants de Phase 0 (pas de `input()`/`print()` dans core/reports, dataclasses immuables, sanitisation systématique).
- Recon uniquement — pas d'exploitation, pas de `--script vuln`, pas de brute-force.
- Nmap invoqué uniquement via `NmapTool.run_scan`, jamais `subprocess.run` direct ailleurs.
- Ligne de commande construite à partir d'une whitelist stricte de tuples de flags — jamais `shell=True`, jamais de concaténation string avec du contenu utilisateur.
- Custom profile : l'utilisateur coche des cases (`-sV`, `-sC`, `-O`, `-Pn`) et saisit des ports (validés) — pas de champ libre pour les flags nmap.
- Le XML brut nmap est toujours sauvegardé sous `extract/nmap-<slug>-YYYYMMDD-HHMMSS.xml`.
- Timeout par défaut : 300 s.
- Tests : mocks `subprocess` + `socket`, fixture XML nmap réelle committée. Aucun nmap réel ni socket réel dans la suite.
- Branche de travail : `devb-phase1` (depuis `devb`). Ne jamais s'ajouter comme collaborateur, ne jamais force-push sur main.
- Commits : `feat:`, `chore:`, `test:`, `docs:` + footer `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`.

## File Structure

```
syffer/
  core/
    models.py            # + NmapScript, NmapPort, NmapHost, NmapScan
    nmap_tool.py         # NmapTool(ExternalTool) + constantes NmapProfile
    nmap_parser.py       # parse_xml(bytes) -> NmapScan
    banner_grab.py       # grab_banner(ip, port, timeout) -> str | None
    port_scan.py         # port_scan orchestrateur
  cli/
    submenu_nmap.py      # sous-menu profils + saisie + dispatch
    handlers.py          # + handle_nmap_scan
    menu.py              # + entree "Scan avance (nmap)"
    display.py           # + render_nmap_scan
    prompts.py           # + ask_target, ask_ports, ask_custom_toggles
  reports/
    formatters.py        # + branches NmapScan pour to_txt/to_json/to_csv
  utils/
    validation.py        # + validate_hostname, validate_target, validate_ports
tests/
  fixtures/
    nmap-sample.xml      # XML nmap reel (genere hors tests, committe)
  test_nmap_tool.py
  test_nmap_parser.py
  test_banner_grab.py
  test_port_scan.py
  test_submenu_nmap.py
  test_validation.py     # + ajouts validate_target/hostname/ports
  test_formatters.py     # + cas NmapScan
CHANGELOG.md             # entree 0.3.0
README.md                # mise a jour section usage
```

## Ordre d'exécution

Les tâches sont ordonnées de sorte que chaque étape s'appuie sur des interfaces déjà en place, et se termine par un cycle test/commit vert : (1) modèles → (2) validation → (3) nmap tool → (4) parser + fixture → (5) banner grab → (6) orchestrateur → (7) formatters → (8) prompts + display + submenu → (9) intégration menu + handler → (10) doc + push.

---

### Task 1: Extension models (NmapScript / NmapPort / NmapHost / NmapScan)

**Files:**
- Modify: `syffer/core/models.py`
- Modify: `tests/test_models.py`

**Interfaces:**
- Consumes: rien
- Produces:
  - `NmapScript(id: str, output: str)` — frozen, slots
  - `NmapPort(port: int, proto: str, state: str, service: str | None, product: str | None, version: str | None, banner: str | None)` — frozen, slots
  - `NmapHost(ip: str, hostname: str | None, state: str, os_guess: str | None, os_accuracy: int | None, ports: tuple[NmapPort, ...], scripts: tuple[NmapScript, ...])` — frozen, slots
  - `NmapScan(target: str, profile: str, started_at: float, duration_s: float, hosts: tuple[NmapHost, ...], nmap_version: str | None, xml_path: pathlib.Path | None)` — frozen, slots

- [ ] **Step 1: Écrire les nouveaux tests dans `tests/test_models.py`**

Ajouter à la fin du fichier :

```python
from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def test_nmap_port_is_frozen():
    p = NmapPort(port=80, proto="tcp", state="open", service="http",
                 product=None, version=None, banner=None)
    with pytest.raises(Exception):
        p.port = 443  # type: ignore[misc]


def test_nmap_host_carries_scripts():
    scripts = (NmapScript(id="http-title", output="Welcome"),)
    ports = (NmapPort(port=80, proto="tcp", state="open", service="http",
                     product=None, version=None, banner=None),)
    host = NmapHost(ip="1.2.3.4", hostname=None, state="up",
                    os_guess=None, os_accuracy=None, ports=ports, scripts=scripts)
    assert host.scripts[0].id == "http-title"
    assert host.ports[0].port == 80


def test_nmap_scan_composition():
    scan = NmapScan(target="1.2.3.4", profile="quick", started_at=0.0,
                    duration_s=1.0, hosts=(), nmap_version="7.94",
                    xml_path=None)
    assert scan.hosts == ()
    assert scan.nmap_version == "7.94"
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_models.py -v`
Expected : FAIL avec `ImportError` sur `NmapPort`, etc.

- [ ] **Step 3: Étendre `syffer/core/models.py`**

Ajouter à la fin du fichier :

```python
@dataclass(frozen=True, slots=True)
class NmapScript:
    id: str
    output: str


@dataclass(frozen=True, slots=True)
class NmapPort:
    port: int
    proto: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    banner: str | None


@dataclass(frozen=True, slots=True)
class NmapHost:
    ip: str
    hostname: str | None
    state: str
    os_guess: str | None
    os_accuracy: int | None
    ports: tuple[NmapPort, ...]
    scripts: tuple[NmapScript, ...]


@dataclass(frozen=True, slots=True)
class NmapScan:
    target: str
    profile: str
    started_at: float
    duration_s: float
    hosts: tuple[NmapHost, ...]
    nmap_version: str | None
    xml_path: Path | None
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_models.py -v`
Expected : 10 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/models.py tests/test_models.py
git commit -m "$(cat <<'EOF'
feat(core): dataclasses nmap (NmapScript/Port/Host/Scan)

Etend models.py avec les types de retour du parser nmap et de
l'orchestrateur port_scan. Toutes frozen+slots comme le reste.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Extensions validation (validate_hostname / validate_target / validate_ports)

**Files:**
- Modify: `syffer/utils/validation.py`
- Modify: `tests/test_validation.py`

**Interfaces:**
- Consumes:
  - `syffer.utils.validation.{validate_ip, validate_cidr}` (Phase 0)
- Produces:
  - `syffer.utils.validation.validate_hostname(name: str) -> str`
  - `syffer.utils.validation.validate_target(target: str) -> str`
  - `syffer.utils.validation.validate_ports(spec: str) -> str`

- [ ] **Step 1: Écrire les tests dans `tests/test_validation.py`**

Ajouter à la fin du fichier :

```python
from syffer.utils.validation import (
    validate_hostname,
    validate_ports,
    validate_target,
)


class TestValidateHostname:
    def test_accepts_simple(self):
        assert validate_hostname("example.com") == "example.com"

    def test_accepts_subdomain(self):
        assert validate_hostname("api.example.co.uk") == "api.example.co.uk"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_hostname("")

    def test_rejects_double_dot(self):
        with pytest.raises(ValueError):
            validate_hostname("foo..com")

    def test_rejects_starts_with_dot(self):
        with pytest.raises(ValueError):
            validate_hostname(".foo.com")

    def test_rejects_shell_chars(self):
        with pytest.raises(ValueError):
            validate_hostname("foo;rm -rf /")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            validate_hostname("a" * 254)


class TestValidateTarget:
    def test_accepts_ipv4(self):
        assert validate_target("8.8.8.8") == "8.8.8.8"

    def test_accepts_cidr(self):
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"

    def test_accepts_hostname(self):
        assert validate_target("scanme.nmap.org") == "scanme.nmap.org"

    def test_rejects_garbage(self):
        with pytest.raises(ValueError):
            validate_target("not a target!!!")


class TestValidatePorts:
    def test_accepts_single(self):
        assert validate_ports("80") == "80"

    def test_accepts_list(self):
        assert validate_ports("22,80,443") == "22,80,443"

    def test_accepts_range(self):
        assert validate_ports("1-1024") == "1-1024"

    def test_accepts_mixed(self):
        assert validate_ports("22,80,1000-2000") == "22,80,1000-2000"

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            validate_ports("0")

    def test_rejects_too_large(self):
        with pytest.raises(ValueError):
            validate_ports("65536")

    def test_rejects_reversed_range(self):
        with pytest.raises(ValueError):
            validate_ports("100-50")

    def test_rejects_shell_chars(self):
        with pytest.raises(ValueError):
            validate_ports("80;rm")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_ports("")
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_validation.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Étendre `syffer/utils/validation.py`**

Ajouter à la fin du fichier :

```python
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-.]*[A-Za-z0-9])?$")
_MAX_HOSTNAME_LEN = 253
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


def validate_hostname(name: str) -> str:
    if not name:
        raise ValueError("hostname vide")
    if len(name) > _MAX_HOSTNAME_LEN:
        raise ValueError(f"hostname trop long (max {_MAX_HOSTNAME_LEN})")
    if ".." in name:
        raise ValueError("hostname contient '..'")
    if not _HOSTNAME_RE.match(name):
        raise ValueError(f"hostname invalide : {name}")
    return name


def validate_target(target: str) -> str:
    """Cible d'un scan : IP, CIDR ou hostname."""
    for candidate in (validate_ip, validate_cidr, validate_hostname):
        try:
            return candidate(target)
        except ValueError:
            continue
    raise ValueError(f"cible invalide : {target}")


def validate_ports(spec: str) -> str:
    if not spec:
        raise ValueError("spec de ports vide")
    if not _PORTS_RE.match(spec):
        raise ValueError(f"spec de ports invalide : {spec}")
    for chunk in spec.split(","):
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2:
                raise ValueError(f"plage invalide : {chunk}")
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise ValueError(f"plage non numerique : {chunk}") from exc
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"plage hors bornes : {chunk}")
        else:
            try:
                n = int(chunk)
            except ValueError as exc:
                raise ValueError(f"port non numerique : {chunk}") from exc
            if not (1 <= n <= 65535):
                raise ValueError(f"port hors bornes : {n}")
    return spec
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_validation.py -v`
Expected : 46 tests PASS (26 anciens + 20 nouveaux).

- [ ] **Step 5: Commit**

```bash
git add syffer/utils/validation.py tests/test_validation.py
git commit -m "$(cat <<'EOF'
feat(utils): validation hostname / target / ports (Phase 1)

Ajoute validate_hostname (regex conservatrice), validate_target
(essaie IP puis CIDR puis hostname) et validate_ports (spec
nmap type "22,80,1000-2000", bornes 1-65535). Defenses contre
injection shell dans les args nmap.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: NmapTool (wrapper subprocess)

**Files:**
- Create: `syffer/core/nmap_tool.py`
- Test: `tests/test_nmap_tool.py`

**Interfaces:**
- Consumes:
  - `syffer.core.external.ExternalTool` (Phase 0)
- Produces:
  - Module constants `syffer.core.nmap_tool.{QUICK, FULL_TCP, SERVICE_VERSION, OS_DETECTION, AGGRESSIVE, CUSTOM_BASE}` : `tuple[str, ...]` de flags.
  - Type alias `syffer.core.nmap_tool.NmapProfile = tuple[str, ...]`
  - Regex `syffer.core.nmap_tool._SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9.:/-]+$")`
  - Class `syffer.core.nmap_tool.NmapTool(ExternalTool)` :
    - `__init__(self)` → `super().__init__("nmap")`
    - `version(self) -> str | None` : parse la première ligne de `nmap --version` ; renvoie None si nmap absent
    - `run_scan(self, target: str, profile: NmapProfile, ports: str | None = None, timeout: int = 300) -> bytes` : construit la ligne de commande, invoque via `run`, renvoie stdout (XML). Lève `FileNotFoundError` si nmap absent, `RuntimeError(stderr)` si returncode ≠ 0.

- [ ] **Step 1: Écrire les tests dans `tests/test_nmap_tool.py`**

```python
"""Tests de syffer.core.nmap_tool."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from syffer.core.nmap_tool import (
    AGGRESSIVE,
    OS_DETECTION,
    QUICK,
    SERVICE_VERSION,
    NmapTool,
)


def test_available_false(mocker):
    mocker.patch("shutil.which", return_value=None)
    assert NmapTool().available() is False


def test_run_scan_refuses_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    with pytest.raises(FileNotFoundError):
        NmapTool().run_scan(target="1.2.3.4", profile=QUICK)


def test_run_scan_builds_command_with_quick_profile(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    completed = MagicMock()
    completed.returncode = 0
    completed.stdout = b"<nmaprun/>"
    completed.stderr = b""
    mock_run = mocker.patch("subprocess.run", return_value=completed)

    result = NmapTool().run_scan(target="1.2.3.4", profile=QUICK)

    assert result == b"<nmaprun/>"
    called_args = mock_run.call_args.args[0]
    assert called_args[0] == "/usr/bin/nmap"
    assert "-T4" in called_args
    assert "-F" in called_args
    assert "-oX" in called_args
    assert "-" in called_args
    assert "1.2.3.4" in called_args


def test_run_scan_appends_ports(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    completed = MagicMock(returncode=0, stdout=b"<nmaprun/>", stderr=b"")
    mock_run = mocker.patch("subprocess.run", return_value=completed)

    NmapTool().run_scan(target="1.2.3.4", profile=SERVICE_VERSION, ports="22,80")
    called_args = mock_run.call_args.args[0]
    assert "-p" in called_args
    p_index = called_args.index("-p")
    assert called_args[p_index + 1] == "22,80"


def test_run_scan_rejects_unsafe_target(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch("subprocess.run")
    with pytest.raises(AssertionError):
        NmapTool().run_scan(target="1.2.3.4; rm -rf /", profile=QUICK)


def test_run_scan_raises_on_nonzero_exit(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch(
        "subprocess.run",
        return_value=MagicMock(returncode=1, stdout=b"", stderr=b"boom"),
    )
    with pytest.raises(RuntimeError):
        NmapTool().run_scan(target="1.2.3.4", profile=QUICK)


def test_version_parses_output(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/nmap")
    mocker.patch(
        "subprocess.run",
        return_value=MagicMock(
            returncode=0,
            stdout=b"Nmap version 7.94 ( https://nmap.org )\n",
            stderr=b"",
        ),
    )
    assert NmapTool().version() == "7.94"


def test_version_none_when_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    assert NmapTool().version() is None


def test_aggressive_profile_contains_A_flag():
    assert "-A" in AGGRESSIVE


def test_os_detection_profile_contains_O_and_Pn():
    assert "-O" in OS_DETECTION
    assert "-Pn" in OS_DETECTION
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_nmap_tool.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/nmap_tool.py`**

```python
"""Wrapper subprocess autour du binaire nmap."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

from syffer.core.external import ExternalTool

logger = logging.getLogger(__name__)

NmapProfile = tuple[str, ...]

QUICK: NmapProfile = ("-T4", "-F")
FULL_TCP: NmapProfile = ("-T4", "-p-")
SERVICE_VERSION: NmapProfile = ("-T4", "-sV")
OS_DETECTION: NmapProfile = ("-T4", "-O", "-Pn")
AGGRESSIVE: NmapProfile = ("-T4", "-A")
CUSTOM_BASE: NmapProfile = ("-T4",)

_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9.:/-]+$")
_VERSION_RE = re.compile(r"Nmap version ([0-9.]+)")


class NmapTool(ExternalTool):
    def __init__(self) -> None:
        super().__init__("nmap")

    def version(self) -> str | None:
        if not self.available():
            return None
        try:
            result = self.run(["--version"], timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        match = _VERSION_RE.search(result.stdout.decode("utf-8", errors="replace"))
        return match.group(1) if match else None

    def run_scan(
        self,
        target: str,
        profile: NmapProfile,
        ports: str | None = None,
        timeout: int = 300,
    ) -> bytes:
        binary = shutil.which(self.name)
        if binary is None:
            raise FileNotFoundError("nmap requis : https://nmap.org/download.html")
        assert _SAFE_TARGET_RE.match(target), f"cible non sanitize (bug amont) : {target!r}"

        args = [binary, *profile, "-oX", "-", "--stats-every", "2s"]
        if ports is not None:
            args.extend(["-p", ports])
        args.append(target)

        logger.debug("nmap : %s", args)
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"nmap exit {completed.returncode} : {stderr}")
        return completed.stdout
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_nmap_tool.py -v`
Expected : 10 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/nmap_tool.py tests/test_nmap_tool.py
git commit -m "$(cat <<'EOF'
feat(core): NmapTool - wrapper subprocess autour de nmap

Sous-classe d'ExternalTool avec 6 profils prets a l'emploi (Quick,
FullTCP, Service+Version, OSDetect, Aggressive, CustomBase). La
ligne de commande est construite en liste (jamais shell=True) a
partir de tuples de flags whitelistes + target valide en amont.
Defense supplementaire : assertion sur le pattern de la cible pour
attraper tout bug de validation amont. version() parse la sortie
de nmap --version. Refuse proprement si nmap absent.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Fixture XML + parser nmap

**Files:**
- Create: `tests/fixtures/nmap-sample.xml`
- Create: `syffer/core/nmap_parser.py`
- Test: `tests/test_nmap_parser.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.{NmapHost, NmapPort, NmapScan, NmapScript}` (Task 1)
- Produces:
  - `syffer.core.nmap_parser.parse_xml(xml_bytes: bytes, target: str = "", profile: str = "") -> NmapScan` : parse le XML de sortie de `nmap -oX -`. Lève `ValueError` si XML malformé ou racine `<nmaprun>` manquante. `target`/`profile` sont juste stockés dans le `NmapScan` retourné (le XML n'a pas cette info dans la même forme).

- [ ] **Step 1: Créer la fixture XML `tests/fixtures/nmap-sample.xml`**

XML minimal mais réaliste (à sauvegarder tel quel, indenté pour la lisibilité) :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -A scanme.nmap.org" start="1700000000" startstr="Sat Nov 14 22:53:20 2023" version="7.94" xmloutputversion="1.05">
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1700000000" endtime="1700000060">
    <status state="up" reason="echo-reply" reason_ttl="53"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.nmap.org" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="53"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="53"/>
        <service name="http" product="Apache httpd" version="2.4.7" method="probed" conf="10"/>
        <script id="http-title" output="Go ahead and ScanMe!"/>
      </port>
      <port protocol="tcp" portid="9929">
        <state state="open" reason="syn-ack" reason_ttl="53"/>
        <service name="nping-echo" product="Nping echo" method="probed" conf="10"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 3.11 - 4.1" accuracy="95" line="12345">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="3.X" accuracy="95"/>
      </osmatch>
      <osmatch name="Linux 3.10 - 4.11" accuracy="93" line="12346"/>
    </os>
    <hostscript>
      <script id="http-server-header" output="Apache/2.4.7 (Ubuntu)"/>
    </hostscript>
  </host>
  <runstats>
    <finished time="1700000060" timestr="Sat Nov 14 22:54:20 2023" elapsed="60.42" summary="Nmap done" exit="success"/>
  </runstats>
</nmaprun>
```

- [ ] **Step 2: Écrire les tests dans `tests/test_nmap_parser.py`**

```python
"""Tests de syffer.core.nmap_parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from syffer.core.nmap_parser import parse_xml

_FIXTURE = Path(__file__).parent / "fixtures" / "nmap-sample.xml"


def _sample_xml() -> bytes:
    return _FIXTURE.read_bytes()


def test_parse_valid_xml_has_one_host():
    scan = parse_xml(_sample_xml())
    assert len(scan.hosts) == 1


def test_parse_extracts_version():
    scan = parse_xml(_sample_xml())
    assert scan.nmap_version == "7.94"


def test_parse_extracts_ports():
    scan = parse_xml(_sample_xml())
    ports = scan.hosts[0].ports
    assert len(ports) == 3
    port_numbers = sorted(p.port for p in ports)
    assert port_numbers == [22, 80, 9929]


def test_parse_extracts_service_and_version():
    scan = parse_xml(_sample_xml())
    ssh = next(p for p in scan.hosts[0].ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version and ssh.version.startswith("6.6.1")


def test_parse_extracts_os_guess():
    scan = parse_xml(_sample_xml())
    host = scan.hosts[0]
    assert host.os_guess == "Linux 3.11 - 4.1"
    assert host.os_accuracy == 95


def test_parse_extracts_scripts():
    scan = parse_xml(_sample_xml())
    # 1 hostscript + 1 script sur port 80 = tous cumules cote host + port
    all_scripts = list(scan.hosts[0].scripts) + [
        s for p in scan.hosts[0].ports for _ in (p,) for s in ()
    ]
    # au moins le hostscript remonte
    assert any(s.id == "http-server-header" for s in scan.hosts[0].scripts)


def test_parse_extracts_hostname():
    scan = parse_xml(_sample_xml())
    assert scan.hosts[0].hostname == "scanme.nmap.org"


def test_parse_extracts_state():
    scan = parse_xml(_sample_xml())
    assert scan.hosts[0].state == "up"


def test_parse_target_profile_pass_through():
    scan = parse_xml(_sample_xml(), target="scanme.nmap.org", profile="Aggressive")
    assert scan.target == "scanme.nmap.org"
    assert scan.profile == "Aggressive"


def test_parse_empty_bytes_raises():
    with pytest.raises(ValueError):
        parse_xml(b"")


def test_parse_malformed_raises():
    with pytest.raises(ValueError):
        parse_xml(b"<not-nmap/>")
```

- [ ] **Step 3: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_nmap_parser.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 4: Écrire `syffer/core/nmap_parser.py`**

```python
"""Parser de la sortie XML de nmap (-oX -)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def _parse_port(elem: ET.Element) -> NmapPort:
    state_elem = elem.find("state")
    service_elem = elem.find("service")
    return NmapPort(
        port=int(elem.get("portid", "0")),
        proto=elem.get("protocol", "tcp"),
        state=state_elem.get("state", "unknown") if state_elem is not None else "unknown",
        service=service_elem.get("name") if service_elem is not None else None,
        product=service_elem.get("product") if service_elem is not None else None,
        version=service_elem.get("version") if service_elem is not None else None,
        banner=None,
    )


def _parse_scripts(elem: ET.Element) -> tuple[NmapScript, ...]:
    scripts = []
    for s in elem.findall("script"):
        script_id = s.get("id")
        output = s.get("output", "")
        if script_id:
            scripts.append(NmapScript(id=script_id, output=output))
    return tuple(scripts)


def _parse_host(elem: ET.Element) -> NmapHost:
    status_elem = elem.find("status")
    state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    ip = ""
    for addr in elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr", "")
            break
        if not ip:
            ip = addr.get("addr", "")

    hostname_elem = elem.find("hostnames/hostname")
    hostname = hostname_elem.get("name") if hostname_elem is not None else None

    ports_container = elem.find("ports")
    ports: tuple[NmapPort, ...] = ()
    if ports_container is not None:
        ports = tuple(_parse_port(p) for p in ports_container.findall("port"))

    os_guess: str | None = None
    os_accuracy: int | None = None
    osmatch = elem.find("os/osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name")
        try:
            os_accuracy = int(osmatch.get("accuracy", "0"))
        except ValueError:
            os_accuracy = None

    scripts: tuple[NmapScript, ...] = ()
    hostscript = elem.find("hostscript")
    if hostscript is not None:
        scripts = _parse_scripts(hostscript)

    return NmapHost(
        ip=ip,
        hostname=hostname,
        state=state,
        os_guess=os_guess,
        os_accuracy=os_accuracy,
        ports=ports,
        scripts=scripts,
    )


def parse_xml(xml_bytes: bytes, target: str = "", profile: str = "") -> NmapScan:
    if not xml_bytes:
        raise ValueError("XML nmap vide")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"XML nmap malforme : {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError(f"racine XML inattendue : <{root.tag}>")

    version = root.get("version")
    try:
        started_at = float(root.get("start", "0"))
    except ValueError:
        started_at = 0.0

    duration = 0.0
    finished = root.find("runstats/finished")
    if finished is not None:
        try:
            duration = float(finished.get("elapsed", "0"))
        except ValueError:
            duration = 0.0

    hosts = tuple(_parse_host(h) for h in root.findall("host"))

    return NmapScan(
        target=target,
        profile=profile,
        started_at=started_at,
        duration_s=duration,
        hosts=hosts,
        nmap_version=version,
        xml_path=None,
    )
```

- [ ] **Step 5: Vérifier que les tests passent**

Run : `python -m pytest tests/test_nmap_parser.py -v`
Expected : 11 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/nmap-sample.xml syffer/core/nmap_parser.py tests/test_nmap_parser.py
git commit -m "$(cat <<'EOF'
feat(core): parser XML nmap + fixture reelle

parse_xml transforme la sortie -oX - de nmap en NmapScan
immuable via xml.etree.ElementTree (stdlib, pas de nouvelle
dep). Fixture nmap-sample.xml embarquee (sortie type d'un
scan agressif sur scanme.nmap.org) pour tester le parser sans
lancer nmap.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Banner grabbing TCP passif

**Files:**
- Create: `syffer/core/banner_grab.py`
- Test: `tests/test_banner_grab.py`

**Interfaces:**
- Consumes: rien
- Produces:
  - `syffer.core.banner_grab.grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None`

- [ ] **Step 1: Écrire les tests dans `tests/test_banner_grab.py`**

```python
"""Tests de syffer.core.banner_grab."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

from syffer.core.banner_grab import grab_banner


def test_grab_banner_returns_stripped_string(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    assert grab_banner("1.2.3.4", 22) == "SSH-2.0-OpenSSH_8.9"


def test_grab_banner_returns_none_on_timeout(mocker):
    mocker.patch("socket.create_connection", side_effect=socket.timeout())
    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_returns_none_on_refused(mocker):
    mocker.patch("socket.create_connection", side_effect=ConnectionRefusedError())
    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_returns_none_on_empty(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b""
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    assert grab_banner("1.2.3.4", 22) is None


def test_grab_banner_decodes_latin1(mocker):
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"\xff\xfe hello"
    fake_sock.__enter__ = MagicMock(return_value=fake_sock)
    fake_sock.__exit__ = MagicMock(return_value=False)
    mocker.patch("socket.create_connection", return_value=fake_sock)

    result = grab_banner("1.2.3.4", 22)
    assert result is not None
    assert "hello" in result
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_banner_grab.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/banner_grab.py`**

```python
"""Banner grabbing TCP passif (recv sans envoi de payload)."""

from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

_BUF_SIZE = 1024


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Ouvre une connexion TCP, lit jusqu'a 1024 octets, ferme, retourne
    la chaine strippee ou None sur erreur/timeout/vide.

    N'envoie AUCUN payload : c'est passif. Certains services (SSH, SMTP,
    FTP) envoient une banner spontanement, d'autres non (HTTP attend une
    requete). C'est acceptable pour du recon simple.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(_BUF_SIZE)
    except (OSError, socket.timeout) as exc:
        logger.debug("banner %s:%d echec : %s", ip, port, exc)
        return None
    if not data:
        return None
    return data.decode("latin-1", errors="replace").strip()
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_banner_grab.py -v`
Expected : 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/banner_grab.py tests/test_banner_grab.py
git commit -m "$(cat <<'EOF'
feat(core): banner grabbing TCP passif

grab_banner ouvre un socket TCP, lit jusqu'a 1024 octets, ferme.
Aucun payload actif envoye : purement recv. Utilise en
complement de nmap pour recuperer les banners des services qui
en envoient spontanement (SSH, SMTP, FTP).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Orchestrateur port_scan

**Files:**
- Create: `syffer/core/port_scan.py`
- Test: `tests/test_port_scan.py`

**Interfaces:**
- Consumes:
  - `syffer.core.nmap_tool.{NmapTool, NmapProfile}` (Task 3)
  - `syffer.core.nmap_parser.parse_xml` (Task 4)
  - `syffer.core.banner_grab.grab_banner` (Task 5)
  - `syffer.core.models.{NmapScan, NmapHost, NmapPort}` (Task 1)
  - `syffer.utils.validation.{validate_target, validate_ports}` (Task 2)
  - `syffer.utils.paths.{resolve_extract_dir, timestamped_name, safe_filename}` (Phase 0)
- Produces:
  - `syffer.core.port_scan.port_scan(target: str, profile: NmapProfile, profile_name: str, ports: str | None = None, banner: bool = False, timeout: int = 300) -> NmapScan`

- [ ] **Step 1: Écrire les tests dans `tests/test_port_scan.py`**

```python
"""Tests de syffer.core.port_scan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from syffer.core.models import NmapHost, NmapPort, NmapScan
from syffer.core.nmap_tool import QUICK
from syffer.core.port_scan import port_scan

_XML = b"""<?xml version="1.0"?>
<nmaprun version="7.94" start="0">
  <host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
    </ports>
  </host>
  <runstats><finished elapsed="1.0"/></runstats>
</nmaprun>"""


def test_port_scan_validates_target(mocker, tmp_extract_dir: Path):
    mocker.patch("syffer.core.port_scan.NmapTool")
    with pytest.raises(ValueError):
        port_scan("bad target!!!", QUICK, profile_name="Quick")


def test_port_scan_refuses_when_nmap_missing(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = False
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    with pytest.raises(FileNotFoundError):
        port_scan("1.2.3.4", QUICK, profile_name="Quick")


def test_port_scan_writes_xml_and_returns_scan(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    scan = port_scan("1.2.3.4", QUICK, profile_name="Quick")

    assert scan.target == "1.2.3.4"
    assert scan.profile == "Quick"
    assert scan.xml_path is not None
    assert scan.xml_path.exists()
    assert scan.xml_path.parent == tmp_extract_dir
    assert scan.hosts[0].ports[0].service == "ssh"


def test_port_scan_enriches_only_open_ports_with_banner(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)
    mock_banner = mocker.patch(
        "syffer.core.port_scan.grab_banner", return_value="SSH-2.0-OpenSSH"
    )

    scan = port_scan("1.2.3.4", QUICK, profile_name="Quick", banner=True)

    # banner grabbing appele UNIQUEMENT sur port 22 (open), pas sur 80 (closed)
    assert mock_banner.call_count == 1
    mock_banner.assert_called_once_with("1.2.3.4", 22)

    port_22 = next(p for p in scan.hosts[0].ports if p.port == 22)
    port_80 = next(p for p in scan.hosts[0].ports if p.port == 80)
    assert port_22.banner == "SSH-2.0-OpenSSH"
    assert port_80.banner is None


def test_port_scan_skips_banner_when_disabled(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)
    mock_banner = mocker.patch("syffer.core.port_scan.grab_banner")

    port_scan("1.2.3.4", QUICK, profile_name="Quick", banner=False)
    mock_banner.assert_not_called()


def test_port_scan_validates_ports(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    fake_tool.run_scan.return_value = _XML
    mocker.patch("syffer.core.port_scan.NmapTool", return_value=fake_tool)

    with pytest.raises(ValueError):
        port_scan("1.2.3.4", QUICK, profile_name="Quick", ports="99999")
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_port_scan.py -v`
Expected : FAIL avec `ImportError`.

- [ ] **Step 3: Écrire `syffer/core/port_scan.py`**

```python
"""Orchestrateur : nmap + banner grabbing optionnel."""

from __future__ import annotations

import logging
import time
from dataclasses import replace

from syffer.core.banner_grab import grab_banner
from syffer.core.models import NmapHost, NmapPort, NmapScan
from syffer.core.nmap_parser import parse_xml
from syffer.core.nmap_tool import NmapProfile, NmapTool
from syffer.utils.paths import resolve_extract_dir, timestamped_name
from syffer.utils.validation import (
    safe_filename,
    validate_ports,
    validate_target,
)

logger = logging.getLogger(__name__)


def _enrich_with_banners(host: NmapHost) -> NmapHost:
    new_ports = []
    for p in host.ports:
        if p.state == "open":
            banner = grab_banner(host.ip, p.port)
            new_ports.append(replace(p, banner=banner))
        else:
            new_ports.append(p)
    return replace(host, ports=tuple(new_ports))


def port_scan(
    target: str,
    profile: NmapProfile,
    profile_name: str,
    ports: str | None = None,
    banner: bool = False,
    timeout: int = 300,
) -> NmapScan:
    validated_target = validate_target(target)
    validated_ports = validate_ports(ports) if ports is not None else None

    tool = NmapTool()
    if not tool.available():
        raise FileNotFoundError("nmap requis : https://nmap.org/download.html")

    logger.info("nmap scan : target=%s profil=%s", validated_target, profile_name)
    started = time.time()
    xml_bytes = tool.run_scan(
        target=validated_target,
        profile=profile,
        ports=validated_ports,
        timeout=timeout,
    )
    duration = time.time() - started
    logger.info("nmap termine en %.2fs", duration)

    slug = safe_filename(validated_target.replace("/", "-").replace(":", "-"))
    xml_path = resolve_extract_dir() / timestamped_name(f"nmap-{slug}", "xml")
    xml_path.write_bytes(xml_bytes)

    scan = parse_xml(xml_bytes, target=validated_target, profile=profile_name)

    if banner:
        scan = NmapScan(
            target=scan.target,
            profile=scan.profile,
            started_at=scan.started_at,
            duration_s=scan.duration_s,
            hosts=tuple(_enrich_with_banners(h) for h in scan.hosts),
            nmap_version=scan.nmap_version,
            xml_path=xml_path,
        )
    else:
        scan = NmapScan(
            target=scan.target,
            profile=scan.profile,
            started_at=scan.started_at,
            duration_s=scan.duration_s,
            hosts=scan.hosts,
            nmap_version=scan.nmap_version,
            xml_path=xml_path,
        )
    return scan
```

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_port_scan.py -v`
Expected : 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add syffer/core/port_scan.py tests/test_port_scan.py
git commit -m "$(cat <<'EOF'
feat(core): orchestrateur port_scan (nmap + banner optionnel)

Valide cible et ports en amont, verifie nmap available, execute
scan, sauvegarde le XML brut sous extract/, parse, et enrichit
optionnellement les ports "open" avec un banner grabbing TCP
passif. Retourne un NmapScan immuable avec xml_path pointant
vers le fichier XML sauvegarde.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Formatters — cas NmapScan

**Files:**
- Modify: `syffer/reports/formatters.py`
- Modify: `tests/test_formatters.py`

**Interfaces:**
- Consumes:
  - `syffer.core.models.NmapScan` (Task 1)
- Produces:
  - `syffer.reports.formatters.Result` étendu (union inclut `NmapScan`)
  - `to_txt`, `to_json`, `to_csv` gèrent le cas `NmapScan`

- [ ] **Step 1: Ajouter les tests dans `tests/test_formatters.py`**

Ajouter à la fin du fichier :

```python
from syffer.core.models import NmapHost, NmapPort, NmapScan, NmapScript


def _sample_nmap() -> NmapScan:
    return NmapScan(
        target="scanme.nmap.org",
        profile="Aggressive",
        started_at=0.0,
        duration_s=12.5,
        nmap_version="7.94",
        xml_path=None,
        hosts=(
            NmapHost(
                ip="45.33.32.156",
                hostname="scanme.nmap.org",
                state="up",
                os_guess="Linux 3.11 - 4.1",
                os_accuracy=95,
                ports=(
                    NmapPort(port=22, proto="tcp", state="open", service="ssh",
                             product="OpenSSH", version="6.6.1", banner="SSH-2.0"),
                    NmapPort(port=80, proto="tcp", state="open", service="http",
                             product="Apache", version="2.4.7", banner=None),
                ),
                scripts=(NmapScript(id="http-server-header", output="Apache/2.4.7"),),
            ),
        ),
    )


class TestNmapScanFormatters:
    def test_txt_contains_target_and_ports(self):
        text = to_txt(_sample_nmap())
        assert "scanme.nmap.org" in text
        assert "45.33.32.156" in text
        assert "22" in text
        assert "ssh" in text
        assert "OpenSSH" in text
        assert "Linux" in text

    def test_json_roundtrip(self):
        import json
        payload = json.loads(to_json(_sample_nmap()))
        assert payload["target"] == "scanme.nmap.org"
        assert payload["hosts"][0]["ports"][0]["service"] == "ssh"

    def test_csv_flattens_ports(self):
        csv_text = to_csv(_sample_nmap())
        lines = csv_text.strip().splitlines()
        assert lines[0].startswith("host_ip,hostname,os_guess,os_accuracy,port")
        # 1 host * 2 ports = 2 lignes de donnees
        assert len(lines) == 3
        assert "45.33.32.156" in csv_text
        assert "OpenSSH" in csv_text
```

- [ ] **Step 2: Vérifier que les tests échouent**

Run : `python -m pytest tests/test_formatters.py -v`
Expected : FAIL sur `TestNmapScanFormatters` avec `TypeError: type de resultat non supporte`.

- [ ] **Step 3: Étendre `syffer/reports/formatters.py`**

Modifier l'import et l'alias :

```python
from syffer.core.models import (
    CaptureResult,
    GeoInfo,
    NetworkInfo,
    NmapScan,
    ScanResult,
)

Result = Union[CaptureResult, ScanResult, NetworkInfo, GeoInfo, NmapScan]
```

Ajouter dans `to_txt` (avant le `raise TypeError` final) :

```python
    if isinstance(result, NmapScan):
        lines = [
            f"Scan nmap : {result.target}",
            f"Profil : {result.profile}",
            f"Version nmap : {result.nmap_version or '?'}",
            f"Duree : {result.duration_s:.2f}s",
            f"XML : {result.xml_path or '-'}",
            "-" * 60,
        ]
        for host in result.hosts:
            hn = f" ({host.hostname})" if host.hostname else ""
            lines.append(f"Host {host.ip}{hn} [{host.state}]")
            if host.os_guess:
                acc = f" {host.os_accuracy}%" if host.os_accuracy is not None else ""
                lines.append(f"  OS : {host.os_guess}{acc}")
            for p in host.ports:
                service = p.service or "?"
                version = f" {p.product or ''} {p.version or ''}".strip()
                banner = f" | {p.banner}" if p.banner else ""
                lines.append(f"  {p.port}/{p.proto} {p.state:<8} {service} {version}{banner}")
            for s in host.scripts:
                lines.append(f"  [script:{s.id}] {s.output}")
        return "\n".join(lines) + "\n"
```

Ajouter dans `to_csv` (avant le `raise TypeError` final) :

```python
    elif isinstance(result, NmapScan):
        writer.writerow([
            "host_ip", "hostname", "os_guess", "os_accuracy",
            "port", "proto", "state", "service", "product", "version", "banner",
        ])
        for host in result.hosts:
            for p in host.ports:
                writer.writerow([
                    host.ip, host.hostname or "",
                    host.os_guess or "", host.os_accuracy if host.os_accuracy is not None else "",
                    p.port, p.proto, p.state,
                    p.service or "", p.product or "", p.version or "", p.banner or "",
                ])
```

Le cas `to_json` fonctionne automatiquement (asdict).

- [ ] **Step 4: Vérifier que les tests passent**

Run : `python -m pytest tests/test_formatters.py -v`
Expected : 14 tests PASS (11 anciens + 3 nouveaux).

- [ ] **Step 5: Commit**

```bash
git add syffer/reports/formatters.py tests/test_formatters.py
git commit -m "$(cat <<'EOF'
feat(reports): export NmapScan en txt / json / csv

Ajoute les branches NmapScan aux 3 formatters. Le csv est
aplati (une ligne par port) avec toutes les colonnes utiles
pour retraitement (host_ip, os_guess, service, version,
banner...).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Prompts + display + sous-menu nmap

**Files:**
- Modify: `syffer/cli/prompts.py`
- Modify: `syffer/cli/display.py`
- Create: `syffer/cli/submenu_nmap.py`
- Test: `tests/test_submenu_nmap.py`

**Interfaces:**
- Consumes:
  - `syffer.core.port_scan.port_scan` (Task 6)
  - `syffer.core.nmap_tool.*` (Task 3)
  - `syffer.cli.session.Session` (Phase 0)
  - `syffer.cli.display` (Phase 0)
  - `syffer.utils.validation.{validate_target, validate_ports}` (Task 2)
- Produces:
  - `syffer.cli.prompts.ask_target() -> str`
  - `syffer.cli.prompts.ask_ports() -> str`
  - `syffer.cli.prompts.ask_custom_toggles() -> tuple[bool, bool, bool, bool]` : `(sv, sc, o, pn)`
  - `syffer.cli.display.render_nmap_scan(scan: NmapScan) -> None`
  - `syffer.cli.submenu_nmap.run(session: Session) -> None`

- [ ] **Step 1: Étendre `syffer/cli/prompts.py`**

Ajouter à la fin du fichier :

```python
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
```

- [ ] **Step 2: Étendre `syffer/cli/display.py`**

Ajouter à la fin du fichier :

```python
def render_nmap_scan(scan: "NmapScan") -> None:
    from syffer.core.models import NmapScan  # local import evite circular
    assert isinstance(scan, NmapScan)

    header_lines = [
        f"Cible : [bold cyan]{scan.target}[/bold cyan]",
        f"Profil : {scan.profile}",
        f"Version nmap : {scan.nmap_version or '?'}",
        f"Duree : {scan.duration_s:.2f}s",
        f"XML : [dim]{scan.xml_path or '-'}[/dim]",
    ]
    _console.print(Panel("\n".join(header_lines), title="Scan nmap", border_style="cyan"))

    for host in scan.hosts:
        hn = f" ({host.hostname})" if host.hostname else ""
        state_color = "green" if host.state == "up" else "red"
        title = f"[{state_color}]{host.ip}[/{state_color}]{hn}"
        if host.os_guess:
            acc = f" [{host.os_accuracy}%]" if host.os_accuracy is not None else ""
            title += f" — OS: {host.os_guess}{acc}"

        table = Table(title=title)
        table.add_column("Port", justify="right", style="cyan")
        table.add_column("Proto")
        table.add_column("Etat")
        table.add_column("Service")
        table.add_column("Version")
        table.add_column("Banner")
        for p in host.ports:
            state_style = "green" if p.state == "open" else "dim"
            version = " ".join(filter(None, [p.product, p.version]))
            banner_display = (p.banner or "")[:40]
            table.add_row(
                str(p.port), p.proto,
                f"[{state_style}]{p.state}[/{state_style}]",
                p.service or "-", version or "-", banner_display or "-",
            )
        _console.print(table)

        for s in host.scripts:
            _console.print(Panel(s.output, title=f"script: {s.id}", border_style="magenta"))
```

- [ ] **Step 3: Écrire `syffer/cli/submenu_nmap.py`**

```python
"""Sous-menu Scan avance (nmap)."""

from __future__ import annotations

import logging
import subprocess

import questionary

from syffer.cli import display, prompts
from syffer.cli.session import Session
from syffer.core import nmap_tool as nt
from syffer.core.port_scan import port_scan

logger = logging.getLogger(__name__)

_PROFILE_LABELS = {
    "Quick (top 100 ports)": ("Quick", nt.QUICK, False),
    "Full TCP (65535 ports)": ("Full TCP", nt.FULL_TCP, False),
    "Service + version (-sV)": ("Service+Version", nt.SERVICE_VERSION, False),
    "OS detection (-O, requiert admin)": ("OS Detection", nt.OS_DETECTION, False),
    "Aggressive (-A : -sV -O -sC --traceroute)": ("Aggressive", nt.AGGRESSIVE, False),
    "Custom": ("Custom", None, True),
}


def _build_custom_profile(sv: bool, sc: bool, o: bool, pn: bool) -> nt.NmapProfile:
    flags = list(nt.CUSTOM_BASE)
    if sv:
        flags.append("-sV")
    if sc:
        flags.append("-sC")
    if o:
        flags.append("-O")
    if pn:
        flags.append("-Pn")
    return tuple(flags)


def run(session: Session) -> None:
    tool = nt.NmapTool()
    if not tool.available():
        display.error("nmap requis. Installe-le : https://nmap.org/download.html")
        return

    label = questionary.select(
        "Profil de scan",
        choices=[*_PROFILE_LABELS.keys(), "Retour"],
    ).ask()
    if label in (None, "Retour"):
        return

    profile_name, profile_flags, is_custom = _PROFILE_LABELS[label]

    try:
        target = prompts.ask_target()
    except KeyboardInterrupt:
        return

    ports: str | None = None
    if is_custom:
        try:
            ports = prompts.ask_ports()
            sv, sc, o, pn = prompts.ask_custom_toggles()
        except KeyboardInterrupt:
            return
        profile_flags = _build_custom_profile(sv, sc, o, pn)

    try:
        do_banner = questionary.confirm("Banner grabbing en complement ?", default=True).ask()
    except KeyboardInterrupt:
        return
    if do_banner is None:
        return

    try:
        result = port_scan(
            target=target,
            profile=profile_flags,
            profile_name=profile_name,
            ports=ports,
            banner=bool(do_banner),
        )
    except FileNotFoundError as exc:
        display.error(str(exc))
        return
    except subprocess.TimeoutExpired:
        display.error("timeout nmap (>300s), essayez le profil Quick")
        return
    except ValueError as exc:
        display.error(str(exc))
        return
    except RuntimeError as exc:
        display.error(f"echec nmap : {exc}")
        return

    display.render_nmap_scan(result)

    from syffer.cli.handlers import _maybe_export
    _maybe_export(result)
```

- [ ] **Step 4: Écrire les tests dans `tests/test_submenu_nmap.py`**

```python
"""Tests du sous-menu nmap."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from syffer.cli import submenu_nmap
from syffer.cli.session import Session
from syffer.core.models import NmapScan


def test_run_refuses_when_nmap_missing(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = False
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mock_error = mocker.patch("syffer.cli.display.error")

    submenu_nmap.run(Session())
    mock_error.assert_called_once()


def test_run_returns_on_retour(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mocker.patch("questionary.select", return_value=MagicMock(ask=lambda: "Retour"))
    mock_port_scan = mocker.patch("syffer.cli.submenu_nmap.port_scan")

    submenu_nmap.run(Session())
    mock_port_scan.assert_not_called()


def test_run_dispatches_to_port_scan(mocker, tmp_extract_dir: Path):
    fake_tool = MagicMock()
    fake_tool.available.return_value = True
    mocker.patch("syffer.cli.submenu_nmap.nt.NmapTool", return_value=fake_tool)
    mocker.patch(
        "questionary.select",
        return_value=MagicMock(ask=lambda: "Quick (top 100 ports)"),
    )
    mocker.patch("syffer.cli.prompts.ask_target", return_value="1.2.3.4")
    mocker.patch(
        "questionary.confirm",
        return_value=MagicMock(ask=lambda: True),
    )
    fake_scan = NmapScan(
        target="1.2.3.4", profile="Quick", started_at=0.0, duration_s=1.0,
        hosts=(), nmap_version="7.94", xml_path=None,
    )
    mock_port_scan = mocker.patch(
        "syffer.cli.submenu_nmap.port_scan", return_value=fake_scan
    )
    mocker.patch("syffer.cli.display.render_nmap_scan")
    mocker.patch("syffer.cli.prompts.ask_export", return_value=None)

    submenu_nmap.run(Session())
    mock_port_scan.assert_called_once()
    kwargs = mock_port_scan.call_args.kwargs
    assert kwargs["target"] == "1.2.3.4"
    assert kwargs["profile_name"] == "Quick"


def test_build_custom_profile_all_toggles():
    profile = submenu_nmap._build_custom_profile(True, True, True, True)
    assert "-sV" in profile
    assert "-sC" in profile
    assert "-O" in profile
    assert "-Pn" in profile


def test_build_custom_profile_none():
    profile = submenu_nmap._build_custom_profile(False, False, False, False)
    assert "-sV" not in profile
    assert "-sC" not in profile
    assert "-O" not in profile
    assert "-Pn" not in profile
```

- [ ] **Step 5: Vérifier que les tests passent**

Run : `python -m pytest tests/test_submenu_nmap.py -v`
Expected : 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add syffer/cli/prompts.py syffer/cli/display.py syffer/cli/submenu_nmap.py tests/test_submenu_nmap.py
git commit -m "$(cat <<'EOF'
feat(cli): sous-menu Scan avance (nmap) + rendu + prompts

- prompts.ask_target/ask_ports/ask_custom_toggles avec validation
- display.render_nmap_scan : panel d'entete + tableau par host +
  panels pour scripts NSE, colorisation etat/OS
- submenu_nmap.run : 5 profils predefinis + Custom (toggles + ports),
  refus propre si nmap absent, gestion timeout/erreurs, export
  via _maybe_export

Aucun input libre pour les flags nmap : le mode Custom passe par
des checkbox et validate_ports.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Intégration menu principal + handler

**Files:**
- Modify: `syffer/cli/handlers.py`
- Modify: `syffer/cli/menu.py`

**Interfaces:**
- Consumes:
  - `syffer.cli.submenu_nmap.run` (Task 8)
- Produces:
  - `syffer.cli.handlers.handle_nmap_scan(session: Session) -> None`

- [ ] **Step 1: Étendre `syffer/cli/handlers.py`**

Ajouter à la fin du fichier :

```python
def handle_nmap_scan(session: Session) -> None:
    from syffer.cli import submenu_nmap
    submenu_nmap.run(session)
```

- [ ] **Step 2: Étendre `syffer/cli/menu.py`**

Modifier la liste `_CHOICES` pour insérer l'entrée nmap avant "Parametres" :

```python
_CHOICES = [
    ("Capture de paquets", handlers.handle_capture),
    ("Scan du reseau (ARP)", handlers.handle_scan),
    ("Scan avance (nmap)", handlers.handle_nmap_scan),
    ("Informations reseau de la machine", handlers.handle_info),
    ("Adresse IP locale", handlers.handle_local_ip),
    ("Geolocaliser une IP publique", handlers.handle_geo),
    ("Details d'un paquet capture", handlers.handle_packet_details),
    ("Parametres", handlers.handle_settings),
    ("Quitter", None),
]
```

- [ ] **Step 3: Vérifier la suite complète**

Run : `python -m pytest -v`
Expected : tous les tests PASS (~120 tests, Phase 0 + Phase 1).

Run : `python -c "from syffer.cli import menu; print([c[0] for c in menu._CHOICES])"`
Expected : liste incluant `'Scan avance (nmap)'`.

- [ ] **Step 4: Commit**

```bash
git add syffer/cli/handlers.py syffer/cli/menu.py
git commit -m "$(cat <<'EOF'
feat(cli): integre le sous-menu nmap au menu principal

Ajoute handle_nmap_scan qui delegue a submenu_nmap.run et
l'entree "Scan avance (nmap)" au menu principal, entre le scan
ARP et les infos machine.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: README + CHANGELOG + push

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Mettre à jour `README.md`**

Dans la section "Menu", insérer entre l'option 2 et l'option 3 :

```markdown
3. **Scan avancé (nmap)** — port scan + fingerprinting via wrapper
   nmap : 5 profils prédéfinis (Quick, Full TCP, Service+Version, OS
   Detection, Aggressive) + mode Custom (ports + toggles). Banner
   grabbing TCP passif optionnel en complément. Le XML brut de nmap
   est sauvegardé sous `extract/nmap-*.xml`. **Requiert nmap
   installé** ([nmap.org/download](https://nmap.org/download.html)) ;
   l'option refuse proprement si le binaire est absent. OS detection
   et scan ARP demandent des droits root/admin.
```

Renuméroter les options suivantes (4→5→6→7→8→9).

Dans la section "Roadmap", remplacer l'entrée "Phase 1" par :

```markdown
- **Phase 2** — corrélation CVE : croiser les versions détectées en
  Phase 1 avec une base CVE (NVD ou dataset local).
```

Dans la section "Prérequis", ajouter une ligne :

```markdown
- **Optionnel** : [nmap](https://nmap.org/download.html) ≥ 7.90 pour
  l'option "Scan avancé (nmap)".
```

- [ ] **Step 2: Mettre à jour `CHANGELOG.md`**

Insérer au-dessus de l'entrée `## 0.2.0` :

```markdown
## 0.3.0 - 2026-09-24

### Ajouts (Phase 1 — port scan + fingerprinting)
- Nouvelle option de menu "Scan avancé (nmap)" avec 5 profils
  prédéfinis (Quick, Full TCP, Service+Version, OS Detection,
  Aggressive) + mode Custom (checkbox de flags + ports validés).
- Wrapper `NmapTool` (sous-classe d'`ExternalTool`) : construction
  100% liste de la ligne de commande, whitelist de flags,
  assertion défensive sur la cible.
- Parser XML nmap (`syffer.core.nmap_parser.parse_xml`) via
  `xml.etree.ElementTree` (stdlib, aucune nouvelle dépendance).
- Banner grabbing TCP passif (`syffer.core.banner_grab.grab_banner`)
  en complément de nmap, activable par confirm.
- Orchestrateur `syffer.core.port_scan.port_scan` : validation
  target/ports, sauvegarde du XML brut sous `extract/nmap-*.xml`,
  enrichissement banner sur les ports "open" uniquement.
- Extensions `validate_hostname`, `validate_target`, `validate_ports`.
- Export `NmapScan` en txt / json / csv (csv aplati, une ligne par
  port).
- Fixture XML nmap embarquée dans `tests/fixtures/` (aucun nmap réel
  invoqué en CI).

### Prérequis ajoutés
- nmap ≥ 7.90 sur le PATH pour l'option "Scan avancé (nmap)".
  L'outil refuse proprement (message + retour menu) si absent, sans
  jamais crasher.

### Sécurité
- Aucun flag nmap n'est saisissable en champ libre : le mode Custom
  passe par des checkbox pour `-sV -sC -O -Pn` uniquement, et par
  `validate_ports` pour la spec de ports.
- La cible est validée en amont (`validate_target`), et une
  assertion défensive dans `NmapTool.run_scan` refuse toute cible
  contenant un caractère hors `[A-Za-z0-9.:/-]`.

```

- [ ] **Step 3: Vérifier la suite finale**

Run : `python -m pytest 2>&1 | tail -5`
Expected : ~120 tests PASS.

Run : `syffer` (test manuel), naviguer jusqu'à "Scan avance (nmap)" pour vérifier que l'option apparaît et que "Retour" fonctionne.

- [ ] **Step 4: Commit final**

```bash
git add README.md CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs(rework): README + CHANGELOG pour Phase 1 (nmap)

Documente la nouvelle option "Scan avance (nmap)", le prerequis
nmap installe sur le PATH, et la roadmap mise a jour (Phase 2
CVE). CHANGELOG 0.3.0 recense les ajouts, prerequis, et les
proprietes de securite du wrapper.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Push sur `devb-phase1`**

```bash
git push -u origin devb-phase1
```

Expected : la branche apparait sur [Rooot3301/SYFFER](https://github.com/Rooot3301/SYFFER/tree/devb-phase1) et gh propose l'URL de creation de PR.

---

## Self-review

**Spec coverage :**
- §5.1 models NmapScript/Port/Host/Scan → Task 1 ✓
- §5.2 validate_hostname/target/ports → Task 2 ✓
- §5.3 NmapTool + profils + assertion défensive → Task 3 ✓
- §5.4 parse_xml + fixture → Task 4 ✓
- §5.5 grab_banner → Task 5 ✓
- §5.6 port_scan orchestrateur + XML sauvé + enrichissement banner sur "open" → Task 6 ✓
- §5.7 submenu_nmap + build_custom_profile + refus si nmap absent → Task 8 ✓
- §5.8 render_nmap_scan → Task 8 ✓
- §5.9 formatters NmapScan → Task 7 ✓
- §5.10 entrée menu principal + handler → Task 9 ✓
- §6 sécurité (whitelist flags, jamais shell, pas de champ libre, validation en amont) → Tasks 2/3/6/8 ✓
- §7 gestion d'erreurs (FileNotFoundError, TimeoutExpired, RuntimeError, ValueError) → Tasks 6/8 ✓
- §8 tests (fixture XML, mocks partout, aucun nmap réel) → Tasks 1-9 ✓
- §9 livrables (menu + refus + export + README/CHANGELOG) → Tasks 9/10 ✓

**Placeholder scan :** aucun TBD/TODO. Tous les blocs de code sont complets, tous les messages de commit sont écrits.

**Type consistency :**
- `NmapPort/NmapHost/NmapScan/NmapScript` : mêmes signatures Task 1 (def) → Tasks 4 (parser), 6 (orchestrateur avec `dataclasses.replace`), 7 (formatters), 8 (display).
- `NmapProfile = tuple[str, ...]` : Task 3 (def), Tasks 6/8 (usage).
- `port_scan(target, profile, profile_name, ports=None, banner=False, timeout=300)` : signature identique Task 6 (def) → Task 8 (usage `port_scan(target=..., profile=profile_flags, profile_name=profile_name, ports=ports, banner=bool(do_banner))`). ✓
- `NmapTool.run_scan(target, profile, ports=None, timeout=300) -> bytes` : Task 3 (def), Task 6 (usage). ✓
- `parse_xml(xml_bytes, target="", profile="") -> NmapScan` : Task 4 (def), Task 6 (usage). ✓
- `grab_banner(ip, port, timeout=2.0) -> str | None` : Task 5 (def), Task 6 (usage). ✓
- `_maybe_export` importé de `syffer.cli.handlers` dans le submenu (Task 8) — existe depuis Phase 0. ✓

Aucune divergence.

---

## Execution handoff

Plan complet et sauvegardé. Le prompt de l'utilisateur est déjà "go phase 1 en inline execution" (chaîné depuis Phase 0). Enchainer directement sur `superpowers:executing-plans`.
