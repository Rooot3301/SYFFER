# Syffer — Phase 1 : Port scan + fingerprinting nmap (design)

Date : 2026-09-24
Statut : validé (en cours de plan d'implémentation)

## 1. Contexte

Phase 0 (mergée sur `devb`) a livré le socle : package modulaire,
menu interactif propre, exports unifiés, wrapper `ExternalTool`
préparé, tests unitaires verts. Phase 1 branche le premier outil
externe majeur : **nmap**, pour ajouter à Syffer les capacités port
scan + fingerprinting services/OS + scripts NSE + banner grabbing
manuel. On reste sur du **recon uniquement**, pas d'exploitation.

## 2. Objectifs

1. Ajouter un module `syffer/core/nmap_tool.py` (sous-classe de
   `ExternalTool`) qui invoque `nmap` en subprocess et retourne
   la sortie XML.
2. Parser cette sortie XML via `xml.etree.ElementTree` (stdlib, pas
   de nouvelle dépendance) dans `syffer/core/nmap_parser.py`.
3. Ajouter un banner grabbing TCP passif dans
   `syffer/core/banner_grab.py`.
4. Orchestrer scan + banner dans `syffer/core/port_scan.py`.
5. Nouveau sous-menu "Scan avancé (nmap)" avec 5 profils prédéfinis
   + mode custom, accessible depuis le menu principal.
6. Étendre les exports (txt / json / csv) au type `NmapScan` et
   sauvegarder le XML brut de nmap dans `extract/`.
7. Refuser proprement si le binaire `nmap` n'est pas dans le PATH
   (message + retour au menu, pas de fallback pure-python en
   Phase 1).
8. Suite pytest complète, avec fixture XML nmap réelle, mocks
   subprocess + socket ; aucun droit admin ni nmap requis pour la
   CI.

**Hors scope Phase 1** :
- Corrélation CVE (→ Phase 2).
- UDP scan (`-sU`) — trop lent, sortie de scope.
- Scripts NSE non-default (`--script vuln`, `--script exploit`…) —
  approche exploitation, exclu.
- CLI à arguments (→ phase suivante).

## 3. Global constraints

- Recon uniquement — jamais d'exploitation active.
- Reprend intégralement les invariants de Phase 0 : pas de `input()`
  ou `print()` dans `core/*` ou `reports/*`, dataclasses immuables
  dans `models.py`, sanitisation systématique des entrées
  utilisateur.
- Nmap est invoqué uniquement via `NmapTool` (sous-classe
  d'`ExternalTool`), jamais via un `subprocess.run` direct dans le
  reste du code.
- La ligne de commande nmap est construite à partir d'une
  **whitelist stricte** de flags — jamais de flags saisis
  directement par l'utilisateur transmis à shell.
- Timeout par défaut : 300 s (nmap agressif peut être long).
- Cible : validée via `validate_ip`, `validate_cidr`, ou une regex
  hostname conservatrice.
- Le XML complet est toujours sauvegardé dans `extract/nmap-*.xml`
  pour retraitement externe.

## 4. Architecture

```
syffer/
  core/
    nmap_tool.py       # NmapTool(ExternalTool) : run_scan(target, profile, ports?, extra?)
    nmap_parser.py     # parse_xml(xml_bytes) -> NmapScan
    banner_grab.py     # grab_banner(ip, port, timeout) -> str | None
    port_scan.py       # port_scan(target, profile, ports?, banner: bool) -> NmapScan
    models.py          # + NmapPort, NmapScript, NmapHost, NmapScan (extension)
  cli/
    submenu_nmap.py    # ask_target, ask_profile, ask_ports (custom), dispatch scan
    handlers.py        # + handle_nmap_scan(session) qui appelle submenu_nmap.run
    menu.py            # + entree "Scan avance (nmap)"
    display.py         # + render_nmap_scan (rich Table par host)
  reports/
    formatters.py      # + branches NmapScan pour to_txt / to_json / to_csv
    exporter.py        # inchange (dispatch generique deja en place)
  utils/
    validation.py      # + validate_ports (ex: "22,80,1000-2000"), validate_hostname
tests/
  fixtures/
    nmap-sample.xml    # XML nmap reel embarque pour parser
  test_nmap_tool.py
  test_nmap_parser.py
  test_banner_grab.py
  test_port_scan.py
  test_submenu_nmap.py
  test_validation.py   # + tests validate_ports / validate_hostname
  test_formatters.py   # + tests NmapScan
```

## 5. Composants détaillés

### 5.1 Extensions `syffer/core/models.py`

```python
@dataclass(frozen=True, slots=True)
class NmapScript:
    id: str
    output: str


@dataclass(frozen=True, slots=True)
class NmapPort:
    port: int
    proto: str              # "tcp" | "udp"
    state: str              # "open" | "closed" | "filtered"
    service: str | None
    product: str | None
    version: str | None
    banner: str | None      # rempli par banner_grab si active


@dataclass(frozen=True, slots=True)
class NmapHost:
    ip: str
    hostname: str | None
    state: str              # "up" | "down"
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
    xml_path: pathlib.Path | None
```

### 5.2 `syffer/utils/validation.py` (ajouts)

- `validate_hostname(name: str) -> str` : regex `[A-Za-z0-9.-]`,
  longueur ≤ 253, pas de `..`, ne commence/finit pas par `.`.
  Utilisé quand la cible n'est ni une IP ni un CIDR.
- `validate_target(target: str) -> str` : essaie
  `validate_ip` → `validate_cidr` → `validate_hostname` dans cet
  ordre, retourne la première forme normalisée qui marche.
- `validate_ports(spec: str) -> str` : accepte
  `"22,80,443"`, `"1-1024"`, `"22,80,1000-2000"`. Chaque entier
  ∈ [1, 65535]. Retourne la chaîne normalisée. Lève `ValueError`
  sinon.

### 5.3 `syffer/core/nmap_tool.py`

```python
class NmapTool(ExternalTool):
    def __init__(self) -> None:
        super().__init__("nmap")

    def version(self) -> str | None:
        """Renvoie la version detectee, ou None si nmap absent."""

    def run_scan(
        self,
        target: str,
        profile: NmapProfile,
        ports: str | None = None,
        timeout: int = 300,
    ) -> bytes:
        """Execute nmap et renvoie le XML brut. Leve FileNotFoundError
        si nmap absent, subprocess.TimeoutExpired si timeout depasse,
        RuntimeError si nmap retourne un code d'erreur."""
```

**Profils** (constantes du module) — chaque profil est une
`tuple[str, ...]` de flags whitelistés :

- `QUICK = ("-T4", "-F")`
- `FULL_TCP = ("-T4", "-p-")`
- `SERVICE_VERSION = ("-T4", "-sV")`
- `OS_DETECTION = ("-T4", "-O", "-Pn")`
- `AGGRESSIVE = ("-T4", "-A")`  # -sV -O -sC --traceroute
- `CUSTOM_BASE = ("-T4",)` (le custom ajoute ports + éventuellement
  `-sV -sC -O` selon les cases cochées)

**Construction de la ligne de commande** (100% liste, jamais
`shell=True`) :
```python
["nmap", *profile_flags, "-oX", "-", "--stats-every", "2s",
 *(("-p", ports) if ports else ()), target]
```

`target` doit être validé par `validate_target` en amont — pas de
re-validation dans NmapTool. Défense supplémentaire : `target` ne
doit contenir aucun caractère hors `[A-Za-z0-9.:/-]` (assertion à
l'entrée, `AssertionError` si violé — indique un bug amont).

### 5.4 `syffer/core/nmap_parser.py`

```python
def parse_xml(xml_bytes: bytes) -> NmapScan:
    """Parse un XML nmap (sortie -oX -) et renvoie un NmapScan.

    Utilise xml.etree.ElementTree (stdlib). Silencieux sur les
    champs manquants (nmap XML est bourre d'optionnels). Leve
    ValueError si le XML est malforme ou ne contient pas d'element
    <nmaprun>."""
```

Extraction :
- `nmaprun` root → `version`, `startstr`.
- Chaque `<host>` → `<address>` (IPv4), `<hostname>` (optionnel),
  `<status state=...>`.
- Chaque `<port>` → `protocol`, `portid`, `<state state=...>`,
  `<service name product version>`.
- `<os>` → `<osmatch name=... accuracy=...>` (garde le premier).
- `<hostscript>` et `<script>` → `id`, `output`.

Fixture de test : `tests/fixtures/nmap-sample.xml` = un vrai XML
nmap (généré une fois par `nmap -A localhost -oX -` sur une VM,
committé), le parser doit en extraire au moins 1 host, 3 ports, 1
service versionné, et 1 script.

### 5.5 `syffer/core/banner_grab.py`

```python
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Ouvre un socket TCP passif, lit jusqu'a 1024 octets, decode
    en latin-1 (safe), renvoie la chaine strippee ou None sur
    erreur/timeout. N'envoie aucun payload actif."""
```

Utilisé uniquement sur les ports `state == "open"` détectés par
nmap.

### 5.6 `syffer/core/port_scan.py`

Orchestrateur :

```python
def port_scan(
    target: str,
    profile: NmapProfile,
    ports: str | None = None,
    banner: bool = False,
    timeout: int = 300,
) -> NmapScan:
    """
    1. Valide target via validate_target
    2. Valide ports via validate_ports (si non None)
    3. Instancie NmapTool, verifie available() (sinon FileNotFoundError)
    4. Appelle run_scan -> xml_bytes
    5. Sauvegarde le XML dans extract/nmap-<slug>-YYYYMMDD-HHMMSS.xml
    6. Parse via parse_xml -> NmapScan
    7. Si banner=True : pour chaque host up et port open, appelle
       grab_banner et enrichit les NmapPort correspondants
    8. Renvoie le NmapScan enrichi (avec xml_path)
    """
```

Les enrichissements de banner reconstruisent des `NmapPort` /
`NmapHost` immuables (les dataclasses sont frozen).

### 5.7 `syffer/cli/submenu_nmap.py`

Sous-menu appelé depuis `handlers.handle_nmap_scan` :

```python
def run(session: Session) -> None:
    tool = NmapTool()
    if not tool.available():
        display.error("nmap requis. Installe-le : https://nmap.org/download.html")
        return

    profile_label = questionary.select("Profil de scan", choices=[
        "Quick (top 100 ports)",
        "Full TCP (65535 ports)",
        "Service + version (-sV)",
        "OS detection (-O, requiert admin)",
        "Aggressive (-A : -sV -O -sC --traceroute)",
        "Custom",
        "Retour",
    ]).ask()
    if profile_label in (None, "Retour"):
        return

    target = prompts.ask_target()
    ports = None
    if profile_label == "Custom":
        ports = prompts.ask_ports()
        # Custom profile utilise CUSTOM_BASE + les toggles user
        profile = build_custom_profile(...)
    else:
        profile = MAP[profile_label]

    banner = questionary.confirm("Banner grabbing en complement ?", default=True).ask()

    try:
        result = port_scan(target, profile, ports=ports, banner=banner)
    except FileNotFoundError:
        display.error("nmap introuvable")
        return
    except subprocess.TimeoutExpired:
        display.error("timeout nmap (>300s)")
        return
    except ValueError as exc:
        display.error(str(exc))
        return
    except RuntimeError as exc:
        display.error(f"echec nmap : {exc}")
        return

    display.render_nmap_scan(result)
    handlers._maybe_export(result)
```

Barre de progression : `rich.progress.Progress` pilotée par le
timer local (nmap `--stats-every 2s` écrit sur stderr, on
capture stderr en background et on incrémente une progress
approximative). Simple et fiable, pas de parsing critique.

### 5.8 `syffer/cli/display.py` (ajout)

`render_nmap_scan(scan: NmapScan) -> None` :
- Un `Panel` d'entête : cible, profil, version nmap, durée.
- Pour chaque host up : un `Table` (port, proto, état, service,
  version, banner tronqué à 40 caractères).
- Si `os_guess` : ligne "OS : xxx (yy%)" au-dessus du tableau.
- Si `scripts` : `Panel` par script (id + output).

### 5.9 `syffer/reports/formatters.py` (extension)

- `to_txt(NmapScan)` : rendu texte hiérarchique (host → ports).
- `to_json(NmapScan)` : `asdict` (frozen dataclasses → naturel).
- `to_csv(NmapScan)` : format aplati, une ligne par port avec
  colonnes `host_ip,hostname,os_guess,os_accuracy,port,proto,state,service,product,version,banner`.

### 5.10 `syffer/cli/menu.py` (extension)

Ajout d'une entrée `"Scan avance (nmap)"` avant `"Parametres"`, qui
appelle `handlers.handle_nmap_scan`.

## 6. Sécurité

- **Injection args** : la ligne de commande nmap est construite à
  partir de constantes tuples + `target` validé + `ports` validé.
  Jamais de `shell=True`. Jamais de concaténation string avec du
  contenu utilisateur.
- **Custom flags** : le mode "Custom" ne permet PAS à l'utilisateur
  de saisir des flags nmap libres — il coche des cases (`-sV`,
  `-sC`, `-O`, `-Pn`) et saisit des ports validés. Pas de champ
  texte libre pour les flags.
- **Fichier XML** : le nom du fichier est construit avec un
  timestamp + un slug de la cible (via `safe_filename` sur la
  cible), stocké sous `extract/` via `safe_output_path`.
- **Banner grabbing** : socket TCP passif uniquement, `recv` sans
  envoi préalable. Certains services ne renvoient rien tant qu'on
  n'a pas envoyé quelque chose (SSH renvoie sa banner immédiatement,
  HTTP non) — c'est acceptable pour Phase 1 recon simple.
- **Cible** : `validate_target` refuse les caractères hors
  `[A-Za-z0-9.:/-]`. Une assertion défensive dans `NmapTool.run_scan`
  double-vérifie.

## 7. Gestion d'erreurs

Politique identique Phase 0 (catch dans les handlers, message rich
propre, retour au menu). Cas ajoutés :

- `FileNotFoundError` (nmap absent) : "nmap requis, installe-le
  depuis nmap.org".
- `subprocess.TimeoutExpired` : "timeout dépassé (>Ns), essayez un
  profil plus rapide (Quick)".
- `RuntimeError` (nmap exit ≠ 0) : affiche le stderr tronqué.
- `ValueError` : validation cible/ports, message brut.
- `xml.etree.ElementTree.ParseError` : converti en `ValueError`
  ("XML nmap malformé, essayez de relancer") avant remontée.

## 8. Tests

Suite `pytest`, mocks partout, **aucun nmap réel invoqué, aucun
socket réel ouvert** :

- `tests/fixtures/nmap-sample.xml` : XML nmap réel (généré une
  fois hors tests, committé). Ne dépend d'aucun host live.
- `test_nmap_tool.py` :
  - `available()` false → refuse proprement
  - `run_scan()` mock `subprocess.run`, vérifie construction
    ligne de commande selon profil (list, jamais shell)
  - assertion défensive sur target avec caractère bizarre
  - `RuntimeError` sur code retour ≠ 0
- `test_nmap_parser.py` :
  - Parse fixture, vérifie au moins 1 host, 3 ports, service
    versionné, 1 script
  - `ValueError` sur XML vide / malformé
- `test_banner_grab.py` :
  - Mock `socket.create_connection`, vérifie recv + close
  - Timeout → `None`
  - `ConnectionRefused` → `None`
- `test_port_scan.py` :
  - Orchestrateur : mock NmapTool + banner_grab, vérifie que
    l'enrichissement banner ne touche que les ports open
  - Vérifie sauvegarde du XML dans extract/
  - Refus si nmap absent
- `test_submenu_nmap.py` :
  - Nmap absent → error + return sans crash
  - Choix "Retour" → return sans scan
  - Custom → construction du profil selon toggles
- `test_validation.py` : ajouts `validate_hostname`, `validate_target`,
  `validate_ports`
- `test_formatters.py` : ajouts NmapScan (txt/json/csv)

## 9. Livrables Phase 1

- Tous les fichiers section 4 créés / étendus.
- Fixture XML nmap embarquée.
- Suite pytest verte (Phase 0 + Phase 1, ~110 tests estimés).
- Entrée "Scan avance (nmap)" dans le menu principal.
- Message clair si nmap absent (pas de crash).
- Export NmapScan fonctionnel en txt/json/csv + XML brut sauvé
  systématiquement.
- README + CHANGELOG mis à jour (v0.3.0).

## 10. Prochaine étape

Invocation du skill `superpowers:writing-plans` pour découper en
tâches TDD (~10 tâches estimées, dans la lignée de Phase 0).
